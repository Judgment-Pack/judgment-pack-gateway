package main

// The write path: content-addressed artifacts, signed chained receipts, and the
// signed seal registry. SPEC.md §1 is normative for every byte written here.
// The bytes are kept through the store contract (store_contract.go): the
// artifacts in a blob space, the receipts in an indexed space, the registry
// in an append log, each of the filesystem kind (store_fs.go) as shipped.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"
)

const seedBytes = ed25519.SeedSize // 32

// sessionPattern is SPEC.md §3a. A session id names a directory under the store
// and a verifier discovers sessions by ENUMERATING that directory, so an id that
// escaped the receipts root would produce genuinely signed receipts verification
// could never find.
var sessionPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func requireSession(sessionID string) error {
	if !sessionPattern.MatchString(sessionID) || sessionID == "." || sessionID == ".." {
		return fmt.Errorf("session id must match %s", sessionPattern)
	}
	return nil
}

// argumentsKey derives the key for the arguments commitment from the signing
// seed. Arguments are committed to with a keyed digest rather than a plain hash
// so a party that only *holds* receipts cannot brute-force a small argument
// space out of one. The keying does not protect against a party that can also
// *invoke* /acquire under the same key — the digest is deterministic per
// arguments, so such a party can test candidates by equality — and since the
// acquire response carries the full receipt, that party is every caller.
// Arguments are therefore non-secret against the gateway's caller set;
// SECURITY.md states the bound. The other consequence is deliberate and stated
// in SPEC.md §1.2: a public verifier cannot recompute this value, and does not
// need to, because the signature covers it.
func argumentsKey(seed []byte) []byte {
	sum := sha256.Sum256(append([]byte("judgment-pack-gateway/arguments-key/2:"), seed...))
	return sum[:]
}

type store struct {
	// root is where the filesystem kind keeps the store (SPEC.md §1.3)
	root      string
	artifacts blobSpace
	receipts  indexedSpace
	seed      []byte
	// private is the seed's key, nil where a key service signs
	private ed25519.PrivateKey
	// signing is what signs the store's receipts, shared with the registry
	// writer beside it (signer.go); publicKey and keyID are its key at start
	signing   *signerHolder
	publicKey ed25519.PublicKey
	keyID     string
	authority string
}

// newStore opens the store at root, of the filesystem kind: its artifacts
// and receipts directories made where they are not there.
func newStore(root string, seed []byte, authority string) (*store, error) {
	return newStoreWith(root, seed, nil, authority)
}

// newStoreWith is newStore signing through signing: the seed's key where it
// is nil. The seed keys the arguments commitment whichever signs.
func newStoreWith(root string, seed []byte, signing *signerHolder, authority string) (*store, error) {
	if len(seed) != seedBytes {
		return nil, fmt.Errorf("an Ed25519 signing seed is %d bytes", seedBytes)
	}
	kind := newFsKind(fsLayout{store: root})
	if err := kind.makeStore(); err != nil {
		return nil, err
	}
	return newStoreOnWith(root, kind.artifacts(), kind.receipts(), seed, signing, authority), nil
}

// newStoreOn is a store kept in the spaces given.
func newStoreOn(root string, artifacts blobSpace, receipts indexedSpace, seed []byte, authority string) *store {
	return newStoreOnWith(root, artifacts, receipts, seed, nil, authority)
}

// newStoreOnWith is newStoreOn signing through signing: the seed's key
// where it is nil.
func newStoreOnWith(root string, artifacts blobSpace, receipts indexedSpace, seed []byte, signing *signerHolder, authority string) *store {
	var private ed25519.PrivateKey
	if signing == nil {
		private = ed25519.NewKeyFromSeed(seed)
		signing = newSignerHolder(seedSigner{private: private})
	}
	key := signing.key()
	return &store{
		root: root, artifacts: artifacts, receipts: receipts,
		seed: seed, private: private, signing: signing, publicKey: key.public,
		keyID: key.keyID, authority: authority,
	}
}

// retain stores canonical result bytes under their own digest and returns the
// resultDigest a receipt carries.
func (s *store) retain(canonical []byte) (string, error) {
	return s.artifacts.putBlob(canonical)
}

// stamp signs a receipt core and appends it to its session. The caller supplies
// every member except keyId and signature.
func (s *store) stamp(core *vObject) (*vObject, string, error) {
	stored, signature, _, err := s.stampOwning(core)
	return stored, signature, err
}

// stampOwning is stamp, reporting as well whether this call made the
// session's directory: it is made exclusively, so a directory another
// process put there first -- at any moment before this call -- is found and
// never taken for this call's own. What a session's owner means is the
// gateway's business (sessionState.created); the store only says what it
// made.
func (s *store) stampOwning(core *vObject) (*vObject, string, bool, error) {
	return s.stampInto(core, nil)
}

// stampOwningAfter is stampOwning running before, where it is not nil, once
// the receipt's signature verifies and before anything is written: an
// acquisition's payload is retained there, so that a receipt that is not
// signed leaves nothing in the store (ADR-0050).
func (s *store) stampOwningAfter(core *vObject, before func() error) (*vObject, string, bool, error) {
	return s.stampInto(core, before)
}

func (s *store) stampInto(core *vObject, before func() error) (*vObject, string, bool, error) {
	sessionValue, ok := core.get("sessionId")
	if !ok {
		return nil, "", false, errors.New("receipt core has no sessionId")
	}
	sessionID, ok := sessionValue.(vString)
	if !ok {
		return nil, "", false, errors.New("sessionId is not a string")
	}
	if err := requireSession(string(sessionID)); err != nil {
		return nil, "", false, err
	}
	indexValue, ok := core.get("callIndex")
	if !ok {
		return nil, "", false, errors.New("receipt core has no callIndex")
	}
	index, ok := indexValue.(vInt)
	if !ok {
		return nil, "", false, errors.New("callIndex is not an integer")
	}
	// The canonical domain is ±(2⁵³−1) (SPEC.md §1.1). The parser enforces it
	// for incoming text; an internally constructed integer must be held to the
	// same bound, or the gateway would sign bytes its own format refuses.
	if int64(index) > maxSafeInteger || int64(index) < minSafeInteger {
		return nil, "", false, errors.New("callIndex is outside the canonical integer domain")
	}

	// One key signs the receipt and is named by it: read once, here, so a
	// rotation while the receipt is minted (registryWriter.rotateTo) leaves
	// it wholly under the key it was begun under or wholly under the next.
	key := s.signing.key()
	core.set("keyId", vString(key.keyID))
	if afterReceiptKeyChosen != nil {
		afterReceiptKeyChosen()
	}
	// The prefix carries the version (SPEC.md §1.2, §1.2a): a version 3 core
	// is signed under the version 3 context, so neither version's signature
	// can be presented as the other's.
	prefix := receiptContext
	if version, ok := memberString(core, "receiptVersion"); ok && version == receiptVersion3 {
		prefix = receiptContext3
	}
	// signed, and the signature held to the key, before anything is
	// written: a signer that does not sign mints nothing and leaves no
	// session made (ADR-0050)
	signature, err := key.signVerified(append([]byte(prefix), canon(core)...))
	if err != nil {
		return nil, "", false, err
	}
	signatureHex := hex.EncodeToString(signature)
	if before != nil {
		if err := before(); err != nil {
			return nil, "", false, err
		}
	}
	// The session is made once the receipt is signed; one that is there
	// already -- made by this process or another, or an entry of another
	// kind, which the create below answers for -- is not this call's own
	// either way.
	made, err := s.receipts.makeSeries(string(sessionID))
	if err != nil {
		return nil, "", false, err
	}

	stored := newObject()
	for _, name := range core.names {
		v, _ := core.get(name)
		stored.set(name, v)
	}
	stored.set("signature", vString(signatureHex))

	body := append(canon(stored), '\n')
	// created once at its index: a receipt is never replaced
	if err := s.receipts.createIndexed(string(sessionID), int64(index), body); err != nil {
		return nil, "", false, err
	}
	return stored, signatureHex, made, nil
}

// --- the seal registry (write side) ---------------------------------------

type registryWriter struct {
	// path names the registry in messages
	path string
	log  appendLog
	seed []byte
	// signing is what signs the seals, shared with the store beside it;
	// keyID is its key's at start
	signing *signerHolder
	keyID   string
	// switching is held by a seal and by a rotation (rotateTo), so that a
	// seal is judged and signed under the key it is appended under
	switching sync.Mutex
	// read is what the writer has walked of a log several writers append to
	// (judgedAppendLog), nil for any other
	read *registryRead
}

// registryRead is a writer's walk of the first offset bytes of a log several
// writers append to (judgedAppendLog), kept so that a seal reads and walks,
// in the append's transaction and under its lock, only the bytes appended
// since: a seal's cost is what was appended since the last, not the
// registry's size, which the transaction's idle bound and the lock every
// writer's seal waits for could not bear (#386). The log is append-only --
// the run-time login may only insert into it, and the schema (version 4)
// admits a record only at its end -- so the bytes before offset are the
// bytes walked. The line that ends at offset is kept as well, and found
// again where it was before what follows it is walked: a log that is not
// the one walked -- a database restored, or one that lost its last commits
// to a failover -- is read and walked whole again, as at the first seal.
//
// offset ends a line, or is 0: a last line not ended may yet be continued by
// another writer's append, and is walked again with what follows it. walk
// never holds a finding and ends at the writer's key; nil, the log is read
// whole. One seal at a time uses it, holding mu.
type registryRead struct {
	mu     sync.Mutex
	offset int64
	last   []byte
	walk   *registryWalk
}

// at moves the cursor to the end of data, the log's first bytes or those
// that follow the cursor, where data ends a line; walk is the walk of the
// log up to that end.
func (r *registryRead) at(from int64, data []byte, walk *registryWalk) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return
	}
	start := bytes.LastIndexByte(data[:len(data)-1], '\n') + 1
	r.offset, r.last, r.walk = from+int64(len(data)), bytes.Clone(data[start:]), walk
}

// judge reads, through read, what the cursor has not walked of the log, in
// the append's transaction, and walks it as engineWalk walks the registry,
// refusing as it refuses: it answers whether the log holds a seal of
// sessionID and the bytes read past the cursor. The cursor moves past them
// where they end a line: they are committed (the append's lock is held,
// and the read is at READ COMMITTED), and stay in the log whatever this
// append comes to.
func (r *registryRead) judge(read func(from int64) ([]byte, error), own ed25519.PublicKey, sessionID string) (bool, []byte, error) {
	if r.walk != nil {
		data, err := read(r.offset - int64(len(r.last)))
		switch {
		case err == nil && bytes.HasPrefix(data, r.last):
			more := data[len(r.last):]
			walk := r.walk.continued(more)
			if err := walk.ownReading(own); err != nil {
				return false, nil, err
			}
			_, sealed := walk.seals[sessionID]
			if !sealed {
				_, sealed = r.walk.seals[sessionID]
			}
			if len(more) > 0 && more[len(more)-1] == '\n' {
				r.walk.absorb(walk)
				r.at(r.offset, more, r.walk)
			}
			return sealed, more, nil
		case err != nil && faultOf(err) != faultRefused:
			return false, nil, err
		}
		// the line that ended at the cursor is not there, or the log ends
		// before it: read whole, as at the first seal
		r.offset, r.last, r.walk = 0, nil, nil
	}
	data, err := read(0)
	if err != nil {
		return false, nil, err
	}
	walk, err := engineWalk(data, own)
	if err != nil {
		return false, nil, err
	}
	_, sealed := walk.seals[sessionID]
	r.at(0, data, walk)
	return sealed, data, nil
}

// sealMayBeWritten is a failure to seal after the record may already be in
// the registry -- written and not made durable, or written in part: the
// session is to be taken as sealed by the process that asked, since a
// reader of the registry may find the seal there.
type sealMayBeWritten struct{ error }

// noHistory reports a store with no sessions: for a registry writer made
// where no store can hold any.
func noHistory() (bool, error) { return false, nil }

// newRegistryWriter opens the registry for sealing. history reports whether
// the store beside it holds a session: a registry that is not there is made
// only when it does not (SPEC.md §3).
func newRegistryWriter(path string, seed []byte, history func() (bool, error)) (*registryWriter, error) {
	return newRegistryWriterWith(path, seed, nil, history)
}

// newRegistryWriterWith is newRegistryWriter sealing through signing: the
// seed's key where it is nil.
func newRegistryWriterWith(path string, seed []byte, signing *signerHolder, history func() (bool, error)) (*registryWriter, error) {
	if len(seed) != seedBytes {
		return nil, fmt.Errorf("an Ed25519 signing seed is %d bytes", seedBytes)
	}
	// the registry is read by its spelling, so it is written by its
	// spelling too: a spelling the platform could resolve otherwise is
	// refused before a directory is made for it (SPEC.md §4.1)
	log, err := openFsLog(path)
	if err != nil {
		return nil, err
	}
	return newRegistryWriterOnWith(log, path, seed, signing, history)
}

// newRegistryWriterOn opens the registry kept in log for sealing; name
// names it in messages.
func newRegistryWriterOn(log appendLog, name string, seed []byte, history func() (bool, error)) (*registryWriter, error) {
	return newRegistryWriterOnWith(log, name, seed, nil, history)
}

// newRegistryWriterOnWith is newRegistryWriterOn sealing through signing:
// the seed's key where it is nil. The registry's walk must end at its key.
func newRegistryWriterOnWith(log appendLog, name string, seed []byte, signing *signerHolder, history func() (bool, error)) (*registryWriter, error) {
	if len(seed) != seedBytes {
		return nil, fmt.Errorf("an Ed25519 signing seed is %d bytes", seedBytes)
	}
	// The engine makes its registry, empty, when it starts without one, so
	// that from then on the registry's absence is never an empty registry
	// to it (loadEngineSeals): a device or a share that has gone away can
	// answer as a missing file does, and no lookup could tell the two
	// apart. What is at the path is judged as the verifier judges it first,
	// and the registry is made only where nothing is -- never through a
	// link to nothing, which an exclusive create does not follow.
	//
	// This one read decides, and the store's history is asked after it:
	// a registry seen present earlier, by anyone, authorizes nothing, since
	// it can be gone by now. A store that holds a session has run before,
	// and its registry may hold that session's seal -- an empty one made in
	// its place would reopen it. An operator who knows no session was ever
	// sealed makes the registry, empty, by hand.
	//
	// Where instances serve one database beside one another, another
	// instance's start may make the registry, and admit a session, between
	// this read and the history's answer: a store found holding sessions has
	// its registry read again before it is refused, and one there now is read
	// and walked as a registry found is. Nothing is made then, so nothing
	// could reopen a session.
	_, shared := log.(judgedAppendLog)
	existing, err := log.readLog(0)
	if faultOf(err) == faultAbsent {
		held, err := history()
		if err != nil {
			return nil, err
		}
		there := false
		if held && shared {
			existing, err = log.readLog(0)
			switch {
			case err == nil:
				there = true
			case faultOf(err) != faultAbsent:
				return nil, err
			}
		}
		switch {
		case there:
		case held:
			return nil, fmt.Errorf("the store holds sessions and the registry is not there: %s; restore the registry, or, knowing no session was ever sealed, make it empty by hand", name)
		default:
			if err := log.createLog(); err != nil {
				// Where instances serve one database beside one another, another
				// instance's start may have made the registry since this read: it
				// is there, and is read and walked as a registry found is.
				if !shared || faultOf(err) != faultTaken {
					return nil, err
				}
				if existing, err = log.readLog(0); err != nil {
					return nil, err
				}
			}
		}
	} else if err != nil {
		return nil, err
	}
	if signing == nil {
		signing = newSignerHolder(newSeedSigner(seed))
	}
	own := signing.key().public
	// The gateway's own reading of its registry (SPEC.md §3b): walked from
	// its first key, it must find nothing and end at this seed's key, or the
	// gateway does not start -- a rotation written and not switched to is
	// pending, and the seed it names is the one to start with.
	walk, err := engineWalk(existing, own)
	if err != nil {
		return nil, fmt.Errorf("registry %s: %w", name, err)
	}
	w := &registryWriter{
		path: name, log: log, seed: seed, signing: signing,
		keyID: keyIDFor(own),
	}
	if shared {
		// the start's walk is where the seals' reading starts from: up to
		// the last line ended, walked again where a line after it is not
		// (registryRead)
		w.read = &registryRead{}
		if cut := bytes.LastIndexByte(existing, '\n') + 1; cut == len(existing) {
			w.read.at(0, existing, walk)
		} else if prefix := walkRegistry(existing[:cut], registryFirstKey(existing, own)); prefix.ownReading(own) == nil {
			w.read.at(0, existing[:cut], prefix)
		}
	}
	return w, nil
}

// seal appends a signed final count. Append-only: sealing an already sealed
// session is refused, so a count can never be re-sealed to a smaller value.
// A session is already sealed when the registry holds a seal for it that
// the verifier loads (SPEC.md §3, §4 step 2), read by the verifier's own
// parseSeals: a line that names the session and is no such seal -- a
// signature that does not verify, a keyId not this gateway's, a member
// missing -- seals nothing, here as for /acquire (§6), and the new seal is
// appended beside it.
func (w *registryWriter) seal(sessionID string, finalCount int64, sealedAt string) (*vObject, error) {
	return w.appendSeal(sessionID, func(key *signingKey) (*vObject, error) {
		signature, err := key.signVerified(sealSigningInput(sessionID, finalCount, sealedAt, key.keyID))
		if err != nil {
			return nil, err
		}
		record := newObject()
		record.set("sessionId", vString(sessionID))
		record.set("finalCount", vInt(finalCount))
		record.set("sealedAt", vString(sealedAt))
		record.set("keyId", vString(key.keyID))
		record.set("signature", vString(hex.EncodeToString(signature)))
		return record, nil
	})
}

// sealOfScope seals a session of a scope identifier with a seal of version 3,
// which names it under the signature by its digest over the session's scope
// salt (saltedScopeDigest), so the registry line carries neither the scope
// identifier nor anything a guessed one could be tested against (ADR-0036,
// ADR-0042; SPEC.md §3, "A seal of version 3"), and a session of no scope
// ("") with seal, in §3's form, the bytes such a seal always had. A session
// that holds no receipt is sealed in §3's form too: no receipt carries a salt
// for a digest to be taken over, and none for the digest to be held to, so
// such a seal would name the scope to no reader, a session-removal record
// among them. A scope with no salt of its form is refused: every new seal
// naming a scope is of version 3.
func (w *registryWriter) sealOfScope(sessionID string, finalCount int64, sealedAt, scope, salt string) (*vObject, error) {
	if scope == "" || finalCount == 0 {
		return w.seal(sessionID, finalCount, sealedAt)
	}
	// what a reader would not load is not written
	if !isScopeIdentifier(scope) || !isScopeSalt(salt) || finalCount < 1 || finalCount > maxSafeInteger || !witnessTimeForm.MatchString(sealedAt) {
		return nil, fmt.Errorf("a seal of version 3 names a scope identifier of its form over a scope salt of 64 lowercase hexadecimal characters, counts from 1 to 2^53-1 receipts and is stamped YYYY-MM-DDThh:mm:ssZ")
	}
	return w.appendSeal(sessionID, func(key *signingKey) (*vObject, error) {
		record := newObject()
		record.set("finalCount", vInt(finalCount))
		record.set("keyId", vString(key.keyID))
		setScopeNaming(record, sessionID, scope, salt)
		record.set("sealedAt", vString(sealedAt))
		record.set("sessionId", vString(sessionID))
		signature, err := key.signVerified(signedOver(versionedSealContext(record), record))
		if err != nil {
			return nil, err
		}
		record.set("signature", vString(hex.EncodeToString(signature)))
		return record, nil
	})
}

// setScopeNaming sets the members by which a seal names scope: with a salt,
// the digest over it and sealVersion "3" (ADR-0042); with none, the digest
// of version 2 and sealVersion "2" (ADR-0036), which only a seal after an
// interruption of receipts an earlier release minted, carrying no salt, is
// written in.
func setScopeNaming(record *vObject, sessionID, scope, salt string) {
	if salt != "" {
		record.set("scopeDigest", vString(saltedScopeDigest(sessionID, scope, salt)))
		record.set("sealVersion", vString(sealVersionSalted))
		return
	}
	record.set("scopeDigest", vString(sealScopeDigest(sessionID, scope)))
	record.set("sealVersion", vString(sealVersionScoped))
}

// sealAfterInterruption appends a seal made after an interruption (SPEC.md
// §3c): the count of the receipts the store holds in a session an earlier
// process left open, the signature of the last of them, when, and by which
// path -- the operator's command or the gateway's start. It is refused as
// seal refuses, for a session the registry holds a seal of either kind for;
// what it seals, its caller has found whole.
func (w *registryWriter) sealAfterInterruption(sessionID string, finalCount int64, head, sealedAt, via string) (*vObject, error) {
	return w.sealAfterInterruptionOfScope(sessionID, finalCount, head, sealedAt, via, "", "")
}

// sealAfterInterruptionOfScope is sealAfterInterruption of a session every
// receipt of which carries the scope identifier scope and the scope salt salt:
// the seal carries the digest over the salt (saltedScopeDigest), never the
// identifier, and sealVersion "3", under its own prefix (ADR-0042); with no
// salt -- receipts an earlier release minted -- the digest of version 2 and
// sealVersion "2" (ADR-0036); scope "" is the eight members of §3c, as
// before.
func (w *registryWriter) sealAfterInterruptionOfScope(sessionID string, finalCount int64, head, sealedAt, via, scope, salt string) (*vObject, error) {
	// what a reader would not load is not written (SPEC.md §3c)
	if finalCount < 1 || finalCount > maxSafeInteger || !isLowerHexOfLen(head, 128) ||
		!witnessTimeForm.MatchString(sealedAt) || (via != sealedViaCommand && via != sealedViaStart) {
		return nil, fmt.Errorf("a seal after an interruption counts from 1 to 2^53-1 receipts, names the last one's signature in lowercase hexadecimal, is stamped YYYY-MM-DDThh:mm:ssZ, and is made by the command or the start")
	}
	if scope != "" && !isScopeIdentifier(scope) {
		return nil, fmt.Errorf("a seal after an interruption names a scope identifier of its form (%s), or none", scopeForm)
	}
	if salt != "" && (scope == "" || !isScopeSalt(salt)) {
		return nil, fmt.Errorf("a seal after an interruption names a scope salt of 64 lowercase hexadecimal characters with a scope identifier, or none")
	}
	return w.appendSeal(sessionID, func(key *signingKey) (*vObject, error) {
		record := newObject()
		record.set("finalCount", vInt(finalCount))
		record.set("headSignature", vString(head))
		record.set("keyId", vString(key.keyID))
		record.set("kind", vString(sealKindInterruption))
		if scope != "" {
			setScopeNaming(record, sessionID, scope, salt)
		}
		record.set("sealedAt", vString(sealedAt))
		record.set("sealedVia", vString(via))
		record.set("sessionId", vString(sessionID))
		signature, err := key.signVerified(interruptionSealSigningInput(record))
		if err != nil {
			return nil, err
		}
		record.set("signature", vString(hex.EncodeToString(signature)))
		return record, nil
	})
}

// errSessionAlreadySealed is a seal refused because the registry holds one
// for the session.
var errSessionAlreadySealed = errors.New("session already sealed")

// judgedAppendLog is a log that several writers append to -- the PostgreSQL
// kind's, where instances serve one database beside one another
// (docs/adr/0035-several-instances-on-one-postgresql-database.md, option
// C): an append is judged against the log as it stands under the append's
// own lock, read in the append's transaction, so two writers never each
// find a session unsealed and both append its seal.
type judgedAppendLog interface {
	// appendJudged takes the append's lock and appends what build answers,
	// as appendRecord appends; build reads the log through read, from a
	// cursor to its end, in the append's transaction, which sees every
	// record committed before the lock was taken, and no other until its
	// commit. A refusal of build appends nothing and is answered as it is.
	appendJudged(build func(read func(from int64) ([]byte, error)) ([]byte, error)) (int, error)
}

// afterSealJudged, where a test sets it, runs once a seal appended to a
// judgedAppendLog was judged and before it is appended.
var afterSealJudged func()

// appendSeal appends the record a session's seal is, once the registry,
// read as the verifier reads it, holds no seal for the session.
func (w *registryWriter) appendSeal(sessionID string, build func(*signingKey) (*vObject, error)) (*vObject, error) {
	if err := requireSession(sessionID); err != nil {
		return nil, err
	}
	w.switching.Lock()
	defer w.switching.Unlock()
	key := w.signing.key()
	if judged, ok := w.log.(judgedAppendLog); ok {
		return w.appendSealJudged(judged, sessionID, key, build)
	}
	// the registry is read as the verifier reads it (readRegistryBytes): a
	// registry that is there and cannot be read -- a link to nothing, a
	// directory or a share that cannot be reached -- is not an empty one,
	// and sealing into it could append a second seal for a session it
	// already holds, or make the target of a link to nothing
	existing, err := w.log.readLog(0)
	if faultOf(err) == faultAbsent {
		return nil, fmt.Errorf("the registry the engine made at its start is not there: %s", w.path)
	}
	if err != nil {
		return nil, err
	}
	// sealed as the verifier loads a seal, never as any parseable line
	// naming the session: a reader of its own would let the writer refuse
	// a session the verifier reports unsealed, and it could never be sealed.
	// The registry is walked from its first key (SPEC.md §3b), so a session
	// sealed under a key this gateway rotated from stays sealed, and a walk
	// that does not hold, or ends at another key, seals nothing.
	line, boundary, record, err := w.sealLine(existing, sessionID, key, build)
	if err != nil {
		return nil, err
	}

	// the registry is there (above); the log makes none where it went
	// away between the read and the append
	if n, err := w.log.appendRecord(line); err != nil {
		// once a byte of the record is written the seal may be there --
		// whole but for its newline, it loads -- and the session is taken
		// as sealed until a retry settles it; a newline ending an earlier
		// line is no part of the record. Written whole and not made
		// durable, it may be there too.
		if n > boundary || committed(err) {
			return nil, sealMayBeWritten{err}
		}
		return nil, err
	}
	return record, nil
}

// appendSealJudged is appendSeal on a log several writers append to: the
// registry is judged in the append's transaction, under its lock
// (judgedAppendLog), as read and walked since the writer's last reading of
// it (registryRead).
func (w *registryWriter) appendSealJudged(log judgedAppendLog, sessionID string, key *signingKey, build func(*signingKey) (*vObject, error)) (*vObject, error) {
	var record *vObject
	boundary := 0
	w.read.mu.Lock()
	defer w.read.mu.Unlock()
	n, err := log.appendJudged(func(read func(int64) ([]byte, error)) ([]byte, error) {
		sealed, more, err := w.read.judge(read, key.public, sessionID)
		if err != nil {
			return nil, err
		}
		if sealed {
			return nil, fmt.Errorf("%w: %s", errSessionAlreadySealed, sessionID)
		}
		// what is read ends where the log does, after the cursor, which
		// ends a line (registryRead)
		line, b, r, err := recordLine(more, key, build)
		if err != nil {
			return nil, err
		}
		if afterSealJudged != nil {
			afterSealJudged()
		}
		record, boundary = r, b
		return line, nil
	})
	if faultOf(err) == faultAbsent {
		return nil, fmt.Errorf("the registry the engine made at its start is not there: %s", w.path)
	}
	if err != nil {
		// as appendSeal answers a failed append
		if record != nil && (n > boundary || committed(err)) {
			return nil, sealMayBeWritten{err}
		}
		return nil, err
	}
	return record, nil
}

// sealLine judges existing, the registry's bytes, for a seal of sessionID:
// walked as the verifier walks it, it must hold no seal for the session. It
// answers the line that appends the record build makes, the offset in it
// where the record starts, and the record.
func (w *registryWriter) sealLine(existing []byte, sessionID string, key *signingKey, build func(*signingKey) (*vObject, error)) ([]byte, int, *vObject, error) {
	// sealed as the verifier loads a seal, never as any parseable line
	// naming the session (appendSeal)
	walk, err := engineWalk(existing, key.public)
	if err != nil {
		return nil, 0, nil, err
	}
	if _, sealed := walk.seals[sessionID]; sealed {
		return nil, 0, nil, fmt.Errorf("%w: %s", errSessionAlreadySealed, sessionID)
	}
	return recordLine(existing, key, build)
}

// recordLine is the line that appends the record build makes to a log whose
// bytes end as existing's do, and the offset in it where the record starts.
func recordLine(existing []byte, key *signingKey, build func(*signingKey) (*vObject, error)) ([]byte, int, *vObject, error) {
	record, err := build(key)
	if err != nil {
		return nil, 0, nil, err
	}
	// A record starts on a line of its own. A registry whose last line is
	// unterminated -- an earlier seal written in part, or whole but for its
	// newline -- is ended first: joined to that line, the record would make
	// one line that is no seal, and neither would load.
	var line []byte
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		line = append(line, '\n')
	}
	boundary := len(line)
	line = append(append(line, canon(record)...), '\n')
	return line, boundary, record, nil
}

func nowStamp() string {
	return time.Now().UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
}
