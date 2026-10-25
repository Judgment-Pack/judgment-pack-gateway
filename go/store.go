package main

// The write path: content-addressed artifacts, signed chained receipts, and the
// signed seal registry. SPEC.md §1 is normative for every byte written here.
// The bytes are kept through the store contract (store_contract.go): the
// artifacts in a blob space, the receipts in an indexed space, the registry
// in an append log, each of the filesystem kind (store_fs.go) as shipped.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
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
	private   ed25519.PrivateKey
	publicKey ed25519.PublicKey
	keyID     string
	authority string
}

// newStore opens the store at root, of the filesystem kind: its artifacts
// and receipts directories made where they are not there.
func newStore(root string, seed []byte, authority string) (*store, error) {
	if len(seed) != seedBytes {
		return nil, fmt.Errorf("an Ed25519 signing seed is %d bytes", seedBytes)
	}
	kind := newFsKind(fsLayout{store: root})
	if err := kind.makeStore(); err != nil {
		return nil, err
	}
	return newStoreOn(root, kind.artifacts(), kind.receipts(), seed, authority), nil
}

// newStoreOn is a store kept in the spaces given.
func newStoreOn(root string, artifacts blobSpace, receipts indexedSpace, seed []byte, authority string) *store {
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	return &store{
		root: root, artifacts: artifacts, receipts: receipts,
		seed: seed, private: private, publicKey: public,
		keyID: keyIDFor(public), authority: authority,
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
	stored, signature, made, err := s.stampInto(core)
	return stored, signature, made, err
}

func (s *store) stampInto(core *vObject) (*vObject, string, bool, error) {
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
	// The session is made before anything is signed for it; one that is
	// there already -- made by this process or another, or an entry of
	// another kind, which the create below answers for -- is not this
	// call's own either way.
	made, err := s.receipts.makeSeries(string(sessionID))
	if err != nil {
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

	core.set("keyId", vString(s.keyID))
	// The prefix carries the version (SPEC.md §1.2, §1.2a): a version 3 core
	// is signed under the version 3 context, so neither version's signature
	// can be presented as the other's.
	prefix := receiptContext
	if version, ok := memberString(core, "receiptVersion"); ok && version == receiptVersion3 {
		prefix = receiptContext3
	}
	signature := ed25519.Sign(s.private, append([]byte(prefix), canon(core)...))
	signatureHex := hex.EncodeToString(signature)

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
	path  string
	log   appendLog
	seed  []byte
	priv  ed25519.PrivateKey
	keyID string
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
	return newRegistryWriterOn(log, path, seed, history)
}

// newRegistryWriterOn opens the registry kept in log for sealing; name
// names it in messages.
func newRegistryWriterOn(log appendLog, name string, seed []byte, history func() (bool, error)) (*registryWriter, error) {
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
	if _, err := log.readLog(0); faultOf(err) == faultAbsent {
		held, err := history()
		if err != nil {
			return nil, err
		}
		if held {
			return nil, fmt.Errorf("the store holds sessions and the registry is not there: %s; restore the registry, or, knowing no session was ever sealed, make it empty by hand", name)
		}
		if err := log.createLog(); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &registryWriter{
		path: name, log: log, seed: seed, priv: priv,
		keyID: keyIDFor(priv.Public().(ed25519.PublicKey)),
	}, nil
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
	if err := requireSession(sessionID); err != nil {
		return nil, err
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
	// a session the verifier reports unsealed, and it could never be sealed
	seals, _ := parseSeals(existing, w.priv.Public().(ed25519.PublicKey))
	if _, sealed := seals[sessionID]; sealed {
		return nil, fmt.Errorf("session already sealed: %s", sessionID)
	}

	signature := ed25519.Sign(w.priv, sealSigningInput(sessionID, finalCount, sealedAt, w.keyID))
	record := newObject()
	record.set("sessionId", vString(sessionID))
	record.set("finalCount", vInt(finalCount))
	record.set("sealedAt", vString(sealedAt))
	record.set("keyId", vString(w.keyID))
	record.set("signature", vString(hex.EncodeToString(signature)))

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

func nowStamp() string {
	return time.Now().UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
}
