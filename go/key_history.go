package main

// The key history (SPEC.md §3e; docs/adr/0052-the-key-history-beside-the-public-key.md):
// every key the gateway's registry proves it signed under, in order, the key
// pinned first, each later key with the two statements of the rotation to
// it (§3b), so that a consumer that pinned the first key checks every entry
// from the answer alone, as it would follow the rotations in the registry.
// It is read from the registry as it stands at each request, and so is
// current across a rotation while serving, and, across a store rotation
// (§3d), from the history the rotation carried into the new store beside its
// registry, which the store continuation names by its digest; the answer is
// kept while the registry's bytes and the carried history's are the same.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
)

// keyHistoryRoute is the open path that answers the key history, beside
// /publickey.
const keyHistoryRoute = "/publickey/history"

const keyHistoryVersion = "1"

var (
	keyHistoryMembers      = map[string]bool{"keyHistoryVersion": true, "keys": true}
	keyHistoryEntryMembers = map[string]bool{"keyId": true, "publicKey": true, "validFrom": true, "validTo": true, "keyRotation": true, "keyContinuation": true}
)

// keyHistoryEntry is one key of a key history: validFrom and the two
// statements "" for the first key, validTo "" for the last, the key in force.
type keyHistoryEntry struct {
	key                ed25519.PublicKey
	keyID              string
	validFrom, validTo string
	forward, reverse   string
}

// historyOfWalk is the entries of the keys a walk reached, in order: each
// key's validTo the rotatedAt of the rotation from it.
func historyOfWalk(keys []reachedKey) []keyHistoryEntry {
	entries := make([]keyHistoryEntry, len(keys))
	for i, k := range keys {
		entries[i] = keyHistoryEntry{key: k.key, keyID: k.keyID, validFrom: k.rotatedAt, forward: k.forward, reverse: k.reverse}
		if i > 0 {
			entries[i-1].validTo = k.rotatedAt
		}
	}
	return entries
}

// keyHistoryDocument is the answer's bytes: canon of {keyHistoryVersion, keys}.
func keyHistoryDocument(entries []keyHistoryEntry) []byte {
	keys := vArray{}
	for _, e := range entries {
		obj := newObject()
		obj.set("keyId", vString(e.keyID))
		obj.set("publicKey", vString(hex.EncodeToString(e.key)))
		for name, v := range map[string]string{"validFrom": e.validFrom, "validTo": e.validTo, "keyRotation": e.forward, "keyContinuation": e.reverse} {
			if v != "" {
				obj.set(name, vString(v))
			}
		}
		keys = append(keys, obj)
	}
	doc := newObject()
	doc.set("keyHistoryVersion", vString(keyHistoryVersion))
	doc.set("keys", keys)
	return canon(doc)
}

// registryKeyHistory is the key history of a registry's bytes (SPEC.md
// §3e): the registry walked as the gateway walks its own (§3b), from its
// first key-continuation's previous key or from own, seals passed over; a
// walk with a finding, of its rotations or of its store continuation, is no
// history at all, never the keys reached before it. A registry whose first
// line is a store continuation continues the history carried beside it
// (present), whose bytes must be the ones the continuation names by its
// keyHistoryDigest, and which must hold from its own first key and end at
// the key that signed the continuation, the continuation's continuedAt
// within that key's validity -- at or after its validFrom, and before its
// validTo, the registry's first rotation, if any; a continued registry with none
// carried is refused, as is one carried beside a registry that continues
// none: a history cut short, or lost, is never answered as the whole.
func registryKeyHistory(data []byte, own ed25519.PublicKey, carried []byte, present bool) ([]keyHistoryEntry, error) {
	w := &registryWalk{seals: map[string]seal{}, conflicted: map[string]bool{}, keysOnly: true}
	first := registryFirstKey(data, own)
	w.keys = []reachedKey{{key: first, keyID: keyIDFor(first)}}
	w.walkLines(data)
	if w.finding != nil {
		return nil, fmt.Errorf("the registry's rotations do not hold: %s at rotation %d", w.finding["status"], w.finding["rotation"])
	}
	if w.continuationFinding != nil {
		return nil, fmt.Errorf("the registry's store continuation does not hold: %s", w.continuationFinding["status"])
	}
	// the walk starts at the key the registry's first key-continuation
	// names, which anyone who can append to the registry can name; it is
	// the gateway's history only where it ends at the gateway's own key, as
	// the gateway's own reading requires (ownReading), each key before then
	// named by the signature of the key after it
	if !bytes.Equal(w.current().key, own) {
		return nil, fmt.Errorf("the registry's rotations end at key %s, not this gateway's key %s", w.current().keyID, keyIDFor(own))
	}
	entries := historyOfWalk(w.keys)
	switch {
	case w.continuation == nil && !present:
		return entries, nil
	case w.continuation == nil:
		return nil, errors.New("a key history is carried beside a registry that continues no store")
	case !present:
		return nil, fmt.Errorf("the store continuation names the key history %s, and none is carried into the store", w.continuation.keyHistoryDigest)
	}
	if got := keyHistoryDigestOf(carried); got != w.continuation.keyHistoryDigest {
		return nil, fmt.Errorf("the key history carried into the store is %s, not the history %s the store continuation names", got, w.continuation.keyHistoryDigest)
	}
	before, err := checkKeyHistory(carried, nil)
	if err != nil {
		return nil, fmt.Errorf("the key history carried into the store: %w", err)
	}
	last := before[len(before)-1]
	if !bytes.Equal(last.key, first) {
		return nil, fmt.Errorf("the key history carried into the store ends at key %s, not key %s, which signed the store continuation", last.keyID, keyIDFor(first))
	}
	// the key in force at the store rotation is one key, its entry the
	// carried one's, and its end the registry's first rotation, if any; the
	// rotation was made while that key was in force: at or after its
	// validFrom, and before its validTo
	at := w.continuation.continuedAt
	if last.validFrom != "" && at < last.validFrom {
		return nil, errors.New("the store continuation's continuedAt is before the validFrom of the key in force at the store rotation")
	}
	if entries[0].validTo != "" && at >= entries[0].validTo {
		return nil, errors.New("the store continuation's continuedAt is not before the validTo of the key in force at the store rotation")
	}
	last.validTo = entries[0].validTo
	return append(append(before[:len(before)-1], last), entries[1:]...), nil
}

// checkKeyHistory is a consumer's check of a key history (SPEC.md §3e),
// from the key it pinned -- nil to take the first entry's, as the gateway
// does of a history carried into its store: one JSON object read by §1.1's
// parser, of exactly its members; the first entry the key pinned, with no
// validFrom and no statements; each later entry a key of §8.4's rule,
// reached by no earlier entry, and its two statements a rotation of §3b's
// form from the entry before it to it -- the key-rotation signed by the key
// before and naming this one, the key-continuation signed by this key and
// naming the one before, the two of one ordinal and one rotatedAt -- that
// rotatedAt its validFrom and the validTo of the entry before, and after
// the rotatedAt of the rotation before it, if any; and only the last entry
// without a validTo. The rotation's ordinal is held to its form
// alone: it is a count within one registry, and starts again at 1 after a
// store continuation (§3d).
func checkKeyHistory(doc []byte, pinned ed25519.PublicKey) ([]keyHistoryEntry, error) {
	v, err := parseJSON(doc)
	if err != nil {
		return nil, fmt.Errorf("not one JSON object: %w", err)
	}
	obj, ok := v.(*vObject)
	if !ok || !onlyMembers(obj, keyHistoryMembers) {
		return nil, errors.New("not an object of keyHistoryVersion and keys")
	}
	if version, _ := memberString(obj, "keyHistoryVersion"); version != keyHistoryVersion {
		return nil, errors.New("keyHistoryVersion is not \"1\"")
	}
	keysV, _ := obj.get("keys")
	keys, ok := keysV.(vArray)
	if !ok || len(keys) == 0 {
		return nil, errors.New("keys is not an array of at least one entry")
	}
	var entries []keyHistoryEntry
	seen := map[string]bool{}
	for i, kv := range keys {
		e, err := historyEntryOf(kv)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		if seen[e.keyID] {
			return nil, fmt.Errorf("entry %d: key %s is an earlier entry's", i, e.keyID)
		}
		seen[e.keyID] = true
		if i == 0 {
			if pinned != nil && !bytes.Equal(e.key, pinned) {
				return nil, fmt.Errorf("entry 0: key %s is not the key pinned", e.keyID)
			}
			if e.validFrom != "" || e.forward != "" || e.reverse != "" {
				return nil, errors.New("entry 0: the key pinned carries no validFrom and no rotation")
			}
		} else {
			before := entries[i-1]
			at, err := rotationPairHolds(before, e)
			if err != nil {
				return nil, fmt.Errorf("entry %d: %w", i, err)
			}
			if e.validFrom != at || before.validTo != at {
				return nil, fmt.Errorf("entry %d: validFrom, and the validTo before it, are not the rotation's rotatedAt %s", i, at)
			}
			// rotatedAt's form is fixed-width, so its order is its bytes'
			if before.validFrom != "" && at <= before.validFrom {
				return nil, fmt.Errorf("entry %d: the rotation's rotatedAt is not after the rotatedAt of the rotation before it", i)
			}
		}
		if (e.validTo == "") != (i == len(keys)-1) {
			return nil, fmt.Errorf("entry %d: only the last entry, the key in force, has no validTo", i)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// onlyMembers is whether obj's members are among allowed.
func onlyMembers(obj *vObject, allowed map[string]bool) bool {
	for name := range obj.byName {
		if !allowed[name] {
			return false
		}
	}
	return true
}

// historyEntryOf is one entry held to its form: a keyId and the publicKey
// it is the key id of, a key §8.4's rule accepts; validFrom and validTo, if
// given, of rotatedAt's form; and the two statements given together or not
// at all, each a string.
func historyEntryOf(v value) (keyHistoryEntry, error) {
	obj, ok := v.(*vObject)
	if !ok || !onlyMembers(obj, keyHistoryEntryMembers) {
		return keyHistoryEntry{}, errors.New("not an object of the entry's members")
	}
	var e keyHistoryEntry
	keyHex, okKey := memberString(obj, "publicKey")
	keyID, okID := memberString(obj, "keyId")
	if !okKey || !isLowerHexOfLen(keyHex, 64) || !okID {
		return e, errors.New("publicKey is not 64 lowercase hexadecimal characters, or keyId is missing")
	}
	e.key, _ = hex.DecodeString(keyHex)
	if e.keyID = keyID; keyIDFor(e.key) != keyID {
		return e, errors.New("keyId is not the key id of publicKey")
	}
	if publicKeyFault(e.key) != keySound {
		return e, errors.New("publicKey is a key §8.4's rule refuses")
	}
	for name, into := range map[string]*string{"validFrom": &e.validFrom, "validTo": &e.validTo, "keyRotation": &e.forward, "keyContinuation": &e.reverse} {
		if _, given := obj.get(name); !given {
			continue
		}
		s, ok := memberString(obj, name)
		if !ok || s == "" || (name == "validFrom" || name == "validTo") && !witnessTimeForm.MatchString(s) {
			return e, fmt.Errorf("%s is not of its form", name)
		}
		*into = s
	}
	if (e.forward == "") != (e.reverse == "") {
		return e, errors.New("keyRotation and keyContinuation are given together")
	}
	return e, nil
}

// rotationPairHolds is whether an entry's two statements are a rotation
// from the entry before it to it (SPEC.md §3b's checks, the ordinal's
// against its place aside), answering the rotation's rotatedAt.
func rotationPairHolds(before, e keyHistoryEntry) (string, error) {
	kind, obj := rotationKindOf(e.forward)
	if kind != rotationKindForward {
		return "", errors.New("keyRotation is not a key-rotation statement")
	}
	st, ok := rotationStatementOf(kind, obj)
	if !ok {
		return "", errors.New("keyRotation does not hold its form")
	}
	if st.keyID != before.keyID || !st.signedBy(before.key) {
		return "", errors.New("keyRotation is not signed by the key before it")
	}
	if !bytes.Equal(st.named, e.key) {
		return "", errors.New("keyRotation does not name this entry's key")
	}
	kind, obj = rotationKindOf(e.reverse)
	if kind != rotationKindReverse {
		return "", errors.New("keyContinuation is not a key-continuation statement")
	}
	reverse, ok := rotationStatementOf(kind, obj)
	if !ok || reverse.rotation != st.rotation || reverse.rotatedAt != st.rotatedAt ||
		!bytes.Equal(reverse.named, before.key) || reverse.keyID != e.keyID || !reverse.signedBy(e.key) {
		return "", errors.New("keyContinuation is not the key-continuation of keyRotation, signed by this entry's key")
	}
	return st.rotatedAt, nil
}

// keyHistoryBeside is the file beside a filesystem registry that holds the
// key history a store rotation carried into it (SPEC.md §3e), outside the
// registry's bytes.
func keyHistoryBeside(registryPath string) string { return registryPath + ".key-history" }

// readCarriedKeyHistory is the key history carried beside a filesystem
// registry, and whether there is one.
func readCarriedKeyHistory(registryPath string) ([]byte, bool, error) {
	data, err := os.ReadFile(keyHistoryBeside(registryPath))
	if absent(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

// carriedKeyHistory is the key history carried into the store the gateway
// serves, and whether there is one.
func (g *gatewayService) carriedKeyHistory() ([]byte, bool, error) {
	if g.kind != nil {
		// read through the kind, so that every instance on one database
		// answers the same; a kind that carries none answers none, and a
		// continuation naming one is answered 500, never a shorter history
		if carrier, carries := g.kind.(keyHistoryCarrier); carries {
			return carrier.carriedKeyHistory()
		}
		return nil, false, nil
	}
	return readCarriedKeyHistory(g.regPath)
}

// keyHistoryCarrier is a kind that keeps the key history a store rotation
// carried into it: the PostgreSQL kind, in gateway.key_history.
type keyHistoryCarrier interface {
	carriedKeyHistory() ([]byte, bool, error)
}

var _ keyHistoryCarrier = (*pgKind)(nil)

// keyHistoryAnswer is an answer to GET /publickey/history and what it was
// made of: the SHA-256 of the registry's bytes, the carried history's, and
// the gateway's key. The answer is the document, or the finding that the
// history does not hold (err), answered 500.
type keyHistoryAnswer struct {
	registry, carried [sha256.Size]byte
	present           bool
	own               string
	doc               []byte
	err               error
}

// keyHistoryKept is the last answer made, a document or a finding, kept for
// the requests after it while what it was made of is the same: the route is
// open, and a walk parses every line and checks each rotation's signatures,
// so a registry whose history does not hold is walked once per change of
// it, not once per request. walks counts the walks made.
type keyHistoryKept struct {
	mu    sync.Mutex
	last  *keyHistoryAnswer
	walks int
}

// keyHistory is the answer to GET /publickey/history: the history of the
// registry as it stands, with what was carried into its store, held to the
// consumer's check from its own first key before it is answered, so that an
// entry the chain does not prove is never served. The registry and the
// carried history are read at each request; the answer is made again
// whenever a byte of either, or the gateway's key, is not the last answer's;
// a finding is kept the same way as a document.
func (g *gatewayService) keyHistory() ([]byte, error) {
	data, err := g.registry.log.readLog(0)
	if faultOf(err) == faultAbsent {
		err = fmt.Errorf("the registry the engine made at its start is not there: %s", g.registry.path)
	}
	if err != nil {
		return nil, err
	}
	carried, present, err := g.carriedKeyHistory()
	if err != nil {
		return nil, fmt.Errorf("the key history carried into the store: %w", err)
	}
	own := g.ownKey()
	made := keyHistoryAnswer{registry: sha256.Sum256(data), carried: sha256.Sum256(carried), present: present, own: hex.EncodeToString(own)}
	g.keyHistoryKept.mu.Lock()
	defer g.keyHistoryKept.mu.Unlock()
	if last := g.keyHistoryKept.last; last != nil && last.registry == made.registry && last.carried == made.carried &&
		last.present == made.present && last.own == made.own {
		return last.doc, last.err
	}
	g.keyHistoryKept.walks++
	made.doc, made.err = walkKeyHistory(data, own, carried, present)
	g.keyHistoryKept.last = &made
	return made.doc, made.err
}

// walkKeyHistory is the key history document of a registry, with what was
// carried into its store, held to the consumer's check from its own first
// key, or the finding that it does not hold.
func walkKeyHistory(data []byte, own ed25519.PublicKey, carried []byte, present bool) ([]byte, error) {
	entries, err := registryKeyHistory(data, own, carried, present)
	if err != nil {
		return nil, err
	}
	doc := keyHistoryDocument(entries)
	if _, err := checkKeyHistory(doc, entries[0].key); err != nil {
		return nil, fmt.Errorf("the key history does not hold: %w", err)
	}
	return doc, nil
}
