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

// keyHistoryVersion2 is the key history that marks each store
// continuation it crosses (SPEC.md §3e, version 2; ADR-0055).
const keyHistoryVersion2 = "2"

// keyHistoryV2Version is the engine version whose configuration may hold
// keyHistoryVersion: "2" (ADR-0055 §8).
const keyHistoryV2Version = "42"

var (
	keyHistoryMembers      = map[string]bool{"keyHistoryVersion": true, "keys": true}
	keyHistoryEntryMembers = map[string]bool{"alg": true, "keyId": true, "publicKey": true, "validFrom": true, "validTo": true, "keyRotation": true, "keyContinuation": true}
	keyHistoryV2Members    = map[string]bool{"keyHistoryVersion": true, "stores": true, "base": true}
	keyHistoryStoreMembers = map[string]bool{"keys": true, "continuation": true}
)

// The classes of a consumer's refusal of a key history (ADR-0055 §9), which
// the corpus compares, not only the verdict.
const (
	refusedVersion      = "version"
	refusedForm         = "form"
	refusedKey          = "key"
	refusedRotation     = "rotation"
	refusedOrdinal      = "ordinal"
	refusedTime         = "time"
	refusedContinuation = "continuation"
	refusedCarried      = "carried"
)

// keyHistoryRefusal is a check's refusal of a key history, with its class;
// its sentence is the refusal's own.
type keyHistoryRefusal struct {
	class string
	err   error
}

func (r *keyHistoryRefusal) Error() string { return r.err.Error() }
func (r *keyHistoryRefusal) Unwrap() error { return r.err }

func refuseHistory(class string, err error) error { return &keyHistoryRefusal{class: class, err: err} }

// keyHistoryRefusalClass is the class of a check's refusal, "" for an error
// that is none.
func keyHistoryRefusalClass(err error) string {
	var r *keyHistoryRefusal
	if errors.As(err, &r) {
		return r.class
	}
	return ""
}

// keyHistoryEntry is one key of a key history: validFrom and the two
// statements "" for the first key, validTo "" for the last, the key in force.
type keyHistoryEntry struct {
	key   []byte
	keyID string
	// alg is the key's algorithm, "ES256" for a P-256 key (ADR-0053 §8)
	alg                string
	validFrom, validTo string
	forward, reverse   string
}

// held is the entry's key with its algorithm.
func (e keyHistoryEntry) held() heldKey { return heldKey{alg: e.alg, key: e.key} }

// historyOfWalk is the entries of the keys a walk reached, in order: each
// key's validTo the rotatedAt of the rotation from it.
func historyOfWalk(keys []reachedKey) []keyHistoryEntry {
	entries := make([]keyHistoryEntry, len(keys))
	for i, k := range keys {
		entries[i] = keyHistoryEntry{key: k.key, keyID: k.keyID, alg: k.alg, validFrom: k.rotatedAt, forward: k.forward, reverse: k.reverse}
		if i > 0 {
			entries[i-1].validTo = k.rotatedAt
		}
	}
	return entries
}

// keyHistoryKeys is the keys member of a history: each entry an object of
// the members it has.
func keyHistoryKeys(entries []keyHistoryEntry) vArray {
	keys := vArray{}
	for _, e := range entries {
		obj := newObject()
		setAlg(obj, "alg", e.alg)
		obj.set("keyId", vString(e.keyID))
		obj.set("publicKey", vString(hex.EncodeToString(e.key)))
		for name, v := range map[string]string{"validFrom": e.validFrom, "validTo": e.validTo, "keyRotation": e.forward, "keyContinuation": e.reverse} {
			if v != "" {
				obj.set(name, vString(v))
			}
		}
		keys = append(keys, obj)
	}
	return keys
}

// keyHistoryDocument is the answer's bytes: canon of {keyHistoryVersion, keys}.
func keyHistoryDocument(entries []keyHistoryEntry) []byte {
	doc := newObject()
	doc.set("keyHistoryVersion", vString(keyHistoryVersion))
	doc.set("keys", keyHistoryKeys(entries))
	return canon(doc)
}

// keyHistoryDocumentV2 is the answer's bytes under version 2 (ADR-0055 §1):
// canon of {base, keyHistoryVersion, stores}, the stores carried and base,
// where one is carried (nil for none), as they were carried, and this
// registry's store after them: its keys, and its first line, the store
// continuation, where it continues one ("" for none).
func keyHistoryDocumentV2(base value, carried vArray, line string, entries []keyHistoryEntry) []byte {
	store := newObject()
	if line != "" {
		store.set("continuation", vString(line))
	}
	store.set("keys", keyHistoryKeys(entries))
	doc := newObject()
	if base != nil {
		doc.set("base", base)
	}
	doc.set("keyHistoryVersion", vString(keyHistoryVersion2))
	doc.set("stores", append(append(vArray{}, carried...), store))
	return canon(doc)
}

// keyHistoryMade is the key history a gateway makes of its registry: every
// key once, in order, the key at a store rotation one entry; the answer's
// bytes; and the history's last time, the later of its last validFrom and,
// under version 2, its last continuedAt, "" for none.
type keyHistoryMade struct {
	entries []keyHistoryEntry
	doc     []byte
	last    string
}

// registryKeyHistory is registryKeyHistoryOf's entries, under the version
// the carried history implies, as a command given by its flags makes it.
func registryKeyHistory(data []byte, own heldKey, carried []byte, present bool) ([]keyHistoryEntry, error) {
	made, err := registryKeyHistoryOf(data, own, carried, present, "")
	return made.entries, err
}

// servedKeyHistoryVersion is the version of the key history a gateway
// answers (ADR-0055 §4): "2" where configured is "2" or the carried history
// is of version "2", and otherwise "1".
func servedKeyHistoryVersion(configured string, carried []byte, present bool) string {
	if configured == keyHistoryVersion2 || present && carriedHistoryVersion(carried) == keyHistoryVersion2 {
		return keyHistoryVersion2
	}
	return keyHistoryVersion
}

// servedKeyHistory is the version of the key history an instance on the
// kind answers under configured, the history carried into the database
// read: what its row of the start lease records (ADR-0062). A read that
// fails fails the start.
func (k *pgKind) servedKeyHistory(configured string) (string, error) {
	if configured == keyHistoryVersion2 {
		return keyHistoryVersion2, nil
	}
	carried, present, err := k.carriedKeyHistory()
	if err != nil {
		return "", err
	}
	return servedKeyHistoryVersion(configured, carried, present), nil
}

// carriedHistoryVersion is the version of a carried history: "2" where it
// says so, and otherwise "1", whose check refuses whatever it is not.
func carriedHistoryVersion(carried []byte) string {
	if v, err := parseJSON(carried); err == nil {
		if obj, ok := v.(*vObject); ok {
			if version, _ := memberString(obj, "keyHistoryVersion"); version == keyHistoryVersion2 {
				return keyHistoryVersion2
			}
		}
	}
	return keyHistoryVersion
}

// registryFirstLine is a registry's first line, without its 0x0A.
func registryFirstLine(data []byte) string {
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return string(data[:i])
	}
	return string(data)
}

// registryKeyHistoryOf is the key history of a registry's bytes (SPEC.md
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
//
// The version (ADR-0055 §4) is "2" where configured is "2" or the carried
// history is of version "2", which no configuration takes back, and
// otherwise "1", byte for byte as before. Under "2" a carried history of
// version "1" is base, and one of version "2" gives its base and stores;
// either is answered as it was carried, so its bytes must be canon of its
// value; and the answer is held to the consumer's check before it is made.
func registryKeyHistoryOf(data []byte, own heldKey, carried []byte, present bool, configured string) (keyHistoryMade, error) {
	w := &registryWalk{seals: map[string]seal{}, conflicted: map[string]bool{}, keysOnly: true}
	first := registryFirstKey(data, own)
	w.keys = []reachedKey{{key: first.key, alg: first.alg, keyID: first.keyID()}}
	w.walkLines(data)
	if w.finding != nil {
		return keyHistoryMade{}, fmt.Errorf("the registry's rotations do not hold: %s at rotation %d", w.finding["status"], w.finding["rotation"])
	}
	if w.continuationFinding != nil {
		return keyHistoryMade{}, fmt.Errorf("the registry's store continuation does not hold: %s", w.continuationFinding["status"])
	}
	// the walk starts at the key the registry's first key-continuation
	// names, which anyone who can append to the registry can name; it is
	// the gateway's history only where it ends at the gateway's own key, as
	// the gateway's own reading requires (ownReading), each key before then
	// named by the signature of the key after it
	if !w.current().held().is(own) {
		return keyHistoryMade{}, fmt.Errorf("the registry's rotations end at key %s, not this gateway's key %s", w.current().keyID, own.keyID())
	}
	entries := historyOfWalk(w.keys)
	version := servedKeyHistoryVersion(configured, carried, present)
	switch {
	case w.continuation == nil && !present:
		if version == keyHistoryVersion2 {
			return madeOfVersion2(keyHistoryDocumentV2(nil, nil, "", entries))
		}
		return keyHistoryMade{entries: entries, doc: keyHistoryDocument(entries), last: entries[len(entries)-1].validFrom}, nil
	case w.continuation == nil:
		return keyHistoryMade{}, errors.New("a key history is carried beside a registry that continues no store")
	case !present:
		return keyHistoryMade{}, fmt.Errorf("the store continuation names the key history %s, and none is carried into the store", w.continuation.keyHistoryDigest)
	}
	if got := keyHistoryDigestOf(carried); got != w.continuation.keyHistoryDigest {
		return keyHistoryMade{}, fmt.Errorf("the key history carried into the store is %s, not the history %s the store continuation names", got, w.continuation.keyHistoryDigest)
	}
	before, err := checkKeyHistoryOf(carried, nil, "")
	if err != nil {
		return keyHistoryMade{}, fmt.Errorf("the key history carried into the store: %w", err)
	}
	last := before.entries[len(before.entries)-1]
	if !last.held().is(first) {
		return keyHistoryMade{}, fmt.Errorf("the key history carried into the store ends at key %s, not key %s, which signed the store continuation", last.keyID, first.keyID())
	}
	// the key in force at the store rotation is one key, its entry the
	// carried one's, and its end the registry's first rotation, if any; the
	// rotation was made while that key was in force: at or after its
	// validFrom, and not after its validTo. Two of one second are not
	// told apart, since the writers hold the clock's form alone
	at := w.continuation.continuedAt
	if last.validFrom != "" && at < last.validFrom {
		return keyHistoryMade{}, errors.New("the store continuation's continuedAt is before the validFrom of the key in force at the store rotation")
	}
	if entries[0].validTo != "" && at > entries[0].validTo {
		return keyHistoryMade{}, errors.New("the store continuation's continuedAt is after the validTo of the key in force at the store rotation")
	}
	if version == keyHistoryVersion {
		last.validTo = entries[0].validTo
		spliced := append(append(before.entries[:len(before.entries)-1], last), entries[1:]...)
		return keyHistoryMade{entries: spliced, doc: keyHistoryDocument(spliced), last: spliced[len(spliced)-1].validFrom}, nil
	}
	// version 2 answers what was carried as it was carried, which canon of
	// its value is only where the bytes are canon: a gateway's own writing
	// always is, and any other is answered 500, never rewritten
	if !bytes.Equal(canon(before.value), carried) {
		return keyHistoryMade{}, errors.New(`the key history carried into the store is not in canon form (SPEC.md §1.1), so it is not answered within a history of version "2"`)
	}
	var base value = before.value
	var stores vArray
	if before.version == keyHistoryVersion2 {
		base, _ = before.value.get("base")
		storesV, _ := before.value.get("stores")
		stores, _ = storesV.(vArray)
	}
	return madeOfVersion2(keyHistoryDocumentV2(base, stores, registryFirstLine(data), entries))
}

// madeOfVersion2 is a version 2 answer held to the consumer's check from its
// own first key, with what the check reads of it.
func madeOfVersion2(doc []byte) (keyHistoryMade, error) {
	checked, err := checkKeyHistoryOf(doc, nil, "")
	if err != nil {
		return keyHistoryMade{}, fmt.Errorf("the key history does not hold: %w", err)
	}
	return keyHistoryMade{entries: checked.entries, doc: doc, last: checked.latest}, nil
}

// checkKeyHistory is checkKeyHistoryOf's entries, from the key pinned with
// its algorithm (nil to take the first entry's), whatever its length.
func checkKeyHistory(doc []byte, pin *heldKey) ([]keyHistoryEntry, error) {
	checked, err := checkKeyHistoryOf(doc, pin, "")
	return checked.entries, err
}

// checkedKeyHistory is what a consumer's check reads of a history that
// holds: its version; every key once, in order, the key at a store rotation
// one entry whose validTo is its last; the latest of its rotatedAt and
// continuedAt values; and the history's value.
type checkedKeyHistory struct {
	version string
	entries []keyHistoryEntry
	latest  string
	value   *vObject
}

// checkKeyHistoryOf is a consumer's check of a key history (SPEC.md §3e),
// from the key it pinned, with its algorithm -- nil to take the first
// entry's, as the gateway does of a history carried into its store: one
// JSON object read by §1.1's parser, its keyHistoryVersion read first, "1"
// or "2", and "2" where requireVersion is "2". Version 1: exactly its
// members; the first entry the key pinned, with no validFrom and no
// statements; each later entry a key of §8.4's rule, reached by no earlier
// entry, and its two statements a rotation of §3b's form from the entry
// before it to it -- the key-rotation signed by the key before and naming
// this one, the key-continuation signed by this key and naming the one
// before, the two of one ordinal and one rotatedAt -- that rotatedAt its
// validFrom and the validTo of the entry before, and after the rotatedAt of
// the rotation before it, if any; and only the last entry without a
// validTo. The rotation's ordinal is held to its form alone: it is a count
// within one registry, and starts again at 1 after a store continuation
// (§3d), which version 1 does not mark. Version 2 (ADR-0055 §2) is
// checkKeyHistoryV2's. A refusal names its class (keyHistoryRefusalClass).
func checkKeyHistoryOf(doc []byte, pinned *heldKey, requireVersion string) (checkedKeyHistory, error) {
	if requireVersion != "" && requireVersion != keyHistoryVersion2 {
		return checkedKeyHistory{}, refuseHistory(refusedVersion, errors.New(`requireVersion is "2", or absent`))
	}
	v, err := parseJSON(doc)
	if err != nil {
		return checkedKeyHistory{}, refuseHistory(refusedForm, fmt.Errorf("not one JSON object: %w", err))
	}
	obj, ok := v.(*vObject)
	if !ok {
		return checkedKeyHistory{}, refuseHistory(refusedForm, errors.New("not an object of keyHistoryVersion and keys"))
	}
	s := &keyHistoryState{seen: map[string]bool{}}
	var entries []keyHistoryEntry
	switch version, _ := memberString(obj, "keyHistoryVersion"); {
	case version == keyHistoryVersion2:
		entries, err = s.checkKeyHistoryV2(obj, pinned)
	case version != keyHistoryVersion:
		return checkedKeyHistory{}, refuseHistory(refusedVersion, errors.New(`keyHistoryVersion is not "1" or "2"`))
	case requireVersion == keyHistoryVersion2:
		return checkedKeyHistory{}, refuseHistory(refusedVersion, errors.New(`keyHistoryVersion is "1", and version "2" is required`))
	default:
		entries, err = s.checkKeyHistoryV1(obj, pinned)
	}
	if err != nil {
		return checkedKeyHistory{}, err
	}
	version, _ := memberString(obj, "keyHistoryVersion")
	return checkedKeyHistory{version: version, entries: entries, latest: s.latest, value: obj}, nil
}

// keyHistoryState is what a check carries from entry to entry, and across
// base and the stores: the keyId of every entry before, the rotatedAt of
// the last rotation, and the latest of every rotatedAt and continuedAt.
type keyHistoryState struct {
	seen          map[string]bool
	lastRotatedAt string
	latest        string
}

// checkKeyHistoryV1 holds a history of version 1, or base, to its check.
func (s *keyHistoryState) checkKeyHistoryV1(obj *vObject, pinned *heldKey) ([]keyHistoryEntry, error) {
	if !onlyMembers(obj, keyHistoryMembers) {
		return nil, refuseHistory(refusedForm, errors.New("not an object of keyHistoryVersion and keys"))
	}
	keysV, _ := obj.get("keys")
	keys, ok := keysV.(vArray)
	if !ok || len(keys) == 0 {
		return nil, refuseHistory(refusedForm, errors.New("keys is not an array of at least one entry"))
	}
	return s.keysHold(keys, func(e keyHistoryEntry) error { return pinnedFirst(e, pinned) }, false, false)
}

// pinnedFirst holds a first entry to the key pinned, nil for none.
func pinnedFirst(e keyHistoryEntry, pinned *heldKey) error {
	if pinned != nil && !e.held().is(*pinned) {
		return refuseHistory(refusedKey, fmt.Errorf("entry 0: key %s is not the key pinned", e.keyID))
	}
	return nil
}

// checkKeyHistoryV2 holds a history of version 2 to its check (SPEC.md §3e,
// "Checking version 2"; ADR-0055 §2): exactly keyHistoryVersion, stores and,
// optionally, base, a history of version 1 held to its check from the key
// pinned; each store exactly keys and, in every store but the first and in
// the first where base is present, continuation; each store's keys held to
// version 1's check, its first entry the key pinned (the first store, no
// base) or the key of the last entry before it, no other entry the key of
// an earlier one, and the entry at place i with rotation i; and each
// continuation of §3d's form, of the store's first key's keyId and alg and
// signed by it, naming by keyHistoryDigest the history before it, and
// stamped at or after every rotatedAt and continuedAt before it and not
// after the validTo of the store's first entry.
func (s *keyHistoryState) checkKeyHistoryV2(obj *vObject, pinned *heldKey) ([]keyHistoryEntry, error) {
	if !onlyMembers(obj, keyHistoryV2Members) {
		return nil, refuseHistory(refusedForm, errors.New("not an object of keyHistoryVersion, stores and base"))
	}
	storesV, _ := obj.get("stores")
	stores, ok := storesV.(vArray)
	if !ok || len(stores) == 0 {
		return nil, refuseHistory(refusedForm, errors.New("stores is not an array of at least one store"))
	}
	var entries []keyHistoryEntry
	base, hasBase := obj.get("base")
	if hasBase {
		baseObj, ok := base.(*vObject)
		if !ok {
			return nil, refuseHistory(refusedForm, errors.New(`base is not a history of version "1"`))
		}
		if version, _ := memberString(baseObj, "keyHistoryVersion"); version != keyHistoryVersion {
			return nil, refuseHistory(refusedForm, errors.New(`base is not a history of version "1"`))
		}
		held, err := s.checkKeyHistoryV1(baseObj, pinned)
		if err != nil {
			return nil, fmt.Errorf("base: %w", err)
		}
		entries = held
	}
	for j, sv := range stores {
		store, ok := sv.(*vObject)
		if !ok || !onlyMembers(store, keyHistoryStoreMembers) {
			return nil, refuseHistory(refusedForm, fmt.Errorf("store %d: not an object of keys and continuation", j))
		}
		joined := j > 0 || hasBase
		lineV, hasLine := store.get("continuation")
		line, isString := lineV.(vString)
		if hasLine != joined || hasLine && !isString {
			return nil, refuseHistory(refusedForm, fmt.Errorf("store %d: a continuation, a string, is held by every store but the first, and by the first where base is present, and by no other", j))
		}
		keysV, _ := store.get("keys")
		keys, ok := keysV.(vArray)
		if !ok || len(keys) == 0 {
			return nil, refuseHistory(refusedForm, fmt.Errorf("store %d: keys is not an array of at least one entry", j))
		}
		first := func(e keyHistoryEntry) error {
			if !joined {
				return pinnedFirst(e, pinned)
			}
			prev := entries[len(entries)-1]
			if e.keyID != prev.keyID || !e.held().is(prev.held()) {
				return refuseHistory(refusedKey, fmt.Errorf("entry 0: key %s is not key %s, the last before it", e.keyID, prev.keyID))
			}
			return s.continuationHolds(string(line), e, historyBefore(base, hasBase, stores[:j]))
		}
		held, err := s.keysHold(keys, first, joined, true)
		if err != nil {
			return nil, fmt.Errorf("store %d: %w", j, err)
		}
		if joined {
			entries[len(entries)-1].validTo = held[0].validTo
			held = held[1:]
		}
		entries = append(entries, held...)
	}
	return entries, nil
}

// historyBefore is the bytes of the history before a store: base, for the
// first store, and otherwise canon of {base, keyHistoryVersion, stores}, the
// stores before it and base where present.
func historyBefore(base value, hasBase bool, stores vArray) []byte {
	if len(stores) == 0 {
		return canon(base)
	}
	doc := newObject()
	if hasBase {
		doc.set("base", base)
	}
	doc.set("keyHistoryVersion", vString(keyHistoryVersion2))
	doc.set("stores", stores)
	return canon(doc)
}

// continuationHolds holds a store's continuation line to §3d's form, signed
// by the store's first key e, to the history before it, and to the time
// before it and e's validTo.
func (s *keyHistoryState) continuationHolds(line string, e keyHistoryEntry, before []byte) error {
	obj := continuationLine(line)
	if obj == nil {
		return refuseHistory(refusedContinuation, errors.New("continuation is not a store continuation"))
	}
	c, ok := continuationOf(obj, reachedKey{key: e.key, keyID: e.keyID, alg: e.alg})
	if !ok {
		return refuseHistory(refusedContinuation, errors.New("continuation does not hold §3d's form, or is not of and signed by the store's first key"))
	}
	if got := keyHistoryDigestOf(before); got != c.keyHistoryDigest {
		return refuseHistory(refusedCarried, fmt.Errorf("continuation names the key history %s, not %s, the history before it", c.keyHistoryDigest, got))
	}
	if c.continuedAt < s.latest {
		return refuseHistory(refusedTime, fmt.Errorf("continuation's continuedAt %s is before %s, a rotatedAt or continuedAt before it", c.continuedAt, s.latest))
	}
	if e.validTo != "" && c.continuedAt > e.validTo {
		return refuseHistory(refusedTime, fmt.Errorf("continuation's continuedAt %s is after %s, the validTo of the store's first key", c.continuedAt, e.validTo))
	}
	s.latest = c.continuedAt
	return nil
}

// keysHold holds one list of entries to version 1's check, entry by entry:
// the first to first, and, where joined, the key at a store rotation, an
// earlier entry's key, which no other entry is; and where ordinals, each
// later entry's rotation its place in the list.
func (s *keyHistoryState) keysHold(keys vArray, first func(keyHistoryEntry) error, joined, ordinals bool) ([]keyHistoryEntry, error) {
	var entries []keyHistoryEntry
	for i, kv := range keys {
		e, err := historyEntryOf(kv)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		if i > 0 || !joined {
			if s.seen[e.keyID] {
				return nil, refuseHistory(refusedKey, fmt.Errorf("entry %d: key %s is an earlier entry's", i, e.keyID))
			}
			s.seen[e.keyID] = true
		}
		if i == 0 {
			if err := first(e); err != nil {
				return nil, err
			}
			if e.validFrom != "" || e.forward != "" || e.reverse != "" {
				if joined {
					return nil, refuseHistory(refusedForm, errors.New("entry 0: a store's first key carries no validFrom and no rotation"))
				}
				return nil, refuseHistory(refusedForm, errors.New("entry 0: the key pinned carries no validFrom and no rotation"))
			}
		} else {
			before := entries[i-1]
			ordinal, at, err := rotationPairOf(before, e)
			if err != nil {
				return nil, refuseHistory(refusedRotation, fmt.Errorf("entry %d: %w", i, err))
			}
			if ordinals && ordinal != int64(i) {
				return nil, refuseHistory(refusedOrdinal, fmt.Errorf("entry %d: the rotation's ordinal is %d, not %d, its place in its store", i, ordinal, i))
			}
			if e.validFrom != at || before.validTo != at {
				return nil, refuseHistory(refusedTime, fmt.Errorf("entry %d: validFrom, and the validTo before it, are not the rotation's rotatedAt %s", i, at))
			}
			// rotatedAt's form is fixed-width, so its order is its bytes';
			// two rotations of one second, which the writers make (two
			// SIGHUPs, or a clock stepped back to the same second), hold
			if s.lastRotatedAt != "" && at < s.lastRotatedAt {
				return nil, refuseHistory(refusedTime, fmt.Errorf("entry %d: the rotation's rotatedAt is before the rotatedAt of the rotation before it", i))
			}
			s.lastRotatedAt = at
			if at > s.latest {
				s.latest = at
			}
		}
		if (e.validTo == "") != (i == len(keys)-1) {
			return nil, refuseHistory(refusedForm, fmt.Errorf("entry %d: only the last entry, the key in force, has no validTo", i))
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
		return keyHistoryEntry{}, refuseHistory(refusedForm, errors.New("not an object of the entry's members"))
	}
	var e keyHistoryEntry
	keyHex, okKey := memberString(obj, "publicKey")
	keyID, okID := memberString(obj, "keyId")
	// alg (ADR-0053 §8): present exactly for a P-256 key, whose publicKey
	// is its compressed point
	alg, okAlg := recordAlg(obj, "alg")
	if !okAlg {
		return e, refuseHistory(refusedForm, errors.New(`alg is not "ES256"`))
	}
	if e.alg = alg; alg == algES256 && (!okKey || !isLowerHexOfLen(keyHex, publicKeyHexLen(algES256)) || !okID) {
		return e, refuseHistory(refusedForm, errors.New("publicKey is not 66 lowercase hexadecimal characters under alg ES256, or keyId is missing"))
	}
	if alg == algEd25519 && (!okKey || !isLowerHexOfLen(keyHex, 64) || !okID) {
		return e, refuseHistory(refusedForm, errors.New("publicKey is not 64 lowercase hexadecimal characters, or keyId is missing"))
	}
	e.key, _ = hex.DecodeString(keyHex)
	if e.keyID = keyID; keyIDFor(e.key) != keyID {
		return e, refuseHistory(refusedKey, errors.New("keyId is not the key id of publicKey"))
	}
	if !keySoundFor(e.alg, e.key) {
		return e, refuseHistory(refusedKey, errors.New("publicKey is a key §8.4's rule refuses"))
	}
	for name, into := range map[string]*string{"validFrom": &e.validFrom, "validTo": &e.validTo, "keyRotation": &e.forward, "keyContinuation": &e.reverse} {
		if _, given := obj.get(name); !given {
			continue
		}
		s, ok := memberString(obj, name)
		if !ok || s == "" || (name == "validFrom" || name == "validTo") && !witnessTimeForm.MatchString(s) {
			return e, refuseHistory(refusedForm, fmt.Errorf("%s is not of its form", name))
		}
		*into = s
	}
	if (e.forward == "") != (e.reverse == "") {
		return e, refuseHistory(refusedForm, errors.New("keyRotation and keyContinuation are given together"))
	}
	return e, nil
}

// rotationPairOf is whether an entry's two statements are a rotation from
// the entry before it to it (SPEC.md §3b's checks, the ordinal's against its
// place aside), answering the rotation's ordinal and rotatedAt.
func rotationPairOf(before, e keyHistoryEntry) (int64, string, error) {
	kind, obj := rotationKindOf(e.forward)
	if kind != rotationKindForward {
		return 0, "", errors.New("keyRotation is not a key-rotation statement")
	}
	st, ok := rotationStatementOf(kind, obj)
	if !ok {
		return 0, "", errors.New("keyRotation does not hold its form")
	}
	if st.keyID != before.keyID || st.alg != before.alg || !st.signedBy(before.held()) {
		return 0, "", errors.New("keyRotation is not signed by the key before it")
	}
	if st.namedAlg != e.alg || !bytes.Equal(st.named, e.key) {
		return 0, "", errors.New("keyRotation does not name this entry's key")
	}
	kind, obj = rotationKindOf(e.reverse)
	if kind != rotationKindReverse {
		return 0, "", errors.New("keyContinuation is not a key-continuation statement")
	}
	reverse, ok := rotationStatementOf(kind, obj)
	if !ok || reverse.rotation != st.rotation || reverse.rotatedAt != st.rotatedAt ||
		reverse.alg != e.alg || reverse.namedAlg != before.alg ||
		!bytes.Equal(reverse.named, before.key) || reverse.keyID != e.keyID || !reverse.signedBy(e.held()) {
		return 0, "", errors.New("keyContinuation is not the key-continuation of keyRotation, signed by this entry's key")
	}
	return int64(st.rotation), st.rotatedAt, nil
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
	own := g.ownHeld()
	made := keyHistoryAnswer{registry: sha256.Sum256(data), carried: sha256.Sum256(carried), present: present, own: own.alg + hex.EncodeToString(own.key)}
	g.keyHistoryKept.mu.Lock()
	defer g.keyHistoryKept.mu.Unlock()
	if last := g.keyHistoryKept.last; last != nil && last.registry == made.registry && last.carried == made.carried &&
		last.present == made.present && last.own == made.own {
		return last.doc, last.err
	}
	g.keyHistoryKept.walks++
	made.doc, made.err = walkKeyHistory(data, own, carried, present, g.keyHistoryVersion)
	g.keyHistoryKept.last = &made
	return made.doc, made.err
}

// walkKeyHistory is the key history document of a registry, with what was
// carried into its store, under the version configured and the carried
// history imply (registryKeyHistoryOf), held to the consumer's check from
// its own first key, or the finding that it does not hold.
func walkKeyHistory(data []byte, own heldKey, carried []byte, present bool, configured string) ([]byte, error) {
	made, err := registryKeyHistoryOf(data, own, carried, present, configured)
	if err != nil {
		return nil, err
	}
	pinned := made.entries[0].held()
	if _, err := checkKeyHistoryOf(made.doc, &pinned, ""); err != nil {
		return nil, fmt.Errorf("the key history does not hold: %w", err)
	}
	return made.doc, nil
}

// keyHistoryRotationFault is a key rotation's refusal of
// keyHistoryWriteRefusal (SPEC.md §3b) for any finding of the history with
// the rotation's record at the registry's end but its rotatedAt's order,
// which storeRotateKeyBefore says.
const keyHistoryRotationFault = "the rotation's record would not hold in the key history: %w"

// keyHistoryContinuationOrder and keyHistoryContinuationFault are a store
// rotation's (SPEC.md §3d): the continuation's continuedAt before the last
// rotation of the history it carries, and any other finding of the new
// registry's history.
const (
	keyHistoryContinuationOrder = "the store continuation's continuedAt %s is before the key history's last rotation %s; correct this host's clock and run again; nothing was written"
	keyHistoryContinuationFault = "the store continuation would not hold in the key history: %w"
)

// keyHistoryWriteRefusal is why a writer's record stamped at would leave a
// key history that the consumer's check refuses (SPEC.md §3e), or nil; the
// cause is decided here alone, for every writer of a rotation or a store
// continuation, before anything is written. before is the history as
// /publickey/history makes it now (registryKeyHistory, with what was
// carried into the store); at before its last rotation, the validFrom of
// the key in force, is the writer's clock, said by order with at and that
// rotation; two of one second hold, as checkKeyHistory holds them. after,
// where it is given, makes the history the route would make with the record
// in place (walkKeyHistory), and any finding of it is said by fault. The
// registry is append-only, so a history refused here would be answered 500
// by the route for good.
func keyHistoryWriteRefusal(before []keyHistoryEntry, at, order, fault string, after func() error) error {
	last := ""
	if len(before) > 0 {
		last = before[len(before)-1].validFrom
	}
	return keyHistoryWriteRefusalAt(last, at, order, fault, after)
}

// keyHistoryWriteRefusalAt is keyHistoryWriteRefusal from the history's
// last time (keyHistoryMade.last): the later of its last validFrom and,
// under version 2, its last continuedAt.
func keyHistoryWriteRefusalAt(last, at, order, fault string, after func() error) error {
	if last != "" && at < last {
		return fmt.Errorf(order, at, last)
	}
	if after != nil {
		if err := after(); err != nil {
			return fmt.Errorf(fault, err)
		}
	}
	return nil
}
