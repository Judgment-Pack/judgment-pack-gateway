package main

// Payload retention (SPEC.md §1.3a; docs/adr/0028-payloads-a-gateway-does-not-keep.md):
// the two ways a receipt stays checkable without the gateway holding the
// bytes it attests -- a receipt that says its call kept no payload, and a
// signed record in the store that a kept payload was removed -- and what
// the artifact step of the ladder (orders 7 and 8) reads beside the store's
// own bytes.

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	// artifactNotRetained is the one value of a receipt's artifact member,
	// and of a platform's (docs/design/engine-config.md, artifact).
	artifactNotRetained = "not-retained"
	// removalsFile is where a store keeps its removal records, beside
	// receipts/ and artifacts/ (SPEC.md §1.3).
	removalsFile = "artifact-removals.jsonl"
	removalKind  = "artifact-removal"
	// removalContext is the prefix a removal record's signature covers, its
	// own, so a record is never read as a seal or a receipt, nor one of
	// those as a record.
	removalContext = "judgment-pack-gateway/artifact-removal/1:"
	// The observations a receipt that passed with no bytes checked carries.
	observationNotRetained = "artifact-not-retained"
	observationRemoved     = "artifact-removed"

	// The records of a scope identifier's removal (SPEC.md §1.3a, "A removed
	// session"; docs/adr/0034-removing-one-scope-identifiers-records.md), in
	// the same file: one for each sealed session removed, and one for the
	// call. Each is signed under a prefix of its own.
	sessionRemovalKind    = "session-removal"
	sessionRemovalContext = "judgment-pack-gateway/session-removal/1:"
	scopeRemovalKind      = "scope-removal"
	scopeRemovalContext   = "judgment-pack-gateway/scope-removal/1:"
	// observationSessionRemoved is what §4 step 4 says of a sealed session
	// absent from the store that a session-removal record names.
	observationSessionRemoved = "session-removed"
)

// sessionRemovalMembers and scopeRemovalMembers are the members each record
// holds, exactly.
var (
	sessionRemovalMembers = map[string]bool{
		"finalCount": true, "keyId": true, "kind": true, "removedAt": true, "removedBy": true,
		"scope": true, "sealSignature": true, "sessionId": true, "signature": true,
	}
	scopeRemovalMembers = map[string]bool{
		"keyId": true, "kind": true, "openSessions": true, "payloads": true, "receipts": true,
		"removedAt": true, "removedBy": true, "scope": true, "sealedSessions": true, "signature": true,
	}
)

// sessionRemoval is a session-removal record that loaded: it names a sealed
// session by its id, its seal's signature as the registry holds it and its
// seal's count.
type sessionRemoval struct {
	sessionID     string
	sealSignature string
	finalCount    int64
	scope         string
	removedAt     string
	removedBy     string
	keyID         string
	keyPos        int
}

// scopeRemoval is a scope-removal record that loaded: what one call removed
// of one scope identifier, by count. No step of §4 reads it.
type scopeRemoval struct {
	scope                                            string
	sealedSessions, openSessions, receipts, payloads int64
	removedAt, removedBy, keyID                      string
	keyPos                                           int
}

// removalRecords are the records of a removal file that loaded, each kind
// by what it names.
type removalRecords struct {
	// artifacts are the artifact-removal records, by the receipt signature
	// each names.
	artifacts map[string][]removalRecord
	// sessions are the session-removal records, by the session each names.
	// A scope-removal record is read by no step of §4, and is not kept.
	sessions map[string][]sessionRemoval
}

func newRemovalRecords() *removalRecords {
	return &removalRecords{artifacts: map[string][]removalRecord{}, sessions: map[string][]sessionRemoval{}}
}

// removalMembers are the members a removal record holds, exactly.
var removalMembers = map[string]bool{
	"callIndex": true, "keyId": true, "kind": true, "receiptSignature": true,
	"removedAt": true, "removedBy": true, "resultDigest": true, "sessionId": true,
	"signature": true,
}

// maxCallIndex is the largest callIndex a record names: 2^53-1, the
// largest integer every JSON reader holds exactly.
const maxCallIndex = 1<<53 - 1

// removalRecord is one record that loaded: of its form, under a key the
// walk reached, its signature verifying.
type removalRecord struct {
	sessionID        string
	callIndex        int64
	receiptSignature string
	resultDigest     string
	removedAt        string
	removedBy        string
	keyID            string
	// keyPos is the place of its key among the keys the walk reached.
	keyPos int
}

// retention is what the artifact step reads beside the store's own bytes:
// the removal records that loaded, by the receipt signature each names,
// and the directory of bytes a reader supplied, "" when none was.
type retention struct {
	removals map[string][]removalRecord
	supplied string
	// sessions are the session-removal records that loaded (§4 step 4).
	sessions map[string][]sessionRemoval
}

// removalSigningInput is what a record's signature covers: the prefix, then
// canon of the record with its top-level signature removed and every other
// member retained.
func removalSigningInput(obj *vObject) []byte {
	return recordSigningInput(removalContext, obj)
}

// recordSigningInput is what a record of the removal file signs under its
// kind's prefix: the prefix, then canon of the record with its top-level
// signature removed and every other member retained.
func recordSigningInput(prefix string, obj *vObject) []byte {
	covered := newObject()
	for _, name := range obj.names {
		if name == "signature" {
			continue
		}
		v, _ := obj.get(name)
		covered.set(name, v)
	}
	return append([]byte(prefix), canon(covered)...)
}

// signedByReachedKey is the place among the keys the walk reached of the key
// keyID names, where the record's signature verifies under it over prefix;
// -1 otherwise.
func signedByReachedKey(obj *vObject, prefix, keyID, signatureHex string, keys []reachedKey) int {
	keyPos := -1
	for i, k := range keys {
		if subtle.ConstantTimeCompare([]byte(keyID), []byte(k.keyID)) == 1 {
			keyPos = i
			break
		}
	}
	if keyPos < 0 {
		return -1
	}
	signature, err := hex.DecodeString(signatureHex)
	if err != nil || !ed25519.Verify(keys[keyPos].key, recordSigningInput(prefix, obj), signature) {
		return -1
	}
	return keyPos
}

// exactMembers is whether obj holds no member outside names. §1.1's parser
// admits no name twice, and each record's readers require every member of
// names, so this is all that is left to refuse.
func exactMembers(obj *vObject, names map[string]bool) bool {
	for name := range obj.byName {
		if !names[name] {
			return false
		}
	}
	return true
}

// recordCount is a count a scope-removal record holds: an integer from 0 to
// 2^53-1.
func recordCount(obj *vObject, name string) (int64, bool) {
	v, _ := obj.get(name)
	n, ok := v.(vInt)
	return int64(n), ok && int64(n) >= 0 && int64(n) <= maxCallIndex
}

// sessionRemovalOf holds a record to a session-removal's form (SPEC.md
// §1.3a, "A removed session") and loads it under the keys the walk reached.
func sessionRemovalOf(obj *vObject, keys []reachedKey) (sessionRemoval, bool) {
	if !exactMembers(obj, sessionRemovalMembers) {
		return sessionRemoval{}, false
	}
	kind, _ := memberString(obj, "kind")
	sessionID, okSession := memberString(obj, "sessionId")
	sealSignature, okSeal := memberString(obj, "sealSignature")
	scope, okScope := memberString(obj, "scope")
	removedAt, okAt := memberString(obj, "removedAt")
	removedBy, okBy := memberString(obj, "removedBy")
	keyID, okKey := memberString(obj, "keyId")
	signatureHex, okSig := memberString(obj, "signature")
	countV, _ := obj.get("finalCount")
	count, okCount := countV.(vInt)
	if kind != sessionRemovalKind ||
		!okSession || requireSession(sessionID) != nil ||
		!okSeal || !isSignature3(sealSignature) ||
		!okCount ||
		!okScope || !isScopeIdentifier(scope) ||
		!okAt || !isRemovalTime(removedAt) ||
		!okBy || !isScopeIdentifier(removedBy) ||
		!okKey || !isLowerHexOfLen(keyID, 32) ||
		!okSig || !isSignature3(signatureHex) {
		return sessionRemoval{}, false
	}
	keyPos := signedByReachedKey(obj, sessionRemovalContext, keyID, signatureHex, keys)
	if keyPos < 0 {
		return sessionRemoval{}, false
	}
	return sessionRemoval{
		sessionID: sessionID, sealSignature: sealSignature, finalCount: int64(count), scope: scope,
		removedAt: removedAt, removedBy: removedBy, keyID: keyID, keyPos: keyPos,
	}, true
}

// scopeRemovalOf holds a record to a scope-removal's form (SPEC.md §1.3a, "A
// removed session") and loads it under the keys the walk reached.
func scopeRemovalOf(obj *vObject, keys []reachedKey) (scopeRemoval, bool) {
	if !exactMembers(obj, scopeRemovalMembers) {
		return scopeRemoval{}, false
	}
	kind, _ := memberString(obj, "kind")
	scope, okScope := memberString(obj, "scope")
	removedAt, okAt := memberString(obj, "removedAt")
	removedBy, okBy := memberString(obj, "removedBy")
	keyID, okKey := memberString(obj, "keyId")
	signatureHex, okSig := memberString(obj, "signature")
	sealed, okSealed := recordCount(obj, "sealedSessions")
	open, okOpen := recordCount(obj, "openSessions")
	receipts, okReceipts := recordCount(obj, "receipts")
	payloads, okPayloads := recordCount(obj, "payloads")
	if kind != scopeRemovalKind ||
		!okScope || !isScopeIdentifier(scope) ||
		!okSealed || !okOpen || !okReceipts || !okPayloads ||
		!okAt || !isRemovalTime(removedAt) ||
		!okBy || !isScopeIdentifier(removedBy) ||
		!okKey || !isLowerHexOfLen(keyID, 32) ||
		!okSig || !isSignature3(signatureHex) {
		return scopeRemoval{}, false
	}
	keyPos := signedByReachedKey(obj, scopeRemovalContext, keyID, signatureHex, keys)
	if keyPos < 0 {
		return scopeRemoval{}, false
	}
	return scopeRemoval{
		scope: scope, sealedSessions: sealed, openSessions: open, receipts: receipts, payloads: payloads,
		removedAt: removedAt, removedBy: removedBy, keyID: keyID, keyPos: keyPos,
	}, true
}

// load loads one line of the removal file, of whichever kind it says it is;
// a line that is no record of its kind loads nothing.
func (set *removalRecords) load(line string, keys []reachedKey) {
	v, err := parseJSON([]byte(line))
	if err != nil {
		return
	}
	obj, ok := v.(*vObject)
	if !ok {
		return
	}
	kind, _ := memberString(obj, "kind")
	switch kind {
	case removalKind:
		if rec, ok := artifactRemovalOf(obj, keys); ok {
			keepRemoval(set.artifacts, rec)
		}
	case sessionRemovalKind:
		if rec, ok := sessionRemovalOf(obj, keys); ok {
			keepSessionRemoval(set.sessions, rec)
		}
	}
	// a scope-removal record is read by no step of §4 (§1.3a), and
	// remove-scope reads its own back with scopeRemovalOf
}

// keepSessionRemoval keeps a session-removal record that loaded once for the
// seal it names: one naming the same session, seal, count and scope as one
// kept replaces it only where its key was reached later, which is all
// sessionRemoved reads of either.
func keepSessionRemoval(sessions map[string][]sessionRemoval, rec sessionRemoval) {
	named := sessions[rec.sessionID]
	for i := range named {
		if named[i].sealSignature == rec.sealSignature && named[i].finalCount == rec.finalCount && named[i].scope == rec.scope {
			if rec.keyPos > named[i].keyPos {
				named[i] = rec
			}
			return
		}
	}
	sessions[rec.sessionID] = append(named, rec)
}

// sessionRemoved is whether a session-removal record that loaded names the
// sealed session (SPEC.md §1.3a, "A removed session"): its id, the signature
// of its first seal that loaded as the registry holds it, and that seal's
// count, under the key the seal loaded under or one the walk reached after
// it; and, where the seal is of version 2, the scope it names: the record's
// scope identifier, digested in the session, is the seal's scopeDigest
// (ADR-0036), so a record of another scope excuses no such session.
func (ret *retention) sessionRemoved(sessionID string, s seal) bool {
	if ret == nil {
		return false
	}
	for _, rec := range ret.sessions[sessionID] {
		if rec.sealSignature == s.signature && rec.finalCount == s.finalCount && rec.keyPos >= s.keyPos &&
			(s.scopeDigest == "" || sealScopeDigest(sessionID, rec.scope) == s.scopeDigest) {
			return true
		}
	}
	return false
}

// removalTimeLayout is removedAt's form: UTC, to the second.
const removalTimeLayout = "2006-01-02T15:04:05Z"

// isRemovalTime is a removedAt of its form that names an instant (SPEC.md
// §1.3a): two digits to each field, which time.Parse does not ask of an
// hour, and no fraction, which it takes unasked; then a date the calendar
// holds, and an hour, minute and second of a day, which it checks.
func isRemovalTime(s string) bool {
	if !witnessTimeForm.MatchString(s) {
		return false
	}
	_, err := time.Parse(removalTimeLayout, s)
	return err == nil
}

// removalOf holds one line to a removal record's form and loads it under
// the keys the walk reached: exactly its members, each of its form, its
// keyId a reached key's, its signature verifying under that key. A line
// that is not so is no record.
func removalOf(line string, keys []reachedKey) (removalRecord, bool) {
	v, err := parseJSON([]byte(line))
	if err != nil {
		return removalRecord{}, false
	}
	obj, ok := v.(*vObject)
	if !ok {
		return removalRecord{}, false
	}
	return artifactRemovalOf(obj, keys)
}

// artifactRemovalOf holds a parsed line to an artifact-removal record's form
// and loads it under the keys the walk reached (removalOf).
func artifactRemovalOf(obj *vObject, keys []reachedKey) (removalRecord, bool) {
	// every member is required below, and §1.1's parser admits no name
	// twice, so a member of no other name is all that is left to refuse
	if !exactMembers(obj, removalMembers) {
		return removalRecord{}, false
	}
	kind, _ := memberString(obj, "kind")
	sessionID, okSession := memberString(obj, "sessionId")
	receiptSignature, okReceipt := memberString(obj, "receiptSignature")
	resultDigest, okDigest := memberString(obj, "resultDigest")
	removedAt, okAt := memberString(obj, "removedAt")
	removedBy, okBy := memberString(obj, "removedBy")
	keyID, okKey := memberString(obj, "keyId")
	signatureHex, okSig := memberString(obj, "signature")
	indexV, _ := obj.get("callIndex")
	index, okIndex := indexV.(vInt)
	if kind != removalKind ||
		!okSession || requireSession(sessionID) != nil ||
		!okIndex || int64(index) < 0 || int64(index) > maxCallIndex ||
		!okReceipt || !isSignature3(receiptSignature) ||
		!okDigest || !isDigest(resultDigest) ||
		!okAt || !isRemovalTime(removedAt) ||
		!okBy || !isScopeIdentifier(removedBy) ||
		!okKey || !isLowerHexOfLen(keyID, 32) ||
		!okSig || !isSignature3(signatureHex) {
		return removalRecord{}, false
	}
	keyPos := signedByReachedKey(obj, removalContext, keyID, signatureHex, keys)
	if keyPos < 0 {
		return removalRecord{}, false
	}
	return removalRecord{
		sessionID: sessionID, callIndex: int64(index), receiptSignature: receiptSignature,
		resultDigest: resultDigest, removedAt: removedAt, removedBy: removedBy,
		keyID: keyID, keyPos: keyPos,
	}, true
}

// removalLineBound is the most bytes a line of the removal file holds, its
// line feed not counted, for a record on it to load (SPEC.md §1.3a). A
// record a command writes is under 1200 bytes, its labels escaped at their
// longest; a longer line loads nothing and is read no further than the bound, so a reader holds one
// line at a time, and what it keeps grows with the records that load.
const removalLineBound = 4096

// removalsRead, when set, runs each time the removal file is read: a
// test's count of the reads. removalJudged, when set, runs between judging
// the file's entry and opening it: a test's way of putting another file in
// its place at that moment.
var (
	removalsRead  func()
	removalJudged func()
)

// errRemovalsNotRegular is something at the removal file's path that is
// not a regular file -- a link, whatever it leads to, a directory, a FIFO.
// A verifier reads no record from it (SPEC.md §1.3a, §4.1), and the
// command and the export refuse it, writing nothing.
var errRemovalsNotRegular = errors.New("is not a regular file")

// loadRemovals reads the store's removal records (SPEC.md §1.3a,
// "Loading"; §4.1): nothing at the path loads none, and nor does something
// there that is not a regular file, which is not read; a regular file that
// cannot be read is no verdict.
func loadRemovals(storeRoot string, keys []reachedKey) (map[string][]removalRecord, error) {
	set, err := loadRecords(storeRoot, keys)
	if err != nil {
		return nil, err
	}
	return set.artifacts, nil
}

// loadRecords is loadRemovals for every kind of record the file holds.
func loadRecords(storeRoot string, keys []reachedKey) (*removalRecords, error) {
	set, _, err := readRecords(storeRoot, keys)
	if errors.Is(err, errRemovalsNotRegular) {
		return &removalRecords{}, nil
	}
	return set, err
}

// readRemovals reads the removal file a line at a time and loads its
// records, and says whether the file ends in a line no append finished.
// Something at the path that is not a regular file is errRemovalsNotRegular.
func readRemovals(storeRoot string, keys []reachedKey) (map[string][]removalRecord, bool, error) {
	set, torn, err := readRecords(storeRoot, keys)
	if err != nil {
		return nil, false, err
	}
	return set.artifacts, torn, nil
}

// readRecords is readRemovals for every kind of record the file holds.
func readRecords(storeRoot string, keys []reachedKey) (*removalRecords, bool, error) {
	if removalsRead != nil {
		removalsRead()
	}
	file, err := openRemovals(storeRoot)
	if err != nil {
		return nil, false, err
	}
	if file == nil {
		// nothing there holds no record: no map at all, as before records
		// of other kinds were read
		return &removalRecords{}, false, nil
	}
	defer file.Close()
	set, torn, err := scanRecords(file, keys)
	if err != nil {
		return nil, false, fmt.Errorf("removal records: %w", err)
	}
	return set, torn, nil
}

// openRemovals opens the store's removal file to read, following no link:
// nil, and no error, where nothing is at its path or no store root is there
// to hold it (openRemovalEntry).
func openRemovals(storeRoot string) (*os.File, error) {
	path := filepath.Join(storeRoot, removalsFile)
	if _, err := lstat(path); err != nil {
		if absent(err) {
			return nil, nil
		}
		// absent confirms a name only in a directory it reached: on Windows
		// a name under a store root that is not there answers
		// ERROR_PATH_NOT_FOUND, so the store root is looked at in its turn,
		// as nothingAt looks at artifacts/.
		if _, rootErr := lstat(storeRoot); rootErr != nil && absent(rootErr) {
			return nil, nil
		}
		return nil, fmt.Errorf("removal records: %w", err)
	}
	root, err := os.OpenRoot(storeRoot)
	if err != nil {
		return nil, fmt.Errorf("removal records: %w", err)
	}
	defer root.Close()
	file, err := openRemovalEntry(root, openNoFollow)
	if err != nil {
		if absent(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("removal records: %s %w", path, err)
	}
	return file, nil
}

// openRemovalEntry opens the removal file in the held store directory with
// open, which follows no link and waits on no writer: the entry at its
// name judged first -- a regular file, or errRemovalsNotRegular -- and the
// file opened the very entry judged.
func openRemovalEntry(root *os.Root, open func(*os.Root, string) (*os.File, error)) (*os.File, error) {
	entry, err := root.Lstat(removalsFile)
	if err != nil {
		return nil, err
	}
	if !entry.Mode().IsRegular() {
		return nil, errRemovalsNotRegular
	}
	if removalJudged != nil {
		removalJudged()
	}
	file, err := open(root, removalsFile)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !os.SameFile(entry, info) {
		file.Close()
		return nil, errors.New("is not the file its name held a moment ago")
	}
	return file, nil
}

// scanRemovals loads the records of a removal file's lines, read one at a
// time: each line terminated by a line feed and of at most
// removalLineBound bytes is judged alone; a longer one is passed over
// unread; the text after the last line feed is a line no append finished,
// and torn says whether there is any.
func scanRemovals(r io.Reader, keys []reachedKey) (removals map[string][]removalRecord, torn bool, err error) {
	set, torn, err := scanRecords(r, keys)
	if err != nil {
		return nil, false, err
	}
	return set.artifacts, torn, nil
}

// scanRecords is scanRemovals for every kind of record a line may hold: an
// artifact-removal, a session-removal or a scope-removal, each by its kind
// (SPEC.md §1.3a, "Loading").
func scanRecords(r io.Reader, keys []reachedKey) (set *removalRecords, torn bool, err error) {
	set = newRemovalRecords()
	in := bufio.NewReaderSize(r, removalLineBound+1)
	for {
		line, err := in.ReadSlice('\n')
		long := false
		for err == bufio.ErrBufferFull {
			long = true
			line, err = in.ReadSlice('\n')
		}
		switch {
		case err == io.EOF:
			return set, long || len(line) > 0, nil
		case err != nil:
			return nil, false, err
		case !long:
			set.load(string(line[:len(line)-1]), keys)
		}
	}
}

// keepRemoval keeps a record that loaded once for what it names: a record
// naming the receipt by the same session, index and digest as one kept
// replaces it only where its key was reached later, which is all namedBy
// reads of either. What is kept grows with the receipts the records name,
// not with the lines that repeat them.
func keepRemoval(removals map[string][]removalRecord, rec removalRecord) {
	named := removals[rec.receiptSignature]
	for i := range named {
		if named[i].sessionID == rec.sessionID && named[i].callIndex == rec.callIndex && named[i].resultDigest == rec.resultDigest {
			if rec.keyPos > named[i].keyPos {
				named[i] = rec
			}
			return
		}
	}
	removals[rec.receiptSignature] = append(named, rec)
}

// namedBy is whether a record that loaded names the receipt: its session
// directory, its index, its signature and its digest, under the receipt's
// key or one the walk reached after it.
func (ret *retention) namedBy(r *receipt, sessionID string) bool {
	if ret == nil {
		return false
	}
	for _, rec := range ret.removals[r.signature] {
		if rec.sessionID == sessionID && rec.callIndex == r.callIndex &&
			rec.resultDigest == r.resultDigest && rec.keyPos >= r.keyPos {
			return true
		}
	}
	return false
}

// errSuppliedUnreadable is a supplied file the verifier cannot read: no
// verdict (SPEC.md §4.1), since a reader that named a directory of bytes is
// answered about those bytes or not at all.
var errSuppliedUnreadable = errors.New("supplied bytes")

// suppliedBytes is the file a reader supplied for a digest, and whether
// there is one: a name the directory holds no entry for is none; an entry
// that is not a regular file, or that cannot be read, is no verdict.
func (ret *retention) suppliedBytes(digestHex string) ([]byte, bool, error) {
	if ret == nil || ret.supplied == "" {
		return nil, false, nil
	}
	path := filepath.Join(ret.supplied, digestHex)
	info, err := os.Lstat(path)
	if err != nil {
		if absent(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("%w: %v", errSuppliedUnreadable, err)
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%w: %s is not a regular file", errSuppliedUnreadable, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %v", errSuppliedUnreadable, err)
	}
	return data, true, nil
}

// artifactStep is orders 7 and 8 of the ladder (SPEC.md §1.3a, "The
// artifact step"): the status, and the observation a receipt that passed
// with no bytes re-digested carries. Bytes the store holds are re-digested
// first and whatever else holds; where nothing at all is there, a receipt
// that says its call kept nothing, or that a record names, passes order 7,
// and bytes a reader supplied for it are re-digested.
func artifactStep(r *receipt, probe artifactProbe, sessionID, digestHex string, ret *retention) (status, observation string, err error) {
	sum, held, nothing := probe(digestHex)
	if held {
		if sum != digestHex {
			return "artifact-mismatch", "", nil
		}
		return "ok", "", nil
	}
	// Nothing at all under the name (fsStoreProbe: no file, no directory, no
	// link). Anything else is what it always was.
	if !nothing {
		return "artifact-missing", "", nil
	}
	switch {
	case r.notRetained:
		observation = observationNotRetained
	case ret.namedBy(r, sessionID):
		observation = observationRemoved
	default:
		return "artifact-missing", "", nil
	}
	supplied, given, err := ret.suppliedBytes(digestHex)
	if err != nil {
		return "", "", err
	}
	if given {
		if digestOfBytes(supplied) != digestHex {
			return "artifact-mismatch", "", nil
		}
		return "ok", "", nil
	}
	return "ok", observation, nil
}

// nothingAt is whether nothing at all is at <root>/artifacts/<hex>: the name
// absent from a directory artifacts/ is, or artifacts/ itself absent from the
// store root. absent confirms a name only in a directory it reached, so on
// Windows, where a name under a directory that is not there answers
// ERROR_PATH_NOT_FOUND, the directory is looked at in its turn: a store that
// never kept a payload need hold no artifacts/ at all.
func nothingAt(storeRoot, digestHex string) bool {
	dir := filepath.Join(storeRoot, "artifacts")
	_, err := lstat(filepath.Join(dir, digestHex))
	if err == nil {
		return false
	}
	if absent(err) {
		return true
	}
	_, err = lstat(dir)
	return err != nil && absent(err)
}

// digestOfBytes is the lowercase hex of data's SHA-256.
func digestOfBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// suppliedDirectory holds the directory a reader named with --artifacts to
// SPEC.md §4.1: taken by its spelling, there, and a directory, or no
// verdict.
func suppliedDirectory(dir string) error {
	if err := requirePlainSpelling(dir, false); err != nil {
		return fmt.Errorf("supplied-bytes directory: %w", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("supplied-bytes directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("supplied-bytes directory is not a directory: %s", dir)
	}
	if _, err := os.ReadDir(dir); err != nil {
		return fmt.Errorf("supplied-bytes directory: %w", err)
	}
	return nil
}
