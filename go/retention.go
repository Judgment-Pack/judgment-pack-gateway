package main

// Payload retention (SPEC.md §1.3a; docs/adr/0028-payloads-a-gateway-does-not-keep.md):
// the two ways a receipt stays checkable without the gateway holding the
// bytes it attests -- a receipt that says its call kept no payload, and a
// signed record in the store that a kept payload was removed -- and what
// the artifact step of the ladder (orders 7 and 8) reads beside the store's
// own bytes.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
)

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
}

// removalSigningInput is what a record's signature covers: the prefix, then
// canon of the record with its top-level signature removed and every other
// member retained.
func removalSigningInput(obj *vObject) []byte {
	covered := newObject()
	for _, name := range obj.names {
		if name == "signature" {
			continue
		}
		v, _ := obj.get(name)
		covered.set(name, v)
	}
	return append([]byte(removalContext), canon(covered)...)
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
	// every member is required below, and §1.1's parser admits no name
	// twice, so a member of no other name is all that is left to refuse
	for name := range obj.byName {
		if !removalMembers[name] {
			return removalRecord{}, false
		}
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
		!okAt || !witnessTimeForm.MatchString(removedAt) ||
		!okBy || !isScopeIdentifier(removedBy) ||
		!okKey || !isLowerHexOfLen(keyID, 32) ||
		!okSig || !isSignature3(signatureHex) {
		return removalRecord{}, false
	}
	keyPos := -1
	for i, k := range keys {
		if subtle.ConstantTimeCompare([]byte(keyID), []byte(k.keyID)) == 1 {
			keyPos = i
			break
		}
	}
	if keyPos < 0 {
		return removalRecord{}, false
	}
	signature, _ := hex.DecodeString(signatureHex)
	if !ed25519.Verify(keys[keyPos].key, removalSigningInput(obj), signature) {
		return removalRecord{}, false
	}
	return removalRecord{
		sessionID: sessionID, callIndex: int64(index), receiptSignature: receiptSignature,
		resultDigest: resultDigest, removedAt: removedAt, removedBy: removedBy,
		keyID: keyID, keyPos: keyPos,
	}, true
}

// loadRemovals reads the store's removal records (SPEC.md §1.3a,
// "Loading"; §4.1): a file that is not there loads none; one there that is
// not a regular file, or cannot be read, is no verdict. Each line
// terminated by a line feed is judged alone, and a torn last line is none.
func loadRemovals(storeRoot string, keys []reachedKey) (map[string][]removalRecord, error) {
	data, present, err := readRemovals(storeRoot)
	if err != nil || !present {
		return nil, err
	}
	return parseRemovals(data, keys), nil
}

// readRemovals is the removal file's bytes, and whether it is there.
func readRemovals(storeRoot string) ([]byte, bool, error) {
	path := filepath.Join(storeRoot, removalsFile)
	if _, err := os.Lstat(path); err != nil {
		if absent(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("removal records: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, false, fmt.Errorf("removal records: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("removal records: %s is not a regular file", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("removal records: %w", err)
	}
	return data, true, nil
}

// parseRemovals loads every record of a removal file's bytes.
func parseRemovals(data []byte, keys []reachedKey) map[string][]removalRecord {
	removals := map[string][]removalRecord{}
	lines := strings.Split(string(data), "\n")
	// The text after the last line feed is a line no append finished.
	for _, line := range lines[:len(lines)-1] {
		if rec, ok := removalOf(line, keys); ok {
			removals[rec.receiptSignature] = append(removals[rec.receiptSignature], rec)
		}
	}
	return removals
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
func artifactStep(r *receipt, storeRoot, sessionID, digestHex string, ret *retention) (status, observation string, err error) {
	path := filepath.Join(storeRoot, "artifacts", digestHex)
	artifact, readErr := os.ReadFile(path)
	if readErr == nil {
		if digestOfBytes(artifact) != digestHex {
			return "artifact-mismatch", "", nil
		}
		return "ok", "", nil
	}
	// Nothing at all at the path: no file, no directory, no link -- a link
	// that leads nowhere is something. Anything else is what it always was.
	if !nothingAt(storeRoot, digestHex) {
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
