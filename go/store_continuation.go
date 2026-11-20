package main

// The store continuation (SPEC.md §3d; ADR-0048, S2): the first line of a
// registry that a store rotation started, naming the registry before it --
// its line count and the SHA-256 of its bytes, whole -- signed by the key in
// force. A verifier given the new store alone observes continues-from, which
// is no finding; given the registry before it (--previous), it holds the
// statement to that registry's bytes and to the key its rotations end at.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// continuationContext is the domain of what a store-continuation signs: none
// of the receipt's, the seal's, the rotation statement's or the witness
// statement's.
const continuationContext = "judgment-pack-gateway/store-continuation/1:"

const (
	continuationKind    = "store-continuation"
	continuationVersion = "1"
)

// The findings a store continuation can give (SPEC.md §3d): of the registry
// read alone, and of the link to the registry before it under --previous.
const (
	statusContinuationMisplaced      = "continuation-misplaced"
	statusContinuationForged         = "continuation-forged"
	statusContinuationMissing        = "continuation-missing"
	statusContinuationCountMismatch  = "continuation-count-mismatch"
	statusContinuationDigestMismatch = "continuation-digest-mismatch"
	statusContinuationKeyMismatch    = "continuation-key-mismatch"
)

// observationContinuesFrom is what a verifier says of a registry whose first
// line is a store continuation that loads (SPEC.md §3d).
const observationContinuesFrom = "continues-from"

var continuationMembers = map[string]bool{
	"kind": true, "continuationVersion": true, "continuedAt": true, "keyId": true,
	"previousLines": true, "previousDigest": true, "signature": true,
}

// storeContinuation is a store-continuation statement that loaded.
type storeContinuation struct {
	keyID          string
	previousLines  int64
	previousDigest string
}

// continuationLine is the object of a registry line that is a store
// continuation -- one JSON object whose kind is store-continuation -- or nil.
func continuationLine(line string) *vObject {
	v, err := parseJSON([]byte(line))
	if err != nil {
		return nil
	}
	obj, ok := v.(*vObject)
	if !ok {
		return nil
	}
	if kind, _ := memberString(obj, "kind"); kind != continuationKind {
		return nil
	}
	return obj
}

// continuationOf holds a store continuation to its form and to the key in
// force at its line: exactly its members, each of its form, its keyId the
// key's and its signature verifying under it.
func continuationOf(obj *vObject, key reachedKey) (*storeContinuation, bool) {
	if len(obj.byName) != len(continuationMembers) {
		return nil, false
	}
	for name := range obj.byName {
		if !continuationMembers[name] {
			return nil, false
		}
	}
	version, _ := memberString(obj, "continuationVersion")
	at, okAt := memberString(obj, "continuedAt")
	keyID, okID := memberString(obj, "keyId")
	last, okLast := memberString(obj, "previousDigest")
	sigHex, okSig := memberString(obj, "signature")
	linesV, _ := obj.get("previousLines")
	lines, okLines := linesV.(vInt)
	if version != continuationVersion || !okAt || !witnessTimeForm.MatchString(at) ||
		!okID || !isLowerHexOfLen(keyID, 32) || !okLast || !isLowerHexOfLen(last, 64) ||
		!okSig || !isLowerHexOfLen(sigHex, 128) || !okLines || int64(lines) < 0 {
		return nil, false
	}
	signature, _ := hex.DecodeString(sigHex)
	if keyID != key.keyID || len(key.key) != ed25519.PublicKeySize || !ed25519.Verify(key.key, continuationSigningInput(obj), signature) {
		return nil, false
	}
	return &storeContinuation{keyID: keyID, previousLines: int64(lines), previousDigest: last}, true
}

// continuationSigningInput is what a store continuation's signature covers:
// the prefix, then canon of the statement without its top-level signature.
func continuationSigningInput(obj *vObject) []byte {
	return signedOver(continuationContext, obj)
}

// readContinuation reads a store continuation at the registry's line at:
// loaded at the first line, and otherwise the registry's finding.
func (w *registryWalk) readContinuation(obj *vObject, at int) {
	if at > 0 {
		if w.continuationFinding == nil {
			w.continuationFinding = finding{"status": statusContinuationMisplaced}
		}
		return
	}
	c, ok := continuationOf(obj, w.current())
	if !ok {
		w.continuationFinding = finding{"status": statusContinuationForged}
		return
	}
	w.continuation = c
}

// registryLink is what a store continuation names of a registry: its line
// count -- its bytes split at each 0x0A, an empty piece after the last one
// not a line -- and the lowercase hexadecimal SHA-256 of its bytes, whole.
func registryLink(data []byte) (int64, string) {
	sum := sha256.Sum256(data)
	if len(data) == 0 {
		return 0, hex.EncodeToString(sum[:])
	}
	return int64(len(strings.Split(strings.TrimSuffix(string(data), "\n"), "\n"))), hex.EncodeToString(sum[:])
}

// rotatedMarkPrefix begins what marks a store rotated away from (SPEC.md
// §3d): "store-rotated:" and the SHA-256 of the continuation line the
// rotation wrote, without its 0x0A -- on the filesystem kind a file beside
// the registry, on the PostgreSQL kind the one row of gateway.rotated.
const rotatedMarkPrefix = "store-rotated:"

// rotatedMark is the mark of a rotation whose new registry's first line is
// line.
func rotatedMark(line []byte) string {
	sum := sha256.Sum256(bytes.TrimSuffix(line, []byte("\n")))
	return rotatedMarkPrefix + hex.EncodeToString(sum[:])
}

// errStoreRotated is the refusal of a store marked rotated away from.
func errStoreRotated(mark string) error {
	return fmt.Errorf("the store was rotated away from (%s): nothing starts on it or appends to it again; start the gateway on the store it was rotated to", mark)
}

// newContinuationLine is the store continuation a rotation writes as the new
// registry's first line, signed by priv, naming the tail of previous.
func newContinuationLine(key *signingKey, previous []byte, at string) ([]byte, error) {
	lines, last := registryLink(previous)
	pub := key.public
	obj := newObject()
	obj.set("continuationVersion", vString(continuationVersion))
	obj.set("continuedAt", vString(at))
	obj.set("keyId", vString(keyIDFor(pub)))
	obj.set("kind", vString(continuationKind))
	obj.set("previousDigest", vString(last))
	obj.set("previousLines", vInt(lines))
	signature, err := key.signVerified(continuationSigningInput(obj))
	if err != nil {
		return nil, err
	}
	obj.set("signature", vString(hex.EncodeToString(signature)))
	return append(canon(obj), '\n'), nil
}

// linkPrevious holds a verdict's store continuation to the registry before
// it (--previous; SPEC.md §3d): the registry's bytes read as the registry is
// read, absent or unreadable no verdict, and a link that does not hold a
// finding. That registry is walked as a gateway walks its own (§3b), from
// its first key-continuation's previous key where it has one and from the
// key pinned otherwise, and the continuation's key must be the key its walk
// ends at; and the key its last seal states must be the key in force at
// that seal's line, so that a registry that never rotated is held to the
// key its seals name, not to the key pinned (lastSealHolds).
func linkPrevious(rep *report, previous string, pinned ed25519.PublicKey) error {
	if previous == "" {
		return nil
	}
	data, present, err := readRegistryBytes(previous)
	if err != nil {
		return fmt.Errorf("the previous registry: %w", err)
	}
	if !present {
		return fmt.Errorf("the previous registry is not there: %s", previous)
	}
	var status string
	switch c := rep.continuation; {
	case c == nil && rep.continuationRefused:
		// the registry's own finding stands for the link
	case c == nil:
		status = statusContinuationMissing
	default:
		lines, digest := registryLink(data)
		before := walkRegistry(data, registryFirstKey(data, pinned))
		if c.previousLines != lines {
			status = statusContinuationCountMismatch
		} else if c.previousDigest != digest {
			status = statusContinuationDigestMismatch
		} else if before.finding != nil || before.current().keyID != c.keyID || !lastSealHolds(data, registryFirstKey(data, pinned)) {
			status = statusContinuationKeyMismatch
		}
	}
	if status != "" {
		rep.Findings = append(rep.Findings, finding{"status": status})
		rep.OK = false
	}
	return nil
}

// lastSealHolds is whether the keyId the registry's last seal states -- its
// last line that is one JSON object holding a string sessionId and a string
// keyId, and no rotation statement or store continuation -- is the key in
// force at that line, the registry walked from start. A registry holding no
// seal holds: its walk's last key alone is held to the continuation.
func lastSealHolds(data []byte, start ed25519.PublicKey) bool {
	lines := strings.SplitAfter(string(data), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSuffix(lines[i], "\n")
		if continuationLine(line) != nil {
			continue
		}
		if kind, _ := rotationKindOf(line); kind != "" {
			continue
		}
		v, err := parseJSON([]byte(line))
		if err != nil {
			continue
		}
		obj, ok := v.(*vObject)
		if !ok {
			continue
		}
		keyID, okKey := memberString(obj, "keyId")
		if _, okSession := memberString(obj, "sessionId"); !okKey || !okSession {
			continue
		}
		upTo := walkRegistry([]byte(strings.Join(lines[:i+1], "")), start)
		return upTo.finding == nil && upTo.current().keyID == keyID
	}
	return true
}
