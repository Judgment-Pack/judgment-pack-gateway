package main

// The store continuation (SPEC.md §3d; ADR-0048, S2): the first line of a
// registry that a store rotation started, naming the tail of the registry
// before it -- its line count and the SHA-256 of its last line -- signed by
// the key in force. A verifier given the new store alone observes
// continues-from, which is no finding; given the registry before it
// (--previous), it holds the statement to that registry's tail.

import (
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
	statusContinuationMisplaced     = "continuation-misplaced"
	statusContinuationForged        = "continuation-forged"
	statusContinuationMissing       = "continuation-missing"
	statusContinuationCountMismatch = "continuation-count-mismatch"
	statusContinuationTailMismatch  = "continuation-tail-mismatch"
)

// observationContinuesFrom is what a verifier says of a registry whose first
// line is a store continuation that loads (SPEC.md §3d).
const observationContinuesFrom = "continues-from"

var continuationMembers = map[string]bool{
	"kind": true, "continuationVersion": true, "continuedAt": true, "keyId": true,
	"previousLines": true, "previousLastLine": true, "signature": true,
}

// storeContinuation is a store-continuation statement that loaded.
type storeContinuation struct {
	previousLines    int64
	previousLastLine string
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
	last, okLast := memberString(obj, "previousLastLine")
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
	return &storeContinuation{previousLines: int64(lines), previousLastLine: last}, true
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

// registryTail is what a store continuation names of a registry: its line
// count -- its bytes split at each 0x0A, an empty piece after the last one
// not a line -- and the lowercase hexadecimal SHA-256 of its last line's
// bytes, of no bytes where it has none.
func registryTail(data []byte) (int64, string) {
	text := string(data)
	text = strings.TrimSuffix(text, "\n")
	if len(data) == 0 {
		sum := sha256.Sum256(nil)
		return 0, hex.EncodeToString(sum[:])
	}
	lines := strings.Split(text, "\n")
	sum := sha256.Sum256([]byte(lines[len(lines)-1]))
	return int64(len(lines)), hex.EncodeToString(sum[:])
}

// newContinuationLine is the store continuation a rotation writes as the new
// registry's first line, signed by priv, naming the tail of previous.
func newContinuationLine(priv ed25519.PrivateKey, previous []byte, at string) []byte {
	lines, last := registryTail(previous)
	pub := priv.Public().(ed25519.PublicKey)
	obj := newObject()
	obj.set("continuationVersion", vString(continuationVersion))
	obj.set("continuedAt", vString(at))
	obj.set("keyId", vString(keyIDFor(pub)))
	obj.set("kind", vString(continuationKind))
	obj.set("previousLastLine", vString(last))
	obj.set("previousLines", vInt(lines))
	obj.set("signature", vString(hex.EncodeToString(ed25519.Sign(priv, continuationSigningInput(obj)))))
	return append(canon(obj), '\n')
}

// linkPrevious holds a verdict's store continuation to the registry before
// it (--previous; SPEC.md §3d): the registry's bytes read as the registry is
// read, absent or unreadable no verdict, and a link that does not hold a
// finding.
func linkPrevious(rep *report, previous string) error {
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
		lines, last := registryTail(data)
		if c.previousLines != lines {
			status = statusContinuationCountMismatch
		} else if c.previousLastLine != last {
			status = statusContinuationTailMismatch
		}
	}
	if status != "" {
		rep.Findings = append(rep.Findings, finding{"status": status})
		rep.OK = false
	}
	return nil
}
