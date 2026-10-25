package main

// Key rotation (SPEC.md §3b): the continuity statement, the pair of registry
// lines by which a gateway hands its signing key on, and the walk a verifier
// follows from the key it pinned. A registry that holds no rotation statement
// is read exactly as before: every line a seal or nothing, under the one key.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// rotationContext is the domain of what a rotation statement signs: none of
// the receipt's, the seal's or the witness statement's.
const rotationContext = "judgment-pack-gateway/rotation/1:"

// The two kinds of a rotation statement: the one the key rotated from signs,
// naming the next key, and the one the next key signs, naming the key it
// continues.
const (
	rotationKindForward = "key-rotation"
	rotationKindReverse = "key-continuation"
	rotationVersion     = "1"
)

// The findings of the walk (SPEC.md §3b): at most one per registry.
const (
	statusRotationBreak      = "rotation-break"
	statusRotationForged     = "rotation-forged"
	statusRotationOrder      = "rotation-order"
	statusRotationKeyRefused = "rotation-key-refused"
)

// maxRotation is the largest ordinal a rotation statement carries, 2^53-2.
const maxRotation = maxSafeInteger - 1

// rotationMembers are the members each kind holds, exactly; the key a
// statement names is "next" on the forward one and "previous" on the reverse.
var rotationMembers = map[string]map[string]bool{
	rotationKindForward: {"kind": true, "rotationVersion": true, "rotation": true, "rotatedAt": true, "keyId": true, "next": true, "nextKeyId": true, "signature": true},
	rotationKindReverse: {"kind": true, "rotationVersion": true, "rotation": true, "rotatedAt": true, "keyId": true, "previous": true, "previousKeyId": true, "signature": true},
}

// rotationStatement is one rotation statement that holds its form.
type rotationStatement struct {
	kind      string
	rotation  int64
	rotatedAt string
	keyID     string
	// named is the key the statement names: next on a key-rotation,
	// previous on a key-continuation.
	named     ed25519.PublicKey
	namedID   string
	signature []byte
	obj       *vObject
}

// rotationKindOf is the kind of a registry line that is a rotation
// statement -- one JSON object, read by §1.1's parser, whose kind member is
// one of the two kinds -- with its object, or "" for any other line.
func rotationKindOf(line string) (string, *vObject) {
	v, err := parseJSON([]byte(line))
	if err != nil {
		return "", nil
	}
	obj, ok := v.(*vObject)
	if !ok {
		return "", nil
	}
	kind, _ := memberString(obj, "kind")
	if rotationMembers[kind] == nil {
		return "", nil
	}
	return kind, obj
}

// rotationStatementOf holds a rotation statement to its form: exactly the
// members of its kind, each of its form, and the key id it carries beside
// the key it names the key id of that key.
func rotationStatementOf(kind string, obj *vObject) (*rotationStatement, bool) {
	allowed := rotationMembers[kind]
	if len(obj.byName) != len(allowed) {
		return nil, false
	}
	for name := range obj.byName {
		if !allowed[name] {
			return nil, false
		}
	}
	named, namedID := "next", "nextKeyId"
	if kind == rotationKindReverse {
		named, namedID = "previous", "previousKeyId"
	}
	st := &rotationStatement{kind: kind, obj: obj}
	version, _ := memberString(obj, "rotationVersion")
	rotatedAt, okAt := memberString(obj, "rotatedAt")
	keyID, okID := memberString(obj, "keyId")
	namedHex, okNamed := memberString(obj, named)
	namedKeyID, okNamedID := memberString(obj, namedID)
	signatureHex, okSig := memberString(obj, "signature")
	rotationV, _ := obj.get("rotation")
	rotation, okRotation := rotationV.(vInt)
	if version != rotationVersion || !okAt || !witnessTimeForm.MatchString(rotatedAt) ||
		!okID || !isLowerHexOfLen(keyID, 32) ||
		!okNamed || !isLowerHexOfLen(namedHex, 64) ||
		!okNamedID || !isLowerHexOfLen(namedKeyID, 32) ||
		!okSig || !isLowerHexOfLen(signatureHex, 128) ||
		!okRotation || int64(rotation) < 1 || int64(rotation) > maxRotation {
		return nil, false
	}
	st.named, _ = hex.DecodeString(namedHex)
	if keyIDFor(st.named) != namedKeyID {
		return nil, false
	}
	st.signature, _ = hex.DecodeString(signatureHex)
	st.rotation, st.rotatedAt, st.keyID, st.namedID = int64(rotation), rotatedAt, keyID, namedKeyID
	return st, true
}

// signingInput is what a rotation statement's signature covers: the prefix,
// then canon of the statement with its top-level signature removed and
// every other member retained.
func (st *rotationStatement) signingInput() []byte {
	return rotationSigningInput(st.obj)
}

func rotationSigningInput(obj *vObject) []byte {
	covered := newObject()
	for _, name := range obj.names {
		if name == "signature" {
			continue
		}
		v, _ := obj.get(name)
		covered.set(name, v)
	}
	return append([]byte(rotationContext), canon(covered)...)
}

// signedBy reports whether the statement's signature verifies under key,
// by §8.4's equation, which crypto/ed25519 verifies.
func (st *rotationStatement) signedBy(key ed25519.PublicKey) bool {
	return len(key) == ed25519.PublicKeySize && ed25519.Verify(key, st.signingInput(), st.signature)
}

// reachedKey is a key the walk reached: the key pinned, at position 0, or a
// key a followed rotation rotated to, at its rotation's ordinal.
type reachedKey struct {
	key   ed25519.PublicKey
	keyID string
}

// registryWalk is what the walk of a registry establishes (SPEC.md §3b and
// §4 step 2): the seals that load, first of a session first, in the order
// they load; the keys reached, in order, the key pinned first; and the
// walk's finding, nil when it has none.
type registryWalk struct {
	seals   map[string]seal
	order   []string
	keys    []reachedKey
	finding finding
}

// followed is how many rotations the walk followed.
func (w *registryWalk) followed() int { return len(w.keys) - 1 }

// current is the last key the walk reached.
func (w *registryWalk) current() reachedKey { return w.keys[len(w.keys)-1] }

// position is the place of the key a key id names among the keys reached,
// or -1 for a key id that names none.
func (w *registryWalk) position(keyID string) int {
	for i, k := range w.keys {
		if k.keyID == keyID {
			return i
		}
	}
	return -1
}

// walkRegistry walks a registry's lines from the key pinned (SPEC.md §3b):
// each line that is not a rotation statement is read as a seal under the
// current key; each rotation is followed when the key before it signed it,
// in order, naming a key the key rule accepts, and the key it names signed
// its reverse on the line after it; and the first statement that is not so
// stops the walk with its finding.
func walkRegistry(data []byte, pinned ed25519.PublicKey) *registryWalk {
	w := &registryWalk{seals: map[string]seal{}, keys: []reachedKey{{key: pinned, keyID: keyIDFor(pinned)}}}
	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if strings.TrimSpace(line) == "" {
			continue
		}
		kind, obj := rotationKindOf(line)
		if kind == "" {
			w.loadSeal(line)
			continue
		}
		if w.finding != nil {
			// past a finding nothing is followed, and a rotation statement
			// is never a seal
			continue
		}
		status := ""
		if kind == rotationKindReverse {
			status = statusRotationForged
		} else {
			var next string
			if i+1 < len(lines) {
				next = lines[i+1]
			}
			status = w.follow(obj, next)
			if status == "" {
				i++ // the continuation, taken with its rotation
				continue
			}
		}
		w.finding = finding{"status": status, "rotation": int64(w.followed() + 1)}
	}
	return w
}

// follow takes the rotation a key-rotation statement states, with the line
// after it, or answers the first check it fails (SPEC.md §3b, 1 to 5).
func (w *registryWalk) follow(obj *vObject, nextLine string) string {
	st, ok := rotationStatementOf(rotationKindForward, obj)
	if !ok {
		return statusRotationBreak
	}
	current := w.current()
	if st.keyID != current.keyID || !st.signedBy(current.key) {
		return statusRotationForged
	}
	if st.rotation != int64(w.followed()+1) {
		return statusRotationOrder
	}
	if publicKeyFault(st.named) != keySound || w.position(st.namedID) >= 0 {
		return statusRotationKeyRefused
	}
	kind, reverseObj := rotationKindOf(nextLine)
	if kind != rotationKindReverse {
		return statusRotationBreak
	}
	reverse, ok := rotationStatementOf(rotationKindReverse, reverseObj)
	if !ok || reverse.rotation != st.rotation || reverse.rotatedAt != st.rotatedAt ||
		!bytes.Equal(reverse.named, current.key) || reverse.keyID != st.namedID || !reverse.signedBy(st.named) {
		return statusRotationBreak
	}
	w.keys = append(w.keys, reachedKey{key: st.named, keyID: st.namedID})
	return ""
}

// loadSeal loads a line as a seal under the current key (SPEC.md §4 step 2):
// one JSON object of the seal's members, its keyId the current key's and its
// signature verifying under it, the first loadable seal of a session first.
func (w *registryWalk) loadSeal(line string) {
	v, err := parseJSON([]byte(line))
	if err != nil {
		return
	}
	obj, ok := v.(*vObject)
	if !ok {
		return
	}
	sessionID, ok1 := memberString(obj, "sessionId")
	sealedAt, ok2 := memberString(obj, "sealedAt")
	keyID, ok3 := memberString(obj, "keyId")
	sigHex, ok4 := memberString(obj, "signature")
	countV, ok5 := obj.get("finalCount")
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return
	}
	// Any integer the canonical parser admits: SPEC.md §3 makes
	// finalCount an integer (§1.1) and nothing more, and parseJSON has
	// already refused a line holding one outside §1.1's range. So a seal
	// counting below zero that passes the checks below loads like any
	// other -- and, as the first for its session, is the one the
	// session's count is compared with
	// (corpus/stores/negative-seal-count-loads.json).
	count, ok := countV.(vInt)
	if !ok {
		return
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return
	}
	// The keyId must name the current key. It sits INSIDE the signed
	// payload, so the signature alone cannot establish it -- a seal signed by
	// this key while naming a foreign keyId verifies happily. SPEC.md §4 step 2
	// originally said "signature" and nothing else, and following that literally
	// is what surfaced the gap; the rule is now explicit and matches the
	// receipt-level key-id check. After a rotation the current key is the key
	// rotated to: a seal the key rotated from signs afterwards loads nothing.
	current := w.current()
	if keyID != current.keyID {
		return
	}
	if !ed25519.Verify(current.key, sealSigningInput(sessionID, int64(count), sealedAt, keyID), sig) {
		return
	}
	if _, seen := w.seals[sessionID]; seen {
		// SPEC.md §3 refuses re-sealing a session, so a conforming
		// gateway writes no second seal for one; where a registry holds
		// one anyway, §4 step 2 lets the first loadable seal win, first
		// in the registry's lines. See AMBIGUITIES.md, section 9.
		return
	}
	w.seals[sessionID] = seal{sessionID: sessionID, finalCount: int64(count)}
	w.order = append(w.order, sessionID)
}

// registryFirstKey is the key a gateway walks its own registry from, since
// it pins none out of band for itself (SPEC.md §3b, "The gateway's own
// reading"): the previous of the registry's first key-continuation
// statement, or own when it holds no rotation statement. A first rotation
// statement that names no key it can read gives own, and the walk from it
// then finds what it finds.
func registryFirstKey(data []byte, own ed25519.PublicKey) ed25519.PublicKey {
	for _, line := range strings.Split(string(data), "\n") {
		kind, obj := rotationKindOf(line)
		if kind != rotationKindReverse {
			continue
		}
		previous, _ := memberString(obj, "previous")
		if key, err := hex.DecodeString(previous); err == nil && len(key) == ed25519.PublicKeySize {
			return key
		}
		return own
	}
	return own
}

// rotationWalkError is the gateway's own reading of its registry refused: a
// walk that found something, or that ends at another key than the gateway's.
type rotationWalkError struct{ msg string }

func (e rotationWalkError) Error() string { return e.msg }

// registryRefusal is why a registry that did not load seals refuses: the
// walk's own words when its rotations do not hold, and otherwise that it
// could not be read, never taken for the absence of a seal.
func registryRefusal(err error) string {
	var walk rotationWalkError
	if errors.As(err, &walk) {
		return walk.msg
	}
	return "the registry could not be read"
}

// engineWalk is the gateway's own reading of its registry: the walk from
// its first key, which must find nothing and end at the gateway's own key.
// Anything else is a refusal -- to start, to seal, to admit into a session
// it does not hold, to answer /verify -- never a reading. A registry holding
// a key-rotation and no key-continuation is walked from the gateway's own
// key, so it is refused under the key rotated from (rotation-break) and
// under the key rotated to (rotation-forged) alike.
func engineWalk(data []byte, own ed25519.PublicKey) (*registryWalk, error) {
	w := walkRegistry(data, registryFirstKey(data, own))
	if w.finding != nil {
		return nil, rotationWalkError{fmt.Sprintf("the registry's rotations do not hold: %s at rotation %d; a rotation whose append was interrupted is finished by gateway rotate-key --resume, and nothing else", w.finding["status"], w.finding["rotation"])}
	}
	if !bytes.Equal(w.current().key, own) {
		return nil, rotationWalkError{fmt.Sprintf("the registry's rotations end at key %s, not this gateway's key %s: a gateway does not start under a key its registry rotated from, and a rotation pending its switch is finished by gateway rotate-key --resume", w.current().keyID, keyIDFor(own))}
	}
	return w, nil
}
