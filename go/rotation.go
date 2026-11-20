package main

// Key rotation (SPEC.md §3b): the continuity statement, the pair of registry
// lines by which a gateway hands its signing key on, and the walk a verifier
// follows from the key it pinned. A registry that holds no rotation statement
// is read exactly as before: every line a seal or nothing, under the one key.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
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

// rotationOptional are the members a statement holds beside those exactly
// where a P-256 key signs it (alg) or is the key it names (nextAlg,
// previousAlg), each then "ES256" (ADR-0053 §1, §7).
var rotationOptional = map[string]map[string]bool{
	rotationKindForward: {"alg": true, "nextAlg": true},
	rotationKindReverse: {"alg": true, "previousAlg": true},
}

// rotationStatement is one rotation statement that holds its form.
type rotationStatement struct {
	kind      string
	rotation  int64
	rotatedAt string
	keyID     string
	// named is the key the statement names: next on a key-rotation,
	// previous on a key-continuation.
	named   []byte
	namedID string
	// alg is the signer's algorithm, namedAlg the named key's.
	alg, namedAlg string
	signature     []byte
	obj           *vObject
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
	allowed, optional := rotationMembers[kind], rotationOptional[kind]
	for name := range allowed {
		if _, present := obj.get(name); !present {
			return nil, false
		}
	}
	for name := range obj.byName {
		if !allowed[name] && !optional[name] {
			return nil, false
		}
	}
	named, namedID, namedAlgMember := "next", "nextKeyId", "nextAlg"
	if kind == rotationKindReverse {
		named, namedID, namedAlgMember = "previous", "previousKeyId", "previousAlg"
	}
	alg, okAlg := recordAlg(obj, "alg")
	namedAlg, okNamedAlg := recordAlg(obj, namedAlgMember)
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
		!okAlg || !okNamedAlg ||
		!okNamed || !isLowerHexOfLen(namedHex, publicKeyHexLen(namedAlg)) ||
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
	st.alg, st.namedAlg = alg, namedAlg
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

// signedBy reports whether the statement's signature verifies under key by
// the algorithm the statement's alg names, which key must be of.
func (st *rotationStatement) signedBy(key heldKey) bool {
	return verifyByAlgorithm(st.alg, key, st.signingInput(), st.signature)
}

// reachedKey is a key the walk reached: the key pinned, at position 0, or a
// key a followed rotation rotated to, at its rotation's ordinal.
type reachedKey struct {
	key   []byte
	keyID string
	// alg is the algorithm the key was reached with: the pin's, or its
	// rotation's nextAlg (ADR-0053 §1).
	alg string
	// rotatedAt, forward and reverse are, for a key a rotation rotated to,
	// that rotation's rotatedAt and its two statements' lines as the
	// registry holds them: what the key history serves of it (SPEC.md §3e).
	// They are "" for the key pinned.
	rotatedAt, forward, reverse string
}

// held is the key with its algorithm.
func (k reachedKey) held() heldKey { return heldKey{alg: k.alg, key: k.key} }

// registryWalk is what the walk of a registry establishes (SPEC.md §3b and
// §4 step 2): the seals that load, first of a session first, in the order
// they load; the keys reached, in order, the key pinned first; and the
// walk's finding, nil when it has none.
type registryWalk struct {
	seals   map[string]seal
	order   []string
	keys    []reachedKey
	finding finding
	// conflicted are the sessions for which more than one seal loads, one
	// of them at least a seal made after an interruption (SPEC.md §3c): the
	// first still anchors the session, and the verdict finds seal-conflict.
	conflicted map[string]bool
	// continuation is the store continuation the registry's first line
	// loads, nil for none; continuationFinding a store continuation that
	// does not load where it stands (SPEC.md §3d), at most one.
	continuation        *storeContinuation
	continuationFinding finding
	// lines is how many of the registry's lines the walk has passed: the
	// place of the next line it reads.
	lines int
	// keysOnly is a walk that loads no seal, every line that is not a
	// rotation statement or a store continuation passed over: what the key
	// history needs of a registry (SPEC.md §3e), each seal's signature left
	// unchecked, since a seal never moves the walk from one key to another.
	keysOnly bool
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
	return walkRegistryFrom(data, edKey(pinned))
}

// walkRegistryFrom is walkRegistry from a key pinned with its algorithm.
func walkRegistryFrom(data []byte, pinned heldKey) *registryWalk {
	w := &registryWalk{seals: map[string]seal{}, conflicted: map[string]bool{}, keys: []reachedKey{{key: pinned.key, alg: pinned.alg, keyID: pinned.keyID()}}}
	w.walkLines(data)
	return w
}

// continued is the walk of more, the bytes that follow those w walked, which
// end a line, continued from where w stopped: from the keys w reached, its
// seals those of more alone. w is not changed; absorb takes the walk into it.
// Walking w's bytes and then more is walking the two as one, but where w
// ends at a rotation whose continuation is the first line of more -- and
// that w finds rotation-break, so a walk with a finding is never continued.
func (w *registryWalk) continued(more []byte) *registryWalk {
	next := &registryWalk{seals: map[string]seal{}, conflicted: map[string]bool{}, keys: slices.Clone(w.keys), lines: w.lines,
		continuation: w.continuation, continuationFinding: w.continuationFinding}
	next.walkLines(more)
	return next
}

// absorb takes next, w's walk continued (continued), into w: w is then the
// walk of its bytes and next's as one.
func (w *registryWalk) absorb(next *registryWalk) {
	w.keys, w.finding = next.keys, next.finding
	w.lines, w.continuation, w.continuationFinding = next.lines, next.continuation, next.continuationFinding
	for _, id := range next.order {
		w.take(next.seals[id])
	}
	for id := range next.conflicted {
		w.conflicted[id] = true
	}
}

// walkLines walks data's lines on from where w stands.
func (w *registryWalk) walkLines(data []byte) {
	lines := strings.Split(string(data), "\n")
	base := w.lines
	if n := len(lines); lines[n-1] == "" {
		w.lines += n - 1
	} else {
		w.lines += n
	}
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if strings.TrimSpace(line) == "" {
			continue
		}
		// a store continuation is never a seal or a rotation statement,
		// and loads only as the registry's first line (SPEC.md §3d)
		if obj := continuationLine(line); obj != nil {
			w.readContinuation(obj, base+i)
			continue
		}
		kind, obj := rotationKindOf(line)
		if kind == "" && w.keysOnly {
			continue
		}
		if kind == "" {
			// a line whose kind is seal-after-interruption is read as
			// that seal and as nothing else (SPEC.md §3c)
			// and a line holding sealVersion as a seal of that version
			// and as nothing else (ADR-0036)
			if sealObj := interruptionSealLine(line); sealObj != nil {
				w.loadInterruptionSeal(sealObj)
			} else if sealObj := versionedSealLine(line); sealObj != nil {
				w.loadVersionedSeal(sealObj)
			} else {
				w.loadSeal(line)
			}
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
			status = w.follow(obj, line, next)
			if status == "" {
				i++ // the continuation, taken with its rotation
				continue
			}
		}
		w.finding = finding{"status": status, "rotation": int64(w.followed() + 1)}
	}
}

// follow takes the rotation a key-rotation statement states, the object of
// line, with the line after it, or answers the first check it fails
// (SPEC.md §3b, 1 to 5).
func (w *registryWalk) follow(obj *vObject, line, nextLine string) string {
	st, ok := rotationStatementOf(rotationKindForward, obj)
	if !ok {
		return statusRotationBreak
	}
	current := w.current()
	// the signer's algorithm is the current key's, and its signature
	// verifies by it (ADR-0053 §7, check 2)
	if st.keyID != current.keyID || st.alg != current.alg || !st.signedBy(current.held()) {
		return statusRotationForged
	}
	if st.rotation != int64(w.followed()+1) {
		return statusRotationOrder
	}
	// the key named holds nextAlg's key rule, and its key id is none of a
	// key reached, of either algorithm (check 4)
	if !keySoundFor(st.namedAlg, st.named) || w.position(st.namedID) >= 0 {
		return statusRotationKeyRefused
	}
	kind, reverseObj := rotationKindOf(nextLine)
	if kind != rotationKindReverse {
		return statusRotationBreak
	}
	reverse, ok := rotationStatementOf(rotationKindReverse, reverseObj)
	// the pair (check 5): the continuation's alg is the rotation's nextAlg,
	// its previous and previousAlg the current key's bytes and algorithm,
	// and it verifies under next by that algorithm
	if !ok || reverse.rotation != st.rotation || reverse.rotatedAt != st.rotatedAt ||
		reverse.alg != st.namedAlg || reverse.namedAlg != current.alg ||
		!bytes.Equal(reverse.named, current.key) || reverse.keyID != st.namedID || !reverse.signedBy(heldKey{alg: st.namedAlg, key: st.named}) {
		return statusRotationBreak
	}
	w.keys = append(w.keys, reachedKey{key: st.named, alg: st.namedAlg, keyID: st.namedID, rotatedAt: st.rotatedAt, forward: line, reverse: nextLine})
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
	// alg (ADR-0053 §1): absent, Ed25519, whose signature's hex stays
	// lenient of case, as it always was; "ES256", whose signature is 128
	// lowercase hexadecimal characters; any other value loads nothing
	alg, okAlg := recordAlg(obj, "alg")
	if !okAlg || alg == algES256 && !isLowerHexOfLen(sigHex, 128) {
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
	if keyID != current.keyID || alg != current.alg {
		return
	}
	if !verifyByAlgorithm(alg, current.held(), sealSigningInputFor(alg, sessionID, int64(count), sealedAt, keyID), sig) {
		return
	}
	w.take(seal{sessionID: sessionID, sealedAt: sealedAt, finalCount: int64(count), signature: hex.EncodeToString(sig), keyPos: len(w.keys) - 1})
}

// take keeps a seal that loaded. SPEC.md §3 refuses re-sealing a session,
// so a conforming gateway writes no second seal for one; where a registry
// holds one anyway, §4 step 2 lets the first loadable seal win, first in the
// registry's lines (AMBIGUITIES.md, section 9). Two seals of today's form
// for one session are read so and nothing more, as they always were; a
// second seal where either is a seal made after an interruption is a
// conflict the verdict finds (SPEC.md §3c), the first still the anchor.
func (w *registryWalk) take(s seal) {
	if first, seen := w.seals[s.sessionID]; seen {
		if first.interrupted || s.interrupted {
			w.conflicted[s.sessionID] = true
		}
		return
	}
	w.seals[s.sessionID] = s
	w.order = append(w.order, s.sessionID)
}

// A seal made after an interruption (SPEC.md §3c): the record by which a
// gateway seals a session an earlier process left open, over the receipts
// the store holds in it, saying so. It only seals: such a session is never
// continued.
const (
	sealKindInterruption    = "seal-after-interruption"
	interruptionSealContext = "judgment-pack-gateway/seal-after-interruption/1:"
	// sealedVia: the operator's command, or the gateway's start with the
	// switch on.
	sealedViaCommand = "command"
	sealedViaStart   = "start"
)

// interruptionSealMembers are the members such a seal holds, exactly; one of
// a session of a scope identifier holds scopedSealMembers besides
// (ADR-0036), and is signed under interruptionSealContext2.
var interruptionSealMembers = map[string]bool{
	"finalCount": true, "headSignature": true, "keyId": true, "kind": true,
	"sealedAt": true, "sealedVia": true, "sessionId": true, "signature": true,
	"alg": true,
}

// A seal of version 2 (ADR-0036; SPEC.md §3, "A seal of version 2"): the
// seal of a session of a scope identifier, naming it under the signature by
// its digest, never by the identifier, so a registry line carries no scope
// identifier and a store of scopes kept apart reads none from the chain it
// reads whole. The member sealVersion selects the form: a line holding it is
// read as a seal of that version and as nothing else, so neither form is read
// as the other, and a seal of §3's form is the bytes it always was.
const (
	sealVersionScoped        = "2"
	scopedSealContext        = "judgment-pack-gateway/seal-version/2:"
	interruptionSealContext2 = "judgment-pack-gateway/seal-after-interruption/2:"
	sealScopeDigestContext   = "judgment-pack-gateway/seal-scope/1:"
)

// A seal of version 3 (ADR-0042; SPEC.md §3, "A seal of version 3"): the
// form of version 2, of either kind, whose scopeDigest is taken over the
// session's scope salt beside the identifier and the session's id. The salt is
// 32 random bytes the gateway draws for the session and writes, in
// hexadecimal, into every receipt of it (scopeSalt, SPEC.md §1.2a) and into no
// registry line, so a reader of the registry alone cannot test a guessed scope
// identifier against the seal, while a reader holding a receipt of the session
// digests its scope and salt and compares, as for version 2.
const (
	sealVersionSalted            = "3"
	saltedSealContext            = "judgment-pack-gateway/seal-version/3:"
	interruptionSealContext3     = "judgment-pack-gateway/seal-after-interruption/3:"
	sealScopeSaltedDigestContext = "judgment-pack-gateway/seal-scope/2:"
)

// scopedSealMembers are the members a seal of version 2 holds, exactly; a
// seal after an interruption of version 2 holds scopeDigest and sealVersion
// beside its own.
var scopedSealMembers = map[string]bool{
	"finalCount": true, "keyId": true, "scopeDigest": true, "sealVersion": true,
	"sealedAt": true, "sessionId": true, "signature": true,
	"alg": true,
}

// sealScopeDigest is what a seal of version 2 names a session's scope by
// (SPEC.md §3, "A seal of version 2"): "sha256:" and the lowercase hex of
// SHA-256 over the prefix and canon of {"scope", "sessionId"}. The session's
// id is in it, so two sessions of one scope carry different digests and a
// reader of the registry cannot group sessions by scope.
func sealScopeDigest(sessionID, scope string) string {
	named := newObject()
	named.set("scope", vString(scope))
	named.set("sessionId", vString(sessionID))
	sum := sha256.Sum256(append([]byte(sealScopeDigestContext), canon(named)...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// saltedScopeDigest is what a seal of version 3 names a session's scope by
// (SPEC.md §3, "A seal of version 3"): "sha256:" and the lowercase hex of
// SHA-256 over the prefix and canon of {"salt", "scope", "sessionId"}, salt the
// session's scope salt as its receipts carry it, 64 lowercase hexadecimal
// characters.
func saltedScopeDigest(sessionID, scope, salt string) string {
	named := newObject()
	named.set("salt", vString(salt))
	named.set("scope", vString(scope))
	named.set("sessionId", vString(sessionID))
	sum := sha256.Sum256(append([]byte(sealScopeSaltedDigestContext), canon(named)...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// namesScope is whether a receipt's scope identifier and scope salt ("" for
// none) are the ones s names: for a seal of version 3 the digest over the
// three, the salt present and of its form; for one of version 2 the digest
// over the identifier and the session's id, whatever salt the receipt
// carries; a seal of a form that names no scope names none.
func (s seal) namesScope(sessionID, scope, salt string) bool {
	switch {
	case s.scopeDigest == "":
		return false
	case s.salted:
		return isScopeSalt(salt) && saltedScopeDigest(sessionID, scope, salt) == s.scopeDigest
	default:
		return sealScopeDigest(sessionID, scope) == s.scopeDigest
	}
}

// isScopeSalt is a scope salt of its form (SPEC.md §1.2a, scopeSalt): the 32
// bytes in 64 lowercase hexadecimal characters.
func isScopeSalt(s string) bool { return isLowerHexOfLen(s, 64) }

// versionedSealLine is a registry line's object when the line is one JSON
// object, read by §1.1's parser, that holds a sealVersion member and no kind,
// and nil for any other line.
func versionedSealLine(line string) *vObject {
	v, err := parseJSON([]byte(line))
	if err != nil {
		return nil
	}
	obj, ok := v.(*vObject)
	if !ok {
		return nil
	}
	if _, versioned := obj.get("sealVersion"); !versioned {
		return nil
	}
	if _, kinded := obj.get("kind"); kinded {
		return nil
	}
	return obj
}

// scopedSealOf holds a seal of version 2 to its form: exactly its members,
// each of its form. It answers the seal, the key id it names and its
// signature's bytes.
func scopedSealOf(obj *vObject) (seal, string, []byte, bool) {
	for name := range obj.byName {
		if !scopedSealMembers[name] {
			return seal{}, "", nil, false
		}
	}
	version, okVersion := memberString(obj, "sealVersion")
	sessionID, okSession := memberString(obj, "sessionId")
	keyID, okKey := memberString(obj, "keyId")
	sealedAt, okAt := memberString(obj, "sealedAt")
	scopeDigest, okScope := memberString(obj, "scopeDigest")
	signatureHex, okSig := memberString(obj, "signature")
	countV, _ := obj.get("finalCount")
	count, okCount := countV.(vInt)
	if !okVersion || (version != sealVersionScoped && version != sealVersionSalted) ||
		!okSession || requireSession(sessionID) != nil ||
		!okCount || int64(count) < 0 ||
		!okKey || !isLowerHexOfLen(keyID, 32) ||
		!okAt || !witnessTimeForm.MatchString(sealedAt) ||
		!okScope || !isDigest(scopeDigest) ||
		!okSig || !isLowerHexOfLen(signatureHex, 128) {
		return seal{}, "", nil, false
	}
	signature, _ := hex.DecodeString(signatureHex)
	return seal{sessionID: sessionID, sealedAt: sealedAt, finalCount: int64(count), scopeDigest: scopeDigest, salted: version == sealVersionSalted}, keyID, signature, true
}

// versionedSealContext is the prefix a seal holding sealVersion is signed
// under: version 2's, or version 3's for "3". scopedSealOf has held the
// version to one of the two.
func versionedSealContext(obj *vObject) string {
	if version, _ := memberString(obj, "sealVersion"); version == sealVersionSalted {
		return saltedSealContext
	}
	return scopedSealContext
}

// signedOver is what a seal whose signature covers every other member is
// signed over: the prefix, then canon of the record with its top-level
// signature removed.
func signedOver(prefix string, obj *vObject) []byte {
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

// loadVersionedSeal loads a line holding sealVersion as a seal of version 2
// or 3, each under its own prefix, under the current key, or loads nothing.
func (w *registryWalk) loadVersionedSeal(obj *vObject) {
	s, keyID, signature, ok := scopedSealOf(obj)
	if !ok {
		return
	}
	current := w.current()
	alg, okAlg := recordAlg(obj, "alg")
	if !okAlg || keyID != current.keyID || alg != current.alg || !verifyByAlgorithm(alg, current.held(), signedOver(versionedSealContext(obj), obj), signature) {
		return
	}
	s.signature, s.keyPos = hex.EncodeToString(signature), len(w.keys)-1
	w.take(s)
}

// interruptionSealLine is a registry line's object when the line is one
// JSON object, read by §1.1's parser, whose kind member is
// seal-after-interruption, and nil for any other line.
func interruptionSealLine(line string) *vObject {
	v, err := parseJSON([]byte(line))
	if err != nil {
		return nil
	}
	obj, ok := v.(*vObject)
	if !ok {
		return nil
	}
	if kind, _ := memberString(obj, "kind"); kind != sealKindInterruption {
		return nil
	}
	return obj
}

// interruptionSealOf holds a seal made after an interruption to its form
// (SPEC.md §3c): exactly its members, each of its form. It answers the
// seal, the key id it names and its signature's bytes.
func interruptionSealOf(obj *vObject) (seal, string, []byte, bool) {
	// every member is required below, and §1.1's parser admits no name
	// twice, so a member of no other name is all that is left to refuse;
	// one of version 2 or 3 holds sealVersion "2" or "3" and a scopeDigest
	// besides (ADR-0036, ADR-0042)
	_, versioned := obj.get("sealVersion")
	for name := range obj.byName {
		if !interruptionSealMembers[name] && (!versioned || (name != "sealVersion" && name != "scopeDigest")) {
			return seal{}, "", nil, false
		}
	}
	var scopeDigest string
	var salted bool
	if versioned {
		version, okVersion := memberString(obj, "sealVersion")
		named, okScope := memberString(obj, "scopeDigest")
		if !okVersion || (version != sealVersionScoped && version != sealVersionSalted) || !okScope || !isDigest(named) {
			return seal{}, "", nil, false
		}
		scopeDigest, salted = named, version == sealVersionSalted
	}
	sessionID, okSession := memberString(obj, "sessionId")
	head, okHead := memberString(obj, "headSignature")
	keyID, okKey := memberString(obj, "keyId")
	sealedAt, okAt := memberString(obj, "sealedAt")
	via, _ := memberString(obj, "sealedVia")
	signatureHex, okSig := memberString(obj, "signature")
	countV, _ := obj.get("finalCount")
	count, okCount := countV.(vInt)
	if !okSession || requireSession(sessionID) != nil ||
		!okCount || int64(count) < 1 ||
		!okHead || !isLowerHexOfLen(head, 128) ||
		!okKey || !isLowerHexOfLen(keyID, 32) ||
		!okAt || !witnessTimeForm.MatchString(sealedAt) ||
		(via != sealedViaCommand && via != sealedViaStart) ||
		!okSig || !isLowerHexOfLen(signatureHex, 128) {
		return seal{}, "", nil, false
	}
	signature, _ := hex.DecodeString(signatureHex)
	return seal{sessionID: sessionID, sealedAt: sealedAt, finalCount: int64(count), interrupted: true, head: head, scopeDigest: scopeDigest, salted: salted}, keyID, signature, true
}

// interruptionSealSigningInput is what such a seal's signature covers: the
// prefix, then canon of the seal with its top-level signature removed and
// every other member retained. A seal of version 2, which names a scope, is
// signed under a prefix of its own (ADR-0036), so a ten-member seal is never
// read under the eight-member form's prefix, nor the reverse.
func interruptionSealSigningInput(obj *vObject) []byte {
	if version, versioned := memberString(obj, "sealVersion"); versioned && version == sealVersionSalted {
		return signedOver(interruptionSealContext3, obj)
	}
	if _, versioned := obj.get("sealVersion"); versioned {
		return signedOver(interruptionSealContext2, obj)
	}
	return signedOver(interruptionSealContext, obj)
}

// loadInterruptionSeal loads a seal made after an interruption under the
// current key, as loadSeal loads one of today's form: of its form, its keyId
// the current key's and its signature verifying under it. A line that is not
// so loads nothing, and is never read as a seal of today's form.
func (w *registryWalk) loadInterruptionSeal(obj *vObject) {
	s, keyID, signature, ok := interruptionSealOf(obj)
	if !ok {
		return
	}
	current := w.current()
	alg, okAlg := recordAlg(obj, "alg")
	if !okAlg || keyID != current.keyID || alg != current.alg || !verifyByAlgorithm(alg, current.held(), interruptionSealSigningInput(obj), signature) {
		return
	}
	s.signature, s.keyPos = hex.EncodeToString(signature), len(w.keys)-1
	w.take(s)
}

// registryFirstKey is the key a gateway walks its own registry from, since
// it pins none out of band for itself (SPEC.md §3b, "The gateway's own
// reading"): the previous of the registry's first key-continuation
// statement, or own when it holds no rotation statement. A first rotation
// statement that names no key it can read gives own, and the walk from it
// then finds what it finds.
func registryFirstKey(data []byte, own heldKey) heldKey {
	for _, line := range strings.Split(string(data), "\n") {
		kind, obj := rotationKindOf(line)
		if kind != rotationKindReverse {
			continue
		}
		// with its previousAlg (ADR-0053 §7, "The gateway's own reading")
		previous, _ := memberString(obj, "previous")
		if alg, ok := recordAlg(obj, "previousAlg"); ok {
			if key, err := hex.DecodeString(previous); err == nil && 2*len(key) == publicKeyHexLen(alg) {
				return heldKey{alg: alg, key: key}
			}
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
func engineWalk(data []byte, own heldKey) (*registryWalk, error) {
	w := walkRegistryFrom(data, registryFirstKey(data, own))
	if err := w.ownReading(own); err != nil {
		return nil, err
	}
	return w, nil
}

// ownReading is engineWalk's judgment of a walk: a refusal where it found
// something, or ends at a key other than own.
func (w *registryWalk) ownReading(own heldKey) error {
	if w.finding != nil {
		return rotationWalkError{fmt.Sprintf("the registry's rotations do not hold: %s at rotation %d; a rotation whose append was interrupted is finished by gateway rotate-key --resume, and nothing else", w.finding["status"], w.finding["rotation"])}
	}
	if w.continuationFinding != nil {
		return rotationWalkError{fmt.Sprintf("the registry's store continuation does not hold: %s; a store continuation is a registry's first line, signed by the key in force when the store was rotated", w.continuationFinding["status"])}
	}
	// the key and its algorithm, as a pair (ADR-0053 §7)
	if !w.current().held().is(own) {
		return rotationWalkError{fmt.Sprintf("the registry's rotations end at key %s, not this gateway's key %s: a gateway does not start under a key its registry rotated from, and a rotation pending its switch is finished by gateway rotate-key --resume", w.current().keyID, own.keyID())}
	}
	return nil
}
