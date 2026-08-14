package main

// Registry-anchored verification of a receipt store (SPEC.md §1-§3).
//
// The shape is: run the inline per-receipt verification over every session in
// the store, reconstruct each session's callIndex sequence and prevSignature
// chain from the receipts that passed, then anchor the whole thing against the
// seals in the registry -- which are themselves dropped unless they verify
// under the public key.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Domain separation. SPEC.md §2: the context prefix is what stops a seal
// signature being replayed as a receipt signature or vice versa.
const (
	receiptContext = "judgment-pack-gateway/receipt/2:"
	sealContext    = "judgment-pack-gateway/seal/2:"
	receiptVersion = "2"
)

type finding map[string]any

type report struct {
	OK       bool      `json:"ok"`
	Findings []finding `json:"findings"`
}

func (r *report) marshal() ([]byte, error) {
	if r.Findings == nil {
		r.Findings = []finding{}
	}
	return json.Marshal(r)
}

// keyIDFor is the identifier a receipt carries so an implementation can tell
// "signed by a key I do not hold" from "signed by my key and tampered with",
// without the receipt ever carrying a key (SPEC.md §4).
func keyIDFor(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])[:32]
}

// --- receipts -------------------------------------------------------------

type receipt struct {
	obj           *vObject
	version       string
	sessionID     string
	callIndex     int64
	keyID         string
	authority     string
	resultDigest  string
	signature     string
	prevSignature string
	hasPrev       bool // false means the member was null: this is a session head
}

func receiptFrom(obj *vObject) (*receipt, error) {
	r := &receipt{obj: obj}
	str := func(name string) (string, error) {
		v, ok := obj.get(name)
		if !ok {
			return "", fmt.Errorf("missing member %q", name)
		}
		s, ok := v.(vString)
		if !ok {
			return "", fmt.Errorf("member %q is not a string", name)
		}
		return string(s), nil
	}
	var err error
	for _, f := range []struct {
		name string
		dst  *string
	}{
		{"receiptVersion", &r.version},
		{"sessionId", &r.sessionID},
		{"keyId", &r.keyID},
		{"authority", &r.authority},
		{"resultDigest", &r.resultDigest},
		{"signature", &r.signature},
		{"source", new(string)},
		{"argumentsDigest", new(string)},
		{"servedAt", new(string)},
	} {
		if *f.dst, err = str(f.name); err != nil {
			return nil, err
		}
	}
	ci, ok := obj.get("callIndex")
	if !ok {
		return nil, errors.New(`missing member "callIndex"`)
	}
	n, ok := ci.(vInt)
	if !ok {
		return nil, errors.New(`member "callIndex" is not an integer`)
	}
	if n < 0 {
		return nil, errors.New(`member "callIndex" is negative`)
	}
	r.callIndex = int64(n)

	prev, ok := obj.get("prevSignature")
	if !ok {
		return nil, errors.New(`missing member "prevSignature"`)
	}
	switch p := prev.(type) {
	case vNull:
	case vString:
		r.prevSignature, r.hasPrev = string(p), true
	default:
		return nil, errors.New(`member "prevSignature" is neither a string nor null`)
	}
	return r, nil
}

// signingInput is the byte string a receipt's signature covers: the context
// prefix, then the canonical form of every member of the receipt except the
// signature itself.
func (r *receipt) signingInput() []byte {
	covered := newObject()
	for _, name := range r.obj.names {
		if name == "signature" {
			continue
		}
		v, _ := r.obj.get(name)
		covered.set(name, v)
	}
	return append([]byte(receiptContext), canon(covered)...)
}

// --- seals ----------------------------------------------------------------

type seal struct {
	sessionID  string
	finalCount int64
}

// sealSigningInput is spelled out by SPEC.md §2: the seal context prefix, then
// canon over exactly these four members.
func sealSigningInput(sessionID string, finalCount int64, sealedAt, keyID string) []byte {
	covered := newObject()
	covered.set("sessionId", vString(sessionID))
	covered.set("finalCount", vInt(finalCount))
	covered.set("sealedAt", vString(sealedAt))
	covered.set("keyId", vString(keyID))
	return append([]byte(sealContext), canon(covered)...)
}

// loadSeals reads the append-only registry and drops any seal whose keyId is not
// the verifier's own or whose signature does not verify under the public key. A malformed line is
// likewise not a seal, so it is dropped too.
func loadSeals(path string, publicKey []byte) (map[string]seal, []string, error) {
	seals := map[string]seal{}
	var order []string

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return seals, order, nil
		}
		return nil, nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
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
		sessionID, ok1 := memberString(obj, "sessionId")
		sealedAt, ok2 := memberString(obj, "sealedAt")
		keyID, ok3 := memberString(obj, "keyId")
		sigHex, ok4 := memberString(obj, "signature")
		countV, ok5 := obj.get("finalCount")
		if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
			continue
		}
		count, ok := countV.(vInt)
		if !ok || count < 0 {
			continue
		}
		sig, err := hex.DecodeString(sigHex)
		if err != nil || len(sig) != ed25519.SignatureSize {
			continue
		}
		// The keyId must name the verifier's own key. It sits INSIDE the signed
		// payload, so the signature alone cannot establish it -- a seal signed by
		// this key while naming a foreign keyId verifies happily. SPEC.md §4 step 2
		// originally said "signature" and nothing else, and following that literally
		// is what surfaced the gap; the rule is now explicit and matches the
		// receipt-level key-id check.
		if keyID != keyIDFor(publicKey) {
			continue
		}
		if !ed25519.Verify(publicKey, sealSigningInput(sessionID, int64(count), sealedAt, keyID), sig) {
			continue
		}
		if _, seen := seals[sessionID]; seen {
			// SPEC.md §2 says re-sealing a session is refused, so a second
			// seal for one session should not exist. See AMBIGUITIES.md.
			continue
		}
		seals[sessionID] = seal{sessionID: sessionID, finalCount: int64(count)}
		order = append(order, sessionID)
	}
	return seals, order, nil
}

func memberString(obj *vObject, name string) (string, bool) {
	v, ok := obj.get(name)
	if !ok {
		return "", false
	}
	s, ok := v.(vString)
	return string(s), ok
}

// --- verification ---------------------------------------------------------

func verifyWithRegistry(storeRoot, registryPath, authority string, publicKey []byte) (*report, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes", ed25519.PublicKeySize)
	}
	rep := &report{OK: true, Findings: []finding{}}

	sessions, err := listSessions(storeRoot)
	if err != nil {
		return nil, err
	}
	counts := map[string]int64{}
	for _, sessionID := range sessions {
		findings, n, err := verifySession(storeRoot, sessionID, authority, publicKey)
		if err != nil {
			return nil, err
		}
		counts[sessionID] = n
		rep.Findings = append(rep.Findings, findings...)
	}

	seals, sealOrder, err := loadSeals(registryPath, publicKey)
	if err != nil {
		return nil, err
	}

	// SPEC.md §3 step 3: every session in the store must be anchored.
	for _, sessionID := range sessions {
		s, sealed := seals[sessionID]
		have := counts[sessionID]
		switch {
		case !sealed:
			rep.Findings = append(rep.Findings, finding{
				"sessionId": sessionID, "status": "unregistered-session",
			})
		case have < s.finalCount:
			rep.Findings = append(rep.Findings, finding{
				"sessionId": sessionID, "status": "tail-rollback",
				"have": have, "sealed": s.finalCount,
			})
		case have > s.finalCount:
			rep.Findings = append(rep.Findings, finding{
				"sessionId": sessionID, "status": "count-exceeds-seal",
				"have": have, "sealed": s.finalCount,
			})
		}
	}
	// SPEC.md §3 step 4: every sealed session must still be in the store.
	inStore := map[string]bool{}
	for _, s := range sessions {
		inStore[s] = true
	}
	for _, sessionID := range sealOrder {
		if !inStore[sessionID] {
			rep.Findings = append(rep.Findings, finding{
				"sessionId": sessionID, "status": "sealed-session-missing",
			})
		}
	}

	for _, f := range rep.Findings {
		if f["status"] != "ok" {
			rep.OK = false
			break
		}
	}
	return rep, nil
}

// listSessions enumerates the session directories under the store's receipts
// root (SPEC.md §2a: a session id names a directory and a verifier discovers
// sessions by enumerating). A store with no receipts root simply has none.
func listSessions(storeRoot string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(storeRoot, "receipts"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var sessions []string
	for _, e := range entries {
		if e.IsDir() {
			sessions = append(sessions, e.Name())
		}
	}
	sort.Strings(sessions)
	return sessions, nil
}

// verifySession returns the findings for one session and the number of receipt
// files it holds -- the "store count" the seal is compared against, which
// counts files present, not the highest callIndex.
func verifySession(storeRoot, sessionID, authority string, publicKey []byte) ([]finding, int64, error) {
	dir := filepath.Join(storeRoot, "receipts", sessionID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	// Filename string order. SPEC.md does not make finding order normative;
	// corpus/README.md records that as an open question.
	sort.Strings(names)

	var findings []finding
	var valid []*receipt
	expectedKeyID := keyIDFor(publicKey)

	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, 0, err
		}
		r, status := checkReceipt(data, storeRoot, sessionID, name, authority, publicKey, expectedKeyID)
		if r == nil {
			findings = append(findings, finding{
				"sessionId": sessionID, "file": name, "status": status,
			})
			continue
		}
		findings = append(findings, finding{
			"sessionId": sessionID, "callIndex": r.callIndex, "status": status,
		})
		if status == "ok" {
			valid = append(valid, r)
		}
	}

	// A receipt that failed is excluded from the reconstruction, so the
	// sequence and chain are checked over what survived.
	sort.Slice(valid, func(i, j int) bool { return valid[i].callIndex < valid[j].callIndex })
	contiguous := true
	for i, r := range valid {
		if r.callIndex != int64(i) {
			contiguous = false
			break
		}
	}
	if !contiguous {
		findings = append(findings, finding{
			"sessionId": sessionID, "callIndex": nil, "status": "sequence-broken",
		})
	} else {
		for i, r := range valid {
			var want string
			var wantSet bool
			if i > 0 {
				want, wantSet = valid[i-1].signature, true
			}
			if r.hasPrev != wantSet || (wantSet && r.prevSignature != want) {
				findings = append(findings, finding{
					"sessionId": sessionID, "callIndex": nil, "status": "chain-broken",
				})
				break
			}
		}
	}
	return findings, int64(len(names)), nil
}

// checkReceipt runs the per-receipt checks in the order SPEC.md §1 lists them:
// SPEC 1.4's normative order, exactly: lexical form (order 1), then
// unsupported-version, key-mismatch, signature-mismatch, misfiled,
// authority-mismatch, artifact-missing, artifact-mismatch. The first failure is
// the receipt's status; a receipt reports one status, not a list. A nil receipt
// means the file never became a receipt at all, which includes a receipt that
// parsed but failed order 1.
func checkReceipt(data []byte, storeRoot, sessionID, fileName, authority string, publicKey []byte, expectedKeyID string) (*receipt, string) {
	v, err := parseJSON(data)
	if err != nil {
		return nil, "malformed"
	}
	obj, ok := v.(*vObject)
	if !ok {
		return nil, "malformed"
	}
	r, err := receiptFrom(obj)
	if err != nil {
		return nil, "malformed"
	}
	// SPEC 1.4 order 1: every LEXICAL requirement, settled before the version,
	// the key id, or any cryptographic work. SPEC 1.2 fixes both forms --
	// resultDigest is "sha256:" + 64 lowercase hex, signature is Ed25519 in hex.
	// encoding/hex accepts uppercase, so lowercase is checked explicitly rather
	// than inferred from a successful decode.
	digestHex, ok := strings.CutPrefix(r.resultDigest, "sha256:")
	if !ok || !isLowerHexOfLen(digestHex, 64) {
		return nil, "malformed"
	}
	// A signature containing non-hex characters is malformed, not a mismatch:
	// nothing about it is a failed cryptographic check.
	if _, err := hex.DecodeString(r.signature); err != nil {
		return nil, "malformed"
	}

	if r.version != receiptVersion {
		return r, "unsupported-version"
	}
	// key-mismatch precedes signature-mismatch (SPEC 1.4 orders 3 then 4), so a
	// receipt carrying both defects reports the earlier one. Verifying first
	// reported the later one and made the diagnostic depend on our own order.
	if subtle.ConstantTimeCompare([]byte(r.keyID), []byte(expectedKeyID)) != 1 {
		return r, "key-mismatch"
	}
	// Well-formed hex of the wrong length is NOT malformed: it is a signature
	// that cannot verify, which is order 4.
	sig, err := hex.DecodeString(r.signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return r, "signature-mismatch"
	}
	if !ed25519.Verify(publicKey, r.signingInput(), sig) {
		return r, "signature-mismatch"
	}
	// Location binding: the receipt has to sit where it says it does, so a
	// valid receipt cannot be moved within or between sessions.
	stem := strings.TrimSuffix(fileName, ".json")
	n, err := strconv.ParseInt(stem, 10, 64)
	if err != nil || n != r.callIndex || r.sessionID != sessionID {
		return r, "misfiled"
	}
	if r.authority != authority {
		return r, "authority-mismatch"
	}
	// Result re-digest: the retained artifact must still be the bytes the
	// receipt attested.
	artifact, err := os.ReadFile(filepath.Join(storeRoot, "artifacts", digestHex))
	if err != nil {
		return r, "artifact-missing"
	}
	sum := sha256.Sum256(artifact)
	if hex.EncodeToString(sum[:]) != digestHex {
		return r, "artifact-mismatch"
	}
	return r, "ok"
}

// isLowerHexOfLen reports whether s is exactly n lowercase hexadecimal
// characters. encoding/hex accepts uppercase and SPEC 1.2 does not, so a
// successful decode is not sufficient evidence of the stated form.
func isLowerHexOfLen(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
