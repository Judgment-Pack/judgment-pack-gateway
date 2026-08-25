package main

// The corpus must have teeth.
//
// It is easy to ship a conformance suite every implementation passes, which
// proves nothing. These tests check the other direction: implementations wrong in
// the specific, realistic ways a second implementation goes wrong must be CAUGHT.
// Each defect below is the DEFAULT behaviour of some standard library, which is
// why they are worth pinning rather than trusting.
//
// This matters more now than it did with two implementations. The corpus is the
// only thing left standing between this code and silent format drift.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"unicode/utf16"
)

const corpusDir = "../corpus"

// defective wraps the real implementation with one injected fault.
type defective struct {
	canonDefect  func([]byte) []byte
	ignoreAnchor bool
}

func (defective) label() string { return "defective" }

func (d defective) canon(source string) ([]byte, bool) {
	out, err := canonText([]byte(source))
	if err != nil {
		return nil, false
	}
	if d.canonDefect != nil {
		out = d.canonDefect(out)
	}
	return out, true
}

func (d defective) verify(storeRoot, registryPath, authority string, publicKey []byte) (bool, []map[string]any, error) {
	if !d.ignoreAnchor {
		return inProcess{}.verify(storeRoot, registryPath, authority, publicKey)
	}
	// Every receipt checked, the registry anchor ignored -- the exact gap this
	// gateway exists to close.
	sessions, err := listSessions(storeRoot)
	if err != nil {
		return false, nil, err
	}
	ok := true
	var findings []map[string]any
	for _, sessionID := range sessions {
		sessionFindings, _, err := verifySession(storeRoot, sessionID, authority, publicKey)
		if err != nil {
			return false, nil, err
		}
		for _, f := range sessionFindings {
			encoded, _ := json.Marshal(f)
			var asMap map[string]any
			_ = json.Unmarshal(encoded, &asMap)
			if status, _ := asMap["status"].(string); status != "ok" {
				ok = false
			}
			findings = append(findings, asMap)
		}
	}
	return ok, findings, nil
}

// Go's encoding/json escapes these three by default.
func htmlEscaping(out []byte) []byte {
	replaced := strings.NewReplacer("<", "\\u003c", ">", "\\u003e", "&", "\\u0026")
	return []byte(replaced.Replace(string(out)))
}

// Many JSON encoders default to ASCII-only output.
func asciiEscaping(out []byte) []byte {
	var sb strings.Builder
	for _, r := range string(out) {
		if r < 128 {
			sb.WriteRune(r)
			continue
		}
		for _, unit := range utf16.Encode([]rune{r}) {
			fmt.Fprintf(&sb, `\u%04x`, unit)
		}
	}
	return []byte(sb.String())
}

func failuresFor(t *testing.T, impl implementation) string {
	t.Helper()
	failures, _, _, err := runCorpus(corpusDir, impl)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(failures, "\n")
}

func TestCorpusCatchesHTMLEscaping(t *testing.T) {
	joined := failuresFor(t, defective{canonDefect: htmlEscaping})
	if !strings.Contains(joined, "<a>&b</a>") {
		t.Fatalf("corpus missed Go-style HTML escaping:\n%s", joined)
	}
}

func TestCorpusCatchesASCIIEscaping(t *testing.T) {
	joined := failuresFor(t, defective{canonDefect: asciiEscaping})
	if joined == "" {
		t.Fatal("corpus missed ASCII-only escaping")
	}
}

func TestCorpusCatchesAVerifierThatIgnoresTheRegistry(t *testing.T) {
	joined := failuresFor(t, defective{ignoreAnchor: true})
	for _, missed := range []string{
		"tail-rollback", "unregistered-session", "count-exceeds-seal", "sealed-session-missing",
	} {
		if !strings.Contains(joined, missed) {
			t.Fatalf("corpus did not catch a verifier ignoring the registry (%s):\n%s",
				missed, joined)
		}
	}
}

func TestSessionCountIncludesOnlyJSONFiles(t *testing.T) {
	for _, tc := range []struct {
		name        string
		removeTail  bool
		replacement string
		wantOK      bool
		want        map[string]int
	}{
		{"stray non-receipt file", false, ".DS_Store", true, map[string]int{"ok": 3}},
		{"deleted tail receipt", true, "", false, map[string]int{"ok": 2, "tail-rollback": 1}},
		{"junk JSON replaces tail receipt", true, "2.json", false, map[string]int{"ok": 2, "malformed": 1}},
		{"junk text replaces tail receipt", true, "2.txt", false, map[string]int{"ok": 2, "tail-rollback": 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, reg, storeRoot, registryPath := testStore(t)
			const sessionID = "teeth-file-count"
			stampSession(t, st, sessionID, 3)
			if _, err := reg.seal(sessionID, 3, "t"); err != nil {
				t.Fatal(err)
			}

			sessionDir := filepath.Join(storeRoot, "receipts", sessionID)
			if tc.removeTail {
				if err := os.Remove(filepath.Join(sessionDir, "2.json")); err != nil {
					t.Fatal(err)
				}
			}
			if tc.replacement != "" {
				if err := os.WriteFile(filepath.Join(sessionDir, tc.replacement), []byte("junk"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			ok, got := statuses(t, storeRoot, registryPath)
			if ok != tc.wantOK || !maps.Equal(got, tc.want) {
				t.Fatalf("verify = (ok=%v, statuses=%v), want (ok=%v, statuses=%v)", ok, got, tc.wantOK, tc.want)
			}
		})
	}
}

// The member-ordering vector must actually discriminate: RFC 8785 and the
// judgment-pack runtime's own internal/jcs order by UTF-16 code unit, this format
// orders by code point, and they disagree outside the BMP. An implementer
// reaching for an existing JCS package gets this wrong, so a vector has to exist
// whose two orderings differ.
func TestOrderingVectorDiscriminatesCodePointFromUTF16(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(corpusDir, "canon.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []canonVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, vector := range file.Vectors {
		if vector.Reject || !strings.Contains(vector.Note, "CODE POINT") {
			continue
		}
		found = true
		expected, err := hex.DecodeString(vector.ExpectedHex)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parseJSON([]byte(vector.InputJSON))
		if err != nil {
			t.Fatal(err)
		}
		object, ok := parsed.(*vObject)
		if !ok || len(object.byName) < 2 {
			t.Fatal("the ordering vector is not a multi-member object")
		}
		names := make([]string, 0, len(object.byName))
		for name := range object.byName {
			names = append(names, name)
		}
		byCodePoint := append([]string(nil), names...)
		sort.Strings(byCodePoint)
		byUTF16 := append([]string(nil), names...)
		sort.Slice(byUTF16, func(i, j int) bool {
			left, right := utf16.Encode([]rune(byUTF16[i])), utf16.Encode([]rune(byUTF16[j]))
			for k := 0; k < len(left) && k < len(right); k++ {
				if left[k] != right[k] {
					return left[k] < right[k]
				}
			}
			return len(left) < len(right)
		})
		if strings.Join(byCodePoint, "\x00") == strings.Join(byUTF16, "\x00") {
			t.Fatal("the ordering vector does not discriminate: both orderings agree on it")
		}
		// And the frozen bytes must follow code point, not UTF-16.
		firstCodePoint := strings.Index(string(expected), byCodePoint[0])
		firstUTF16 := strings.Index(string(expected), byUTF16[0])
		if firstCodePoint > firstUTF16 {
			t.Fatalf("the frozen vector is in UTF-16 order, not code point order: %q", expected)
		}
	}
	if !found {
		t.Fatal("no member-ordering vector in the corpus")
	}
}

// A receipt signature covers everything except the signature member, so an
// appended unsigned member invalidates it. An implementation that instead
// verified a fixed list of the known members would accept the smuggled member
// — the exact attack SPEC.md §1.2 calls security-relevant — and this is the
// asserted form of that attack.
func TestAppendedUnsignedMemberInvalidatesTheReceipt(t *testing.T) {
	st, _, _, _ := testStore(t)
	core := newObject()
	core.set("receiptVersion", vString(receiptVersion))
	core.set("sessionId", vString("teeth-append"))
	core.set("callIndex", vInt(0))
	core.set("prevSignature", vNull{})
	core.set("source", vString("s"))
	core.set("argumentsDigest", vString("hmac-sha256:"+strings.Repeat("0", 64)))
	core.set("resultDigest", vString("sha256:"+strings.Repeat("0", 64)))
	core.set("servedAt", vString("t"))
	core.set("authority", vString("gateway:test"))
	stored, signatureHex, err := st.stamp(core)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := hex.DecodeString(signatureHex)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := func(smuggle bool) []byte {
		o := newObject()
		for _, name := range stored.names {
			if name == "signature" {
				continue
			}
			v, _ := stored.get(name)
			o.set(name, v)
		}
		if smuggle {
			o.set("smuggled", vString("x"))
		}
		return append([]byte(receiptContext), canon(o)...)
	}
	if !ed25519.Verify(st.publicKey, unsigned(false), sig) {
		t.Fatal("the untampered receipt must verify")
	}
	if ed25519.Verify(st.publicKey, unsigned(true), sig) {
		t.Fatal("an appended unsigned member must invalidate the signature")
	}
}

// An internally constructed callIndex outside §1.1's integer domain is refused
// at the stamp, not signed: the gateway never signs bytes its own canonical
// form would refuse to parse.
func TestStampRefusesACallIndexOutsideTheCanonicalDomain(t *testing.T) {
	st, _, _, _ := testStore(t)
	core := newObject()
	core.set("receiptVersion", vString(receiptVersion))
	core.set("sessionId", vString("teeth-domain"))
	core.set("callIndex", vInt(9007199254740992))
	core.set("prevSignature", vNull{})
	core.set("source", vString("s"))
	core.set("argumentsDigest", vString("hmac-sha256:"+strings.Repeat("0", 64)))
	core.set("resultDigest", vString("sha256:"+strings.Repeat("0", 64)))
	core.set("servedAt", vString("t"))
	core.set("authority", vString("gateway:test"))
	if _, _, err := st.stamp(core); err == nil {
		t.Fatal("a callIndex beyond 2^53-1 must be refused, not signed")
	}
}

// SPEC §1.4 fixes ONE finding per receipt, at the first failure in a stated
// order. A verifier that reports a later status for a receipt carrying two
// defects is not merely less helpful — it makes the diagnostic depend on its
// own internal ordering, so two conforming implementations disagree about a
// byte-identical receipt. These vectors are built with overlapping defects on
// purpose, because a single-defect suite cannot see an ordering error at all.
func TestReceiptFirstFailureOrderFollowsTheSpec(t *testing.T) {
	st, _, storeRoot, _ := testStore(t)

	// A receipt that verifies, to mutate from. It is deliberately misfiled
	// nowhere and its artifact is absent, so every case below stops before
	// those checks and isolates orders 1 through 4.
	core := newObject()
	core.set("receiptVersion", vString(receiptVersion))
	core.set("sessionId", vString("teeth-order"))
	core.set("callIndex", vInt(0))
	core.set("prevSignature", vNull{})
	core.set("source", vString("s"))
	core.set("argumentsDigest", vString("hmac-sha256:"+strings.Repeat("0", 64)))
	core.set("resultDigest", vString("sha256:"+strings.Repeat("0", 64)))
	core.set("servedAt", vString("t"))
	core.set("authority", vString("gateway:test"))
	// Stamped once: the store is append-only, so re-stamping the same
	// (session, callIndex) is refused. Every case mutates a copy.
	base, _, err := st.stamp(core)
	if err != nil {
		t.Fatal(err)
	}
	build := func(mutate func(o *vObject)) []byte {
		clone := newObject()
		for _, name := range base.names {
			v, _ := base.get(name)
			clone.set(name, v)
		}
		if mutate != nil {
			mutate(clone)
		}
		return canon(clone)
	}

	// A syntactically perfect Ed25519 signature that is simply not the right
	// one: 128 lowercase hex characters, so order 1 has nothing to say.
	wrongSignature := strings.Repeat("ab", ed25519.SignatureSize)

	for _, tt := range []struct {
		name   string
		mutate func(o *vObject)
		want   string
		why    string
	}{
		{
			name:   "non-hex signature and an unsupported version",
			mutate: func(o *vObject) { o.set("signature", vString("zz")); o.set("receiptVersion", vString("1")) },
			want:   "malformed",
			why:    "order 1 (lexical) precedes order 2 (unsupported-version)",
		},
		{
			name: "wrong key id and a signature that does not verify",
			mutate: func(o *vObject) {
				o.set("keyId", vString(strings.Repeat("f", 32)))
				o.set("signature", vString(wrongSignature))
			},
			want: "key-mismatch",
			why:  "order 3 (key-mismatch) precedes order 4 (signature-mismatch)",
		},
		{
			name:   "uppercase resultDigest hex",
			mutate: func(o *vObject) { o.set("resultDigest", vString("sha256:"+strings.Repeat("A", 64))) },
			want:   "malformed",
			why:    "SPEC 1.2 requires 64 LOWERCASE hex; encoding/hex would accept this",
		},
		{
			name:   "well-formed signature bytes that do not verify",
			mutate: func(o *vObject) { o.set("signature", vString(wrongSignature)) },
			want:   "signature-mismatch",
			why:    "correct length and lexically hex, so not malformed",
		},
		{
			name:   "hex signature of the wrong length",
			mutate: func(o *vObject) { o.set("signature", vString("abcd")) },
			want:   "signature-mismatch",
			why:    "lexically hex, so order 1 passes; it cannot verify, which is order 4",
		},
		{
			name:   "odd-length signature is not hex at all",
			mutate: func(o *vObject) { o.set("signature", vString("abc")) },
			want:   "malformed",
			why:    "an odd number of hex characters is not a hex encoding",
		},
		{
			name:   "unsupported version alone",
			mutate: func(o *vObject) { o.set("receiptVersion", vString("1")) },
			want:   "unsupported-version",
			why:    "order 2, with nothing lexical to report first",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, status := checkReceipt(build(tt.mutate), storeRoot, "teeth-order", "0.json",
				"gateway:test", st.publicKey, st.keyID)
			if status != tt.want {
				t.Fatalf("status = %q, want %q -- %s", status, tt.want, tt.why)
			}
		})
	}

	// The unmutated receipt must reach past every status above, so the table is
	// discriminating rather than reporting an early failure for all of them.
	if _, status := checkReceipt(build(nil), storeRoot, "teeth-order", "0.json",
		"gateway:test", st.publicKey, st.keyID); status != "artifact-missing" {
		t.Fatalf("the untampered receipt reports %q; the table above would be vacuous", status)
	}
}

// TestKeyIDForProperties pins the property invariants of keyIDFor:
// exact 32 characters, lowercase hex alphabet, determinism, prefix match against
// an independently computed SHA-256 digest, and collision resistance across distinct keys.
func TestKeyIDForProperties(t *testing.T) {
	cases := []struct {
		name string
		key  []byte
	}{
		{
			name: "32-byte ed25519 public key",
			key:  []byte("0123456789abcdef0123456789abcdef"),
		},
		{
			name: "all zeros 32 bytes",
			key:  make([]byte, ed25519.PublicKeySize),
		},
		{
			name: "arbitrary 64 bytes",
			key:  []byte("arbitrary-length-key-bytes-for-digest-testing-purpose-longer-than-32"),
		},
		{
			name: "single byte",
			key:  []byte{0x42},
		},
		{
			name: "empty key",
			key:  []byte{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id1 := keyIDFor(tc.key)
			id2 := keyIDFor(tc.key)

			// 1. Determinism
			if id1 != id2 {
				t.Fatalf("keyIDFor is not deterministic: %q != %q", id1, id2)
			}

			// 2. Length: exactly 32 hex characters (128 bits)
			if len(id1) != 32 {
				t.Fatalf("len(keyIDFor) = %d, want 32", len(id1))
			}

			// 3. Alphabet: all lowercase hex characters [0-9a-f]
			for i, r := range id1 {
				if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
					t.Fatalf("keyIDFor[%d] = %q is not lowercase hex (full id: %q)", i, r, id1)
				}
			}

			// 4. Prefix relationship against an independently computed digest
			fullDigest := sha256.Sum256(tc.key)
			fullHex := hex.EncodeToString(fullDigest[:])
			if !strings.HasPrefix(fullHex, id1) {
				t.Fatalf("keyIDFor(%q) = %q is not a prefix of independent full digest %q", tc.key, id1, fullHex)
			}
			if id1 != fullHex[:32] {
				t.Fatalf("keyIDFor(%q) = %q, want fullHex[:32] %q", tc.key, id1, fullHex[:32])
			}
		})
	}

	// 5. Collision resistance / distinct keys produce different IDs
	distinctKeys := [][]byte{
		[]byte("key-alpha-1234567890123456789012"),
		[]byte("key-beta--1234567890123456789012"),
		[]byte("key-gamma-1234567890123456789012"),
	}
	seenIDs := make(map[string][]byte)
	for _, key := range distinctKeys {
		id := keyIDFor(key)
		if existingKey, exists := seenIDs[id]; exists {
			t.Fatalf("collision detected for distinct keys: keyIDFor(%q) == keyIDFor(%q) == %q", key, existingKey, id)
		}
		seenIDs[id] = key
	}
}

func TestStoreAppendOnlyRefusesOverwrite(t *testing.T) {
	s, _, root, _ := testStore(t)

	sessionID := "test-session-append-only"
	receiptCore := func(index int64, prev value) *vObject {
		core := newObject()
		core.set("receiptVersion", vString(receiptVersion))
		core.set("sessionId", vString(sessionID))
		core.set("callIndex", vInt(index))
		core.set("prevSignature", prev)
		core.set("source", vString("s"))
		core.set("argumentsDigest", vString("hmac-sha256:"+strings.Repeat("0", 64)))
		core.set("resultDigest", vString("sha256:"+strings.Repeat("1", 64)))
		core.set("servedAt", vString("2026-08-16T00:00:00Z"))
		core.set("authority", vString("gateway:test"))
		return core
	}
	core := receiptCore(0, vNull{})

	_, sig, err := s.stamp(core)
	if err != nil {
		t.Fatalf("first stamp failed: %v", err)
	}
	if sig == "" {
		t.Fatal("stamp returned empty signature")
	}

	receiptPath := filepath.Join(root, "receipts", sessionID, "0.json")
	originalBytes, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatalf("read original receipt at %s: %v", receiptPath, err)
	}

	// 1. Attempting to stamp again with the same callIndex in the same session must fail
	duplicateCore := receiptCore(0, vNull{})
	duplicateCore.set("resultDigest", vString("sha256:"+strings.Repeat("2", 64)))
	_, _, err = s.stamp(duplicateCore)
	if err == nil {
		t.Fatal("expected second stamp with duplicate callIndex to fail, but it succeeded")
	}
	if !strings.Contains(err.Error(), "receipt already exists (append-only)") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// 2. Verify original receipt content is untouched and unmodified
	currentBytes, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatalf("read receipt after failed stamp: %v", err)
	}
	if !bytes.Equal(originalBytes, currentBytes) {
		t.Fatalf("receipt file content altered after failed overwrite: got %s, want %s", currentBytes, originalBytes)
	}

	// 3. A refused stamp must not leave a temporary or partial file behind
	entries, err := os.ReadDir(filepath.Dir(receiptPath))
	if err != nil {
		t.Fatalf("read session directory after failed stamp: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "0.json" {
		t.Fatalf("session directory after failed stamp = %v, want only 0.json", entries)
	}

	// 4. The next callIndex in the same session must still be accepted
	if _, _, err := s.stamp(receiptCore(1, vString(sig))); err != nil {
		t.Fatalf("stamp at next callIndex failed: %v", err)
	}

	// 5. Direct write with exclusive=true must also refuse to overwrite
	err = s.write(receiptPath, []byte("tampered content"), true)
	if err == nil {
		t.Fatal("expected write with exclusive=true on existing file to fail, but succeeded")
	}
	if !strings.Contains(err.Error(), "receipt already exists (append-only)") {
		t.Fatalf("unexpected write error message: %v", err)
	}

	// 6. Verify file content remains exactly identical to original bytes
	afterWriteBytes, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatalf("read receipt after direct write attempt: %v", err)
	}
	if !bytes.Equal(originalBytes, afterWriteBytes) {
		t.Fatalf("receipt content overwritten: got %s, want %s", afterWriteBytes, originalBytes)
	}
}

func TestUnreadableReceiptsPermissionsRefusal(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("permission fixtures are platform-bound and bypassed by root")
	}

	t.Run("receipts directory is unreadable", func(t *testing.T) {
		_, _, storeRoot, _ := testStore(t)
		receiptsPath := filepath.Join(storeRoot, "receipts")

		if err := os.Chmod(receiptsPath, 0o111); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(receiptsPath, 0o755)

		_, err := listSessions(storeRoot)
		if err == nil {
			t.Fatal("verifier should refuse (return error) when receipts is unreadable")
		}
	})

	t.Run("storeRoot is unreadable", func(t *testing.T) {
		_, _, storeRoot, _ := testStore(t)

		if err := os.Chmod(storeRoot, 0o000); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(storeRoot, 0o755)

		_, err := listSessions(storeRoot)
		if err == nil {
			t.Fatal("verifier should refuse (return error) when storeRoot is unreadable")
		}
	})
}

func TestLoadSealDropShapes(t *testing.T) {
	st, _, _, _ := testStore(t)
	priv := st.private
	pub := st.publicKey
	session := "drop-shapes"
	kid := keyIDFor(pub)

	for _, tt := range []struct {
		name     string
		lines    string
		wantSeal int // number of seals expected to load
		wantCID  int64
		why      string
	}{
		{
			name:  "not JSON at all",
			lines: "this is not json\n",
			why:   "parseJSON fails; dropped before any member is read",
		},
		{
			name:  "array instead of object",
			lines: `[1,2,3]` + "\n",
			why:   "parseJSON succeeds but the result is not *vObject; dropped",
		},
		{
			name: "missing member (sealedAt dropped)",
			lines: func() string {
				// We sign an empty sealedAt because if missing, a string member query yields "".
				sig := ed25519.Sign(priv, sealSigningInput(session, 5, "", kid))
				obj := map[string]any{
					"sessionId":  session,
					"finalCount": 5,
					"keyId":      kid,
					"signature":  hex.EncodeToString(sig),
				}
				out, _ := json.Marshal(obj)
				return string(out) + "\n"
			}(),
			why: "the ok1…ok5 gate drops it before the signature check",
		},
		{
			name: "finalCount is a string",
			lines: func() string {
				// We sign count 0 because a failed type assertion yields the zero value.
				sig := ed25519.Sign(priv, sealSigningInput(session, 0, "t", kid))
				obj := map[string]any{
					"sessionId":  session,
					"finalCount": "five",
					"sealedAt":   "t",
					"keyId":      kid,
					"signature":  hex.EncodeToString(sig),
				}
				out, _ := json.Marshal(obj)
				return string(out) + "\n"
			}(),
			why: "countV.(vInt) fails; string is not an integer",
		},
		{
			// json.Marshal would write 3, not 3.0, so we write raw JSON.
			name: "finalCount is a float literal",
			lines: func() string {
				// We sign count 3 since the parsed float matches this value.
				sig := ed25519.Sign(priv, sealSigningInput(session, 3, "t", kid))
				return `{"sessionId":"` + session + `","finalCount":3.0,"sealedAt":"t","keyId":"` + kid + `","signature":"` + hex.EncodeToString(sig) + `"}` + "\n"
			}(),
			why: "parseJSON rejects float; never reaches the seal checks",
		},
		{
			// json.Marshal deduplicates map keys, so we write raw JSON.
			name: "duplicate member name",
			lines: func() string {
				// We sign count 5 because that is the valid count in the JSON.
				sig := ed25519.Sign(priv, sealSigningInput(session, 5, "t", kid))
				return `{"sessionId":"` + session + `","sessionId":"` + session + `","finalCount":5,"sealedAt":"t","keyId":"` + kid + `","signature":"` + hex.EncodeToString(sig) + `"}` + "\n"
			}(),
			why: "parseJSON rejects duplicate names (canon.go:254); never reaches the seal checks",
		},
		{
			name:     "negative finalCount with correct signature",
			lines:    sealLine(t, priv, session, -1),
			wantSeal: 0,
			why:      "correctly signed but count < 0; isolates the count check",
		},
		{
			name: "signature is valid hex but wrong length (4 chars)",
			lines: func() string {
				sig := ed25519.Sign(priv, sealSigningInput(session, 5, "t", kid))
				obj := map[string]any{
					"sessionId":  session,
					"finalCount": 5,
					"sealedAt":   "t",
					"keyId":      kid,
					"signature":  hex.EncodeToString(sig)[:4],
				}
				out, _ := json.Marshal(obj)
				return string(out) + "\n"
			}(),
			// This leg is provably unholdable because Go's ed25519.Verify naturally rejects wrong-size signatures.
			why: "hex.DecodeString succeeds but len(sig) != ed25519.SignatureSize",
		},
		{
			name: "signature has decode error",
			lines: func() string {
				sig := ed25519.Sign(priv, sealSigningInput(session, 5, "t", kid))
				obj := map[string]any{
					"sessionId":  session,
					"finalCount": 5,
					"sealedAt":   "t",
					"keyId":      kid,
					"signature":  hex.EncodeToString(sig) + "ZZ",
				}
				out, _ := json.Marshal(obj)
				return string(out) + "\n"
			}(),
			why: "hex.DecodeString fails because of non-hex chars; dropped at the decode check",
		},
		{
			name: "Foreign keyId",
			lines: func() string {
				_, dummyPriv, _ := ed25519.GenerateKey(nil)
				foreignKid := keyIDFor(dummyPriv.Public().(ed25519.PublicKey))
				return sealLineKeyID(t, priv, session, 5, foreignKid)
			}(),
			why: "signed by correct key but names a foreign keyId",
		},
		{
			name: "Wrong signature",
			lines: func() string {
				obj := map[string]any{
					"sessionId":  session,
					"finalCount": 5,
					"sealedAt":   "t",
					"keyId":      kid,
					"signature":  strings.Repeat("0", 128),
				}
				out, _ := json.Marshal(obj)
				return string(out) + "\n"
			}(),
			why: "signature is well-formed but fails verification",
		},

		// must NOT drop
		{
			name:     "correctly signed seal loads",
			lines:    sealLine(t, priv, session, 5),
			wantSeal: 1,
			wantCID:  5,
			why:      "discriminating: the table is not vacuous — a valid seal does load",
		},
		{
			name:     "zero-count seal loads",
			lines:    sealLine(t, priv, session, 0),
			wantSeal: 1,
			wantCID:  0,
			why:      "0 is a valid finalCount",
		},
		{
			name:     "blank and whitespace lines beside a good seal",
			lines:    "\n   \n	\n" + sealLine(t, priv, session, 5) + "\n\n  \n",
			wantSeal: 1,
			wantCID:  5,
			why:      "blank/whitespace lines must not disturb a valid seal",
		},

		// two loadable seals for one session
		{
			name:     "tie-break: first wins (5 then 3)",
			lines:    sealLine(t, priv, session, 5) + sealLine(t, priv, session, 3),
			wantSeal: 1,
			wantCID:  5,
			why:      "SPEC.md §4 step 2: the first wins; second seal for same session is dropped",
		},
		{
			name:     "tie-break: first wins (3 then 5)",
			lines:    sealLine(t, priv, session, 3) + sealLine(t, priv, session, 5),
			wantSeal: 1,
			wantCID:  3,
			why:      "both orders must agree: the first line's count wins",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			regPath := filepath.Join(t.TempDir(), "registry.jsonl")
			if err := os.WriteFile(regPath, []byte(tt.lines), 0o600); err != nil {
				t.Fatal(err)
			}

			seals, _, err := loadSeals(regPath, pub)
			if err != nil {
				t.Fatalf("loadSeals returned error: %v", err)
			}

			if len(seals) != tt.wantSeal {
				t.Fatalf("loadSeals loaded %d seal(s), want %d — %s", len(seals), tt.wantSeal, tt.why)
			}

			for _, s := range seals {
				if s.finalCount != tt.wantCID {
					t.Fatalf("got finalCount=%d, want %d — %s", s.finalCount, tt.wantCID, tt.why)
				}
			}
		})
	}
}

func TestStoreRootShapes(t *testing.T) {
	regPath := filepath.Join(t.TempDir(), "registry.jsonl")
	if err := os.WriteFile(regPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var dummyKey [ed25519.PublicKeySize]byte

	t.Run("missing root falls through", func(t *testing.T) {
		priv := ed25519.NewKeyFromSeed(testSeed)
		regPath := filepath.Join(t.TempDir(), "registry.jsonl")
		if err := os.WriteFile(regPath, []byte(sealLine(t, priv, "ghost", 3)), 0o600); err != nil {
			t.Fatal(err)
		}
		storeRoot := filepath.Join(t.TempDir(), "does-not-exist")
		rep, err := verifyWithRegistry(storeRoot, regPath, "gateway:test", priv.Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatalf("missing root must still grade, got error: %v", err)
		}
		if rep.OK {
			t.Fatal("missing root with a sealed registry graded ok: true")
		}

		// exactly one sealed-session-missing for the ghost session
		if len(rep.Findings) != 1 || rep.Findings[0]["status"] != "sealed-session-missing" {
			t.Fatalf("expected one sealed-session-missing finding, got: %v", rep.Findings)
		}
	})

	t.Run("regular file root refuses", func(t *testing.T) {
		storeRoot := filepath.Join(t.TempDir(), "regular-file")
		if err := os.WriteFile(storeRoot, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := verifyWithRegistry(storeRoot, regPath, "test", dummyKey[:])
		if err == nil || !strings.Contains(err.Error(), "store root is not a directory") {
			t.Fatalf("expected 'store root is not a directory' error, got: %v", err)
		}
	})

	t.Run("unreadable directory root refuses", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Getuid() == 0 {
			t.Skip("permission fixtures are platform-bound and bypassed by root")
		}
		storeRoot := filepath.Join(t.TempDir(), "unreadable-dir")
		if err := os.Mkdir(storeRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(storeRoot, 0o000); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(storeRoot, 0o755)

		_, err := verifyWithRegistry(storeRoot, regPath, "test", dummyKey[:])
		if err == nil {
			t.Fatal("verifyWithRegistry should return error for unreadable directory root")
		}
	})
}

// TestRegistryPathShapes pins the third instance of the OS-split verdict class,
// at the anchor. A registry the platform cannot reach must never be read as a
// registry that is not there: the first grades every session
// `unregistered-session` from evidence nobody looked at, the second is a fact
// about the store.
func TestRegistryPathShapes(t *testing.T) {
	t.Run("missing registry grades unregistered-session", func(t *testing.T) {
		// A store holding a stamped session is what makes the GRADE assertable.
		// An empty store can still tell a refusal from a verdict — the call
		// either errors or does not — but it grades ok: true with no findings
		// whether or not seals loaded, so it cannot pin what the grade should
		// be, which is the half a fail-open gets wrong.
		st, _, storeRoot, _ := testStore(t)
		stampSession(t, st, "s1", 2)
		regPath := filepath.Join(t.TempDir(), "registry.jsonl") // never written

		ok, counts := statuses(t, storeRoot, regPath)
		if ok {
			t.Fatalf("a stamped session against a missing registry graded ok: true (%v)", counts)
		}
		if counts["unregistered-session"] != 1 || counts["ok"] != 2 || len(counts) != 2 {
			t.Fatalf("expected one unregistered-session over two ok receipts, got: %v", counts)
		}
	})

	// No skips below: these are the legs that prove the fix on Windows, where the
	// error for a non-directory path component is ERROR_PATH_NOT_FOUND at any
	// depth and os.IsNotExist reports it as an absent registry.
	//
	// The depths are separate rows because they fail differently: the direct
	// parent is caught by statting the parent, while a file ANCESTOR is not —
	// Windows answers not-exist for the intermediate directory too, so a
	// parent-only check reports absence and grades. Only the downward walk sees
	// the file.
	for _, tt := range []struct {
		name string
		// suffix is joined onto a path that is a regular file to build the
		// registry path.
		suffix []string
	}{
		{name: "registry parent is a regular file refuses", suffix: []string{"registry.jsonl"}},
		{name: "registry ancestor is a regular file refuses", suffix: []string{"missing", "registry.jsonl"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Same store as the row above, so the rows differ only in the
			// registry path: the missing one grades, these refuse.
			st, _, storeRoot, _ := testStore(t)
			stampSession(t, st, "s1", 2)
			file := filepath.Join(t.TempDir(), "regular-file")
			if err := os.WriteFile(file, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			regPath := filepath.Join(append([]string{file}, tt.suffix...)...)

			_, err := verifyWithRegistry(storeRoot, regPath, "gateway:test", st.publicKey)
			if err == nil {
				t.Fatal("an unreachable registry graded instead of refusing")
			}
			// The refusal must name the component the specification names, not
			// whatever the platform happened to call the failure.
			want := "registry parent path component is not a directory: " + file
			if err.Error() != want {
				t.Fatalf("got %q, want %q", err.Error(), want)
			}
		})
	}

	// The /registry endpoint hands the anchor to verifiers that never touch this
	// filesystem, so it must classify the registry path the same way the verifier
	// does. Serving 200 with an empty body for a registry that is present and
	// unreachable would tell every one of them "no seals" — the same fail-open,
	// one process further out. Socket-free: the handler is exercised directly.
	t.Run("registry endpoint refuses an unreachable registry", func(t *testing.T) {
		root := t.TempDir()
		regDir := filepath.Join(root, "anchor")
		if err := os.Mkdir(regDir, 0o755); err != nil {
			t.Fatal(err)
		}
		regPath := filepath.Join(regDir, "registry.jsonl")
		service, err := newGatewayService(
			filepath.Join(root, "store"), testSeed, "gateway:test", regPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		handler := service.handler()

		// Swap the registry's directory for a regular file AFTER construction,
		// the way a running gateway's storage can be replaced under it.
		if err := os.RemoveAll(regDir); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(regDir, nil, 0o600); err != nil {
			t.Fatal(err)
		}

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/registry", nil))
		if rec.Code == http.StatusOK {
			t.Fatalf("/registry served %d with body %q for an unreachable registry; "+
				"an external verifier reads that as an empty anchor", rec.Code, rec.Body.String())
		}
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
		}
		// The status alone cannot show the endpoint and the verifier agree: on
		// POSIX the pre-fix ReadFile also errors here, and it is Windows where
		// the two answers diverge. Pinning the message pins the classifier, so
		// an endpoint that goes back to reading the path its own way fails this
		// row on every platform rather than only in Windows CI.
		var body struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decoding %q: %v", rec.Body.String(), err)
		}
		want := "registry parent path component is not a directory: " + regDir
		if body.Error != want {
			t.Fatalf("/registry answered %q; want %q — the endpoint is not using the "+
				"classifier the verifier uses", body.Error, want)
		}
	})
}
