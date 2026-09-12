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
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

const corpusDir = "../corpus"

const envConformHelper = "GATEWAY_TEST_CONFORM_HELPER"

func init() {
	if os.Getenv(envConformHelper) == "1" {
		if len(os.Args) < 2 {
			os.Exit(2)
		}
		switch os.Args[1] {
		case "canon":
			src, _ := io.ReadAll(os.Stdin)
			out, err := canonText(src)
			if err != nil {
				os.Exit(1)
			}
			os.Stdout.Write(append(out, '\n'))
			os.Exit(0)
		case "verify":
			os.Exit(cmdVerify(os.Args[2:]))
		default:
			os.Exit(2)
		}
	}
}

// defective wraps the real implementation with one injected fault.
type defective struct {
	canonDefect       func([]byte) []byte
	ignoreAnchor      bool
	ignoreActionLinks bool
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

func (d defective) verify(storeRoot, registryPath, authority, decisionRecords string, publicKey []byte) (bool, []map[string]any, error) {
	if d.ignoreActionLinks {
		// Every ladder and registry check intact; SPEC.md §4 steps 5 and 6
		// never run -- a verifier that treats an action receipt's citations
		// and decision record as decoration.
		ok, findings, err := inProcess{}.verify(storeRoot, registryPath, authority, decisionRecords, publicKey)
		if err != nil {
			return false, nil, err
		}
		kept := findings[:0]
		for _, f := range findings {
			if f["status"] == "citation-unresolved" || f["status"] == "decision-record-mismatch" {
				continue
			}
			kept = append(kept, f)
		}
		ok = true
		for _, f := range kept {
			if f["status"] != "ok" {
				ok = false
			}
		}
		return ok, kept, nil
	}
	if !d.ignoreAnchor {
		return inProcess{}.verify(storeRoot, registryPath, authority, decisionRecords, publicKey)
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
		result, err := verifySession(storeRoot, sessionID, authority, publicKey)
		if err != nil {
			return false, nil, err
		}
		for _, f := range result.findings {
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

// A verifier that ignores an action receipt's citations and decision record
// must be caught: the version 3 vectors for citation-unresolved and
// decision-record-mismatch exist for exactly that verifier.
func TestCorpusCatchesAVerifierThatIgnoresActionLinks(t *testing.T) {
	joined := failuresFor(t, defective{ignoreActionLinks: true})
	for _, missed := range []string{"v3-citation-unresolved", "v3-decision-record-mismatch", "v3-decision-records-absent"} {
		if !strings.Contains(joined, missed) {
			t.Fatalf("corpus did not catch a verifier ignoring action links (%s):\n%s", missed, joined)
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

func TestArgumentsDigest(t *testing.T) {
	// Version 2's keyed digest, pinned as it was: the form a consumer on
	// --receipt-version 2 still receives.
	service, server := testService(t)
	service.receiptVersion = receiptVersion

	// 1. Format: "hmac-sha256:" + exactly 64 lowercase hex characters
	getArgumentsDigest := func(body map[string]any) string {
		t.Helper()
		receipt, ok := body["receipt"].(map[string]any)
		if !ok {
			t.Fatal("response has no receipt")
		}
		d, ok := receipt["argumentsDigest"].(string)
		if !ok {
			t.Fatal("receipt has no argumentsDigest")
		}
		return d
	}

	digestPattern := regexp.MustCompile(`^hmac-sha256:[0-9a-f]{64}$`)

	code, resp := post(t, server, "/acquire",
		`{"session":"args-fmt","source":"screening","arguments":{"q":"alpha"}}`)
	if code != http.StatusOK {
		t.Fatalf("acquire failed: %d %v", code, resp)
	}
	d1 := getArgumentsDigest(resp)
	if !digestPattern.MatchString(d1) {
		t.Fatalf("argumentsDigest = %q, want hmac-sha256: + 64 lowercase hex", d1)
	}

	// 2. Same arguments in different sessions produce the same digest
	code, resp2 := post(t, server, "/acquire",
		`{"session":"args-det-2","source":"screening","arguments":{"q":"alpha"}}`)
	if code != http.StatusOK {
		t.Fatalf("acquire failed: %d %v", code, resp2)
	}
	d2 := getArgumentsDigest(resp2)
	if d1 != d2 {
		t.Fatalf("same arguments in different sessions produced different digests: %q vs %q", d1, d2)
	}

	// 3. Different arguments produce a different digest
	code, resp3 := post(t, server, "/acquire",
		`{"session":"args-diff","source":"screening","arguments":{"q":"bravo"}}`)
	if code != http.StatusOK {
		t.Fatalf("acquire failed: %d %v", code, resp3)
	}
	d3 := getArgumentsDigest(resp3)
	if d1 == d3 {
		t.Fatalf("different arguments produced the same digest: %q", d1)
	}

	// 4. The digest is NOT the plain SHA-256 of the canonical arguments
	obj := &vObject{byName: map[string]value{"q": vString("alpha")},
		names: []string{"q"}}
	canonicalArgs := canon(obj)
	hash := sha256.Sum256(canonicalArgs)
	hexOnly := strings.TrimPrefix(d1, "hmac-sha256:")
	if hexOnly == hex.EncodeToString(hash[:]) {
		t.Fatalf("the hex portion of argumentsDigest matches plain SHA-256 — keyed commitment is broken")
	}

	// 5. Recomputing HMAC under argumentsKey reproduces the digest exactly
	mac := hmac.New(sha256.New, argumentsKey(testSeed))
	mac.Write(append([]byte("args:"), canonicalArgs...))
	expected := "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
	if d1 != expected {
		t.Fatalf("argumentsDigest = %q, recomputed = %q — digest does not reproduce from construction", d1, expected)
	}

	// 6. The derivation itself is pinned with a byte-literal digest
	const pinnedDigest = "hmac-sha256:877dcd76b5c1748c3508592122aad72a2f89276b4980ad18b5e8f6842d4a2add"
	if d1 != pinnedDigest {
		t.Fatalf("argumentsDigest = %q, want byte-literal %q — derivation drifted", d1, pinnedDigest)
	}
}

func TestArgumentsDigestChangesWithSeed(t *testing.T) {
	t.Setenv(envSourceHelper, "1")
	seed1 := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") // 32 bytes
	seed2 := []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") // 32 bytes

	root1 := t.TempDir()
	service1, err := newGatewayService(
		filepath.Join(root1, "store"), seed1, "gateway:test",
		filepath.Join(root1, "registry.jsonl"),
		map[string]sourceSpec{"screening": {argv: []string{os.Args[0]}, env: helperEnv}})
	if err != nil {
		t.Fatal(err)
	}
	service1.receiptVersion = receiptVersion
	server1 := httptest.NewServer(service1.handler())
	defer server1.Close()

	root2 := t.TempDir()
	service2, err := newGatewayService(
		filepath.Join(root2, "store"), seed2, "gateway:test",
		filepath.Join(root2, "registry.jsonl"),
		map[string]sourceSpec{"screening": {argv: []string{os.Args[0]}, env: helperEnv}})
	if err != nil {
		t.Fatal(err)
	}
	service2.receiptVersion = receiptVersion
	server2 := httptest.NewServer(service2.handler())
	defer server2.Close()

	args := `{"session":"seed-test","source":"screening","arguments":{"q":"test"}}`

	code1, resp1 := post(t, server1, "/acquire", args)
	if code1 != http.StatusOK {
		t.Fatalf("first acquire failed: %d %v", code1, resp1)
	}
	d1 := resp1["receipt"].(map[string]any)["argumentsDigest"].(string)

	code2, resp2 := post(t, server2, "/acquire", args)
	if code2 != http.StatusOK {
		t.Fatalf("second acquire failed: %d %v", code2, resp2)
	}
	d2 := resp2["receipt"].(map[string]any)["argumentsDigest"].(string)

	if d1 == d2 {
		t.Fatalf("argumentsDigest did not change when seed changed: %q == %q", d1, d2)
	}
}

// TestCmdConformExitStatus pins the exit-status contract: when the corpus
// finds disagreements, cmdConform must return 1. CI gates on this; a
// conformance runner that under-reports is exactly the "suite with no teeth"
// this file exists to guard against. The healthy direction is asserted in the
// same test so it cannot pass by always reporting failure, and 1 is
// distinguished from 2 (corpus could not be run).
//
// The deliberately-wrong implementation is the test binary itself as a helper
// (via GATEWAY_TEST_CONFORM_HELPER), answering canon with a trailing newline
// — the default of nearly every shell pipeline — and delegating verify to
// cmdVerify so store vectors pass and the exit-1 comes from canon
// disagreements, the exact code path under test.
func TestCmdConformExitStatus(t *testing.T) {
	// Healthy: in-process agrees with frozen corpus -> 0 and empty failures.
	if rc := cmdConform([]string{"--corpus", corpusDir}); rc != 0 {
		t.Fatalf("cmdConform healthy returned %d, want 0", rc)
	}
	failures, _, _, err := runCorpus(corpusDir, inProcess{})
	if err != nil {
		t.Fatalf("runCorpus healthy: %v", err)
	}
	if len(failures) != 0 {
		t.Fatalf("healthy impl produced %d failures, want 0: %v", len(failures), failures)
	}

	// Wrong: via --impl helper -> non-zero and non-empty, specifically 1 not 2.
	t.Setenv(envConformHelper, "1")
	impl := subprocess{argv: []string{os.Args[0]}}
	failures, _, _, err = runCorpus(corpusDir, impl)
	if err != nil {
		t.Fatalf("runCorpus wrong impl returned error (would be exit 2): %v", err)
	}
	if len(failures) == 0 {
		t.Fatal("wrong impl produced no failures, want non-empty")
	}
	rc := cmdConform([]string{"--impl", os.Args[0], "--corpus", corpusDir})
	if rc != 1 {
		t.Fatalf("cmdConform --impl wrong returned %d, want 1 (2 is corpus error, not disagreement)", rc)
	}
}

// --- source isolation (ADR-0001) --------------------------------------------
//
// Each test below is an attack on the separation the gateway claims between
// itself and a source: something reaching a source that should not, or a
// source holding the gateway to something it should not.

func echoFromSource(t *testing.T, service *gatewayService, session, name string) (string, bool) {
	t.Helper()
	t.Setenv(envSourceEcho, name)
	out, err := service.acquire(session, "screening", vString("x"))
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	result := out["result"].(map[string]any)
	value, _ := result["echo"].(string)
	present, _ := result["present"].(bool)
	return value, present
}

// A variable the operator did not declare for a source never reaches it, even
// though this process holds it. PATH is the one exception, copied unless
// declared, because a source that cannot find a shell is not a source.
func TestSourceSeesOnlyTheDeclaredEnvironment(t *testing.T) {
	service, _ := testService(t)
	t.Setenv("GATEWAY_TEST_LEAK", "secret")
	if value, present := echoFromSource(t, service, "env-1", "GATEWAY_TEST_LEAK"); present || value != "" {
		t.Fatalf("an undeclared variable reached the source: present=%v value=%q", present, value)
	}
	if value, present := echoFromSource(t, service, "env-2", "PATH"); !present || value != os.Getenv("PATH") {
		t.Fatalf("PATH must be copied unless declared: present=%v value=%q", present, value)
	}
}

// A declared KEY=VALUE reaches the source as declared, and a declared PATH
// replaces the copied one.
func TestDeclaredEnvironmentReachesTheSource(t *testing.T) {
	service, _ := testService(t)
	spec := service.sources["screening"]
	spec.env = append(append([]string{}, spec.env...), "GATEWAY_TEST_DECLARED=declared-value", "PATH=/declared/path")
	service.sources["screening"] = spec
	if value, present := echoFromSource(t, service, "env-3", "GATEWAY_TEST_DECLARED"); !present || value != "declared-value" {
		t.Fatalf("declared value did not reach the source: present=%v value=%q", present, value)
	}
	if value, _ := echoFromSource(t, service, "env-4", "PATH"); value != "/declared/path" {
		t.Fatalf("a declared PATH must win over the copied one: %q", value)
	}
}

// A bare key names a variable to copy at spawn time; one this process does
// not hold is omitted, not set empty, so a source can tell the two apart.
func TestBareKeyAbsentFromTheGatewayIsOmitted(t *testing.T) {
	service, _ := testService(t)
	spec := service.sources["screening"]
	spec.env = append(append([]string{}, spec.env...), "GATEWAY_TEST_NEVER_SET")
	service.sources["screening"] = spec
	os.Unsetenv("GATEWAY_TEST_NEVER_SET")
	if value, present := echoFromSource(t, service, "env-5", "GATEWAY_TEST_NEVER_SET"); present || value != "" {
		t.Fatalf("an absent variable must be omitted: present=%v value=%q", present, value)
	}
}

// Output past the bound fails the acquisition, kills the source, and leaves
// nothing behind: no receipt, no artifact, no session to seal.
func TestSourceOutputIsBounded(t *testing.T) {
	service, _ := testService(t)
	service.maxSourceOutput = 1024
	t.Setenv(envSourceBig, "4096")
	_, err := service.acquire("big-1", "screening", vString("x"))
	if err == nil {
		t.Fatal("output past the bound must fail the acquisition")
	}
	if !strings.Contains(err.Error(), "exceeds 1024 bytes") {
		t.Fatalf("the failure must name the bound: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(service.storeRoot, "receipts", "big-1")); statErr == nil {
		t.Fatal("a receipt was written for output that was never accepted")
	}
	entries, _ := os.ReadDir(filepath.Join(service.storeRoot, "artifacts"))
	if len(entries) != 0 {
		t.Fatalf("an artifact was retained for output that was never accepted: %d", len(entries))
	}
	if _, sealErr := service.sealSession("big-1"); sealErr == nil {
		t.Fatal("a session whose only acquisition overflowed must not be sealable")
	}

	service.maxSourceOutput = defaultMaxSourceOutput
	if _, err := service.acquire("big-2", "screening", vString("x")); err != nil {
		t.Fatalf("the same output within the bound must be accepted: %v", err)
	}
}

// A declared "Path" is a declared PATH exactly where the platform says so.
// Windows environment names are case-insensitive and os/exec keeps the last
// spelling, so appending the copied PATH there would silently win.
func TestDeclaredPathIsRecognizedByThePlatformRule(t *testing.T) {
	env := sourceEnvironment(sourceSpec{env: []string{"Path=/declared"}})
	var pathEntries []string
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(key, "PATH") {
			pathEntries = append(pathEntries, entry)
		}
	}
	switch runtime.GOOS {
	case "windows":
		if len(pathEntries) != 1 || pathEntries[0] != "Path=/declared" {
			t.Fatalf("on Windows a declared Path is the PATH; got %v", pathEntries)
		}
	default:
		if len(pathEntries) != 2 {
			t.Fatalf("elsewhere Path and PATH are two variables; got %v", pathEntries)
		}
	}
}

// The one undeclared variable a source receives on Windows, stated as such.
func TestWindowsSystemRootIsTheDocumentedException(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("os/exec adds SYSTEMROOT only on Windows")
	}
	service, _ := testService(t)
	if _, present := echoFromSource(t, service, "env-6", "SYSTEMROOT"); !present {
		t.Fatal("os/exec is documented to add SYSTEMROOT to an explicit environment; it did not")
	}
}

// The bound is exact: output of the bound's size is accepted, one byte more is
// not. The helper's body is the padding plus ten bytes of JSON around it.
func TestOutputBoundIsExact(t *testing.T) {
	service, _ := testService(t)
	const padding = 1000
	t.Setenv(envSourceBig, strconv.Itoa(padding))
	service.maxSourceOutput = padding + 10
	if _, err := service.acquire("exact-1", "screening", vString("x")); err != nil {
		t.Fatalf("output exactly at the bound must be accepted: %v", err)
	}
	service.maxSourceOutput = padding + 9
	if _, err := service.acquire("exact-2", "screening", vString("x")); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("output one byte past the bound must be refused: %v", err)
	}
}

// A source that overflows and then stays alive is killed: the acquisition
// returns on the overflow, not on the thirty-second timeout.
func TestOverflowingSourceIsKilled(t *testing.T) {
	service, _ := testService(t)
	service.maxSourceOutput = 1024
	t.Setenv(envSourceBig, "4096")
	t.Setenv(envSourceHold, "1")
	started := time.Now()
	_, err := service.acquire("kill-1", "screening", vString("x"))
	elapsed := time.Since(started)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected the overflow failure, got %v", err)
	}
	if elapsed > 20*time.Second {
		t.Fatalf("the source was not killed on overflow; acquire took %s", elapsed)
	}
}

// expectHolder arranges for the helper's grandchild to be killed when the
// test ends, whether or not the gateway reached it, and returns a function
// that reports the grandchild's pid and fails the test if it never started --
// a holder test that ran without a holder tested nothing. A test must not
// leave a process holding the test binary open: Windows refuses to delete it,
// and `go test` then fails after every test passed, so the cleanup kills the
// grandchild and waits until it is gone.
func expectHolder(t *testing.T) func() int {
	t.Helper()
	pidFile := filepath.Join(t.TempDir(), "holder.pid")
	t.Setenv(envSourceHolderPid, pidFile)
	readPid := func() (int, bool) {
		raw, err := os.ReadFile(pidFile)
		if err != nil {
			return 0, false
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
		return pid, err == nil
	}
	t.Cleanup(func() {
		pid, ok := readPid()
		if !ok {
			return
		}
		proc, err := os.FindProcess(pid)
		if err != nil {
			return
		}
		_ = proc.Kill()
		_, _ = proc.Wait() // waits on Windows; not a child on Unix, returns at once
		if !awaitGone(pid, 10*time.Second) {
			t.Errorf("holder %d is still running after cleanup", pid)
		}
	})
	return func() int {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			if pid, ok := readPid(); ok {
				return pid
			}
			if time.Now().After(deadline) {
				t.Fatal("the holder grandchild never recorded its pid; the test ran without a descendant")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// awaitGone reports whether pid stops existing within the deadline.
func awaitGone(pid int, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for {
		if processGone(pid) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A source that leaves a descendant holding its stdout cannot strand the
// acquisition. On Unix the whole process group is killed, so the return is
// immediate; where there is no process group the bounded pipe wait is what
// returns, five seconds later. Either way the descendant does not decide.
func TestDescendantHoldingThePipeCannotStrandTheAcquisition(t *testing.T) {
	service, _ := testService(t)
	holderPid := expectHolder(t)
	service.maxSourceOutput = 1024
	// On Unix the pipe wait is set long so that only the group kill can make
	// the acquisition return under the limit; process startup and scheduling
	// then have ten seconds of room, and the alternative would take twenty.
	limit := 10 * time.Second
	if runtime.GOOS == "windows" {
		limit = service.waitDelay + 10*time.Second
	} else {
		service.waitDelay = 20 * time.Second
	}
	t.Setenv(envSourceBig, "4096")
	t.Setenv(envSourceHolder, "1")
	// The parent stays alive after writing, so the overflow is observed while
	// the direct child still exists and the context watcher is still acting:
	// this test is about the kill, and the late-exit ordering has its own.
	t.Setenv(envSourceHold, "1")
	started := time.Now()
	_, err := service.acquire("hold-1", "screening", vString("x"))
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("an overflowing source with a descendant on its pipe must fail the acquisition")
	}
	holderPid()
	if elapsed > limit {
		t.Fatalf("the acquisition was held by a descendant; acquire took %s, limit %s", elapsed, limit)
	}
	if _, sealErr := service.sealSession("hold-1"); sealErr == nil {
		t.Fatal("a session whose only acquisition failed must not be sealable")
	}
}

// The bounded buffers bound memory, not only the verdict: past the limit
// nothing more is retained, however much is written.
func TestBoundedBufferRetainsAtMostItsLimit(t *testing.T) {
	buf := &boundedBuffer{limit: 4096}
	chunk := bytes.Repeat([]byte("x"), 1<<20)
	for i := 0; i < 8; i++ {
		if n, err := buf.Write(chunk); n != len(chunk) || err != nil {
			t.Fatalf("Write returned (%d, %v); it must never fail", n, err)
		}
	}
	if buf.buf.Len() != 4096 {
		t.Fatalf("retained %d bytes, want exactly the limit", buf.buf.Len())
	}
	if !buf.overflowed {
		t.Fatal("overflow was not recorded")
	}
	calls := 0
	stopping := &boundedBuffer{limit: 8, stop: func() { calls++ }}
	stopping.Write([]byte("0123456789"))
	stopping.Write([]byte("0123456789"))
	if calls != 1 {
		t.Fatalf("stop must be called exactly once, was called %d times", calls)
	}
}

// Shutting the service down cancels a source in flight rather than leaving
// it running past the gateway. The source is held at a barrier so it is
// certainly running when the service's context ends.
func TestShutdownCancelsAnInFlightSource(t *testing.T) {
	service, _ := testService(t)
	ctx, cancel := context.WithCancel(context.Background())
	service.bindLifetime(ctx)
	dir := t.TempDir()
	started := filepath.Join(dir, "started")
	t.Setenv(envSourceReady, started)
	t.Setenv(envSourceWait, filepath.Join(dir, "never-released"))

	result := make(chan error, 1)
	go func() {
		_, err := service.acquire("shutdown-1", "screening", vString("x"))
		result <- err
	}()
	waitForFile(t, started)
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("a source cancelled by shutdown must fail the acquisition")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("shutdown did not end the in-flight acquisition")
	}
	if _, sealErr := service.sealSession("shutdown-1"); sealErr == nil {
		t.Fatal("a session whose only acquisition was cancelled must not be sealable")
	}
}

// stderr is bounded too: a source that floods it fails with a short message
// and the gateway retains none of the flood.
func TestStderrFloodIsTruncated(t *testing.T) {
	service, _ := testService(t)
	t.Setenv(envSourceStderr, "200000")
	_, err := service.acquire("stderr-1", "screening", vString("x"))
	if err == nil {
		t.Fatal("a failing source must fail the acquisition")
	}
	if len(err.Error()) > 300 {
		t.Fatalf("the failure message must be bounded; got %d bytes", len(err.Error()))
	}
}

// Shutting down over the real HTTP path answers a request in flight before
// serveOn returns: the source is cancelled, the handler writes its refusal,
// the client reads a whole response, and only then does the server come
// down -- so a process that exits when serveOn returns never exits under a
// handler.
func TestShutdownAnswersInFlightRequestsBeforeReturning(t *testing.T) {
	service, _ := testService(t)
	ctx, cancel := context.WithCancel(context.Background())
	service.bindLifetime(ctx)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- service.serveOn(listener) }()

	dir := t.TempDir()
	started := filepath.Join(dir, "started")
	t.Setenv(envSourceReady, started)
	t.Setenv(envSourceWait, filepath.Join(dir, "never-released"))
	type answer struct {
		code int
		body map[string]any
		err  error
	}
	answered := make(chan answer, 1)
	go func() {
		resp, err := http.Post("http://"+listener.Addr().String()+"/acquire", "application/json",
			strings.NewReader(`{"session":"shutdown-http","source":"screening","arguments":{"q":"x"}}`))
		if err != nil {
			answered <- answer{err: err}
			return
		}
		defer resp.Body.Close()
		var body map[string]any
		decodeErr := json.NewDecoder(resp.Body).Decode(&body)
		answered <- answer{code: resp.StatusCode, body: body, err: decodeErr}
	}()
	waitForFile(t, started)
	cancel()

	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("serveOn returned an error: %v", err)
		}
	case <-time.After(service.waitDelay + 20*time.Second):
		t.Fatal("serveOn did not return after shutdown")
	}
	select {
	case a := <-answered:
		if a.err != nil {
			t.Fatalf("the in-flight request must receive a whole response, got transport error: %v", a.err)
		}
		if a.code != http.StatusBadRequest || a.body["error"] == nil {
			t.Fatalf("the in-flight request must be answered with the refusal, got %d %v", a.code, a.body)
		}
	default:
		t.Fatal("serveOn returned before the in-flight request was answered")
	}
	if _, sealErr := service.sealSession("shutdown-http"); sealErr == nil {
		t.Fatal("a session whose only acquisition was cancelled must not be sealable")
	}
}

// When Serve itself fails -- the listener taken away under it -- the sources
// in flight are still ended and their handlers still answer before serveOn
// returns, carrying the serve error. Without that, the process would exit
// with a source running and a handler mid-flight. The request goes over HTTP
// because that is what Shutdown waits for: a handler, not a bare call.
func TestServeFailureStillEndsSourcesInFlight(t *testing.T) {
	service, _ := testService(t)
	service.bindLifetime(context.Background())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- service.serveOn(listener) }()

	dir := t.TempDir()
	started := filepath.Join(dir, "started")
	t.Setenv(envSourceReady, started)
	t.Setenv(envSourceWait, filepath.Join(dir, "never-released"))
	type answer struct {
		code int
		err  error
	}
	answered := make(chan answer, 1)
	go func() {
		resp, err := http.Post("http://"+listener.Addr().String()+"/acquire", "application/json",
			strings.NewReader(`{"session":"serve-failure","source":"screening","arguments":{"q":"x"}}`))
		if err != nil {
			answered <- answer{err: err}
			return
		}
		resp.Body.Close()
		answered <- answer{code: resp.StatusCode}
	}()
	waitForFile(t, started)
	// Take the listener away: Serve returns an error that is not ErrServerClosed.
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-served:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("serveOn must return the serve error, got %v", err)
		}
	case <-time.After(service.waitDelay + 20*time.Second):
		t.Fatal("serveOn did not return after the listener failed")
	}
	select {
	case a := <-answered:
		if a.err != nil || a.code != http.StatusBadRequest {
			t.Fatalf("the in-flight request must be answered with the refusal, got %d %v", a.code, a.err)
		}
	default:
		t.Fatal("serveOn returned while a request was still in flight")
	}
	if _, sealErr := service.sealSession("serve-failure"); sealErr == nil {
		t.Fatal("a session whose only acquisition was cancelled must not be sealable")
	}
}

// A request that is still open when the grace expires is aborted rather than
// kept forever, and serveOn says so. The client here sends headers and a
// partial body and then stalls, which is what a body read timeout longer
// than the grace lets through to Shutdown.
func TestGraceExpiryAbortsAStalledRequest(t *testing.T) {
	service, _ := testService(t)
	service.waitDelay = time.Second // grace of eleven seconds
	ctx, cancel := context.WithCancel(context.Background())
	service.bindLifetime(ctx)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- service.serveOn(listener) }()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Headers complete, body incomplete, then silence.
	if _, err := conn.Write([]byte("POST /acquire HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"session\":")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case err := <-served:
		if err == nil || !strings.Contains(err.Error(), "aborted") {
			t.Fatalf("serveOn must report the aborted request, got %v", err)
		}
	case <-time.After(40 * time.Second):
		t.Fatal("serveOn did not return; the stalled request held it")
	}
}

// --- version 3 minting (SPEC.md §1.2a) ---------------------------------------

// The arguments commitment is salted per receipt: two acquisitions with the
// same arguments commit differently, so no caller can compare across
// receipts; and the salt the caller receives reproduces the commitment
// exactly, so the caller alone can reveal.
func TestArgumentsCommitmentIsSaltedAndReproducible(t *testing.T) {
	_, server := testService(t)
	body := `{"session":"salt-1","source":"screening","arguments":{"q":"acme","n":1}}`
	_, first := post(t, server, "/acquire", body)
	_, second := post(t, server, "/acquire", body)
	c1 := first["receipt"].(map[string]any)["argumentsCommitment"].(string)
	c2 := second["receipt"].(map[string]any)["argumentsCommitment"].(string)
	if c1 == c2 {
		t.Fatal("the same arguments committed identically twice: the salt is not fresh per receipt")
	}
	salt, err := hex.DecodeString(first["salts"].(map[string]any)["args"].(string))
	if err != nil || len(salt) != 32 {
		t.Fatalf("salts.args must decode to 32 bytes: %v", err)
	}
	// Recomputed here from the literal canonical arguments and the returned
	// salt, with no help from the production helper, so a commitment that
	// dropped the arguments or the label would not reproduce.
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte("args:"))
	h.Write([]byte(`{"n":1,"q":"acme"}`))
	if want := "sha256:" + hex.EncodeToString(h.Sum(nil)); want != c1 {
		t.Fatalf("the returned salt does not reproduce the commitment: %s vs %s", want, c1)
	}
	h.Reset()
	h.Write(salt)
	h.Write([]byte("statement:"))
	h.Write([]byte(`{"n":1,"q":"acme"}`))
	if "sha256:"+hex.EncodeToString(h.Sum(nil)) == c1 {
		t.Fatal("labels must separate the commitments of one receipt")
	}
	// Several more draws are all distinct and none is empty. That the draw
	// is unpredictable is crypto/rand's property, which no test observes; a
	// reused salt is the mutation this does catch.
	seen := map[string]bool{first["salts"].(map[string]any)["args"].(string): true,
		second["salts"].(map[string]any)["args"].(string): true}
	for i := 0; i < 4; i++ {
		_, more := post(t, server, "/acquire", body)
		got := more["salts"].(map[string]any)["args"].(string)
		if seen[got] || got == strings.Repeat("0", 64) {
			t.Fatalf("salt %q repeated or empty", got)
		}
		seen[got] = true
	}
}

// observedAt for the command shape is the gateway's own stamp of when it had
// read the source's output in full (SPEC.md §1.2a): of the stamp form, no
// earlier than the request, no later than servedAt.
func TestObservedAtIsTheGatewaysStampOfTheReadInFull(t *testing.T) {
	_, server := testService(t)
	before := nowStamp()
	_, first := post(t, server, "/acquire", `{"session":"obs-1","source":"screening","arguments":{}}`)
	after := nowStamp()
	receipt := first["receipt"].(map[string]any)
	observedAt, _ := receipt["acquisition"].(map[string]any)["observedAt"].(string)
	servedAt, _ := receipt["servedAt"].(string)
	if !regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`).MatchString(observedAt) {
		t.Fatalf("observedAt is not a stamp: %q", observedAt)
	}
	// The stamp form is fixed-width UTC, so string order is time order.
	if observedAt < before || servedAt < observedAt || after < servedAt {
		t.Fatalf("observedAt %s must lie between the request (%s) and servedAt %s (request answered by %s)", observedAt, before, servedAt, after)
	}
}

// The digest names the file that was started, resolved as os/exec resolves
// it: a relative command without an extension resolves to the executable on
// Windows, and the same file is what the record digests.
func TestAdapterDigestNamesTheFileStarted(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	image, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	name := "fetch"
	if runtime.GOOS == "windows" {
		name = "fetch.exe"
	}
	if err := os.WriteFile(filepath.Join(dir, name), image, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	t.Setenv(envSourceHelper, "1")
	configured := "." + string(filepath.Separator) + "fetch"
	root := t.TempDir()
	service, err := newGatewayService(
		filepath.Join(root, "store"), testSeed, "gateway:test", filepath.Join(root, "registry.jsonl"),
		map[string]sourceSpec{"screening": {argv: []string{configured}, env: helperEnv}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(service.handler())
	defer server.Close()
	code, first := post(t, server, "/acquire", `{"session":"rel-1","source":"screening","arguments":{}}`)
	if code != http.StatusOK {
		t.Fatalf("acquire failed: %d %v", code, first)
	}
	adapter := first["receipt"].(map[string]any)["acquisition"].(map[string]any)["adapter"].(map[string]any)
	sum := sha256.Sum256(image)
	if adapter["digest"] != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("the digest must be of the file started (%s): %v", name, adapter["digest"])
	}
	if adapter["name"] != configured {
		t.Fatalf("the adapter is named as configured: %v", adapter["name"])
	}
}

// A command that cannot be resolved or read fails the acquisition before
// anything is started, and leaves the session usable.
func TestAcquisitionFailsCleanlyWhenTheExecutableIsMissing(t *testing.T) {
	t.Setenv(envSourceHelper, "1")
	root := t.TempDir()
	service, err := newGatewayService(
		filepath.Join(root, "store"), testSeed, "gateway:test", filepath.Join(root, "registry.jsonl"),
		map[string]sourceSpec{
			"screening": {argv: []string{os.Args[0]}, env: helperEnv},
			"broken":    {argv: []string{filepath.Join(root, "missing")}},
		})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(service.handler())
	defer server.Close()
	code, body := post(t, server, "/acquire", `{"session":"miss-1","source":"broken","arguments":{}}`)
	if code == http.StatusOK || !strings.Contains(fmt.Sprint(body["error"]), "could not be started") {
		t.Fatalf("a missing executable must fail the acquisition as unstartable: %d %v", code, body)
	}
	code, first := post(t, server, "/acquire", `{"session":"miss-1","source":"screening","arguments":{}}`)
	if code != http.StatusOK || first["receipt"].(map[string]any)["callIndex"] != float64(0) {
		t.Fatalf("the session must remain usable at index 0 after the failure: %d %v", code, first)
	}
}

// The salt is in the acquire response and nowhere the gateway writes: not in
// the store, in either form, and not in the registry.
func TestSaltIsRetainedNowhere(t *testing.T) {
	service, server := testService(t)
	_, first := post(t, server, "/acquire", `{"session":"nowhere-1","source":"screening","arguments":{"q":"acme"}}`)
	saltHex := first["salts"].(map[string]any)["args"].(string)
	raw, err := hex.DecodeString(saltHex)
	if err != nil {
		t.Fatal(err)
	}
	if code, body := post(t, server, "/seal", `{"session":"nowhere-1"}`); code != http.StatusOK {
		t.Fatalf("seal failed: %d %v", code, body)
	}
	check := func(path string) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(saltHex)) || bytes.Contains(data, raw) {
			t.Fatalf("the salt was retained in %s", path)
		}
	}
	files := 0
	err = filepath.WalkDir(service.storeRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			files++
			check(path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 2 {
		t.Fatalf("expected a receipt and an artifact in the store, walked %d files", files)
	}
	check(service.regPath)
}

// The receipt version reaches minting through the command line: the default
// mints version 3, an explicit 3 the same, a 2 the version 2 form; and one
// store holds sessions of both versions across restarts and still verifies.
func TestMintingFollowsTheCommandLineAcrossRestarts(t *testing.T) {
	t.Setenv(envSourceHelper, "1")
	root := t.TempDir()
	store, registry := filepath.Join(root, "store"), filepath.Join(root, "registry.jsonl")
	build := func(extra ...string) *gatewayService {
		t.Helper()
		args := append([]string{
			store, "seed-is-loaded-separately", "gateway:test", registry,
			"--source", "screening=" + os.Args[0], "--source-env", "screening=" + envSourceHelper,
		}, extra...)
		opts, msg, ok := parseServeOptions(args)
		if !ok {
			t.Fatal(msg)
		}
		service, err := buildService(store, testSeed, "gateway:test", registry, opts)
		if err != nil {
			t.Fatal(err)
		}
		return service
	}
	run := func(service *gatewayService, session string) map[string]any {
		t.Helper()
		server := httptest.NewServer(service.handler())
		defer server.Close()
		code, first := post(t, server, "/acquire", `{"session":"`+session+`","source":"screening","arguments":{"q":"x"}}`)
		if code != http.StatusOK {
			t.Fatalf("acquire failed: %d %v", code, first)
		}
		if code, body := post(t, server, "/seal", `{"session":"`+session+`"}`); code != http.StatusOK {
			t.Fatalf("seal failed: %d %v", code, body)
		}
		return first
	}
	byDefault := run(build(), "by-default")
	if r := byDefault["receipt"].(map[string]any); r["receiptVersion"] != "3" || byDefault["salts"] == nil {
		t.Fatalf("the default mints version 3 with salts: %v", byDefault)
	}
	explicit := run(build("--receipt-version", "3"), "explicit-3")
	if r := explicit["receipt"].(map[string]any); r["receiptVersion"] != "3" {
		t.Fatalf("--receipt-version 3 mints version 3: %v", explicit)
	}
	asked := run(build("--receipt-version", "2"), "asked-2")
	if r := asked["receipt"].(map[string]any); r["receiptVersion"] != "2" || asked["salts"] != nil {
		t.Fatalf("--receipt-version 2 mints the version 2 form without salts: %v", asked)
	}
	last := build()
	report, err := verifyWithRegistry(store, registry, "gateway:test", last.publicKey)
	if err != nil || !report.OK || len(report.Findings) != 3 {
		t.Fatalf("a store holding both versions across sessions must verify, three sessions: %v %v", err, report)
	}
}

// A minted version 3 receipt verifies under the version 3 verifier and
// records the command as its adapter: name, an empty version, and the digest
// of the executable the command resolved to.
func TestMintedVersion3ReceiptVerifiesAndDescribesTheCommand(t *testing.T) {
	service, server := testService(t)
	_, first := post(t, server, "/acquire", `{"session":"mint-1","source":"screening","arguments":{"q":"x"}}`)
	if code, body := post(t, server, "/seal", `{"session":"mint-1"}`); code != http.StatusOK {
		t.Fatalf("seal failed: %d %v", code, body)
	}
	report, err := verifyWithRegistry(service.storeRoot, service.regPath, "gateway:test", service.publicKey)
	if err != nil || !report.OK {
		t.Fatalf("a minted version 3 store must verify: %v %v", err, report)
	}
	acquisition := first["receipt"].(map[string]any)["acquisition"].(map[string]any)
	adapter := acquisition["adapter"].(map[string]any)
	if adapter["name"] != os.Args[0] || adapter["version"] != "" {
		t.Fatalf("the adapter is the command as configured: %v", adapter)
	}
	resolved, err := exec.LookPath(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if adapter["digest"] != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("the adapter digest must be the executable's: %v", adapter["digest"])
	}
	if acquisition["observedAt"] == nil || acquisition["observedAt"] == "" {
		t.Fatal("observedAt must be recorded")
	}
}

// A version 3 receipt signed under the version 2 prefix would verify nowhere;
// the store signs under the prefix the core's version names.
func TestMintedReceiptIsSignedUnderItsVersionsPrefix(t *testing.T) {
	service, server := testService(t)
	_, first := post(t, server, "/acquire", `{"session":"prefix-1","source":"screening","arguments":{}}`)
	raw, _ := json.Marshal(first["receipt"])
	v, err := parseJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	r, err := receiptFrom(v.(*vObject))
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := hex.DecodeString(r.signature)
	if !ed25519.Verify(service.publicKey, r.signingInput(), sig) {
		t.Fatal("the minted receipt does not verify under its own version's prefix")
	}
	if ed25519.Verify(service.publicKey, append([]byte(receiptContext), canon(coveredMembers(r))...), sig) {
		t.Fatal("the minted receipt verifies under the version 2 prefix; the prefix does not carry the version")
	}
}

func coveredMembers(r *receipt) *vObject {
	covered := newObject()
	for _, name := range r.obj.names {
		if name == "signature" {
			continue
		}
		v, _ := r.obj.get(name)
		covered.set(name, v)
	}
	return covered
}

// --- adapter sources (SPEC.md §6, "Adapter sources") ------------------------

// shapedService has one adapter source of the given shape and one bare
// command, both the test helper.
func shapedService(t *testing.T, shape string) (*gatewayService, *httptest.Server) {
	t.Helper()
	t.Setenv(envSourceHelper, "1")
	root := t.TempDir()
	service, err := newGatewayService(
		filepath.Join(root, "store"), testSeed, "gateway:test", filepath.Join(root, "registry.jsonl"),
		map[string]sourceSpec{
			"history":   {argv: []string{os.Args[0]}, env: helperEnv, shape: shape},
			"screening": {argv: []string{os.Args[0]}, env: helperEnv},
		})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(service.handler())
	t.Cleanup(server.Close)
	return service, server
}

func envelopeDigest(label string) string {
	sum := sha256.Sum256([]byte(label))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// goodEnvelope is a complete envelope as an Airbyte adapter would write it:
// a page of two records. The acquisition map is returned too, so a test can
// mutate it in place.
func goodEnvelope() (map[string]any, map[string]any) {
	acquisition := map[string]any{
		"adapter":       map[string]any{"name": "airbyte/source-postgres", "version": "3.6.1", "digest": envelopeDigest("image")},
		"endpoint":      "warehouse.internal:5432",
		"statement":     "SELECT id, status FROM decisions WHERE id > 100",
		"snapshot":      "state:8812041",
		"peerIdentity":  "tls:" + envelopeDigest("peer"),
		"schema":        envelopeDigest("schema"),
		"upstreamToken": nil,
		"observedAt":    "2026-09-12T10:00:00Z",
	}
	env := map[string]any{
		"acquisition": acquisition,
		"result":      []any{map[string]any{"id": 101, "status": "approved"}, map[string]any{"id": 102, "status": "denied"}},
		"page":        true,
	}
	return env, acquisition
}

func envelopeText(t *testing.T, env map[string]any) string {
	t.Helper()
	text, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return string(text)
}

// An adapter's envelope is recorded as reported, except for what §1.2a gives
// the gateway: the shape it configured, the commitment to the statement, and
// the page items it digests itself. The attested result is the inner one.
func TestAdapterEnvelopeIsRecordedAsReported(t *testing.T) {
	service, server := shapedService(t, "airbyte")
	env, reported := goodEnvelope()
	t.Setenv(envSourceEnvelope, envelopeText(t, env))
	code, first := post(t, server, "/acquire", `{"session":"env-1","source":"history","arguments":{"stream":"decisions"}}`)
	if code != http.StatusOK {
		t.Fatalf("acquire failed: %d %v", code, first)
	}
	receipt := first["receipt"].(map[string]any)
	acquisition := receipt["acquisition"].(map[string]any)
	if acquisition["shape"] != "airbyte" {
		t.Fatalf("the shape is the configured one: %v", acquisition["shape"])
	}
	for _, name := range []string{"adapter", "endpoint", "snapshot", "peerIdentity", "schema", "upstreamToken", "observedAt"} {
		if !reflect.DeepEqual(acquisition[name], reported[name]) {
			t.Fatalf("%s recorded as %v, reported %v", name, acquisition[name], reported[name])
		}
	}
	// The statement is committed, not stored, and the salt comes back.
	statement, _ := acquisition["statement"].(string)
	saltHex, _ := first["salts"].(map[string]any)["statement"].(string)
	salt, err := hex.DecodeString(saltHex)
	if err != nil || len(salt) != 32 {
		t.Fatalf("salts.statement must be 32 bytes of hex: %q", saltHex)
	}
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte("statement:"))
	h.Write([]byte(`"SELECT id, status FROM decisions WHERE id > 100"`))
	if want := "sha256:" + hex.EncodeToString(h.Sum(nil)); statement != want {
		t.Fatalf("statement commitment %s does not reproduce from the salt (%s)", statement, want)
	}
	if encoded, _ := json.Marshal(receipt); bytes.Contains(encoded, []byte("SELECT")) {
		t.Fatal("the statement text reached the receipt")
	}
	// Page items are the gateway's own digests of each item's canonical form.
	items, _ := acquisition["pageItems"].([]any)
	want := []string{envelopeDigest(`{"id":101,"status":"approved"}`), envelopeDigest(`{"id":102,"status":"denied"}`)}
	if len(items) != 2 || items[0] != want[0] || items[1] != want[1] {
		t.Fatalf("pageItems %v, want %v", items, want)
	}
	// What is attested is the inner result, and that is what the caller gets.
	if receipt["resultDigest"] != envelopeDigest(`[{"id":101,"status":"approved"},{"id":102,"status":"denied"}]`) {
		t.Fatalf("resultDigest must be over the inner result: %v", receipt["resultDigest"])
	}
	if result, _ := first["result"].([]any); len(result) != 2 {
		t.Fatalf("the response result is the inner result: %v", first["result"])
	}
	if code, body := post(t, server, "/seal", `{"session":"env-1"}`); code != http.StatusOK {
		t.Fatalf("seal failed: %d %v", code, body)
	}
	report, err := verifyWithRegistry(service.storeRoot, service.regPath, "gateway:test", service.publicKey)
	if err != nil || !report.OK {
		t.Fatalf("a store with an adapter receipt must verify: %v %v", err, report)
	}
}

// A null statement has no salt and no page has no pageItems; and the same
// bytes from a bare command are attested whole, envelope and all.
func TestAdapterEnvelopeWithoutStatementOrPageAndTheCommandContrast(t *testing.T) {
	_, server := shapedService(t, "mcp")
	env, acquisition := goodEnvelope()
	acquisition["statement"] = nil
	delete(env, "page")
	env["result"] = map[string]any{"content": "live"}
	text := envelopeText(t, env)
	t.Setenv(envSourceEnvelope, text)
	code, first := post(t, server, "/acquire", `{"session":"env-2","source":"history","arguments":{}}`)
	if code != http.StatusOK {
		t.Fatalf("acquire failed: %d %v", code, first)
	}
	acq := first["receipt"].(map[string]any)["acquisition"].(map[string]any)
	if acq["shape"] != "mcp" || acq["statement"] != nil {
		t.Fatalf("a null statement stays null under the configured shape: %v", acq)
	}
	if _, present := acq["pageItems"]; present {
		t.Fatal("no page, no pageItems")
	}
	if _, present := first["salts"].(map[string]any)["statement"]; present {
		t.Fatal("a null statement has no salt")
	}
	// The bare command writes the same text and is attested whole.
	code, whole := post(t, server, "/acquire", `{"session":"env-2","source":"screening","arguments":{}}`)
	if code != http.StatusOK {
		t.Fatalf("acquire failed: %d %v", code, whole)
	}
	receipt := whole["receipt"].(map[string]any)
	if receipt["acquisition"].(map[string]any)["shape"] != "command" {
		t.Fatal("a bare command is the command shape whatever it writes")
	}
	canonical, err := canonText([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if receipt["resultDigest"] != envelopeDigest(string(canonical)) {
		t.Fatal("a bare command's output is attested whole, envelope and all")
	}
	if _, isObject := whole["result"].(map[string]any)["acquisition"]; !isObject {
		t.Fatal("the caller gets the bare command's whole output")
	}
}

// Every departure from the envelope contract fails the acquisition, with
// nothing minted or retained, and the session stays usable.
func TestAdapterEnvelopeRefusals(t *testing.T) {
	_, server := shapedService(t, "http")
	cases := []struct {
		name   string
		mutate func(env, acq map[string]any)
	}{
		{"missing acquisition", func(env, _ map[string]any) { delete(env, "acquisition") }},
		{"missing result", func(env, _ map[string]any) { delete(env, "result") }},
		{"unknown envelope member", func(env, _ map[string]any) { env["extra"] = 1 }},
		{"acquisition missing observedAt", func(_, acq map[string]any) { delete(acq, "observedAt") }},
		{"acquisition names its own shape", func(_, acq map[string]any) { acq["shape"] = "http" }},
		{"acquisition names pageItems", func(_, acq map[string]any) { acq["pageItems"] = []any{} }},
		{"adapter digest malformed", func(_, acq map[string]any) { acq["adapter"].(map[string]any)["digest"] = "sha256:nope" }},
		{"adapter with an extra member", func(_, acq map[string]any) { acq["adapter"].(map[string]any)["image"] = "x" }},
		{"adapter missing its version", func(_, acq map[string]any) { delete(acq["adapter"].(map[string]any), "version") }},
		{"schema not a digest", func(_, acq map[string]any) { acq["schema"] = "the schema" }},
		{"observedAt not a stamp", func(_, acq map[string]any) { acq["observedAt"] = "2026-09-12 10:00:00" }},
		{"endpoint not a string", func(_, acq map[string]any) { acq["endpoint"] = 5432 }},
		{"statement not a string", func(_, acq map[string]any) { acq["statement"] = 7 }},
		{"upstreamToken absent", func(_, acq map[string]any) { delete(acq, "upstreamToken") }},
		{"page false", func(env, _ map[string]any) { env["page"] = false }},
		{"page with an object result", func(env, _ map[string]any) { env["result"] = map[string]any{"rows": 2} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, acq := goodEnvelope()
			tc.mutate(env, acq)
			t.Setenv(envSourceEnvelope, envelopeText(t, env))
			code, body := post(t, server, "/acquire", `{"session":"env-3","source":"history","arguments":{}}`)
			if code == http.StatusOK || !strings.Contains(fmt.Sprint(body["error"]), "not an envelope") {
				t.Fatalf("must be refused as not an envelope: %d %v", code, body)
			}
		})
	}
	t.Run("not an object", func(t *testing.T) {
		t.Setenv(envSourceEnvelope, `[]`)
		code, body := post(t, server, "/acquire", `{"session":"env-3","source":"history","arguments":{}}`)
		if code == http.StatusOK || !strings.Contains(fmt.Sprint(body["error"]), "not an envelope") {
			t.Fatalf("must be refused as not an envelope: %d %v", code, body)
		}
	})
	env, _ := goodEnvelope()
	t.Setenv(envSourceEnvelope, envelopeText(t, env))
	code, first := post(t, server, "/acquire", `{"session":"env-3","source":"history","arguments":{}}`)
	if code != http.StatusOK || first["receipt"].(map[string]any)["callIndex"] != float64(0) {
		t.Fatalf("no refusal minted anything: the session's first receipt is index 0: %d %v", code, first)
	}
}

// An adapter source has nowhere to put its acquisition in a version 2
// receipt, so a version 2 gateway refuses it rather than attest the
// envelope as a result.
func TestAdapterSourceNeedsVersion3(t *testing.T) {
	service, server := shapedService(t, "airbyte")
	service.receiptVersion = receiptVersion
	env, _ := goodEnvelope()
	t.Setenv(envSourceEnvelope, envelopeText(t, env))
	code, body := post(t, server, "/acquire", `{"session":"env-4","source":"history","arguments":{}}`)
	if code == http.StatusOK || !strings.Contains(fmt.Sprint(body["error"]), "needs receipt version 3") {
		t.Fatalf("an adapter source under version 2 must be refused: %d %v", code, body)
	}
}
