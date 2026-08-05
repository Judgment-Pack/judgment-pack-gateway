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
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
