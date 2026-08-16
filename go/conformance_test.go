package main

// Runs the frozen corpus against this implementation. The corpus is the
// arbiter -- these are not tests of the Go code's own opinions.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func corpusPath(parts ...string) string {
	return filepath.Join(append([]string{"..", "corpus"}, parts...)...)
}

func TestEd25519Vectors(t *testing.T) {
	var doc struct {
		Vectors []struct {
			Seed      string `json:"seed"`
			Message   string `json:"message"`
			PublicKey string `json:"publicKey"`
			Signature string `json:"signature"`
		} `json:"vectors"`
	}
	readJSON(t, corpusPath("ed25519-vectors.json"), &doc)
	for i, v := range doc.Vectors {
		seed := mustHex(t, v.Seed)
		msg := mustHex(t, v.Message)
		priv := ed25519.NewKeyFromSeed(seed)
		pub := []byte(priv.Public().(ed25519.PublicKey))
		if got := hex.EncodeToString(pub); got != v.PublicKey {
			t.Errorf("vector %d: public key %s, want %s", i, got, v.PublicKey)
		}
		if got := hex.EncodeToString(ed25519.Sign(priv, msg)); got != v.Signature {
			t.Errorf("vector %d: signature %s, want %s", i, got, v.Signature)
		}
		if !ed25519.Verify(pub, msg, mustHex(t, v.Signature)) {
			t.Errorf("vector %d: signature did not verify", i)
		}
	}
	t.Logf("%d/%d ed25519 vectors", len(doc.Vectors), len(doc.Vectors))
}

func TestCanonVectors(t *testing.T) {
	var doc struct {
		Vectors []struct {
			Note        string `json:"note"`
			InputJSON   string `json:"inputJson"`
			ExpectedHex string `json:"expectedHex"`
			Reject      bool   `json:"reject"`
		} `json:"vectors"`
	}
	readJSON(t, corpusPath("canon.json"), &doc)
	passed := 0
	for _, v := range doc.Vectors {
		got, err := canonText([]byte(v.InputJSON))
		switch {
		case v.Reject && err == nil:
			t.Errorf("%s: accepted %s -> %q, want refusal", v.Note, v.InputJSON, got)
		case v.Reject:
			passed++
		case err != nil:
			t.Errorf("%s: refused %s: %v", v.Note, v.InputJSON, err)
		case hex.EncodeToString(got) != v.ExpectedHex:
			t.Errorf("%s: %s\n got %s (%q)\nwant %s", v.Note, v.InputJSON,
				hex.EncodeToString(got), got, v.ExpectedHex)
		default:
			passed++
		}
	}
	t.Logf("%d/%d canon vectors", passed, len(doc.Vectors))
}

func TestStoreVectors(t *testing.T) {
	publicKey := mustHex(t, strings.TrimSpace(readFile(t, corpusPath("TEST-PUBLIC-KEY"))))
	names, err := filepath.Glob(corpusPath("stores", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	passed := 0
	for _, name := range names {
		// One materializer, shared with `gateway conform`. This test used to
		// carry its own copy, and the two silently disagreed the moment the
		// vector schema grew a field only one of them knew about.
		var vec storeVector
		readJSON(t, name, &vec)

		tmp, root, registryPath, err := materializeVector(vec)
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmp)

		rep, err := verifyWithRegistry(root, registryPath, vec.Authority, publicKey)
		if err != nil {
			t.Errorf("%s: no verdict: %v", vec.Name, err)
			continue
		}
		ok := true
		if rep.OK != vec.Expected.OK {
			t.Errorf("%s: ok=%v, want %v", vec.Name, rep.OK, vec.Expected.OK)
			ok = false
		}
		got := normalizeFindings(t, rep.Findings)
		want := normalizeFindingMaps(vec.Expected.Findings)
		if !equalMultiset(got, want) {
			t.Errorf("%s: findings\n got %v\nwant %v", vec.Name, got, want)
			ok = false
		}
		if ok {
			passed++
		}
	}
	t.Logf("%d/%d store vectors", passed, len(names))
}

// normalizeFindings round-trips through the wire encoding, so what is compared
// is what the process contract would actually emit.
func normalizeFindings(t *testing.T, findings []finding) []string {
	t.Helper()
	raw, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	var back []map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	return normalizeFindingMaps(back)
}

func normalizeFindingMaps(findings []map[string]any) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		keys := make([]string, 0, len(f))
		for k := range f {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var sb strings.Builder
		for i, k := range keys {
			if i > 0 {
				sb.WriteString(" ")
			}
			fmt.Fprintf(&sb, "%s=%v", k, f[k])
		}
		out = append(out, sb.String())
	}
	sort.Strings(out)
	return out
}

func equalMultiset(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func readJSON(t *testing.T, path string, dst any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader([]byte(readFile(t, path))))
	if err := dec.Decode(dst); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestREADMEVectorCounts(t *testing.T) {
	readme := readFile(t, corpusPath("README.md"))

	canonRe := regexp.MustCompile(`\*\*` + "`" + `canon\.json` + "`" + `\*\* — (\d+) vectors`)
	storesRe := regexp.MustCompile(`\*\*` + "`" + `stores/\*\.json` + "`" + `\*\* — (\d+) vectors`)

	canonMatch := canonRe.FindStringSubmatch(readme)
	if canonMatch == nil {
		t.Fatal("README.md missing expected sentence for canon.json vectors count")
	}
	statedCanon, _ := strconv.Atoi(canonMatch[1])

	storesMatch := storesRe.FindStringSubmatch(readme)
	if storesMatch == nil {
		t.Fatal("README.md missing expected sentence for stores/*.json vectors count")
	}
	statedStores, _ := strconv.Atoi(storesMatch[1])

	var canonDoc struct {
		Vectors []any `json:"vectors"`
	}
	readJSON(t, corpusPath("canon.json"), &canonDoc)
	actualCanon := len(canonDoc.Vectors)

	storeFiles, err := filepath.Glob(corpusPath("stores", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	actualStores := len(storeFiles)

	if statedCanon != actualCanon {
		t.Errorf("README.md states %d canon vectors, but there are actually %d in canon.json", statedCanon, actualCanon)
	}
	if statedStores != actualStores {
		t.Errorf("README.md states %d store vectors, but there are actually %d in stores/*.json", statedStores, actualStores)
	}
}
