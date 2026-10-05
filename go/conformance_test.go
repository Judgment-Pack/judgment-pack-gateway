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
	names, err := storeVectorPaths(corpusPath())
	if err != nil {
		t.Fatal(err)
	}
	passed := 0
	for _, name := range names {
		// One materializer, shared with `gateway conform`. This test used to
		// carry its own copy, and the two silently disagreed the moment the
		// vector schema grew a field only one of them knew about.
		var vec storeVector
		readJSON(t, name, &vec)

		tmp, root, registryPath, decisionRecords, err := materializeVector(vec)
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmp)

		rep, err := verifyWithRegistryAndRecords(root, registryPath, vec.Authority, decisionRecords, publicKey)
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

// TestWitnessVectors holds this reader to every witness vector, through the
// files the process contract hands an implementation (SPEC.md §8).
func TestWitnessVectors(t *testing.T) {
	failures, count, err := runWitnessVectors(corpusPath(), inProcess{})
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range failures {
		t.Error(failure)
	}
	t.Logf("%d/%d witness vectors", count-len(failures), count)
}

// The corpus holds nothing the runner does not read: an entry of another
// name, a file in place of a directory of vectors, and a vector of a family
// the runner does not know each refuse the run.
func TestTheCorpusHoldsNothingUnread(t *testing.T) {
	if err := corpusEntries(corpusPath()); err != nil {
		t.Fatalf("the corpus: %v", err)
	}
	copyCorpus := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		if err := os.CopyFS(dir, os.DirFS(corpusPath())); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	for _, c := range []struct {
		what string
		make func(dir string) error
	}{
		{"a family of vectors with no reader", func(dir string) error {
			return os.Mkdir(filepath.Join(dir, "v4"), 0o755)
		}},
		{"a file beside the witness vectors", func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "witness", "notes.txt"), nil, 0o600)
		}},
		{"a directory under the version 3 vectors", func(dir string) error {
			return os.Mkdir(filepath.Join(dir, "v3", "receipts"), 0o755)
		}},
		{"a directory among the store vectors", func(dir string) error {
			return os.Mkdir(filepath.Join(dir, "v3", "stores", "more"), 0o755)
		}},
	} {
		dir := copyCorpus(t)
		if err := c.make(dir); err != nil {
			t.Fatal(err)
		}
		if _, _, err := runCorpus(dir, inProcess{}); err == nil {
			t.Errorf("%s: the run was not refused", c.what)
		}
	}
	dir := copyCorpus(t)
	vector := filepath.Join(dir, "witness", "valid-one-statement.json")
	raw, err := os.ReadFile(vector)
	if err != nil {
		t.Fatal(err)
	}
	for what, edit := range map[string][2]string{
		"a family no reader knows":   {`"family": "valid"`, `"family": "continuation"`},
		"a member no reader knows":   {`"family": "valid",`, `"family": "valid", "resume": "",`},
		"a name that is not its own": {`"name": "valid-one-statement"`, `"name": "valid-two-statements"`},
	} {
		if err := os.WriteFile(vector, bytes.Replace(raw, []byte(edit[0]), []byte(edit[1]), 1), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := runCorpus(dir, inProcess{}); err == nil {
			t.Errorf("%s: the run was not refused", what)
		}
	}
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
	v3Re := regexp.MustCompile(`\*\*` + "`" + `v3/stores/\*\.json` + "`" + `\*\* — (\d+) vectors`)

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

	v3Match := v3Re.FindStringSubmatch(readme)
	if v3Match == nil {
		t.Fatal("README.md missing expected sentence for v3/stores/*.json vectors count")
	}
	statedV3, _ := strconv.Atoi(v3Match[1])

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
	v3Files, err := filepath.Glob(corpusPath("v3", "stores", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if statedV3 != len(v3Files) {
		t.Errorf("README.md states %d version 3 store vectors, but there are actually %d in v3/stores/*.json", statedV3, len(v3Files))
	}

	// The witness vectors: the total, and each family's row of the table.
	witnessRe := regexp.MustCompile(`\*\*` + "`" + `witness/\*\.json` + "`" + `\*\* — (\d+) vectors`)
	witnessMatch := witnessRe.FindStringSubmatch(readme)
	if witnessMatch == nil {
		t.Fatal("README.md missing expected sentence for witness/*.json vectors count")
	}
	statedWitness, _ := strconv.Atoi(witnessMatch[1])
	paths, err := witnessVectorPaths(corpusPath())
	if err != nil {
		t.Fatal(err)
	}
	if statedWitness != len(paths) {
		t.Errorf("README.md states %d witness vectors, but there are actually %d in witness/*.json", statedWitness, len(paths))
	}
	actualFamilies := map[string]int{}
	for _, path := range paths {
		vector, err := readWitnessVector(path)
		if err != nil {
			t.Fatal(err)
		}
		actualFamilies[vector.Family]++
	}
	statedFamilies := map[string]int{}
	for _, row := range regexp.MustCompile("(?m)^\\| `([a-z-]+)` \\| (\\d+) \\|").FindAllStringSubmatch(readme, -1) {
		n, _ := strconv.Atoi(row[2])
		statedFamilies[row[1]] = n
	}
	for family := range witnessFamilies {
		if statedFamilies[family] != actualFamilies[family] {
			t.Errorf("README.md states %d witness vectors of family %s, but there are %d", statedFamilies[family], family, actualFamilies[family])
		}
	}
}
