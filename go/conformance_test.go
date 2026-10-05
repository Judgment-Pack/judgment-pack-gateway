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
	"sort"
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
		{"a file beside the witness recovery vectors", func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "witness-recovery", "generator.go"), nil, 0o600)
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
		"a family no reader knows":                      {`"family": "valid"`, `"family": "continuation"`},
		"a member no reader knows":                      {`"family": "valid",`, `"family": "valid", "resume": "",`},
		"a name that is not its own":                    {`"name": "valid-one-statement"`, `"name": "valid-two-statements"`},
		"an expected member no runner compares":         {`"expected": {`, `"expected": {"unread-claim": true,`},
		"a latest-checkpoint member no runner compares": {`"latestCheckpoint": {`, `"latestCheckpoint": {"unread-claim": true,`},
		"an expected answer missing a member":           {`"retired": false`, `"retiredd": false`},
	} {
		if err := os.WriteFile(vector, bytes.Replace(raw, []byte(edit[0]), []byte(edit[1]), 1), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := runCorpus(dir, inProcess{}); err == nil {
			t.Errorf("%s: the run was not refused", what)
		}
	}
}

// TestWitnessRecoveryVectors holds this implementation's witness to every
// recovery vector (corpus/witness-recovery/; ADR-0013 §4), and holds the
// runner to refusing a vector it cannot read and to running none for
// another implementation.
func TestWitnessRecoveryVectors(t *testing.T) {
	failures, count, err := runRecoveryVectors(corpusPath(), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range failures {
		t.Error(failure)
	}
	t.Logf("%d/%d witness recovery vectors", count-len(failures), count)

	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(corpusPath())); err != nil {
		t.Fatal(err)
	}
	vector := filepath.Join(dir, "witness-recovery", "refused-a-stale-backup-behind-the-marks.json")
	raw, err := os.ReadFile(vector)
	if err != nil {
		t.Fatal(err)
	}
	wrong := bytes.Replace(raw, []byte(`"outcome": "refused"`), []byte(`"outcome": "start"`), 1)
	if err := os.WriteFile(vector, wrong, 0o600); err != nil {
		t.Fatal(err)
	}
	if failures, _, err := runRecoveryVectors(dir, false); err != nil || len(failures) != 0 {
		t.Errorf("read for another implementation, a vector was run: %v, %d failures", err, len(failures))
	}
	if failures, _, err := runRecoveryVectors(dir, true); err != nil || len(failures) != 1 {
		t.Errorf("a vector expecting a start where the rules refuse: %v, %d failures", err, len(failures))
	}
	for what, edit := range map[string][2]string{
		"a family no reader knows":         {`"family": "refused"`, `"family": "rollback"`},
		"a member no reader knows":         {`"family": "refused",`, `"family": "refused", "seed": "",`},
		"a name that is not its own":       {`"name": "refused-a-stale-backup-behind-the-marks"`, `"name": "refused-a-stale-backup"`},
		"a file no runner compares":        {`"files": {`, `"files": {"journal": "",`},
		"a step of two actions":            {`"open": {`, `"replace": {}, "open": {`},
		"an expected outcome with nothing": {`"findings": [`, `"findingz": [`},
		"a registration of no kind":        {`"registration": "operator"`, `"registration": "anyone"`},
	} {
		if err := os.WriteFile(vector, bytes.Replace(raw, []byte(edit[0]), []byte(edit[1]), 1), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := runCorpus(dir, inProcess{}); err == nil {
			t.Errorf("%s: the run was not refused", what)
		}
	}
	if err := os.WriteFile(vector, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// a statement the test key did not sign refuses the vector before it runs
	writer := filepath.Join(dir, "witness-recovery", "writer-a-sync-failure-stops-another-trail.json")
	raw, err = os.ReadFile(writer)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(writer, bytes.Replace(raw, []byte(`"statements": [
    "{\"checkpoint\":{\"checkpointVersion\":\"1\",\"recordDigest\":\"sha256:`), []byte(`"statements": [
    "{\"checkpoint\":{\"checkpointVersion\":\"1\",\"recordDigest\":\"sha256:0`), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runRecoveryVectors(dir, false); err == nil || !strings.Contains(err.Error(), "no statement the test key signed") {
		t.Errorf("a statement no key signed: %v", err)
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

// The README states how many vectors each family holds, and `gateway
// conform` refuses a corpus whose README says otherwise: a total of canon,
// store, version 3 store or witness vectors, or a witness family's row.
func TestREADMEVectorCounts(t *testing.T) {
	if err := corpusStatedCounts(corpusPath()); err != nil {
		t.Fatal(err)
	}
	readme, err := os.ReadFile(corpusPath("README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, edit := range []struct{ what, from, to string }{
		{"the canon count", "**`canon.json`** — 30 vectors", "**`canon.json`** — 31 vectors"},
		{"the store count", "**`stores/*.json`** — 21 vectors", "**`stores/*.json`** — 20 vectors"},
		{"the version 3 count", "**`v3/stores/*.json`** — 31 vectors", "**`v3/stores/*.json`** — 32 vectors"},
		{"the witness count", "**`witness/*.json`** — 54 vectors", "**`witness/*.json`** — 55 vectors"},
		{"a family's row", "| `chain` | 10 |", "| `chain` | 11 |"},
		{"a family no runner reads", "| `chain` | 10 |", "| `chain` | 10 |\n| `continuation` | 0 |"},
		{"the witness recovery count", "**`witness-recovery/*.json`** — 25 vectors", "**`witness-recovery/*.json`** — 24 vectors"},
		{"a recovery family's row", "| `new-key` | 8 |", "| `new-key` | 7 |"},
		{"a recovery family no runner reads", "| `writer` | 5 |", "| `writer` | 5 |\n| `continuation` | 0 |"},
		{"a recovery family stated among the witness families", "| `chain` | 10 |", "| `chain` | 10 |\n| `writer` | 0 |"},
	} {
		if !bytes.Contains(readme, []byte(edit.from)) {
			t.Fatalf("%s: the README no longer says %q", edit.what, edit.from)
		}
		dir := t.TempDir()
		if err := os.CopyFS(dir, os.DirFS(corpusPath())); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "README.md"), bytes.Replace(readme, []byte(edit.from), []byte(edit.to), 1), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := runCorpus(dir, inProcess{}); err == nil {
			t.Errorf("%s: a README that misstates it did not refuse the run", edit.what)
		}
	}
}
