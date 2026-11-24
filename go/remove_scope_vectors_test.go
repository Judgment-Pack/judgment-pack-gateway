package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The remove-scope vectors of corpus/v3/stores (ADR-0059 §8, as built
// 2026-11-24): v3-journal-refusal-holds after a real gateway remove-scope
// of its scope corpus-a, which holds the refusal journal and no session,
// signed by the corpus's TEST-SEED. Its operator journal's second entry is
// remove-scope's, naming no removal record and the refusal journal by its
// two members. Both verifiers run them by TestStoreVectors and verify-ts's
// corpus test; this test writes them again where
// GATEWAY_WRITE_REMOVE_SCOPE_VECTORS is 1.
func TestRemoveScopeVectorsAreWritten(t *testing.T) {
	if os.Getenv("GATEWAY_WRITE_REMOVE_SCOPE_VECTORS") != "1" {
		t.Skip("writes the corpus's remove-scope vectors where GATEWAY_WRITE_REMOVE_SCOPE_VECTORS is 1")
	}
	var source storeVector
	readJSON(t, corpusPath("v3", "stores", "v3-journal-refusal-holds.json"), &source)
	tmp, root, registryPath, _, err := materializeVector(source)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)
	const scope = "corpus-a"
	name := refusalJournalName(scope)
	dir := filepath.Join(root, journalsDir)
	// the scope's key and forwarding cursor, as a serving gateway leaves them
	if err := os.WriteFile(filepath.Join(dir, name+".key"), []byte(strings.Repeat("ab", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".forwarded"), []byte("0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	removed := readFile(t, filepath.Join(dir, name+".jsonl"))
	seedPath := filepath.Join(t.TempDir(), "gateway.seed")
	if err := os.WriteFile(seedPath, []byte(hex.EncodeToString(corpusSeed(t))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := cmdRemoveScopeAt([]string{"--store", root, "--seed", seedPath, "--registry", registryPath, "--authority", source.Authority, "--scope", scope, "--by", "operator-1"},
		&stdout, &stderr, fixedStamp("2026-09-12T00:00:03Z")); code != 0 || !strings.Contains(stderr.String(), "its key and its cursor are removed") {
		t.Fatalf("remove-scope: %d %q", code, stderr.String())
	}
	files := map[string]any{}
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		files[filepath.ToSlash(rel)] = readFile(t, path)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, left := files["journals/"+name+".jsonl"]; left || len(files) != len(source.Files)-1 {
		t.Fatalf("the store after the removal: %v", files)
	}
	operator := files["journals/"+operatorJournal+".jsonl"].(string)
	lines, _ := journalLines([]byte(operator))
	if len(lines) != 2 {
		t.Fatalf("%d operator entries", len(lines))
	}
	v, err := parseRecordJSON(lines[1])
	if err != nil {
		t.Fatal(err)
	}
	entry := v.(*vObject)
	raw, _ := entry.get("body")
	body := raw.(*vObject)
	if n, _ := recordCount(body, "refusalJournalBytes"); n != int64(len(removed)) {
		t.Fatalf("the entry names %d bytes of %d", n, len(removed))
	}
	// the half: the same entry with refusalJournalDigest dropped, signed again
	half := newObject()
	for _, member := range body.names {
		if member != "refusalJournalDigest" {
			m, _ := body.get(member)
			half.set(member, m)
		}
	}
	seed, err := loadSeed(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	ordinal, _ := recordCount(entry, "ordinal")
	previous, _ := memberString(entry, "previous")
	at, _ := memberString(entry, "at")
	halfLine, err := signedJournalEntry(newSigningKey(newSeedSigner(seed)), operatorJournal, ordinal, previous, at, half)
	if err != nil {
		t.Fatal(err)
	}
	halfFiles := map[string]any{}
	for path, data := range files {
		halfFiles[path] = data
	}
	halfFiles["journals/"+operatorJournal+".jsonl"] = string(lines[0]) + "\n" + string(halfLine)

	for _, w := range []struct {
		name, note string
		files      map[string]any
		forged     bool
	}{
		{"v3-journal-remove-scope-refusal-journal", "v3-journal-refusal-holds after gateway remove-scope of corpus-a, a scope that holds its refusal journal and no session: the journal goes, and the operator journal's second entry is remove-scope's, naming no removal record (removalBytes 0) and the refusal journal by refusalJournalBytes and refusalJournalDigest (ADR-0059 §8, amending ADR-0056 §4): no finding, and journal-from.",
			files, false},
		{"v3-journal-remove-scope-refusal-half", "v3-journal-remove-scope-refusal-journal with refusalJournalDigest dropped from the remove-scope entry, signed again by the key in force: a removed refusal journal is named by both members or by neither, so the entry does not load: journal-entry-forged at ordinal 1 (ADR-0059 §8).",
			halfFiles, true},
	} {
		var vec map[string]any
		raw, err := os.ReadFile(corpusPath("v3", "stores", "v3-journal-holds.json"))
		if err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&vec); err != nil {
			t.Fatal(err)
		}
		vec["name"], vec["note"], vec["files"] = w.name, w.note, w.files
		expected := vec["expected"].(map[string]any)
		if w.forged {
			expected["findings"] = append(expected["findings"].([]any), map[string]any{"journal": operatorJournal, "ordinal": 1, "status": "journal-entry-forged"})
			expected["ok"] = false
			var kept []any
			for _, o := range expected["observations"].([]any) {
				if o.(map[string]any)["journal"] != operatorJournal {
					kept = append(kept, o)
				}
			}
			expected["observations"] = kept
		}
		var out bytes.Buffer
		encoder := json.NewEncoder(&out)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(vec); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(corpusPath("v3", "stores", w.name+".json"), out.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
