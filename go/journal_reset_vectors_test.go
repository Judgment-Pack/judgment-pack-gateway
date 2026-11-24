package main

import (
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The journal reset vectors of corpus/v3/stores (gateway #611):
// v3-journal-refusal-holds, given a refusal journal of the sources of no
// scope with its key and cursor, after gateway journal reset --unscoped's
// work, signed by the corpus's TEST-SEED. The scope corpus-a's journal
// stays; the operator journal's second entry is refusal-journal-reset's.
// Both verifiers run them by TestStoreVectors and verify-ts's corpus test;
// this test writes them again where GATEWAY_WRITE_JOURNAL_RESET_VECTORS is
// 1. The journal it resets is drawn afresh each time, under a new key and
// nonces, so a rewrite changes the entry's digest and not the verdict.
func TestJournalResetVectorsAreWritten(t *testing.T) {
	if os.Getenv("GATEWAY_WRITE_JOURNAL_RESET_VECTORS") != "1" {
		t.Skip("writes the corpus's journal reset vectors where GATEWAY_WRITE_JOURNAL_RESET_VECTORS is 1")
	}
	var source storeVector
	readJSON(t, corpusPath("v3", "stores", "v3-journal-refusal-holds.json"), &source)
	tmp, root, registryPath, _, err := materializeVector(source)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)
	seed := corpusSeed(t)
	key := newSigningKey(newSeedSigner(seed))
	walk, err := engineWalk([]byte(readFile(t, registryPath)), key.held())
	if err != nil {
		t.Fatal(err)
	}
	keys := func() ([]reachedKey, error) { return walk.keys, nil }
	j, err := newRefusalJournals(&refusalJournalConfig{maxBytes: refusalDefaultCap}, map[string]bool{unscopedMarker: true}, refusalFS{root: root},
		func() *signingKey { return key }, keys, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	j.handOff(j.scopes[unscopedMarker], "/seal", refusalNote{reason: "session"}, 404, unitCaller(), nil, time.Date(2026, 9, 12, 0, 0, 2, 0, time.UTC))
	j.round()
	j.stop()
	name := refusalJournalName(unscopedMarker)
	dir := filepath.Join(root, journalsDir)
	if err := os.WriteFile(filepath.Join(dir, name+".forwarded"), []byte("0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	removed := readFile(t, filepath.Join(dir, name+".jsonl"))
	// the command's work once the registry is held (journalReset)
	journal, err := beginOperatorJournal(root, registryPath, operatorJournalVersion, key, walk.keys, fixedStamp("2026-09-12T00:00:03Z"))
	if err != nil {
		t.Fatal(err)
	}
	var out removalOutcome
	if err := resetUnscopedRefusalJournal(root, "operator-1", journal, walk.keys, &out); err != nil || len(out.notes) != 1 {
		t.Fatalf("the reset: %v %v", err, out.notes)
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
	if len(files) != len(source.Files) {
		t.Fatalf("the store after the reset: %v", files)
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
	ordinal, _ := recordCount(entry, "ordinal")
	previous, _ := memberString(entry, "previous")
	at, _ := memberString(entry, "at")
	halfLine, err := signedJournalEntry(key, operatorJournal, ordinal, previous, at, half)
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
		{"v3-journal-refusal-journal-reset", "v3-journal-refusal-holds, given a refusal journal of the sources of no scope (unscoped) with its key and cursor, after gateway journal reset --unscoped: that journal, its key and its cursor go, the scope corpus-a's journal stays, and the operator journal's second entry is refusal-journal-reset's, naming the journal by refusalJournalBytes and refusalJournalDigest (gateway #611; ADR-0056 §4, amended): no finding, and journal-from for each journal.",
			files, false},
		{"v3-journal-refusal-journal-reset-half", "v3-journal-refusal-journal-reset with refusalJournalDigest dropped from the refusal-journal-reset entry, signed again by the key in force: both members are required in that kind, so the entry does not load: journal-entry-forged at ordinal 1.",
			halfFiles, true},
	} {
		var vec map[string]any
		raw, err := os.ReadFile(corpusPath("v3", "stores", "v3-journal-refusal-holds.json"))
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
			findings, _ := expected["findings"].([]any)
			expected["findings"] = append(findings, map[string]any{"journal": operatorJournal, "ordinal": 1, "status": "journal-entry-forged"})
			expected["ok"] = false
			var kept []any
			for _, o := range expected["observations"].([]any) {
				if o.(map[string]any)["journal"] != operatorJournal {
					kept = append(kept, o)
				}
			}
			expected["observations"] = kept
		}
		var buf bytes.Buffer
		encoder := json.NewEncoder(&buf)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(vec); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(corpusPath("v3", "stores", w.name+".json"), buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
