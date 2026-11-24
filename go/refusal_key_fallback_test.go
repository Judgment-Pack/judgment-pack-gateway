package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A store whose journals/ is on another filesystem cannot link the staged
// key into place: the draw falls back to the key made in place, whole, the
// staged file goes, and entries chain under it. Any other link failure
// still refuses the draw.
func TestAKeyDrawFallsBackWhereTheStoreLinksNoFile(t *testing.T) {
	failWith := func(cause syscall.Errno) {
		keyLink = func(old, new string) error { return &os.LinkError{Op: "link", Old: old, New: new, Err: cause} }
	}
	t.Cleanup(func() { keyLink = os.Link })
	failWith(syscall.EIO)
	if _, _, err := (refusalFS{root: t.TempDir()}).key(refusalJournalName(callerScopeA)); err == nil {
		t.Fatal("a link that failed for another cause drew a key")
	}

	failWith(syscall.EXDEV)
	h := limitsSetup(t, refusalLimits())
	if err := h.g.openRefusalJournals(&refusalJournalConfig{maxBytes: refusalDefaultCap}, &refusalStderr{}); err != nil {
		t.Fatalf("the start on a store that links no file: %v", err)
	}
	j := h.g.refusals
	t.Cleanup(j.stop)
	s := j.scopes[callerScopeA]
	dir := filepath.Join(h.g.storeRoot, journalsDir)
	key := readFile(t, filepath.Join(dir, s.name+".key"))
	if len(key) != refusalKeyFileBytes || strings.TrimSuffix(key, "\n") != hex.EncodeToString(s.secret) {
		t.Fatalf("the key drawn in place: %q", key)
	}
	entries, err := os.ReadDir(h.g.storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("a staged file stands: %s", e.Name())
		}
	}
	for i := 0; i < 2; i++ {
		j.handOff(s, "/seal", refusalNote{reason: "session"}, 404, unitCaller(), nil, time.Now())
		j.round()
	}
	data := []byte(readFile(t, filepath.Join(dir, s.name+".jsonl")))
	keys, _ := h.g.provenanceKeys()
	if f, n, _ := judgeRefusalJournal(data, s.name, keys); f != nil || n != 2 {
		t.Fatalf("the journal: %v, %d entries", f, n)
	}
	lines, _ := journalLines(data)
	if ok, _, err := matchRefusalEntry(lines[1], s.secret, "/seal", nil); !ok || err != nil {
		t.Fatalf("the second entry under the key: %v", err)
	}
}

// A key file shorter than a key beside no journal, as a draw in place
// ended part way leaves it, is drawn again at the start, which says so;
// beside a journal holding entries the start still refuses it.
func TestAShortKeyBesideNoEntryIsDrawnAgain(t *testing.T) {
	h := limitsSetup(t, refusalLimits())
	dir := filepath.Join(h.g.storeRoot, journalsDir)
	name := refusalJournalName(callerScopeA)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".key"), []byte("ab12"), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr := &refusalStderr{}
	if err := h.g.openRefusalJournals(&refusalJournalConfig{maxBytes: refusalDefaultCap}, stderr); err != nil {
		t.Fatalf("the start: %v", err)
	}
	h.g.refusals.stop()
	if strings.Count(stderr.String(), "refusal journal: journal "+name+": its key file is shorter than a key and no entry is beside it") != 1 {
		t.Errorf("stderr: %q", stderr.String())
	}
	key, err := os.ReadFile(filepath.Join(dir, name+".key"))
	if err != nil || len(key) != refusalKeyFileBytes || !bytes.Equal(key[64:], []byte("\n")) {
		t.Fatalf("the key drawn again: %q %v", key, err)
	}

	if err := os.WriteFile(filepath.Join(dir, name+".key"), []byte("ab12"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.g.openRefusalJournals(&refusalJournalConfig{maxBytes: refusalDefaultCap}, &refusalStderr{}); err == nil {
		h.g.refusals.stop()
		t.Fatal("a short key beside a journal holding entries was taken")
	}
	if got := readFile(t, filepath.Join(dir, name+".key")); got != "ab12" {
		t.Fatalf("the short key beside entries changed: %q", got)
	}
}
