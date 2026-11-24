package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A line whose sync fails is cut back, under the round's lock, so the size
// the lock shows never counts a line that may not be durable: the file is
// back to its old size, the entry is dropped and counted (write-failed), and
// the next entry is written at that ordinal and chains to the one before.
// Where the cut back's own sync fails too, the scope is lost and nothing more
// is written after it. A writer that does not cut back fails it.
func TestARefusalLineWhoseSyncFailsIsCutBack(t *testing.T) {
	h, j, s := refusalUnit(t, refusalDefaultCap)
	path := filepath.Join(h.g.storeRoot, journalsDir, s.name+".jsonl")
	refuse := func() {
		j.handOff(s, "/seal", refusalNote{reason: "session"}, 404, unitCaller(), nil, time.Now())
		j.round()
	}
	refuse()
	before, err := os.ReadFile(path)
	if err != nil || len(before) == 0 {
		t.Fatalf("the first entry: %d bytes, %v", len(before), err)
	}

	failed := errors.New("a sync that fails")
	syncs := 0
	refusalSync = func(file *os.File) error {
		syncs++
		if syncs == 1 {
			return failed
		}
		return file.Sync()
	}
	t.Cleanup(func() { refusalSync = func(file *os.File) error { return file.Sync() } })
	refuse()
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatalf("after a failed sync the file is %d bytes; want %d", len(after), len(before))
	}
	if n := s.tally[dropWriteFailed].Load(); n != 1 || s.lost {
		t.Fatalf("a failed sync: %d write-failed, lost %v; want 1, not lost", n, s.lost)
	}

	refuse()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := h.g.provenanceKeys()
	if f, n, torn := judgeRefusalJournal(data, s.name, keys); f != nil || n != 2 || torn != 0 {
		t.Fatalf("the journal after the cut back: %v, %d entries, torn %d; want 2", f, n, torn)
	}

	// the line's sync fails, and the cut back's sync fails too
	syncs = 0
	refusalSync = func(*os.File) error { syncs++; return failed }
	refuse()
	refusalSync = func(file *os.File) error { return file.Sync() }
	if !s.lost || syncs != 2 {
		t.Fatalf("a cut back that cannot be synced: lost %v after %d syncs; want lost after 2", s.lost, syncs)
	}
	held, _ := os.ReadFile(path)
	refuse()
	if again, _ := os.ReadFile(path); string(again) != string(held) {
		t.Fatal("an entry was written after a cut back that was not synced")
	}
	if n := s.tally[dropWriteFailed].Load(); n != 3 {
		t.Fatalf("%d write-failed; want 3", n)
	}
}
