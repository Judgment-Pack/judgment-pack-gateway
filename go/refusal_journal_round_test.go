package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The filesystem kind's writer holds a journal's file for one append round
// alone (ADR-0059 §8, as built 2026-11-24): each entry opens, locks, checks,
// appends, syncs and closes. Only a journal the writer has not found is
// made; once found, a missing file is a removal, and nothing is made again.

func roundEntry(t *testing.T, j *refusalJournals, s *refusalScope) {
	t.Helper()
	j.handOff(s, "/seal", refusalNote{reason: "session"}, 404, unitCaller(), nil, time.Now())
	j.round()
}

// roundLines are the journal's lines, each without its line end, and each
// line's ordinal and previous.
func roundLines(t *testing.T, path string) (lines [][]byte, ordinals []int64, previous []string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range bytes.SplitAfter(data, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var m struct {
			Ordinal  int64  `json:"ordinal"`
			Previous string `json:"previous"`
		}
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		lines = append(lines, bytes.TrimSuffix(line, []byte("\n")))
		ordinals, previous = append(ordinals, m.Ordinal), append(previous, m.Previous)
	}
	return lines, ordinals, previous
}

func roundPaths(h *limitsHarness, s *refusalScope) (journal, key string) {
	dir := filepath.Join(h.g.storeRoot, journalsDir)
	return filepath.Join(dir, s.name+".jsonl"), filepath.Join(dir, s.name+".key")
}

// The scope's first entry makes the journal: under the key drawn at this
// start, and under the key an earlier start drew for a journal that took no
// entry; a writer that has not yet found the journal opens the one another
// made, and chains onto it.
func TestRefusalJournalFirstWriteMakesTheJournal(t *testing.T) {
	h, j, s := refusalUnit(t, refusalDefaultCap)
	journal, _ := roundPaths(h, s)
	if _, err := os.Lstat(journal); !errors.Is(err, os.ErrNotExist) || s.found {
		t.Fatalf("a journal before the first entry: %v, found %v", err, s.found)
	}
	again, err := newRefusalJournals(&refusalJournalConfig{maxBytes: refusalDefaultCap}, map[string]bool{callerScopeA: true}, refusalFS{root: h.g.storeRoot}, h.g.store.signing.key, h.g.provenanceKeys, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	later := again.scopes[callerScopeA]
	if !bytes.Equal(later.secret, s.secret) || later.found {
		t.Fatalf("the later start: the key is another (%v), or the journal was found (%v)", !bytes.Equal(later.secret, s.secret), later.found)
	}
	roundEntry(t, again, later)
	roundEntry(t, j, s)
	if a, b := later.tally[dropWriteFailed].Load(), s.tally[dropWriteFailed].Load(); a != 0 || b != 0 || later.lost || s.lost {
		t.Fatalf("write-failed %d and %d, lost %v and %v", a, b, later.lost, s.lost)
	}
	lines, ordinals, previous := roundLines(t, journal)
	if len(lines) != 2 || ordinals[0] != 0 || ordinals[1] != 1 || previous[1] != journalDigest(lines[0]) {
		t.Fatalf("the journal: %d lines, ordinals %v", len(lines), ordinals)
	}
}

// remove-scope while the gateway serves, whole or cut off between the
// journal and its key: the next entries are dropped and counted, the scope
// is lost, and no journal is made again (ADR-0059 §8).
func TestRefusalJournalRemovalMidServeMakesNoJournal(t *testing.T) {
	if !journalFilesLock {
		t.Skip("without flock, remove-scope runs with the gateway stopped")
	}
	for _, c := range []struct {
		name    string
		keyGone bool
		atStart bool // the journal was there at start, and went before this start's first entry
	}{
		{"journal and key gone", true, false},
		{"journal gone, key kept", false, false},
		{"there at start, journal gone before the first entry, key kept", false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, j, s := refusalUnit(t, refusalDefaultCap)
			roundEntry(t, j, s)
			if n := s.tally[dropWriteFailed].Load(); n != 0 {
				t.Fatalf("the first entry: %d write-failed", n)
			}
			if c.atStart {
				again, err := newRefusalJournals(&refusalJournalConfig{maxBytes: refusalDefaultCap}, map[string]bool{callerScopeA: true}, refusalFS{root: h.g.storeRoot}, h.g.store.signing.key, h.g.provenanceKeys, io.Discard)
				if err != nil {
					t.Fatal(err)
				}
				j, s = again, again.scopes[callerScopeA]
				if !s.found {
					t.Fatal("the journal there at start was not found")
				}
			}
			journal, key := roundPaths(h, s)
			if err := os.Remove(journal); err != nil {
				t.Fatal(err)
			}
			if c.keyGone {
				if err := os.Remove(key); err != nil {
					t.Fatal(err)
				}
			}
			roundEntry(t, j, s)
			roundEntry(t, j, s)
			if n := s.tally[dropWriteFailed].Load(); n != 2 || !s.lost {
				t.Fatalf("after the removal: %d write-failed, want 2; lost %v", n, s.lost)
			}
			if _, err := os.Lstat(journal); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the journal was made again: %v", err)
			}
			if _, err := os.Lstat(key); errors.Is(err, os.ErrNotExist) != c.keyGone {
				t.Fatalf("the key: %v", err)
			}
		})
	}
}

// A key that cannot be read for a while, and is neither gone nor another,
// drops that entry alone and counts it; the scope is not lost, and the next
// entry is written.
func TestRefusalJournalTransientKeyReadDropsOneEntry(t *testing.T) {
	h, j, s := refusalUnit(t, refusalDefaultCap)
	roundEntry(t, j, s)
	journal, key := roundPaths(h, s)
	aside := key + ".aside"
	if err := os.Rename(key, aside); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(key, 0o700); err != nil {
		t.Fatal(err)
	}
	roundEntry(t, j, s)
	if n := s.tally[dropWriteFailed].Load(); n != 1 || s.lost {
		t.Fatalf("an unreadable key: %d write-failed, want 1; lost %v", n, s.lost)
	}
	if lines, _, _ := roundLines(t, journal); len(lines) != 1 {
		t.Fatalf("an entry was written under an unreadable key: %d lines", len(lines))
	}
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(aside, key); err != nil {
		t.Fatal(err)
	}
	roundEntry(t, j, s)
	if n := s.tally[dropWriteFailed].Load(); n != 1 || s.lost {
		t.Fatalf("the key read again: %d write-failed, want 1; lost %v", n, s.lost)
	}
	if lines, ordinals, previous := roundLines(t, journal); len(lines) != 2 || ordinals[1] != 1 || previous[1] != journalDigest(lines[0]) {
		t.Fatalf("the entry after the key came back: %d lines, ordinals %v", len(lines), ordinals)
	}
}

// A journal file replaced under the same key, by another of the same
// length, or cut back in place, is read again before the next entry, which
// chains onto what the file holds and not onto the end the writer held.
func TestRefusalJournalReloadsAReplacedFile(t *testing.T) {
	h, j, s := refusalUnit(t, refusalDefaultCap)
	roundEntry(t, j, s)
	journal, _ := roundPaths(h, s)
	data, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	at := bytes.LastIndex(data, []byte(`"signature":"`)) + len(`"signature":"`)
	if data[at] == '0' {
		data[at] = '1'
	} else {
		data[at] = '0'
	}
	replaced := filepath.Join(filepath.Dir(journal), "replacement")
	if err := os.WriteFile(replaced, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replaced, journal); err != nil {
		t.Fatal(err)
	}
	roundEntry(t, j, s)
	lines, ordinals, previous := roundLines(t, journal)
	if len(lines) != 2 || ordinals[1] != 1 || previous[1] != journalDigest(lines[0]) || !bytes.Equal(append(bytes.Clone(lines[0]), '\n'), data) {
		t.Fatalf("after a replacement of the same length: %d lines, ordinals %v", len(lines), ordinals)
	}
	if err := os.Truncate(journal, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	roundEntry(t, j, s)
	lines, ordinals, previous = roundLines(t, journal)
	if len(lines) != 2 || ordinals[1] != 1 || previous[1] != journalDigest(lines[0]) {
		t.Fatalf("after a cut in place: %d lines, ordinals %v", len(lines), ordinals)
	}
	if n := s.tally[dropWriteFailed].Load(); n != 0 || s.lost {
		t.Fatalf("%d write-failed, lost %v", n, s.lost)
	}
}
