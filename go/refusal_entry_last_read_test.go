package main

// The filesystem source's one read per pass (ADR-0059 section 9, as built
// 2026-11-24): a pass reads the entry at the cursor and the batch after it
// in one read, which starts at the line the last read ended on where that
// line is still there, and reads the file whole where it was replaced or
// cut back.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// scanCounter counts the bytes read through it.
type scanCounter struct {
	r io.Reader
	n *atomic.Int64
}

func (c scanCounter) Read(p []byte) (int, error) {
	k, err := c.r.Read(p)
	c.n.Add(int64(k))
	return k, err
}

// scanned counts the bytes entriesAfter reads past the line it starts at.
func scanned(t *testing.T) *atomic.Int64 {
	t.Helper()
	n := &atomic.Int64{}
	refusalScanReader = func(_ string, r io.Reader) io.Reader { return scanCounter{r, n} }
	t.Cleanup(func() { refusalScanReader = nil })
	return n
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

// A pass over a journal that has not changed since the last pass reads the
// one line it checks, the cursor's, and no entry byte past it; a pass after
// an append reads that line alone.
func TestAPassOverAnUnchangedJournalReadsNoEntryBytes(t *testing.T) {
	h := limitsSetup(t, refusalLimits())
	j := sourceJournals(t, h, refusalFS{root: h.g.storeRoot}, callerScopeA)
	name := refusalJournalName(callerScopeA)
	appendRefusals(t, j, callerScopeA, 3)
	source := newFSRefusalEntries(h.g.storeRoot, refusalJournalNames(j))
	sink, url := ordinalSink(t, func(int64) bool { return true })
	owner := ownerFor(t, url, source, nil)
	read := scanned(t)

	size := fileSize(t, source.path(name))
	if err := owner.forwardJournal(context.Background(), name); err != nil {
		t.Fatal(err)
	}
	if got := entryOrdinalsSince(t, sink, 0); fmt.Sprint(got) != "[0 1 2]" || read.Load() != size {
		t.Fatalf("the first pass delivered %v and read %d bytes; want [0 1 2] and the file's %d", got, read.Load(), size)
	}
	for pass := 0; pass < 2; pass++ {
		read.Store(0)
		before, _ := sink.snapshot()
		if err := owner.forwardJournal(context.Background(), name); err != nil {
			t.Fatal(err)
		}
		if got, _ := sink.snapshot(); len(got) != len(before) || read.Load() != 0 {
			t.Fatalf("a pass over an unchanged journal delivered %d and read %d bytes past its cursor's line", len(got)-len(before), read.Load())
		}
	}
	appendRefusals(t, j, callerScopeA, 1)
	grown := fileSize(t, source.path(name))
	read.Store(0)
	before, _ := sink.snapshot()
	if err := owner.forwardJournal(context.Background(), name); err != nil {
		t.Fatal(err)
	}
	if got := entryOrdinalsSince(t, sink, len(before)); fmt.Sprint(got) != "[3]" || read.Load() != grown-size {
		t.Fatalf("a pass after one append delivered %v and read %d bytes; want [3] and the new line's %d", got, read.Load(), grown-size)
	}
	if at, err := source.cursors().read(name); err != nil || at.ordinal != 3 {
		t.Fatalf("the cursor: %+v %v; want 3", at, err)
	}
}

// A journal's file replaced, cut back, or removed and begun again is read
// whole, and forwarding holds: a copy put in its place forwards nothing
// again; a file cut back, or rewritten in place, stops at the diverged
// cursor; and a new journal after remove-scope is forwarded from its first
// entry. A last read used without its file's identity fails the copy; one
// used without its line checked fails the file rewritten in place.
func TestAReplacedOrCutBackJournalFileIsReadWhole(t *testing.T) {
	h := limitsSetup(t, refusalLimits())
	j := sourceJournals(t, h, refusalFS{root: h.g.storeRoot}, callerScopeA)
	name := refusalJournalName(callerScopeA)
	appendRefusals(t, j, callerScopeA, 3)
	source := newFSRefusalEntries(h.g.storeRoot, refusalJournalNames(j))
	sink, url := ordinalSink(t, func(int64) bool { return true })
	owner := ownerFor(t, url, source, nil)
	read := scanned(t)
	path := source.path(name)
	if err := owner.forwardJournal(context.Background(), name); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(data, []byte{'\n'})
	if len(lines) != 4 || len(lines[3]) != 0 {
		t.Fatalf("the journal holds %d lines; want 3", len(lines)-1)
	}
	pass := func(what string, want error, whole int64) {
		t.Helper()
		read.Store(0)
		before, _ := sink.snapshot()
		if err := owner.forwardJournal(context.Background(), name); !errors.Is(err, want) && (want != nil || err != nil) {
			t.Fatalf("%s: %v; want %v", what, err, want)
		}
		if got, _ := sink.snapshot(); len(got) != len(before) {
			t.Fatalf("%s: %d entries forwarded", what, len(got)-len(before))
		}
		if read.Load() != whole {
			t.Fatalf("%s: read %d bytes; want the file whole, %d", what, read.Load(), whole)
		}
	}

	// another file with the same bytes, renamed into place
	staged := filepath.Join(filepath.Dir(path), "staged-copy")
	if err := os.WriteFile(staged, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(staged, path); err != nil {
		t.Fatal(err)
	}
	pass("a copy in its place", nil, int64(len(data)))

	// the same file rewritten in place, as long, its last two lines swapped
	rewritten := append(append(append([]byte(nil), lines[0]...), lines[2]...), lines[1]...)
	if err := os.WriteFile(path, rewritten, 0o600); err != nil {
		t.Fatal(err)
	}
	pass("the file rewritten in place", errCursorDiverged, int64(len(rewritten)))

	// cut back to its first line
	if err := os.Truncate(path, int64(len(lines[0]))); err != nil {
		t.Fatal(err)
	}
	pass("the file cut back", errCursorDiverged, int64(len(lines[0])))

	// remove-scope takes the journal, its key and its cursor; the next
	// start begins a new one
	for _, suffix := range []string{".jsonl", ".key", refusalForwardedSuffix} {
		if err := os.Remove(filepath.Join(h.g.storeRoot, journalsDir, name+suffix)); err != nil {
			t.Fatal(err)
		}
	}
	pass("no journal", nil, 0)
	again := sourceJournals(t, h, refusalFS{root: h.g.storeRoot}, callerScopeA)
	appendRefusals(t, again, callerScopeA, 2)
	read.Store(0)
	before, _ := sink.snapshot()
	if err := owner.forwardJournal(context.Background(), name); err != nil {
		t.Fatal(err)
	}
	if got := entryOrdinalsSince(t, sink, len(before)); fmt.Sprint(got) != "[0 1]" || read.Load() != fileSize(t, path) {
		t.Fatalf("the new journal: delivered %v and read %d bytes; want [0 1] and the file whole", got, read.Load())
	}
	entries, _ := source.entriesAfter(name, 0, 1)
	held, _ := owner.forwarder.heldRefusalEntry(name, entries[0].line)
	if at, err := source.cursors().read(name); err != nil || at.ordinal != 1 || at.digest != held.digest {
		t.Fatalf("the new journal's cursor: %+v %v", at, err)
	}
}

// The last read is one line for each configured journal, the last its read
// ended on, whatever the journal's length, and it is dropped once the file
// is gone.
func TestTheLastReadHoldsOneLineForEachJournalAndDropsAGoneFile(t *testing.T) {
	h := limitsSetup(t, refusalLimits())
	j := sourceJournals(t, h, refusalFS{root: h.g.storeRoot}, callerScopeA, callerScopeB)
	a, b := refusalJournalName(callerScopeA), refusalJournalName(callerScopeB)
	appendRefusals(t, j, callerScopeB, 2)
	source := newFSRefusalEntries(h.g.storeRoot, refusalJournalNames(j))
	for round := 0; round < 4; round++ {
		appendRefusals(t, j, callerScopeA, 3)
		for _, name := range []string{a, b} {
			if _, err := source.entriesAfter(name, -1, refusalForwardBatch); err != nil {
				t.Fatal(err)
			}
		}
	}
	lastLine := func(name string) []byte {
		data, err := os.ReadFile(source.path(name))
		if err != nil {
			t.Fatal(err)
		}
		lines := bytes.SplitAfter(data, []byte{'\n'})
		return lines[len(lines)-2]
	}
	source.lastRead.mu.Lock()
	held := len(source.lastRead.lines)
	atA, atB := source.lastRead.lines[a], source.lastRead.lines[b]
	source.lastRead.mu.Unlock()
	if held != 2 || atA.ordinal != 11 || !bytes.Equal(atA.line, lastLine(a)) || atB.ordinal != 1 || !bytes.Equal(atB.line, lastLine(b)) {
		t.Fatalf("the last read holds %d journals, at %d and %d; want 2, each at its last line alone", held, atA.ordinal, atB.ordinal)
	}
	if _, err := source.entriesAfter("refusal-zzzzzzzzzzzzzzzzzzzzzzzz", -1, 1); err == nil {
		t.Fatal("a journal not configured was read")
	}
	if err := os.Remove(source.path(a)); err != nil {
		t.Fatal(err)
	}
	if entries, err := source.entriesAfter(a, -1, 1); err != nil || len(entries) != 0 {
		t.Fatalf("a journal with no file: %d entries, %v", len(entries), err)
	}
	source.lastRead.mu.Lock()
	_, keptA := source.lastRead.lines[a]
	held = len(source.lastRead.lines)
	source.lastRead.mu.Unlock()
	if keptA || held != 1 {
		t.Fatalf("the last read of a journal whose file is gone was kept (%d held)", held)
	}
}
