package main

// The seam for refusal entries, the forwarding owner and its cursor
// (ADR-0059 section 9, conditions C5 and C11), against a stand-in journal:
// entries forwarded oldest first from the cursor, the cursor moved under the
// journal's lock by a monotone compare-and-set on both kinds, and a sink that
// declines refusal entries given no forwarding and no cursor.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"
)

const standInJournal = "refusal-abcdefghijklmnopqrstuvwx"

// standInEntries is a refusal journal held in memory, with its lock.
type standInEntries struct {
	mu    sync.Mutex
	lines map[string][][]byte
	held  bool
	locks int
}

func (s *standInEntries) journals() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var names []string
	for name := range s.lines {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func (s *standInEntries) entriesAfter(journal string, ordinal int64, limit int) ([]refusalEntryLine, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []refusalEntryLine
	for i := ordinal + 1; i < int64(len(s.lines[journal])) && len(out) < limit; i++ {
		out = append(out, refusalEntryLine{ordinal: i, line: s.lines[journal][i]})
	}
	return out, nil
}

func (s *standInEntries) locked(_ string, fn func() error) error {
	s.mu.Lock()
	s.locks++
	s.held = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.held = false; s.mu.Unlock() }()
	return fn()
}

// lockChecked refuses a cursor moved outside the journal's lock.
type lockChecked struct {
	forwardingCursors
	source *standInEntries
}

func (c lockChecked) advance(journal string, from int64, to forwardingCursor) (bool, error) {
	c.source.mu.Lock()
	held := c.source.held
	c.source.mu.Unlock()
	if !held {
		return false, errors.New("the cursor was moved outside the journal's lock")
	}
	return c.forwardingCursors.advance(journal, from, to)
}

func standInJournalOf(n int) *standInEntries {
	s := &standInEntries{lines: map[string][][]byte{}}
	for i := 0; i < n; i++ {
		s.lines[standInJournal] = append(s.lines[standInJournal], []byte(fmt.Sprintf(`{"body":{"kind":"refusal","n":%d},"ordinal":%d}`, i, i)))
	}
	return s
}

// entrySink acknowledges each refusal entry by its digest, except those
// refuse names by n, and counts each entry it is sent.
func entrySink(t *testing.T) (*standInSink, string, func(refuse func(n int) bool), func(n int) int) {
	t.Helper()
	sink, server := newStandInSink(t)
	answer := func(refuse func(n int) bool) {
		sink.setAnswer(func(k int, _ string, w http.ResponseWriter, _ *http.Request) {
			got, _ := sink.snapshot()
			var d struct {
				Kind, Digest, Journal string
				Entry                 struct{ Body struct{ N int } }
			}
			_ = json.Unmarshal(got[k], &d)
			if d.Kind != sinkKindRefusalEntry || d.Journal != standInJournal || refuse != nil && refuse(d.Entry.Body.N) {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = io.WriteString(w, `{"acknowledged":"`+d.Digest+`"}`)
		})
	}
	sent := func(n int) int {
		got, _ := sink.snapshot()
		count := 0
		for _, body := range got {
			var d struct {
				Entry struct{ Body struct{ N int } }
			}
			if json.Unmarshal(body, &d) == nil && d.Entry.Body.N == n {
				count++
			}
		}
		return count
	}
	answer(nil)
	return sink, server.URL, answer, sent
}

func ownerFor(t *testing.T, url string, source refusalEntrySource, cursors forwardingCursors) *refusalEntryForwarding {
	t.Helper()
	spec, err := parseSinkMember(t, `{"url":"`+url+`","deliveryVersion":"3"}`, sinkDeliveryV3Version)
	if err != nil {
		t.Fatal(err)
	}
	owner := newRefusalEntryForwarding(spec, source, cursors)
	if owner == nil {
		t.Fatal("no forwarding for a sink on 3 that takes refusal entries")
	}
	owner.forwarder.attemptTimeout = 300 * time.Millisecond
	owner.forwarder.backoff = []time.Duration{time.Millisecond, time.Millisecond}
	return owner
}

func TestRefusalEntriesAreForwardedFromTheCursorAndItMovesForwardAlone(t *testing.T) {
	root := t.TempDir()
	source := standInJournalOf(3)
	cursors := fsForwardingCursors{root: root, mu: &sync.Mutex{}}
	_, url, answer, sent := entrySink(t)
	owner := ownerFor(t, url, source, lockChecked{cursors, source})
	answer(func(n int) bool { return n == 2 })
	if err := owner.forwardJournal(context.Background(), standInJournal); err != nil {
		t.Fatal(err)
	}
	first, err := cursors.read(standInJournal)
	entry1, _ := owner.forwarder.heldRefusalEntry(standInJournal, source.lines[standInJournal][1])
	if err != nil || first.ordinal != 1 || first.digest != entry1.digest {
		t.Fatalf("the cursor after the first pass: %+v %v; want ordinal 1", first, err)
	}
	if data, err := os.ReadFile(filepath.Join(root, "journals", standInJournal+".forwarded")); err != nil || string(data) != string(encodeForwardingCursor(standInJournal, first))+"\n" {
		t.Fatalf("the cursor's file: %q %v", data, err)
	}
	answer(nil)
	if err := owner.forwardJournal(context.Background(), standInJournal); err != nil {
		t.Fatal(err)
	}
	if last, err := cursors.read(standInJournal); err != nil || last.ordinal != 2 {
		t.Fatalf("the cursor after the second pass: %+v %v", last, err)
	}
	// resumed from the cursor: the entries acknowledged are not sent again
	if sent(0) != 1 || sent(1) != 1 || sent(2) < 2 {
		t.Fatalf("sent %d, %d and %d times", sent(0), sent(1), sent(2))
	}
	if source.locks != 2 {
		t.Fatalf("the cursor moved under the lock %d times; want 2", source.locks)
	}
	// the compare-and-set: a stale read does not move it, nor does a lesser
	// or an equal ordinal
	if moved, err := cursors.advance(standInJournal, 1, forwardingCursor{3, first.digest}); moved || err != nil {
		t.Fatalf("a stale compare-and-set: %v %v", moved, err)
	}
	for _, to := range []int64{2, 1} {
		if moved, err := cursors.advance(standInJournal, 2, forwardingCursor{to, first.digest}); moved || !errors.Is(err, errCursorBackwards) {
			t.Fatalf("a cursor moved to %d: %v %v", to, moved, err)
		}
	}
	if now, _ := cursors.read(standInJournal); now.ordinal != 2 {
		t.Fatalf("the cursor moved to %d", now.ordinal)
	}
	// a cursor's file of another journal is no cursor, never one at -1
	other := "refusal-zzzzzzzzzzzzzzzzzzzzzzzz"
	data, _ := os.ReadFile(cursors.path(standInJournal))
	if err := os.WriteFile(cursors.path(other), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cursors.read(other); err == nil {
		t.Fatal("another journal's cursor was read")
	}
	if _, err := cursors.read("../receipts"); err == nil {
		t.Fatal("a name outside the journal rule was read")
	}
}

// A sink that declines refusal entries, or one not on 3, is given no
// forwarding and no cursor; the seam as this change leaves it names no
// journal.
func TestASinkThatDeclinesRefusalEntriesIsGivenNoForwarding(t *testing.T) {
	for _, text := range []string{
		`{"url":"https://sink.example/r","deliveryVersion":"3","refusalEntries":false}`,
		`{"url":"https://sink.example/r","seals":true}`,
		`{"url":"https://sink.example/r"}`,
	} {
		spec, err := parseSinkMember(t, text, sinkDeliveryV3Version)
		if err != nil {
			t.Fatal(err)
		}
		root := t.TempDir()
		owner := newRefusalEntryForwarding(spec, standInJournalOf(2), fsForwardingCursors{root: root, mu: &sync.Mutex{}})
		if owner != nil {
			t.Fatalf("%s: forwarded", text)
		}
		owner.forwardAll(context.Background())
		if err := owner.forwardJournal(context.Background(), standInJournal); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(root, "journals")); err == nil {
			t.Fatalf("%s: a cursor was written", text)
		}
	}
	if names, err := (noRefusalEntries{}).journals(); err != nil || len(names) != 0 {
		t.Fatalf("the seam names %v", names)
	}
	sink, url, _, _ := entrySink(t)
	root := t.TempDir()
	ownerFor(t, url, noRefusalEntries{}, fsForwardingCursors{root: root, mu: &sync.Mutex{}}).forwardAll(context.Background())
	if got, _ := sink.snapshot(); len(got) != 0 {
		t.Fatalf("the seam's journals sent %d deliveries", len(got))
	}
	if _, err := os.Stat(filepath.Join(root, "journals")); err == nil {
		t.Fatal("the seam's journals wrote a cursor")
	}
}

// On the PostgreSQL kind two instances share one cursor: the compare-and-set
// is monotone, a stale instance never moves it back, and two owners
// forwarding one journal together pass over no ordinal.
func TestAPostgresRefusalEntryCursorMovesByAMonotoneCompareAndSet(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	a := pgForwardingCursors{db.open(t, nil).ofNoScope().documents()}
	b := pgForwardingCursors{db.open(t, nil).ofNoScope().documents()}
	digest := "sha256:" + fmt.Sprintf("%064x", 1)
	if c, err := a.read(standInJournal); err != nil || c.ordinal != -1 {
		t.Fatalf("no cursor: %+v %v", c, err)
	}
	if moved, err := a.advance(standInJournal, -1, forwardingCursor{5, digest}); !moved || err != nil {
		t.Fatalf("the first move: %v %v", moved, err)
	}
	if moved, err := b.advance(standInJournal, -1, forwardingCursor{3, digest}); moved || err != nil {
		t.Fatalf("a stale instance's move: %v %v", moved, err)
	}
	if c, _ := b.read(standInJournal); c.ordinal != 5 {
		t.Fatalf("the cursor is at %d after a stale move; want 5", c.ordinal)
	}
	if moved, err := b.advance(standInJournal, 5, forwardingCursor{4, digest}); moved || !errors.Is(err, errCursorBackwards) {
		t.Fatalf("a move backwards: %v %v", moved, err)
	}
	if moved, err := b.advance(standInJournal, 5, forwardingCursor{6, digest}); !moved || err != nil {
		t.Fatalf("the second instance's move: %v %v", moved, err)
	}
	if c, _ := a.read(standInJournal); c.ordinal != 6 || c.digest != digest {
		t.Fatalf("the first instance reads %+v", c)
	}

	other := "refusal-yyyyyyyyyyyyyyyyyyyyyyyy"
	source := standInJournalOf(0)
	for i := 0; i < 12; i++ {
		source.lines[other] = append(source.lines[other], []byte(fmt.Sprintf(`{"body":{"kind":"refusal","n":%d},"ordinal":%d}`, i, i)))
	}
	sink, url, _, _ := entrySink(t)
	sink.setAnswer(func(k int, _ string, w http.ResponseWriter, _ *http.Request) {
		got, _ := sink.snapshot()
		var d struct{ Digest string }
		_ = json.Unmarshal(got[k], &d)
		_, _ = io.WriteString(w, `{"acknowledged":"`+d.Digest+`"}`)
	})
	owners := []*refusalEntryForwarding{ownerFor(t, url, source, a), ownerFor(t, url, source, b)}
	var wg sync.WaitGroup
	for _, owner := range owners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pass := 0; pass < 6; pass++ {
				_ = owner.forwardJournal(context.Background(), other)
			}
		}()
	}
	wg.Wait()
	if c, err := a.read(other); err != nil || c.ordinal != 11 {
		t.Fatalf("the shared cursor: %+v %v; want 11", c, err)
	}
	got, _ := sink.snapshot()
	seen := map[int]bool{}
	for _, body := range got {
		var d struct {
			Entry struct{ Body struct{ N int } }
		}
		_ = json.Unmarshal(body, &d)
		seen[d.Entry.Body.N] = true
	}
	for i := 0; i < 12; i++ {
		if !seen[i] {
			t.Fatalf("entry %d was passed over", i)
		}
	}
}

// A journal recreated, or cut back, under its cursor is not forwarded from
// it: the entry at the cursor is not the one the sink acknowledged there.
func TestARefusalJournalRecreatedUnderItsCursorIsNotForwarded(t *testing.T) {
	source := standInJournalOf(3)
	cursors := fsForwardingCursors{root: t.TempDir(), mu: &sync.Mutex{}}
	sink, url, _, _ := entrySink(t)
	owner := ownerFor(t, url, source, lockChecked{cursors, source})
	if err := owner.forwardJournal(context.Background(), standInJournal); err != nil {
		t.Fatal(err)
	}
	at, _ := cursors.read(standInJournal)
	for name, lines := range map[string]int{"recreated": 5, "cut back": 2} {
		source.mu.Lock()
		source.lines[standInJournal] = nil
		for i := 0; i < lines; i++ {
			source.lines[standInJournal] = append(source.lines[standInJournal], []byte(fmt.Sprintf(`{"body":{"kind":"refusal","n":%d},"ordinal":%d}`, 10+i, i)))
		}
		source.mu.Unlock()
		before, _ := sink.snapshot()
		if err := owner.forwardJournal(context.Background(), standInJournal); !errors.Is(err, errCursorDiverged) {
			t.Fatalf("%s: %v", name, err)
		}
		if got, _ := sink.snapshot(); len(got) != len(before) {
			t.Fatalf("%s: %d entries forwarded", name, len(got)-len(before))
		}
		if now, _ := cursors.read(standInJournal); now != at {
			t.Fatalf("%s: the cursor moved to %+v", name, now)
		}
	}
}
