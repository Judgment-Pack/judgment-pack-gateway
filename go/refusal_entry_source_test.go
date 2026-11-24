package main

// The refusal journal as the forwarding owner's source (ADR-0059 section 9,
// R3): entries forwarded from the real journals on both kinds, resumed from
// the cursor, one delivery in flight, the cursor moved under the journal's
// own lock alone, and no answer awaiting any of it.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// sourceJournals are the journals of the scopes given on kind's store, with
// no writer started: the test appends with appendRefusals.
func sourceJournals(t *testing.T, h *limitsHarness, store refusalStore, scopes ...string) *refusalJournals {
	t.Helper()
	keys := map[string]bool{}
	for _, scope := range scopes {
		keys[scope] = true
	}
	j, err := newRefusalJournals(&refusalJournalConfig{maxBytes: refusalDefaultCap}, keys, store, h.g.store.signing.key, h.g.provenanceKeys, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(j.store.close)
	return j
}

// appendRefusal writes one refusal entry to the scope's journal, in one
// round of the writer.
func appendRefusal(j *refusalJournals, scope string) {
	j.handOff(j.scopes[scope], "/seal", refusalNote{reason: "session"}, 404, unitCaller(), []byte(`{"session":"s-none"}`), time.Now())
	j.round()
}

// appendRefusals writes n refusal entries to the scope's journal, one round
// each, and fails the test where one was not written.
func appendRefusals(t *testing.T, j *refusalJournals, scope string, n int) {
	t.Helper()
	s := j.scopes[scope]
	for i := 0; i < n; i++ {
		appendRefusal(j, scope)
	}
	if failed := s.tally[dropWriteFailed].Load() + s.tally[dropJournalFull].Load() + s.tally[dropQueueFull].Load(); failed != 0 {
		t.Fatalf("%d records were not written", failed)
	}
}

// entryOrdinal is the ordinal of the refusal entry a "3" delivery carries,
// or -1 for a delivery of another kind.
func entryOrdinal(t *testing.T, body []byte) (int64, string) {
	t.Helper()
	var d struct {
		Kind, Digest, Journal string
		Entry                 struct{ Ordinal *int64 }
	}
	if err := json.Unmarshal(body, &d); err != nil {
		t.Errorf("a delivery that is not JSON: %v", err)
		return -1, ""
	}
	if d.Kind != sinkKindRefusalEntry {
		return -1, d.Digest
	}
	if d.Entry.Ordinal == nil || d.Journal == "" {
		t.Errorf("a refusal entry delivered without its journal or ordinal: %s", body)
		return -1, d.Digest
	}
	return *d.Entry.Ordinal, d.Digest
}

// ordinalSink acknowledges each refusal entry ack holds true for, by its
// digest, and every other delivery.
func ordinalSink(t *testing.T, ack func(ordinal int64) bool) (*standInSink, string) {
	t.Helper()
	sink, server := newStandInSink(t)
	sink.setAnswer(func(k int, _ string, w http.ResponseWriter, _ *http.Request) {
		got, _ := sink.snapshot()
		ordinal, digest := entryOrdinal(t, got[k])
		if ordinal >= 0 && !ack(ordinal) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, `{"acknowledged":"`+digest+`"}`)
	})
	return sink, server.URL
}

func entryOrdinalsSince(t *testing.T, sink *standInSink, n int) []int64 {
	t.Helper()
	got, _ := sink.snapshot()
	var out []int64
	for _, body := range got[n:] {
		if ordinal, _ := entryOrdinal(t, body); ordinal >= 0 {
			out = append(out, ordinal)
		}
	}
	return out
}

// postWithin posts as who and fails the test where no answer comes within
// the bound.
func postWithin(t *testing.T, h *limitsHarness, bound time.Duration, path, body, who string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.tokens[who])
	client := &http.Client{Transport: h.server.Client().Transport, Timeout: bound}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s was not answered within %v: %v", path, bound, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

// R3: a sink that never acknowledges refusal entries, one held in flight,
// while acquisitions are answered, their receipts acknowledged, and further
// refusals answered and journaled, none of them waiting on it. Mutant 14 (a
// refusal delivery awaited on the answer path) fails it.
func TestASinkThatNeverAcknowledgesRefusalEntriesLeavesAcquisitionsAnswered(t *testing.T) {
	h, _, _ := refusalSetup(t, refusalLimits())
	release := make(chan struct{})
	var held atomic.Int64
	sink, server := newStandInSink(t)
	t.Cleanup(func() { close(release) })
	sink.setAnswer(func(k int, _ string, w http.ResponseWriter, r *http.Request) {
		got, _ := sink.snapshot()
		ordinal, digest := entryOrdinal(t, got[k])
		if ordinal >= 0 {
			held.Add(1)
			select {
			case <-release:
			case <-r.Context().Done():
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, `{"acknowledged":"`+digest+`"}`)
	})
	h.g.forwarder = v3Forwarder(t, server.URL, "")
	for i := 0; i < 2; i++ {
		if code, _ := postWithin(t, h, 3*time.Second, "/seal", `{"session":"s-none"}`, "a"); code/100 != 4 {
			t.Fatalf("the refusal: %d", code)
		}
	}
	waitUntil(t, "the refusals to be journaled", func() bool { return len(refusalBodies(t, h.g.storeRoot, callerScopeA)) == 2 })

	owner := h.g.refusalEntryForwardingOf()
	if owner == nil {
		t.Fatal("no forwarding for a sink on 3 with the journal configured")
	}
	if _, onFS := owner.source.(fsRefusalEntries); !onFS {
		t.Fatalf("the source is %T", owner.source)
	}
	owner.forwarder.attemptTimeout = time.Minute
	h.g.refusalForwarding = owner
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go owner.run(ctx, 10*time.Millisecond)
	waitUntil(t, "a refusal entry in flight at the sink", func() bool { return held.Load() >= 1 })

	for i := 0; i < 3; i++ {
		start := time.Now()
		code, body := postWithin(t, h, 3*time.Second, "/acquire", acquireBodyFor(fmt.Sprintf("s-%d", i), "scoped-a", callerScopeA), "a")
		if code != http.StatusOK {
			t.Fatalf("acquisition %d: %d %s", i, code, body)
		}
		if took := time.Since(start); took > 2*time.Second {
			t.Fatalf("acquisition %d took %v", i, took)
		}
	}
	if code, _ := postWithin(t, h, 3*time.Second, "/seal", `{"session":"s-none"}`, "a"); code/100 != 4 {
		t.Fatalf("a refusal while an entry is held: %d", code)
	}
	waitUntil(t, "the third refusal to be journaled", func() bool { return len(refusalBodies(t, h.g.storeRoot, callerScopeA)) == 3 })
	if held.Load() != 1 {
		t.Fatalf("%d refusal entries reached the sink while one was held", held.Load())
	}
	acks := 0
	got, _ := sink.snapshot()
	for _, body := range got {
		if ordinal, _ := entryOrdinal(t, body); ordinal < 0 {
			acks++
		}
	}
	if acks != 3 {
		t.Fatalf("%d acquisition receipts reached the sink; want 3", acks)
	}
	if _, err := os.Stat(filepath.Join(h.g.storeRoot, journalsDir, refusalJournalName(callerScopeA)+refusalForwardedSuffix)); err == nil {
		t.Fatal("a cursor was written with nothing acknowledged")
	}
}

// R3: forwarding resumes from the cursor after a stop: the cursor stops
// before the first entry not acknowledged, and a new owner, as after a
// restart, sends every later entry once and none at or before the cursor.
// Mutant 15 (the cursor advanced before the acknowledgment) fails it.
func TestRefusalEntryForwardingResumesFromTheCursorAfterAStop(t *testing.T) {
	h := limitsSetup(t, refusalLimits())
	j := sourceJournals(t, h, refusalFS{root: h.g.storeRoot}, callerScopeA)
	name := refusalJournalName(callerScopeA)
	appendRefusals(t, j, callerScopeA, 6)
	source := fsRefusalEntries{root: h.g.storeRoot, names: refusalJournalNames(j)}
	var ackBelow atomic.Int64
	ackBelow.Store(3)
	sink, url := ordinalSink(t, func(ordinal int64) bool { return ordinal < ackBelow.Load() })

	first := ownerFor(t, url, source, fsForwardingCursors{root: h.g.storeRoot, mu: &sync.Mutex{}})
	if err := first.forwardJournal(context.Background(), name); err != nil {
		t.Fatal(err)
	}
	cursors := fsForwardingCursors{root: h.g.storeRoot, mu: &sync.Mutex{}}
	if at, err := cursors.read(name); err != nil || at.ordinal != 2 {
		t.Fatalf("the cursor after the first owner: %+v %v; want 2, before the entry not acknowledged", at, err)
	}
	if sent := entryOrdinalsSince(t, sink, 0); len(sent) < 4 || fmt.Sprint(sent[:3]) != "[0 1 2]" {
		t.Fatalf("the first owner sent %v", sent)
	}

	// stopped; the journal grows; the sink comes back; a new owner starts
	appendRefusals(t, j, callerScopeA, 2)
	ackBelow.Store(1 << 40)
	got, _ := sink.snapshot()
	second := ownerFor(t, url, source, cursors)
	if err := second.forwardJournal(context.Background(), name); err != nil {
		t.Fatal(err)
	}
	if sent := entryOrdinalsSince(t, sink, len(got)); fmt.Sprint(sent) != "[3 4 5 6 7]" {
		t.Fatalf("after the stop the owner sent %v; want [3 4 5 6 7]", sent)
	}
	entries, _ := source.entriesAfter(name, 6, 1)
	last, _ := second.forwarder.heldRefusalEntry(name, entries[0].line)
	if at, err := cursors.read(name); err != nil || at.ordinal != 7 || at.digest != last.digest {
		t.Fatalf("the cursor at the end: %+v %v", at, err)
	}
	for _, ordinal := range []int64{0, 1, 2} {
		n := 0
		for _, sent := range entryOrdinalsSince(t, sink, 0) {
			if sent == ordinal {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("entry %d was sent %d times", ordinal, n)
		}
	}
}

// R3: one delivery in flight gateway-wide, whatever the number of journals
// and of passes at once.
func TestOneRefusalEntryDeliveryIsInFlightGatewayWide(t *testing.T) {
	h := limitsSetup(t, refusalLimits())
	j := sourceJournals(t, h, refusalFS{root: h.g.storeRoot}, callerScopeA, callerScopeB)
	appendRefusals(t, j, callerScopeA, 3)
	appendRefusals(t, j, callerScopeB, 3)
	var now, most atomic.Int64
	sink, server := newStandInSink(t)
	sink.setAnswer(func(k int, _ string, w http.ResponseWriter, _ *http.Request) {
		n := now.Add(1)
		for m := most.Load(); n > m && !most.CompareAndSwap(m, n); m = most.Load() {
		}
		time.Sleep(30 * time.Millisecond)
		now.Add(-1)
		got, _ := sink.snapshot()
		_, digest := entryOrdinal(t, got[k])
		_, _ = io.WriteString(w, `{"acknowledged":"`+digest+`"}`)
	})
	source := fsRefusalEntries{root: h.g.storeRoot, names: refusalJournalNames(j)}
	cursors := fsForwardingCursors{root: h.g.storeRoot, mu: &sync.Mutex{}}
	owner := ownerFor(t, server.URL, source, cursors)
	var wg sync.WaitGroup
	for _, name := range source.names {
		wg.Add(2)
		go func() { defer wg.Done(); _ = owner.forwardJournal(context.Background(), name) }()
		go func() { defer wg.Done(); owner.forwardAll(context.Background()) }()
	}
	wg.Wait()
	if most.Load() != 1 {
		t.Fatalf("%d deliveries were in flight at once", most.Load())
	}
	for _, name := range source.names {
		if at, err := cursors.read(name); err != nil || at.ordinal != 2 {
			t.Fatalf("the cursor of %s: %+v %v", name, at, err)
		}
	}
}

// R3: the cursor moves under the journal file's own lock, the one each
// append round takes: an entry appended while the owner holds it waits.
// locked runs nothing where the journal no longer holds the entry the cursor
// is to name: an entry not there, or a journal with no file, as remove-scope
// leaves it. A locked that takes no lock fails it.
func TestTheRefusalCursorMovesUnderTheJournalFilesLockAlone(t *testing.T) {
	if !journalFilesLock {
		t.Skip("no flock on this platform: the cursor moves under no file lock, and remove-scope relies on the gateway being stopped, which this platform does not check (remove-scope says so on stderr)")
	}
	h := limitsSetup(t, refusalLimits())
	j := sourceJournals(t, h, refusalFS{root: h.g.storeRoot}, callerScopeA, callerScopeB)
	name := refusalJournalName(callerScopeA)
	appendRefusals(t, j, callerScopeA, 2)
	source := fsRefusalEntries{root: h.g.storeRoot, names: refusalJournalNames(j)}
	entries, err := source.entriesAfter(name, -1, 8)
	if err != nil || len(entries) != 2 || entries[1].ordinal != 1 {
		t.Fatalf("the entries: %d %v", len(entries), err)
	}
	inside, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	// the lock is let go on every way out, so a failure never holds it
	letGo := sync.OnceFunc(func() { close(release) })
	t.Cleanup(letGo)
	ran := make(chan error, 1)
	go func() {
		ran <- source.locked(name, entries[1], func() error { close(inside); <-release; return nil })
	}()
	<-inside
	go func() { appendRefusal(j, callerScopeA); close(done) }()
	select {
	case <-done:
		t.Fatal("an entry was appended while the owner held the journal's lock")
	case <-time.After(300 * time.Millisecond):
	}
	letGo()
	if err := <-ran; err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the append did not go through once the lock was let go")
	}
	if all, _ := source.entriesAfter(name, -1, 8); len(all) != 3 {
		t.Fatalf("%d entries after the lock; want 3", len(all))
	}

	runs := 0
	count := func() error { runs++; return nil }
	other := entries[1]
	other.line = append([]byte(nil), entries[0].line...)
	if err := source.locked(name, other, count); err != nil || runs != 0 {
		t.Fatalf("an entry the journal does not hold there: ran %d, %v", runs, err)
	}
	if err := source.locked(refusalJournalName(callerScopeB), refusalEntryLine{}, count); err != nil || runs != 0 {
		t.Fatalf("a journal with no file: ran %d, %v", runs, err)
	}
	if err := source.locked(name, entries[1], count); err != nil || runs != 1 {
		t.Fatalf("the entry held: ran %d, %v", runs, err)
	}
	if err := os.Remove(source.path(name)); err != nil {
		t.Fatal(err)
	}
	if err := source.locked(name, entries[1], count); err != nil || runs != 1 {
		t.Fatalf("a journal removed since the read: ran %d, %v", runs, err)
	}
	if _, err := source.entriesAfter("refusal-zzzzzzzzzzzzzzzzzzzzzzzz", -1, 1); err == nil {
		t.Fatal("a journal not configured was read")
	}
}

// R3, the PostgreSQL kind: two instances, each with its source on a
// connection of its own and its owner, forward one journal while its writer
// appends; no ordinal is passed over, and the shared cursor ends at the last
// entry. The cursor moves under the journal's advisory lock: an append
// waits while an owner holds it.
func TestTwoPostgresInstancesForwardRefusalEntriesPassingOverNone(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	h := limitsSetup(t, refusalLimits())
	j := sourceJournals(t, h, newRefusalPG(db.open(t, nil)), callerScopeA)
	name := refusalJournalName(callerScopeA)
	appendRefusals(t, j, callerScopeA, 4)
	sink, url := ordinalSink(t, func(int64) bool { return true })
	var owners []*refusalEntryForwarding
	var sources []*pgRefusalEntries
	for i := 0; i < 2; i++ {
		source := newPGRefusalEntries(db.open(t, nil), refusalJournalNames(j))
		t.Cleanup(source.close)
		sources = append(sources, source)
		owners = append(owners, ownerFor(t, url, source, pgForwardingCursors{db.open(t, nil).ofNoScope().documents()}))
	}
	var wg sync.WaitGroup
	for _, owner := range owners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pass := 0; pass < 8; pass++ {
				_ = owner.forwardJournal(context.Background(), name)
			}
		}()
	}
	appendRefusals(t, j, callerScopeA, 6)
	wg.Wait()
	for _, owner := range owners {
		if err := owner.forwardJournal(context.Background(), name); err != nil {
			t.Fatal(err)
		}
	}
	cursors := pgForwardingCursors{db.open(t, nil).ofNoScope().documents()}
	entries, err := sources[0].entriesAfter(name, 8, 4)
	if err != nil || len(entries) != 1 || entries[0].ordinal != 9 {
		t.Fatalf("the last entry: %d %v", len(entries), err)
	}
	last, _ := owners[0].forwarder.heldRefusalEntry(name, entries[0].line)
	if at, err := cursors.read(name); err != nil || at.ordinal != 9 || at.digest != last.digest {
		t.Fatalf("the shared cursor: %+v %v; want 9", at, err)
	}
	seen := map[int64]bool{}
	for _, ordinal := range entryOrdinalsSince(t, sink, 0) {
		seen[ordinal] = true
	}
	for i := int64(0); i < 10; i++ {
		if !seen[i] {
			t.Fatalf("entry %d was passed over", i)
		}
	}

	inside, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	// the lock is let go on every way out, so a failure never holds it
	letGo := sync.OnceFunc(func() { close(release) })
	t.Cleanup(letGo)
	ran := make(chan error, 1)
	go func() {
		ran <- sources[1].locked(name, entries[0], func() error { close(inside); <-release; return nil })
	}()
	select {
	case <-inside:
	case err := <-ran:
		t.Fatalf("locked ran nothing: %v", err)
	}
	go func() { appendRefusal(j, callerScopeA); close(done) }()
	select {
	case <-done:
		t.Fatal("an entry was appended while an owner held the journal's advisory lock")
	case <-time.After(400 * time.Millisecond):
	}
	letGo()
	if err := <-ran; err != nil {
		t.Fatal(err)
	}
	<-done
	runs := 0
	other := entries[0]
	other.line = []byte(`{"not":"the entry"}`)
	if err := sources[0].locked(name, other, func() error { runs++; return nil }); err != nil || runs != 0 {
		t.Fatalf("an entry the journal does not hold there: ran %d, %v", runs, err)
	}
}
