package main

// The PostgreSQL forwarding cursor on the source's own connection (ADR-0059
// section 9, as built 2026-11-24): a pass reads the cursor and the entries,
// and moves the cursor, without a slot of the pool; no transaction spans a
// delivery; and remove-scope cannot come between the journal's lock and the
// cursor's put.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// pgSourceKind is a kind of no scope over db with a pool of one connection,
// whose transactions end where idle in one longer than idle.
func pgSourceKind(t *testing.T, db *pgTestDB, operation, idle time.Duration) *pgKind {
	t.Helper()
	kind := &pgKind{pool: newPgPool(db.runtime, 1), row: pgNoScope, operation: operation, clock: time.Now, idle: idle}
	t.Cleanup(kind.close)
	return kind
}

// pgCursorDocument is the journal's cursor document as the pool of another
// kind reads it: its revision, or noRevision where there is none.
func pgCursorDocument(t *testing.T, db *pgTestDB, journal string) (forwardingCursor, string) {
	t.Helper()
	cursor, revision, err := pgForwardingCursors{db.open(t, nil).ofNoScope().documents()}.load(journal)
	if err != nil {
		t.Fatal(err)
	}
	return cursor, revision
}

// A forwarding pass takes no slot of the pool: with the pool's one
// connection held by a request, it still reads the cursor and the entries,
// delivers them and moves the cursor. The advance put back on the pool
// fails it.
func TestAPostgresForwardingPassTakesNoPoolConnection(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	h := limitsSetup(t, refusalLimits())
	j := sourceJournals(t, h, newRefusalPG(db.open(t, nil)), callerScopeA)
	name := refusalJournalName(callerScopeA)
	appendRefusals(t, j, callerScopeA, 3)
	// a step that waited for the pool would fail within 2 s
	kind := pgSourceKind(t, db, 2*time.Second, pgIdleInTransaction)
	request, err := kind.pool.acquire(time.Now().Add(5 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { kind.pool.release(request) })
	source := newPGRefusalEntries(kind, refusalJournalNames(j))
	t.Cleanup(source.close)
	sink, url := ordinalSink(t, func(int64) bool { return true })
	owner := ownerFor(t, url, source, nil)

	if err := owner.forwardJournal(context.Background(), name); err != nil {
		t.Fatalf("a pass with the pool held: %v", err)
	}
	if got := entryOrdinalsSince(t, sink, 0); fmt.Sprint(got) != "[0 1 2]" {
		t.Fatalf("delivered %v; want [0 1 2]", got)
	}
	if at, _ := pgCursorDocument(t, db, name); at.ordinal != 2 {
		t.Fatalf("the cursor is at %d; want 2", at.ordinal)
	}
	appendRefusals(t, j, callerScopeA, 1)
	if err := owner.forwardJournal(context.Background(), name); err != nil {
		t.Fatalf("a pass from the cursor with the pool held: %v", err)
	}
	if at, _ := pgCursorDocument(t, db, name); at.ordinal != 3 {
		t.Fatalf("the cursor is at %d; want 3", at.ordinal)
	}
}

// A sink slower than the idle bound of a transaction: no transaction is
// open across a delivery, so none is ended, the cursor moves once, on the
// connection the pass began on, and nothing is said on stderr. The idle
// bound is the kind's idle (idle_in_transaction_session_timeout, set for
// each transaction), here 300 ms, and each delivery takes 900 ms. A delivery
// moved inside locked fails it.
func TestAPostgresSlowSinkMovesTheCursorOnceAndEndsNoTransaction(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	h := limitsSetup(t, refusalLimits())
	j := sourceJournals(t, h, newRefusalPG(db.open(t, nil)), callerScopeA)
	name := refusalJournalName(callerScopeA)
	appendRefusals(t, j, callerScopeA, 2)
	kind := pgSourceKind(t, db, pgDefaultOperation, 300*time.Millisecond)
	source := newPGRefusalEntries(kind, refusalJournalNames(j))
	t.Cleanup(source.close)
	sink, url := ordinalSink(t, func(int64) bool { time.Sleep(900 * time.Millisecond); return true })
	owner := ownerFor(t, url, source, nil)
	owner.forwarder.attemptTimeout = 10 * time.Second
	var said strings.Builder
	owner.stderr = &said

	if err := owner.forwardJournal(context.Background(), name); err != nil {
		t.Fatalf("a pass past the idle bound: %v", err)
	}
	if got := entryOrdinalsSince(t, sink, 0); fmt.Sprint(got) != "[0 1]" {
		t.Fatalf("delivered %v; want each entry once", got)
	}
	at, revision := pgCursorDocument(t, db, name)
	if at.ordinal != 1 || revision == noRevision {
		t.Fatalf("the cursor is at %d; want 1", at.ordinal)
	}
	own := source.own
	if own == nil || own.broken || own.status != 'I' {
		t.Fatal("the source's connection was ended or left in a transaction")
	}
	before, _ := sink.snapshot()
	owner.forwardAll(context.Background())
	if got, _ := sink.snapshot(); len(got) != len(before) {
		t.Fatalf("the next pass delivered %d more", len(got)-len(before))
	}
	if again, now := pgCursorDocument(t, db, name); again != at || now != revision {
		t.Fatalf("the cursor moved again: %+v", again)
	}
	if source.own != own {
		t.Fatal("the source opened its connection again: a transaction of it was ended")
	}
	if said.Len() != 0 {
		t.Fatalf("said on stderr: %q", said.String())
	}
}

// pgRemoveJournalAsOwner removes the scope's refusal journal, its key and
// its cursor, in the owner's transaction, as gateway store remove-scope
// opens it.
func pgRemoveJournalAsOwner(db *pgTestDB, scope string) error {
	c, err := pgConnect(db.migrator, time.Now().Add(time.Minute))
	if err != nil {
		return err
	}
	defer c.close()
	if _, err := c.exec("BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE"); err != nil {
		return err
	}
	if _, err := c.exec(`SELECT pg_catalog.set_config('role', $1, true), pg_catalog.set_config('search_path', 'pg_catalog', true),
		pg_catalog.set_config('gateway.scope', $2, true)`, db.roles.owner, pgNoScope); err != nil {
		return err
	}
	if _, err := pgRemoveRefusalJournal(pgTx{c}, scope, true); err != nil {
		return err
	}
	_, err = c.exec("COMMIT")
	return err
}

// The review's scenario: remove-scope of the journal's scope begins once
// the owner holds the journal's lock and has found the entry, and the pool
// is saturated past the idle bound. The cursor's put is a statement of the
// lock's transaction, so remove-scope waits for it and then takes the
// journal and the cursor: none is left. A put on the pool waited past the
// idle bound, which ended the session and let the lock go, and then made
// the cursor again, naming an entry no journal holds.
func TestAPostgresRemoveScopeCannotComeBetweenTheLockAndTheCursorsPut(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	h := limitsSetup(t, refusalLimits())
	j := sourceJournals(t, h, newRefusalPG(db.open(t, nil)), callerScopeA)
	name := refusalJournalName(callerScopeA)
	appendRefusals(t, j, callerScopeA, 2)
	// the idle bound is longer than the wait below for remove-scope to
	// queue, and shorter than a put's wait for the pool
	kind := pgSourceKind(t, db, 10*time.Second, 2*time.Second)
	source := newPGRefusalEntries(kind, refusalJournalNames(j))
	t.Cleanup(source.close)
	_, url := ordinalSink(t, func(int64) bool { return true })
	owner := ownerFor(t, url, source, nil)
	watch := db.open(t, nil)

	removed := make(chan error, 1)
	var waiting atomic.Bool
	var once sync.Once
	refusalCursorLockHeld = func(string) {
		once.Do(func() {
			// a request holds the pool's one connection until remove-scope ends
			request, err := kind.pool.acquire(time.Now().Add(5 * time.Second))
			if err != nil {
				removed <- err
				return
			}
			done := make(chan error, 1)
			go func() { done <- pgRemoveJournalAsOwner(db, callerScopeA) }()
			go func() { err := <-done; kind.pool.release(request); removed <- err }()
			// remove-scope waits for the journal's advisory lock
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
				_ = watch.transact(pgRead, func(tx pgTx) error {
					rows, err := tx.exec(`SELECT 1 FROM pg_catalog.pg_locks WHERE locktype = 'advisory' AND NOT granted`)
					waiting.Store(err == nil && len(rows.rows) > 0)
					return err
				})
				if waiting.Load() {
					return
				}
			}
		})
	}
	t.Cleanup(func() { refusalCursorLockHeld = nil })

	passErr := owner.forwardJournal(context.Background(), name)
	refusalCursorLockHeld = nil
	select {
	case err := <-removed:
		if err != nil {
			t.Fatalf("remove-scope: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("remove-scope did not end")
	}
	if !waiting.Load() {
		t.Fatal("remove-scope did not wait for the journal's lock")
	}
	if at, revision := pgCursorDocument(t, db, name); revision != noRevision {
		t.Fatalf("a cursor at %d is left after remove-scope took the journal (the pass: %v)", at.ordinal, passErr)
	}
	if passErr != nil {
		t.Fatalf("the pass: %v", passErr)
	}
	if entries, err := source.entriesAfter(name, -1, 4); err != nil || len(entries) != 0 {
		t.Fatalf("the journal after remove-scope: %d entries, %v", len(entries), err)
	}
}
