package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// remove-scope while the gateway serves: the next entry is dropped and
// counted, never appended to the unlinked file nor to a journal made anew
// without its key; a start after it makes a key and
// is not refused (ADR-0059 §8).
func TestRefusalJournalStaleWriterDropsWhatRemoveScopeTook(t *testing.T) {
	if !journalFilesLock {
		t.Skip("without flock, remove-scope runs with the gateway stopped")
	}
	h, j, s := refusalUnit(t, refusalDefaultCap)
	j.handOff(s, "/seal", refusalNote{reason: "session"}, 404, unitCaller(), nil, time.Now())
	j.round()
	if n := s.tally[dropWriteFailed].Load(); n != 0 {
		t.Fatalf("the first entry: %d write-failed", n)
	}
	r, err := holdRefusalRemoval(h.g.storeRoot, callerScopeA)
	if err != nil || len(r.data) == 0 {
		t.Fatalf("hold: %v", err)
	}
	if err := r.remove(); err != nil {
		t.Fatal(err)
	}
	r.release()
	j.handOff(s, "/seal", refusalNote{reason: "session"}, 404, unitCaller(), nil, time.Now())
	j.round()
	if n := s.tally[dropWriteFailed].Load(); n < 1 {
		t.Fatal("the entry after the removal was not counted as dropped")
	}
	dir := filepath.Join(h.g.storeRoot, journalsDir)
	for _, suffix := range []string{".jsonl", ".key"} {
		if _, err := os.Lstat(filepath.Join(dir, s.name+suffix)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s was made again: %v", suffix, err)
		}
	}
	var stderr bytes.Buffer
	again, err := newRefusalJournals(&refusalJournalConfig{maxBytes: refusalDefaultCap}, map[string]bool{callerScopeA: true}, refusalFS{root: h.g.storeRoot}, h.g.store.signing.key, h.g.provenanceKeys, &stderr)
	if err != nil || again.scopes[callerScopeA].secret == nil || strings.Contains(stderr.String(), "no key") {
		t.Fatalf("the next start: %v %q", err, stderr.String())
	}
}

// remove-scope while an instance serves, on the PostgreSQL kind: the
// writer's next entries find no key row and are dropped and counted, no
// row is written, and the next start is not refused (ADR-0059 §8).
func TestThePostgresKindDropsAStaleWritersEntriesAfterARemoval(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	h := limitsSetup(t, refusalLimits())
	cfg := &refusalJournalConfig{maxBytes: refusalDefaultCap}
	j, err := newRefusalJournals(cfg, map[string]bool{callerScopeA: true}, newRefusalPG(db.open(t, nil)), h.g.store.signing.key, h.g.provenanceKeys, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(j.store.close)
	s := j.scopes[callerScopeA]
	j.handOff(s, "/seal", refusalNote{reason: "session"}, 404, unitCaller(), nil, time.Now())
	j.round()
	if n := s.tally[dropWriteFailed].Load(); n != 0 {
		t.Fatalf("the first entry: %d write-failed", n)
	}
	c, err := pgConnect(db.migrator, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	if _, err := c.exec("BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.exec(`SELECT pg_catalog.set_config('role', $1, true), pg_catalog.set_config('search_path', 'pg_catalog', true),
		pg_catalog.set_config('gateway.scope', $2, true)`, db.roles.owner, pgNoScope); err != nil {
		t.Fatal(err)
	}
	if _, err := pgRemoveRefusalJournal(pgTx{c}, callerScopeA, true); err != nil {
		t.Fatal(err)
	}
	if _, err := c.exec("COMMIT"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		j.handOff(s, "/seal", refusalNote{reason: "session"}, 404, unitCaller(), nil, time.Now())
		j.round()
	}
	if n := s.tally[dropWriteFailed].Load(); n < 2 {
		t.Fatalf("%d of the 2 entries after the removal counted as dropped", n)
	}
	var data []byte
	if err := db.open(t, nil).transact(pgRead, func(tx pgTx) error {
		var err error
		data, err = pgJournalFile(tx, refusalJournalName(callerScopeA))
		return err
	}); err != nil || len(data) != 0 {
		t.Fatalf("rows were written after the removal: %v %d", err, len(data))
	}
	var stderr bytes.Buffer
	again, err := newRefusalJournals(cfg, map[string]bool{callerScopeA: true}, newRefusalPG(db.open(t, nil)), h.g.store.signing.key, h.g.provenanceKeys, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(again.store.close)
	if again.scopes[callerScopeA].secret == nil || strings.Contains(stderr.String(), "no key") {
		t.Fatalf("the next start: %q", stderr.String())
	}
}
