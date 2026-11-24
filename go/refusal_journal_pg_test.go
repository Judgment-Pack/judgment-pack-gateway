package main

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"time"
)

// Two instances write one scope's refusal journal at once under its lock:
// one key, one chain with no fork, one signature per entry; and a removal
// under the lock takes the rows, the key and the cursor (ADR-0059 §7, §8;
// conditions C7, C8).
func TestThePostgresKindKeepsOneRefusalJournalUnderItsLock(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	h := limitsSetup(t, refusalLimits())
	cfg := &refusalJournalConfig{maxBytes: refusalDefaultCap}
	var js []*refusalJournals
	for i := 0; i < 2; i++ {
		kind := db.open(t, nil)
		j, err := newRefusalJournals(cfg, map[string]bool{callerScopeA: true}, newRefusalPG(kind), h.g.store.signing.key, h.g.provenanceKeys, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(j.store.close)
		js = append(js, j)
	}
	a0, a1 := js[0].scopes[callerScopeA], js[1].scopes[callerScopeA]
	if a0.secret == nil || !bytes.Equal(a0.secret, a1.secret) {
		t.Fatal("the two instances hold two keys")
	}
	const each = 6
	var wg sync.WaitGroup
	for _, j := range js {
		wg.Add(1)
		go func(j *refusalJournals) {
			defer wg.Done()
			s := j.scopes[callerScopeA]
			for i := 0; i < each; i++ {
				j.handOff(s, "/seal", refusalNote{reason: "session"}, 404, unitCaller(), []byte(`{"session":"s-none"}`), time.Now())
				j.round()
			}
		}(j)
	}
	wg.Wait()
	for _, s := range []*refusalScope{a0, a1} {
		if n := s.tally[dropWriteFailed].Load() + s.tally[dropJournalFull].Load(); n != 0 {
			t.Fatalf("%d records were not written", n)
		}
	}
	name := refusalJournalName(callerScopeA)
	var data []byte
	if err := db.open(t, nil).transact(pgRead, func(tx pgTx) error {
		var err error
		data, err = pgJournalFile(tx, name)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	keys, _ := h.g.provenanceKeys()
	if f, n, _ := judgeRefusalJournal(data, name, keys); f != nil || n != 2*each {
		t.Fatalf("the journal: %v, %d entries of %d", f, n, 2*each)
	}
	lines, _ := journalLines(data)
	if ok, _, err := matchRefusalEntry(lines[0], a1.secret, "/seal", []byte(`{"session":"s-none"}`)); !ok || err != nil {
		t.Fatalf("the shared key does not open an entry: %v", err)
	}

	// the owner's transaction, as gateway store remove-scope opens it
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
	removed, err := pgRemoveRefusalJournal(pgTx{c}, callerScopeA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.exec("COMMIT"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(removed, data) {
		t.Fatal("the removal named other bytes than the journal's")
	}
	if _, err := (pgSecrets{db.open(t, nil)}).getSecret(refusalKeyName(name)); faultOf(err) != faultAbsent {
		t.Fatalf("the key stands: %v", err)
	}
	if err := db.open(t, nil).transact(pgRead, func(tx pgTx) error {
		var err error
		data, err = pgJournalFile(tx, name)
		return err
	}); err != nil || len(data) != 0 {
		t.Fatalf("the rows stand: %v %d", err, len(data))
	}
}
