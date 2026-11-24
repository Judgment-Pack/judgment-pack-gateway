package main

import (
	"bytes"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"
)

// gateway store remove-scope of a scope that holds no row and a refusal
// journal removes the journal's rows, its key and its cursor in the
// owner's transaction, under the journal's lock, with an entry that names
// no record and the journal (ADR-0059 §8, as built 2026-11-24); the
// export's journal verifies, and a second run, or a scope holding nothing,
// removes nothing and writes no entry, as before.
func TestAPostgresStoreRemoveScopeTakesTheRefusalJournalOfAScopeThatHoldsNoRecord(t *testing.T) {
	db, dir, config, _ := pgJournalService(t, false)
	h := limitsSetup(t, refusalLimits())
	j, err := newRefusalJournals(&refusalJournalConfig{maxBytes: refusalDefaultCap}, map[string]bool{refusedOnly: true}, newRefusalPG(db.open(t, nil)),
		h.g.store.signing.key, h.g.provenanceKeys, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(j.store.close)
	s := j.scopes[refusedOnly]
	j.handOff(s, "/seal", refusalNote{reason: "session"}, 404, unitCaller(), nil, time.Now())
	j.round()
	name := refusalJournalName(refusedOnly)
	journalOf := func() []byte {
		var data []byte
		if err := db.open(t, nil).transact(pgRead, func(tx pgTx) error {
			var err error
			data, err = pgJournalFile(tx, name)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return data
	}
	data := journalOf()
	lines, _ := journalLines(data)
	if len(lines) != 1 {
		t.Fatalf("%d entries in the refusal journal", len(lines))
	}
	cursors := pgForwardingCursors{db.open(t, nil).ofNoScope().documents()}
	if moved, err := cursors.advance(name, -1, forwardingCursor{ordinal: 0, digest: "sha256:" + journalDigest(lines[0])}); !moved || err != nil {
		t.Fatalf("the cursor: %v %v", moved, err)
	}
	connection := writeConnection(t, db.migrator)
	remove := func(scope string) (int, string, string) {
		return runStoreRemoveScope("--connection-file", connection, "--owner", db.roles.owner, "--runtime", db.roles.runtime,
			"--config", config, "--scope", scope, "--by", "operator-1", "--timeout", "60")
	}
	records := pgRowsFile(t, db, "removal_records")
	// journal_records holds every journal's rows: the operator journal's
	// bodies alone
	operatorBodiesOf := func(file string) []map[string]any {
		entries, bodies := journalBodiesOf(t, file)
		var out []map[string]any
		for i, e := range entries {
			if e["journal"] == operatorJournal {
				out = append(out, bodies[i])
			}
		}
		return out
	}
	before := operatorBodiesOf(pgRowsFile(t, db, "journal_records"))

	code, stdout, stderr := remove(refusedOnly)
	if code != 0 || stdout != "" || !strings.Contains(stderr, "the scope's refusal journal, "+strconv.Itoa(len(data))+" bytes, its key and its cursor are removed\n") ||
		!strings.Contains(stderr, "no row of the scope identifier is in the store; nothing else was removed\n") {
		t.Fatalf("remove-scope: %d %q %q", code, stdout, stderr)
	}
	if left := journalOf(); len(left) != 0 {
		t.Fatalf("%d bytes of the journal's rows stand", len(left))
	}
	if _, err := (pgSecrets{db.open(t, nil)}).getSecret(refusalKeyName(name)); faultOf(err) != faultAbsent {
		t.Fatalf("the key stands: %v", err)
	}
	if at, err := cursors.read(name); err != nil || at.ordinal != -1 {
		t.Fatalf("the forwarding cursor stands: %+v %v", at, err)
	}
	if pgRowsFile(t, db, "removal_records") != records {
		t.Fatal("the removal records changed")
	}
	journal := pgRowsFile(t, db, "journal_records")
	bodies := operatorBodiesOf(journal)
	if len(bodies) != len(before)+1 {
		t.Fatalf("%d entries, %d before", len(bodies), len(before))
	}
	b := bodies[len(bodies)-1]
	if b["kind"] != "remove-scope" || b["scope"] != refusedOnly || b["by"] != "operator-1" || b["removalFrom"] != float64(len(records)) ||
		b["removalBytes"] != float64(0) || b["removalDigest"] != journalDigest(nil) ||
		b["refusalJournalBytes"] != float64(len(data)) || b["refusalJournalDigest"] != journalDigest(data) || len(b) != 9 {
		t.Fatalf("the entry: %v", b)
	}
	rep, _ := pgExportVerdict(t, dir, config, "export-after", "")
	rep.requireJournals([]string{operatorJournal})
	if said := journalSaid(rep); strings.Join(said, ",") != "journal-from" {
		t.Fatalf("the export's journal: %v %v", said, rep.Findings)
	}

	for _, scope := range []string{refusedOnly, "never-held"} {
		code, stdout, stderr := remove(scope)
		if code != 0 || stdout != "" || !strings.Contains(stderr, "no row of the scope identifier is in the store; nothing was removed\n") || strings.Contains(stderr, "refusal journal") {
			t.Fatalf("%s: %d %q %q", scope, code, stdout, stderr)
		}
	}
	if pgRowsFile(t, db, "journal_records") != journal {
		t.Fatal("a run that removed nothing wrote an entry")
	}
}

// store remove-scope refuses --scope "unscoped" before anything is read,
// as remove-scope does: the sources of none's refusal journal and its key
// stand. A command that takes it as a scope fails it.
func TestAPostgresStoreRemoveScopeRefusesTheUnscopedMarker(t *testing.T) {
	db, _, config, _ := pgJournalService(t, false)
	h := limitsSetup(t, refusalLimits())
	j, err := newRefusalJournals(&refusalJournalConfig{maxBytes: refusalDefaultCap}, map[string]bool{unscopedMarker: true}, newRefusalPG(db.open(t, nil)),
		h.g.store.signing.key, h.g.provenanceKeys, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(j.store.close)
	s := j.scopes[unscopedMarker]
	j.handOff(s, "/seal", refusalNote{reason: "session"}, 404, unitCaller(), nil, time.Now())
	j.round()
	name := refusalJournalName(unscopedMarker)
	journalOf := func() []byte {
		var data []byte
		if err := db.open(t, nil).transact(pgRead, func(tx pgTx) error {
			var err error
			data, err = pgJournalFile(tx, name)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return data
	}
	data := journalOf()
	if len(data) == 0 {
		t.Fatal("no unscoped refusal journal")
	}
	connection := writeConnection(t, db.migrator)
	code, _, stderr := runStoreRemoveScope("--connection-file", connection, "--owner", db.roles.owner, "--runtime", db.roles.runtime,
		"--config", config, "--scope", unscopedMarker, "--by", "operator-1", "--timeout", "60")
	if code != 2 || !strings.Contains(stderr, removeUnscopedRefusal) {
		t.Fatalf("store remove-scope --scope unscoped: %d %q", code, stderr)
	}
	if left := journalOf(); !bytes.Equal(left, data) {
		t.Fatal("the unscoped refusal journal changed")
	}
	if _, err := (pgSecrets{db.open(t, nil)}).getSecret(refusalKeyName(name)); err != nil {
		t.Fatalf("the key was removed: %v", err)
	}
}
