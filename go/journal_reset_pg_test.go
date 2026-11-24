package main

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// gateway store journal-reset --unscoped removes the rows of the refusal
// journal of the sources of no scope, its key's row and its cursor, with a
// refusal-journal-reset entry naming the rows' bytes, in the owner's
// transaction under the journal's lock (gateway #611). A run cut off before
// its commit changes nothing, and the next run completes it. The entry
// verifies in the export, and nothing else in the export changes, a
// scope's journal byte for byte. A second run removes nothing and writes no
// entry, and the next start draws a new key and journals the sources of no
// scope again.
func TestAPostgresStoreJournalResetTakesTheUnscopedRefusalJournalAlone(t *testing.T) {
	db, dir, config, _ := pgJournalService(t, false)
	h := limitsSetup(t, refusalLimits())
	journals := func() *refusalJournals {
		j, err := newRefusalJournals(&refusalJournalConfig{maxBytes: refusalDefaultCap}, map[string]bool{refusedOnly: true, unscopedMarker: true}, newRefusalPG(db.open(t, nil)),
			h.g.store.signing.key, h.g.provenanceKeys, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(j.store.close)
		return j
	}
	j := journals()
	for _, key := range []string{refusedOnly, unscopedMarker} {
		j.handOff(j.scopes[key], "/seal", refusalNote{reason: "session"}, 404, unitCaller(), nil, time.Now())
	}
	j.round()
	name := refusalJournalName(unscopedMarker)
	journalOf := func(name string) []byte {
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
	data := journalOf(name)
	lines, _ := journalLines(data)
	if len(lines) != 1 || len(journalOf(refusalJournalName(refusedOnly))) == 0 {
		t.Fatalf("%d entries in the journal of the sources of no scope", len(lines))
	}
	cursors := pgForwardingCursors{db.open(t, nil).ofNoScope().documents()}
	if moved, err := cursors.advance(name, -1, forwardingCursor{ordinal: 0, digest: "sha256:" + journalDigest(lines[0])}); !moved || err != nil {
		t.Fatalf("the cursor: %v %v", moved, err)
	}
	secrets := pgSecrets{db.open(t, nil)}
	oldKey, err := secrets.getSecret(refusalKeyName(name))
	if err != nil {
		t.Fatal(err)
	}
	connection := writeConnection(t, db.migrator)
	reset := func() (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := cmdStoreJournalResetAt([]string{"--connection-file", connection, "--owner", db.roles.owner, "--runtime", db.roles.runtime,
			"--config", config, "--unscoped", "--by", "operator-1", "--timeout", "60"}, &stdout, &stderr, func() string { return "2026-11-24T12:00:00Z" })
		return code, stdout.String(), stderr.String()
	}
	pgExportVerdict(t, dir, config, "export-before", "")
	before := storeTree(t, filepath.Join(dir, "export-before", "store"))
	journal := pgRowsFile(t, db, "journal_records")

	// cut off before the commit: nothing changes
	journalCutOff = func() error { return errors.New("cut off") }
	t.Cleanup(func() { journalCutOff = nil })
	if code, stdout, stderr := reset(); code != 1 || stdout != "" || !strings.Contains(stderr, "cut off; nothing was removed") {
		t.Fatalf("the cut-off run: %d %q %q", code, stdout, stderr)
	}
	journalCutOff = nil
	if pgRowsFile(t, db, "journal_records") != journal {
		t.Fatal("the cut-off run changed the journals")
	}
	if _, err := secrets.getSecret(refusalKeyName(name)); err != nil {
		t.Fatalf("the cut-off run removed the key: %v", err)
	}

	code, stdout, stderr := reset()
	if code != 0 || stderr != "" || stdout != "store journal-reset: the refusal journal of the sources of no scope, "+strconv.Itoa(len(data))+" bytes, its key and its cursor are removed\n" {
		t.Fatalf("store journal-reset: %d %q %q", code, stdout, stderr)
	}
	if left := journalOf(name); len(left) != 0 {
		t.Fatalf("%d bytes of the journal's rows stand", len(left))
	}
	if _, err := secrets.getSecret(refusalKeyName(name)); faultOf(err) != faultAbsent {
		t.Fatalf("the key stands: %v", err)
	}
	if at, err := cursors.read(name); err != nil || at.ordinal != -1 {
		t.Fatalf("the forwarding cursor stands: %+v %v", at, err)
	}
	if _, err := secrets.getSecret(refusalKeyName(refusalJournalName(refusedOnly))); err != nil {
		t.Fatalf("the scope's key went: %v", err)
	}
	rep, _ := pgExportVerdict(t, dir, config, "export-after", "")
	rep.requireJournals([]string{operatorJournal})
	for _, said := range journalSaid(rep) {
		if said != "journal-from" {
			t.Fatalf("the export's journals: %v %v", journalSaid(rep), rep.Findings)
		}
	}
	after := storeTree(t, filepath.Join(dir, "export-after", "store"))
	operator := filepath.Join(journalsDir, operatorJournal+".jsonl")
	_, bodies := journalBodiesOf(t, after[operator])
	if len(bodies) == 0 || !strings.HasPrefix(after[operator], before[operator]) {
		t.Fatal("the operator journal's earlier entries changed")
	}
	b := bodies[len(bodies)-1]
	if b["kind"] != refusalJournalResetKind || b["by"] != "operator-1" ||
		b["refusalJournalBytes"] != float64(len(data)) || b["refusalJournalDigest"] != journalDigest(data) || len(b) != 6 {
		t.Fatalf("the entry: %v", b)
	}
	if _, left := after[filepath.Join(journalsDir, name+".jsonl")]; left {
		t.Fatal("the export holds the journal")
	}
	delete(before, filepath.Join(journalsDir, name+".jsonl"))
	delete(before, operator)
	delete(after, operator)
	if len(after) != len(before) {
		t.Fatalf("%d files in the export after, %d before", len(after), len(before))
	}
	for path, was := range before {
		if after[path] != was {
			t.Errorf("%s changed", path)
		}
	}

	// a second run removes nothing and writes no entry
	journal = pgRowsFile(t, db, "journal_records")
	if code, stdout, stderr := reset(); code != 0 || stderr != "" ||
		stdout != "store journal-reset: the refusal journal of the sources of no scope holds no entry; nothing was removed, and no entry was written\n" {
		t.Fatalf("the second run: %d %q %q", code, stdout, stderr)
	}
	if pgRowsFile(t, db, "journal_records") != journal {
		t.Fatal("a run that removed nothing wrote an entry")
	}

	// the next start draws a new key and journals the sources of no scope
	j = journals()
	j.handOff(j.scopes[unscopedMarker], "/seal", refusalNote{reason: "session"}, 404, unitCaller(), nil, time.Now())
	j.round()
	if lines, _ := journalLines(journalOf(name)); len(lines) != 1 {
		t.Fatalf("%d entries in the new journal", len(lines))
	}
	if k, err := secrets.getSecret(refusalKeyName(name)); err != nil || bytes.Equal(k, oldKey) {
		t.Fatalf("the start's key: %v", err)
	}
}
