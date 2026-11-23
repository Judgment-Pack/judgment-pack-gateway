package main

// gateway store rotate's operator journal on the PostgreSQL kind (ADR-0056
// §3, §5): store-rotate in the database rotated from, store-continued in
// the one rotated to.

import (
	"path/filepath"
	"strings"
	"testing"
)

// gateway store rotate writes store-rotate in the old database, after its
// seals, and begins the new database's journal with store-continued in the
// migration's transaction that makes its registry: the new store verifies
// with the journal required and linked to the old registry, and its entry
// names the old journal, whole. A rerun holds the entry, and writes it
// again where it is lost.
func TestAPostgresStoreRotateWritesBothJournals(t *testing.T) {
	db, dir, config, _ := pgJournalService(t, true)
	before := pgRegistryOf(t, db)
	target := pgTestDBBeside(t, db)
	code, stdout, stderr := rotatePgAt(t, config, target, dir, fixedStamp(removalStamp))
	if code != 0 {
		t.Fatalf("store rotate: %d %q %q", code, stdout, stderr)
	}
	out := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	continuation := out[len(out)-1] + "\n"
	registry := pgRegistryOf(t, db)
	old := pgRowsFile(t, db, "journal_records")
	_, bodies := journalBodiesOf(t, old)
	if len(bodies) != 1 || bodies[0]["kind"] != "store-rotate" || bodies[0]["seals"] != float64(1) || bodies[0]["registryFrom"] != float64(len(before)) ||
		bodies[0]["sealDigest"] != sha256Hex([]byte(registry[len(before):])) {
		t.Fatalf("the old journal: %q", old)
	}
	continued := pgRowsFile(t, target, "journal_records")
	entries, bodies := journalBodiesOf(t, continued)
	if len(entries) != 1 || entries[0]["ordinal"] != float64(0) || bodies[0]["kind"] != "store-continued" ||
		bodies[0]["continuation"] != sha256Hex([]byte(strings.TrimSuffix(continuation, "\n"))) ||
		bodies[0]["previousJournalBytes"] != float64(len(old)) || bodies[0]["previousJournalDigest"] != sha256Hex([]byte(old)) ||
		bodies[0]["registryFrom"] != float64(0) || bodies[0]["removalFrom"] != float64(0) {
		t.Fatalf("the new journal: %q", continued)
	}
	rep, oldRegistry := pgExportVerdict(t, dir, config, "export-old", "")
	rep.requireJournals([]string{operatorJournal})
	if said := journalSaid(rep); !rep.OK || strings.Join(said, ",") != "journal-from" {
		t.Fatalf("the old store's verdict: %v %v", said, rep.Findings)
	}
	newDir := tempDirAt(t, 0o700)
	newConfig, _ := sealOpenPgConfig(t, target, newDir, "engine.json", false, "")
	verifyNew := func(name string) {
		t.Helper()
		rep, _ := pgExportVerdict(t, newDir, newConfig, name, oldRegistry)
		rep.requireJournals([]string{operatorJournal})
		if said, text := journalSaid(rep), marshalled(t, rep); !rep.OK || strings.Join(said, ",") != "journal-from" || !strings.Contains(text, `"observation":"continues-from"`) {
			t.Fatalf("the new store's verdict with --previous: %v %s", said, text)
		}
		if got := readFile(t, filepath.Join(newDir, name, "store", journalsDir, operatorJournal+".jsonl")); got != pgRowsFile(t, target, "journal_records") {
			t.Fatalf("the new export's journal is %q", got)
		}
	}
	verifyNew("export-new")

	// a rerun whose mark was lost holds the entry there and keeps it
	asOwnerIn(t, db, pgNoScope, `DELETE FROM gateway.rotated`)
	if code, stdout, stderr := rotatePgAt(t, config, target, dir, fixedStamp(removalStamp)); code != 0 || stdout != continuation {
		t.Fatalf("the rerun: %d %q %q", code, stdout, stderr)
	}
	if pgRowsFile(t, target, "journal_records") != continued || pgRowsFile(t, db, "journal_records") != old {
		t.Fatal("a rerun changed a journal it held")
	}
	// one whose entry was lost as well writes it again
	asOwnerIn(t, db, pgNoScope, `DELETE FROM gateway.rotated`)
	asOwnerIn(t, target, pgNoScope, `DELETE FROM gateway.journal_records`)
	if code, stdout, stderr := rotatePgAt(t, config, target, dir, fixedStamp(removalStamp)); code != 0 || stdout != continuation {
		t.Fatalf("the rerun with the entry lost: %d %q %q", code, stdout, stderr)
	}
	if pgRowsFile(t, target, "journal_records") != continued {
		t.Fatal("the rerun did not write the store-continued entry again")
	}
	verifyNew("export-new-again")
	// one there that is not this rotation's is refused, and the old store
	// stays unmarked
	asOwnerIn(t, db, pgNoScope, `DELETE FROM gateway.rotated`)
	asOwnerIn(t, target, pgNoScope, `UPDATE gateway.journal_records SET line = pg_catalog.convert_to(pg_catalog.replace(pg_catalog.convert_from(line, 'UTF8'), '"previousJournalBytes":', '"previousJournalBytes":1'), 'UTF8')`)
	if code, stdout, stderr := rotatePgAt(t, config, target, dir, fixedStamp(removalStamp)); code != 1 || !strings.Contains(stderr, "is not the store-continued entry of this rotation") {
		t.Fatalf("the rerun with another entry: %d %q %q", code, stdout, stderr)
	}
	if got := asOwnerIn(t, db, pgNoScope, `SELECT count(*)::int8 FROM gateway.rotated`); len(got.rows) != 1 {
		t.Fatal("the mark did not read")
	} else if n, ok := pgInt8(got.rows[0][0]); !ok || n != 0 {
		t.Fatal("a refused rerun marked the old store")
	}
}
