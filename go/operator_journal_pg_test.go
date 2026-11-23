package main

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// The run-time login inserts journal rows at a journal's end and nowhere
// else, and the database refuses it UPDATE, DELETE and TRUNCATE on them as
// permission denied, SQLSTATE 42501 (ADR-0056, Amendment A).
func TestAPostgresJournalRecordsAreOneChainAndAppendOnly(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	c := db.runtimeConn(t)
	insert := func(journal string, ordinal int64, line string) error {
		_, err := c.exec(`INSERT INTO gateway.journal_records (journal, ordinal, line) VALUES ($1, $2, $3)`, journal, ordinal, []byte(line))
		return err
	}
	for _, row := range []struct {
		journal string
		ordinal int64
	}{{"operator", 0}, {"operator", 1}, {"refusal", 0}} {
		if err := insert(row.journal, row.ordinal, `{"n":0}`); err != nil {
			t.Fatalf("%s at %d: %v", row.journal, row.ordinal, err)
		}
	}
	for _, r := range []struct {
		name, journal string
		ordinal       int64
		line          string
	}{
		{"a second row at an ordinal", "operator", 1, `{"n":1}`},
		{"a row past the journal's end", "operator", 3, `{"n":3}`},
		{"a first row past ordinal 0", "other", 1, `{}`},
		{"a name with a capital", "Operator", 0, `{}`},
		{"a name with a digit", "operator2", 0, `{}`},
		{"a name of 33 characters", strings.Repeat("a", 33), 0, `{}`},
		{"an empty name", "", 0, `{}`},
		{"a line holding a line feed", "operator", 2, "{}\n"},
		{"an empty line", "operator", 2, ""},
		{"a line over the bound", "operator", 2, strings.Repeat("a", 4097)},
		{"a negative ordinal", "operator", -1, `{}`},
	} {
		if err := insert(r.journal, r.ordinal, r.line); err == nil {
			t.Errorf("%s: admitted", r.name)
		}
	}
	if err := insert(strings.Repeat("a", 32), 0, strings.Repeat("a", 4096)); err != nil {
		t.Fatalf("a name and a line at their bounds: %v", err)
	}
	for _, statement := range []string{
		`UPDATE gateway.journal_records SET line = '\x7b7d'::bytea WHERE journal = 'operator'`,
		`DELETE FROM gateway.journal_records WHERE journal = 'operator' AND ordinal = 1`,
		`TRUNCATE gateway.journal_records`,
	} {
		if _, err := c.exec(statement); err == nil || !strings.Contains(err.Error(), "SQLSTATE 42501") {
			t.Errorf("%s, as the run-time login: %v", statement, err)
		}
	}
	rows, err := c.exec(`SELECT count(*)::int8 FROM gateway.journal_records`)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := pgInt8(rows.rows[0][0]); n != 4 {
		t.Fatalf("%d rows after the refusals, want 4", n)
	}
}

// The start refuses a run-time role that may change or remove a journal's
// rows (ADR-0056, Amendment A).
func TestAPostgresStartRefusesARunTimeRoleThatMayChangeAJournal(t *testing.T) {
	for _, privilege := range []string{"UPDATE", "DELETE", "TRUNCATE"} {
		t.Run(privilege, func(t *testing.T) {
			db := newPgTestDB(t)
			db.migrate(t)
			db.asOwner(t, `GRANT `+privilege+` ON gateway.journal_records TO "`+db.roles.runtime+`"`)
			view := &pgKind{pool: newPgPool(db.runtime, 1), operation: pgDefaultOperation, clock: time.Now}
			defer view.close()
			if err := view.holdsItsConditions(pgShippedMigrations()); err == nil {
				t.Fatalf("the start took a run-time role holding %s on the journals", privilege)
			}
		})
	}
}

// A gateway whose migrations stop at 0009 -- v0.38.0's, and the release
// before the journal's -- refuses a database at schema 0010: its migration
// and its start alike, and nothing is changed (ADR-0056, Amendment A).
func TestJournalRecordsMigrationRefusesAnOlderGateway(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	shipped := pgShippedMigrations()
	if len(shipped.versions) < 10 || shipped.versions[9].name != "0010_journal_records.sql" {
		t.Fatalf("migration 0010 is not the journals': %d versions", len(shipped.versions))
	}
	older := shipped
	older.versions = slices.Clone(shipped.versions[:9])
	older.definitionsHeld = false
	before := db.fingerprint(t)
	if _, err := migratePostgres(db.migrator, older, db.roles, time.Minute); err == nil || !strings.Contains(err.Error(), "the database's schema is at version 10 and this gateway's migrations reach version 9") {
		t.Fatalf("an older gateway's migration: %v", err)
	}
	view := &pgKind{pool: newPgPool(db.runtime, 1), operation: pgDefaultOperation, clock: time.Now}
	defer view.close()
	if err := view.holdsItsConditions(older); err == nil || !strings.Contains(err.Error(), "older than its schema") {
		t.Fatalf("an older gateway's start: %v", err)
	}
	if after := db.fingerprint(t); after != before {
		t.Fatalf("a refusal changed the database:\n%s\n%s", before, after)
	}
}
