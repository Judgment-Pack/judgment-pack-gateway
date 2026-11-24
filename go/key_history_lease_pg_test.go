package main

// The key history each instance answers, recorded in its row of the start
// lease (ADR-0062; migration 0012).

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// pgShippedFrom is the shipped schema versions from version from on: what
// gateway store migrate applies to a database at version from-1.
func pgShippedFrom(from int) []int {
	var versions []int
	for _, v := range pgShippedMigrations().versions {
		if v.version >= from {
			versions = append(versions, v.version)
		}
	}
	return versions
}

// An instance answering the key history of version "2" is refused beside
// one answering "1", and the other way round, by name (errInstanceMismatch),
// by a sentence naming both versions and saying to stop every instance;
// instances answering one version serve beside one another.
func TestAPostgresInstanceAnsweringAnotherKeyHistoryIsRefusedByName(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	sources := sealOpenPgSources(t)
	_, one := labelsPgConfig(t, db, tempDirAt(t, 0o700), keyHistoryV2Version, true, "")
	_, two := labelsPgConfig(t, db, tempDirAt(t, 0o700), keyHistoryV2Version, true, `,"keyHistoryVersion":"2"`)
	start := func(cfg engineConfig) (*kindStart, error) {
		var said bytes.Buffer
		s, err := startEngineOnKind(cfg, testSeed, sources, nil, &said)
		if err == nil {
			t.Cleanup(func() { s.stop(&said) })
		}
		return s, err
	}
	refused := func(err error, theirs, ours string) {
		t.Helper()
		if !errors.Is(err, errInstanceMismatch) ||
			!strings.Contains(err.Error(), `answering the key history of version "`+theirs+`", and this instance answers version "`+ours+`"`) ||
			!strings.Contains(err.Error(), "stop every instance, and start them all with one keyHistoryVersion (ADR-0062)") {
			t.Fatalf("refused: %v", err)
		}
	}
	first, err := start(one)
	if err != nil {
		t.Fatal(err)
	}
	if got := pgTestQuery(t, db.runtime, `SELECT key_history FROM gateway.start_lease WHERE expires > pg_catalog.clock_timestamp()`).rows; len(got) != 1 || string(got[0][0]) != "1" {
		t.Fatalf("the row of an instance answering version 1: %q", got)
	}
	_, err = start(two)
	refused(err, "1", "2")
	second, err := start(one)
	if err != nil {
		t.Fatalf("version 1 beside version 1: %v", err)
	}
	var said bytes.Buffer
	first.stop(&said)
	second.stop(&said)
	third, err := start(two)
	if err != nil {
		t.Fatalf("version 2, once the instances of version 1 stopped: %v", err)
	}
	if got := pgTestQuery(t, db.runtime, `SELECT key_history FROM gateway.start_lease WHERE expires > pg_catalog.clock_timestamp()`).rows; len(got) != 1 || string(got[0][0]) != "2" {
		t.Fatalf("the row of an instance answering version 2: %q", got)
	}
	_, err = start(one)
	refused(err, "2", "1")
	if _, err := start(two); err != nil {
		t.Fatalf("version 2 beside version 2: %v", err)
	}
	third.stop(&said)
}

// The version an instance records is the one it answers: "2" where the
// history carried into the database is of version "2", whatever its
// configuration says, and otherwise its configuration's.
func TestAPostgresInstanceRecordsTheKeyHistoryVersionItAnswers(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	kind := db.open(t, nil)
	for _, c := range []struct{ configured, want string }{{"", "1"}, {"2", "2"}} {
		if got, err := kind.servedKeyHistory(c.configured); err != nil || got != c.want {
			t.Fatalf("none carried, configured %q: %q %v", c.configured, got, err)
		}
	}
	asOwnerIn(t, db, pgNoScope, `INSERT INTO gateway.key_history (history) VALUES ($1)`, []byte(`{"keyHistoryVersion":"2"}`))
	for _, configured := range []string{"", "2"} {
		if got, err := kind.servedKeyHistory(configured); err != nil || got != "2" {
			t.Fatalf("a history of version 2 carried, configured %q: %q %v", configured, got, err)
		}
	}
	asOwnerIn(t, db, pgNoScope, `UPDATE gateway.key_history SET history = $1`, []byte(`{"keyHistoryVersion":"1"}`))
	if got, err := kind.servedKeyHistory(""); err != nil || got != "1" {
		t.Fatalf("a history of version 1 carried: %q %v", got, err)
	}
}

// A store at schema version 11 migrates to 12 with every instance stopped:
// a row of the lease from before reads "1", and the column holds "1" or
// "2" alone.
func TestAPostgresStoreAtSchemaElevenMigratesToTheLeasesKeyHistory(t *testing.T) {
	db := newPgTestDB(t)
	set := pgShippedMigrations()
	if len(set.versions) < 12 || set.versions[11].name != "0012_lease_key_history.sql" {
		t.Fatalf("the shipped schema has %d versions: the test names version 12 as the lease's key history", len(set.versions))
	}
	older := pgMigrationSet{versions: set.versions[:11], grants: pgGrantsOfVersion(t, set.grants, 11)}
	if applied, err := migratePostgres(db.migrator, older, db.roles, time.Minute); err != nil || len(applied) != 11 {
		t.Fatalf("schema version 11: %v %v", applied, err)
	}
	asOwnerIn(t, db, pgNoScope, `INSERT INTO gateway.start_lease (holder, several, key_id, authority, renewed, expires)
		SELECT $1, true, $2, 'gateway:test', n.now - interval '1 minute', n.now - interval '1 second' FROM (SELECT pg_catalog.clock_timestamp() AS now) n`,
		newTestLeaseHolder(t), strings.Repeat("a", 32))
	if applied, err := migratePostgres(db.migrator, set, db.roles, time.Minute); err != nil || !slices.Equal(applied, pgShippedFrom(12)) {
		t.Fatalf("the migration from version 11: %v %v", applied, err)
	}
	if rows := pgTestQuery(t, db.runtime, `SELECT key_history FROM gateway.start_lease`).rows; len(rows) != 1 || string(rows[0][0]) != "1" {
		t.Fatalf("a row from before reads %q", rows)
	}
	c, err := pgConnect(db.migrator, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	if err := c.script("BEGIN; SET LOCAL ROLE " + db.roles.owner); err != nil {
		t.Fatal(err)
	}
	if _, err := c.exec(`UPDATE gateway.start_lease SET key_history = '3'`); pgCode(err) != "23514" {
		t.Fatalf("a version other than 1 or 2: %v", err)
	}
}

// admitBeside compares the key-history versions of the rows it is given: a
// row naming none reads "1", as a row of an earlier schema does.
func TestAnInstanceIsAdmittedBesideRowsOfItsKeyHistoryVersionAlone(t *testing.T) {
	row := func(version string) []pgLeaseRow {
		return []pgLeaseRow{{holder: "instance-" + strings.Repeat("0", 32), several: true, live: true, keyHistory: version}}
	}
	as := func(version string) pgInstance { return pgInstance{several: true, keyHistory: version} }
	for _, c := range []struct {
		row, as  string
		admitted bool
	}{{"1", "1", true}, {"2", "2", true}, {"", "1", true}, {"1", "", true}, {"1", "2", false}, {"2", "1", false}, {"2", "", false}} {
		err := admitBeside(as(c.as), row(c.row))
		if (err == nil) != c.admitted || err != nil && !errors.Is(err, errInstanceMismatch) {
			t.Fatalf("row %q, instance %q: %v", c.row, c.as, err)
		}
	}
}
