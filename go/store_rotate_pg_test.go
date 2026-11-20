package main

// gateway store rotate on the PostgreSQL kind (store_rotate_pg.go): the
// sessions left open in the old database sealed, the new database migrated
// and given a registry whose first line names the old one's tail, the pair
// verified through exports with --previous; refused while an instance
// serves the old database, and into a database that holds a store.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pgTestDBBeside makes a second database for db's roles, as an operator
// provisions one to rotate into, and drops it when the test ends. It does
// not migrate it.
func pgTestDBBeside(t *testing.T, db *pgTestDB) *pgTestDB {
	t.Helper()
	beside := *db
	beside.database = "gw_db_" + pgTestRandom(t, 6)
	beside.migrator.database, beside.runtime.database, beside.inDB.database = beside.database, beside.database, beside.database
	t.Cleanup(func() {
		drop := func() error {
			return db.adminScript("SET ROLE "+db.roles.owner, "DROP DATABASE IF EXISTS "+beside.database+" WITH (FORCE)")
		}
		err := drop()
		for wait := time.Now().Add(10 * time.Second); err != nil && time.Now().Before(wait); err = drop() {
			time.Sleep(100 * time.Millisecond)
		}
		if err != nil {
			t.Errorf("dropping the second test database: %v", err)
		}
	})
	if err := db.adminScript("CREATE DATABASE " + beside.database + " OWNER " + db.roles.owner + " ENCODING 'UTF8' TEMPLATE template0"); err != nil {
		t.Fatalf("making the second test database: %v", err)
	}
	if err := db.adminScript("SET ROLE "+db.roles.owner,
		"REVOKE ALL ON DATABASE "+beside.database+" FROM PUBLIC",
		"GRANT CONNECT ON DATABASE "+beside.database+" TO "+db.migRole+", "+db.roles.runtime+", SESSION_USER",
	); err != nil {
		t.Fatalf("making the second test database: %v", err)
	}
	return &beside
}

// rotatePg runs gateway store rotate on the store config names into
// target, by the migration login's connection string in a file in dir.
func rotatePg(t *testing.T, config string, target *pgTestDB, dir string) (int, string, string) {
	t.Helper()
	return rotatePgAt(t, config, target, dir, nowStamp)
}

// rotatePgAt is rotatePg with the gateway's clock at the rotation stamp's.
func rotatePgAt(t *testing.T, config string, target *pgTestDB, dir string, stamp func() string) (int, string, string) {
	t.Helper()
	connection := filepath.Join(dir, "migration-"+target.database)
	if err := os.WriteFile(connection, []byte(pgTestURL(target.migrator)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := cmdStoreRotateAt([]string{"--config", config, "--connection-file", connection,
		"--owner", target.roles.owner, "--runtime", target.roles.runtime, "--timeout", "60"}, &stdout, &stderr, stamp)
	return code, stdout.String(), stderr.String()
}

// pgRegistryOf is the registry db keeps, "" where it keeps none.
func pgRegistryOf(t *testing.T, db *pgTestDB) string {
	t.Helper()
	data, err := db.open(t, nil).registry().readLog(0)
	if faultOf(err) == faultAbsent {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// pgHasSchema is whether db holds the kind's schema.
func pgHasSchema(t *testing.T, db *pgTestDB) bool {
	t.Helper()
	rows := pgTestQuery(t, db.inDB, `SELECT count(*) FROM pg_catalog.pg_namespace WHERE nspname = 'gateway'`)
	n, _ := pgInt8(rows.rows[0][0])
	return n == 1
}

// pgExportVerdict exports the store config names into dir/name and
// verifies the export, as gateway verify does, with --previous where
// previous is not "".
func pgExportVerdict(t *testing.T, dir, config, name, previous string) (*report, string) {
	t.Helper()
	out := filepath.Join(dir, name)
	if _, err := exportEngine(config, out, nil, ""); err != nil {
		t.Fatalf("export: %v", err)
	}
	requireExportChecks(t, out)
	rep := pgVerifyPrevious(t, out, previous)
	return rep, filepath.Join(out, "registry")
}

// pgVerifyPrevious is gateway verify's verdict on the export at out, given
// --previous where previous is not "".
func pgVerifyPrevious(t *testing.T, out, previous string) *report {
	t.Helper()
	m, err := readExportManifest(out)
	if err != nil {
		t.Fatal(err)
	}
	records := ""
	if m.decisionRecords {
		records = filepath.Join(out, "decision-records")
	}
	rep, err := verifyWithRegistryAndRecords(filepath.Join(out, "store"), filepath.Join(out, "registry"), "gateway:test", records, ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("no verdict for %s: %v", out, err)
	}
	if err := linkPrevious(rep, previous, edKey(ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey))); err != nil {
		t.Fatal(err)
	}
	return rep
}

// pgLinkFindings are the statuses of rep's findings that are not a call's
// "ok".
func pgLinkFindings(rep *report) []any {
	var out []any
	for _, f := range rep.Findings {
		if f["status"] != "ok" {
			out = append(out, f["status"])
		}
	}
	return out
}

func marshalled(t *testing.T, rep *report) string {
	t.Helper()
	out, err := rep.marshal()
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// A rotation seals what an instance left open in the old database, in a
// scope identifier and in none, sealedVia command; then migrates the new
// database and makes its registry, holding the store continuation alone,
// naming the old registry's tail after those seals. The old database's
// lease is not left live, and the run-time role holds on the new database
// what it holds on the old one. A second rotation into the database the
// first made is refused, and nothing is sealed. Exported, the old store
// verifies; an instance starts on the new database, and the new store's
// export verifies, continuing from the old one, and links to the old
// export's registry with --previous, and to no other. An instance started
// on the old database after the rotation serves it, and its store verifies
// still; its registry has grown past the tail the link names, so the link
// holds to the old registry as the rotation left it, not as it is after.
func TestAPostgresStoreRotationSealsWhatIsOpenAndLinksTheNewDatabase(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	config, cfg := sealOpenPgConfig(t, db, dir, "engine.json", false, "")
	sources := sealOpenPgSources(t)
	stop := sealOpenPgLeaveOpen(t, cfg, sources, []string{
		`{"session":"r-a","source":"screening-a","scope":"scope-a","arguments":{"q":"acme"}}`,
		`{"session":"r-none","source":"plain","arguments":{"q":"acme"}}`,
		`{"session":"r-done","source":"plain","arguments":{"q":"other"}}`,
	}, "r-done")
	stop()
	heads := sealOpenPgHeads(t, db, map[string]string{"r-a": "scope-a", "r-none": ""})
	target := pgTestDBBeside(t, db)

	code, stdout, stderr := rotatePg(t, config, target, dir)
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	out := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if len(out) != 3 {
		t.Fatalf("not two seals and the continuation: %q", stdout)
	}
	if got := sealOpenPgSeals(t, out[:2], "", sealedViaCommand, heads); strings.Join(got, ",") != "r-a,r-none" {
		t.Fatalf("the rotation sealed %v", got)
	}
	old := pgRegistryOf(t, db)
	if !strings.HasSuffix(old, out[0]+"\n"+out[1]+"\n") {
		t.Fatalf("the old registry does not end in the seals printed:\n%s", old)
	}
	if got := pgRegistryOf(t, target); got != out[2]+"\n" {
		t.Fatalf("the new registry is %q, not the continuation printed", got)
	}
	lines, last := registryLink([]byte(old))
	walk, err := engineWalk([]byte(out[2]+"\n"), edKey(ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)))
	if err != nil || walk.continuation == nil || walk.continuation.previousLines != lines || walk.continuation.previousDigest != last {
		t.Fatalf("the new registry's own reading: %v %+v, want %d %s", err, walk, lines, last)
	}
	if pgLeaseLive(t, db) {
		t.Fatal("the rotation left the old database's start lease live")
	}
	if a, b := fmt.Sprint(pgRuntimeGrants(t, db)), fmt.Sprint(pgRuntimeGrants(t, target)); a != b || a == "map[]" {
		t.Fatalf("the run-time role holds %s on the new database and %s on the old", b, a)
	}

	code, stdout, stderr = rotatePg(t, config, target, dir)
	// the old database is marked rotated: the second rotation takes no lease
	if code != 1 || stdout != "" || !strings.Contains(stderr, errStoreRotated(rotatedMark([]byte(out[2]))).Error()) {
		t.Fatalf("a second rotation of the store rotated away from: %d %q %q", code, stdout, stderr)
	}
	if pgRegistryOf(t, db) != old || pgRegistryOf(t, target) != out[2]+"\n" {
		t.Fatal("a refused rotation changed a registry")
	}

	t.Chdir(dir)
	rep, oldRegistry := pgExportVerdict(t, dir, config, "export-old", "")
	if text := marshalled(t, rep); !rep.OK || strings.Count(text, `"observation":"sealed-after-interruption"`) != 2 {
		t.Fatalf("the old store's verdict: %s", text)
	}
	newDir := tempDirAt(t, 0o700)
	newConfig, newCfg := sealOpenPgConfig(t, target, newDir, "engine.json", false, "")
	stopNew := sealOpenPgLeaveOpen(t, newCfg, sources, []string{`{"session":"n-1","source":"plain","arguments":{"q":"acme"}}`}, "n-1")
	stopNew()
	rep, newRegistry := pgExportVerdict(t, newDir, newConfig, "export-new", oldRegistry)
	if text := marshalled(t, rep); !rep.OK || len(pgLinkFindings(rep)) != 0 || !strings.Contains(text, `"observation":"continues-from"`) {
		t.Fatalf("the new store's verdict with --previous: %s", text)
	}
	if got := readFile(t, newRegistry); !strings.HasPrefix(got, out[2]+"\n") {
		t.Fatalf("the new export's registry does not start with the continuation: %q", got)
	}
	for _, tc := range []struct {
		name, previous, status string
	}{
		{"one line more", old + out[2] + "\n", statusContinuationCountMismatch},
		{"the last line changed", strings.TrimSuffix(old, out[1]+"\n") + strings.Replace(out[1], `"sessionId":"`, `"sessionId":"x`, 1) + "\n", statusContinuationDigestMismatch},
	} {
		path := filepath.Join(t.TempDir(), "previous.jsonl")
		if err := os.WriteFile(path, []byte(tc.previous), 0o600); err != nil {
			t.Fatal(err)
		}
		if rep := pgVerifyPrevious(t, filepath.Join(newDir, "export-new"), path); rep.OK || fmt.Sprint(pgLinkFindings(rep)) != "["+tc.status+"]" {
			t.Fatalf("%s: %v, want %s", tc.name, rep.Findings, tc.status)
		}
	}

	// the mark refuses a start on the old database; the owner removes it,
	// as only the owner can, and an instance serves the old store again
	asOwnerIn(t, db, pgNoScope, `DELETE FROM gateway.rotated`)
	stopLate := sealOpenPgLeaveOpen(t, cfg, sources, []string{`{"session":"late","source":"plain","arguments":{"q":"acme"}}`}, "late")
	stopLate()
	rep, laterRegistry := pgExportVerdict(t, dir, config, "export-old-later", "")
	if text := marshalled(t, rep); !rep.OK || strings.Count(text, `"observation":"sealed-after-interruption"`) != 2 {
		t.Fatalf("the old store's verdict after an instance served it again: %s", text)
	}
	if rep := pgVerifyPrevious(t, filepath.Join(newDir, "export-new"), laterRegistry); rep.OK || fmt.Sprint(pgLinkFindings(rep)) != "["+statusContinuationCountMismatch+"]" {
		t.Fatalf("the link to the old registry as it grew after the rotation: %v", rep.Findings)
	}
}

// While an instance serves the old database, in the several-instances mode,
// the rotation, which takes the lease in the one-instance mode, is refused
// with start-lease-held: nothing is sealed, and the new database is not
// migrated.
// The old database is marked rotated away from by the one row of
// gateway.rotated, which the run-time role can neither change, remove nor
// double; a start on it is refused by name before it takes the lease; and a
// rotation rerun when its row was not written writes the row alone.
func TestAPostgresStoreRotatedAwayFromIsMarkedAndAStartOnItIsRefusedByName(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	config, cfg := sealOpenPgConfig(t, db, dir, "engine.json", false, "")
	stop := sealOpenPgLeaveOpen(t, cfg, sealOpenPgSources(t), []string{`{"session":"s-1","source":"plain","arguments":{"q":"acme"}}`})
	stop()
	target := pgTestDBBeside(t, db)
	code, stdout, stderr := rotatePg(t, config, target, dir)
	out := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if code != 0 || stderr != "" || len(out) != 2 {
		t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	mark := rotatedMark([]byte(out[1]))
	if rows := pgTestQuery(t, db.runtime, `SELECT continuation FROM gateway.rotated`); len(rows.rows) != 1 || rotatedMarkPrefix+string(rows.rows[0][0]) != mark {
		t.Fatalf("the old database's mark: %v, not %s", rows.rows, mark)
	}

	kind := db.open(t, nil)
	t.Cleanup(kind.close)
	if lease, err := kind.takeStartLease(newTestLeaseHolder(t), pgStartLeasePeriod, pgStartLeaseRenewal); err == nil || !strings.Contains(err.Error(), errStoreRotated(mark).Error()) {
		if lease != nil {
			lease.closeOwn()
		}
		t.Fatalf("a start on the store rotated away from: %v", err)
	}
	if pgLeaseLive(t, db) {
		t.Fatal("a refused start left the start lease live")
	}

	// a removal is refused on it too: it would append to the registry the
	// new store's continuation names
	seed := filepath.Join(tempDirAt(t, 0o700), "gateway.seed")
	if err := os.WriteFile(seed, []byte(hex.EncodeToString(testSeed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runStoreRemoveScope("--connection-file", writeConnection(t, db.migrator), "--owner", db.roles.owner, "--runtime", db.roles.runtime,
		"--seed", seed, "--scope", "scope-a", "--by", "operator-1", "--timeout", "60"); code != 1 || !strings.Contains(stderr, errStoreRotated(mark).Error()+"; nothing was removed") {
		t.Fatalf("remove-scope on the store rotated away from: %d %q", code, stderr)
	}

	for _, change := range []string{
		`UPDATE gateway.rotated SET rotated_at = pg_catalog.now()`,
		`DELETE FROM gateway.rotated`,
		`TRUNCATE gateway.rotated`,
	} {
		if _, err := pgTestQueryErr(db.runtime, change); err == nil || !strings.Contains(err.Error(), "SQLSTATE 42501") {
			t.Fatalf("the run-time role's %q: %v", change, err)
		}
	}
	zeros := strings.Repeat("0", 64)
	if _, err := pgTestQueryErr(db.runtime, `INSERT INTO gateway.rotated (continuation, rotated_at) VALUES ($1, pg_catalog.now())`, zeros); err == nil || !strings.Contains(err.Error(), "SQLSTATE 23505") {
		t.Fatalf("a second mark: %v", err)
	}
	if _, err := pgTestQueryErr(db.runtime, `INSERT INTO gateway.rotated (singleton, continuation, rotated_at) VALUES (false, $1, pg_catalog.now())`, zeros); err == nil || !strings.Contains(err.Error(), "SQLSTATE 23514") {
		t.Fatalf("a second mark of another key: %v", err)
	}

	// the rerun: the row not written, the new database's registry the
	// continuation alone; the rotation writes the row and nothing else
	newRegistry := pgRegistryOf(t, target)
	asOwnerIn(t, db, pgNoScope, `DELETE FROM gateway.rotated`)
	code, stdout, stderr = rotatePg(t, config, target, dir)
	if code != 0 || stderr != "" || stdout != out[1]+"\n" {
		t.Fatalf("the rerun: exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	if rows := pgTestQuery(t, db.runtime, `SELECT continuation FROM gateway.rotated`); len(rows.rows) != 1 || rotatedMarkPrefix+string(rows.rows[0][0]) != mark {
		t.Fatalf("the mark the rerun wrote: %v", rows.rows)
	}
	if pgRegistryOf(t, target) != newRegistry {
		t.Fatal("the rerun changed the new database's registry")
	}
}

func TestAPostgresStoreRotationIsRefusedWhileAnInstanceServes(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	config, cfg := instancesPgConfig(t, db, dir, "engine.json", false)
	sources := sealOpenPgSources(t)
	sealOpenPgLeaveOpen(t, cfg, sources, []string{`{"session":"s-1","source":"plain","arguments":{"q":"acme"}}`})
	target := pgTestDBBeside(t, db)
	before := pgRegistryOf(t, db)
	code, stdout, stderr := rotatePg(t, config, target, dir)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "store rotate: start-lease-held: ") || !strings.HasSuffix(stderr, "; stop the gateway, then rotate\n") {
		t.Fatalf("a rotation while an instance serves: %d %q %q", code, stdout, stderr)
	}
	if pgRegistryOf(t, db) != before {
		t.Fatal("a refused rotation appended to the old registry")
	}
	if pgHasSchema(t, target) {
		t.Fatal("a refused rotation migrated the new database")
	}
}

// A database that holds a store -- here the old database itself -- is no
// database to rotate into: the rotation is refused before anything is
// sealed, and the session left open stays open.
func TestAPostgresStoreRotationIsRefusedIntoADatabaseThatHoldsAStore(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	config, cfg := sealOpenPgConfig(t, db, dir, "engine.json", false, "")
	stop := sealOpenPgLeaveOpen(t, cfg, sealOpenPgSources(t), []string{`{"session":"s-1","source":"plain","arguments":{"q":"acme"}}`})
	stop()
	before := pgRegistryOf(t, db)
	code, stdout, stderr := rotatePg(t, config, db, dir)
	if code != 1 || stdout != "" || stderr != "store rotate: the new database: it holds a registry; a rotation starts a new store in a database that holds none; nothing was changed\n" {
		t.Fatalf("a rotation into the old database: %d %q %q", code, stdout, stderr)
	}
	if pgRegistryOf(t, db) != before || strings.Contains(before, `"sessionId":"s-1"`) {
		t.Fatal("a refused rotation sealed a session")
	}
}

// Each kind takes its own flags of the new store alone: the filesystem
// kind's rotation given the migration login's, or the PostgreSQL kind's
// given a new store directory, is a usage error, and nothing is read.
func TestStoreRotateTakesEachKindsFlagsOfTheNewStoreAlone(t *testing.T) {
	dir := tempDirAt(t, 0o700)
	config, _ := sealOpenPgConfig(t, &pgTestDB{runtime: pgDSN{host: "127.0.0.1", port: "1", user: "nobody", database: "none"}}, dir, "engine.json", false, "")
	for _, args := range [][]string{
		{"--store", dir, "--seed", filepath.Join(dir, "gateway.seed"), "--registry", filepath.Join(dir, "registry"), "--authority", "gateway:test",
			"--new-store", filepath.Join(dir, "new"), "--new-registry", filepath.Join(dir, "new.jsonl"), "--owner", "gw_owner"},
		{"--config", config, "--new-store", filepath.Join(dir, "new"), "--connection-env", "GATEWAY_NEW", "--owner", "gw_owner", "--runtime", "gw_run"},
		{"--config", config, "--connection-env", "GATEWAY_NEW", "--owner", "gw_owner"},
	} {
		var stdout, stderr bytes.Buffer
		if code := cmdStoreRotateAt(args, &stdout, &stderr, nowStamp); code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "gateway store rotate --config <engine.json> (--connection-file") {
			t.Fatalf("%q: %d %q", args, code, stderr.String())
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 4 {
		t.Fatalf("a refused rotation made something: %v", entries)
	}
}

// A database that holds a key history carried but no other row, or a row of
// a store but no key history, holds a store all the same: each is refused
// as a database to rotate into, by name, before anything is sealed.
func TestAPostgresStoreRotationIsRefusedIntoADatabaseHoldingKeyHistoryOrRowsAlone(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	config, cfg := sealOpenPgConfig(t, db, dir, "engine.json", false, "")
	stop := sealOpenPgLeaveOpen(t, cfg, sealOpenPgSources(t), []string{`{"session":"s-1","source":"plain","arguments":{"q":"acme"}}`})
	stop()
	before := pgRegistryOf(t, db)
	for name, row := range map[string]string{
		"a key history alone":          `INSERT INTO gateway.key_history (history) VALUES ('\x7b7d')`,
		"a row of a store, no history": `INSERT INTO gateway.series (scope, name) VALUES ('none', 'held')`,
	} {
		target := pgTestDBBeside(t, db)
		target.migrate(t)
		asOwnerIn(t, target, pgNoScope, row)
		code, stdout, stderr := rotatePg(t, config, target, dir)
		if code != 1 || stdout != "" || stderr != "store rotate: the new database: it holds rows of a store; a rotation starts a new store in a database that holds none; nothing was changed\n" {
			t.Errorf("%s: a rotation into it: %d %q %q", name, code, stdout, stderr)
		}
		if pgRegistryOf(t, db) != before {
			t.Fatalf("%s: a refused rotation appended to the old registry", name)
		}
	}
}

// On the PostgreSQL kind too, a seal held for the sink -- its marker among
// the documents of no scope -- refuses a rotation that would not deliver
// it, here by a configuration that names no receipt sink, before anything
// is sealed: the session left open stays open, the marker stays, and the
// new database is not migrated.
func TestAPostgresStoreRotationRefusesASealHeldForTheSink(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	config, cfg := sealOpenPgConfig(t, db, dir, "engine.json", false, "")
	stop := sealOpenPgLeaveOpen(t, cfg, sealOpenPgSources(t), []string{
		`{"session":"s-1","source":"plain","arguments":{"q":"acme"}}`,
		`{"session":"s-2","source":"plain","arguments":{"q":"acme"}}`,
	}, "s-2")
	stop()
	marks := pgSealForwarding{db.open(t, nil).ofNoScope().documents()}
	if err := marks.mark("s-2"); err != nil {
		t.Fatal(err)
	}
	target := pgTestDBBeside(t, db)
	before := pgRegistryOf(t, db)
	code, stdout, stderr := rotatePg(t, config, target, dir)
	if code != 1 || stdout != "" || stderr != "store rotate: "+storeRotateSealsHeld([]string{"s-2"}).Error()+"\n" {
		t.Fatalf("a rotation past a held seal: %d %q %q", code, stdout, stderr)
	}
	if after := pgRegistryOf(t, db); after != before || strings.Contains(after, `"sessionId":"s-1"`) {
		t.Fatal("a refused rotation sealed a session")
	}
	if pending := markedPending(t, marks); len(pending) != 1 || pending[0] != "s-2" {
		t.Fatalf("the marker is not kept: %v", pending)
	}
	if pgHasSchema(t, target) || strings.Contains(stderr, "store-rotated") {
		t.Fatal("a refused rotation migrated the new database")
	}
}
