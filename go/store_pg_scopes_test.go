package main

// Platforms fixed to scope identifiers on the PostgreSQL kind
// (store_pg_scopes.go, docs/adr/0033): the record of the scope identifiers
// is of no scope and kept from every scope; a scope set for one transaction
// reaches no other on its connection; the owner role is held to the policy
// too; a service of scoped sources writes each source's rows in its scope,
// holds a session to one scope, and exports what a store of the filesystem
// kind holding the same receipts exports, byte for byte; and a store at
// schema version 2 migrates with its rows as rows of no scope. Each test
// skips without a server.

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// pgInScopeOn runs fn on c in one transaction that sets gateway.scope to
// row for itself ("" sets nothing), and rolls the transaction back.
func pgInScopeOn(t *testing.T, c *pgConn, row string, fn func()) {
	t.Helper()
	if err := c.script("BEGIN"); err != nil {
		t.Fatal(err)
	}
	if row != "" {
		if _, err := c.exec(`SELECT pg_catalog.set_config('gateway.scope', $1, true)`, row); err != nil {
			t.Fatal(err)
		}
	}
	fn()
	if err := c.script("ROLLBACK"); err != nil {
		t.Fatal(err)
	}
}

// pgColumn is a query's first column, in the order the rows came.
func pgColumn(t *testing.T, c *pgConn, query string, args ...any) []string {
	t.Helper()
	rows, err := c.exec(query, args...)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	var names []string
	for _, row := range rows.rows {
		names = append(names, string(row[0]))
	}
	return names
}

// pgScopedRowCount counts the rows of every scoped table c's transaction
// sees.
const pgScopedRowCount = `SELECT ((SELECT count(*) FROM gateway.blobs) + (SELECT count(*) FROM gateway.series) +
	(SELECT count(*) FROM gateway.entries) + (SELECT count(*) FROM gateway.documents) +
	(SELECT count(*) FROM gateway.scope_identifiers))::int8`

func pgCount(t *testing.T, c *pgConn, query string, args ...any) int64 {
	t.Helper()
	rows, err := c.exec(query, args...)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	n, _ := pgInt8(rows.rows[0][0])
	return n
}

// The record of the scope identifiers is of no scope: the view of no scope
// reads every identifier recorded, a transaction of a scope identifier and
// one that sets none read none, and no transaction records one but of no
// scope, or changes or removes one. The owner role is held to every scoped
// table's policy as the run-time role is (FORCE ROW LEVEL SECURITY). The
// schema holds no view, function or trigger a scope could reach another's
// rows through.
func TestPostgresScopeIdentifiersAreOfNoScopeAndTheOwnerIsHeld(t *testing.T) {
	kind, db := pgTestKind(t, "", nil)
	views, err := kind.scopeViews([]string{"scope-a", "scope-b"})
	if err != nil {
		t.Fatal(err)
	}
	// recorded once: a second start records nothing new and refuses nothing
	if _, err := kind.scopeViews([]string{"scope-a"}); err != nil {
		t.Fatalf("a second record of a scope identifier: %v", err)
	}
	a := views["scope-a"]
	blob, err := a.artifacts().putBlob([]byte("a blob of scope a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.receipts().makeSeries("session-of-a"); err != nil {
		t.Fatal(err)
	}
	if err := a.receipts().createIndexed("session-of-a", 0, []byte("{\"of\":\"a\"}\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.documents().putDocument("doc-of-a", []byte("a's"), noRevision); err != nil {
		t.Fatal(err)
	}

	c := db.runtimeConn(t)
	pgInScopeOn(t, c, pgNoScope, func() {
		if got := pgColumn(t, c, `SELECT identifier FROM gateway.scope_identifiers ORDER BY identifier`); !slices.Equal(got, []string{"scope:scope-a", "scope:scope-b"}) {
			t.Fatalf("the view of no scope reads the identifiers %v", got)
		}
	})
	for _, row := range []string{pgRowScope("scope-a"), pgRowScope("scope-b"), ""} {
		pgInScopeOn(t, c, row, func() {
			if n := pgCount(t, c, `SELECT count(*)::int8 FROM gateway.scope_identifiers`); n != 0 {
				t.Errorf("a transaction of %q reads %d scope identifiers", row, n)
			}
		})
	}
	for _, tc := range []struct{ row, query string }{
		{pgRowScope("scope-b"), `INSERT INTO gateway.scope_identifiers (scope, identifier) VALUES ('none', 'scope:scope-c')`},
		{"", `INSERT INTO gateway.scope_identifiers (scope, identifier) VALUES ('none', 'scope:scope-c')`},
		{pgNoScope, `UPDATE gateway.scope_identifiers SET identifier = 'scope:scope-c' WHERE identifier = 'scope:scope-a'`},
		{pgNoScope, `DELETE FROM gateway.scope_identifiers WHERE identifier = 'scope:scope-a'`},
		{pgRowScope("scope-b"), `DELETE FROM gateway.scope_identifiers`},
	} {
		pgInScopeOn(t, c, tc.row, func() {
			if _, err := c.exec(tc.query); pgCode(err) != pgInsufficientPriv {
				t.Errorf("in a transaction of %q: %s: %v", tc.row, tc.query, err)
			}
		})
	}

	// the owner role, reached from the migration login, in a transaction of
	// scope b and in one that sets no scope: it reads none of scope a's rows
	// and writes none
	owner, err := pgConnect(db.migrator, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.close()
	asOwnerIn := func(row string, fn func()) {
		t.Helper()
		pgInScopeOn(t, owner, row, func() {
			if err := owner.script("SET LOCAL ROLE " + db.roles.owner); err != nil {
				t.Fatal(err)
			}
			fn()
		})
	}
	asOwnerIn(pgRowScope("scope-a"), func() {
		// the test reaches the rows it then asks the owner for
		if n := pgCount(t, owner, pgScopedRowCount); n != 4 {
			t.Fatalf("the owner in scope a reads %d rows, want scope a's 4: the test tests nothing", n)
		}
	})
	for _, row := range []string{pgRowScope("scope-b"), ""} {
		asOwnerIn(row, func() {
			if n := pgCount(t, owner, pgScopedRowCount); n != 0 {
				t.Errorf("the owner in a transaction of %q reads %d rows of another scope", row, n)
			}
			if got := pgColumn(t, owner, `SELECT name FROM gateway.blobs WHERE scope = 'scope:scope-a' AND name = $1`, blob); len(got) != 0 {
				t.Errorf("the owner in a transaction of %q read scope a's blob by its key", row)
			}
		})
		for _, query := range []string{
			`INSERT INTO gateway.series (scope, name) VALUES ('scope:scope-a', 'owner-of-a')`,
			`INSERT INTO gateway.scope_identifiers (scope, identifier) VALUES ('none', 'scope:scope-c')`,
		} {
			asOwnerIn(row, func() {
				if _, err := owner.exec(query); pgCode(err) != pgInsufficientPriv {
					t.Errorf("the owner in a transaction of %q: %s: %v", row, query, err)
				}
			})
		}
		asOwnerIn(row, func() {
			for query, want := range map[string]string{
				`UPDATE gateway.documents SET data = 'owner''s' WHERE name = 'doc-of-a'`: "UPDATE 0",
				`DELETE FROM gateway.entries WHERE series = 'session-of-a'`:              "DELETE 0",
				`DELETE FROM gateway.scope_identifiers`:                                  "DELETE 0",
			} {
				rows, err := owner.exec(query)
				if err != nil || rows.tag != want {
					t.Errorf("the owner in a transaction of %q: %s: %q %v, want %q", row, query, rows.tag, err, want)
				}
			}
		})
	}

	// every table that holds a scope is held by its policy, forced
	forced := pgTestQuery(t, db.runtime, `SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'gateway' AND c.relkind = 'r' AND c.relrowsecurity AND c.relforcerowsecurity
		AND EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = c.oid) ORDER BY c.relname`)
	var held []string
	for _, row := range forced.rows {
		held = append(held, string(row[0]))
	}
	if !slices.Equal(held, pgScopedTables) {
		t.Errorf("the tables held by a forced policy are %v, want %v", held, pgScopedTables)
	}
	reach := pgTestQuery(t, db.runtime, `SELECT
		(SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'gateway' AND c.relkind NOT IN ('r', 'i'))::int8,
		(SELECT count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname NOT IN ('pg_catalog', 'information_schema'))::int8,
		(SELECT count(*) FROM pg_catalog.pg_trigger g WHERE NOT g.tgisinternal)::int8`)
	for i, what := range []string{"relations other than tables and indexes (a view, a sequence)", "functions", "triggers"} {
		if n, _ := pgInt8(reach.rows[0][i]); n != 0 {
			t.Errorf("the database holds %d %s", n, what)
		}
	}
}

// A scope set by one of the kind's transactions reaches no later one on
// its connection: after a write of scope a, an export that sets each scope
// in its turn, and the start's questions of every scope, a transaction on
// the pool's one connection that sets no scope reads no row and finds the
// setting empty.
func TestAPostgresScopeSetForOneTransactionReachesNoOtherOnItsConnection(t *testing.T) {
	_, db := pgTestKind(t, "", nil)
	single, err := openPgKind(pgOptions{dsn: db.runtime, connections: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer single.close()
	views, err := single.scopeViews([]string{"scope-a"})
	if err != nil {
		t.Fatal(err)
	}
	a := views["scope-a"]
	if _, err := single.artifacts().putBlob([]byte("a blob of no scope")); err != nil {
		t.Fatal(err)
	}
	backend := ""
	unset := func(after string) {
		t.Helper()
		c, err := single.pool.acquire(time.Now().Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		defer single.pool.release(c)
		rows, err := c.exec(`SELECT pg_catalog.pg_backend_pid()::text, coalesce(pg_catalog.current_setting('gateway.scope', true), ''), ` + strings.TrimPrefix(pgScopedRowCount, "SELECT "))
		if err != nil {
			t.Fatal(err)
		}
		pid, setting := string(rows.rows[0][0]), string(rows.rows[0][1])
		if backend == "" {
			backend = pid
		} else if pid != backend {
			t.Fatalf("after %s the pool handed out another connection: the test tests nothing", after)
		}
		if setting != "" {
			t.Errorf("after %s the connection's scope is %q", after, setting)
		}
		if n, _ := pgInt8(rows.rows[0][2]); n != 0 {
			t.Errorf("after %s a transaction that sets no scope reads %d rows", after, n)
		}
	}
	unset("a write of no scope")
	if _, err := a.artifacts().putBlob([]byte("a blob of scope a")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.receipts().makeSeries("session-of-a"); err != nil {
		t.Fatal(err)
	}
	unset("a write of scope a")
	if names, err := a.artifacts().listBlobs(); err != nil || len(names) != 1 {
		t.Fatalf("scope a lists %v %v", names, err)
	}
	unset("a read of scope a")
	cut, err := pgEveryScope{single}.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(cut.blobs) != 2 || len(cut.series) != 1 {
		t.Fatalf("the export's cut lists %v %v", cut.blobs, cut.series)
	}
	unset("an export's cut")
	if held, err := single.holdsAnySeries(); err != nil || !held {
		t.Fatalf("holdsAnySeries: %v %v", held, err)
	}
	if held, ofScope, _, err := single.seriesHeld("session-of-a", "scope-a"); err != nil || !held || !ofScope {
		t.Fatalf("seriesHeld: %v %v %v", held, ofScope, err)
	}
	unset("the start's questions of every scope")
}

// The export's cut is refused where two scopes hold different bytes under
// one blob's name, or one series' name (which the table's key forbids,
// taken away here as the owner), rather than one taken for the other; a
// blob two scopes hold alike is listed once.
func TestAPostgresExportRefusesTwoScopesThatDisagree(t *testing.T) {
	kind, db := pgTestKind(t, "", nil)
	if _, err := kind.scopeViews([]string{"scope-a", "scope-b"}); err != nil {
		t.Fatal(err)
	}
	c := db.runtimeConn(t)
	write := func(row, query string, args ...any) {
		t.Helper()
		if err := c.script("BEGIN"); err != nil {
			t.Fatal(err)
		}
		if _, err := c.exec(`SELECT pg_catalog.set_config('gateway.scope', $1, true)`, row); err != nil {
			t.Fatal(err)
		}
		if _, err := c.exec(query, args...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		if err := c.script("COMMIT"); err != nil {
			t.Fatal(err)
		}
	}
	alike := "sha256:" + strings.Repeat("1", 64)
	differ := "sha256:" + strings.Repeat("2", 64)
	for _, row := range []string{pgRowScope("scope-a"), pgRowScope("scope-b")} {
		write(row, `INSERT INTO gateway.blobs (scope, name, data) VALUES ($1, $2, 'alike')`, row, alike)
		write(row, `INSERT INTO gateway.blobs (scope, name, data) VALUES ($1, $2, $3)`, row, differ, []byte(row))
	}
	cut, err := pgEveryScope{kind}.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cut.blobs, []string{alike, differ}) {
		t.Fatalf("the cut lists the blobs %v", cut.blobs)
	}
	if data, err := cut.blob(alike); err != nil || string(data) != "alike" {
		t.Fatalf("a blob two scopes hold alike: %q %v", data, err)
	}
	if _, err := cut.blob(differ); faultOf(err) != faultUnreadable || !strings.Contains(err.Error(), "two scopes hold different bytes under one blob's name") {
		t.Fatalf("a blob two scopes hold with different bytes: %v", err)
	}
	db.asOwner(t, "ALTER TABLE gateway.entries DROP CONSTRAINT entries_scope_series_fkey", "ALTER TABLE gateway.series DROP CONSTRAINT series_pkey")
	for _, row := range []string{pgRowScope("scope-a"), pgRowScope("scope-b")} {
		write(row, `INSERT INTO gateway.series (scope, name) VALUES ($1, 'one-name')`, row)
	}
	if _, err := (pgEveryScope{kind}).snapshot(); faultOf(err) != faultUnreadable || !strings.Contains(err.Error(), "two scopes hold one series' name") {
		t.Fatalf("one series' name in two scopes: %v", err)
	}
}

// scopedServiceStart is a version-24 configuration of the PostgreSQL kind
// on db and the service serve --config starts on it with sources.
func scopedServiceStart(t *testing.T, db *pgTestDB, dir string, sources map[string]sourceSpec) (string, *kindStart, *httptest.Server) {
	t.Helper()
	connection := filepath.Join(dir, "connection")
	if err := os.WriteFile(connection, []byte(pgTestURL(db.runtime)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	seedPath := filepath.Join(dir, "gateway.seed")
	if err := os.WriteFile(seedPath, []byte(hex.EncodeToString(testSeed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "decisions"), 0o700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "engine.json")
	text := `{"engineVersion":"24","authority":"gateway:test","seed":"` + abs(t, seedPath) + `","storage":{"kind":"postgresql","connection":{"file":"` + abs(t, connection) + `"},"connections":2},` +
		`"decisionRecords":"` + abs(t, dir, "decisions") + `","listen":"127.0.0.1:8787","catalog":"` + abs(t, dir, "catalog") + `","platforms":{}}`
	if err := os.WriteFile(config, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := parseEngineConfig([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	var said bytes.Buffer
	started, err := startEngineOnKind(cfg, testSeed, sources, nil, &said)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { started.stop(&said) })
	server := httptest.NewServer(started.service.handler())
	t.Cleanup(server.Close)
	return config, started, server
}

// A service of sources fixed to scope identifiers, and one of none, on the
// PostgreSQL kind: each source's payloads and receipts are rows of its
// scope, and its receipts name that scope; a session is held to the scope
// of its first receipt, an acquisition of another scope refused before its
// source runs. The export, of a configuration that names no scope at all,
// holds every scope's receipts and verifies; it is byte for byte the export
// of a store of the filesystem kind into which the same receipts, payloads
// and registry were written through that kind's own spaces, and the
// verdicts agree. (Two services' runs differ in their stamps and salts, so
// the filesystem kind is given the rows the PostgreSQL kind holds.)
func TestThePostgresKindServesScopedPlatformsAndExportsWhatTheFilesystemKindWould(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	t.Setenv(envSourceHelper, "1")
	helper := sourceSpec{argv: []string{os.Args[0]}, env: helperEnv}
	scoped := func(scope string) sourceSpec { s := helper; s.scope = scope; return s }
	never := sourceSpec{argv: []string{filepath.Join(dir, "no-such-source")}}
	config, started, server := scopedServiceStart(t, db, dir, map[string]sourceSpec{
		"screening-a": scoped("scope-a"), "screening-b": scoped("scope-b"), "plain": helper, "never": never, "never-b": func() sourceSpec { s := never; s.scope = "scope-b"; return s }(),
	})
	for _, call := range []struct{ path, body string }{
		{"/acquire", `{"session":"s-a","source":"screening-a","scope":"scope-a","arguments":{"q":"acme"}}`},
		{"/acquire", `{"session":"s-a","source":"screening-a","scope":"scope-a","arguments":{"q":"other"}}`},
		{"/acquire", `{"session":"s-b","source":"screening-b","scope":"scope-b","arguments":{"q":"acme"}}`},
		{"/acquire", `{"session":"s-none","source":"plain","arguments":{"q":"acme"}}`},
	} {
		if code, body := post(t, server, call.path, call.body); code != http.StatusOK {
			t.Fatalf("%s %s: %d %v", call.path, call.body, code, body)
		}
	}
	// a session held by one scope, or by none, takes no receipt of another:
	// refused before the source, which names nothing that runs, is started
	for _, tc := range []struct{ session, source, scope string }{
		{"s-a", "never", ``},
		{"s-a", "never-b", `,"scope":"scope-b"`},
		{"s-none", "never-b", `,"scope":"scope-b"`},
	} {
		body := `{"session":"` + tc.session + `","source":"` + tc.source + `"` + tc.scope + `,"arguments":{"q":"acme"}}`
		if code, got := post(t, server, "/acquire", body); code != http.StatusBadRequest || fmt.Sprint(got["error"]) != fmt.Sprintf(refusalOtherScope, tc.session) {
			t.Fatalf("%s: %d %v", body, code, got)
		}
	}
	for _, session := range []string{"s-a", "s-b", "s-none"} {
		if code, body := post(t, server, "/seal", `{"session":"`+session+`"}`); code != http.StatusOK {
			t.Fatalf("seal %s: %d %v", session, code, body)
		}
	}
	// a sealed session is refused as sealed, whatever the scope asking
	if code, got := post(t, server, "/acquire", `{"session":"s-a","source":"never","arguments":{"q":"acme"}}`); code != http.StatusBadRequest || fmt.Sprint(got["error"]) != "session is sealed: s-a" {
		t.Fatalf("an acquisition of no scope into sealed s-a: %d %v", code, got)
	}

	// each scope's rows, as the run-time login reads them in that scope
	c := db.runtimeConn(t)
	for scope, want := range map[string]struct {
		session string
		entries int
	}{"": {"s-none", 1}, "scope-a": {"s-a", 2}, "scope-b": {"s-b", 1}} {
		pgInScopeOn(t, c, pgRowScope(scope), func() {
			if got := pgColumn(t, c, `SELECT name FROM gateway.series`); !slices.Equal(got, []string{want.session}) {
				t.Errorf("scope %q holds the sessions %v", scope, got)
			}
			receipts := pgColumn(t, c, `SELECT data FROM gateway.entries WHERE series = $1`, want.session)
			if len(receipts) != want.entries {
				t.Fatalf("scope %q holds %d receipts", scope, len(receipts))
			}
			for _, receipt := range receipts {
				if names := strings.Contains(receipt, `"scope":"`); names != (scope != "") || scope != "" && !strings.Contains(receipt, `"scope":"`+scope+`"`) {
					t.Errorf("a receipt of scope %q: %s", scope, receipt)
				}
			}
			if n := pgCount(t, c, `SELECT count(*)::int8 FROM gateway.blobs`); n == 0 {
				t.Errorf("scope %q holds no payload", scope)
			}
		})
	}

	t.Chdir(dir)
	pgOut := filepath.Join(dir, "export-postgresql")
	if _, err := exportEngine(config, pgOut, nil); err != nil {
		t.Fatalf("export: %v", err)
	}
	requireExportChecks(t, pgOut)
	verdict := restoredVerdict(t, pgOut, "gateway:test", started.service.publicKey)
	if !bytes.Contains(verdict, []byte(`"ok":true`)) {
		t.Fatalf("the export does not verify: %s", verdict)
	}

	// the same rows, written through the filesystem kind's own spaces
	fsRoot := filepath.Join(dir, "filesystem")
	fsStore, fsRegistry := filepath.Join(fsRoot, "store"), filepath.Join(fsRoot, "registry.jsonl")
	if err := os.Mkdir(fsRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	fsKind := newFsKind(fsLayout{store: fsStore, registry: fsRegistry})
	if err := fsKind.makeStore(); err != nil {
		t.Fatal(err)
	}
	kind := db.open(t, nil)
	for i, scope := range []string{"", "scope-a", "scope-b"} {
		view := kind
		if scope != "" {
			var err error
			if view, err = kind.inScope(scope); err != nil {
				t.Fatal(err)
			}
		}
		cut, err := view.snapshot()
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if err := fsKind.registry().createLog(); err != nil {
				t.Fatal(err)
			}
			if _, err := fsKind.registry().appendRecord(cut.log); err != nil {
				t.Fatal(err)
			}
		}
		for _, series := range cut.series {
			if _, err := fsKind.receipts().makeSeries(series); err != nil {
				t.Fatal(err)
			}
			for _, entry := range cut.entries[series] {
				data, err := cut.entry(series, entry)
				if err != nil {
					t.Fatal(err)
				}
				index, err := strconv.ParseInt(entry, 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				if err := fsKind.receipts().createIndexed(series, index, data); err != nil {
					t.Fatal(err)
				}
			}
		}
		for _, blob := range cut.blobs {
			data, err := cut.blob(blob)
			if err != nil {
				t.Fatal(err)
			}
			if name, err := fsKind.artifacts().putBlob(data); err != nil || name != blob {
				t.Fatalf("the blob %s is %s in the filesystem kind: %v", blob, name, err)
			}
		}
	}
	fsConfig := filepath.Join(dir, "engine-filesystem.json")
	raw, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	storage := `"storage":{"kind":"postgresql","connection":{"file":"` + abs(t, dir, "connection") + `"},"connections":2}`
	if !bytes.Contains(raw, []byte(storage)) {
		t.Fatal("the configuration's storage member is not where the test looks")
	}
	raw = bytes.Replace(raw, []byte(storage), []byte(`"store":"`+abs(t, fsStore)+`","registry":"`+abs(t, fsRegistry)+`"`), 1)
	if err := os.WriteFile(fsConfig, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	fsOut := filepath.Join(dir, "export-filesystem")
	if _, err := exportEngine(fsConfig, fsOut, nil); err != nil {
		t.Fatalf("export of the filesystem kind: %v", err)
	}
	want := readTreeBytes(t, fsOut)
	if len(want) == 0 {
		t.Fatal("the filesystem kind's export is empty: the test tests nothing")
	}
	requireSameTree(t, "postgresql", readTreeBytes(t, pgOut), want)
	if live := verdictBytes(t, fsStore, fsRegistry, "gateway:test", abs(t, dir, "decisions"), started.service.publicKey); !bytes.Equal(live, verdict) {
		t.Fatalf("the verdicts differ:\nfilesystem: %s\npostgresql: %s", live, verdict)
	}
}

// What the start asks of the store, it asks of every scope: a store whose
// one session is of a scope identifier, beside no registry, is a start
// refused, though no source of the gateway is of that scope; a session an
// earlier process left open in a scope is continued by no acquisition, of
// its scope or of another, nor sealed from a count.
func TestThePostgresStartAsksEveryScopeOfTheSessionsItHolds(t *testing.T) {
	kind, _ := pgTestKind(t, "", nil)
	views, err := kind.scopeViews([]string{"scope-a"})
	if err != nil {
		t.Fatal(err)
	}
	a := views["scope-a"]
	stampSession(t, newStoreOn("", a.artifacts(), a.receipts(), testSeed, "gateway:test"), "left-1", 1)
	t.Setenv(envSourceHelper, "1")
	helper := sourceSpec{argv: []string{os.Args[0]}, env: helperEnv}
	if _, err := newGatewayServiceOn(kind, testSeed, "gateway:test", map[string]sourceSpec{"plain": helper}); err == nil || !strings.Contains(err.Error(), "the store holds sessions and the registry is not there: "+pgRegistryName) {
		t.Fatalf("no registry beside a session of a scope: %v", err)
	}
	if err := kind.registry().createLog(); err != nil {
		t.Fatal(err)
	}
	scopedA := helper
	scopedA.scope = "scope-a"
	service, err := newGatewayServiceOn(kind, testSeed, "gateway:test", map[string]sourceSpec{"plain": helper, "screening-a": scopedA})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(service.handler())
	t.Cleanup(server.Close)
	for _, tc := range []struct{ path, body, want string }{
		{"/acquire", `{"session":"left-1","source":"screening-a","scope":"scope-a","arguments":{"q":"acme"}}`, fmt.Sprintf(refusalLeftOpen, "left-1")},
		{"/acquire", `{"session":"left-1","source":"plain","arguments":{"q":"acme"}}`, fmt.Sprintf(refusalOtherScope, "left-1")},
		{"/seal", `{"session":"left-1"}`, fmt.Sprintf(refusalLeftOpen, "left-1")},
	} {
		if code, body := post(t, server, tc.path, tc.body); code == http.StatusOK || fmt.Sprint(body["error"]) != tc.want {
			t.Fatalf("%s %s: %d %v", tc.path, tc.body, code, body)
		}
	}
	// a session of no name held yet is the scope's to begin
	if code, body := post(t, server, "/acquire", `{"session":"new-1","source":"screening-a","scope":"scope-a","arguments":{"q":"acme"}}`); code != http.StatusOK {
		t.Fatalf("a new session of scope a: %d %v", code, body)
	}
}

// A store at schema version 2 holding rows migrates to version 3 with every
// row as it was, a row of no scope that no scope's view reads, and no scope
// identifier recorded; the run-time role is given SELECT and INSERT on the
// record alone; a second run applies nothing and changes nothing.
func TestAPostgresStoreAtSchemaTwoMigratesWithItsRowsOfNoScope(t *testing.T) {
	db := newPgTestDB(t)
	set := pgShippedMigrations()
	if len(set.versions) != 3 {
		t.Fatalf("the shipped schema has %d versions: the test names version 2 as the one before", len(set.versions))
	}
	older := pgMigrationSet{versions: set.versions[:2], grants: bytes.Replace(set.grants, []byte(", gateway.scope_identifiers"), nil, 1)}
	if bytes.Equal(older.grants, set.grants) {
		t.Fatal("the grants name no record of the scope identifiers: the test tests nothing")
	}
	if applied, err := migratePostgres(db.migrator, older, db.roles, time.Minute); err != nil || !slices.Equal(applied, []int{1, 2}) {
		t.Fatalf("schema version 2: %v %v", applied, err)
	}
	c := db.runtimeConn(t)
	if err := c.script("BEGIN"); err != nil {
		t.Fatal(err)
	}
	blob := "sha256:" + strings.Repeat("3", 64)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`SELECT pg_catalog.set_config('gateway.scope', 'none', true)`, nil},
		{`INSERT INTO gateway.series (scope, name) VALUES ('none', 'before-3')`, nil},
		{`INSERT INTO gateway.entries (scope, series, name, data) VALUES ('none', 'before-3', '0', 'receipt')`, nil},
		{`INSERT INTO gateway.blobs (scope, name, data) VALUES ('none', $1, 'payload')`, []any{blob}},
		{`INSERT INTO gateway.documents (scope, name, revision, data) VALUES ('none', 'doc', $1, 'document')`, []any{strings.Repeat("0", 32)}},
		{`INSERT INTO gateway.logs (name) VALUES ('registry')`, nil},
		{`INSERT INTO gateway.log_records (log, start, data) VALUES ('registry', 0, 'line')`, nil},
	} {
		if _, err := c.exec(statement.query, statement.args...); err != nil {
			t.Fatalf("%s: %v", statement.query, err)
		}
	}
	if err := c.script("COMMIT"); err != nil {
		t.Fatal(err)
	}
	if applied, err := migratePostgres(db.migrator, set, db.roles, time.Minute); err != nil || !slices.Equal(applied, []int{3}) {
		t.Fatalf("from schema version 2: %v %v", applied, err)
	}
	first := db.fingerprint(t)
	kind := db.open(t, nil)
	cut, err := kind.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cut.series, []string{"before-3"}) || !slices.Equal(cut.blobs, []string{blob}) || string(cut.documents["doc"]) != "document" || string(cut.log) != "line" {
		t.Fatalf("the rows of no scope after the migration: %v %v %v %q", cut.series, cut.blobs, cut.documents, cut.log)
	}
	if data, err := cut.entry("before-3", "0"); err != nil || string(data) != "receipt" {
		t.Fatalf("the receipt after the migration: %q %v", data, err)
	}
	every, err := pgEveryScope{kind}.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	requireSameCut(t, "every scope after the migration", every, cut)
	a, err := kind.inScope("scope-a")
	if err != nil {
		t.Fatal(err)
	}
	if names, err := a.receipts().listSeries(); err != nil || len(names) != 0 {
		t.Fatalf("a scope's view after the migration lists %v %v", names, err)
	}
	pgInScopeOn(t, c, pgNoScope, func() {
		if n := pgCount(t, c, `SELECT count(*)::int8 FROM gateway.scope_identifiers`); n != 0 {
			t.Fatalf("the migration recorded %d scope identifiers", n)
		}
	})
	privileges := pgTestQuery(t, db.runtime, `SELECT string_agg(p, ',' ORDER BY p) FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']) p
		WHERE pg_catalog.has_table_privilege('gateway.scope_identifiers', p)`)
	if got := string(privileges.rows[0][0]); got != "INSERT,SELECT" {
		t.Fatalf("the run-time role's privileges on the record: %s", got)
	}
	if applied, err := migratePostgres(db.migrator, set, db.roles, time.Minute); err != nil || len(applied) != 0 {
		t.Fatalf("the second run: %v %v", applied, err)
	}
	if second := db.fingerprint(t); second != first {
		t.Fatalf("the second run changed the database:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}
