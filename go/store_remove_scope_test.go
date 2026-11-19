package main

// `gateway store remove-scope` (store_remove_scope.go).

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func runStoreRemoveScope(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := cmdStoreRemoveScopeAt(args, &stdout, &stderr, func() string { return "2026-11-15T12:00:00Z" })
	return code, stdout.String(), stderr.String()
}

// The command is refused, before anything is read, unless it names one
// reference to the connection string, both roles, the seed, a scope
// identifier and a label; gateway store dispatches it.
func TestTheStoreRemoveScopeCommandLine(t *testing.T) {
	file := filepath.Join(t.TempDir(), "connection")
	full := []string{"--connection-file", file, "--owner", "o", "--runtime", "r", "--seed", "s", "--scope", "scope-a", "--by", "operator-1"}
	without := func(flag string) []string {
		var out []string
		for i := 0; i < len(full); i += 2 {
			if full[i] != flag {
				out = append(out, full[i], full[i+1])
			}
		}
		return out
	}
	for _, args := range [][]string{
		{},
		without("--connection-file"),
		append(without("--connection-file"), "--connection-env", "X", "--connection-file", file),
		without("--owner"),
		without("--runtime"),
		without("--seed"),
		without("--scope"),
		without("--by"),
		append(without("--by"), "--by", "operator\n1"),
		append(without("--scope"), "--scope", ""),
		append(without("--scope"), "--scope", "a\tb"),
		append(slices.Clone(full), "--timeout", "0"),
		append(slices.Clone(full), "--scope", "scope-b"),
		append(slices.Clone(full), "--store", "x"),
	} {
		if code, stdout, stderr := runStoreRemoveScope(args...); code != 2 || stdout != "" || !strings.Contains(stderr, "usage:") {
			t.Errorf("%q: %d %q %q", args, code, stdout, stderr)
		}
	}
	if code, _, stderr := runStore("remove-scope"); code != 2 || !strings.Contains(stderr, "gateway store remove-scope (") {
		t.Fatalf("gateway store remove-scope: %d %q", code, stderr)
	}
	if code, _, stderr := runStore("remove"); code != 2 || !strings.Contains(stderr, "gateway store migrate (") || !strings.Contains(stderr, "gateway store remove-scope (") {
		t.Fatalf("gateway store remove: %d %q", code, stderr)
	}
}

// pgRuntimeGrants are the run-time role's privileges on each table of the
// schema, read from the server's catalog in the store's database.
func pgRuntimeGrants(t *testing.T, db *pgTestDB) map[string][]string {
	t.Helper()
	rows, err := db.runtimeConn(t).exec(`SELECT c.relname, p.privilege_type FROM pg_catalog.pg_class c
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'gateway'
		CROSS JOIN LATERAL (SELECT a.privilege_type FROM pg_catalog.aclexplode(c.relacl) a
			JOIN pg_catalog.pg_roles r ON r.oid = a.grantee WHERE r.rolname = $1) p
		WHERE c.relkind = 'r' ORDER BY 1, 2`, db.roles.runtime)
	if err != nil {
		t.Fatal(err)
	}
	grants := map[string][]string{}
	for _, row := range rows.rows {
		grants[string(row[0])] = append(grants[string(row[0])], string(row[1]))
	}
	return grants
}

// A service of two scope identifiers and of none on the PostgreSQL kind:
// while it serves, the removal of one scope is refused and nothing changes.
// Once it stops, the removal takes that scope's rows -- a sealed session,
// an open one, their receipts and their payload -- and its row of the scope
// identifiers, and keeps a session-removal record for the sealed session
// and a scope-removal record for the call, which it prints. The other
// scope and no scope keep every row. The export writes the records as the
// store's removal file and verifies, the sealed session read as removed;
// the scope identifier is then in the export's store and registry only in
// that file. A second run removes nothing; the gateway starts again on the
// store; and the run-time role's privileges are what they were, with no
// DELETE on a table but documents.
func TestPostgresRemoveScopeRemovesOneScopesRowsAndRecordsIt(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	grants := pgRuntimeGrants(t, db)
	if len(grants) != len(pgPrivileges) || !slices.Equal(grants["removal_records"], []string{"SELECT"}) {
		t.Fatalf("the run-time role's grants read %v", grants)
	}
	dir := tempDirAt(t, 0o700)
	t.Setenv(envSourceHelper, "1")
	helper := sourceSpec{argv: []string{os.Args[0]}, env: helperEnv}
	scoped := func(scope string) sourceSpec { s := helper; s.scope = scope; return s }
	sources := map[string]sourceSpec{"screening-a": scoped("scope-a"), "screening-b": scoped("scope-b"), "plain": helper}
	config, started, server := scopedServiceStart(t, db, dir, sources)
	for _, body := range []string{
		`{"session":"s-a","source":"screening-a","scope":"scope-a","arguments":{"q":"acme"}}`,
		`{"session":"s-a","source":"screening-a","scope":"scope-a","arguments":{"q":"other"}}`,
		`{"session":"s-a-open","source":"screening-a","scope":"scope-a","arguments":{"q":"third"}}`,
		`{"session":"s-b","source":"screening-b","scope":"scope-b","arguments":{"q":"acme"}}`,
		`{"session":"s-none","source":"plain","arguments":{"q":"acme"}}`,
	} {
		if code, got := post(t, server, "/acquire", body); code != http.StatusOK {
			t.Fatalf("%s: %d %v", body, code, got)
		}
	}
	for _, session := range []string{"s-a", "s-b", "s-none"} {
		if code, got := post(t, server, "/seal", `{"session":"`+session+`"}`); code != http.StatusOK {
			t.Fatalf("seal %s: %d %v", session, code, got)
		}
	}
	connection := writeConnection(t, db.migrator)
	seed := filepath.Join(dir, "gateway.seed")
	remove := func() (int, string, string) {
		return runStoreRemoveScope("--connection-file", connection, "--owner", db.roles.owner, "--runtime", db.roles.runtime,
			"--seed", seed, "--scope", "scope-a", "--by", "operator-1", "--timeout", "60")
	}

	// refused while the gateway serves
	before := db.fingerprint(t)
	code, stdout, stderr := remove()
	if code != 1 || stdout != "" || !strings.HasPrefix(stderr, "store remove-scope: start-lease-held: a gateway instance serves the database") ||
		!strings.HasSuffix(stderr, "; stop the gateway, then remove; nothing was removed\n") || strings.Contains(stderr, "scope-a") {
		t.Fatalf("while the gateway serves: %d %q %q", code, stdout, stderr)
	}
	if db.fingerprint(t) != before {
		t.Fatal("a refused removal changed the database")
	}
	var said bytes.Buffer
	started.stop(&said)
	server.Close()

	code, stdout, stderr = remove()
	if code != 0 || stderr != "store remove-scope: removed 2 session(s), 1 sealed, holding 3 receipt(s), 1 payload(s), and 0 document(s)\n" {
		t.Fatalf("the removal: %d %q %q", code, stdout, stderr)
	}
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"kind":"session-removal"`) || !strings.Contains(lines[0], `"sessionId":"s-a"`) ||
		!strings.Contains(lines[1], `"kind":"scope-removal"`) || !strings.Contains(lines[1], `"openSessions":1,"payloads":1,"receipts":3`) ||
		!strings.Contains(lines[1], `"sealedSessions":1`) {
		t.Fatalf("the records printed: %q", stdout)
	}

	c := db.runtimeConn(t)
	pgInScopeOn(t, c, pgRowScope("scope-a"), func() {
		if n := pgCount(t, c, pgScopedRowCount); n != 0 {
			t.Errorf("scope-a holds %d rows", n)
		}
	})
	pgInScopeOn(t, c, pgRowScope("scope-b"), func() {
		if got := pgColumn(t, c, `SELECT name FROM gateway.series`); !slices.Equal(got, []string{"s-b"}) {
			t.Errorf("scope-b holds the sessions %v", got)
		}
		if n := pgCount(t, c, `SELECT count(*)::int8 FROM gateway.entries`); n != 1 {
			t.Errorf("scope-b holds %d receipts", n)
		}
	})
	pgInScopeOn(t, c, pgNoScope, func() {
		if got := pgColumn(t, c, `SELECT identifier FROM gateway.scope_identifiers ORDER BY identifier`); !slices.Equal(got, []string{pgRowScope("scope-b")}) {
			t.Errorf("the scope identifiers recorded: %v", got)
		}
		if got := pgColumn(t, c, `SELECT name FROM gateway.series`); !slices.Equal(got, []string{"s-none"}) {
			t.Errorf("no scope holds the sessions %v", got)
		}
		if got := pgColumn(t, c, `SELECT line FROM gateway.removal_records ORDER BY ordinal`); strings.Join(got, "\n")+"\n" != stdout {
			t.Errorf("the records kept: %q", got)
		}
	})

	t.Chdir(dir)
	out := filepath.Join(dir, "export")
	if _, err := exportEngine(config, out, nil, ""); err != nil {
		t.Fatalf("export: %v", err)
	}
	requireExportChecks(t, out)
	if file := readFile(t, filepath.Join(out, "store", removalsFile)); file != stdout {
		t.Fatalf("the export's removal file: %q", file)
	}
	rep, err := verifyWithRegistry(filepath.Join(out, "store"), filepath.Join(out, "registry"), "gateway:test", started.service.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	var observed []string
	for _, o := range rep.Observations {
		observed = append(observed, o["sessionId"].(string)+" "+o["observation"].(string))
	}
	if !rep.OK || strings.Join(observed, ",") != "s-a "+observationSessionRemoved {
		t.Fatalf("the export's verdict: ok %v, observations %v, findings %v", rep.OK, observed, rep.Findings)
	}
	if held := filesOutside(filesHolding(t, out, "scope-a"), "decision-records/"); !slices.Equal(held, []string{"store/" + removalsFile}) {
		t.Fatalf("the scope identifier is in the export's %v", held)
	}

	// a second run removes nothing and keeps no record
	if code, stdout, stderr := remove(); code != 0 || stdout != "" || stderr != "store remove-scope: no row of the scope identifier is in the store; nothing was removed\n" {
		t.Fatalf("a second run: %d %q %q", code, stdout, stderr)
	}
	// the gateway starts again on the store, and the run-time role holds
	// what it held, no DELETE on a table but documents
	cfg, err := parseEngineConfig([]byte(readFile(t, config)))
	if err != nil {
		t.Fatal(err)
	}
	again, err := startEngineOnKind(cfg, testSeed, sources, nil, &said)
	if err != nil {
		t.Fatalf("the start after the removal: %v", err)
	}
	again.stop(&said)
	after := pgRuntimeGrants(t, db)
	if len(after) != len(grants) {
		t.Fatalf("the run-time role's grants: %v, before %v", after, grants)
	}
	for table, privileges := range after {
		if !slices.Equal(privileges, grants[table]) {
			t.Errorf("the run-time role holds %v on %s, and held %v", privileges, table, grants[table])
		}
		if table != "documents" && (slices.Contains(privileges, "DELETE") || slices.Contains(privileges, "TRUNCATE")) {
			t.Errorf("the run-time role holds %v on %s", privileges, table)
		}
	}
	if !slices.Equal(after["removal_records"], []string{"SELECT"}) {
		t.Errorf("the run-time role holds %v on removal_records", after["removal_records"])
	}
}

// Each DELETE is held to the count read before the records were signed: a
// row of the scope that goes between the read and the DELETE -- here a
// document a second connection removes, its row locked before the read and
// its removal committed while the DELETE waits for it -- refuses the call,
// and the transaction rolls back: every other row of the scope, its row of
// the scope identifiers, and no record, as they were.
func TestPostgresRemoveScopeRefusesRowsThatChangeWhileItRemoves(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	t.Setenv(envSourceHelper, "1")
	helper := sourceSpec{argv: []string{os.Args[0]}, env: helperEnv, scope: "scope-a"}
	_, started, server := scopedServiceStart(t, db, dir, map[string]sourceSpec{"screening-a": helper})
	if code, got := post(t, server, "/acquire", `{"session":"s-a","source":"screening-a","scope":"scope-a","arguments":{"q":"acme"}}`); code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, got)
	}
	if code, got := post(t, server, "/seal", `{"session":"s-a"}`); code != http.StatusOK {
		t.Fatalf("seal: %d %v", code, got)
	}
	var said bytes.Buffer
	started.stop(&said)
	server.Close()

	row := pgRowScope("scope-a")
	other := db.runtimeConn(t)
	if err := other.script("BEGIN"); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		query string
		args  []any
	}{
		{`SELECT pg_catalog.set_config('gateway.scope', $1, true)`, []any{row}},
		{`INSERT INTO gateway.documents (scope, name, revision, data) VALUES ($1, 'held', repeat('0', 32), '\x00'::bytea)`, []any{row}},
	} {
		if _, err := other.exec(step.query, step.args...); err != nil {
			t.Fatalf("%s: %v", step.query, err)
		}
	}
	if err := other.script("COMMIT"); err != nil {
		t.Fatal(err)
	}
	c := db.runtimeConn(t)
	scopeRows := func() int64 {
		var n int64
		pgInScopeOn(t, c, row, func() { n = pgCount(t, c, pgScopedRowCount) })
		return n
	}
	before := scopeRows()

	// the document's row locked, its removal not yet committed
	if err := other.script("BEGIN"); err != nil {
		t.Fatal(err)
	}
	if _, err := other.exec(`SELECT pg_catalog.set_config('gateway.scope', $1, true)`, row); err != nil {
		t.Fatal(err)
	}
	if done, err := other.exec(`DELETE FROM gateway.documents WHERE scope = $1 AND name = 'held'`, row); err != nil || done.tag != "DELETE 1" {
		t.Fatalf("the second connection's DELETE: %v %v", done.tag, err)
	}
	type result struct {
		code           int
		stdout, stderr string
	}
	finished := make(chan result, 1)
	connection := writeConnection(t, db.migrator)
	go func() {
		code, stdout, stderr := runStoreRemoveScope("--connection-file", connection, "--owner", db.roles.owner, "--runtime", db.roles.runtime,
			"--seed", filepath.Join(dir, "gateway.seed"), "--scope", "scope-a", "--by", "operator-1", "--timeout", "60")
		finished <- result{code, stdout, stderr}
	}()
	// the removal's DELETE waits for the second connection's transaction
	waiting := `SELECT count(*)::int8 FROM pg_catalog.pg_locks w JOIN pg_catalog.pg_locks h
		ON h.locktype = 'transactionid' AND h.transactionid = w.transactionid AND h.granted AND h.pid = pg_catalog.pg_backend_pid()
		WHERE w.locktype = 'transactionid' AND NOT w.granted`
	for deadline := time.Now().Add(30 * time.Second); pgCount(t, other, waiting) == 0; {
		if time.Now().After(deadline) {
			other.script("ROLLBACK")
			t.Fatalf("the removal never waited for the locked row: %+v", <-finished)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := other.script("COMMIT"); err != nil {
		t.Fatal(err)
	}
	got := <-finished
	if got.code != 1 || got.stdout != "" || got.stderr != "store remove-scope: the scope's rows changed while they were removed; nothing was removed\n" {
		t.Fatalf("the removal: %d %q %q", got.code, got.stdout, got.stderr)
	}
	if after := scopeRows(); after != before-1 {
		t.Fatalf("the scope holds %d rows, and held %d with the document the second connection removed", after, before)
	}
	pgInScopeOn(t, c, pgNoScope, func() {
		if n := pgCount(t, c, `SELECT count(*)::int8 FROM gateway.removal_records`); n != 0 {
			t.Errorf("%d record(s) kept", n)
		}
		if got := pgColumn(t, c, `SELECT identifier FROM gateway.scope_identifiers`); !slices.Equal(got, []string{row}) {
			t.Errorf("the scope identifiers recorded: %v", got)
		}
	})
}

// filesOutside are the paths not under prefix.
func filesOutside(paths []string, prefix string) []string {
	var out []string
	for _, p := range paths {
		if !strings.HasPrefix(p, prefix) {
			out = append(out, p)
		}
	}
	return out
}

// The removal holds the store to its conditions: a schema not raised to
// this gateway's, the run-time login, and a store with no registry yet are
// each refused by name, and change nothing.
func TestPostgresRemoveScopeRefusesWhatItCannotHold(t *testing.T) {
	db := newPgTestDB(t)
	dir := tempDirAt(t, 0o700)
	seed := filepath.Join(dir, "gateway.seed")
	if err := os.WriteFile(seed, []byte(strings.Repeat("ab", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	remove := func(login pgDSN, scope string) (int, string, string) {
		return runStoreRemoveScope("--connection-file", writeConnection(t, login), "--owner", db.roles.owner, "--runtime", db.roles.runtime,
			"--seed", seed, "--scope", scope, "--by", "operator-1")
	}
	// a schema not migrated at all is refused
	if code, stdout, stderr := remove(db.migrator, "scope-a"); code != 1 || stdout != "" || !strings.Contains(stderr, "gateway store migrate raises it first") {
		t.Fatalf("an empty database: %d %q %q", code, stdout, stderr)
	}
	db.migrate(t)
	// the run-time login is refused as the migration refuses it
	before := db.fingerprint(t)
	if code, _, stderr := remove(db.runtime, "scope-a"); code != 1 || !strings.Contains(stderr, "the migration login is neither the owner role nor the run-time role") {
		t.Fatalf("the run-time login: %d %q", code, stderr)
	}
	// a store whose registry is not there yet is refused
	if code, _, stderr := remove(db.migrator, "scope-a"); code != 1 || !strings.Contains(stderr, "the registry is not there") {
		t.Fatalf("no registry: %d %q", code, stderr)
	}
	if db.fingerprint(t) != before {
		t.Fatal("a refused removal changed the database")
	}
}

// keptRemovalsKind is a kind that keeps removal records itself, as the
// PostgreSQL kind does, on the memory kind.
type keptRemovalsKind struct {
	storeKind
	file []byte
}

func (k keptRemovalsKind) snapshot() (*storeCut, error) {
	cut, err := k.storeKind.snapshot()
	if err != nil {
		return nil, err
	}
	cut.removals = func() ([]byte, bool, error) { return k.file, len(k.file) > 0, nil }
	return cut, nil
}

// An export writes the removal records a kind keeps as the store's removal
// file; a kind that keeps none beside a store directory holding the file
// writes the file; and a kind that keeps some beside a store directory
// that holds a file is refused, before the decision records are read: the
// export takes neither for the other.
func TestAnExportWritesTheRemovalRecordsTheKindKeepsAndRefusesTwoSources(t *testing.T) {
	kept := []byte(`{"kind":"kept"}` + "\n")
	onDisk := []byte(`{"kind":"on-disk"}` + "\n")
	storeRoot := t.TempDir()
	export := func(file []byte, root string) (string, error) {
		out := filepath.Join(t.TempDir(), "export")
		_, err := writeExport(exportInputs{authority: "gateway:test", kind: keptRemovalsKind{newMemoryKind(nil), file}, storeRoot: root}, out)
		if err != nil {
			return "", err
		}
		data, err := os.ReadFile(filepath.Join(out, "store", removalsFile))
		if os.IsNotExist(err) {
			return "", nil
		}
		return string(data), err
	}
	if got, err := export(kept, ""); err != nil || got != string(kept) {
		t.Fatalf("the kind's records: %q %v", got, err)
	}
	if got, err := export(nil, ""); err != nil || got != "" {
		t.Fatalf("no records: %q %v", got, err)
	}
	if err := os.WriteFile(filepath.Join(storeRoot, removalsFile), onDisk, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := export(nil, storeRoot); err != nil || got != string(onDisk) {
		t.Fatalf("the file beside a kind that keeps none: %q %v", got, err)
	}
	if _, err := export(kept, storeRoot); err == nil || !strings.Contains(err.Error(), "the export takes neither for the other") {
		t.Fatalf("records in the kind and a file beside it: %v", err)
	}
}

// hookedCut is a kind whose cut runs a step once, before the export's first
// read of a receipt's bytes, of a payload's, or of the removal records:
// where an export and a removal of a scope identifier, which take no lock
// in common, may interleave.
type hookedCut struct {
	storeKind
	beforeEntry, beforeBlob, beforeRemovals func()
}

func (k hookedCut) snapshot() (*storeCut, error) {
	cut, err := k.storeKind.snapshot()
	if err != nil {
		return nil, err
	}
	once := func(step func()) func() {
		done := step == nil
		return func() {
			if !done {
				done = true
				step()
			}
		}
	}
	entry, blob, removals := cut.entry, cut.blob, cut.removals
	onEntry, onBlob, onRemovals := once(k.beforeEntry), once(k.beforeBlob), once(k.beforeRemovals)
	cut.entry = func(series, name string) ([]byte, error) { onEntry(); return entry(series, name) }
	cut.blob = func(name string) ([]byte, error) { onBlob(); return blob(name) }
	cut.removals = func() ([]byte, bool, error) { onRemovals(); return removals() }
	return cut, nil
}

// An export of the PostgreSQL kind that gateway store remove-scope runs
// beside: a removal committed after the cut's snapshot and before the
// export reads a receipt or a payload the cut listed refuses the export,
// before its manifest, rather than writing a removed session's receipts
// without their payloads, which would verify as damage; one committed after
// every byte was read leaves the export of the cut, which verifies, its
// removal records read in the cut's snapshot and so none.
func TestPostgresAnExportDuringAScopeRemovalRefusesOrHoldsTheCut(t *testing.T) {
	for _, at := range []string{"receipts", "payloads", "records"} {
		t.Run(at, func(t *testing.T) {
			db := newPgTestDB(t)
			db.migrate(t)
			dir := tempDirAt(t, 0o700)
			t.Setenv(envSourceHelper, "1")
			helper := sourceSpec{argv: []string{os.Args[0]}, env: helperEnv, scope: "scope-a"}
			config, started, server := scopedServiceStart(t, db, dir, map[string]sourceSpec{"screening-a": helper})
			for _, body := range []string{
				`{"session":"s-a","source":"screening-a","scope":"scope-a","arguments":{"q":"acme"}}`,
				`{"session":"s-a","source":"screening-a","scope":"scope-a","arguments":{"q":"other"}}`,
			} {
				if code, got := post(t, server, "/acquire", body); code != http.StatusOK {
					t.Fatalf("%s: %d %v", body, code, got)
				}
			}
			if code, got := post(t, server, "/seal", `{"session":"s-a"}`); code != http.StatusOK {
				t.Fatalf("seal: %d %v", code, got)
			}
			publicKey := started.service.publicKey
			var said bytes.Buffer
			started.stop(&said)
			server.Close()

			connection := writeConnection(t, db.migrator)
			removed := false
			remove := func() {
				code, stdout, stderr := runStoreRemoveScope("--connection-file", connection, "--owner", db.roles.owner, "--runtime", db.roles.runtime,
					"--seed", filepath.Join(dir, "gateway.seed"), "--scope", "scope-a", "--by", "operator-1", "--timeout", "60")
				if code != 0 || !strings.Contains(stdout, `"kind":"scope-removal"`) {
					t.Fatalf("the removal: %d %q %q", code, stdout, stderr)
				}
				removed = true
			}
			cfg, err := parseEngineConfig([]byte(readFile(t, config)))
			if err != nil {
				t.Fatal(err)
			}
			pg, err := openStorageKind(cfg.storage)
			if err != nil {
				t.Fatal(err)
			}
			defer pg.close()
			kind := hookedCut{storeKind: pgEveryScope{pg}}
			switch at {
			case "receipts":
				kind.beforeEntry = remove
			case "payloads":
				kind.beforeBlob = remove
			case "records":
				kind.beforeRemovals = remove
			}
			out := filepath.Join(dir, "export")
			_, err = writeExport(exportInputs{authority: "gateway:test", keyID: keyIDFor(publicKey), publicKey: publicKey, kind: kind}, out)
			if !removed {
				t.Fatalf("no removal ran: %v", err)
			}
			if at != "records" {
				if err == nil || !strings.Contains(err.Error(), "was removed while the export read it (gateway store remove-scope ran during the export)") {
					t.Fatalf("an export across the removal: %v", err)
				}
				if _, statErr := os.Lstat(filepath.Join(out, exportManifestName)); !os.IsNotExist(statErr) {
					t.Fatalf("the refused export holds a manifest: %v", statErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("an export whose every byte was read before the removal: %v", err)
			}
			requireExportChecks(t, out)
			if _, statErr := os.Lstat(filepath.Join(out, "store", removalsFile)); !os.IsNotExist(statErr) {
				t.Fatalf("the export holds a removal file the cut did not: %v", statErr)
			}
			rep, err := verifyWithRegistry(filepath.Join(out, "store"), filepath.Join(out, "registry"), "gateway:test", publicKey)
			if err != nil {
				t.Fatal(err)
			}
			if !rep.OK || len(rep.Observations) != 0 {
				t.Fatalf("the export's verdict: ok %v, observations %v, findings %v", rep.OK, rep.Observations, rep.Findings)
			}
		})
	}
}
