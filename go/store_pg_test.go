package main

// The conditions the PostgreSQL storage kind runs under, each held on a
// server (store_pg_harness_test.go): the roles, the schema's migrations,
// row security keyed on the transaction's scope identifier, append-only
// tables by privilege, and the kind's start, which refuses a database
// outside them. Each test skips without a server.

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// runtimeConn is a connection as the run-time login, outside the kind.
func (db *pgTestDB) runtimeConn(t testing.TB) *pgConn {
	t.Helper()
	c, err := pgConnect(db.runtime, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.close)
	return c
}

// fingerprint is the database's schema, its roles' attributes, memberships
// and settings, and its migrations' records, as lines read by the admin
// login: two reads that differ in nothing the migration could change read
// the same.
func (db *pgTestDB) fingerprint(t testing.TB) string {
	t.Helper()
	c, err := pgConnect(db.inDB, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	if err := c.script("BEGIN; SET LOCAL search_path = pg_catalog"); err != nil {
		t.Fatal(err)
	}
	// the admin login reads the migrations' records where it may: a
	// superuser always, as in the CI job
	migrations := `SELECT NULL::text WHERE false`
	if rows, err := c.exec(`SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'gateway' AND c.relname = 'schema_migrations'
		AND has_table_privilege(c.oid, 'SELECT')`); err == nil && len(rows.rows) == 1 {
		migrations = `SELECT 'migration ' || version || ' ' || name || ' ' || digest FROM gateway.schema_migrations`
	} else if err != nil {
		t.Fatal(err)
	}
	rows, err := c.exec(`SELECT coalesce(string_agg(line, E'\n' ORDER BY line), '') FROM (
		SELECT 'class ' || c.relname || ' ' || c.relkind::text || ' ' || pg_get_userbyid(c.relowner) || ' ' || coalesce(c.relacl::text, '') || ' ' || c.relrowsecurity || ' ' || c.relforcerowsecurity AS line
			FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'gateway'
		UNION ALL SELECT 'column ' || c.relname || '.' || a.attname || ' ' || format_type(a.atttypid, a.atttypmod) || ' ' || a.attnotnull || ' ' || a.attgenerated::text || ' ' || coalesce(a.attacl::text, '')
			FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'gateway' AND a.attnum > 0 AND NOT a.attisdropped
		UNION ALL SELECT 'constraint ' || o.conname || ' ' || pg_get_constraintdef(o.oid) FROM pg_constraint o JOIN pg_namespace n ON n.oid = o.connamespace WHERE n.nspname = 'gateway'
		UNION ALL SELECT 'index ' || pg_get_indexdef(i.indexrelid) FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'gateway'
		UNION ALL SELECT 'policy ' || tablename || ' ' || policyname || ' ' || permissive || ' ' || cmd || ' ' || roles::text || ' ' || coalesce(qual, '') || ' ' || coalesce(with_check, '') FROM pg_policies WHERE schemaname = 'gateway'
		UNION ALL SELECT 'schema ' || nspname || ' ' || pg_get_userbyid(nspowner) || ' ' || coalesce(nspacl::text, '') FROM pg_namespace
		UNION ALL SELECT 'function ' || p.oid::regprocedure::text FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
		UNION ALL SELECT 'role ' || rolname || ' ' || rolsuper || rolinherit || rolcreaterole || rolcreatedb || rolcanlogin || rolreplication || rolbypassrls FROM pg_roles
		UNION ALL SELECT 'member ' || pg_get_userbyid(roleid) || ' ' || pg_get_userbyid(member) || ' ' || admin_option || inherit_option || set_option FROM pg_auth_members
		UNION ALL SELECT 'setting ' || setdatabase || ' ' || setrole || ' ' || array_to_string(setconfig, ',') FROM pg_db_role_setting
		UNION ALL SELECT 'database ' || datname || ' ' || pg_get_userbyid(datdba) || ' ' || coalesce(datacl::text, '') FROM pg_database WHERE datname = current_database()
		UNION ALL ` + migrations + `) lines`)
	if err != nil {
		t.Fatal(err)
	}
	c.script("ROLLBACK")
	return string(rows.rows[0][0])
}

// The migration applies the schema once: a second run applies nothing and
// changes nothing, and neither run makes a role, changes one, or stores a
// setting on a role or on the database.
func TestAPostgresMigrationRunTwiceChangesNothing(t *testing.T) {
	db := newPgTestDB(t)
	before := db.fingerprint(t)
	applied, err := migratePostgres(db.migrator, pgShippedMigrations(), db.roles, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(applied, []int{1}) {
		t.Fatalf("the first run applied %v", applied)
	}
	first := db.fingerprint(t)
	if first == before {
		t.Fatal("the first run changed nothing: the test tests nothing")
	}
	lines := func(text, prefix string) []string {
		var out []string
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, prefix) {
				out = append(out, line)
			}
		}
		return out
	}
	for _, prefix := range []string{"role ", "member ", "setting ", "database ", "function "} {
		if !slices.Equal(lines(before, prefix), lines(first, prefix)) {
			t.Errorf("the migration changed the %q lines:\nbefore: %v\nafter:  %v", prefix, lines(before, prefix), lines(first, prefix))
		}
	}
	applied, err = migratePostgres(db.migrator, pgShippedMigrations(), db.roles, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 0 {
		t.Fatalf("the second run applied %v", applied)
	}
	if second := db.fingerprint(t); second != first {
		t.Fatalf("the second run changed the database:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
	db.open(t, nil)
}

// A migration file changed after it was applied is refused by its digest,
// by the migration and by the kind's start alike, and nothing is applied;
// so is a schema newer than the binary, and a record changed in place.
func TestAPostgresMigrationChangedOnceAppliedIsRefused(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	shipped := pgShippedMigrations()
	changed := shipped
	changed.versions = slices.Clone(shipped.versions)
	changed.versions[0].sql = append(bytes.Clone(changed.versions[0].sql), "\n-- a line added after the file was applied\n"...)
	before := db.fingerprint(t)
	if _, err := migratePostgres(db.migrator, changed, db.roles, time.Minute); err == nil || !strings.Contains(err.Error(), "never changed once applied") {
		t.Fatalf("a migration changed once applied: %v", err)
	}
	if after := db.fingerprint(t); after != before {
		t.Fatalf("a refused migration changed the database:\n%s\n%s", before, after)
	}
	view := &pgKind{pool: newPgPool(db.runtime, 1), operation: pgDefaultOperation, clock: time.Now}
	defer view.close()
	if err := view.holdsItsConditions(changed); err == nil || !strings.Contains(err.Error(), "never changed once applied") {
		t.Fatalf("the start on a migration changed once applied: %v", err)
	}
	if err := view.holdsItsConditions(shipped); err != nil {
		t.Fatalf("the start on the schema as applied: %v", err)
	}

	t.Run("a schema newer than the binary", func(t *testing.T) {
		db := newPgTestDB(t)
		db.migrate(t)
		db.asOwner(t, "INSERT INTO gateway.schema_migrations VALUES (2, '0002_later.sql', 'sha256:"+strings.Repeat("0", 64)+"')")
		if _, err := migratePostgres(db.migrator, shipped, db.roles, time.Minute); err == nil || !strings.Contains(err.Error(), "older than its schema") {
			t.Fatalf("a migration onto a newer schema: %v", err)
		}
		if _, err := openPgKind(pgOptions{dsn: db.runtime}); err == nil || !strings.Contains(err.Error(), "older than its schema") {
			t.Fatalf("a start on a newer schema: %v", err)
		}
	})
	t.Run("a record changed in place", func(t *testing.T) {
		db := newPgTestDB(t)
		db.migrate(t)
		db.asOwner(t, "UPDATE gateway.schema_migrations SET digest = 'sha256:"+strings.Repeat("0", 64)+"'")
		if _, err := openPgKind(pgOptions{dsn: db.runtime}); err == nil || !strings.Contains(err.Error(), "never changed once applied") {
			t.Fatalf("a start on a changed record: %v", err)
		}
	})
}

// The migration runs only with the roles held to their conditions, and on
// a database where the schema is its own: otherwise it applies nothing.
func TestAPostgresMigrationRefusesRolesOutsideTheirConditions(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, db *pgTestDB) (pgDSN, pgRoles)
		want  string
	}{
		{"an owner that can log in", func(t *testing.T, db *pgTestDB) (pgDSN, pgRoles) {
			db.asAdmin(t, "ALTER ROLE "+db.roles.owner+" LOGIN")
			return db.migrator, db.roles
		}, "can log in"},
		{"a migration login that inherits the owner's privileges", func(t *testing.T, db *pgTestDB) (pgDSN, pgRoles) {
			db.asAdmin(t, "GRANT "+db.roles.owner+" TO "+db.migRole+" WITH INHERIT TRUE")
			return db.migrator, db.roles
		}, "WITH INHERIT FALSE"},
		{"a migration login that cannot SET ROLE to the owner", func(t *testing.T, db *pgTestDB) (pgDSN, pgRoles) {
			db.asAdmin(t, "REVOKE "+db.roles.owner+" FROM "+db.migRole)
			return db.migrator, db.roles
		}, "cannot SET ROLE"},
		{"the run-time login as the migration login", func(t *testing.T, db *pgTestDB) (pgDSN, pgRoles) {
			return db.runtime, db.roles
		}, "neither the owner role nor the run-time role"},
		{"a run-time role that reaches the owner", func(t *testing.T, db *pgTestDB) (pgDSN, pgRoles) {
			db.asAdmin(t, "GRANT "+db.roles.owner+" TO "+db.roles.runtime+" WITH INHERIT FALSE, SET FALSE")
			return db.migrator, db.roles
		}, "reaches the owner role"},
		{"one role as owner and run-time role", func(t *testing.T, db *pgTestDB) (pgDSN, pgRoles) {
			return db.migrator, pgRoles{owner: db.roles.owner, runtime: db.roles.owner}
		}, "are two roles"},
		{"a run-time role that is not there", func(t *testing.T, db *pgTestDB) (pgDSN, pgRoles) {
			return db.migrator, pgRoles{owner: db.roles.owner, runtime: db.roles.runtime + "_absent"}
		}, "is not there"},
		{"a role's name with a double quote", func(t *testing.T, db *pgTestDB) (pgDSN, pgRoles) {
			return db.migrator, pgRoles{owner: db.roles.owner, runtime: `x"; DROP SCHEMA gateway; --`}
		}, "no double quote"},
		{"a schema gateway of another role's", func(t *testing.T, db *pgTestDB) (pgDSN, pgRoles) {
			db.asAdmin(t, "CREATE SCHEMA gateway")
			return db.migrator, db.roles
		}, "another role owns it"},
		{"a schema gateway that is not the store's", func(t *testing.T, db *pgTestDB) (pgDSN, pgRoles) {
			db.asOwner(t, "CREATE SCHEMA gateway")
			return db.migrator, db.roles
		}, "records no migration"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newPgTestDB(t)
			dsn, roles := tc.setup(t, db)
			before := db.fingerprint(t)
			applied, err := migratePostgres(dsn, pgShippedMigrations(), roles, time.Minute)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the migration: applied %v, error %v; want a refusal saying %q", applied, err, tc.want)
			}
			if after := db.fingerprint(t); after != before {
				t.Fatalf("a refused migration changed the database:\n%s\n%s", before, after)
			}
		})
	}
	t.Run("a superuser's attributes on a role", func(t *testing.T) {
		db := newPgTestDB(t)
		if !db.super {
			t.Skip("the admin login is no superuser and cannot give BYPASSRLS")
		}
		db.asAdmin(t, "ALTER ROLE "+db.roles.runtime+" BYPASSRLS")
		if _, err := migratePostgres(db.migrator, pgShippedMigrations(), db.roles, time.Minute); err == nil || !strings.Contains(err.Error(), "BYPASSRLS") {
			t.Fatalf("a migration naming a run-time role with BYPASSRLS: %v", err)
		}
	})
}

// The run-time login holds table privileges and nothing more: it makes,
// changes and drops nothing in the database, switches off no row security,
// reaches no other role, and changes or removes no row of an append-only
// table. Every one of these is refused by the server for lack of privilege.
func TestThePostgresRuntimeLoginIsRefusedDDLAndChanges(t *testing.T) {
	_, db := pgTestKind(t, "", nil)
	c := db.runtimeConn(t)
	for _, statement := range []string{
		"CREATE TABLE gateway.another (x int)",
		"CREATE TABLE public.another (x int)",
		"CREATE TEMPORARY TABLE another (x int)",
		"CREATE SCHEMA another",
		"CREATE FUNCTION gateway.another() RETURNS int LANGUAGE sql AS 'SELECT 1'",
		"CREATE INDEX another ON gateway.blobs (data)",
		"CREATE POLICY another ON gateway.blobs USING (true)",
		"DROP POLICY scope_of_the_transaction ON gateway.blobs",
		"ALTER TABLE gateway.blobs DISABLE ROW LEVEL SECURITY",
		"ALTER TABLE gateway.documents NO FORCE ROW LEVEL SECURITY",
		"ALTER TABLE gateway.entries ADD COLUMN another int",
		"DROP TABLE gateway.log_records",
		"DROP SCHEMA gateway CASCADE",
		"TRUNCATE gateway.blobs",
		"TRUNCATE gateway.log_records",
		"TRUNCATE gateway.documents",
		"UPDATE gateway.blobs SET data = ''",
		"DELETE FROM gateway.blobs",
		"UPDATE gateway.series SET name = name",
		"DELETE FROM gateway.series",
		"UPDATE gateway.entries SET data = ''",
		"DELETE FROM gateway.entries",
		"UPDATE gateway.log_records SET data = 'x'",
		"DELETE FROM gateway.log_records",
		"DELETE FROM gateway.logs",
		"UPDATE gateway.secrets SET value = ''",
		"DELETE FROM gateway.secrets",
		"INSERT INTO gateway.schema_migrations VALUES (9, 'x', 'sha256:" + strings.Repeat("0", 64) + "')",
		"DELETE FROM gateway.schema_migrations",
		"SET ROLE " + db.roles.owner,
		"SET SESSION AUTHORIZATION " + db.roles.owner,
		"ALTER ROLE " + db.roles.runtime + " BYPASSRLS",
	} {
		err := c.script(statement)
		if err == nil {
			t.Errorf("the run-time login ran %s", statement)
			continue
		}
		if code := pgCode(err); code != pgInsufficientPriv {
			t.Errorf("%s: refused with SQLSTATE %s (%v), want %s", statement, code, err, pgInsufficientPriv)
		}
	}
	// a grant of a privilege the grantor does not hold is answered with a
	// warning and grants nothing
	c.script("GRANT UPDATE, DELETE, TRUNCATE ON gateway.blobs TO " + db.roles.runtime)
	rows, err := c.exec(`SELECT pg_catalog.has_table_privilege('gateway.blobs', 'UPDATE') OR pg_catalog.has_table_privilege('gateway.blobs', 'DELETE')
		OR pg_catalog.has_table_privilege('gateway.blobs', 'TRUNCATE')`)
	if err != nil {
		t.Fatal(err)
	}
	if granted, _ := pgBool(rows.rows[0][0]); granted {
		t.Fatal("the run-time login granted itself a privilege on an append-only table")
	}
}

// Rows of one scope identifier are another's to neither read nor write: by
// the kind's views, and by statements of the run-time login's own that
// name the other scope, a key of its rows, or that reach them by an index
// alone. Nothing in the schema counts across scopes: it has no sequence.
func TestPostgresRowSecurityKeepsEachScopeApart(t *testing.T) {
	kind, db := pgTestKind(t, "", nil)
	a, err := kind.inScope("scope-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := kind.inScope("scope-b")
	if err != nil {
		t.Fatal(err)
	}
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
	revision, err := a.documents().putDocument("doc-of-a", []byte("a's"), noRevision)
	if err != nil {
		t.Fatal(err)
	}

	// the kind's view of scope b
	if _, err := b.artifacts().getBlob(blob); faultOf(err) != faultAbsent {
		t.Errorf("scope b read scope a's blob: %v", err)
	}
	if _, err := b.receipts().getEntry("session-of-a", "0"); faultOf(err) != faultAbsent {
		t.Errorf("scope b read scope a's entry: %v", err)
	}
	if _, err := b.receipts().listEntries("session-of-a"); faultOf(err) != faultAbsent {
		t.Errorf("scope b listed scope a's series: %v", err)
	}
	requireFault(t, "scope b's create into scope a's series", b.receipts().createIndexed("session-of-a", 1, []byte("{}\n")), faultAbsent)
	// a session's name is one across scopes, by a key row security does not
	// narrow: scope b does not make a series scope a holds
	if made, err := b.receipts().makeSeries("session-of-a"); err != nil || made {
		t.Errorf("scope b made the series scope a holds: %v %v", made, err)
	}
	if _, _, err := b.documents().getDocument("doc-of-a"); faultOf(err) != faultAbsent {
		t.Errorf("scope b read scope a's document: %v", err)
	}
	requireFault(t, "scope b's delete of scope a's document", b.documents().deleteDocument("doc-of-a", revision), faultAbsent)
	if _, err := b.documents().putDocument("doc-of-a", []byte("b's"), revision); faultOf(err) != faultConflict {
		t.Errorf("scope b's replacement of scope a's document: %v", err)
	}
	for space, list := range map[string]func() ([]string, error){
		"blobs": b.artifacts().listBlobs, "series": b.receipts().listSeries, "documents": b.documents().listDocuments,
		"no scope's blobs": kind.artifacts().listBlobs, "no scope's series": kind.receipts().listSeries,
	} {
		if names, err := list(); err != nil || len(names) != 0 {
			t.Errorf("%s listed %v %v", space, names, err)
		}
	}
	cut, err := b.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(cut.blobs)+len(cut.series)+len(cut.documents) != 0 {
		t.Errorf("scope b's cut holds scope a's rows: %v %v %v", cut.blobs, cut.series, cut.documents)
	}
	if got, _, err := a.documents().getDocument("doc-of-a"); err != nil || string(got) != "a's" {
		t.Fatalf("scope a's document after scope b's writes: %q %v", got, err)
	}

	// the run-time login's own statements, in scope b
	vacuum, err := pgConnect(db.migrator, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{"SET ROLE " + db.roles.owner, "VACUUM (ANALYZE) gateway.series", "VACUUM (ANALYZE) gateway.blobs"} {
		if err := vacuum.script(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	vacuum.close()
	c := db.runtimeConn(t)
	if err := c.script("SET enable_seqscan = off; SET enable_bitmapscan = off"); err != nil {
		t.Fatal(err)
	}
	inScope := func(t *testing.T, scope string, fn func()) {
		t.Helper()
		if err := c.script("BEGIN"); err != nil {
			t.Fatal(err)
		}
		if _, err := c.exec(`SELECT pg_catalog.set_config('gateway.scope', $1, true)`, pgRowScope(scope)); err != nil {
			t.Fatal(err)
		}
		fn()
		c.script("ROLLBACK")
	}
	inScope(t, "scope-b", func() {
		plan, err := c.exec(`EXPLAIN (COSTS OFF) SELECT name FROM gateway.series WHERE name = 'session-of-a'`)
		if err != nil {
			t.Fatal(err)
		}
		var lines []string
		for _, row := range plan.rows {
			lines = append(lines, string(row[0]))
		}
		if !strings.Contains(strings.Join(lines, "\n"), "Index Only Scan") {
			t.Fatalf("the read by index alone is planned otherwise: the test tests another path:\n%s", strings.Join(lines, "\n"))
		}
		for query, args := range map[string][]any{
			`SELECT name FROM gateway.series WHERE name = 'session-of-a'`:                nil,
			`SELECT name FROM gateway.series WHERE scope = 'scope:scope-a'`:              nil,
			`SELECT name FROM gateway.blobs WHERE scope = 'scope:scope-a' AND name = $1`: {blob},
			`SELECT data FROM gateway.entries WHERE series = 'session-of-a'`:             nil,
			`SELECT data FROM gateway.documents WHERE name = 'doc-of-a'`:                 nil,
			`SELECT name FROM gateway.blobs`:                                             nil,
			`SELECT count(*) FROM gateway.series HAVING count(*) > 0`:                    nil,
		} {
			rows, err := c.exec(query, args...)
			if err != nil {
				t.Fatalf("%s: %v", query, err)
			}
			if len(rows.rows) != 0 {
				t.Errorf("scope b read scope a's rows: %s", query)
			}
		}
		for query, want := range map[string]string{
			`UPDATE gateway.documents SET data = 'b''s' WHERE name = 'doc-of-a'`: "UPDATE 0",
			`DELETE FROM gateway.documents WHERE scope = 'scope:scope-a'`:        "DELETE 0",
		} {
			rows, err := c.exec(query)
			if err != nil || rows.tag != want {
				t.Errorf("%s: %q %v, want %q", query, rows.tag, err, want)
			}
		}
	})
	for _, query := range []string{
		`INSERT INTO gateway.blobs (scope, name, data) VALUES ('scope:scope-a', 'sha256:` + strings.Repeat("0", 64) + `', '')`,
		`INSERT INTO gateway.series (scope, name) VALUES ('scope:scope-a', 'session-of-b')`,
		`INSERT INTO gateway.entries (scope, series, name, data) VALUES ('scope:scope-a', 'session-of-a', '9', '')`,
		`INSERT INTO gateway.documents (scope, name, revision, data) VALUES ('scope:scope-a', 'doc-of-b', '` + strings.Repeat("0", 32) + `', '')`,
		`INSERT INTO gateway.documents (scope, name, revision, data) VALUES ('none', 'doc-of-no-scope', '` + strings.Repeat("0", 32) + `', '')`,
	} {
		inScope(t, "scope-b", func() {
			if _, err := c.exec(query); pgCode(err) != pgInsufficientPriv {
				t.Errorf("scope b wrote a row of another scope: %s: %v", query, err)
			}
		})
	}
	sequences := pgTestQuery(t, db.runtime, `SELECT
		(SELECT count(*) FROM pg_catalog.pg_class WHERE relkind = 'S')::int8,
		(SELECT count(*) FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
			JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'gateway' AND a.attidentity <> '')::int8`)
	if n, _ := pgInt8(sequences.rows[0][0]); n != 0 {
		t.Errorf("the database holds %d sequences", n)
	}
	if n, _ := pgInt8(sequences.rows[0][1]); n != 0 {
		t.Errorf("the schema holds %d identity columns", n)
	}
}

// A transaction that sets no scope sees no row and writes none, of no scope
// or of any: on a connection that never set the scope (the setting reads as
// NULL), on one whose earlier transaction set it for itself (it reads as the
// empty string), and in one that sets the empty string. The kind's view of
// no scope names its scope, and sees the rows of no scope alone, on the one
// connection a view of a scope used before it.
func TestAPostgresTransactionThatSetsNoScopeSeesNoRow(t *testing.T) {
	kind, db := pgTestKind(t, "", nil)
	single, err := openPgKind(pgOptions{dsn: db.runtime, connections: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer single.close()
	a, _ := single.inScope("scope-a")
	if _, err := a.artifacts().putBlob([]byte("a blob of scope a")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.documents().putDocument("doc", []byte("a's"), noRevision); err != nil {
		t.Fatal(err)
	}
	if _, err := single.artifacts().putBlob([]byte("a blob of no scope")); err != nil {
		t.Fatal(err)
	}
	if _, err := single.documents().putDocument("doc", []byte("no scope's"), noRevision); err != nil {
		t.Fatal(err)
	}
	// the view of no scope, on the one connection the view of scope a used
	if names, err := single.artifacts().listBlobs(); err != nil || len(names) != 1 {
		t.Fatalf("the view of no scope after a view of scope a listed %v %v", names, err)
	}
	if got, _, err := single.documents().getDocument("doc"); err != nil || string(got) != "no scope's" {
		t.Fatalf("the view of no scope read %q %v", got, err)
	}
	if names, err := kind.documents().listDocuments(); err != nil || len(names) != 1 {
		t.Fatalf("the kind's view of no scope listed %v %v", names, err)
	}

	c := db.runtimeConn(t)
	seesNothing := func(what string) {
		t.Helper()
		rows, err := c.exec(`SELECT (SELECT count(*) FROM gateway.blobs)::int8 + (SELECT count(*) FROM gateway.documents)::int8`)
		if err != nil {
			t.Fatal(err)
		}
		if n, _ := pgInt8(rows.rows[0][0]); n != 0 {
			t.Errorf("%s: a transaction that set no scope sees %d rows", what, n)
		}
		for _, row := range []string{pgNoScope, pgRowScope("scope-a")} {
			_, err := c.exec(`INSERT INTO gateway.documents (scope, name, revision, data) VALUES ($1, 'written', $2, '')`, row, strings.Repeat("0", 32))
			if pgCode(err) != pgInsufficientPriv {
				t.Errorf("%s: a transaction that set no scope wrote a row of %s: %v", what, row, err)
			}
		}
	}
	seesNothing("a connection that never set the scope")
	if err := c.script("BEGIN"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.exec(`SELECT pg_catalog.set_config('gateway.scope', $1, true)`, pgRowScope("scope-a")); err != nil {
		t.Fatal(err)
	}
	if err := c.script("COMMIT"); err != nil {
		t.Fatal(err)
	}
	seesNothing("a connection whose last transaction set the scope for itself")
	if err := c.script("SET gateway.scope = ''"); err != nil {
		t.Fatal(err)
	}
	seesNothing("a connection that set the empty string")
}

// Every transaction of the kind sets its own synchronous commit, search
// path and timeouts: what a role or a database sets otherwise decides
// nothing.
func TestAPostgresTransactionSetsItsOwnSettings(t *testing.T) {
	_, db := pgTestKind(t, "", nil)
	db.asAdmin(t,
		"ALTER ROLE "+db.roles.runtime+" IN DATABASE "+db.database+" SET synchronous_commit = off",
		"ALTER ROLE "+db.roles.runtime+" IN DATABASE "+db.database+" SET search_path = public",
		"ALTER ROLE "+db.roles.runtime+" IN DATABASE "+db.database+" SET statement_timeout = 0",
		"ALTER ROLE "+db.roles.runtime+" IN DATABASE "+db.database+" SET gateway.scope = 'scope:scope-a'",
	)
	kind := db.open(t, nil)
	var got []string
	if err := kind.transact(pgWriteCommitted, func(tx pgTx) error {
		rows, err := tx.exec(`SELECT pg_catalog.current_setting('synchronous_commit'), pg_catalog.current_setting('search_path'),
			pg_catalog.current_setting('statement_timeout'), pg_catalog.current_setting('lock_timeout'), pg_catalog.current_setting('gateway.scope')`)
		if err == nil {
			for _, v := range rows.rows[0] {
				got = append(got, string(v))
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"on", "pg_catalog", "30s", "30s", "none"}; !slices.Equal(got, want) {
		t.Fatalf("a transaction's settings read %q, want %q", got, want)
	}
}

// A commit the server answers with ROLLBACK, as it answers the commit of a
// transaction a statement failed in, is a failure, never a success.
func TestAPostgresCommitAnsweredWithRollbackIsAFailure(t *testing.T) {
	kind, _ := pgTestKind(t, "", nil)
	err := kind.transact(pgWriteCommitted, func(tx pgTx) error {
		tx.exec(`INSERT INTO gateway.blobs (scope, name, data) VALUES ('none', 'sha256:` + strings.Repeat("2", 64) + `', 'x')`)
		tx.exec(`SELECT 1 / 0`) // the transaction fails; the failure is not passed on
		return nil
	})
	if err == nil {
		t.Fatal("a commit answered with ROLLBACK was taken as a success")
	}
	if names, err := kind.artifacts().listBlobs(); err != nil || len(names) != 0 {
		t.Fatalf("a rolled-back write is listed: %v %v", names, err)
	}
	if name, err := kind.artifacts().putBlob([]byte("after")); err != nil || name == "" {
		t.Fatalf("the kind after a rolled-back commit: %v", err)
	}
}

// The kind does not start on a database outside its conditions: each case
// is a database migrated and then changed in one way, and the start
// refuses it, saying why.
func TestThePostgresKindRefusesToStartOutsideItsConditions(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, db *pgTestDB) pgDSN
		want  string
	}{
		{"a database not migrated", func(t *testing.T, db *pgTestDB) pgDSN { return db.runtime }, "no schema gateway"},
		{"a table privilege the store does not give", func(t *testing.T, db *pgTestDB) pgDSN {
			db.asOwner(t, "GRANT UPDATE ON gateway.blobs TO "+db.roles.runtime)
			return db.runtime
		}, "holds UPDATE on gateway.blobs"},
		{"a column privilege the store does not give", func(t *testing.T, db *pgTestDB) pgDSN {
			db.asOwner(t, "GRANT UPDATE (data) ON gateway.entries TO "+db.roles.runtime)
			return db.runtime
		}, "holds UPDATE on gateway.entries"},
		{"TRUNCATE on an append-only table", func(t *testing.T, db *pgTestDB) pgDSN {
			db.asOwner(t, "GRANT TRUNCATE ON gateway.log_records TO "+db.roles.runtime)
			return db.runtime
		}, "holds TRUNCATE on gateway.log_records"},
		{"a privilege given to every role", func(t *testing.T, db *pgTestDB) pgDSN {
			db.asOwner(t, "GRANT DELETE ON gateway.secrets TO PUBLIC")
			return db.runtime
		}, "holds DELETE on gateway.secrets"},
		{"a privilege the store needs taken back", func(t *testing.T, db *pgTestDB) pgDSN {
			db.asOwner(t, "REVOKE INSERT ON gateway.entries FROM "+db.roles.runtime)
			return db.runtime
		}, "lacks INSERT on gateway.entries"},
		{"a schema behind the binary's migrations", func(t *testing.T, db *pgTestDB) pgDSN {
			db.asOwner(t, "DELETE FROM gateway.schema_migrations")
			return db.runtime
		}, "apply the store's migrations"},
		{"row security not forced", func(t *testing.T, db *pgTestDB) pgDSN {
			db.asOwner(t, "ALTER TABLE gateway.documents NO FORCE ROW LEVEL SECURITY")
			return db.runtime
		}, "not enabled and forced on gateway.documents"},
		{"row security disabled", func(t *testing.T, db *pgTestDB) pgDSN {
			db.asOwner(t, "ALTER TABLE gateway.entries DISABLE ROW LEVEL SECURITY")
			return db.runtime
		}, "not enabled and forced on gateway.entries"},
		{"a policy beside the scope's", func(t *testing.T, db *pgTestDB) pgDSN {
			db.asOwner(t, "CREATE POLICY everything ON gateway.blobs USING (true)")
			return db.runtime
		}, "not the store's scope policy"},
		{"the scope's policy changed", func(t *testing.T, db *pgTestDB) pgDSN {
			db.asOwner(t, "ALTER POLICY scope_of_the_transaction ON gateway.series USING (true)")
			return db.runtime
		}, "not the store's scope policy"},
		{"the scope's policy dropped", func(t *testing.T, db *pgTestDB) pgDSN {
			db.asOwner(t, "DROP POLICY scope_of_the_transaction ON gateway.documents")
			return db.runtime
		}, "holds no scope policy"},
		{"a function in the schema", func(t *testing.T, db *pgTestDB) pgDSN {
			db.asOwner(t, "CREATE FUNCTION gateway.f() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'")
			return db.runtime
		}, "holds a function"},
		{"a sequence in the schema", func(t *testing.T, db *pgTestDB) pgDSN {
			db.asOwner(t, "CREATE SEQUENCE gateway.counter")
			return db.runtime
		}, "holds counter"},
		{"a view in the schema", func(t *testing.T, db *pgTestDB) pgDSN {
			db.asOwner(t, "CREATE VIEW gateway.everything AS SELECT * FROM gateway.blobs")
			return db.runtime
		}, "holds everything"},
		{"a trigger on a table", func(t *testing.T, db *pgTestDB) pgDSN {
			db.asOwner(t, "CREATE FUNCTION public.t() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END'",
				"CREATE TRIGGER t BEFORE INSERT ON gateway.blobs FOR EACH ROW EXECUTE FUNCTION public.t()")
			return db.runtime
		}, "holds a trigger"},
		{"a table of no scope beside the store's", func(t *testing.T, db *pgTestDB) pgDSN {
			db.asOwner(t, "CREATE TABLE gateway.another (x int)")
			return db.runtime
		}, "holds the tables"},
		{"CREATE on a schema", func(t *testing.T, db *pgTestDB) pgDSN {
			db.asOwner(t, "GRANT CREATE ON SCHEMA gateway TO "+db.roles.runtime)
			return db.runtime
		}, "create objects in a schema"},
		{"TEMPORARY on the database", func(t *testing.T, db *pgTestDB) pgDSN {
			db.asAdmin(t, "GRANT TEMPORARY ON DATABASE "+db.database+" TO "+db.roles.runtime)
			return db.runtime
		}, "temporary tables"},
		{"a run-time login that reaches the owner", func(t *testing.T, db *pgTestDB) pgDSN {
			db.asAdmin(t, "GRANT "+db.roles.owner+" TO "+db.roles.runtime+" WITH INHERIT FALSE, SET FALSE")
			return db.runtime
		}, "reaches, the schema's owner"},
		{"the migration login as the run-time login", func(t *testing.T, db *pgTestDB) pgDSN {
			return db.migrator
		}, "reaches, the schema's owner"},
		{"a run-time login with BYPASSRLS", func(t *testing.T, db *pgTestDB) pgDSN {
			if !db.super {
				t.Skip("the admin login is no superuser and cannot give BYPASSRLS")
			}
			db.asAdmin(t, "ALTER ROLE "+db.roles.runtime+" BYPASSRLS")
			return db.runtime
		}, "BYPASSRLS"},
		{"a run-time login that may make roles", func(t *testing.T, db *pgTestDB) pgDSN {
			db.asAdmin(t, "ALTER ROLE "+db.roles.runtime+" CREATEROLE")
			return db.runtime
		}, "CREATEROLE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newPgTestDB(t)
			if tc.name != "a database not migrated" {
				db.migrate(t)
			}
			dsn := tc.setup(t, db)
			kind, err := openPgKind(pgOptions{dsn: dsn})
			if err == nil {
				kind.close()
				t.Fatalf("the kind started; want a refusal saying %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the start was refused as %q, want %q", err, tc.want)
			}
		})
	}
	t.Run("the database as migrated", func(t *testing.T) {
		db := newPgTestDB(t)
		db.migrate(t)
		db.open(t, nil)
	})
}

// One scenario on both kinds holds the same bytes: receipts stamped and
// sessions sealed through the contract into a store of the filesystem kind
// and into one of the PostgreSQL kind, of no scope and of one scope
// identifier, export to trees equal byte for byte, with every entry, blob
// and the log equal at the cut.
func TestThePostgresKindHoldsTheBytesTheFilesystemKindDoes(t *testing.T) {
	root := t.TempDir()
	fsKind := newFsKind(fsLayout{store: filepath.Join(root, "store"), registry: filepath.Join(root, "registry.jsonl")})
	if err := fsKind.makeStore(); err != nil {
		t.Fatal(err)
	}
	pgNoScope, _ := pgTestKind(t, "", nil)
	pgScoped, _ := pgTestKind(t, "scope-a", nil)
	kinds := []struct {
		name string
		kind storeKind
	}{{"filesystem", fsKind}, {"postgresql", pgNoScope}, {"postgresql-scoped", pgScoped}}
	exports := map[string]map[string][]byte{}
	cuts := map[string]*storeCut{}
	for _, k := range kinds {
		st := newStoreOn("", k.kind.artifacts(), k.kind.receipts(), testSeed, "gateway:test")
		reg, err := newRegistryWriterOn(k.kind.registry(), "the registry", testSeed, noHistory)
		if err != nil {
			t.Fatal(err)
		}
		stampSession(t, st, "first", 3)
		if _, err := reg.seal("first", 3, "2026-10-01T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
		stampSession(t, st, "second", 2)
		if _, err := reg.seal("second", 2, "2026-10-02T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
		stampSession(t, st, "open", 1)
		out := filepath.Join(t.TempDir(), "export")
		if _, err := writeExport(exportInputs{authority: "gateway:test", keyID: st.keyID, kind: k.kind}, out); err != nil {
			t.Fatalf("%s: export: %v", k.name, err)
		}
		requireExportChecks(t, out)
		exports[k.name] = readTreeBytes(t, out)
		cut, err := k.kind.snapshot()
		if err != nil {
			t.Fatal(err)
		}
		cuts[k.name] = cut
	}
	want := exports["filesystem"]
	if len(want) == 0 {
		t.Fatal("the filesystem kind's export is empty: the test tests nothing")
	}
	for _, k := range kinds[1:] {
		requireSameTree(t, k.name, exports[k.name], want)
		requireSameCut(t, k.name, cuts[k.name], cuts["filesystem"])
	}
}

func readTreeBytes(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	tree := map[string][]byte{}
	err := filepath.WalkDir(dir, func(at string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, at)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(at)
		tree[filepath.ToSlash(rel)] = data
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func requireSameTree(t *testing.T, name string, got, want map[string][]byte) {
	t.Helper()
	for path, data := range want {
		if other, ok := got[path]; !ok {
			t.Errorf("%s: the export lacks %s", name, path)
		} else if !bytes.Equal(other, data) {
			t.Errorf("%s: %s differs:\n%s\nwant:\n%s", name, path, other, data)
		}
	}
	for path := range got {
		if _, ok := want[path]; !ok {
			t.Errorf("%s: the export holds %s, which the filesystem kind's does not", name, path)
		}
	}
}

func requireSameCut(t *testing.T, name string, got, want *storeCut) {
	t.Helper()
	if !bytes.Equal(got.log, want.log) || got.logPresent != want.logPresent {
		t.Errorf("%s: the log differs at the cut", name)
	}
	if !slices.Equal(got.series, want.series) || !slices.Equal(got.blobs, want.blobs) {
		t.Errorf("%s: the cut lists %v %v, want %v %v", name, got.series, got.blobs, want.series, want.blobs)
	}
	for _, series := range want.series {
		if !slices.Equal(got.entries[series], want.entries[series]) {
			t.Errorf("%s: %s lists %v, want %v", name, series, got.entries[series], want.entries[series])
		}
		for _, entry := range want.entries[series] {
			a, errA := got.entry(series, entry)
			b, errB := want.entry(series, entry)
			if errA != nil || errB != nil || !bytes.Equal(a, b) {
				t.Errorf("%s: %s/%s differs: %v %v", name, series, entry, errA, errB)
			}
		}
	}
	for _, blob := range want.blobs {
		a, errA := got.blob(blob)
		b, errB := want.blob(blob)
		if errA != nil || errB != nil || !bytes.Equal(a, b) {
			t.Errorf("%s: blob %s differs: %v %v", name, blob, errA, errB)
		}
	}
}

// Every store vector of the corpus, held in the PostgreSQL kind, exports
// byte for byte as the filesystem kind exports it, and its restore
// verifies to the store's verdict: no vector changed, the vectors loaded
// into the kind's tables as the filesystem holds them.
func TestEveryCorpusStoreExportsFromThePostgresKindByteForByte(t *testing.T) {
	pgTestAdmin(t)
	corpus := filepath.Join("..", "corpus")
	publicKey, err := corpusPublicKey(corpus)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := storeVectorPaths(corpus)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no store vectors: the test tests nothing")
	}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var vector storeVector
		if err := decodeVectorFile(raw, &vector, false); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		t.Run(vector.Name, func(t *testing.T) {
			root, storeRoot, registryPath, records, err := materializeVector(vector)
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(root)
			live := verdictBytes(t, storeRoot, registryPath, vector.Authority, records, publicKey)
			fsKind := newFsKind(fsLayout{store: storeRoot, registry: registryPath})
			fsOut := filepath.Join(t.TempDir(), "filesystem")
			if _, err := writeExport(exportInputs{authority: vector.Authority, keyID: keyIDFor(publicKey), kind: fsKind, storeRoot: storeRoot, decisionRecords: records}, fsOut); err != nil {
				t.Fatalf("export of the filesystem kind: %v", err)
			}
			kind, db := pgTestKind(t, "", nil)
			cut, err := fsKind.snapshot()
			if err != nil {
				t.Fatal(err)
			}
			pgLoadCut(t, db, cut)
			pgOut := filepath.Join(t.TempDir(), "postgresql")
			if _, err := writeExport(exportInputs{authority: vector.Authority, keyID: keyIDFor(publicKey), kind: kind, storeRoot: storeRoot, decisionRecords: records}, pgOut); err != nil {
				t.Fatalf("export of the PostgreSQL kind: %v", err)
			}
			requireSameTree(t, "postgresql", readTreeBytes(t, pgOut), readTreeBytes(t, fsOut))
			restored := filepath.Join(t.TempDir(), "restored")
			restoreTree(t, pgOut, restored)
			requireExportChecks(t, restored)
			if got := restoredVerdict(t, restored, vector.Authority, publicKey); !bytes.Equal(got, live) {
				t.Fatalf("the restored export's verdict differs from the store's:\nstore:    %s\nrestored: %s", live, got)
			}
		})
	}
}

// pgLoadCut writes a cut into the kind's tables of no scope as the run-time
// login, row by row as the filesystem holds them: a vector's entries are
// named as its files are, and its blobs need not digest to their names.
func pgLoadCut(t *testing.T, db *pgTestDB, cut *storeCut) {
	t.Helper()
	c := db.runtimeConn(t)
	if err := c.script("BEGIN"); err != nil {
		t.Fatal(err)
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := c.exec(query, args...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	// rows of no scope, in a transaction that names it: one that names
	// none writes no row
	exec(`SELECT pg_catalog.set_config('gateway.scope', $1, true)`, pgNoScope)
	if cut.logPresent {
		exec(`INSERT INTO gateway.logs (name) VALUES ('registry')`)
		if len(cut.log) > 0 {
			exec(`INSERT INTO gateway.log_records (log, start, data) VALUES ('registry', 0, $1)`, cut.log)
		}
	}
	for _, series := range cut.series {
		exec(`INSERT INTO gateway.series (scope, name) VALUES ('none', $1)`, series)
		for _, entry := range cut.entries[series] {
			data, err := cut.entry(series, entry)
			if err != nil {
				t.Fatal(err)
			}
			exec(`INSERT INTO gateway.entries (scope, series, name, data) VALUES ('none', $1, $2, $3)`, series, entry, data)
		}
	}
	for _, blob := range cut.blobs {
		data, err := cut.blob(blob)
		if err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO gateway.blobs (scope, name, data) VALUES ('none', $1, $2)`, blob, data)
	}
	for name, data := range cut.documents {
		exec(`INSERT INTO gateway.documents (scope, name, revision, data) VALUES ('none', $1, $2, $3)`, name, strings.Repeat("0", 32), data)
	}
	if err := c.script("COMMIT"); err != nil {
		t.Fatal(err)
	}
}

// Appends from many writers at once all land, once each and in each
// writer's order, and every read taken meanwhile is the log's start in
// whole records: an append holds the log's lock to its commit, so a record
// commits only after the one it follows, and none loses the log's end to
// another append and is refused.
func TestAPostgresLogUnderConcurrentAppendsLosesNoneAndReadsWhole(t *testing.T) {
	kind, _ := pgTestKind(t, "", nil)
	log := kind.registry()
	if err := log.createLog(); err != nil {
		t.Fatal(err)
	}
	const writers, each = 6, 8
	failures := make(chan error, writers*each+2)
	var reads sync.Mutex
	var seen [][]byte
	stop := make(chan struct{})
	var readers, appenders sync.WaitGroup
	for r := 0; r < 2; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				data, err := log.readLog(0)
				if err != nil {
					failures <- fmt.Errorf("a read under appends: %w", err)
					return
				}
				reads.Lock()
				seen = append(seen, data)
				reads.Unlock()
			}
		}()
	}
	for w := 0; w < writers; w++ {
		appenders.Add(1)
		go func(w int) {
			defer appenders.Done()
			for i := 0; i < each; i++ {
				record := []byte(fmt.Sprintf("writer %d record %d\n", w, i))
				if n, err := log.appendRecord(record); err != nil || n != len(record) {
					failures <- fmt.Errorf("writer %d's append %d: %d %v", w, i, n, err)
				}
			}
		}(w)
	}
	appenders.Wait()
	close(stop)
	readers.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	final, err := log.readLog(0)
	if err != nil {
		t.Fatal(err)
	}
	next := make([]int, writers)
	lines := strings.Split(strings.TrimSuffix(string(final), "\n"), "\n")
	for _, line := range lines {
		var w, i int
		if _, err := fmt.Sscanf(line, "writer %d record %d", &w, &i); err != nil || w < 0 || w >= writers || i != next[w] {
			t.Fatalf("the log holds %q out of its writer's order", line)
		}
		next[w]++
	}
	if len(lines) != writers*each {
		t.Fatalf("the log holds %d records of %d appended", len(lines), writers*each)
	}
	if len(seen) == 0 {
		t.Fatal("no read was taken under the appends: the test tests nothing")
	}
	for _, data := range seen {
		if !bytes.HasPrefix(final, data) || (len(data) > 0 && data[len(data)-1] != '\n') {
			t.Fatalf("a read under appends is not the log's start in whole records: %q", data)
		}
	}
}

// A migration that changes rows of a scoped table, under the forcing of
// row security that holds the owner too, fails and applies nothing, rather
// than changing no row because it set no scope; one that lifts the forcing
// for the table, changes the rows and restores it changes the rows of every
// scope.
func TestAPostgresMigrationOfRowsFailsRatherThanChangingNone(t *testing.T) {
	kind, db := pgTestKind(t, "", nil)
	a, _ := kind.inScope("scope-a")
	for _, view := range []*pgKind{kind, a} {
		if _, err := view.documents().putDocument("doc", []byte("before"), noRevision); err != nil {
			t.Fatal(err)
		}
	}
	shipped := pgShippedMigrations()
	with := func(sql string) pgMigrationSet {
		set := shipped
		set.versions = append(slices.Clone(shipped.versions), pgMigration{version: 2, name: "0002_rows.sql", sql: []byte(sql)})
		return set
	}
	before := db.fingerprint(t)
	if _, err := migratePostgres(db.migrator, with(`UPDATE gateway.documents SET data = 'after'`), db.roles, time.Minute); pgCode(err) != pgInsufficientPriv {
		t.Fatalf("a migration of rows under forced row security: %v", err)
	}
	if after := db.fingerprint(t); after != before {
		t.Fatalf("a migration that failed changed the database:\n%s\n%s", before, after)
	}
	applied, err := migratePostgres(db.migrator, with(`ALTER TABLE gateway.documents NO FORCE ROW LEVEL SECURITY;
UPDATE gateway.documents SET data = 'after';
ALTER TABLE gateway.documents FORCE ROW LEVEL SECURITY;`), db.roles, time.Minute)
	if err != nil || !slices.Equal(applied, []int{2}) {
		t.Fatalf("a migration of rows that lifts the forcing: %v %v", applied, err)
	}
	for _, view := range []*pgKind{kind, a} {
		if got, _, err := view.documents().getDocument("doc"); err != nil || string(got) != "after" {
			t.Errorf("a row the migration changed reads %q %v", got, err)
		}
	}
}

// Bytes that hold a NUL, as a byte and as the escape \u0000 that Go's JSON
// encoder writes for one in a caller's text, are kept and read back byte
// for byte by every kind, in every space and in a cut: the PostgreSQL kind
// keeps each value as bytea bound in the binary format, and no column or
// statement reads one as JSON.
func TestAValueHoldingANULRoundTripsOnEveryKind(t *testing.T) {
	value := []byte("{\"text\":\"a\\u0000b\"}\n\x00\\x00\n")
	if !bytes.Contains(value, []byte(`\u0000`)) || !bytes.Contains(value, []byte{0}) {
		t.Fatal("the value holds no NUL: the test tests nothing")
	}
	for _, k := range storeKindsUnderTest() {
		t.Run(k.name, func(t *testing.T) {
			kind, _ := k.open(t, time.Now)
			same := func(what string, got []byte, err error) {
				t.Helper()
				if err != nil || !bytes.Equal(got, value) {
					t.Errorf("%s reads %q %v", what, got, err)
				}
			}
			blob, err := kind.artifacts().putBlob(value)
			if err != nil {
				t.Fatal(err)
			}
			got, err := kind.artifacts().getBlob(blob)
			same("the blob", got, err)
			if _, err := kind.receipts().makeSeries("session-nul"); err != nil {
				t.Fatal(err)
			}
			if err := kind.receipts().createIndexed("session-nul", 0, value); err != nil {
				t.Fatal(err)
			}
			got, err = kind.receipts().getEntry("session-nul", "0")
			same("the entry", got, err)
			if err := kind.registry().createLog(); err != nil {
				t.Fatal(err)
			}
			if _, err := kind.registry().appendRecord(value); err != nil {
				t.Fatal(err)
			}
			got, err = kind.registry().readLog(0)
			same("the log", got, err)
			if _, err := kind.documents().putDocument("doc-nul", value, noRevision); err != nil {
				t.Fatal(err)
			}
			got, _, err = kind.documents().getDocument("doc-nul")
			same("the document", got, err)
			if err := kind.secrets().putSecret("secret-nul", value); err != nil {
				t.Fatal(err)
			}
			got, err = kind.secrets().getSecret("secret-nul")
			same("the secret", got, err)
			cut, err := kind.snapshot()
			if err != nil {
				t.Fatal(err)
			}
			same("the cut's log", cut.log, nil)
			same("the cut's document", cut.documents["doc-nul"], nil)
			got, err = cut.entry("session-nul", "0")
			same("the cut's entry", got, err)
			got, err = cut.blob(blob)
			same("the cut's blob", got, err)
		})
	}
}
