package main

// The PostgreSQL storage kind's test database (docs/postgresql-store.md,
// "Testing"). A test that needs one takes it from the server the variable
// GATEWAY_TEST_POSTGRES_DSN names, as a login that may make roles and
// databases; without it the test skips and says why, unless
// GATEWAY_TEST_POSTGRES_REQUIRED is set, as it is in the CI job that runs
// these tests, where a test that would skip fails instead.
//
// Each database is the test's own: its three roles (the owner, the
// migration login, the run-time login) and the database are made for it,
// with names and passwords drawn at random, and dropped when it ends.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	pgTestDSNVariable      = "GATEWAY_TEST_POSTGRES_DSN"
	pgTestRequiredVariable = "GATEWAY_TEST_POSTGRES_REQUIRED"
)

// pgTestAdmin is the login the tests make roles and databases as.
func pgTestAdmin(t testing.TB) pgDSN {
	t.Helper()
	d, skip, fail := pgTestAdminFrom(os.Getenv)
	if fail != "" {
		t.Fatal(fail)
	}
	if skip != "" {
		t.Skip(skip)
	}
	return d
}

// pgTestAdminFrom reads the admin login from the environment: a reason to
// skip where no server is named, a failure instead where the tests are
// required to run, and a failure for a connection string out of form.
func pgTestAdminFrom(getenv func(string) string) (pgDSN, string, string) {
	text := getenv(pgTestDSNVariable)
	if text == "" {
		if getenv(pgTestRequiredVariable) != "" {
			return pgDSN{}, "", fmt.Sprintf("%s is set and %s is not: here the PostgreSQL storage kind's tests run, and do not skip", pgTestRequiredVariable, pgTestDSNVariable)
		}
		return pgDSN{}, fmt.Sprintf("the PostgreSQL storage kind's tests need a server: set %s to the postgresql:// URL of a login that may make roles and databases (docs/postgresql-store.md, \"Testing\")", pgTestDSNVariable), ""
	}
	d, err := parsePgDSN(text)
	if err != nil {
		return pgDSN{}, "", fmt.Sprintf("%s: %v", pgTestDSNVariable, err)
	}
	return d, "", ""
}

func pgTestRandom(t testing.TB, n int) string {
	t.Helper()
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}

// pgTestDB is one test's database and roles.
type pgTestDB struct {
	admin    pgDSN // the admin login, on its own database
	inDB     pgDSN // the admin login, on this database
	migrator pgDSN
	runtime  pgDSN
	roles    pgRoles
	migRole  string
	database string
	super    bool // the admin login is a superuser
}

// newPgTestDB makes a database and its roles as the operator would
// (docs/postgresql-store.md, "Before the first start"), and drops them when
// the test ends. It does not migrate the database.
func newPgTestDB(t testing.TB) *pgTestDB {
	t.Helper()
	admin := pgTestAdmin(t)
	tag := pgTestRandom(t, 6)
	db := &pgTestDB{
		admin:    admin,
		roles:    pgRoles{owner: "gw_owner_" + tag, runtime: "gw_run_" + tag},
		migRole:  "gw_mig_" + tag,
		database: "gw_db_" + tag,
	}
	db.migrator, db.runtime, db.inDB = admin, admin, admin
	db.migrator.user, db.migrator.password, db.migrator.database = db.migRole, pgTestRandom(t, 16), db.database
	db.runtime.user, db.runtime.password, db.runtime.database = db.roles.runtime, pgTestRandom(t, 16), db.database
	db.inDB.database = db.database
	t.Cleanup(func() {
		// the kinds a test opened close first: cleanups run last-made first
		for _, statement := range []string{
			"DROP DATABASE IF EXISTS " + db.database + " WITH (FORCE)",
			"DROP ROLE IF EXISTS " + db.roles.runtime,
			"DROP ROLE IF EXISTS " + db.migRole,
			"DROP ROLE IF EXISTS " + db.roles.owner,
		} {
			if err := db.adminScript(statement); err != nil {
				t.Errorf("dropping the test database: %s: %v", statement, err)
			}
		}
	})
	rows := db.adminQuery(t, `SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user`)
	db.super, _ = pgBool(rows.rows[0][0])
	for _, statement := range []string{
		"CREATE ROLE " + db.roles.owner + " NOLOGIN",
		"CREATE ROLE " + db.migRole + " LOGIN PASSWORD '" + db.migrator.password + "'",
		"CREATE ROLE " + db.roles.runtime + " LOGIN PASSWORD '" + db.runtime.password + "'",
		"GRANT " + db.roles.owner + " TO " + db.migRole + " WITH INHERIT FALSE, SET TRUE",
		// an admin that is no superuser makes a database for the owner by
		// SET ROLE to it
		"GRANT " + db.roles.owner + " TO current_user WITH INHERIT FALSE, SET TRUE",
		"CREATE DATABASE " + db.database + " OWNER " + db.roles.owner + " ENCODING 'UTF8' TEMPLATE template0",
		"REVOKE ALL ON DATABASE " + db.database + " FROM PUBLIC",
		"GRANT CONNECT ON DATABASE " + db.database + " TO " + db.migRole + ", " + db.roles.runtime,
	} {
		if err := db.adminScript(statement); err != nil {
			t.Fatalf("making the test database: %s: %v", strings.SplitN(statement, " PASSWORD ", 2)[0], err)
		}
	}
	return db
}

func (db *pgTestDB) adminScript(statement string) error {
	c, err := pgConnect(db.admin, time.Now().Add(time.Minute))
	if err != nil {
		return err
	}
	defer c.close()
	return c.script(statement)
}

func (db *pgTestDB) adminQuery(t testing.TB, query string, args ...any) pgRows {
	t.Helper()
	return pgTestQuery(t, db.admin, query, args...)
}

// asAdmin runs statements as the admin login in this test's database, one
// at a time.
func (db *pgTestDB) asAdmin(t testing.TB, statements ...string) {
	t.Helper()
	c, err := pgConnect(db.inDB, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	for _, statement := range statements {
		if err := c.script(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
}

// asOwner runs statements as the owner role, reached from the migration
// login by SET ROLE, in one transaction.
func (db *pgTestDB) asOwner(t testing.TB, statements ...string) {
	t.Helper()
	c, err := pgConnect(db.migrator, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	script := "BEGIN; SET LOCAL ROLE " + db.roles.owner + "; " + strings.Join(statements, "; ") + "; COMMIT"
	if err := c.script(script); err != nil {
		t.Fatalf("%s: %v", script, err)
	}
}

func pgTestQuery(t testing.TB, d pgDSN, query string, args ...any) pgRows {
	t.Helper()
	c, err := pgConnect(d, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	rows, err := c.exec(query, args...)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return rows
}

// migrate applies the schema this binary carries.
func (db *pgTestDB) migrate(t testing.TB) {
	t.Helper()
	if _, err := migratePostgres(db.migrator, pgShippedMigrations(), db.roles, time.Minute); err != nil {
		t.Fatalf("migrate: %v", err)
	}
}

// open opens the kind as the run-time login, and closes it when the test
// ends.
func (db *pgTestDB) open(t testing.TB, clock func() time.Time) *pgKind {
	t.Helper()
	kind, err := openPgKind(pgOptions{dsn: db.runtime, clock: clock})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(kind.close)
	return kind
}

// pgTestKind is a migrated database's kind, seen as scope sees it ("" for
// no scope).
func pgTestKind(t testing.TB, scope string, clock func() time.Time) (*pgKind, *pgTestDB) {
	t.Helper()
	db := newPgTestDB(t)
	db.migrate(t)
	kind := db.open(t, clock)
	if scope == "" {
		return kind, db
	}
	view, err := kind.inScope(scope)
	if err != nil {
		t.Fatal(err)
	}
	return view, db
}

// pgKindsUnderTest are the PostgreSQL kind's entries in the conformance
// suite: the kind as no scope sees it, and as one scope identifier does.
// Its blob space breaks as a database that keeps nothing more would: the
// run-time login's INSERT on blobs is taken back.
func pgKindsUnderTest() []kindUnderTest {
	open := func(scope string) func(t *testing.T, clock func() time.Time) (storeKind, func()) {
		return func(t *testing.T, clock func() time.Time) (storeKind, func()) {
			kind, db := pgTestKind(t, scope, clock)
			return kind, func() {
				db.asOwner(t, "REVOKE INSERT ON gateway.blobs FROM "+db.roles.runtime)
			}
		}
	}
	return []kindUnderTest{
		{"postgresql", open("")},
		{"postgresql-scoped", open("scope-a")},
	}
}

func (db *pgTestDB) String() string { return fmt.Sprintf("test database %s", db.database) }
