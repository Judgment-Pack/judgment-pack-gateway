package main

// `gateway store migrate` (store_migrate_cmd.go).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeConnection writes a login's connection string into a file of its
// own, private to this process's user, and returns the file.
func writeConnection(t *testing.T, d pgDSN) string {
	t.Helper()
	file := filepath.Join(tempDirAt(t, 0o700), "connection")
	if err := os.WriteFile(file, []byte(pgTestURL(d)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

func runStore(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := cmdStore(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// The command is refused, before anything is read, unless it names one
// reference to the connection string and both roles.
func TestTheStoreMigrateCommandTakesOneReferenceAndBothRoles(t *testing.T) {
	file := filepath.Join(t.TempDir(), "connection")
	for _, args := range [][]string{
		{},
		{"upgrade"},
		{"migrate", "--owner", "o", "--runtime", "r"},
		{"migrate", "--connection-file", file, "--connection-env", "X", "--owner", "o", "--runtime", "r"},
		{"migrate", "--connection-file", file, "--runtime", "r"},
		{"migrate", "--connection-file", file, "--owner", "o"},
		{"migrate", "--connection-file", file, "--owner", "o", "--runtime", "r", "--timeout", "0"},
		{"migrate", "--connection-env", "store url", "--owner", "o", "--runtime", "r"},
		{"migrate", "--connection-url", "postgresql://u:p@h/d", "--owner", "o", "--runtime", "r"},
		{"migrate", "--owner", "o", "--owner", "p", "--connection-file", file, "--runtime", "r"},
	} {
		if code, stdout, stderr := runStore(args...); code != 2 || stdout != "" || !strings.Contains(stderr, "usage:") && !strings.Contains(stderr, "--connection-env is a variable's name") {
			t.Errorf("%q: %d %q %q", args, code, stdout, stderr)
		}
	}
	// a connection file others may read is refused as the seed's would be
	if err := os.WriteFile(file, []byte("postgresql://u:synthetic@127.0.0.1/d?sslmode=disable"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runStore("migrate", "--connection-file", file, "--owner", "o", "--runtime", "r"); code != 1 || strings.Contains(stderr, "synthetic") {
		t.Fatalf("a file others may read: %d %q", code, stderr)
	}
	// and so is one in a directory others may write in, which could be
	// replaced under the command
	open := tempDirAt(t, 0o777)
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	file = filepath.Join(open, "connection")
	if err := os.WriteFile(file, []byte("postgresql://u:synthetic@127.0.0.1/d?sslmode=disable"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runStore("migrate", "--connection-file", file, "--owner", "o", "--runtime", "r"); code != 1 || !strings.HasPrefix(stderr, "store migrate: --connection-file:") || strings.Contains(stderr, "synthetic") {
		t.Fatalf("a file in a directory others may write in: %d %q", code, stderr)
	}
}

// The migration login migrates the schema once: a second run applies
// nothing; the run-time login's start holds after it; and the output names
// no part of the connection string.
func TestThePostgresMigrateCommandMigratesOnceAndPrintsNoSecret(t *testing.T) {
	db := newPgTestDB(t)
	file := writeConnection(t, db.migrator)
	set := pgShippedMigrations()
	var all []int
	for _, m := range set.versions {
		all = append(all, m.version)
	}
	report := func(applied []int) string {
		versions := make([]string, len(applied))
		for i, v := range applied {
			versions[i] = fmt.Sprint(v)
		}
		return `{"applied":[` + strings.Join(versions, ",") + `],"migrations":"` + set.digest() + `","schemaVersion":` + fmt.Sprint(len(set.versions)) + "}\n"
	}
	code, stdout, stderr := runStore("migrate", "--connection-file", file, "--owner", db.roles.owner, "--runtime", db.roles.runtime)
	if code != 0 || stdout != report(all) || stderr != "" {
		t.Fatalf("the first run: %d %q %q", code, stdout, stderr)
	}
	t.Setenv("GATEWAY_TEST_MIGRATION_URL", pgTestURL(db.migrator))
	code, again, stderr := runStore("migrate", "--connection-env", "GATEWAY_TEST_MIGRATION_URL", "--owner", db.roles.owner, "--runtime", db.roles.runtime, "--timeout", "60")
	if code != 0 || again != report(nil) || stderr != "" {
		t.Fatalf("the second run: %d %q %q", code, again, stderr)
	}
	if _, set := os.LookupEnv("GATEWAY_TEST_MIGRATION_URL"); set {
		t.Fatal("the variable is left in the environment once read")
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(stdout), &decoded); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{stdout, again} {
		if strings.Contains(text, db.migrator.password) || strings.Contains(text, db.migrator.user) {
			t.Fatalf("the output names the connection string: %s", text)
		}
	}
	db.open(t, nil)
}

// The run-time login cannot migrate: the command refuses it, applies
// nothing, and its refusal names no part of the connection string.
func TestThePostgresMigrateCommandRefusesTheRunTimeLogin(t *testing.T) {
	db := newPgTestDB(t)
	before := db.fingerprint(t)
	file := writeConnection(t, db.runtime)
	code, stdout, stderr := runStore("migrate", "--connection-file", file, "--owner", db.roles.owner, "--runtime", db.roles.runtime)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "the migration login is neither the owner role nor the run-time role") {
		t.Fatalf("the run-time login: %d %q %q", code, stdout, stderr)
	}
	if strings.Contains(stderr, db.runtime.password) {
		t.Fatalf("the refusal names the password: %q", stderr)
	}
	if after := db.fingerprint(t); after != before {
		t.Fatal("a refused migration changed the database")
	}
	// and once migrated, the run-time login still cannot raise the schema
	db.migrate(t)
	migrated := db.fingerprint(t)
	if code, _, stderr := runStore("migrate", "--connection-file", file, "--owner", db.roles.owner, "--runtime", db.roles.runtime); code != 1 || !strings.Contains(stderr, "neither the owner role nor the run-time role") {
		t.Fatalf("the run-time login on a migrated database: %d %q", code, stderr)
	}
	if after := db.fingerprint(t); after != migrated {
		t.Fatal("a refused migration changed the database")
	}
}

// A schema one version ahead of this binary's migrations refuses the
// migration command and the start the configuration names alike.
func TestAPostgresSchemaAheadRefusesTheMigrateCommandAndTheStart(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	next := len(pgShippedMigrations().versions) + 1
	db.asOwner(t, fmt.Sprintf("INSERT INTO gateway.schema_migrations VALUES (%d, '%04d_later.sql', 'sha256:%s')", next, next, strings.Repeat("0", 64)))
	ahead := db.fingerprint(t)
	code, stdout, stderr := runStore("migrate", "--connection-file", writeConnection(t, db.migrator), "--owner", db.roles.owner, "--runtime", db.roles.runtime)
	if code != 1 || stdout != "" || !strings.Contains(stderr, fmt.Sprintf("the database's schema is at version %d", next)) || !strings.Contains(stderr, "older than its schema") {
		t.Fatalf("migrate onto a schema ahead: %d %q %q", code, stdout, stderr)
	}
	if db.fingerprint(t) != ahead {
		t.Fatal("a refused migration changed the database")
	}
	cfg, err := parseEngineConfig([]byte(storageConfig(t, `{"kind":"postgresql","connection":{"file":"`+abs(t, writeConnection(t, db.runtime))+`"}}`, ``, ``)))
	if err != nil {
		t.Fatal(err)
	}
	if kind, err := openStorageKind(cfg.storage); err == nil {
		kind.close()
		t.Fatal("the start took a schema ahead of its migrations")
	} else if !strings.Contains(err.Error(), "older than its schema") {
		t.Fatalf("the start on a schema ahead: %v", err)
	}
}
