package main

// `gateway store migrate` (docs/postgresql-store.md, "The migration
// command"): the PostgreSQL storage kind's schema created or raised, as the
// migration login, with the gateway stopped or running. The command is the
// only way the schema changes; the gateway's start checks it and changes
// nothing (pgKind.holdsItsConditions), so the run-time login never needs,
// and is refused, what a migration does.

import (
	"fmt"
	"io"
	"strconv"
	"time"
)

const storeUsage = `usage:
  gateway store migrate (--connection-file <path> | --connection-env <NAME>) --owner <role> --runtime <role> [--timeout <seconds>]
Creates or raises the PostgreSQL storage kind's schema in the database the
connection string names, as the migration login it names: a login that
reaches the owner role by SET ROLE and nothing more, never the run-time
login. The run-time role's privileges and the row security are given anew
on every run. A second run applies nothing; a schema newer than this
gateway's migrations is refused, and so is a migration changed since it was
applied. The connection string is read from the file, held as the seed's
file is, or from the variable; it is never printed. Prints, as canonical
JSON, the versions applied, the schema's version and the migrations' digest.`

// storeMigrateDefaultTimeout bounds a migration run, connection included.
const storeMigrateDefaultTimeout = 5 * time.Minute

func cmdStore(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "retain" {
		return cmdStoreRetain(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "remove-scope" {
		return cmdStoreRemoveScope(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "journal-reset" {
		return cmdStoreJournalReset(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "rotate" {
		return cmdStoreRotate(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "rotate-key" {
		return cmdStoreRotateKey(args[1:], stdout, stderr)
	}
	if len(args) == 0 || args[0] != "migrate" {
		fmt.Fprintln(stderr, storeUsage+"\n"+storeRemoveScopeUsage+"\n"+storeRetainUsage+"\n"+storeRotateUsage+"\n"+storeRotateKeyUsage+"\n"+storeJournalResetUsage)
		return 2
	}
	flags, code := storeFlags(args[1:], []string{"--connection-file", "--connection-env", "--owner", "--runtime", "--timeout"}, "store migrate", storeUsage, stderr)
	if code != 0 {
		return code
	}
	timeout, ok := storeTimeout(flags, "store migrate", storeUsage, stderr)
	if !ok {
		return 2
	}
	spec, code := storeConnectionSpec(flags, "store migrate", stderr)
	if code != 0 {
		return code
	}
	report, err := storeMigrate(spec, pgRoles{owner: flags["--owner"], runtime: flags["--runtime"]}, timeout)
	if err != nil {
		fmt.Fprintln(stderr, "store migrate:", err)
		return 1
	}
	stdout.Write(append(canon(report), '\n'))
	return 0
}

// storeMigrate migrates the database the reference names to this binary's
// migrations, and reports what it did: never anything of the connection
// string.
func storeMigrate(spec *storageSpec, roles pgRoles, timeout time.Duration) (*vObject, error) {
	dsn, err := storageConnection(spec)
	if err != nil {
		return nil, err
	}
	set := pgShippedMigrations()
	applied, err := migratePostgres(dsn, set, roles, timeout)
	if err != nil {
		return nil, err
	}
	versions := vArray{}
	for _, v := range applied {
		versions = append(versions, vNumber(strconv.Itoa(v)))
	}
	report := newObject()
	report.set("applied", versions)
	report.set("migrations", vString(set.digest()))
	report.set("schemaVersion", vNumber(strconv.Itoa(len(set.versions))))
	return report, nil
}
