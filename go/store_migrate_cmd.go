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
	"os"
	"path/filepath"
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
	if len(args) == 0 || args[0] != "migrate" {
		fmt.Fprintln(stderr, storeUsage)
		return 2
	}
	flags := map[string]string{}
	for rest := args[1:]; len(rest) > 0; rest = rest[2:] {
		switch rest[0] {
		case "--connection-file", "--connection-env", "--owner", "--runtime", "--timeout":
		default:
			fmt.Fprintln(stderr, storeUsage)
			return 2
		}
		if len(rest) < 2 || rest[1] == "" {
			fmt.Fprintln(stderr, storeUsage)
			return 2
		}
		if _, given := flags[rest[0]]; given {
			fmt.Fprintf(stderr, "store migrate: %s is given twice\n%s\n", rest[0], storeUsage)
			return 2
		}
		flags[rest[0]] = rest[1]
	}
	file, environment := flags["--connection-file"], flags["--connection-env"]
	if (file == "") == (environment == "") || flags["--owner"] == "" || flags["--runtime"] == "" {
		fmt.Fprintln(stderr, storeUsage)
		return 2
	}
	timeout := storeMigrateDefaultTimeout
	if text, given := flags["--timeout"]; given {
		seconds, err := strconv.Atoi(text)
		if err != nil || seconds < 1 || seconds > 3600 {
			fmt.Fprintf(stderr, "store migrate: --timeout is a number of seconds from 1 to 3600\n%s\n", storeUsage)
			return 2
		}
		timeout = time.Duration(seconds) * time.Second
	}
	spec := &storageSpec{kind: storagePostgreSQL, environment: environment}
	if file != "" {
		abs, err := filepath.Abs(file)
		if err != nil {
			fmt.Fprintln(stderr, "store migrate: --connection-file:", err)
			return 1
		}
		// the way to the file held as the seed's is, as serve holds the
		// run-time login's (engineRefusals)
		euid := os.Geteuid()
		resolved, err := trustedFile(abs, euid, linkOwners{other: euid}, osEngineHost())
		if err != nil {
			fmt.Fprintln(stderr, "store migrate: --connection-file:", err)
			return 1
		}
		spec.file = resolved
	} else if !storageEnvironmentName.MatchString(environment) {
		fmt.Fprintln(stderr, "store migrate: --connection-env is a variable's name: capital letters, digits and _, not starting with a digit, at most 128")
		return 2
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
