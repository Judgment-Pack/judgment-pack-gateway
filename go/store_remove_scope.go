package main

// `gateway store remove-scope` (gateway #434; ADR-0034, option 1; SPEC.md
// §6, "Removing one scope identifier's records"; docs/postgresql-store.md,
// "Removing one scope identifier's rows"): one scope identifier's rows
// removed from the PostgreSQL storage kind -- its sessions, receipts,
// payloads and documents -- with its row of gateway.scope_identifiers, and
// the removal recorded, in one transaction.
//
// The transaction is the migration's: the migration login, SET ROLE to the
// owner for the transaction alone, under the migration's advisory lock, so
// no migration runs beside it. It holds the start lease's lock and every
// row of the lease to its commit (pgHoldEveryInstance), so no instance
// starts while it runs, and it refuses while any instance's row is live. Row security stays forced: the scope's
// rows are read and removed with gateway.scope set to the scope's form, and
// named in every statement besides; the records and the scope identifier's
// row with it set to 'none'. The owner holds DELETE as the tables' owner;
// the run-time role's privileges do not change, and it holds no DELETE on
// a table but documents.
//
// On this kind a session's receipts are of one scope (the foreign key of
// gateway.entries to gateway.series names both), and nothing that cites a
// receipt (/act, descriptor statements) is available, so no session is of
// mixed scopes and no receipt of another scope cites one removed: what the
// filesystem kind's command refuses cannot be here.
//
// The records are the filesystem kind's, signed by the seed's key, which is
// the key the registry's walk ends at: a session-removal record for each
// sealed session and a scope-removal record for the call, each read back as
// a verifier reads the removal file before it is kept, and kept in
// gateway.removal_records, whose rows an export writes as the store's
// artifact-removals.jsonl. The transaction commits the records and the
// removal together, or neither.

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const storeRemoveScopeUsage = `usage:
  gateway store remove-scope (--connection-file <path> | --connection-env <NAME>) --owner <role> --runtime <role> --seed <file> --scope <identifier> --by <label> [--timeout <seconds>]
Removes one scope identifier's rows from the PostgreSQL storage kind -- its
sessions, receipts, payloads and documents -- and its row of the scope
identifiers recorded, as the migration login acting as the owner role, in
one transaction that holds the migration's lock and the start lease: a
gateway serving the database refuses it. The removal is recorded in the same
transaction, signed by the seed's key, which is the gateway's: a
session-removal record for each sealed session and a scope-removal record
for the call, which an export writes as the store's artifact-removals.jsonl
(SPEC.md §1.3a, §6). The run-time role's privileges do not change. --by is
a label, recorded and not checked. Prints each record kept, as its line.`

// storeRemoveScopeOptions is the command line, the connection apart.
type storeRemoveScopeOptions struct {
	roles     pgRoles
	seed      string
	scope, by string
	timeout   time.Duration
}

// storeFlags reads a store command's flags, each given once with a value:
// what is not one of names, or is given twice, or names not exactly one
// reference to the connection and both roles, is a usage error (2). The
// reference is read by storeConnectionSpec, after every other argument is
// checked.
func storeFlags(args []string, names []string, command, usage string, stderr io.Writer) (map[string]string, int) {
	flags := map[string]string{}
	for rest := args; len(rest) > 0; rest = rest[2:] {
		if !contains(names, rest[0]) || len(rest) < 2 || rest[1] == "" {
			fmt.Fprintln(stderr, usage)
			return nil, 2
		}
		if _, given := flags[rest[0]]; given {
			fmt.Fprintf(stderr, "%s: %s is given twice\n%s\n", command, rest[0], usage)
			return nil, 2
		}
		flags[rest[0]] = rest[1]
	}
	file, environment := flags["--connection-file"], flags["--connection-env"]
	if (file == "") == (environment == "") || flags["--owner"] == "" || flags["--runtime"] == "" {
		fmt.Fprintln(stderr, usage)
		return nil, 2
	}
	if environment != "" && !storageEnvironmentName.MatchString(environment) {
		fmt.Fprintf(stderr, "%s: --connection-env is a variable's name: capital letters, digits and _, not starting with a digit, at most 128\n", command)
		return nil, 2
	}
	return flags, 0
}

// storeConnectionSpec holds the connection's reference storeFlags checked:
// a file is held as the seed's is (1 when it cannot be).
func storeConnectionSpec(flags map[string]string, command string, stderr io.Writer) (*storageSpec, int) {
	file, environment := flags["--connection-file"], flags["--connection-env"]
	spec := &storageSpec{kind: storagePostgreSQL, environment: environment}
	if file != "" {
		abs, err := filepath.Abs(file)
		if err != nil {
			fmt.Fprintf(stderr, "%s: --connection-file: %v\n", command, err)
			return nil, 1
		}
		// the way to the file held as the seed's is, as serve holds the
		// run-time login's (engineRefusals)
		euid := os.Geteuid()
		resolved, err := trustedFile(abs, euid, linkOwners{other: euid}, osEngineHost())
		if err != nil {
			fmt.Fprintf(stderr, "%s: --connection-file: %v\n", command, err)
			return nil, 1
		}
		spec.file = resolved
	}
	return spec, 0
}

// storeTimeout is --timeout, 1 to 3600 seconds, or the default.
func storeTimeout(flags map[string]string, command, usage string, stderr io.Writer) (time.Duration, bool) {
	text, given := flags["--timeout"]
	if !given {
		return storeMigrateDefaultTimeout, true
	}
	seconds, err := strconv.Atoi(text)
	if err != nil || seconds < 1 || seconds > 3600 {
		fmt.Fprintf(stderr, "%s: --timeout is a number of seconds from 1 to 3600\n%s\n", command, usage)
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

func cmdStoreRemoveScope(args []string, stdout, stderr io.Writer) int {
	return cmdStoreRemoveScopeAt(args, stdout, stderr, nowStamp)
}

// cmdStoreRemoveScopeAt is the command, each record stamped by stamp.
func cmdStoreRemoveScopeAt(args []string, stdout, stderr io.Writer, stamp func() string) int {
	const command = "store remove-scope"
	usage := storeRemoveScopeUsage
	flags, code := storeFlags(args, []string{"--connection-file", "--connection-env", "--owner", "--runtime", "--seed", "--scope", "--by", "--timeout"}, command, usage, stderr)
	if code != 0 {
		return code
	}
	if flags["--seed"] == "" || flags["--scope"] == "" || flags["--by"] == "" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	if !isScopeIdentifier(flags["--scope"]) {
		fmt.Fprintf(stderr, "%s: --scope is a scope identifier: %s\n%s\n", command, scopeForm, usage)
		return 2
	}
	if !isScopeIdentifier(flags["--by"]) {
		fmt.Fprintf(stderr, "%s: --by is a label of the form of a scope identifier: %s\n%s\n", command, scopeForm, usage)
		return 2
	}
	timeout, ok := storeTimeout(flags, command, usage, stderr)
	if !ok {
		return 2
	}
	spec, code := storeConnectionSpec(flags, command, stderr)
	if code != 0 {
		return code
	}
	o := storeRemoveScopeOptions{
		roles: pgRoles{owner: flags["--owner"], runtime: flags["--runtime"]},
		seed:  flags["--seed"], scope: flags["--scope"], by: flags["--by"], timeout: timeout,
	}
	out, err := storeRemoveScope(spec, o, stamp)
	for _, record := range out.appended {
		fmt.Fprintf(stdout, "%s\n", canon(record))
	}
	for _, note := range out.notes {
		fmt.Fprintln(stderr, command+":", note)
	}
	if err != nil {
		fmt.Fprintln(stderr, command+":", err)
		return 1
	}
	return 0
}

// storeRemoveScope reads the seed and the connection string, and removes
// the scope's rows.
func storeRemoveScope(spec *storageSpec, o storeRemoveScopeOptions, stamp func() string) (removalOutcome, error) {
	seed, err := loadSeed(o.seed)
	if err != nil {
		return removalOutcome{}, fmt.Errorf("seed: %w", err)
	}
	dsn, err := storageConnection(spec)
	if err != nil {
		return removalOutcome{}, err
	}
	return removeScopeRows(dsn, o, ed25519.NewKeyFromSeed(seed), stamp)
}

// pgScopeRows is what one scope identifier holds in the scoped tables.
type pgScopeRows struct {
	series                    []string
	entries, blobs, documents int64
	// takeUps are the rows of gateway.series_holders: the instances that
	// took up a session of the scope (schema version 6), removed with it
	takeUps int64
}

func (h pgScopeRows) none() bool {
	return len(h.series) == 0 && h.entries == 0 && h.blobs == 0 && h.documents == 0
}

// removeScopeRows is the command's transaction. Out carries the records
// only once the transaction committed them.
func removeScopeRows(dsn pgDSN, o storeRemoveScopeOptions, priv ed25519.PrivateKey, stamp func() string) (out removalOutcome, err error) {
	roles := o.roles
	if !pgRoleName(roles.owner) || !pgRoleName(roles.runtime) {
		return out, errors.New("store: a role's name is 1 to 63 bytes with no NUL and no double quote")
	}
	if roles.owner == roles.runtime {
		return out, errors.New("store: the owner role and the run-time role are two roles")
	}
	deadline := time.Now().Add(o.timeout)
	c, err := pgConnect(dsn, deadline)
	if err != nil {
		return out, err
	}
	defer c.close()
	if err := c.conn.SetDeadline(deadline); err != nil {
		return out, pgTransport(err)
	}
	if _, err := c.exec(`SELECT pg_catalog.set_config('search_path', 'pg_catalog', false)`); err != nil {
		return out, err
	}
	if err := pgServerHolds(c); err != nil {
		return out, err
	}
	if err := pgMigrationRolesHold(c, roles); err != nil {
		return out, err
	}
	failed := func(err error) (removalOutcome, error) {
		if !c.broken {
			c.exec("ROLLBACK")
		}
		return removalOutcome{}, fmt.Errorf("%v; nothing was removed", err)
	}
	if _, err := c.exec("BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE"); err != nil {
		return out, err
	}
	// Row security stays forced on the owner: a statement reads and
	// changes the rows of the scope gateway.scope names alone.
	if _, err := c.exec(`SELECT pg_catalog.set_config('role', $1, true),
		pg_catalog.set_config('search_path', 'pg_catalog', true),
		pg_catalog.set_config('gateway.scope', $2, true),
		pg_catalog.pg_advisory_xact_lock($3)`, roles.owner, pgNoScope, int64(pgMigrationLock)); err != nil {
		return failed(err)
	}
	set := pgShippedMigrations()
	recorded, err := pgAppliedMigrations(c, roles.owner)
	if err != nil {
		return failed(err)
	}
	if err := pgRecordedMatch(recorded, set); err != nil {
		return failed(err)
	}
	if len(recorded) != len(set.versions) {
		return failed(fmt.Errorf("store: the database's schema is at version %d and this gateway's is %d; gateway store migrate raises it first", len(recorded), len(set.versions)))
	}
	// the lease's lock and every row of the lease, to the commit: no start
	// takes a row meanwhile, and the removal is refused while an instance
	// serves (ADR-0034, option 1; ADR-0035, option C)
	if err := pgHoldEveryInstance(c, "remove"); err != nil {
		return failed(err)
	}

	tx := pgTx{c}
	data, present, err := pgLog{name: "registry"}.readTx(tx, 0)
	if err != nil {
		return failed(err)
	}
	if !present {
		return failed(errors.New("the registry is not there; a gateway makes it when it starts, and its walk names the key the records are signed under"))
	}
	walk, err := engineWalk(data, priv.Public().(ed25519.PublicKey))
	if err != nil {
		return failed(err)
	}
	_, next, err := pgRemovalFile(tx)
	if err != nil {
		return failed(err)
	}

	row := pgRowScope(o.scope)
	if _, err := c.exec(`SELECT pg_catalog.set_config('gateway.scope', $1, true)`, row); err != nil {
		return failed(err)
	}
	held, err := pgScopeHeld(tx, row)
	if err != nil {
		return failed(err)
	}
	var lines [][]byte
	var notes []string
	if !held.none() {
		var sealed int64
		for _, session := range held.series {
			s, ok := walk.seals[session]
			if !ok {
				continue
			}
			sealed++
			// a seal of version 3 is named over the scope salt the
			// session's receipts carry (ADR-0042); one that is not the
			// seal's makes a record that does not name it, refused below
			var salt string
			if s.salted {
				if salt, err = pgSeriesSalt(tx, row, session); err != nil {
					return failed(err)
				}
			}
			record, line, err := signedSessionRemoval(priv, walk.keys, session, s, o.scope, salt, o.by, stamp())
			if err != nil {
				return failed(err)
			}
			lines = append(lines, line)
			out.appended = append(out.appended, record)
		}
		record, line, err := signedScopeRemoval(priv, walk.keys, o.scope, o.by, stamp(), scopeRemovalCounts{
			open: int64(len(held.series)) - sealed, sealed: sealed, receipts: held.entries, payloads: held.blobs,
		})
		if err != nil {
			return failed(err)
		}
		lines = append(lines, line)
		out.appended = append(out.appended, record)
		// the rows of the scope, named in each statement, and each count
		// held to what was read
		for _, d := range []struct {
			table string
			want  int64
		}{{"entries", held.entries}, {"series_holders", held.takeUps}, {"series", int64(len(held.series))}, {"blobs", held.blobs}, {"documents", held.documents}} {
			done, err := c.exec(`DELETE FROM gateway.`+d.table+` WHERE scope = $1`, row)
			if err != nil {
				return failed(err)
			}
			if done.tag != fmt.Sprintf("DELETE %d", d.want) {
				return failed(errors.New("the scope's rows changed while they were removed"))
			}
		}
		notes = append(notes, fmt.Sprintf("removed %d session(s), %d sealed, holding %d receipt(s), %d payload(s), and %d document(s)", len(held.series), sealed, held.entries, held.blobs, held.documents))
	}

	// the records and the scope identifier's row, of no scope
	if _, err := c.exec(`SELECT pg_catalog.set_config('gateway.scope', $1, true)`, pgNoScope); err != nil {
		return failed(err)
	}
	for _, line := range lines {
		if _, err := c.exec(`INSERT INTO gateway.removal_records (scope, ordinal, line) VALUES ($1, $2, $3)`, pgNoScope, next, bytes.TrimSuffix(line, []byte{'\n'})); err != nil {
			return failed(err)
		}
		next++
	}
	gone, err := c.exec(`DELETE FROM gateway.scope_identifiers WHERE scope = $1 AND identifier = $2`, pgNoScope, row)
	if err != nil {
		return failed(err)
	}
	switch {
	case held.none() && gone.tag == "DELETE 1":
		notes = append(notes, "the scope identifier was recorded and held no row; its record is removed, and nothing else was")
	case held.none():
		notes = append(notes, "no row of the scope identifier is in the store; nothing was removed")
	}
	done, err := c.exec("COMMIT")
	if err != nil {
		return removalOutcome{}, fmt.Errorf("the commit's answer did not arrive, so whether the removal was made is not known: %v; a second run removes what is left", err)
	}
	if done.tag != "COMMIT" {
		return removalOutcome{}, errors.New("the database rolled the removal back; nothing was removed")
	}
	out.notes = notes
	return out, nil
}

// pgSeriesSalt is the scope salt the first receipt of the session carries
// (ADR-0042), "" where it carries none or the session holds no receipt. It
// is not judged here: the record made over it is read back as a verifier
// reads it, and one that does not name the seal is refused.
func pgSeriesSalt(tx pgTx, row, session string) (string, error) {
	rows, err := tx.exec(`SELECT data FROM gateway.entries WHERE scope = $1 AND series = $2 ORDER BY name LIMIT 1`, row, session)
	if err != nil {
		return "", err
	}
	if len(rows.rows) != 1 {
		return "", nil
	}
	v, err := parseJSON(rows.rows[0][0])
	if err != nil {
		return "", nil
	}
	obj, isObject := v.(*vObject)
	if !isObject {
		return "", nil
	}
	salt, _ := memberString(obj, "scopeSalt")
	return salt, nil
}

// pgScopeHeld reads, with gateway.scope set to row, the scope's series and
// how many entries, blobs and documents it holds.
func pgScopeHeld(tx pgTx, row string) (pgScopeRows, error) {
	var h pgScopeRows
	series, err := tx.exec(`SELECT name FROM gateway.series WHERE scope = $1 ORDER BY name`, row)
	if err != nil {
		return h, err
	}
	for _, s := range series.rows {
		h.series = append(h.series, string(s[0]))
	}
	counts, err := tx.exec(`SELECT (SELECT count(*) FROM gateway.entries WHERE scope = $1),
		(SELECT count(*) FROM gateway.blobs WHERE scope = $1),
		(SELECT count(*) FROM gateway.documents WHERE scope = $1),
		(SELECT count(*) FROM gateway.series_holders WHERE scope = $1)`, row)
	if err != nil {
		return h, err
	}
	if len(counts.rows) != 1 {
		return h, errors.New("store: the scope's rows did not count")
	}
	for i, n := range []*int64{&h.entries, &h.blobs, &h.documents, &h.takeUps} {
		v, ok := pgInt8(counts.rows[0][i])
		if !ok {
			return h, errors.New("store: the scope's rows did not count")
		}
		*n = v
	}
	return h, nil
}

// pgRemovalFile reads the removal records, with gateway.scope set to
// 'none', as the store's removal file holds them: each row's line and a
// line feed, in the order of their ordinals, which run from 0 with no gap;
// and the ordinal the next record takes. A gap, or a line holding a line
// feed, is refused: the file would not be the one the records were kept as.
func pgRemovalFile(tx pgTx) ([]byte, int64, error) {
	rows, err := tx.exec(`SELECT ordinal, line FROM gateway.removal_records WHERE scope = $1 ORDER BY ordinal`, pgNoScope)
	if err != nil {
		return nil, 0, err
	}
	var file []byte
	for i, r := range rows.rows {
		ordinal, ok := pgInt8(r[0])
		if !ok || ordinal != int64(i) {
			return nil, 0, storeFailure(faultUnreadable, "removal-records", errors.New("store: the removal records do not run from 0 with no gap"))
		}
		if bytes.IndexByte(r[1], '\n') >= 0 {
			return nil, 0, storeFailure(faultUnreadable, "removal-records", errors.New("store: a removal record holds a line feed"))
		}
		file = append(append(file, r[1]...), '\n')
	}
	return file, int64(len(rows.rows)), nil
}
