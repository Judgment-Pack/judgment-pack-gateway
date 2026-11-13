package main

// The PostgreSQL storage kind's schema and the conditions it runs under
// (docs/adr/0031-a-second-storage-kind-on-postgresql.md, docs/postgresql-store.md).
//
// The schema is the SQL files under store_pg/, carried in the binary and
// recorded by digest in store_pg/SHA256SUMS. The migration applies them as
// the migration login, after SET ROLE to the owner role, in one transaction:
// every version not applied yet, each recorded with its file's digest, and
// then the run-time role's grants. A version applied with another digest,
// or one this binary does not carry, refuses the migration and the kind's
// start alike.
//
// The roles are the operator's, made beforehand and named here; nothing
// here creates a role or stores a setting on one or on the database.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"
	"time"
)

//go:embed store_pg/migrations/*.sql store_pg/grants.sql store_pg/SHA256SUMS
var pgSchemaFiles embed.FS

// pgMigration is one version of the schema: its file's name and bytes.
type pgMigration struct {
	version int
	name    string
	sql     []byte
}

func (m pgMigration) digest() string {
	sum := sha256.Sum256(m.sql)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// pgMigrationSet is a release's schema: its versions in order and the
// run-time role's grants.
type pgMigrationSet struct {
	versions []pgMigration
	grants   []byte
}

// digest is the set's own digest: of each version's line, then the grants'.
// A release names it (docs/postgresql-store.md).
func (s pgMigrationSet) digest() string {
	h := sha256.New()
	for _, m := range s.versions {
		fmt.Fprintf(h, "%d %s %s\n", m.version, m.name, m.digest())
	}
	sum := sha256.Sum256(s.grants)
	fmt.Fprintf(h, "grants sha256:%s\n", hex.EncodeToString(sum[:]))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// readPgMigrationSet reads a schema from files laid out as store_pg/ is:
// migrations/NNNN_name.sql numbered from 1 with no gap, and grants.sql.
func readPgMigrationSet(files fs.FS) (pgMigrationSet, error) {
	var set pgMigrationSet
	names, err := fs.Glob(files, "migrations/*.sql")
	if err != nil {
		return set, err
	}
	for i, name := range names {
		base := path.Base(name)
		number, _, ok := strings.Cut(base, "_")
		version, err := strconv.Atoi(number)
		if !ok || err != nil || len(number) != 4 || version != i+1 {
			return set, fmt.Errorf("store: migration %s is not numbered %04d", base, i+1)
		}
		data, err := fs.ReadFile(files, name)
		if err != nil {
			return set, err
		}
		set.versions = append(set.versions, pgMigration{version: version, name: base, sql: data})
	}
	if len(set.versions) == 0 {
		return set, errors.New("store: no migration")
	}
	if set.grants, err = fs.ReadFile(files, "grants.sql"); err != nil {
		return set, err
	}
	sums, err := fs.ReadFile(files, "SHA256SUMS")
	if err != nil {
		return set, err
	}
	recorded, err := pgRecordedDigests(sums)
	if err != nil {
		return set, err
	}
	actual := map[string][]byte{"grants.sql": set.grants}
	for _, m := range set.versions {
		actual["migrations/"+m.name] = m.sql
	}
	if len(recorded) != len(actual) {
		return set, errors.New("store: SHA256SUMS does not list every schema file and no other")
	}
	for name, data := range actual {
		sum := sha256.Sum256(data)
		if recorded[name] != hex.EncodeToString(sum[:]) {
			return set, fmt.Errorf("store: %s does not match its digest in SHA256SUMS", name)
		}
	}
	return set, nil
}

// pgShippedMigrations is the schema this binary carries.
func pgShippedMigrations() pgMigrationSet {
	sub, err := fs.Sub(pgSchemaFiles, "store_pg")
	if err != nil {
		panic(err)
	}
	set, err := readPgMigrationSet(sub)
	if err != nil {
		panic(err)
	}
	return set
}

// pgRecordedDigests reads store_pg/SHA256SUMS: a file's digest beside its
// path, as sha256sum writes it.
func pgRecordedDigests(data []byte) (map[string]string, error) {
	recorded := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		sum, name, ok := strings.Cut(line, "  ")
		if !ok || !isLowerHexOfLen(sum, 64) || name == "" {
			return nil, fmt.Errorf("store: SHA256SUMS line %q is not a digest and a path", line)
		}
		recorded[name] = sum
	}
	return recorded, scanner.Err()
}

// pgRoles are the roles the operator made, by name.
type pgRoles struct {
	owner   string
	runtime string
}

// pgRoleName is a role's name as the kind takes one: what PostgreSQL holds a
// name to (1 to 63 bytes), with no NUL and no double quote, so nothing that
// quotes it is ever asked to escape.
func pgRoleName(name string) bool {
	return len(name) >= 1 && len(name) <= 63 && !strings.ContainsAny(name, "\x00\"")
}

// The migration's lock: one migration at a time in the database.
const pgMigrationLock = 0x6761746577617931 // "gatewayl" in ASCII, a constant of this schema

// migratePostgres brings the database's schema to set as the migration
// login dsn names, and answers the versions it applied: none on a second
// run. Nothing is applied unless every condition below holds.
func migratePostgres(dsn pgDSN, set pgMigrationSet, roles pgRoles, timeout time.Duration) ([]int, error) {
	if !pgRoleName(roles.owner) || !pgRoleName(roles.runtime) {
		return nil, errors.New("store: a role's name is 1 to 63 bytes with no NUL and no double quote")
	}
	if roles.owner == roles.runtime {
		return nil, errors.New("store: the owner role and the run-time role are two roles")
	}
	deadline := time.Now().Add(timeout)
	c, err := pgConnect(dsn, deadline)
	if err != nil {
		return nil, err
	}
	defer c.close()
	if err := c.conn.SetDeadline(deadline); err != nil {
		return nil, pgTransport(err)
	}
	if err := pgServerHolds(c); err != nil {
		return nil, err
	}
	if err := pgMigrationRolesHold(c, roles); err != nil {
		return nil, err
	}
	var applied []int
	failed := func(err error) ([]int, error) {
		if !c.broken {
			c.exec("ROLLBACK")
		}
		return nil, err
	}
	if _, err := c.exec("BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE"); err != nil {
		return nil, err
	}
	if _, err := c.exec(`SELECT pg_catalog.set_config('role', $1, true),
		pg_catalog.set_config('search_path', 'pg_catalog', true),
		pg_catalog.set_config('gateway.runtime_role', $2, true),
		pg_catalog.pg_advisory_xact_lock($3)`, roles.owner, roles.runtime, int64(pgMigrationLock)); err != nil {
		return failed(err)
	}
	recorded, err := pgAppliedMigrations(c, roles.owner)
	if err != nil {
		return failed(err)
	}
	if err := pgRecordedMatch(recorded, set); err != nil {
		return failed(err)
	}
	for _, m := range set.versions[len(recorded):] {
		if err := c.script(string(m.sql)); err != nil {
			return failed(fmt.Errorf("store: migration %s: %w", m.name, err))
		}
		if _, err := c.exec(`INSERT INTO gateway.schema_migrations (version, name, digest) VALUES ($1, $2, $3)`, m.version, m.name, m.digest()); err != nil {
			return failed(err)
		}
		applied = append(applied, m.version)
	}
	if err := c.script(string(set.grants)); err != nil {
		return failed(fmt.Errorf("store: grants: %w", err))
	}
	done, err := c.exec("COMMIT")
	if err != nil {
		return nil, err
	}
	if done.tag != "COMMIT" {
		return nil, errors.New("store: the database rolled the migration back")
	}
	return applied, nil
}

// pgRecord is a version the database records as applied.
type pgRecord struct {
	version int
	name    string
	digest  string
}

// pgAppliedMigrations reads what the schema records, or nothing for a
// database where the schema is not there yet. A schema of that name that
// another role owns, or that holds no record, is another's, and refused.
func pgAppliedMigrations(c *pgConn, owner string) ([]pgRecord, error) {
	rows, err := c.exec(`SELECT r.rolname = $1,
		EXISTS (SELECT 1 FROM pg_catalog.pg_class t WHERE t.relnamespace = n.oid AND t.relname = 'schema_migrations')
		FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles r ON r.oid = n.nspowner WHERE n.nspname = 'gateway'`, owner)
	if err != nil {
		return nil, err
	}
	if len(rows.rows) == 0 {
		return nil, nil
	}
	owned, _ := pgBool(rows.rows[0][0])
	recorded, _ := pgBool(rows.rows[0][1])
	if !owned {
		return nil, errors.New("store: the schema gateway is there and another role owns it; the store keeps a database of its own")
	}
	if !recorded {
		return nil, errors.New("store: the schema gateway is there and records no migration; it is not this store's")
	}
	records, err := c.exec(`SELECT version::int8, name, digest FROM gateway.schema_migrations ORDER BY version`)
	if err != nil {
		return nil, err
	}
	var out []pgRecord
	for _, row := range records.rows {
		v, _ := pgInt8(row[0])
		out = append(out, pgRecord{version: int(v), name: string(row[1]), digest: string(row[2])})
	}
	return out, nil
}

// pgRecordedMatch holds what the database records to the set: every version
// it records is the set's, in order, by name and by digest. A version the
// set does not carry is a schema newer than this binary.
func pgRecordedMatch(recorded []pgRecord, set pgMigrationSet) error {
	if len(recorded) > len(set.versions) {
		return fmt.Errorf("store: the database's schema is at version %d and this gateway's migrations reach version %d; a gateway older than its schema does not run on it", recorded[len(recorded)-1].version, len(set.versions))
	}
	for i, r := range recorded {
		m := set.versions[i]
		if r.version != m.version || r.name != m.name {
			return fmt.Errorf("store: the database records migration %d as %s, which is not this gateway's %s", r.version, r.name, m.name)
		}
		if r.digest != m.digest() {
			return fmt.Errorf("store: migration %s was applied with digest %s, and this gateway's file digests to %s; a migration is never changed once applied", m.name, r.digest, m.digest())
		}
	}
	return nil
}

// pgServerHolds refuses a server older than the major version tested or a
// database whose encoding is not UTF-8.
func pgServerHolds(c *pgConn) error {
	version, err := strconv.Atoi(c.params["server_version_num"])
	if err != nil {
		rows, qerr := c.exec(`SELECT pg_catalog.current_setting('server_version_num')`)
		if qerr != nil {
			return qerr
		}
		if len(rows.rows) == 1 {
			version, err = strconv.Atoi(string(rows.rows[0][0]))
		}
		if err != nil {
			return errors.New("store: the server's version did not read")
		}
	}
	if version < pgMinServerVersion {
		return errors.New("store: the PostgreSQL storage kind runs on PostgreSQL 16 or later")
	}
	if c.params["server_encoding"] != "UTF8" {
		return errors.New("store: the PostgreSQL storage kind runs on a database whose encoding is UTF8")
	}
	return nil
}

// pgRoleWithout names the attributes no role of the store holds: each would
// let it past the row security or the privileges the store is kept under,
// or make roles and databases, which nothing at run time needs.
const pgRoleWithout = `(r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication)`

// pgMigrationRolesHold holds the roles to what the migration needs and no
// more: an owner that cannot log in and is no superuser, reached by the
// migration login by SET ROLE alone, and a run-time role that is neither
// the owner nor reaches it, and holds no attribute past its privileges.
func pgMigrationRolesHold(c *pgConn, roles pgRoles) error {
	rows, err := c.exec(`SELECT
		(SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname = $1)::int8,
		(SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname = $2)::int8,
		(SELECT r.rolcanlogin FROM pg_catalog.pg_roles r WHERE r.rolname = $1),
		(SELECT `+pgRoleWithout+` FROM pg_catalog.pg_roles r WHERE r.rolname = $1),
		(SELECT `+pgRoleWithout+` FROM pg_catalog.pg_roles r WHERE r.rolname = $2),
		(SELECT r.rolsuper OR r.rolbypassrls FROM pg_catalog.pg_roles r WHERE r.rolname = current_user),
		current_user = $1 OR current_user = $2`, roles.owner, roles.runtime)
	if err != nil {
		return err
	}
	if len(rows.rows) != 1 {
		return errors.New("store: the roles did not read")
	}
	row := rows.rows[0]
	if n, _ := pgInt8(row[0]); n != 1 {
		return fmt.Errorf("store: the owner role %s is not there; the operator makes the roles beforehand", roles.owner)
	}
	if n, _ := pgInt8(row[1]); n != 1 {
		return fmt.Errorf("store: the run-time role %s is not there; the operator makes the roles beforehand", roles.runtime)
	}
	if login, _ := pgBool(row[2]); login {
		return fmt.Errorf("store: the owner role %s can log in; the owner of the store's objects is a role no one logs in as", roles.owner)
	}
	if over, _ := pgBool(row[3]); over {
		return fmt.Errorf("store: the owner role %s is a superuser or holds BYPASSRLS, CREATEROLE, CREATEDB or REPLICATION", roles.owner)
	}
	if over, _ := pgBool(row[4]); over {
		return fmt.Errorf("store: the run-time role %s is a superuser or holds BYPASSRLS, CREATEROLE, CREATEDB or REPLICATION", roles.runtime)
	}
	if over, _ := pgBool(row[5]); over {
		return errors.New("store: the migration login is a superuser or holds BYPASSRLS; it reaches the owner role by SET ROLE and nothing past it")
	}
	if same, _ := pgBool(row[6]); same {
		return errors.New("store: the migration login is neither the owner role nor the run-time role")
	}
	reach, err := c.exec(`SELECT pg_catalog.pg_has_role(current_user, $1, 'SET'),
		pg_catalog.pg_has_role(current_user, $1, 'USAGE'),
		pg_catalog.pg_has_role($2, $1, 'MEMBER'),
		EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE `+pgRoleWithout+` AND pg_catalog.pg_has_role($2, r.oid, 'MEMBER'))`, roles.owner, roles.runtime)
	if err != nil {
		return err
	}
	row = reach.rows[0]
	if set, _ := pgBool(row[0]); !set {
		return fmt.Errorf("store: the migration login cannot SET ROLE %s", roles.owner)
	}
	if inherits, _ := pgBool(row[1]); inherits {
		return fmt.Errorf("store: the migration login holds the privileges of %s without SET ROLE; grant it WITH INHERIT FALSE", roles.owner)
	}
	if member, _ := pgBool(row[2]); member {
		return fmt.Errorf("store: the run-time role %s reaches the owner role %s", roles.runtime, roles.owner)
	}
	if member, _ := pgBool(row[3]); member {
		return fmt.Errorf("store: the run-time role %s reaches a role that is a superuser or holds BYPASSRLS, CREATEROLE, CREATEDB or REPLICATION", roles.runtime)
	}
	return nil
}

// pgPrivileges is what the run-time role holds on each table, and nothing
// else: grants.sql gives exactly this. Every other privilege a table has is
// refused at the kind's start.
var pgPrivileges = map[string][]string{
	"schema_migrations": {"SELECT"},
	"blobs":             {"SELECT", "INSERT"},
	"series":            {"SELECT", "INSERT"},
	"entries":           {"SELECT", "INSERT"},
	"logs":              {"SELECT", "INSERT"},
	"log_records":       {"SELECT", "INSERT"},
	"secrets":           {"SELECT", "INSERT"},
	"documents":         {"SELECT", "INSERT", "UPDATE", "DELETE"},
}

// pgTables are the schema's tables, in the order the start reads them.
var pgTables = []string{"blobs", "documents", "entries", "log_records", "logs", "schema_migrations", "secrets", "series"}

// pgScopedTables are the tables whose rows carry a scope identifier: row
// security is enabled and forced on each.
var pgScopedTables = []string{"blobs", "documents", "entries", "series"}

// pgTablePrivileges are the privileges a table has (pgPrivilegesHold).
var pgTablePrivileges = []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"}

// holdsItsConditions is the kind's start: the server, the login it runs as,
// the schema's migrations and its row security are held to what the kind
// is run under, and the kind does not open otherwise. The run-time login
// holds no attribute past its privileges, does not reach the owner, makes
// nothing in the database or the schema, and holds on each table exactly
// the privileges grants.sql gives.
func (k *pgKind) holdsItsConditions(set pgMigrationSet) error {
	return k.transact(pgReadSnapshot, func(tx pgTx) error {
		if err := pgServerHolds(tx.c); err != nil {
			return err
		}
		rows, err := tx.exec(`SELECT
			(SELECT ` + pgRoleWithout + ` FROM pg_catalog.pg_roles r WHERE r.rolname = current_user),
			EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE (` + pgRoleWithout + ` OR r.oid = n.nspowner) AND pg_catalog.pg_has_role(current_user, r.oid, 'MEMBER')),
			pg_catalog.has_database_privilege(pg_catalog.current_database(), 'CREATE') OR pg_catalog.has_database_privilege(pg_catalog.current_database(), 'TEMPORARY'),
			EXISTS (SELECT 1 FROM pg_catalog.pg_namespace m WHERE pg_catalog.has_schema_privilege(m.oid, 'CREATE'))
			FROM pg_catalog.pg_namespace n WHERE n.nspname = 'gateway'`)
		if err != nil {
			return err
		}
		if len(rows.rows) == 0 {
			return errors.New("store: the database holds no schema gateway; the store's migrations are applied first (docs/postgresql-store.md)")
		}
		row := rows.rows[0]
		if over, _ := pgBool(row[0]); over {
			return errors.New("store: the run-time login is a superuser or holds BYPASSRLS, CREATEROLE, CREATEDB or REPLICATION")
		}
		if reaches, _ := pgBool(row[1]); reaches {
			return errors.New("store: the run-time login is, or reaches, the schema's owner or a role past its privileges")
		}
		if create, _ := pgBool(row[2]); create {
			return errors.New("store: the run-time login may create schemas or temporary tables in the database; it holds table privileges alone")
		}
		if create, _ := pgBool(row[3]); create {
			return errors.New("store: the run-time login may create objects in a schema of the database; it holds table privileges alone")
		}
		records, err := pgAppliedMigrationsTx(tx)
		if err != nil {
			return err
		}
		if err := pgRecordedMatch(records, set); err != nil {
			return err
		}
		if len(records) != len(set.versions) {
			return fmt.Errorf("store: the database's schema is at version %d and this gateway's is %d; apply the store's migrations (docs/postgresql-store.md)", len(records), len(set.versions))
		}
		if err := pgPrivilegesHold(tx); err != nil {
			return err
		}
		return pgSchemaHolds(tx)
	})
}

// pgPrivilegesHold holds the run-time login to exactly the privileges
// pgPrivileges names on each table, by table and by column alike: a column
// privilege (UPDATE of one column, say) is a privilege the store does not
// give as much as the table's is.
func pgPrivilegesHold(tx pgTx) error {
	held, err := tx.exec(`SELECT c.relname, p.privilege, pg_catalog.has_table_privilege(c.oid, p.privilege),
		p.privilege IN ('SELECT', 'INSERT', 'UPDATE', 'REFERENCES') AND pg_catalog.has_any_column_privilege(c.oid, p.privilege)
		FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) AS p (privilege)
		WHERE n.nspname = 'gateway' AND c.relkind = 'r'`)
	if err != nil {
		return err
	}
	seen := map[string]int{}
	for _, row := range held.rows {
		table, privilege := string(row[0]), string(row[1])
		onTable, _ := pgBool(row[2])
		onColumn, _ := pgBool(row[3])
		want := contains(pgPrivileges[table], privilege)
		columnar := privilege == "SELECT" || privilege == "INSERT" || privilege == "UPDATE" || privilege == "REFERENCES"
		if onTable && !want || onColumn && !want {
			return fmt.Errorf("store: the run-time login holds %s on gateway.%s, which the store does not give it", privilege, table)
		}
		if want && (!onTable || columnar && !onColumn) {
			return fmt.Errorf("store: the run-time login lacks %s on gateway.%s; apply the store's migrations naming it the run-time role", privilege, table)
		}
		seen[table]++
	}
	for _, table := range pgTables {
		if seen[table] != len(pgTablePrivileges) {
			return fmt.Errorf("store: the table gateway.%s is not there", table)
		}
	}
	return nil
}

// pgScopePolicy is the one policy on each table whose rows carry a scope
// identifier, as the server prints it under the search path the kind sets.
const pgScopePolicy = `(scope = COALESCE(current_setting('gateway.scope'::text, true), ''::text))`

// pgSchemaHolds holds the schema to what the migrations made: the store's
// tables and their indexes alone, with no view, sequence, function,
// trigger or rule beside them; row security enabled and forced on every
// table with a column scope, and on each of those one policy, the scope's,
// for every command and every role; and on no other table any policy.
func pgSchemaHolds(tx pgTx) error {
	objects, err := tx.exec(`SELECT c.relname, c.relkind::text,
		EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'scope' AND NOT a.attisdropped),
		c.relrowsecurity AND c.relforcerowsecurity
		FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'gateway' ORDER BY c.relname`)
	if err != nil {
		return err
	}
	tables := []string{}
	for _, row := range objects.rows {
		name, kind := string(row[0]), string(row[1])
		scoped, _ := pgBool(row[2])
		secured, _ := pgBool(row[3])
		switch kind {
		case "i":
			continue
		case "r":
		default:
			return fmt.Errorf("store: the schema gateway holds %s, which is not one of the store's tables", name)
		}
		tables = append(tables, name)
		if scoped != contains(pgScopedTables, name) {
			return fmt.Errorf("store: the table gateway.%s carries a scope identifier other than the store's tables do", name)
		}
		if scoped && !secured {
			return fmt.Errorf("store: row security is not enabled and forced on gateway.%s", name)
		}
	}
	if strings.Join(tables, " ") != strings.Join(pgTables, " ") {
		return fmt.Errorf("store: the schema gateway holds the tables %v, and the store's are %v", tables, pgTables)
	}
	others, err := tx.exec(`SELECT
		(SELECT count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'gateway')::int8,
		(SELECT count(*) FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
			JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'gateway' AND NOT t.tgisinternal)::int8,
		(SELECT count(*) FROM pg_catalog.pg_rewrite w JOIN pg_catalog.pg_class c ON c.oid = w.ev_class
			JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'gateway')::int8,
		(SELECT count(*) FROM pg_catalog.pg_type y JOIN pg_catalog.pg_namespace n ON n.oid = y.typnamespace
			WHERE n.nspname = 'gateway' AND y.typrelid = 0 AND y.typelem = 0)::int8`)
	if err != nil {
		return err
	}
	for i, what := range []string{"a function", "a trigger", "a rule", "a type"} {
		if n, _ := pgInt8(others.rows[0][i]); n != 0 {
			return fmt.Errorf("store: the schema gateway holds %s, and the store's schema holds none", what)
		}
	}
	policies, err := tx.exec(`SELECT c.relname, p.polname, p.polpermissive, p.polcmd::text, p.polroles = '{0}'::oid[],
		pg_catalog.pg_get_expr(p.polqual, p.polrelid), pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid)
		FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid = p.polrelid
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'gateway'`)
	if err != nil {
		return err
	}
	held := map[string]bool{}
	for _, row := range policies.rows {
		table := string(row[0])
		permissive, _ := pgBool(row[2])
		everyone, _ := pgBool(row[4])
		if !contains(pgScopedTables, table) || held[table] || string(row[1]) != "scope_of_the_transaction" ||
			!permissive || string(row[3]) != "*" || !everyone || string(row[5]) != pgScopePolicy || string(row[6]) != pgScopePolicy {
			return fmt.Errorf("store: gateway.%s holds the policy %s, which is not the store's scope policy", table, row[1])
		}
		held[table] = true
	}
	for _, table := range pgScopedTables {
		if !held[table] {
			return fmt.Errorf("store: gateway.%s holds no scope policy", table)
		}
	}
	return nil
}

func pgAppliedMigrationsTx(tx pgTx) ([]pgRecord, error) {
	records, err := tx.exec(`SELECT version::int8, name, digest FROM gateway.schema_migrations ORDER BY version`)
	if err != nil {
		return nil, err
	}
	var out []pgRecord
	for _, row := range records.rows {
		v, _ := pgInt8(row[0])
		out = append(out, pgRecord{version: int(v), name: string(row[1]), digest: string(row[2])})
	}
	return out, nil
}
