package main

// `gateway store rotate-key` (ADR-0050, decision 3(a); SPEC.md §3b; gateway
// #563): the PostgreSQL kind's signing key handed on to the next, every
// instance stopped. On this kind SIGHUP rotation is refused
// (errRotationOnKind) and gateway rotate-key needs a file registry, so this
// is the one way a store on the kind moves from the seed to a key service,
// or from one key service's key version to the next.
//
// It is run as gateway store retain is (store_retain.go): as the migration
// login acting as the owner role, in one transaction that holds the
// migration's lock and every row of the start lease, none of them live, so
// a gateway serving the database refuses it and no instance starts while it
// runs. In that transaction the registry is read under the log's append
// lock, as every append reads it, and walked; the record of SPEC.md §3b's
// two statements is signed -- the key-rotation by the key rotated from, the
// key-continuation by the next key, each signature held to its key before it
// is written (rotationRecordSigned, the record form a rotation while serving
// writes) -- and appended by the statement every append of the log is
// (pgLogAppendAtEnd); and the registry is read back and walked to the next
// key before the COMMIT. The record commits whole or not at all, so no part
// of it is ever left in the registry. A COMMIT whose answer did not arrive
// is settled by a rerun: one that finds the rotation's record whole at the
// registry's end changes nothing, and one that finds none rotates.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"
)

const storeRotateKeyUsage = `  gateway store rotate-key (--connection-file <path> | --connection-env <NAME>) --owner <role> --runtime <role> --config <engine.json> [--from-key-version <name> --from-public-key <hex>] [--timeout <seconds>]
Rotates the PostgreSQL kind's signing key, every instance stopped, to the key
service's key version the configuration names (signingKeyVersion, held to
signingPublicKey), from the key the registry's walk ends at: the seed's key, or
the key version --from-key-version names, held to --from-public-key. As the
migration login acting as the owner role, under the migration's lock and every
row of the start lease, it appends SPEC.md §3b's key-rotation, signed by the key
rotated from, and key-continuation, signed by the next key, in one transaction.
It is refused while a session that holds a receipt is open: seal it first with
gateway seal-open --config under the key in force. A rerun finds the rotation
made, and changes nothing, or makes it.`

// storeRotateKeyOpen refuses a rotation while a session holding a receipt
// is open: its seal is made under the key rotated from, before the
// rotation, so the seal's count bounds what that key signed in it.
// storeRotateKeyBefore refuses a rotation whose rotatedAt, this host's
// clock, is before the key history's last rotation: the registry is
// append-only, so a history its own check refuses (SPEC.md §3e) would be
// answered 500 by /publickey/history for good. Every writer of a rotation
// says it (keyHistoryWriteRefusal): this command, SIGHUP's rotateTo and
// gateway rotate-key.
const storeRotateKeyBefore = "the rotation's rotatedAt %s is before the key history's last rotation %s; correct this host's clock and run again; nothing was written"

const storeRotateKeyOpen = "session %s holds a receipt and is not sealed: a rotation seals nothing; seal every session left open first, under the key in force, with gateway seal-open --config <the configuration naming it> --all, then rotate"

// keyRotationOutcome is what the command did: the record it appended, or
// none where an earlier run had made the rotation already, and the
// rotation's ordinal.
type keyRotationOutcome struct {
	record   []byte
	ordinal  int
	from, to *signingKey
}

// rotateKeyBeforeCommit, where it is not nil, runs on the command's
// connection once the record is appended and read back, just before the
// COMMIT: a test makes the COMMIT's answer uncertain there.
var rotateKeyBeforeCommit func(c *pgConn)

func cmdStoreRotateKey(args []string, stdout, stderr io.Writer) int {
	return cmdStoreRotateKeyAt(args, stdout, stderr, nowStamp)
}

// cmdStoreRotateKeyAt is the command, the rotation stamped by stamp.
func cmdStoreRotateKeyAt(args []string, stdout, stderr io.Writer, stamp func() string) int {
	const command = "store rotate-key"
	usage := "usage:\n" + storeRotateKeyUsage
	flags, code := storeFlags(args, []string{"--connection-file", "--connection-env", "--owner", "--runtime", "--config", "--from-key-version", "--from-public-key", "--timeout"}, command, usage, stderr)
	if code != 0 {
		return code
	}
	if flags["--config"] == "" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	fromVersion, fromPublic := flags["--from-key-version"], flags["--from-public-key"]
	switch {
	case (fromVersion == "") != (fromPublic == ""):
		fmt.Fprintf(stderr, "%s: --from-key-version and --from-public-key name the key version rotated from together, as signingKeyVersion and signingPublicKey do; the seed's key is rotated from with neither\n%s\n", command, usage)
		return 2
	case fromVersion != "" && !keyVersionForm.MatchString(fromVersion):
		fmt.Fprintf(stderr, "%s: --from-key-version is one key version's resource name, %s\n%s\n", command, keyVersionFormText, usage)
		return 2
	case fromPublic != "" && !signingPublicKeyForm.MatchString(fromPublic):
		fmt.Fprintf(stderr, "%s: --from-public-key is the key version's Ed25519 public key, 64 lowercase hexadecimal characters\n%s\n", command, usage)
		return 2
	}
	timeout, ok := storeTimeout(flags, command, usage, stderr)
	if !ok {
		return 2
	}
	data, err := readBounded(flags["--config"], maxEngineConfigBytes)
	if err != nil {
		fmt.Fprintf(stderr, "%s: engine configuration: %v\n", command, err)
		return 1
	}
	cfg, err := parseEngineConfig(data)
	if err != nil {
		fmt.Fprintln(stderr, command+":", err)
		return 1
	}
	if cfg.storage == nil {
		fmt.Fprintf(stderr, "%s: the engine configuration names the filesystem kind, whose key is rotated by gateway rotate-key, the seed's, or by SIGHUP to a key service's key version (ADR-0050); gateway store rotate-key is the PostgreSQL kind's\n%s\n", command, usage)
		return 2
	}
	spec, code := storeConnectionSpec(flags, command, stderr)
	if code != 0 {
		return code
	}
	out, err := storeRotateKey(spec, pgRoles{owner: flags["--owner"], runtime: flags["--runtime"]}, cfg, fromVersion, fromPublic, timeout, stamp)
	if err != nil {
		fmt.Fprintln(stderr, command+":", err)
		return 1
	}
	if out.record == nil {
		fmt.Fprintf(stderr, "%s: the registry's walk already ends at this rotation, rotation %d from key %s to key %s, which may be an earlier run's: nothing was changed\n", command, out.ordinal, out.from.keyID, out.to.keyID)
		return 0
	}
	stdout.Write(bytes.TrimLeft(out.record, "\n"))
	fmt.Fprintf(stderr, "%s: rotation %d: key %s rotated to key %s, the key service's key version %s; start every instance under the configuration naming it\n", command, out.ordinal, out.from.keyID, out.to.keyID, cfg.signingKeyVersion)
	return 0
}

// storeRotateKey is the command once its arguments hold: the key rotated
// from -- the seed's, or the key version named, held to its public key --
// and the next, the configuration's key version held to signingPublicKey,
// each read and checked as at the start, then the rotation (rotateKeyRows).
func storeRotateKey(spec *storageSpec, roles pgRoles, cfg engineConfig, fromVersion, fromPublic string, timeout time.Duration, stamp func() string) (keyRotationOutcome, error) {
	if cfg.signingKeyVersion == "" {
		return keyRotationOutcome{}, errors.New("the engine configuration names no signingKeyVersion: a rotation on the PostgreSQL kind is to a key service's key version, which the configuration names beside signingPublicKey; nothing was changed")
	}
	at := stamp()
	if !witnessTimeForm.MatchString(at) {
		return keyRotationOutcome{}, errors.New("a rotation is stamped YYYY-MM-DDThh:mm:ssZ; nothing was changed")
	}
	seed, err := loadSeed(cfg.seed)
	if err != nil {
		return keyRotationOutcome{}, fmt.Errorf("seed: %w; nothing was changed", err)
	}
	dsn, err := storageConnection(spec)
	if err != nil {
		return keyRotationOutcome{}, err
	}
	from, err := commandSigner(fromVersion, fromPublic, seed)
	if err != nil {
		return keyRotationOutcome{}, fmt.Errorf("the key rotated from: %w; nothing was changed", err)
	}
	next, err := commandSigner(cfg.signingKeyVersion, cfg.signingPublicKey, seed)
	if err != nil {
		return keyRotationOutcome{}, fmt.Errorf("the next key: %w; nothing was changed", err)
	}
	return rotateKeyRows(dsn, roles, newSigningKey(from), newSigningKey(next), timeout, at)
}

// rotateKeyRows rotates the registry the database keeps from from to to,
// stamped at, in one transaction of the migration login acting as the
// owner, under the migration's lock and every row of the start lease. The
// registry's walk must end at from, or, where an earlier run committed the
// rotation, at to by a rotation from from, which is answered as made with
// nothing changed. Anything refused rolls the transaction back.
func rotateKeyRows(dsn pgDSN, roles pgRoles, from, to *signingKey, timeout time.Duration, at string) (keyRotationOutcome, error) {
	out := keyRotationOutcome{from: from, to: to}
	if !pgRoleName(roles.owner) || !pgRoleName(roles.runtime) {
		return out, errors.New("store: a role's name is 1 to 63 bytes with no NUL and no double quote")
	}
	if roles.owner == roles.runtime {
		return out, errors.New("store: the owner role and the run-time role are two roles")
	}
	deadline := time.Now().Add(timeout)
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
	rollback := func() {
		if !c.broken {
			c.exec("ROLLBACK")
		}
	}
	failed := func(err error) (keyRotationOutcome, error) {
		rollback()
		return keyRotationOutcome{}, fmt.Errorf("%v; nothing was changed", err)
	}
	if _, err := c.exec("BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE"); err != nil {
		return out, err
	}
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
	// every instance stopped: the lease's lock and every row of it held to
	// the commit, refused at once while a row is live or a write of an
	// instance whose row ran out holds it still
	if err := pgHoldEveryInstance(c, "rotate-key"); err != nil {
		return failed(err)
	}
	// a database rotated away from takes nothing more: a record appended
	// to its registry would break the link the new store names (ADR-0048)
	if err := pgRefuseRotated(c); err != nil {
		return failed(err)
	}
	tx := pgTx{c}
	// the registry's end taken as every append takes it
	if _, err := c.exec(`SELECT pg_catalog.pg_advisory_xact_lock($1)`, int64(pgLogAppendLock)); err != nil {
		return failed(err)
	}
	registry := pgLog{name: "registry"}
	data, present, err := registry.readTx(tx, 0)
	if err != nil {
		return failed(err)
	}
	if !present {
		return failed(errors.New("the registry is not there; a gateway makes it when it starts, and a rotation is recorded in it"))
	}
	// the walk as the gateway's own reading makes it, from the key its
	// first rotation rotated from; anything it finds refuses
	walk := walkRegistry(data, registryFirstKey(data, from.public))
	if err := walk.ownReading(walk.current().key); err != nil {
		return failed(err)
	}
	end := walk.current()
	if end.keyID == to.keyID {
		// a rerun after a COMMIT that did not answer: the rotation from
		// the key rotated from to the next key is the walk's last
		if n := len(walk.keys); n >= 2 && walk.keys[n-2].keyID == from.keyID {
			rollback()
			out.ordinal = n - 1
			return out, nil
		}
		return failed(fmt.Errorf("the next key, key id %s, is the key in force already: the registry's walk ends at it; a rotation is to a key other than the one in force", to.keyID))
	}
	if end.keyID != from.keyID {
		return failed(fmt.Errorf("the registry's walk ends at key id %s, not at the key rotated from, key id %s: the key rotated from is the key in force, the seed's with no --from-key-version, or the key version --from-key-version and --from-public-key name", end.keyID, from.keyID))
	}
	// the key rotated from is the key in force: nothing in the registry,
	// and no session's first receipt, is under a key the walk did not
	// reach, read in every row scope under its row security
	if err := heldUnderAnotherKey(data, walk.keys, from.public, nil); err != nil {
		return failed(err)
	}
	ids, err := tx.exec(`SELECT identifier FROM gateway.scope_identifiers ORDER BY identifier`)
	if err != nil {
		return failed(err)
	}
	rowScopes := []string{pgNoScope}
	for _, r := range ids.rows {
		rowScopes = append(rowScopes, string(r[0]))
	}
	var firsts []seriesFirst
	for _, row := range rowScopes {
		if _, err := c.exec(`SELECT pg_catalog.set_config('gateway.scope', $1, true)`, row); err != nil {
			return failed(err)
		}
		rows, err := tx.exec(`SELECT DISTINCT ON (e.series) e.series, e.data FROM gateway.entries e
			WHERE e.scope = $1 ORDER BY e.series, e.name COLLATE "C"`, row)
		if err != nil {
			return failed(err)
		}
		for _, r := range rows.rows {
			firsts = append(firsts, seriesFirst{series: string(r[0]), data: r[1]})
		}
	}
	if _, err := c.exec(`SELECT pg_catalog.set_config('gateway.scope', $1, true)`, pgNoScope); err != nil {
		return failed(err)
	}
	if err := firstsUnderAnotherKey(firsts, walk.keys, from.public); err != nil {
		return failed(err)
	}
	for _, f := range firsts {
		// a series no session id names is no session (SPEC.md §3a), and
		// seal-open seals none
		if _, sealed := walk.seals[f.series]; !sealed && requireSession(f.series) == nil {
			return failed(fmt.Errorf(storeRotateKeyOpen, f.series))
		}
	}
	// the key history as /publickey/history makes it, from the registry
	// and what a store rotation carried into gateway.key_history; held
	// again with the record at its end before the COMMIT
	carriedRows, err := tx.exec(`SELECT history FROM gateway.key_history`)
	if err != nil {
		return failed(err)
	}
	var carried []byte
	carriedPresent := len(carriedRows.rows) == 1
	if carriedPresent {
		carried = carriedRows.rows[0][0]
	}
	before, err := registryKeyHistory(data, from.public, carried, carriedPresent)
	if err != nil {
		return failed(fmt.Errorf("the key history before the rotation does not hold: %w", err))
	}
	ordinal := walk.followed() + 1
	record, err := rotationRecordSigned(data, ordinal, at, from, to)
	if err != nil {
		return failed(fmt.Errorf("the rotation's record could not be signed: %w", err))
	}
	if len(record) > pgMaxValue {
		return failed(fmt.Errorf("store: a record of %d bytes is past the kind's bound of %d", len(record), pgMaxValue))
	}
	appended, err := tx.exec(pgLogAppendAtEnd, "registry", record)
	if err != nil {
		return failed(err)
	}
	if len(appended.rows) != 1 {
		return failed(errors.New("store: the rotation's record was not appended"))
	}
	// read back before the COMMIT: the registry is the one walked with the
	// record at its end, and walks to the next key
	again, _, err := registry.readTx(tx, 0)
	if err != nil {
		return failed(err)
	}
	if !bytes.Equal(again, append(bytes.Clone(data), record...)) {
		return failed(errors.New("the registry read back is not the registry walked with the rotation's record at its end"))
	}
	if _, err := engineWalk(again, to.public); err != nil {
		return failed(fmt.Errorf("the rotation's record would not walk to the next key: %w", err))
	}
	if err := keyHistoryWriteRefusal(before, at, storeRotateKeyBefore, keyHistoryRotationFault, func() error {
		_, err := walkKeyHistory(again, to.public, carried, carriedPresent)
		return err
	}); err != nil {
		return failed(err)
	}
	if rotateKeyBeforeCommit != nil {
		rotateKeyBeforeCommit(c)
	}
	done, err := c.exec("COMMIT")
	if err != nil {
		return keyRotationOutcome{}, fmt.Errorf("the COMMIT's answer did not arrive, so whether the rotation was made is not known: %v; the key may have rotated: rerun to check (a rerun finds the rotation's record whole and changes nothing, or finds none and rotates)", err)
	}
	if done.tag != "COMMIT" {
		return keyRotationOutcome{}, errors.New("the database rolled the rotation back; nothing was changed")
	}
	out.record, out.ordinal = record, ordinal
	return out, nil
}
