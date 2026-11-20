package main

// `gateway store rotate` on the PostgreSQL kind (ADR-0048, decision 3;
// SPEC.md §3d; docs/postgresql-store.md, "Rotating the store"): the store
// let go of by starting another in a new database. A new instance on the
// same database is no new store: every instance on one database shares one
// registry chain (ADR-0035; #471, option C).
//
// The old database is reached as seal-open --config reaches it, by the
// configuration's run-time login: the start lease is taken first, in the
// one-instance mode whatever storage.instances says, so the command is
// refused while any instance serves and no instance starts while it runs;
// every session left open is sealed under it, as seal-open --all seals it,
// each seal fenced on the lease; and nothing else is written there.
//
// The new database is reached as gateway store migrate reaches it, by the
// migration login acting as the owner. Before anything is sealed, the
// migrations are run there in a transaction rolled back at its end, and the
// database is held to be empty in it; a database that cannot be migrated,
// or that holds a store, refuses the rotation with nothing changed. Once
// the seals are appended, the migrations are run again and, in the same
// transaction, under the migration's lock, the database is held to be
// empty again, the old registry is read again under the lease and held to
// what the continuation names, and the registry is made holding the store
// continuation alone: the migration, the registry and its first line commit
// together or not at all. The run-time role is given what every migration
// gives it (grants.sql), and nothing more.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// pgRotationTarget is the database a rotation starts the new store in: the
// migration login's connection to it, the roles it migrates as, and the
// bound of each of its two transactions there, connection included.
type pgRotationTarget struct {
	spec    *storageSpec
	roles   pgRoles
	timeout time.Duration
}

// storeRotatePostgres is the command on the PostgreSQL kind: the seals it
// appended, and the new registry's first line once it is committed.
func storeRotatePostgres(o sealOpenOptions, target pgRotationTarget, stamp func() string, said io.Writer) ([]*vObject, []byte, error) {
	dsn, err := storageConnection(target.spec)
	if err != nil {
		return nil, nil, err
	}
	set := pgShippedMigrations()
	// prior is the new database's registry when it holds the continuation
	// alone: a rotation whose mark was not written, rerun to write it
	var prior []byte
	if _, err := migratePostgresThen(dsn, set, target.roles, target.timeout, func(tx pgTx) (err error) {
		prior, err = pgRotationTargetContinued(tx)
		return err
	}, false); err != nil {
		return nil, nil, fmt.Errorf("the new database: %v; nothing was changed", err)
	}
	var line []byte
	sealed, _, err := sealOpenPostgresHeld(o, stamp, said, pgLeaseCommand{as: "store rotate", verb: "rotate", alone: true,
		// the key in force signs the seals and the continuation (ADR-0050):
		// before anything is sealed, the registry walks to it, and neither
		// the registry nor the store's receipts hold anything under a key
		// the walk did not reach
		before: func(kind *pgKind, key *signingKey) error {
			data, err := pgRegistryUnderLease(kind)
			if err != nil {
				return err
			}
			walk, err := engineWalk(data, key.public)
			if err != nil {
				return err
			}
			return heldUnderAnotherKey(data, walk.keys, key.public, kind.receipts())
		},
		then: func(kind *pgKind, key *signingKey, refused []string, held *kindStart) error {
			if len(refused) > 0 {
				return fmt.Errorf("a session left open could not be sealed, so the store is not rotated: %s", refused[0])
			}
			// the tail is read after the seals, under the lease, and walked
			// as the gateway walks it: the continuation names the registry
			// as it ends
			data, err := pgRegistryUnderLease(kind)
			if err != nil {
				return err
			}
			// the registry as it ends walks to the key in force still
			if _, err := engineWalk(data, key.public); err != nil {
				return err
			}
			if prior != nil {
				// the rerun: the new database holds the continuation of
				// this registry as it ends, and the old one is marked
				if err := continuesRegistry(prior, data, key.public); err != nil {
					return fmt.Errorf("the new database: it holds a registry; %v; a rotation starts a new store in a database that holds none", err)
				}
				if err := pgMarkRotated(kind, prior); err != nil {
					return fmt.Errorf("the new database holds the continuation, and the old one is not marked rotated: %v; rerun to mark it", err)
				}
				line = prior
				return nil
			}
			made, err := newContinuationLine(key, data, stamp())
			if err != nil {
				return fmt.Errorf("the continuation could not be signed: %v; the store is not rotated, and the seals appended stay in the old registry", err)
			}
			_, err = migratePostgresThen(dsn, set, target.roles, target.timeout, func(tx pgTx) error {
				if err := pgRotationTargetEmpty(tx); err != nil {
					return err
				}
				again, err := pgRegistryUnderLease(kind)
				if err != nil {
					return err
				}
				if !bytes.Equal(again, data) {
					return errors.New("the old registry changed after it was read under the start lease")
				}
				if err := pgWriteContinuation(tx, made); err != nil {
					return err
				}
				// last before the commit: the lease is held still, with a
				// write's margin of it to spare, or nothing is committed
				return held.holding(kind.fenceMargin())
			}, true)
			if errors.Is(err, errPgCommitUncertain) {
				return fmt.Errorf("the new database: %v; the store may have rotated; rerun to check, and the seals appended stay in the old registry", err)
			}
			if err != nil {
				return fmt.Errorf("the new database: %v; the store is not rotated, and the seals appended stay in the old registry", err)
			}
			// the mark, last: a start on the old database is refused by name
			if err := pgMarkRotated(kind, made); err != nil {
				return fmt.Errorf("the new database holds the continuation, and the old one is not marked rotated: %v; rerun to mark it", err)
			}
			line = made
			return nil
		}})
	if err != nil {
		return sealed, nil, err
	}
	return sealed, line, nil
}

// pgRegistryUnderLease reads the registry the kind keeps in a write
// transaction that writes nothing, so its commit holds the fence: the bytes
// are the registry as it stands while this process holds the start lease.
func pgRegistryUnderLease(k *pgKind) ([]byte, error) {
	var data []byte
	present := false
	err := k.transact(pgWriteCommitted, func(tx pgTx) error {
		var err error
		data, present, err = pgLog{k: k, name: "registry"}.readTx(tx, 0)
		return err
	})
	if err != nil {
		return nil, pgFailure("read-log", false, err)
	}
	if !present {
		return nil, fmt.Errorf("the registry is not there: %s; there is no store to rotate", pgRegistryName)
	}
	return data, nil
}

// pgRotationTargetEmpty holds the database a migration runs in, as the
// owner in the migration's transaction, to hold no store: no registry, no
// row of the start lease, no secret, and no row of no scope -- the scope
// identifiers recorded among them. A gateway makes the registry and takes
// the lease before it writes anything else, and a command of the migration
// login writes nothing in a store with no registry. Row security is put
// back on for the transaction: the scoped tables are read as 'none'.
func pgRotationTargetEmpty(tx pgTx) error {
	if _, err := tx.exec(`SELECT pg_catalog.set_config('row_security', 'on', true),
		pg_catalog.set_config('search_path', 'pg_catalog', true),
		pg_catalog.set_config('gateway.scope', $1, true)`, pgNoScope); err != nil {
		return err
	}
	rows, err := tx.exec(`SELECT EXISTS (SELECT 1 FROM gateway.logs) OR EXISTS (SELECT 1 FROM gateway.log_records),
		EXISTS (SELECT 1 FROM gateway.start_lease) OR EXISTS (SELECT 1 FROM gateway.secrets)
		OR EXISTS (SELECT 1 FROM gateway.scope_identifiers) OR EXISTS (SELECT 1 FROM gateway.series)
		OR EXISTS (SELECT 1 FROM gateway.blobs) OR EXISTS (SELECT 1 FROM gateway.documents)
		OR EXISTS (SELECT 1 FROM gateway.removal_records) OR EXISTS (SELECT 1 FROM gateway.rotated)`)
	if err != nil {
		return err
	}
	if len(rows.rows) != 1 {
		return errors.New("store: what the database holds did not read")
	}
	registry, ok1 := pgBool(rows.rows[0][0])
	other, ok2 := pgBool(rows.rows[0][1])
	switch {
	case !ok1 || !ok2:
		return errors.New("store: what the database holds did not read")
	case registry && !other:
		return errPgTargetHoldsRegistry
	case registry:
		return errors.New("it holds a registry; a rotation starts a new store in a database that holds none")
	case other:
		return errors.New("it holds rows of a store; a rotation starts a new store in a database that holds none")
	}
	return nil
}

// pgRotationTargetContinued is pgRotationTargetEmpty, except that a database
// holding a registry of one record and nothing else gives that record back:
// the continuation of a rotation rerun to write its mark, which the caller
// holds to name the old registry.
func pgRotationTargetContinued(tx pgTx) ([]byte, error) {
	err := pgRotationTargetEmpty(tx)
	if err != errPgTargetHoldsRegistry { //nolint:errorlint // the sentinel itself, never wrapped
		return nil, err
	}
	rows, err := tx.exec(`SELECT data FROM gateway.log_records WHERE log = 'registry' ORDER BY start`)
	if err != nil {
		return nil, err
	}
	if len(rows.rows) != 1 {
		return nil, errPgTargetHoldsRegistry
	}
	return append([]byte(nil), rows.rows[0][0]...), nil
}

// errPgTargetHoldsRegistry refuses a database holding a registry and no
// other row of a store.
var errPgTargetHoldsRegistry = errors.New("it holds a registry; a rotation starts a new store in a database that holds none")

// continuesRegistry holds line to be a store continuation, signed by pub,
// that names previous as it ends.
func continuesRegistry(line, previous []byte, pub ed25519.PublicKey) error {
	if _, err := engineWalk(line, pub); err != nil {
		return err
	}
	var c struct {
		Lines  *int64  `json:"previousLines"`
		Digest *string `json:"previousDigest"`
	}
	if err := json.Unmarshal(bytes.TrimSuffix(line, []byte("\n")), &c); err != nil || c.Lines == nil || c.Digest == nil {
		return errors.New("its one line is not a store continuation")
	}
	if lines, digest := registryLink(previous); *c.Lines != lines || *c.Digest != digest {
		return errors.New("its continuation names another registry")
	}
	return nil
}

// pgMarkRotated writes the one row of gateway.rotated, as the run-time
// login, fenced as every write is: the old store is marked rotated away from
// to the continuation line.
func pgMarkRotated(k *pgKind, line []byte) error {
	mark := strings.TrimPrefix(rotatedMark(line), rotatedMarkPrefix)
	err := k.transact(pgWriteCommitted, func(tx pgTx) error {
		_, err := tx.exec(`INSERT INTO gateway.rotated (continuation, rotated_at) VALUES ($1, pg_catalog.now())`, mark)
		return err
	})
	if err != nil {
		return pgFailure("mark-rotated", false, err)
	}
	return nil
}

// pgWriteContinuation makes the registry, in the migration's transaction,
// holding line alone: its one record, at offset 0, as an append writes it.
func pgWriteContinuation(tx pgTx, line []byte) error {
	if len(line) == 0 || len(line) > pgMaxValue {
		return fmt.Errorf("store: a record of %d bytes is not within the kind's bounds of 1 to %d", len(line), pgMaxValue)
	}
	if _, err := tx.exec(`INSERT INTO gateway.logs (name) VALUES ($1)`, "registry"); err != nil {
		return err
	}
	rows, err := tx.exec(`INSERT INTO gateway.log_records (log, start, data) VALUES ($1, 0, $2) RETURNING stop`, "registry", line)
	if err != nil {
		return err
	}
	if len(rows.rows) != 1 {
		return errors.New("store: the registry's first record was not written")
	}
	if stop, ok := pgInt8(rows.rows[0][0]); !ok || stop != int64(len(line)) {
		return errors.New("store: the registry's first record was not written whole")
	}
	return nil
}
