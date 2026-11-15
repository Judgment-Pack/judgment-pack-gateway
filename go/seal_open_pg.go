package main

// The seal made after an interruption on the PostgreSQL kind (gateway #466;
// docs/adr/0035-several-instances-on-one-postgresql-database.md, the third
// step; SPEC.md §3c): gateway seal-open --config, sealedVia "command", and
// the start's switch sealOpenAtStart, sealedVia "start", seal each session
// an instance that no longer serves left open, as they do on the filesystem
// kind. No record changes form: the seal is §3c's, its count the receipts
// the store holds in the session, its head the last one's signature.
//
// Who is stopped. The filesystem kind holds the registry's lock; this kind
// holds the start lease (store_pg_lease.go). The command takes the lease as
// a start does, and as gateway store remove-scope does it is refused at once,
// start-lease-held, while an instance's lease is live -- it does not wait,
// whatever storage.startWaitSeconds says; it renews the lease while it runs
// and releases it at its end, and every seal it appends is fenced on it. The
// start seals once it holds the lease and the registry's walk held, and
// before it serves. One instance holds the lease at a time (ADR-0035, option
// D), so every session found open then was left by an instance that no
// longer serves: ADR-0035's question 11 (seal the sessions whose holder's
// lease has expired) asks no more than this until each session records the
// instance that holds it (option C), which is when the rule is to read it.
//
// What is read, and where. Nothing read is written anywhere: the judgment
// is the filesystem kind's (sealOpenUnder, the verifier's own ladder) of
// the sessions as this kind holds them (pgSealOpenStore). The scope
// identifiers recorded and the removal records are read in a transaction of
// no scope; each scope's series names -- of no scope first, then of each
// identifier in byte order -- in a transaction of that scope alone, as every
// read of this kind is (ADR-0033). A series whose name no session id is
// (SPEC.md §3a) is named as a refusal and read no further; so is a session a
// seal closes already. Each other session is read in one transaction of its
// own scope: its receipts, kept in this process's memory, and, for each
// payload a receipt names, whether the scope holds bytes under that name and
// the SHA-256 of those bytes, computed by the database -- the bytes never
// leave it. The ladder's payload step reads that, and nothing else: what a
// receipt of one scope names is judged by what its own scope holds, never
// by what another scope holds under the same name. Every session is judged
// before a seal is appended; a session that cannot be read stops it all with
// nothing sealed. The seals are appended to the registry the kind keeps, by
// the append it serialises (pgLog.appendRecord), each refused where the
// registry, read again, holds a seal for its session (appendSeal).

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// sealOpenOnKind seals what may be sealed on the kind -- the session named,
// or with "" every session no seal closes -- through writer, the registry
// the kind keeps, this process holding the start lease. It answers as
// sealOpenUnder does.
func sealOpenOnKind(kind *pgKind, authority string, writer *registryWriter, session, via string, stamp func() string) ([]*vObject, []string, error) {
	data, err := writer.log.readLog(0)
	if faultOf(err) == faultAbsent {
		return nil, nil, fmt.Errorf("the registry is not there: %s; a gateway makes it when it starts, and a seal is recorded in it", writer.path)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("registry: %w", err)
	}
	st, err := readPgSealOpenStore(kind)
	if err != nil {
		return nil, nil, fmt.Errorf("the store's sessions could not be read, and nothing was sealed: %v", err)
	}
	return sealOpenUnder(st, authority, writer, data, session, via, stamp)
}

// pgSealOpenStore is the kind's sessions as sealOpenUnder judges them: each
// series' name and the scope that holds it, listed once, and the removal
// records' bytes. A series' name is the key of gateway.series, so no two
// scopes hold one.
type pgSealOpenStore struct {
	kind     *pgKind
	names    []string          // of no scope first, then of each identifier
	scopeOf  map[string]string // a series' name -> its scope's row
	removalF []byte
}

// readPgSealOpenStore lists the kind's series: the scope identifiers
// recorded and the removal records in a transaction of no scope, then each
// scope's series in a transaction of that scope.
func readPgSealOpenStore(k *pgKind) (*pgSealOpenStore, error) {
	st := &pgSealOpenStore{kind: k, scopeOf: map[string]string{}}
	var recorded []string
	err := k.ofNoScope().transact(pgReadSnapshot, func(tx pgTx) error {
		var err error
		if st.removalF, _, err = pgRemovalFile(tx); err != nil {
			return err
		}
		rows, err := tx.exec(`SELECT identifier FROM gateway.scope_identifiers WHERE scope = $1 ORDER BY identifier`, pgNoScope)
		recorded = pgNames(rows)
		return err
	})
	if err != nil {
		return nil, pgFailure("list-series", false, err)
	}
	for _, row := range append([]string{pgNoScope}, recorded...) {
		view := k.ofRow(row)
		var names []string
		err := view.transact(pgRead, func(tx pgTx) error {
			rows, err := tx.exec(`SELECT name FROM gateway.series WHERE scope = $1 ORDER BY name`, view.row)
			names = pgNames(rows)
			return err
		})
		if err != nil {
			return nil, pgFailure("list-series", false, err)
		}
		for _, name := range names {
			if _, held := st.scopeOf[name]; held {
				continue
			}
			st.scopeOf[name] = row
			st.names = append(st.names, name)
		}
	}
	return st, nil
}

func (st *pgSealOpenStore) sessions() ([]string, error) { return st.names, nil }

// a series --all meets that no session id names is no session of a
// gateway's (SPEC.md §3a); it is named, and the rest judged, as the
// filesystem kind names such a directory
func (st *pgSealOpenStore) misnamed(name string) string {
	return fmt.Sprintf("the store's series %q is not named as a session is (SPEC.md §3a); it is not sealed", name)
}

func (st *pgSealOpenStore) removals(keys []reachedKey) (map[string][]removalRecord, error) {
	set, _, err := scanRecords(bytes.NewReader(st.removalF), keys)
	if err != nil {
		return nil, fmt.Errorf("removal records: %w", err)
	}
	return set.artifacts, nil
}

// reading reads one session in one transaction of its own scope: each
// receipt, as <index>.json, an export's name for it; and, for each payload a
// receipt names, whether the scope holds bytes under that name and their
// SHA-256, computed in the transaction.
func (st *pgSealOpenStore) reading(sessionID string) (sessionReading, string, error) {
	row, held := st.scopeOf[sessionID]
	if !held {
		return sessionReading{}, fmt.Sprintf("session %s is not in the store", sessionID), nil
	}
	view := st.kind.ofRow(row)
	receipts := map[string][]byte{}
	var names []string
	sums := map[string]string{} // a payload's name -> the SHA-256 held, "" for none
	err := view.transact(pgReadSnapshot, func(tx pgTx) error {
		entries, err := tx.exec(`SELECT name, data FROM gateway.entries WHERE scope = $1 AND series = $2 ORDER BY name`, view.row, sessionID)
		if err != nil {
			return err
		}
		for _, e := range entries.rows {
			name := string(e[0]) + ".json"
			receipts[name] = e[1]
			names = append(names, name)
			if hexSum, ok := namedPayload(e[1]); ok {
				sums[hexSum] = ""
			}
		}
		for hexSum := range sums {
			rows, err := tx.exec(`SELECT pg_catalog.encode(pg_catalog.sha256(data), 'hex') FROM gateway.blobs WHERE scope = $1 AND name = $2`, view.row, "sha256:"+hexSum)
			if err != nil {
				return err
			}
			if len(rows.rows) == 1 {
				sums[hexSum] = string(rows.rows[0][0])
			}
		}
		return nil
	})
	if err != nil {
		return sessionReading{}, "", pgFailure("read-session", false, err)
	}
	return sessionReading{
		names: names,
		read:  func(name string) ([]byte, error) { return receipts[name], nil },
		probe: storeProbe{
			artifact: func(digestHex string) (string, bool, bool) {
				sum, asked := sums[digestHex]
				switch {
				case !asked:
					// a name the reading did not ask after is not known to
					// be absent: missing, never passed over
					return "", false, false
				case sum == "":
					return "", false, true
				}
				return sum, true, false
			},
			// the kind refuses descriptor provenance at its start (its
			// snapshot is read from a store on disk), so it makes no receipt
			// that carries one; one found is judged not whole
			provenance: func(descriptorProvenance, string, string, string, bool, []reachedKey) string {
				return "descriptor-provenance-missing"
			},
		},
	}, "", nil
}

// namedPayload is the payload a receipt's bytes name -- its resultDigest's
// hexadecimal, as the ladder's lexical order reads it -- where they name one.
// Bytes that do not are a receipt the ladder refuses, and need none.
func namedPayload(data []byte) (string, bool) {
	v, err := parseJSON(data)
	if err != nil {
		return "", false
	}
	obj, ok := v.(*vObject)
	if !ok {
		return "", false
	}
	digest, ok := memberString(obj, "resultDigest")
	if !ok {
		return "", false
	}
	hexSum, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || !isLowerHexOfLen(hexSum, 64) {
		return "", false
	}
	return hexSum, true
}

// sealOpenPostgres is the command on the PostgreSQL kind: the seed read, a
// rotation under way beside it refused, the kind opened as serve opens it,
// the start lease taken -- refused at once while an instance serves -- and
// held until the command ends, and what may be sealed sealed under it.
func sealOpenPostgres(o sealOpenOptions, stamp func() string, said io.Writer) ([]*vObject, []string, error) {
	seed, err := loadSeed(o.seedNames[0])
	if err != nil {
		return nil, nil, fmt.Errorf("seed: %w", err)
	}
	// a rotation under way beside the seed is refused, as the start refuses
	// it on this kind
	if err := rotationPendingAtStart(engineConfig{storage: o.storage}, o.seedNames); err != nil {
		return nil, nil, err
	}
	spec := *o.storage
	if spec.file != "" {
		// the connection file held as serve, export and store migrate hold
		// it (#444), and the resolved path read from here on
		euid := os.Geteuid()
		resolved, err := trustedFile(spec.file, euid, linkOwners{other: euid}, osEngineHost())
		if err != nil {
			return nil, nil, fmt.Errorf("storage.connection.file: %v", err)
		}
		spec.file = resolved
	}
	kind, err := openStorageKind(&spec)
	if err != nil {
		return nil, nil, err
	}
	holder, err := newStartLeaseHolder()
	if err != nil {
		kind.close()
		return nil, nil, err
	}
	lease, err := kind.takeStartLease(holder, pgStartLeasePeriod, pgStartLeaseRenewal)
	if err != nil {
		kind.close()
		if errors.Is(err, errStartLeaseHeld) {
			return nil, nil, fmt.Errorf("%w; stop the gateway, then seal", err)
		}
		return nil, nil, err
	}
	held := &kindStart{kind: kind, lease: lease, as: "seal-open"}
	held.renew()
	defer held.stop(said)
	if _, err := kind.registry().readLog(0); faultOf(err) == faultAbsent {
		return nil, nil, fmt.Errorf("the registry is not there: %s; a gateway makes it when it starts, and a seal is recorded in it", pgRegistryName)
	}
	// a registry that is not there is never made here (the store's history
	// is taken as held), and one whose walk does not end at the seed's key
	// is refused
	writer, err := newRegistryWriterOn(kind.registry(), pgRegistryName, seed, func() (bool, error) { return true, nil })
	if err != nil {
		return nil, nil, err
	}
	// a seal is appended only while the lease is held: once it is lost,
	// each append fails at its fence and the command ends with that failure
	return sealOpenOnKind(kind, o.authority, writer, o.session, sealedViaCommand, stamp)
}
