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
// What is read. The scope identifiers recorded are read in a transaction of
// no scope; then each scope's sessions -- of no scope first, then of each
// identifier in byte order -- in transactions of that scope alone, as every
// read of this kind is (ADR-0033): the scope's series in one, and each
// session's receipts, with the payloads they name, in one of its own.
// Neither the sessions a seal closes already nor, with --all, a series of
// no receipt is read past its name. What is read is written, as an export
// writes it (writeExport), into a directory of this process's own, made
// private and removed when the judgment ends, and judged there as the
// filesystem kind's command judges its store (sealOpenUnder): what may be
// sealed is what gateway verify of an export observes session-open, by the
// verifier's own ladder. Every session is judged before a seal is appended;
// a session that cannot be read stops it all with nothing sealed. The seals
// are appended to the registry the kind keeps, by the append it serialises
// (pgLog.appendRecord), each refused where the registry, read again, holds a
// seal for its session (appendSeal).

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	walk, err := engineWalk(data, writer.priv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, nil, err
	}
	if session != "" {
		if err := requireSession(session); err != nil {
			return nil, nil, err
		}
	}
	dir, err := os.MkdirTemp("", "gateway-seal-open-")
	if err != nil {
		return nil, nil, fmt.Errorf("the directory the sessions are judged in could not be made, and nothing was sealed: %v", err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("the directory the sessions are judged in could not be made private, and nothing was sealed: %v", err)
	}
	storeRoot := filepath.Join(dir, "store")
	if err := kind.openSessionsInto(storeRoot, walk.seals, session); err != nil {
		return nil, nil, fmt.Errorf("the store's sessions could not be read, and nothing was sealed: %v", err)
	}
	return sealOpenUnder(storeRoot, authority, writer, data, session, via, stamp)
}

// openSessionsInto writes into root, in the layout of an export's store,
// the sessions to judge -- the one named, or with "" each session sealed
// holds no seal for -- with the payloads their receipts name, and the
// removal records. The scope identifiers recorded are read in a
// transaction of no scope; each scope's rows in transactions of that scope.
func (k *pgKind) openSessionsInto(root string, sealed map[string]seal, session string) error {
	for _, d := range []string{root, filepath.Join(root, "receipts"), filepath.Join(root, "artifacts")} {
		if err := os.Mkdir(d, 0o700); err != nil {
			return err
		}
	}
	var removals []byte
	var recorded []string
	err := k.ofNoScope().transact(pgReadSnapshot, func(tx pgTx) error {
		var err error
		if removals, _, err = pgRemovalFile(tx); err != nil {
			return err
		}
		rows, err := tx.exec(`SELECT identifier FROM gateway.scope_identifiers WHERE scope = $1 ORDER BY identifier`, pgNoScope)
		recorded = pgNames(rows)
		return err
	})
	if err != nil {
		return pgFailure("list-series", false, err)
	}
	if len(removals) > 0 {
		if err := os.WriteFile(filepath.Join(root, removalsFile), removals, 0o600); err != nil {
			return err
		}
	}
	payloads := map[string]string{}
	for _, row := range append([]string{pgNoScope}, recorded...) {
		if err := k.ofRow(row).scopeSessionsInto(root, sealed, session, payloads); err != nil {
			return err
		}
	}
	return nil
}

// scopeSessionsInto writes the view's sessions to judge into root: the
// scope's series in one transaction of the scope, and each session's
// receipts and the payloads they name in one of its own. payloads holds the
// digest of the bytes written under each payload's name, so that two
// scopes holding different bytes under one name are refused, as an export
// refuses them, rather than one taken for the other.
func (k *pgKind) scopeSessionsInto(root string, sealed map[string]seal, session string, payloads map[string]string) error {
	var names []string
	err := k.transact(pgRead, func(tx pgTx) error {
		rows, err := tx.exec(`SELECT name FROM gateway.series WHERE scope = $1 ORDER BY name`, k.row)
		names = pgNames(rows)
		return err
	})
	if err != nil {
		return pgFailure("list-series", false, err)
	}
	for _, name := range names {
		if session != "" && name != session {
			continue
		}
		if _, closed := sealed[name]; closed && session == "" {
			continue
		}
		// a name no directory can take is read no further; as an export
		// refuses it, so does the judgment, which is no verdict on it
		if !validListedSeries(name) {
			return fmt.Errorf("session %q cannot be named as a directory of a store", name)
		}
		if err := k.sessionInto(root, name, payloads); err != nil {
			return fmt.Errorf("session %s: %w", name, err)
		}
	}
	return nil
}

// sessionInto writes one session of the view's scope into root, read in one
// transaction of that scope: each receipt at receipts/<session>/<index>.json
// and each payload a receipt names, held by the scope, at artifacts/<hex>.
func (k *pgKind) sessionInto(root, name string, payloads map[string]string) error {
	dir := filepath.Join(root, "receipts", name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	return k.transact(pgReadSnapshot, func(tx pgTx) error {
		entries, err := tx.exec(`SELECT name, data FROM gateway.entries WHERE scope = $1 AND series = $2 ORDER BY name`, k.row, name)
		if err != nil {
			return err
		}
		named := map[string]bool{}
		for _, e := range entries.rows {
			entry := string(e[0])
			if !validListedEntry(entry) {
				return fmt.Errorf("a receipt's name %q cannot be named as a file of a store", entry)
			}
			if err := os.WriteFile(filepath.Join(dir, entry+".json"), e[1], 0o600); err != nil {
				return err
			}
			if hexSum, ok := namedPayload(e[1]); ok {
				named[hexSum] = true
			}
		}
		for hexSum := range named {
			rows, err := tx.exec(`SELECT data FROM gateway.blobs WHERE scope = $1 AND name = $2`, k.row, "sha256:"+hexSum)
			if err != nil {
				return err
			}
			if len(rows.rows) != 1 {
				// none held: what verification finds of the receipt then
				continue
			}
			digest := digestOfBytes(rows.rows[0][0])
			if was, written := payloads[hexSum]; written {
				if was != digest {
					return errors.New("two scopes hold different bytes under one payload's name")
				}
				continue
			}
			if err := os.WriteFile(filepath.Join(root, "artifacts", hexSum), rows.rows[0][0], 0o600); err != nil {
				return err
			}
			payloads[hexSum] = digest
		}
		return nil
	})
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
	held := &kindStart{kind: kind, lease: lease}
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
