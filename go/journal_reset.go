package main

// `gateway journal reset --unscoped` and `gateway store journal-reset
// --unscoped` (gateway #611; ADR-0059 §8, as built 2026-11-24): the way out
// for the refusal journal of the sources of no scope where its key is lost,
// as after a restore from a full export, which carries no key. remove-scope
// refuses --scope unscoped, since its no-record path would take that live
// journal beside a scope's records; these commands take that one journal
// alone, by construction: its name is refusalJournalName(unscopedMarker),
// and no argument names a scope.
//
// On the remove-scope rails: the gateway stopped (the registry held on the
// filesystem kind, the start lease on the PostgreSQL kind), a signed
// operator entry of the kind refusal-journal-reset naming the journal's
// bytes by their length and digest written before anything is removed, and
// then the journal's key, its forwarding cursor and the journal, under its
// lock. A journal absent or empty is left, and no entry is written. A
// filesystem run cut off after its entry is completed by the next start or
// a second run, as remove-scope's is; on the PostgreSQL kind the entry and
// the removal are one transaction.

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"
)

// refusalJournalResetKind is the operator entry's body kind (ADR-0056 §4,
// amended): by, refusalJournalBytes and refusalJournalDigest, each required.
const refusalJournalResetKind = "refusal-journal-reset"

// unscopedRefusalJournal is how the commands name the journal they take.
const unscopedRefusalJournal = "the refusal journal of the sources of no scope"

const journalResetUsage = `usage: gateway journal reset --config <engine.json> --unscoped --by <label>
Removes, the gateway stopped, the refusal journal of the sources of no scope
(the journal "gateway journal name --scope unscoped" prints), its key and its
forwarding cursor: the way out where that journal's key is lost, as after a
restore from a full export, which carries no key. Before anything is removed
it writes a signed operator journal entry, refusal-journal-reset, naming the
journal's bytes by their length and digest. The next start draws a new key
and journals the refusals of the sources of no scope again. It takes no
scope identifier, and no receipt, session, removal record or other journal:
gateway remove-scope removes a scope identifier's. A journal that is absent
or holds no entry is left, and no entry is written. A run cut off after its
entry is completed by the next start or a second run. A gateway serving
the store, under this registry or another, refuses it where the platform
locks the registry and the store (store-served); on Windows nothing is
locked, so stop the gateway first. --by is a label, recorded and not
checked. Prints what was removed. On the PostgreSQL kind, gateway store
journal-reset --unscoped resets its rows.`

const storeJournalResetUsage = `usage:
  gateway store journal-reset (--connection-file <path> | --connection-env <NAME>) --owner <role> --runtime <role> --config <engine.json> --unscoped --by <label> [--timeout <seconds>]
Removes the refusal journal of the sources of no scope from the PostgreSQL
storage kind -- its rows, its key's row of gateway.secrets and its
forwarding cursor's document -- with a signed operator journal entry,
refusal-journal-reset, naming the journal's bytes, in one transaction of the
migration login acting as the owner role, under the journal's lock, the
migration's lock and the start lease: a gateway serving the database refuses
it. The key is the one the configuration names (ADR-0050). The next start
draws a new key. It takes no scope identifier, and no receipt, session,
removal record or other journal. A journal holding no entry is left, and no
entry is written. Prints what was removed.`

// journalResetFlags reads the command's arguments: --unscoped once, with
// no value, and each of names once with a value. Anything else -- a scope
// argument among them -- or a name missing, is a usage error.
func journalResetFlags(args []string, names []string) (map[string]string, string) {
	flags := map[string]string{}
	unscoped := false
	for rest := args; len(rest) > 0; {
		name := rest[0]
		if name == "--unscoped" {
			if unscoped {
				return nil, "--unscoped is given twice"
			}
			unscoped, rest = true, rest[1:]
			continue
		}
		if !contains(names, name) || len(rest) < 2 || rest[1] == "" {
			return nil, ""
		}
		if _, given := flags[name]; given {
			return nil, name + " is given twice"
		}
		flags[name], rest = rest[1], rest[2:]
	}
	if !unscoped || flags["--config"] == "" || flags["--by"] == "" {
		return nil, ""
	}
	if !isScopeIdentifier(flags["--by"]) {
		return nil, "--by is a label of the form of a scope identifier: " + scopeForm
	}
	return flags, "ok"
}

func cmdJournalReset(args []string, stdout, stderr io.Writer) int {
	return cmdJournalResetAt(args, stdout, stderr, nowStamp)
}

// cmdJournalResetAt is the command, its entry stamped by stamp.
func cmdJournalResetAt(args []string, stdout, stderr io.Writer, stamp func() string) int {
	flags, msg := journalResetFlags(args, []string{"--config", "--by"})
	switch msg {
	case "ok":
	case "":
		fmt.Fprintln(stderr, journalResetUsage)
		return 2
	default:
		fmt.Fprintf(stderr, "journal reset: %s\n%s\n", msg, journalResetUsage)
		return 2
	}
	data, err := readBounded(flags["--config"], maxEngineConfigBytes)
	if err != nil {
		fmt.Fprintf(stderr, "journal reset: engine configuration: %v\n", err)
		return 2
	}
	cfg, err := parseEngineConfig(data)
	if err != nil {
		fmt.Fprintf(stderr, "journal reset: %v\n", err)
		return 2
	}
	if cfg.storage != nil {
		fmt.Fprintln(stderr, "journal reset: the engine configuration names the PostgreSQL kind; gateway store journal-reset --unscoped resets its rows")
		return 2
	}
	out, unlocked, err := journalReset(cfg, flags["--by"], stamp)
	for _, note := range out.notes {
		fmt.Fprintln(stdout, "journal reset:", note)
	}
	if unlocked {
		fmt.Fprintln(stderr, "journal reset: this platform locks no registry, so a gateway still running was not looked for; the gateway was to be stopped")
	}
	if err != nil {
		fmt.Fprintln(stderr, "journal reset:", err)
		return 1
	}
	return 0
}

// journalReset is the command on the filesystem kind: the seed read, the
// registry there and held as a gateway holds it while it runs (so a running
// gateway refuses it), the operator journal begun, and the journal of the
// sources of no scope taken under them.
func journalReset(cfg engineConfig, by string, stamp func() string) (out removalOutcome, unlocked bool, err error) {
	seedNames := []string{cfg.seed}
	if resolved, err := filepath.EvalSymlinks(cfg.seed); err == nil && resolved != cfg.seed {
		seedNames = append(seedNames, resolved)
	}
	seed, err := loadSeed(cfg.seed)
	if err != nil {
		return out, false, fmt.Errorf("seed: %w", err)
	}
	if _, present, err := readRegistryBytes(cfg.registry); err != nil {
		return out, false, fmt.Errorf("registry: %w", err)
	} else if !present {
		return out, false, fmt.Errorf("the registry is not there: %s; a gateway makes it when it starts, and its walk names the key the entry is signed under", cfg.registry)
	}
	sig, err := commandSigner(cfg.signingKeyVersion, cfg.signingPublicKey, cfg.signingKeyAlgorithm, seed)
	if err != nil {
		return out, false, err
	}
	key := newSigningKey(sig)
	hold, err := holdEngineRegistryKey(seedNames, cfg.registry, key.held())
	if err != nil {
		if errors.Is(err, errRegistryHeld) {
			return out, false, fmt.Errorf("%w; stop the gateway, then reset", err)
		}
		return out, false, err
	}
	defer hold.Close()
	alone, err := holdStoreAlone(cfg.store, "reset")
	if err != nil {
		return out, false, err
	}
	defer alone.Close()
	unlocked = !registryLocked
	data, present, err := readRegistryBytes(cfg.registry)
	if err != nil {
		return out, unlocked, fmt.Errorf("registry: %w", err)
	}
	if !present {
		return out, unlocked, fmt.Errorf("the registry is not there: %s", cfg.registry)
	}
	walk, err := engineWalk(data, key.held())
	if err != nil {
		return out, unlocked, err
	}
	if err := heldUnderAnotherKey(data, walk.keys, key.public, newFsKind(fsLayout{store: cfg.store}).receipts()); err != nil {
		return out, unlocked, err
	}
	journal, err := beginOperatorJournal(cfg.store, cfg.registry, cfg.version, key, walk.keys, stamp)
	if err != nil {
		return out, unlocked, err
	}
	err = resetUnscopedRefusalJournal(cfg.store, by, journal, walk.keys, &out)
	return out, unlocked, err
}

// resetUnscopedRefusalJournal takes the journal of the sources of no scope
// on remove-scope's rails (removeRefusalJournalUnder): a reset a run was
// cut off in is completed; a journal holding entries goes with its key and
// its cursor after the call's refusal-journal-reset entry, appended and
// synced; one absent or empty is left, and nothing is written.
func resetUnscopedRefusalJournal(storeRoot, by string, j *operatorJournalCall, keys []reachedKey, out *removalOutcome) error {
	noted := len(out.notes)
	if err := removeRefusalJournalUnder(storeRoot, unscopedMarker, keys, out, unscopedRefusalJournal, func(data []byte) error {
		return j.refusalResetEntry(refusalResetBody(by, data))
	}); err != nil {
		return err
	}
	if len(out.notes) == noted {
		out.notes = append(out.notes, unscopedRefusalJournal+" is absent or holds no entry; nothing was removed, and no entry was written")
	}
	return nil
}

// refusalResetBody is the refusal-journal-reset body before the
// envelope's lengths: by, and the journal by its length and digest.
func refusalResetBody(by string, removed []byte) *vObject {
	body := newObject()
	body.set("kind", vString(refusalJournalResetKind))
	body.set("by", vString(by))
	describeRefusalRemoval(body, removed)
	return body
}

// errNoOperatorJournal refuses a reset whose entry has nowhere to go.
var errNoOperatorJournal = fmt.Errorf("the store holds no operator journal and the configuration's engineVersion is below %s, so the reset's entry has nowhere to be written; raise engineVersion to %s or later and run it again", operatorJournalVersion, operatorJournalVersion)

// refusalResetEntry appends the reset's entry and syncs it, before the
// journal goes: no record is appended, so nothing is staged. Unlike
// remove-scope's, a call with no operator journal is refused, since the
// entry is the reset's one trace and what completes it after a crash.
func (j *operatorJournalCall) refusalResetEntry(body *vObject) error {
	if j == nil {
		return errNoOperatorJournal
	}
	line, err := j.entry(body)
	if err != nil {
		return err
	}
	return j.appendEntry(line)
}

// --- the PostgreSQL kind ------------------------------------------------------

func cmdStoreJournalReset(args []string, stdout, stderr io.Writer) int {
	return cmdStoreJournalResetAt(args, stdout, stderr, nowStamp)
}

// cmdStoreJournalResetAt is the command, its entry stamped by stamp.
func cmdStoreJournalResetAt(args []string, stdout, stderr io.Writer, stamp func() string) int {
	const command = "store journal-reset"
	flags, msg := journalResetFlags(args, []string{"--connection-file", "--connection-env", "--owner", "--runtime", "--config", "--by", "--timeout"})
	switch msg {
	case "ok":
	case "":
		fmt.Fprintln(stderr, storeJournalResetUsage)
		return 2
	default:
		fmt.Fprintf(stderr, "%s: %s\n%s\n", command, msg, storeJournalResetUsage)
		return 2
	}
	// the connection's flags, held as every store command holds them
	var rest []string
	for _, name := range []string{"--connection-file", "--connection-env", "--owner", "--runtime"} {
		if v, given := flags[name]; given {
			rest = append(rest, name, v)
		}
	}
	if _, code := storeFlags(rest, []string{"--connection-file", "--connection-env", "--owner", "--runtime"}, command, storeJournalResetUsage, stderr); code != 0 {
		return code
	}
	timeout, ok := storeTimeout(flags, command, storeJournalResetUsage, stderr)
	if !ok {
		return 2
	}
	spec, code := storeConnectionSpec(flags, command, stderr)
	if code != 0 {
		return code
	}
	notes, err := storeJournalReset(spec, pgRoles{owner: flags["--owner"], runtime: flags["--runtime"]}, flags["--config"], flags["--by"], timeout, stamp)
	for _, note := range notes {
		fmt.Fprintln(stdout, command+":", note)
	}
	if err != nil {
		fmt.Fprintln(stderr, command+":", err)
		return 1
	}
	return 0
}

// storeJournalReset reads the configuration naming the seed and the key
// version, and the connection string, and resets the journal's rows.
func storeJournalReset(spec *storageSpec, roles pgRoles, config, by string, timeout time.Duration, stamp func() string) ([]string, error) {
	data, err := readBounded(config, maxEngineConfigBytes)
	if err != nil {
		return nil, fmt.Errorf("engine configuration: %v", err)
	}
	cfg, err := parseEngineConfig(data)
	if err != nil {
		return nil, err
	}
	if cfg.storage == nil {
		return nil, errors.New("the engine configuration names the filesystem kind; gateway journal reset --unscoped resets its files")
	}
	seed, err := loadSeed(cfg.seed)
	if err != nil {
		return nil, fmt.Errorf("seed: %w", err)
	}
	dsn, err := storageConnection(spec)
	if err != nil {
		return nil, err
	}
	sig, err := commandSigner(cfg.signingKeyVersion, cfg.signingPublicKey, cfg.signingKeyAlgorithm, seed)
	if err != nil {
		return nil, err
	}
	return resetUnscopedRows(dsn, roles, timeout, cfg.version, by, newSigningKey(sig), stamp)
}

// resetUnscopedRows is the command's transaction, store remove-scope's
// (beginPgOwnerRemoval): the journal's rows, its key's row and its cursor
// removed under the journal's lock (pgRemoveRefusalJournal), and the entry
// naming the rows' bytes inserted, committed together or not at all. A
// journal holding no row is left, with its key, and the transaction is
// rolled back.
func resetUnscopedRows(dsn pgDSN, roles pgRoles, timeout time.Duration, engineVersion, by string, priv *signingKey, stamp func() string) ([]string, error) {
	r, err := beginPgOwnerRemoval(dsn, roles, timeout, priv, engineVersion, "reset", stamp)
	if err != nil {
		return nil, err
	}
	defer r.c.close()
	removed, err := pgRemoveRefusalJournal(r.tx, unscopedMarker, false)
	if err != nil {
		return nil, r.fail(err)
	}
	if len(removed) == 0 {
		if !r.c.broken {
			r.c.exec("ROLLBACK")
		}
		return []string{unscopedRefusalJournal + " holds no entry; nothing was removed, and no entry was written"}, nil
	}
	if r.journal == nil {
		return nil, r.fail(errNoOperatorJournal)
	}
	if err := r.journal.insert(r.tx, refusalResetBody(by, removed)); err != nil {
		return nil, r.fail(fmt.Errorf("journal: %w", err))
	}
	if err := r.commit(); err != nil {
		return nil, err
	}
	return []string{fmt.Sprintf("%s, %d bytes, its key and its cursor are removed", unscopedRefusalJournal, len(removed))}, nil
}
