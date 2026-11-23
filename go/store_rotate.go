package main

// `gateway store rotate` (ADR-0048, S2; SPEC.md §3d): a store let go of by
// starting another. With the gateway stopped, the registry held as a
// gateway holds it while it serves (holdEngineRegistry), every session left
// open in the old store is sealed after the interruption, as seal-open --all
// seals it (SPEC.md §3c); then a new registry is made, in a new store
// directory the operator names, whose first line is a store continuation
// naming the old registry's line count and the SHA-256 of its bytes, signed
// by the key in force; then the old store is marked rotated away from, which
// every later hold of its registry refuses. The old store and its registry
// are otherwise left as they are, for the operator to archive or delete
// whole.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const storeRotateUsage = `usage:
  gateway store rotate (--config <engine.json> | --store <dir> --seed <file> --registry <file> --authority <authority> --no-sink) --new-store <dir> --new-registry <file>
  gateway store rotate --config <engine.json> (--connection-file <path> | --connection-env <NAME>) --owner <role> --runtime <role> [--timeout <seconds>]
Rotates the store, the gateway stopped: seals every session left open in
it, as seal-open --all does, then makes the new store directory and the new
registry, whose first line names the old registry's line count and the
SHA-256 of its bytes, signed by the key in force (SPEC.md §3d); then marks
the old store rotated away from, in a file beside its registry, and nothing
starts on it again. Neither new path may be there already, but an empty new
store directory, or what a rotation stopped by a crash left, which a rerun
finishes. A session that cannot be sealed refuses the rotation, and nothing
new is made. With a receiptSink in the configuration, what a session holds
is delivered to the sink before it is sealed, as seal-open --config
delivers it, and a session the sink does not acknowledge, or whose seal it
does not, refuses the rotation. The store by its flags names no receipt
sink, and is rotated only with --no-sink, for a store no gateway forwarding
receipts wrote: no receipt is delivered, and stderr says so. A seal held
for the sink, pending forwarding, that the rotation would not deliver
refuses it, nothing sealed: deliver it first with seal-open --config, or by
the gateway's start. The old store is not changed but by the seals and the mark; it
is the operator's to archive or delete whole. Prints each seal appended,
then the new registry's first line.
With the PostgreSQL kind (--config alone names it) the new store is a new
database, which the migration login's connection string names, as gateway
store migrate takes it: the database is to hold no store, and is migrated
and given the registry in one transaction. The start lease of the old
database is taken first: an instance serving it refuses the rotation.`

// storeRotateNeedsSink is the refusal of a store given by its flags
// without --no-sink, as seal-open refuses it (sealOpenNeedsSink, #541): the
// flags cannot say whether the gateway that wrote it forwarded receipts to a
// sink, which the rotation's seals would skip before it shuts the store.
const storeRotateNeedsSink = "a store given by its flags may have been written by a gateway that forwards receipts to a receipt sink, and a rotation here would seal what was left open without delivering it first, then shut the old store for good; give --config, which names the sink, or --no-sink for a store with no receipt sink; nothing was rotated"

// storeRotateNoSinkSaid is the line store rotate writes to stderr first
// under --no-sink.
const storeRotateNoSinkSaid = "store rotate: --no-sink: delivery to a receipt sink was skipped; no receipt was delivered before a seal\n"

// storeRotateByFlagsVersion1 is the line store rotate given by its flags
// writes to stderr after carrying a key history of version "1": the flags
// name no keyHistoryVersion, so the old store's version is carried, even
// where the store's configuration names "2".
const storeRotateByFlagsVersion1 = "store rotate: given by its flags, the key history carried is of version \"1\", the old store's; to carry version \"2\", rotate with --config naming keyHistoryVersion \"2\"\n"

// storeRotateNotSealed is the refusal of a rotation past a session left
// open that the seals did not settle: one not sealed, or one sealed whose
// seal the receipt sink did not acknowledge and holds pending forwarding.
const storeRotateNotSealed = "a session left open was not sealed, or its seal is held for the receipt sink, so the store is not rotated: %s"

// storeRotateSealsHeld is the refusal of a rotation while the store holds
// the marker of a seal pending forwarding (seal_sink.go) that the rotation
// would not deliver: a rotation shuts the old store for good, and nothing
// delivers the seal from it after that.
func storeRotateSealsHeld(sessions []string) error {
	return fmt.Errorf("a seal is held for the receipt sink, pending forwarding, of session %s; a rotation shuts the old store for good, so deliver it first with gateway seal-open --config, or by the gateway's start, then rotate; nothing was sealed, written or marked", strings.Join(sessions, ", "))
}

// refuseSealsPending refuses a rotation, before anything is sealed, while
// the store holds a marker of a seal pending forwarding and forwardsSeals
// is false: a store by its flags, or a configuration whose receipt sink
// takes no seals, delivers none. With seals forwarded the rotation delivers
// the pending seals first (sealOpenUnderSink), and one the sink does not
// acknowledge refuses it (storeRotateNotSealed).
func refuseSealsPending(marks sealForwarding, forwardsSeals bool) error {
	if forwardsSeals {
		return nil
	}
	marked, err := marks.pending()
	if err != nil {
		return fmt.Errorf("the seals pending forwarding could not be read, so nothing was sealed and the store is not rotated: %v", err)
	}
	if len(marked) > 0 {
		return storeRotateSealsHeld(marked)
	}
	return nil
}

// forwardsSeals is whether the configuration's receipt sink takes seals.
func (o sealOpenOptions) forwardsSeals() bool { return o.receiptSink != nil && o.receiptSink.seals }

// storeRotateTargetFlags are the flags of the new store: its directory and
// registry on the filesystem kind, its database on the PostgreSQL kind.
var (
	storeRotateFsFlags = []string{"--new-store", "--new-registry"}
	storeRotatePgFlags = []string{"--connection-file", "--connection-env", "--owner", "--runtime", "--timeout"}
)

func cmdStoreRotate(args []string, stdout, stderr io.Writer) int {
	return cmdStoreRotateAt(args, stdout, stderr, nowStamp)
}

// cmdStoreRotateAt is the command, each line it writes stamped by stamp.
func cmdStoreRotateAt(args []string, stdout, stderr io.Writer, stamp func() string) int {
	var rest []string
	targets := map[string]string{}
	for i := 0; i < len(args); i++ {
		if name := args[i]; contains(storeRotateFsFlags, name) || contains(storeRotatePgFlags, name) {
			if i+1 >= len(args) || args[i+1] == "" {
				fmt.Fprintln(stderr, storeRotateUsage)
				return 2
			}
			if _, given := targets[name]; given {
				fmt.Fprintf(stderr, "store rotate: %s is given twice\n%s\n", name, storeRotateUsage)
				return 2
			}
			targets[name] = args[i+1]
			i++
			continue
		}
		if args[i] == "--all" || args[i] == "--session" {
			fmt.Fprintln(stderr, storeRotateUsage)
			return 2
		}
		rest = append(rest, args[i])
	}
	o, msg := parseSealOpen(append(rest, "--all"))
	switch msg {
	case "ok":
	case "":
		fmt.Fprintln(stderr, storeRotateUsage)
		return 2
	default:
		fmt.Fprintf(stderr, "store rotate: %s\n%s\n", msg, storeRotateUsage)
		return 2
	}
	// each kind's flags of the new store, and none of the other's
	own, other := storeRotateFsFlags, storeRotatePgFlags
	if o.storage != nil {
		own, other = other, own
	}
	for _, name := range other {
		if _, given := targets[name]; given {
			fmt.Fprintf(stderr, "store rotate: %s is not of the storage kind the configuration names\n%s\n", name, storeRotateUsage)
			return 2
		}
	}
	var sealed []*vObject
	var continuation []byte
	var err error
	if o.storage != nil {
		var given []string
		for _, name := range own {
			if value, ok := targets[name]; ok {
				given = append(given, name, value)
			}
		}
		flags, code := storeFlags(given, own, "store rotate", storeRotateUsage, stderr)
		if code != 0 {
			return code
		}
		timeout, ok := storeTimeout(flags, "store rotate", storeRotateUsage, stderr)
		if !ok {
			return 2
		}
		spec, code := storeConnectionSpec(flags, "store rotate", stderr)
		if code != 0 {
			return code
		}
		target := pgRotationTarget{spec: spec, roles: pgRoles{owner: flags["--owner"], runtime: flags["--runtime"]}, timeout: timeout}
		sealed, continuation, err = storeRotatePostgres(o, target, stamp, stderr)
	} else {
		if targets["--new-store"] == "" || targets["--new-registry"] == "" {
			fmt.Fprintln(stderr, storeRotateUsage)
			return 2
		}
		// a store by its flags is rotated only under --no-sink, which is said
		if o.byFlags && !o.noSink {
			fmt.Fprintln(stderr, "store rotate:", storeRotateNeedsSink)
			return 1
		}
		if o.noSink {
			fmt.Fprint(stderr, storeRotateNoSinkSaid)
		}
		sealed, continuation, err = storeRotate(o, targets["--new-store"], targets["--new-registry"], stamp)
	}
	for _, record := range sealed {
		fmt.Fprintf(stdout, "%s\n", canon(record))
	}
	if err != nil {
		fmt.Fprintln(stderr, "store rotate:", err)
		return 1
	}
	stdout.Write(continuation)
	if o.byFlags {
		if carried, present, err := readCarriedKeyHistory(targets["--new-registry"]); err == nil && present {
			if checked, err := checkKeyHistoryOf(carried, nil, ""); err == nil && checked.version != keyHistoryVersion2 {
				fmt.Fprint(stderr, storeRotateByFlagsVersion1)
			}
		}
	}
	return 0
}

// storeRotate is the command on the filesystem kind: the old registry held,
// what was left open sealed, and the new store and registry made under the
// hold, the registry's bytes read after the last seal appended; then the old
// store marked rotated away from, still under the hold. The continuation
// names the key history carried beside the new registry by its digest. A
// rerun after a crash finds the new registry whole or not there: whole, and
// its only line the continuation of the old registry as it stands, the key
// history beside it held to the digest the continuation names -- written
// again where it is not there, refused where its bytes are other ones --
// and only then the mark written.
func storeRotate(o sealOpenOptions, newStore, newRegistry string, stamp func() string) ([]*vObject, []byte, error) {
	if err := newStoreFree(newStore, newRegistry); err != nil {
		return nil, nil, err
	}
	seed, err := loadSeed(o.seedNames[0])
	if err != nil {
		return nil, nil, fmt.Errorf("seed: %w", err)
	}
	if _, present, err := readRegistryBytes(o.registry); err != nil {
		return nil, nil, fmt.Errorf("registry: %w", err)
	} else if !present {
		return nil, nil, fmt.Errorf("the registry is not there: %s; there is no store to rotate", o.registry)
	}
	// the key in force signs the seals and the continuation: the key
	// service's key version the configuration names, held to
	// signingPublicKey, or else the seed's (ADR-0050)
	sig, err := commandSigner(o.keyVersion, o.keyPublic, o.keyAlg, seed)
	if err != nil {
		return nil, nil, err
	}
	key := newSigningKey(sig)
	hold, err := holdEngineRegistryKey(o.seedNames, o.registry, key.held())
	if err != nil {
		if errors.Is(err, errRegistryHeld) {
			return nil, nil, fmt.Errorf("%w; stop the gateway, then rotate", err)
		}
		return nil, nil, err
	}
	defer hold.Close()
	data, present, err := readRegistryBytes(o.registry)
	if err != nil || !present {
		return nil, nil, fmt.Errorf("registry: the registry could not be read under the hold: %v", err)
	}
	pub := key.public
	walk, err := engineWalk(data, key.held())
	if err != nil {
		return nil, nil, err
	}
	if err := heldUnderAnotherKey(data, walk.keys, pub, newFsKind(fsLayout{store: o.store}).receipts()); err != nil {
		return nil, nil, err
	}
	marks := fsSealOpenStore{o.store}.forwarding()
	if made, present, err := readRegistryBytes(newRegistry); err != nil {
		return nil, nil, fmt.Errorf("the new registry: %w", err)
	} else if present {
		// a rerun: the new registry is this one's continuation alone, made
		// by a rotation stopped before its mark, or it is refused
		named, ok := continuesAlone(made, data, key.held())
		if !ok {
			return nil, nil, fmt.Errorf("%s is there already; a rotation starts a new store and registry, and nothing was changed", newRegistry)
		}
		// the rerun seals nothing, so delivers nothing: a seal held is
		// refused whatever the sink
		if err := refuseSealsPending(marks, false); err != nil {
			return nil, nil, err
		}
		// the history is written before the registry, and the continuation
		// names its bytes: one beside it is held to them, and one lost is
		// carried again from the same bytes, which must be the ones named
		if err := carryKeyHistory(o.registry, data, key.held(), newRegistry, named, o.keyHistoryVersion); err != nil {
			return nil, nil, err
		}
		if err := markRotated(o.registry, made); err != nil {
			return nil, nil, err
		}
		return nil, made, nil
	}
	// before anything is sealed: a seal held that this rotation does not
	// deliver refuses it
	if err := refuseSealsPending(marks, o.forwardsSeals()); err != nil {
		return nil, nil, err
	}
	// and a continuation stamped before the last rotation of the history it
	// would carry, a clock behind, refuses it before anything is written:
	// the seals pass over the history, so it is the history after them
	if err := continuationOrderRefusal(o.registry, data, key.held(), stamp(), o.keyHistoryVersion); err != nil {
		return nil, nil, err
	}
	writer, err := newRegistryWriterWith(o.registry, seed, newSignerHolder(sig), func() (bool, error) { return true, nil })
	if err != nil {
		return nil, nil, err
	}
	sealed, refused, err := sealOpenUnderSink(fsSealOpenStore{o.store}, o.authority, writer, data, "", sealedViaCommand, stamp, o.sink())
	if err != nil {
		return sealed, nil, fmt.Errorf("%v; the store is not rotated", err)
	}
	if len(refused) > 0 {
		return sealed, nil, fmt.Errorf(storeRotateNotSealed, refused[0])
	}
	// the bytes are read after the seals, under the hold, and walked again
	// as the gateway walks them: the continuation names the registry as it
	// ends
	data, present, err = readRegistryBytes(o.registry)
	if err != nil || !present {
		return sealed, nil, fmt.Errorf("registry: the registry could not be read after sealing: %v", err)
	}
	if _, err := engineWalk(data, key.held()); err != nil {
		return sealed, nil, err
	}
	history, err := carriedHistoryOf(o.registry, data, key.held(), o.keyHistoryVersion)
	if err != nil {
		return sealed, nil, fmt.Errorf("%v; the store is not rotated", err)
	}
	at := stamp()
	line, err := newContinuationLine(key, data, history, at)
	if err != nil {
		return sealed, nil, fmt.Errorf("the continuation could not be signed: %v; the store is not rotated, and the seals appended stay in the old registry", err)
	}
	if err := continuationHolds(data, line, key.held(), history, at, o.keyHistoryVersion); err != nil {
		return sealed, nil, fmt.Errorf("%v; the store is not rotated, and the seals appended stay in the old registry", err)
	}
	if err := os.Mkdir(newStore, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return sealed, nil, fmt.Errorf("the new store: %w", err)
	}
	// the key history is carried into the new store before its registry is
	// made, so a new registry that is there has its history beside it
	if err := writeNewRegistry(keyHistoryBeside(newRegistry), history); err != nil {
		return sealed, nil, fmt.Errorf("the new registry's key history: %w", err)
	}
	if err := writeNewRegistry(newRegistry, line); err != nil {
		return sealed, nil, fmt.Errorf("the new registry: %w", err)
	}
	if err := markRotated(o.registry, line); err != nil {
		return sealed, line, err
	}
	return sealed, line, nil
}

// newStoreFree refuses a rotation into a new store that is there already:
// the directory may be absent, or hold nothing but what a rotation stopped
// by a crash leaves in it -- the new registry, which the rerun holds to the
// old one, its key history, or the file either is written to before it is
// renamed into place -- and the new registry, if there, is held under the
// hold.
func newStoreFree(newStore, newRegistry string) error {
	info, err := os.Lstat(newStore)
	if absent(err) {
		return nil
	}
	if err != nil {
		return err
	}
	there := fmt.Errorf("%s is there already; a rotation starts a new store and registry, and nothing was changed", newStore)
	if !info.IsDir() {
		return there
	}
	entries, err := os.ReadDir(newStore)
	if err != nil {
		return err
	}
	for _, e := range entries {
		path := filepath.Join(newStore, e.Name())
		history := keyHistoryBeside(filepath.Clean(newRegistry))
		if path != filepath.Clean(newRegistry) && path != newRegistryTemp(newRegistry) && path != history && path != newRegistryTemp(history) {
			return there
		}
	}
	return nil
}

// continuesAlone is whether made is one line, a store continuation that
// loads under the key and names previous's line count and digest, and the
// key history it names.
func continuesAlone(made, previous []byte, key heldKey) (string, bool) {
	w := walkRegistryFrom(made, key)
	lines, digest := registryLink(previous)
	if bytes.Count(made, []byte("\n")) == 1 && bytes.HasSuffix(made, []byte("\n")) && w.continuation != nil &&
		w.continuationFinding == nil && w.continuation.previousLines == lines && w.continuation.previousDigest == digest {
		return w.continuation.keyHistoryDigest, true
	}
	return "", false
}

// newRegistryTemp is the file a new registry is written to, beside it, before
// it is renamed into place.
// syncRotationDirectory syncs the directory at path, so an entry made or
// renamed in it is durable: where Unix syncs a directory (connect_unix.go),
// as the store's other directories are; elsewhere a directory is not synced
// (connect_other.go), and the file's own sync is what is durable.
func syncRotationDirectory(path string) error {
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	return syncDirectory(root, ".")
}

func newRegistryTemp(path string) string {
	return filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".rotating")
}

// writeNewRegistry makes the registry at path, which is not there, holding
// line alone, durably: written whole and synced in a file beside it, renamed
// into place, and the directory that names it synced. A crash leaves the
// registry whole or not there.
func writeNewRegistry(path string, line []byte) error {
	temp := newRegistryTemp(path)
	f, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(line); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		return err
	}
	return syncRotationDirectory(filepath.Dir(path))
}

// rotatedMarkPath is the file beside a registry that marks its store rotated
// away from (SPEC.md §3d). It is outside the registry's bytes.
func rotatedMarkPath(registryPath string) string { return registryPath + ".rotated" }

// markRotated writes the mark of the rotation whose continuation is line
// beside the old registry, durably.
func markRotated(registryPath string, line []byte) error {
	path := rotatedMarkPath(registryPath)
	err := writeFileSynced(path, []byte(rotatedMark(line)+"\n"))
	if err == nil {
		err = syncRotationDirectory(filepath.Dir(path))
	}
	if err != nil {
		return fmt.Errorf("the new registry is made, but the old store could not be marked rotated away from (%v); rerun the same rotation to mark it", err)
	}
	return nil
}

// writeFileSynced writes data to a new file at path and syncs it before it
// is closed, so the bytes are durable before the directory is.
func writeFileSynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// refuseRotatedStore refuses a registry whose store is marked rotated away
// from, by the mark's name.
func refuseRotatedStore(registryPath string) error {
	data, err := os.ReadFile(rotatedMarkPath(registryPath))
	if absent(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("the store's rotation mark %s cannot be read: %w", rotatedMarkPath(registryPath), err)
	}
	mark := strings.TrimSpace(string(data))
	if !strings.HasPrefix(mark, rotatedMarkPrefix) || !isLowerHexOfLen(strings.TrimPrefix(mark, rotatedMarkPrefix), 64) {
		mark = rotatedMarkPrefix + "?"
	}
	return errStoreRotated(mark)
}

// carriedHistoryOf is the key history a store rotation carries into the new
// store (SPEC.md §3e; ADR-0052): the history of the old registry's bytes as
// the rotation names them, walked from the key in force, with what was
// carried into the old store in its turn -- the answer the old store's
// gateway gives, which the new store's continues, under the version the
// rotation's configuration names (configured, "" by its flags) and the
// history carried implies. A history that does not hold refuses the
// rotation.
func carriedHistoryOf(registryPath string, data []byte, key heldKey, configured string) ([]byte, error) {
	carried, present, err := readCarriedKeyHistory(registryPath)
	return historyToCarry(data, key, carried, present, err, configured)
}

// continuationOrderRefusal refuses a store rotation from the registry at
// registryPath, of bytes data and key key, whose continuation stamped at
// is before the last rotation of the key history it would carry
// (keyHistoryWriteRefusal), before anything is sealed or written. A history
// that does not hold refuses it as carriedHistoryOf does.
func continuationOrderRefusal(registryPath string, data []byte, key heldKey, at, configured string) error {
	carried, present, err := readCarriedKeyHistory(registryPath)
	if err != nil {
		return fmt.Errorf("the key history carried into the store: %w; the store is not rotated", err)
	}
	return continuationOrderRefusalOf(data, key, carried, present, at, configured)
}

// continuationOrderRefusalOf is continuationOrderRefusal over the history
// carried into the store as read, on either kind.
func continuationOrderRefusalOf(data []byte, key heldKey, carried []byte, present bool, at, configured string) error {
	made, err := registryKeyHistoryOf(data, key, carried, present, configured)
	if err != nil {
		return fmt.Errorf("the store's key history: %w; the store is not rotated", err)
	}
	return keyHistoryWriteRefusalAt(made.last, at, keyHistoryContinuationOrder, keyHistoryContinuationFault, nil)
}

// continuationHolds holds a store continuation line, stamped at over the
// old registry's bytes data, to the key history the new store's
// /publickey/history would make from it and history, carried beside it
// (keyHistoryWriteRefusal), before the new store is written.
func continuationHolds(data, line []byte, key heldKey, history []byte, at, configured string) error {
	before, err := checkKeyHistoryOf(history, nil, "")
	if err != nil {
		return fmt.Errorf("the key history to carry: %w", err)
	}
	return keyHistoryWriteRefusalAt(before.latest, at, keyHistoryContinuationOrder, keyHistoryContinuationFault, func() error {
		_, err := walkKeyHistory(line, key, history, true, configured)
		return err
	})
}

// historyToCarry is the key history a store rotation carries, from the old
// registry's bytes and the history carried into the old store, read with
// err: the answer the old store's gateway gives.
func historyToCarry(data []byte, key heldKey, carried []byte, present bool, err error, configured string) ([]byte, error) {
	if err != nil {
		return nil, fmt.Errorf("the key history carried into the store: %w", err)
	}
	made, err := registryKeyHistoryOf(data, key, carried, present, configured)
	if err != nil {
		return nil, fmt.Errorf("the store's key history: %w", err)
	}
	return made.doc, nil
}

// carryKeyHistory is a rerun's carrying of the key history beside a new
// registry whose continuation names the history by named, its digest: a
// history there already is kept only when its bytes are the ones named,
// and one not there is written, durably, only when the history
// carriedHistoryOf gives is; otherwise the rerun is refused, nothing
// changed.
func carryKeyHistory(registryPath string, data []byte, key heldKey, newRegistry, named, configured string) error {
	there, present, err := readCarriedKeyHistory(newRegistry)
	if err != nil {
		return fmt.Errorf("the new registry's key history: %w", err)
	}
	if present {
		if got := keyHistoryDigestOf(there); got != named {
			return fmt.Errorf("the key history beside the new registry is %s, not the history %s its store continuation names; nothing was changed", got, named)
		}
		return nil
	}
	history, err := carriedHistoryOf(registryPath, data, key, configured)
	if err != nil {
		return err
	}
	if got := keyHistoryDigestOf(history); got != named {
		return fmt.Errorf("the store's key history is %s, not the history %s the new registry's store continuation names; nothing was changed", got, named)
	}
	if err := writeNewRegistry(keyHistoryBeside(newRegistry), history); err != nil {
		return fmt.Errorf("the new registry's key history: %w", err)
	}
	return nil
}
