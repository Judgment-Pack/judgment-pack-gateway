package main

// `gateway store rotate` (ADR-0048, S2; SPEC.md §3d): a store let go of by
// starting another. With the gateway stopped, the registry held as a
// gateway holds it while it serves (holdEngineRegistry), every session left
// open in the old store is sealed after the interruption, as seal-open --all
// seals it (SPEC.md §3c); then a new registry is made, in a new store
// directory the operator names, whose first line is a store continuation
// naming the old registry's line count and the SHA-256 of its last line,
// signed by the key in force. The old store and its registry are left as
// they are, for the operator to archive or delete whole.

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const storeRotateUsage = `usage:
  gateway store rotate (--config <engine.json> | --store <dir> --seed <file> --registry <file> --authority <authority>) --new-store <dir> --new-registry <file>
  gateway store rotate --config <engine.json> (--connection-file <path> | --connection-env <NAME>) --owner <role> --runtime <role> [--timeout <seconds>]
Rotates the store, the gateway stopped: seals every session left open in
it, as seal-open --all does, then makes the new store directory and the new
registry, whose first line names the old registry's line count and the
SHA-256 of its last line, signed by the key in force (SPEC.md §3d). Neither
new path may be there already. A session that cannot be sealed refuses the
rotation, and nothing new is made. The old store is not changed but by the
seals; it is the operator's to archive or delete whole. Prints each seal
appended, then the new registry's first line.
With the PostgreSQL kind (--config alone names it) the new store is a new
database, which the migration login's connection string names, as gateway
store migrate takes it: the database is to hold no store, and is migrated
and given the registry in one transaction. The start lease of the old
database is taken first: an instance serving it refuses the rotation.`

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
	return 0
}

// storeRotate is the command on the filesystem kind: the old registry held,
// what was left open sealed, and the new store and registry made under the
// hold, the registry's tail read after the last seal appended.
func storeRotate(o sealOpenOptions, newStore, newRegistry string, stamp func() string) ([]*vObject, []byte, error) {
	for _, path := range []string{newStore, newRegistry} {
		if _, err := os.Lstat(path); err == nil {
			return nil, nil, fmt.Errorf("%s is there already; a rotation starts a new store and registry, and nothing was changed", path)
		} else if !absent(err) {
			return nil, nil, err
		}
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
	hold, err := holdEngineRegistry(o.seedNames, o.registry, seed)
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
	writer, err := newRegistryWriter(o.registry, seed, func() (bool, error) { return true, nil })
	if err != nil {
		return nil, nil, err
	}
	sealed, refused, err := sealOpenUnder(fsSealOpenStore{o.store}, o.authority, writer, data, "", sealedViaCommand, stamp)
	if err != nil {
		return sealed, nil, fmt.Errorf("%v; the store is not rotated", err)
	}
	if len(refused) > 0 {
		return sealed, nil, fmt.Errorf("a session left open could not be sealed, so the store is not rotated: %s", refused[0])
	}
	// the tail is read after the seals, under the hold, and walked again as
	// the gateway walks it: the continuation names the registry as it ends
	data, present, err = readRegistryBytes(o.registry)
	if err != nil || !present {
		return sealed, nil, fmt.Errorf("registry: the registry could not be read after sealing: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if _, err := engineWalk(data, priv.Public().(ed25519.PublicKey)); err != nil {
		return sealed, nil, err
	}
	line := newContinuationLine(priv, data, stamp())
	if err := os.Mkdir(newStore, 0o700); err != nil {
		return sealed, nil, fmt.Errorf("the new store: %w", err)
	}
	if err := writeNewRegistry(newRegistry, line); err != nil {
		return sealed, nil, fmt.Errorf("the new registry: %w", err)
	}
	return sealed, line, nil
}

// writeNewRegistry makes the registry at path, which is not there, holding
// line alone, durably: the file and the directory that names it synced.
func writeNewRegistry(path string, line []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
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
	return syncDirectoryAt(filepath.Dir(path))
}
