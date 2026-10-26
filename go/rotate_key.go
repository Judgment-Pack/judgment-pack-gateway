package main

// `gateway rotate-key`: a gateway's signing key handed on to a new one
// (SPEC.md §3b, "Rotating"), with the gateway stopped -- on Unix, the
// registry locked, which a running gateway holds. The next seed is made, the
// record of the rotation is kept beside the seed, both statements are
// appended to the registry as one durable record, and only then is the signer
// switched to the next seed. `--resume` finishes a rotation that stopped
// anywhere after the next seed was made: it cuts from the registry nothing
// but a tail of the very record it keeps, appends that record again, and
// makes the switch.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
)

const rotateKeyUsage = `usage: gateway rotate-key --seed <file> --registry <file> [--resume]
Rotates the gateway's signing key, the gateway stopped: makes <seed>.next,
keeps the record it appends in <seed>.rotation, appends the rotation's two
statements to the registry, then moves the seed to <seed>.rotated-<n> and
<seed>.next to <seed>. --resume finishes a rotation that stopped on the way.
Verifiers follow the rotation from the key they pinned; nothing new is pinned.`

// rotation is what a rotation wrote: its ordinal, the keys it rotated from
// and to, where the seed rotated from was kept, and whether the registry was
// locked while it was written.
type rotation struct {
	ordinal  int
	from, to ed25519.PublicKey
	kept     string
	unlocked bool
}

// errRotationPending is a rotation begun and not finished: a next seed or
// a kept record beside the seed. The gateway refuses to start under either
// key until gateway rotate-key --resume finishes it.
var errRotationPending = errors.New("a rotation is pending")

// errRegistryHeld is the registry locked by another: a running gateway, or
// a rotation under way.
var errRegistryHeld = errors.New("the registry is held by a running gateway, or by a rotation under way")

// The files a rotation keeps beside the seed while it is under way.
const (
	nextSeedSuffix = ".next"
	recordSuffix   = ".rotation"
)

// openRotationLog is the registry's log as rotate-key appends to it; a test
// stands in a write that fails part way, or a writer beside it.
var openRotationLog = func(path string) (*fsLog, error) { return openFsLog(path) }

func cmdRotateKey(args []string, stdout, stderr io.Writer) int {
	flags := map[string]string{}
	resume := false
	for rest := args; len(rest) > 0; {
		name := rest[0]
		if name == "--resume" && !resume {
			resume, rest = true, rest[1:]
			continue
		}
		if (name != "--seed" && name != "--registry") || len(rest) < 2 || rest[1] == "" {
			fmt.Fprintln(stderr, rotateKeyUsage)
			return 2
		}
		if _, given := flags[name]; given {
			fmt.Fprintf(stderr, "%s is given twice\n%s\n", name, rotateKeyUsage)
			return 2
		}
		flags[name] = rest[1]
		rest = rest[2:]
	}
	if flags["--seed"] == "" || flags["--registry"] == "" {
		fmt.Fprintln(stderr, rotateKeyUsage)
		return 2
	}
	run := rotateKey
	if resume {
		run = resumeRotation
	}
	r, err := run(flags["--seed"], flags["--registry"], nowStamp, rand.Reader)
	if err != nil {
		fmt.Fprintln(stderr, "rotate-key:", err)
		return 1
	}
	fmt.Fprintf(stdout, "rotation %d: key %s rotated to key %s\npublicKey %s\nthe seed rotated from is kept at %s; destroy it once nothing needs it\n",
		r.ordinal, keyIDFor(r.from), keyIDFor(r.to), hex.EncodeToString(r.to), r.kept)
	if r.unlocked {
		fmt.Fprintln(stderr, "rotate-key: this platform locks no registry, so a gateway still running was not looked for; the gateway was to be stopped")
	}
	return 0
}

// rotationPendingBeside refuses a seed beside which a rotation is under way:
// a next seed made, or a record kept, and the rotation not finished. A
// gateway does not start under either key while it is (SPEC.md §3b).
func rotationPendingBeside(seedPath, registryPath string) error {
	for _, suffix := range []string{recordSuffix, nextSeedSuffix} {
		if _, err := os.Lstat(seedPath + suffix); err == nil || !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: %s is there; finish it with gateway rotate-key --resume --seed %s --registry %s", errRotationPending, seedPath+suffix, seedPath, registryPath)
		}
	}
	return nil
}

// holdEngineRegistry is the lock a gateway holds on its registry while it
// runs, taken once the registry is there: refused when another holds it,
// and, once held, the gateway's own reading of the registry is made again
// under it, so a rotation finished between the gateway's first reading and
// the lock is seen and refused. The file returned holds the lock until it
// is closed; nil where the platform locks no registry.
func holdEngineRegistry(registryPath string, seed []byte) (io.Closer, error) {
	lock, err := lockRegistry(registryPath)
	if err != nil {
		if errors.Is(err, errRegistryHeld) {
			return nil, fmt.Errorf("%w: %s", err, registryPath)
		}
		return nil, err
	}
	data, _, err := readRegistryBytes(registryPath)
	if err == nil {
		_, err = engineWalk(data, ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	}
	if err != nil {
		if lock != nil {
			lock.Close()
		}
		return nil, err
	}
	if lock == nil {
		return io.NopCloser(nil), nil
	}
	return lock, nil
}

// keptRecord is what rotate-key keeps beside the seed before it appends:
// the rotation's ordinal, the key ids it rotates from and to, the registry's
// length and digest where the rotation goes, and the record's exact bytes.
type keptRecord struct {
	rotation int
	from, to string
	length   int64
	digest   string
	record   []byte
}

func (k keptRecord) bytes() []byte {
	o := newObject()
	o.set("from", vString(k.from))
	o.set("record", vString(string(k.record)))
	o.set("registryDigest", vString(k.digest))
	o.set("registryLength", vInt(k.length))
	o.set("rotation", vInt(k.rotation))
	o.set("to", vString(k.to))
	return append(canon(o), '\n')
}

func readKeptRecord(path string) (keptRecord, error) {
	data, err := readBounded(path, 1<<16)
	if err != nil {
		return keptRecord{}, err
	}
	v, err := parseJSON(data)
	obj, ok := v.(*vObject)
	if err != nil || !ok {
		return keptRecord{}, fmt.Errorf("%s is not the record rotate-key keeps", path)
	}
	var k keptRecord
	record, _ := memberString(obj, "record")
	k.from, _ = memberString(obj, "from")
	k.to, _ = memberString(obj, "to")
	k.digest, _ = memberString(obj, "registryDigest")
	length, okL := obj.get("registryLength")
	ordinal, okR := obj.get("rotation")
	l, okLI := length.(vInt)
	r, okRI := ordinal.(vInt)
	if !okL || !okR || !okLI || !okRI || l < 0 || r < 1 || record == "" || !isLowerHexOfLen(k.from, 32) || !isLowerHexOfLen(k.to, 32) || !isDigest(k.digest) {
		return keptRecord{}, fmt.Errorf("%s is not the record rotate-key keeps", path)
	}
	k.record, k.length, k.rotation = []byte(record), int64(l), int(r)
	return k, nil
}

func registryDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// rotationRecord is the record a rotation appends: the key-rotation the key
// rotated from signs, then the key-continuation the next key signs, each on
// a line of its own, after a newline ending an unterminated last line of
// the registry before it.
func rotationRecord(before []byte, ordinal int, at string, from, next ed25519.PrivateKey) []byte {
	fromKey, toKey := from.Public().(ed25519.PublicKey), next.Public().(ed25519.PublicKey)
	forward := rotationStatementObject(rotationKindForward, ordinal, at, keyIDFor(fromKey), toKey)
	forward.set("signature", vString(hex.EncodeToString(ed25519.Sign(from, rotationSigningInput(forward)))))
	reverse := rotationStatementObject(rotationKindReverse, ordinal, at, keyIDFor(toKey), fromKey)
	reverse.set("signature", vString(hex.EncodeToString(ed25519.Sign(next, rotationSigningInput(reverse)))))
	var record []byte
	if len(before) > 0 && before[len(before)-1] != '\n' {
		record = append(record, '\n')
	}
	record = append(append(record, canon(forward)...), '\n')
	return append(append(record, canon(reverse)...), '\n')
}

// rotateKey rotates the key of the seed at seedPath, recording the rotation
// in the registry at registryPath (SPEC.md §3b, "Rotating"). It refuses,
// before anything is written, a seed that cannot sign, a rotation under way,
// a registry held by a running gateway or not there, a walk that does not
// hold or ends at another key than the seed's, and a seed kept already where
// this one would be.
func rotateKey(seedPath, registryPath string, stamp func() string, random io.Reader) (*rotation, error) {
	seed, err := loadSeed(seedPath)
	if err != nil {
		return nil, fmt.Errorf("the seed of the key to rotate from cannot be read, and a key that cannot sign cannot name its successor: %w", err)
	}
	if err := rotationPendingBeside(seedPath, registryPath); err != nil {
		return nil, err
	}
	nextPath, recordPath := seedPath+nextSeedSuffix, seedPath+recordSuffix
	if _, present, err := readRegistryBytes(registryPath); err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	} else if !present {
		return nil, fmt.Errorf("the registry is not there: %s; a gateway makes it when it starts, and a rotation is recorded in it", registryPath)
	}
	lock, err := lockRegistry(registryPath)
	if err != nil {
		return nil, err
	}
	if lock != nil {
		defer lock.Close()
	}
	data, _, err := readRegistryBytes(registryPath)
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	private := ed25519.NewKeyFromSeed(seed)
	from := private.Public().(ed25519.PublicKey)
	walk, err := engineWalk(data, from)
	if err != nil {
		return nil, err
	}
	ordinal := walk.followed() + 1
	kept := seedPath + ".rotated-" + strconv.Itoa(ordinal)
	if _, err := os.Lstat(kept); err == nil || !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s is there already; nothing was changed", kept)
	}

	// The next seed, made once and never replaced; its key is derived from
	// the bytes persisted, as keygen derives its own.
	next := make([]byte, seedBytes)
	if _, err := io.ReadFull(random, next); err != nil {
		return nil, fmt.Errorf("generate the next seed: %w", err)
	}
	if err := seedSecret(nextPath).putSecret("seed", []byte(hex.EncodeToString(next)+"\n")); err != nil {
		return nil, fmt.Errorf("write the next seed: %w", err)
	}
	persisted, err := readSeedFile(nextPath)
	if err != nil {
		os.Remove(nextPath)
		return nil, fmt.Errorf("read back the next seed at %s: %w", nextPath, err)
	}
	nextPrivate := ed25519.NewKeyFromSeed(persisted)
	to := nextPrivate.Public().(ed25519.PublicKey)

	// The record is kept, durably, before a byte of it reaches the
	// registry: whatever stops the append, --resume knows exactly which
	// bytes are the rotation's.
	record := rotationRecord(data, ordinal, stamp(), private, nextPrivate)
	k := keptRecord{rotation: ordinal, from: keyIDFor(from), to: keyIDFor(to), length: int64(len(data)), digest: registryDigest(data), record: record}
	if err := writeNewSeed(recordPath, k.bytes()); err != nil {
		os.Remove(nextPath)
		return nil, fmt.Errorf("keep the rotation's record: %w", err)
	}
	syncDir(filepath.Dir(seedPath))
	abandon := func() {
		os.Remove(recordPath)
		os.Remove(nextPath)
		syncDir(filepath.Dir(seedPath))
	}

	log, err := openRotationLog(registryPath)
	if err != nil {
		abandon()
		return nil, err
	}
	existing, err := log.readLog(0)
	if err != nil {
		abandon()
		return nil, err
	}
	if !bytes.Equal(existing, data) {
		abandon()
		return nil, fmt.Errorf("the registry changed while the rotation was made, so something is writing to it, and a rotation is made with the gateway stopped; nothing was written")
	}
	if n, err := log.appendRecord(record); err != nil {
		if n > 0 || committed(err) {
			return nil, fmt.Errorf("%w: the rotation may be in the registry in part (%v); finish it with gateway rotate-key --resume --seed %s --registry %s, which cuts nothing but the rotation's own bytes", errRotationPending, err, seedPath, registryPath)
		}
		// nothing of the record was written: the next seed names no key
		// any registry holds
		abandon()
		return nil, err
	}
	if err := switchSeed(seedPath, kept); err != nil {
		return nil, err
	}
	return &rotation{ordinal: ordinal, from: from, to: to, kept: kept, unlocked: lock == nil}, nil
}

// switchSeed makes the switch once the record is durable: the seed rotated
// from moved aside to kept, the next seed moved to the seed's name, and the
// kept record removed last. Each step left undone is --resume's to finish.
func switchSeed(seedPath, kept string) error {
	nextPath, recordPath := seedPath+nextSeedSuffix, seedPath+recordSuffix
	pending := func(err error) error {
		return fmt.Errorf("%w: the rotation is in the registry and the switch stopped (%v); finish it with gateway rotate-key --resume", errRotationPending, err)
	}
	if _, err := os.Lstat(nextPath); err == nil {
		if _, err := os.Lstat(seedPath); err == nil {
			if _, err := os.Lstat(kept); err == nil || !errors.Is(err, fs.ErrNotExist) {
				return pending(fmt.Errorf("%s is there already", kept))
			}
			if err := os.Rename(seedPath, kept); err != nil {
				return pending(err)
			}
		}
		if err := os.Rename(nextPath, seedPath); err != nil {
			return pending(err)
		}
	}
	syncDir(filepath.Dir(seedPath))
	if err := os.Remove(recordPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return pending(err)
	}
	syncDir(filepath.Dir(seedPath))
	return nil
}

// seedKeyAt is the private key of the seed at path, nil when no seed is
// there.
func seedKeyAt(path string) (ed25519.PrivateKey, error) {
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	seed, err := loadSeed(path)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// resumeRotation finishes a rotation that stopped after its next seed was
// made (SPEC.md §3b, "Rotating"). From the record kept beside the seed it
// finds the two keys, among the seed, the next seed and the seed kept aside;
// it rebuilds the record from them and holds the kept one to it byte for
// byte; it holds the registry before the rotation's place to the length and
// digest kept; and the registry from there must be the record, whole, or a
// part of it from its first byte. A part is cut and the record appended
// whole. Then the switch is made. Anything else is refused, nothing changed.
func resumeRotation(seedPath, registryPath string, _ func() string, _ io.Reader) (*rotation, error) {
	nextPath, recordPath := seedPath+nextSeedSuffix, seedPath+recordSuffix
	if _, err := os.Lstat(recordPath); errors.Is(err, fs.ErrNotExist) {
		return nil, resumeWithoutRecord(seedPath, registryPath)
	}
	k, err := readKeptRecord(recordPath)
	if err != nil {
		return nil, err
	}
	kept := seedPath + ".rotated-" + strconv.Itoa(k.rotation)
	var from, next ed25519.PrivateKey
	for _, path := range []string{seedPath, nextPath, kept} {
		key, err := seedKeyAt(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if key == nil {
			continue
		}
		switch keyIDFor(key.Public().(ed25519.PublicKey)) {
		case k.from:
			from = key
		case k.to:
			next = key
		}
	}
	if from == nil || next == nil {
		return nil, fmt.Errorf("the seeds of the keys the kept record names are not beside %s; nothing was changed", seedPath)
	}
	lock, err := lockRegistry(registryPath)
	if err != nil {
		return nil, err
	}
	if lock != nil {
		defer lock.Close()
	}
	data, present, err := readRegistryBytes(registryPath)
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	if !present || int64(len(data)) < k.length || registryDigest(data[:k.length]) != k.digest {
		return nil, fmt.Errorf("the registry before the rotation's place is not the one the rotation walked; nothing was changed")
	}
	before, tail := data[:k.length], data[k.length:]
	at, ok := keptRotatedAt(k.record)
	if !ok || !bytes.Equal(rotationRecord(before, k.rotation, at, from, next), k.record) {
		return nil, fmt.Errorf("the kept record is not the record this rotation writes; nothing was changed")
	}
	if w, err := engineWalk(before, from.Public().(ed25519.PublicKey)); err != nil || w.followed()+1 != k.rotation {
		return nil, fmt.Errorf("the registry before the rotation's place does not end at the key rotated from; nothing was changed")
	}
	if !bytes.Equal(tail, k.record) {
		if !bytes.HasPrefix(k.record, tail) {
			return nil, fmt.Errorf("the registry holds %d bytes after the rotation's place that are not the rotation's; nothing was changed", len(tail))
		}
		// A part of the record from its first byte, and nothing else: cut
		// it, and append the record whole.
		if err := cutRegistry(registryPath, k.length); err != nil {
			return nil, err
		}
		log, err := openRotationLog(registryPath)
		if err != nil {
			return nil, err
		}
		if n, err := log.appendRecord(k.record); err != nil {
			if n > 0 || committed(err) {
				return nil, fmt.Errorf("%w: the record may be in the registry in part again (%v); run gateway rotate-key --resume again", errRotationPending, err)
			}
			return nil, err
		}
	}
	if err := switchSeed(seedPath, kept); err != nil {
		return nil, err
	}
	return &rotation{ordinal: k.rotation, from: from.Public().(ed25519.PublicKey), to: next.Public().(ed25519.PublicKey), kept: kept, unlocked: lock == nil}, nil
}

// resumeWithoutRecord is --resume with no record kept: rotate-key keeps the
// record before it appends, so no byte of a rotation was appended. A next
// seed left from before the record was kept names no key the registry
// holds, and is removed when the registry's walk ends at the seed's key.
func resumeWithoutRecord(seedPath, registryPath string) error {
	nextPath := seedPath + nextSeedSuffix
	if _, err := os.Lstat(nextPath); errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("no rotation is under way beside %s", seedPath)
	}
	seed, err := loadSeed(seedPath)
	if err != nil {
		return fmt.Errorf("the seed: %w", err)
	}
	data, _, err := readRegistryBytes(registryPath)
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	if _, err := engineWalk(data, ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)); err != nil {
		return fmt.Errorf("%s is there with no record kept, and the registry does not end at the seed's key: %w", nextPath, err)
	}
	if err := os.Remove(nextPath); err != nil {
		return err
	}
	syncDir(filepath.Dir(seedPath))
	return fmt.Errorf("the rotation stopped before anything was appended; its next seed was removed, and the registry holds no rotation of it: run gateway rotate-key again")
}

// keptRotatedAt is the rotatedAt of the key-rotation a kept record holds.
func keptRotatedAt(record []byte) (string, bool) {
	for _, line := range bytes.Split(record, []byte{'\n'}) {
		if kind, obj := rotationKindOf(string(line)); kind == rotationKindForward {
			at, ok := memberString(obj, "rotatedAt")
			return at, ok
		}
	}
	return "", false
}

// cutRegistry cuts the registry back to length, and makes the cut durable.
// It is the one cut of a registry this reference makes, and it cuts only a
// part of the record rotate-key kept, from its first byte (resumeRotation).
func cutRegistry(path string, length int64) error {
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if err := file.Truncate(length); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

// rotationStatementObject is a rotation statement without its signature
// (SPEC.md §3b): a key-rotation names the key rotated to as next, a
// key-continuation the key rotated from as previous; keyID is the signer's.
func rotationStatementObject(kind string, ordinal int, at, keyID string, named ed25519.PublicKey) *vObject {
	o := newObject()
	o.set("kind", vString(kind))
	o.set("rotationVersion", vString(rotationVersion))
	o.set("rotation", vInt(ordinal))
	o.set("rotatedAt", vString(at))
	o.set("keyId", vString(keyID))
	if kind == rotationKindForward {
		o.set("next", vString(hex.EncodeToString(named)))
		o.set("nextKeyId", vString(keyIDFor(named)))
	} else {
		o.set("previous", vString(hex.EncodeToString(named)))
		o.set("previousKeyId", vString(keyIDFor(named)))
	}
	return o
}
