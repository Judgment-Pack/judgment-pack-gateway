package main

// `gateway rotate-key`: a gateway's signing key handed on to a new one
// (SPEC.md §3b, "Rotating"), with the gateway stopped. The next seed is made,
// both statements of the rotation are appended to the registry as one durable
// record, and only then is the signer switched to the next seed.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
)

const rotateKeyUsage = `usage: gateway rotate-key --seed <file> --registry <file>
Rotates the gateway's signing key, the gateway stopped: makes <seed>.next,
appends the rotation's two statements to the registry, then moves the seed to
<seed>.rotated-<n> and <seed>.next to <seed>. Verifiers follow the rotation
from the key they pinned; nothing new is pinned.`

// rotation is what a rotation wrote: its ordinal, the keys it rotated from
// and to, and where the seed rotated from was kept.
type rotation struct {
	ordinal  int
	from, to ed25519.PublicKey
	kept     string
}

// errRotationPending is a rotation that was written, or may have been, and
// whose switch was not made: the gateway refuses to start under the seed it
// rotated from until its operator completes the switch.
var errRotationPending = errors.New("a rotation is pending")

func cmdRotateKey(args []string, stdout, stderr io.Writer) int {
	flags := map[string]string{}
	for rest := args; len(rest) > 0; rest = rest[2:] {
		name := rest[0]
		if (name != "--seed" && name != "--registry") || len(rest) < 2 || rest[1] == "" {
			fmt.Fprintln(stderr, rotateKeyUsage)
			return 2
		}
		if _, given := flags[name]; given {
			fmt.Fprintf(stderr, "%s is given twice\n%s\n", name, rotateKeyUsage)
			return 2
		}
		flags[name] = rest[1]
	}
	if flags["--seed"] == "" || flags["--registry"] == "" {
		fmt.Fprintln(stderr, rotateKeyUsage)
		return 2
	}
	r, err := rotateKey(flags["--seed"], flags["--registry"], nowStamp, rand.Reader)
	if err != nil {
		fmt.Fprintln(stderr, "rotate-key:", err)
		return 1
	}
	fmt.Fprintf(stdout, "rotation %d: key %s rotated to key %s\npublicKey %s\nthe seed rotated from is kept at %s; destroy it once nothing needs it\n",
		r.ordinal, keyIDFor(r.from), keyIDFor(r.to), hex.EncodeToString(r.to), r.kept)
	return 0
}

// rotateKey rotates the key of the seed at seedPath, recording the rotation
// in the registry at registryPath (SPEC.md §3b, "Rotating"). It refuses a
// seed that is not there or not a seed, a registry that is not there or
// whose walk does not hold or ends at another key than the seed's, and a
// next seed already made: each before anything is written.
func rotateKey(seedPath, registryPath string, stamp func() string, random io.Reader) (*rotation, error) {
	seed, err := loadSeed(seedPath)
	if err != nil {
		return nil, fmt.Errorf("the seed of the key to rotate from cannot be read, and a key that cannot sign cannot name its successor: %w", err)
	}
	nextPath := seedPath + ".next"
	if _, err := os.Lstat(nextPath); err == nil || !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s is there; complete the switch to it, or remove it if no registry names its key", errRotationPending, nextPath)
	}
	data, present, err := readRegistryBytes(registryPath)
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	if !present {
		return nil, fmt.Errorf("the registry is not there: %s; a gateway makes it when it starts, and a rotation is recorded in it", registryPath)
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
		return nil, fmt.Errorf("read back the next seed at %s: %w", nextPath, err)
	}
	nextPrivate := ed25519.NewKeyFromSeed(persisted)
	to := nextPrivate.Public().(ed25519.PublicKey)

	at := stamp()
	forward := rotationStatementObject(rotationKindForward, ordinal, at, keyIDFor(from), to)
	forward.set("signature", vString(hex.EncodeToString(ed25519.Sign(private, rotationSigningInput(forward)))))
	reverse := rotationStatementObject(rotationKindReverse, ordinal, at, keyIDFor(to), from)
	reverse.set("signature", vString(hex.EncodeToString(ed25519.Sign(nextPrivate, rotationSigningInput(reverse)))))

	// One record, the key-rotation first, each on a line of its own; an
	// unterminated last line is ended first, as the seal's writer ends it.
	log, err := openFsLog(registryPath)
	if err != nil {
		os.Remove(nextPath)
		return nil, err
	}
	existing, err := log.readLog(0)
	if err != nil {
		os.Remove(nextPath)
		return nil, err
	}
	if string(existing) != string(data) {
		os.Remove(nextPath)
		return nil, fmt.Errorf("the registry changed while the rotation was made, so something is writing to it -- a running gateway? -- and a rotation is made with the gateway stopped; nothing was written")
	}
	var record []byte
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		record = append(record, '\n')
	}
	boundary := len(record)
	record = append(append(record, canon(forward)...), '\n')
	record = append(append(record, canon(reverse)...), '\n')
	if n, err := log.appendRecord(record); err != nil {
		if n > boundary || committed(err) {
			return nil, fmt.Errorf("%w: the rotation may be in the registry (%v); the gateway starts again only once %s is moved to %s and %s to %s", errRotationPending, err, seedPath, kept, nextPath, seedPath)
		}
		// nothing of the rotation was written: the next seed names no key
		// any registry holds
		os.Remove(nextPath)
		return nil, err
	}

	// The switch, only now that the rotation is durable: the seed rotated
	// from is kept aside, and the next seed takes its name.
	if err := os.Rename(seedPath, kept); err != nil {
		return nil, fmt.Errorf("%w: the rotation is in the registry, and the seed was not moved (%v); move %s to %s and %s to %s", errRotationPending, err, seedPath, kept, nextPath, seedPath)
	}
	if err := os.Rename(nextPath, seedPath); err != nil {
		return nil, fmt.Errorf("%w: the rotation is in the registry and the seed rotated from is at %s, and the next seed was not moved (%v); move %s to %s", errRotationPending, kept, err, nextPath, seedPath)
	}
	syncDir(filepath.Dir(seedPath))
	return &rotation{ordinal: ordinal, from: from, to: to, kept: kept}, nil
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
