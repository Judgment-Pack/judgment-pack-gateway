package main

// A rotation while the gateway serves (docs/adr/0050-an-external-signer-in-a-key-service.md;
// SPEC.md §3b): the gateway's key handed on to the next, the two statements
// appended to the registry by the gateway itself, under the writer's own
// hold on it, and only then the switch. The store and the registry share
// one signerHolder, switched whole: a receipt or a seal reads it once and is
// signed, and names its keyId, under what it read, so each is under exactly
// one key. One minted before the switch, after the record is appended, is
// under the key rotated from, which the registry's walk reaches: a verifier
// that pinned the first key verifies it, as every receipt under an earlier
// key, from the registry alone.

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// rotationMayBeWritten is a rotation whose append failed: its record may be
// in the registry, in part or whole and not made durable, or not at all.
// The gateway does not switch, and it stops; the operator settles the
// registry before it starts again, as ADR-0050 ("A rotation whose append
// failed") says: a key-service rotation leaves no kept record beside a seed,
// so gateway rotate-key --resume does not settle it.
type rotationMayBeWritten struct{ error }

// errRotationBesideWitness is SIGHUP on a gateway serving as a witness,
// whose checkpoints the seed's key signs: the configuration read again
// without its witness member does not move it to a key service.
var errRotationBesideWitness = errors.New("this gateway serves as a witness, whose checkpoints the seed's key signs: a rotation while serving to a key service is not made beside it (ADR-0050); nothing was changed")

// rotationRecordSigned is rotationRecord signed through two keys: the
// key-rotation by from, the key-continuation by to, each signature held to
// its key before the record is answered. Under two seeds' keys it is
// rotationRecord's bytes.
func rotationRecordSigned(before []byte, ordinal int, at string, from, to *signingKey) ([]byte, error) {
	forward := rotationStatementObjectAlg(rotationKindForward, ordinal, at, from.keyID, from.alg, to.public, to.alg)
	signature, err := from.signVerified(rotationSigningInput(forward))
	if err != nil {
		return nil, err
	}
	forward.set("signature", vString(hex.EncodeToString(signature)))
	reverse := rotationStatementObjectAlg(rotationKindReverse, ordinal, at, to.keyID, to.alg, from.public, from.alg)
	if signature, err = to.signVerified(rotationSigningInput(reverse)); err != nil {
		return nil, err
	}
	reverse.set("signature", vString(hex.EncodeToString(signature)))
	var record []byte
	if len(before) > 0 && before[len(before)-1] != '\n' {
		record = append(record, '\n')
	}
	record = append(append(record, canon(forward)...), '\n')
	return append(append(record, canon(reverse)...), '\n'), nil
}

// rotationStatementObjectAlg is rotationStatementObject naming, where a
// P-256 key signs it, the signer's algorithm in alg, and, where the key it
// names is one, that key's in nextAlg or previousAlg (ADR-0053 §7). Under
// two Ed25519 keys it is rotationStatementObject's object.
func rotationStatementObjectAlg(kind string, ordinal int, at, keyID, alg string, named []byte, namedAlg string) *vObject {
	obj := rotationStatementObject(kind, ordinal, at, keyID, named)
	setAlg(obj, "alg", alg)
	member := "nextAlg"
	if kind == rotationKindReverse {
		member = "previousAlg"
	}
	setAlg(obj, member, namedAlg)
	return obj
}

// hsmToSoftwareLine is the one line a rotation from a P-256 key, taken at
// the key service's HSM protection level alone, to an Ed25519 key says on
// the standard error (ADR-0053 §7): allowed, since refusing it would block
// a rollback, and named.
const hsmToSoftwareLine = "this rotation moves the gateway from an HSM key (ES256, protection level HSM) to a key that is not one (Ed25519): allowed, and recorded in the key history as any rotation (ADR-0053)"

// rotateTo hands the gateway's key on to next, stamped at, while it serves.
// Under the writer's switching hold, which every seal takes: the registry
// is walked to the current key; the record is signed, the forward statement
// by the current key and the reverse by next -- with a key service, two
// calls of it -- and read back, with the registry before it, as a walk to
// next; it is appended; and only once the append has returned is the
// holder switched. Anything refused before the append changes nothing.
func (w *registryWriter) rotateTo(next signer, at string) (*signingKey, error) {
	if _, judged := w.log.(judgedAppendLog); judged {
		return nil, errors.New("a rotation while serving is not yet built on a registry several instances append to (ADR-0050); nothing was changed")
	}
	if !witnessTimeForm.MatchString(at) {
		return nil, errors.New("a rotation is stamped YYYY-MM-DDThh:mm:ssZ; nothing was changed")
	}
	w.switching.Lock()
	defer w.switching.Unlock()
	from := w.signing.key()
	to := newSigningKey(next)
	if to.keyID == from.keyID {
		return nil, errors.New("the key to rotate to is the gateway's key already; nothing was changed")
	}
	existing, err := w.log.readLog(0)
	if err != nil {
		return nil, fmt.Errorf("registry %s: %w", w.path, err)
	}
	walk, err := engineWalk(existing, from.held())
	if err != nil {
		return nil, fmt.Errorf("registry %s: %w", w.path, err)
	}
	record, err := rotationRecordSigned(existing, walk.followed()+1, at, from, to)
	if err != nil {
		return nil, err
	}
	if _, err := engineWalk(append(bytes.Clone(existing), record...), to.held()); err != nil {
		return nil, fmt.Errorf("the rotation's record would not walk to the next key; nothing was changed: %w", err)
	}
	// the key history /publickey/history would make with the record, held
	// before the append: no rotation is written that the history refuses
	if err := rotationHoldsInKeyHistory(w.path, existing, record, from.held(), to.held(), at); err != nil {
		return nil, err
	}
	if n, err := w.log.appendRecord(record); err != nil {
		if n > 0 || committed(err) {
			return nil, rotationMayBeWritten{fmt.Errorf("the rotation's record may be in the registry %s; the gateway did not switch, and stops: settle the registry before it starts again (ADR-0050): %w", w.path, err)}
		}
		return nil, rotationMayBeWritten{fmt.Errorf("the rotation's record could not be appended to the registry %s; the gateway did not switch, and stops: settle the registry before it starts again (ADR-0050): %w", w.path, err)}
	}
	w.signing.switchTo(to)
	return to, nil
}

// rotationHoldsInKeyHistory refuses, on the file kind, a rotation from
// from to to stamped at whose record, at the end of the registry's bytes
// data, would leave a key history the consumer's check refuses
// (keyHistoryWriteRefusal): the history built as /publickey/history builds
// it, with what a store rotation carried beside the registry at
// registryPath. A history that does not hold before the rotation refuses it
// too. Nothing is written.
func rotationHoldsInKeyHistory(registryPath string, data, record []byte, from, to heldKey, at string) error {
	carried, present, err := readCarriedKeyHistory(registryPath)
	if err != nil {
		return fmt.Errorf("the key history carried into the store: %w; nothing was written", err)
	}
	before, err := registryKeyHistory(data, from, carried, present)
	if err != nil {
		return fmt.Errorf("the key history before the rotation does not hold: %w; nothing was written", err)
	}
	return keyHistoryWriteRefusal(before, at, storeRotateKeyBefore, keyHistoryRotationFault, func() error {
		_, err := walkKeyHistory(append(bytes.Clone(data), record...), to, carried, present)
		return err
	})
}

// errRotationOnKind is SIGHUP on the PostgreSQL kind, where several
// instances may serve one database: a rotation there is every instance
// stopped, the registry rotated by gateway store rotate-key
// (store_rotate_key_pg.go), and every instance started under the next key;
// a coordinated rotation across instances while they serve is #537.
var errRotationOnKind = errors.New("a rotation while serving is not made on the PostgreSQL kind: stop every instance, rotate with gateway store rotate-key, and start them all under the next key version (ADR-0050); nothing was changed")

// installRotationOnHangup rotates the gateway's key at each SIGHUP until ctx
// ends (rotateOnHangup), saying the outcome on said; a rotation whose append
// failed stops the gateway through stop (answerHangup).
func installRotationOnHangup(ctx context.Context, g *gatewayService, said io.Writer, stop func(error)) {
	hangups := make(chan os.Signal, 1)
	signal.Notify(hangups, syscall.SIGHUP)
	go func() {
		defer signal.Stop(hangups)
		for {
			select {
			case <-ctx.Done():
				return
			case <-hangups:
				if g.answerHangup(nowStamp, said, stop) {
					return
				}
			}
		}
	}()
}

// answerHangup is one SIGHUP: the rotation's outcome said on said, and,
// where the rotation's append failed (rotationMayBeWritten), stop called
// with it, for the gateway does not serve on over a registry that may hold
// part of a rotation it did not switch to. It answers whether it stopped.
func (g *gatewayService) answerHangup(stamp func() string, said io.Writer, stop func(error)) bool {
	var fromAlg string
	if g.registry != nil {
		fromAlg = g.registry.signing.key().alg
	}
	line, err := g.rotateOnHangup(stamp)
	if err == nil {
		fmt.Fprintln(said, "rotate:", line)
		if fromAlg == algES256 && g.registry.signing.key().alg == algEd25519 {
			fmt.Fprintln(said, "rotate:", hsmToSoftwareLine)
		}
		return false
	}
	fmt.Fprintln(said, "rotate:", err)
	var written rotationMayBeWritten
	if !errors.As(err, &written) {
		return false
	}
	stop(err)
	return true
}

// rotateOnHangup is the operator's trigger of a rotation while serving
// (ADR-0050, decision 3(a)), on the file kind alone: the configuration read
// again, under its own checks, for signingKeyVersion and signingPublicKey
// only; the key version it names read and checked as at the start; and the
// gateway's key rotated to it (registryWriter.rotateTo), whose walk check
// refuses a key the registry rotated from. A gateway its seed signs for is
// moved to the key service the same way. A refusal before the append
// changes nothing; an append that failed (rotationMayBeWritten) switches
// nothing, and the gateway stops (answerHangup).
func (g *gatewayService) rotateOnHangup(stamp func() string) (string, error) {
	if g.kind != nil {
		return "", errRotationOnKind
	}
	if g.witness != nil {
		return "", errRotationBesideWitness
	}
	if g.rereadConfig == nil || g.registry == nil {
		return "", errors.New("this gateway was not started from a configuration it can read again; nothing was changed")
	}
	cfg, err := g.rereadConfig()
	if err != nil {
		return "", fmt.Errorf("the configuration could not be read again: %w; nothing was changed", err)
	}
	if cfg.signingKeyVersion == "" {
		return "", errors.New("the configuration names no signingKeyVersion; a rotation while serving is to a key service's key version; nothing was changed")
	}
	next, _, err := newKeyServiceSignerPinned(cfg.signingKeyVersion, cfg.signingPublicKey, cfg.signingKeyAlgorithm)
	if err != nil {
		return "", fmt.Errorf("%w; nothing was changed", err)
	}
	if g.ctx != nil {
		next.bindLife(g.ctx)
	}
	to, err := g.registry.rotateTo(next, stamp())
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("the gateway's key is rotated to the key service's key version %s, keyId %s; a receipt begun from now on is under it", cfg.signingKeyVersion, to.keyID), nil
}

// said0 is said, or the standard error where it is nil.
func said0(said io.Writer) io.Writer {
	if said == nil {
		return os.Stderr
	}
	return said
}
