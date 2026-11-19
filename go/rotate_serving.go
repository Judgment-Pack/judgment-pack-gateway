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

// rotationMayBeWritten is a rotation whose record may be in the registry,
// in part or whole and not made durable: the gateway does not switch, and
// is to be stopped and the registry settled as gateway rotate-key --resume
// settles a torn append.
type rotationMayBeWritten struct{ error }

// rotationRecordSigned is rotationRecord signed through two keys: the
// key-rotation by from, the key-continuation by to, each signature held to
// its key before the record is answered. Under two seeds' keys it is
// rotationRecord's bytes.
func rotationRecordSigned(before []byte, ordinal int, at string, from, to *signingKey) ([]byte, error) {
	forward := rotationStatementObject(rotationKindForward, ordinal, at, from.keyID, to.public)
	signature, err := from.signVerified(rotationSigningInput(forward))
	if err != nil {
		return nil, err
	}
	forward.set("signature", vString(hex.EncodeToString(signature)))
	reverse := rotationStatementObject(rotationKindReverse, ordinal, at, to.keyID, from.public)
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
	walk, err := engineWalk(existing, from.public)
	if err != nil {
		return nil, fmt.Errorf("registry %s: %w", w.path, err)
	}
	record, err := rotationRecordSigned(existing, walk.followed()+1, at, from, to)
	if err != nil {
		return nil, err
	}
	if _, err := engineWalk(append(bytes.Clone(existing), record...), to.public); err != nil {
		return nil, fmt.Errorf("the rotation's record would not walk to the next key; nothing was changed: %w", err)
	}
	if n, err := w.log.appendRecord(record); err != nil {
		if n > 0 || committed(err) {
			return nil, rotationMayBeWritten{fmt.Errorf("the rotation's record may be in the registry %s; the gateway did not switch, and is to be stopped and the registry settled: %w", w.path, err)}
		}
		return nil, err
	}
	w.signing.switchTo(to)
	return to, nil
}

// errRotationOnKind is SIGHUP on the PostgreSQL kind, where several
// instances may serve one database: a rotation there is every instance
// stopped, the registry rotated, and every instance started under the next
// key; a coordinated rotation across instances while they serve is #537.
var errRotationOnKind = errors.New("a rotation while serving is not made on the PostgreSQL kind: stop every instance, rotate, and start them all under the next key version (ADR-0050); nothing was changed")

// installRotationOnHangup rotates the gateway's key at each SIGHUP until ctx
// ends (rotateOnHangup), saying the outcome on said.
func installRotationOnHangup(ctx context.Context, g *gatewayService, said io.Writer) {
	hangups := make(chan os.Signal, 1)
	signal.Notify(hangups, syscall.SIGHUP)
	go func() {
		defer signal.Stop(hangups)
		for {
			select {
			case <-ctx.Done():
				return
			case <-hangups:
				line, err := g.rotateOnHangup(nowStamp)
				if err != nil {
					fmt.Fprintln(said, "rotate:", err)
					continue
				}
				fmt.Fprintln(said, "rotate:", line)
			}
		}
	}()
}

// rotateOnHangup is the operator's trigger of a rotation while serving
// (ADR-0050, decision 3(a)), on the file kind alone: the configuration read
// again, under its own checks, for signingKeyVersion and signingPublicKey
// only; the key version it names read and checked as at the start; and the
// gateway's key rotated to it (registryWriter.rotateTo), whose walk check
// refuses a key the registry rotated from. A gateway its seed signs for is
// moved to the key service the same way. Anything refused changes nothing.
func (g *gatewayService) rotateOnHangup(stamp func() string) (string, error) {
	if g.kind != nil {
		return "", errRotationOnKind
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
	next, _, err := newKeyServiceSignerPinned(cfg.signingKeyVersion, cfg.signingPublicKey)
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
