package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"math/big"
)

// A write held to a record a trusted runtime key signed
// (docs/adr/0012-hold-a-write-to-a-signed-record.md). The runtime signs each
// record of a chained audit trail in a sidecar beside the trail,
// signatures.jsonl (runtime ADR-0047 §2b). A decision policy that sets
// requireSignedRecord holds a write to a record one of its keys signed
// there, so a writer of the decision-record directory who holds none of the
// keys cannot write a record the policy admits. Nothing here is the
// runtime's code: it is the rule the runtime's guide writes down ("Record
// signatures, exactly"), read for one record without its trail, with one
// choice of this engine's own -- a key is trusted because the policy names
// it, and a key-rotation line is never followed.

// sidecarName is the sidecar's name, exactly, in the directory of the trail
// whose records it signs.
const sidecarName = "signatures.jsonl"

// maxSidecarLine is the longest sidecar line read, in bytes, its newline not
// counted; a longer line is unreadable.
const maxSidecarLine = 4096

// recordSignaturePrefix is the domain of what a record signature signs.
const recordSignaturePrefix = "judgment-pack-runtime/record-signature/1:"

// maxSidecarSequence is the largest sequence a sidecar line names, 2^53-2.
const maxSidecarSequence = maxSafeInteger - 1

// recordSigner is one runtime key a policy trusts: the public key, and the
// keyId a sidecar line names it by -- the first 32 hex characters of the
// SHA-256 of its 32 bytes, as this engine's own keyId is.
type recordSigner struct {
	keyID string
	key   ed25519.PublicKey
}

// recordSignature is one readable record-signature line of a sidecar.
type recordSignature struct {
	keyID     string
	trail     string
	sequence  int64
	record    string
	signature []byte
}

var recordSignatureMembers = map[string]bool{"kind": true, "sidecarVersion": true, "keyId": true, "trail": true, "sequence": true, "record": true, "signature": true}

// sidecarEvidence is what the walk of the decision-record directory found
// for one record: whether a sidecar lies beside any file the record was
// found in, and the readable record-signature lines of those sidecars that
// name the record's digest.
type sidecarEvidence struct {
	beside bool
	lines  []recordSignature
}

// recordSignaturesFor reads a sidecar's bytes by the runtime's rule and
// returns its readable record-signature lines naming the record digest. A
// line is the bytes before a newline, so the piece after the last newline --
// a write that did not finish -- is none; a line longer than maxSidecarLine
// is unreadable; and a readable one is one JSON object, read by the
// canonical parser whatever its whitespace, with exactly the seven members
// of a record signature, each once and of its form. Any other line, a key
// rotation among them, signs nothing here and fails nothing.
func recordSignaturesFor(data []byte, record string) []recordSignature {
	var lines []recordSignature
	for {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			return lines
		}
		line := data[:i]
		data = data[i+1:]
		if len(line) > maxSidecarLine {
			continue
		}
		if s, ok := readRecordSignature(line); ok && s.record == record {
			lines = append(lines, s)
		}
	}
}

// readRecordSignature reads one sidecar line as a record signature, or
// reports that it is not one.
func readRecordSignature(line []byte) (recordSignature, bool) {
	v, err := parseJSON(line)
	if err != nil {
		return recordSignature{}, false
	}
	obj, ok := v.(*vObject)
	if !ok || exactlyMembers(obj, recordSignatureMembers, "sidecar line") != nil {
		return recordSignature{}, false
	}
	var s recordSignature
	kind, _ := memberString(obj, "kind")
	version, _ := memberString(obj, "sidecarVersion")
	s.keyID, _ = memberString(obj, "keyId")
	s.trail, _ = memberString(obj, "trail")
	s.record, _ = memberString(obj, "record")
	signature, _ := memberString(obj, "signature")
	sequenceV, _ := obj.get("sequence")
	sequence, isInteger := sequenceV.(vInt)
	if kind != "record-signature" || version != "1" || !isLowerHexOfLen(s.keyID, 32) || !isLowerHexOfLen(s.trail, 32) ||
		!isInteger || sequence < 1 || int64(sequence) > maxSidecarSequence || !isDigest(s.record) || !isLowerHexOfLen(signature, 128) {
		return recordSignature{}, false
	}
	s.sequence = int64(sequence)
	s.signature, _ = hex.DecodeString(signature)
	return s, true
}

// recordSignedBytes is what a record signature signs: the domain prefix,
// then the canonical form of {record, sequence, trail}, which for these
// values -- two ASCII strings and an integer in the safe range -- is their
// RFC 8785 form too.
func recordSignedBytes(trail string, sequence int64, record string) []byte {
	signed := newObject()
	signed.set("record", vString(record))
	signed.set("sequence", vInt(sequence))
	signed.set("trail", vString(trail))
	return append([]byte(recordSignaturePrefix), canon(signed)...)
}

// chainPosition is a record's place in its chained trail: its trail, 32
// lowercase hex, and its sequence, an integer a sidecar line can name -- or
// false for a record no chain numbers, which no signature can name.
func chainPosition(obj *vObject) (string, int64, bool) {
	trail, _ := memberString(obj, "trail")
	sequenceV, _ := obj.get("sequence")
	sequence, isInteger := sequenceV.(vInt)
	if !isLowerHexOfLen(trail, 32) || !isInteger || sequence < 1 || int64(sequence) > maxSidecarSequence {
		return "", 0, false
	}
	return trail, int64(sequence), true
}

// holdToSignature is the executor's step for a policy that sets
// requireSignedRecord (policy-signed): some readable line of a sidecar
// beside the record must sign the record's trail, its sequence and the
// digest of its exact bytes -- the digest step 7 matched, never one of a
// re-encoding -- under its keyId, which must be the keyId of a key the
// policy names, and the signature must verify under that key. A key-rotation
// line hands nothing on: a key signs here because the policy names it. The
// refusal says which of the ways it failed, and never a value of the
// record's.
func holdToSignature(record *runtimeRecord, recordDigest string, evidence sidecarEvidence, signers []recordSigner) error {
	trail, sequence, chained := chainPosition(record.obj)
	if !chained {
		return actRefusal{"policy-signed", "the record carries no trail and sequence of a chained trail, so no signature can name it; the tool's decision policy requires a record signed by a key it trusts"}
	}
	if !evidence.beside {
		return actRefusal{"policy-signed", "no " + sidecarName + " lies beside the record, so nothing signs it; the tool's decision policy requires a record signed by a key it trusts"}
	}
	signed := recordSignedBytes(trail, sequence, recordDigest)
	invalid, untrusted := false, false
	for _, line := range evidence.lines {
		if line.trail != trail || line.sequence != sequence || line.record != recordDigest {
			continue
		}
		trusted := false
		for _, signer := range signers {
			if signer.keyID != line.keyID {
				continue
			}
			trusted = true
			if ed25519.Verify(signer.key, signed, line.signature) {
				return nil
			}
		}
		if trusted {
			invalid = true
		} else {
			untrusted = true
		}
	}
	switch {
	case invalid:
		return actRefusal{"policy-signed", "the record's signature under a key the tool's decision policy trusts does not verify"}
	case untrusted:
		return actRefusal{"policy-signed", "the record is signed only by keys the tool's decision policy does not trust"}
	}
	return actRefusal{"policy-signed", "no readable line of the " + sidecarName + " beside the record signs it; the tool's decision policy requires a record signed by a key it trusts"}
}

// The curve of Ed25519 (RFC 8032 §5.1): -x² + y² = 1 + d·x²·y² over the
// field of p = 2²⁵⁵ - 19.
var (
	curveP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	curveD = func() *big.Int {
		d := new(big.Int).ModInverse(big.NewInt(121666), curveP)
		d.Mul(d, big.NewInt(-121665))
		return d.Mod(d, curveP)
	}()
)

// unusableSigningKey is why 32 bytes are no key a policy may trust, or "":
// they encode no point of the curve, so no signature verifies under them;
// or they encode a point whose order divides 8, the curve's cofactor. Under
// such a key a signature can be made without any secret -- this engine's
// verifier, the standard library's, admits one for most messages -- so a
// policy that trusted it would admit a record anyone signed. The encoding
// is read as the verifier reads it: y little-endian, the top bit the sign of
// x, a y of p or more taken modulo p.
func unusableSigningKey(raw []byte) string {
	if len(raw) != ed25519.PublicKeySize {
		return "is not 32 bytes"
	}
	le := make([]byte, len(raw))
	for i, b := range raw {
		le[len(raw)-1-i] = b
	}
	le[0] &= 0x7f
	p := curveP
	y := new(big.Int).SetBytes(le)
	y.Mod(y, p)
	// x² = (y² - 1) / (d·y² + 1)
	yy := new(big.Int).Mul(y, y)
	u := new(big.Int).Sub(yy, big.NewInt(1))
	v := new(big.Int).Mul(curveD, yy)
	v.Add(v, big.NewInt(1))
	xx := new(big.Int).ModInverse(v.Mod(v, p), p)
	xx.Mul(xx, u).Mod(xx, p)
	x, ok := squareRoot(xx)
	if !ok {
		return "is not a point of the Ed25519 curve, so no signature verifies under it"
	}
	// [8]P by three doublings; the identity is (0, 1).
	for range 3 {
		x, y = edwardsAdd(x, y, x, y)
	}
	if x.Sign() == 0 && y.Cmp(big.NewInt(1)) == 0 {
		return "is of small order, under which a signature can be made without any secret"
	}
	return ""
}

// squareRoot is a square root of a modulo p, or false when a is no square
// (RFC 8032 §5.1.3, step 3).
func squareRoot(a *big.Int) (*big.Int, bool) {
	p := curveP
	exp := new(big.Int).Add(p, big.NewInt(3))
	exp.Rsh(exp, 3)
	x := new(big.Int).Exp(a, exp, p)
	check := func(x *big.Int) bool {
		xx := new(big.Int).Mul(x, x)
		return xx.Mod(xx, p).Cmp(a) == 0
	}
	if check(x) {
		return x, true
	}
	// x·√-1, where √-1 = 2^((p-1)/4)
	root := new(big.Int).Sub(p, big.NewInt(1))
	root.Rsh(root, 2)
	root.Exp(big.NewInt(2), root, p)
	x.Mul(x, root).Mod(x, p)
	if check(x) {
		return x, true
	}
	return nil, false
}

// edwardsAdd is the curve's complete addition law (RFC 8032 §5.1.4, in
// affine coordinates): its denominators are never zero, since d is not a
// square.
func edwardsAdd(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	p := curveP
	t := new(big.Int).Mul(x1, x2)
	t.Mul(t, y1).Mul(t, y2).Mul(t, curveD).Mod(t, p)
	xNum := new(big.Int).Mul(x1, y2)
	xNum.Add(xNum, new(big.Int).Mul(y1, x2))
	yNum := new(big.Int).Mul(y1, y2)
	yNum.Add(yNum, new(big.Int).Mul(x1, x2))
	xDen := new(big.Int).Add(big.NewInt(1), t)
	yDen := new(big.Int).Sub(big.NewInt(1), t)
	x := xNum.Mul(xNum, new(big.Int).ModInverse(xDen.Mod(xDen, p), p))
	y := yNum.Mul(yNum, new(big.Int).ModInverse(yDen.Mod(yDen, p), p))
	return x.Mod(x, p), y.Mod(y, p)
}
