package main

// The two signature algorithms (docs/adr/0053-an-ecdsa-p256-signer-at-a-key-services-hsm-protection-level.md):
// Ed25519, every record's since the first release, and ECDSA over P-256 with
// SHA-256, a key service's key version at its HSM protection level alone. A
// record names its algorithm in its alg member, "ES256", exactly when a P-256
// key signs it, inside what is signed; a record without the member is
// Ed25519, byte for byte what it always was. A verifier takes the algorithm
// from the record, never from a key's length, and verifies only under a key
// it was given with that algorithm (verifyByAlgorithm).

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"maps"
	"math/big"
)

const (
	// algEd25519 is Ed25519's alg: the member absent.
	algEd25519 = ""
	// algES256 is ECDSA P-256 SHA-256's alg (RFC 7518 §3.4), its signature
	// r||s, 64 bytes, low-S.
	algES256 = "ES256"
	// p256SignerVersion is the engine configuration version that takes
	// signingKeyAlgorithm (ADR-0053 §6); keyServiceSignerVersion's
	// neighbour, the one to renumber if another version lands first.
	p256SignerVersion = "40"
	// keyServiceAlgorithmP256 is the key service's name of a P-256 key
	// version's algorithm.
	keyServiceAlgorithmP256 = "EC_SIGN_P256_SHA256"
	// p256PublicKeySize is a compressed SEC 1 point's length.
	p256PublicKeySize = 33
	// p256SignatureSize is r||s.
	p256SignatureSize = 64
)

var (
	p256Order     = elliptic.P256().Params().N
	p256HalfOrder = new(big.Int).Rsh(p256Order, 1) // (n - 1)/2, n odd
)

// heldKey is a public key with the algorithm it was given with: by the pin,
// a rotation's nextAlg or previousAlg, a key-history entry's alg, or the
// signer's own. Its length and form are held to that algorithm, and never
// choose it.
type heldKey struct {
	alg string
	key []byte
}

// edKey is an Ed25519 key held as one.
func edKey(key []byte) heldKey { return heldKey{alg: algEd25519, key: key} }

// keyID is the key's key id: the first 32 lowercase hexadecimal characters
// of SHA-256 over its bytes, the 32 of an Ed25519 key or the 33 of a P-256
// point.
func (k heldKey) keyID() string { return keyIDFor(k.key) }

// is reports whether k and o are one key of one algorithm.
func (k heldKey) is(o heldKey) bool { return k.alg == o.alg && bytes.Equal(k.key, o.key) }

// algName is the algorithm's name where an answer names it (/publickey):
// "ES256", or Ed25519's lowercase "ed25519", the value it always had.
func algName(alg string) string {
	if alg == algES256 {
		return algES256
	}
	return "ed25519"
}

// recordAlg is the algorithm a record's member names: Ed25519 where it is
// absent, ES256 where it is the string "ES256", and false for any other
// value, which is refused wherever the member sits (ADR-0053 §1).
func recordAlg(obj *vObject, member string) (string, bool) {
	v, present := obj.get(member)
	if !present {
		return algEd25519, true
	}
	if s, ok := v.(vString); ok && string(s) == algES256 {
		return algES256, true
	}
	return "", false
}

// setAlg sets member to alg on a record a P-256 key signs or names, and
// leaves an Ed25519 record as it was.
func setAlg(obj *vObject, member, alg string) {
	if alg != algEd25519 {
		obj.set(member, vString(alg))
	}
}

// membersWithAlg is an exact-member kind's members, with alg among them
// where obj holds it: what recordAlg then holds to its one value.
func membersWithAlg(members map[string]bool, obj *vObject) map[string]bool {
	if _, present := obj.get("alg"); !present {
		return members
	}
	with := maps.Clone(members)
	with["alg"] = true
	return with
}

// publicKeyHexLen is the length of alg's public key in lowercase hex.
func publicKeyHexLen(alg string) int {
	if alg == algES256 {
		return 2 * p256PublicKeySize
	}
	return 2 * ed25519.PublicKeySize
}

// keySoundFor holds key to alg's key rule: Ed25519's of §8.4
// (publicKeyFault), or a compressed P-256 point that exists (p256PublicKey).
func keySoundFor(alg string, key []byte) bool {
	switch alg {
	case algEd25519:
		return publicKeyFault(key) == keySound
	case algES256:
		_, ok := p256PublicKey(key)
		return ok
	}
	return false
}

// p256PublicKey is the P-256 key a compressed SEC 1 point names: 33 bytes,
// the first 02 or 03, x below p, and x³ − 3x + b a square modulo p. The
// uncompressed form and every other length are refused.
func p256PublicKey(compressed []byte) (*ecdsa.PublicKey, bool) {
	if len(compressed) != p256PublicKeySize || (compressed[0] != 2 && compressed[0] != 3) {
		return nil, false
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), compressed)
	if x == nil {
		return nil, false
	}
	uncompressed := make([]byte, 1+2*32)
	uncompressed[0] = 4
	x.FillBytes(uncompressed[1:33])
	y.FillBytes(uncompressed[33:])
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
	return key, err == nil
}

// compressP256 is the compressed point of an uncompressed one (04 || x ||
// y), or nil where it is not one of P-256.
func compressP256(uncompressed []byte) []byte {
	if len(uncompressed) != 65 || uncompressed[0] != 4 {
		return nil
	}
	if _, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed); err != nil {
		return nil
	}
	compressed := make([]byte, p256PublicKeySize)
	compressed[0] = 2 | uncompressed[64]&1
	copy(compressed[1:], uncompressed[1:33])
	return compressed
}

// verifyByAlgorithm is every signature check of the gateway's records: sig is
// alg's signature of input under key, which holds only where key was given
// with alg, and key and sig are of alg's form, before any library call. A
// key of the other algorithm, or of another length, never reaches it:
// ed25519.Verify panics on a key that is not 32 bytes. An ES256 signature
// is r||s with 1 ≤ r ≤ n − 1 and 1 ≤ s ≤ (n − 1)/2, low-S, verified over
// SHA-256 of input (FIPS 186-5); a DER one and a high-S one do not verify.
func verifyByAlgorithm(alg string, key heldKey, input, sig []byte) bool {
	if key.alg != alg {
		return false
	}
	switch alg {
	case algEd25519:
		return len(key.key) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize && ed25519.Verify(key.key, input, sig)
	case algES256:
		if len(sig) != p256SignatureSize {
			return false
		}
		public, ok := p256PublicKey(key.key)
		if !ok {
			return false
		}
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		if r.Sign() < 1 || r.Cmp(p256Order) >= 0 || s.Sign() < 1 || s.Cmp(p256HalfOrder) > 0 {
			return false
		}
		digest := sha256.Sum256(input)
		return ecdsa.Verify(public, digest[:], r, s)
	}
	return false
}

// p256SignatureOfDER is the key service's DER answer as r||s (ADR-0053 §5):
// one SEQUENCE of two INTEGERs, minimally encoded and positive, nothing
// after it; each 1 ≤ v ≤ n − 1; s above (n − 1)/2 replaced by n − s; each
// left-padded to 32 bytes. false for anything else.
func p256SignatureOfDER(der []byte) ([]byte, bool) {
	var pair struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &pair)
	if err != nil || len(rest) != 0 || pair.R == nil || pair.S == nil {
		return nil, false
	}
	// encoding/asn1 refuses a length or an integer not minimally
	// encoded; a re-encoding equal to the answer leaves no other form
	again, err := asn1.Marshal(pair)
	if err != nil || !bytes.Equal(again, der) {
		return nil, false
	}
	r, s := pair.R, pair.S
	if r.Sign() < 1 || r.Cmp(p256Order) >= 0 || s.Sign() < 1 || s.Cmp(p256Order) >= 0 {
		return nil, false
	}
	if s.Cmp(p256HalfOrder) > 0 {
		s = new(big.Int).Sub(p256Order, s)
	}
	out := make([]byte, p256SignatureSize)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, true
}

// decodeKeyHex is a key of alg's length written in lowercase hex, or nil.
func decodeKeyHex(alg, s string) []byte {
	if !isLowerHexOfLen(s, publicKeyHexLen(alg)) {
		return nil
	}
	key, _ := hex.DecodeString(s)
	return key
}
