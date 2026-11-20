package main

// The gateway's signer (docs/adr/0050-an-external-signer-in-a-key-service.md):
// what signs while the gateway serves -- a receipt (store.go), a seal of every
// form (store.go) and a descriptor statement (descriptor_provenance.go) -- and
// the two statements of a rotation (rotationRecordSigned). Two kinds: the seed
// file, signing as it always has, byte for byte; and a key version in a key
// service, asked to sign over its API (key_service_signer.go), whose private
// key the gateway never holds. Both are Ed25519 (SPEC.md §1.2): receipts,
// seals and verifiers are the same whichever kind signed. A key version may
// instead be ECDSA P-256 at the service's HSM protection level (ADR-0053),
// whose records carry alg: "ES256".

import (
	"crypto/ed25519"
	"errors"
	"sync/atomic"
)

// signer signs with one key: Ed25519, or a key service's P-256 key version
// (ADR-0053).
type signer interface {
	// publicKey is the key every signature of this signer verifies under:
	// 32 bytes of Ed25519, or a P-256 key's 33-byte compressed point.
	publicKey() []byte
	// algorithm is the key's alg: algEd25519 or algES256.
	algorithm() string
	// sign answers the Ed25519 signature of message, or why there is none.
	sign(message []byte) ([]byte, error)
}

// seedSigner is the seed file's key: ed25519.Sign over the seed's private
// key, deterministic, the bytes every earlier release signed.
type seedSigner struct{ private ed25519.PrivateKey }

func newSeedSigner(seed []byte) seedSigner {
	return seedSigner{private: ed25519.NewKeyFromSeed(seed)}
}

func (s seedSigner) publicKey() []byte {
	return s.private.Public().(ed25519.PublicKey)
}

// algorithm is the seed's, always Ed25519 (ADR-0053 §10).
func (s seedSigner) algorithm() string { return algEd25519 }

func (s seedSigner) sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.private, message), nil
}

// errSignatureNotVerified is a signature that does not verify under the
// signer's key: what a key service answered for another key, another
// message or nothing at all.
var errSignatureNotVerified = errors.New("the signer answered a signature that does not verify under the gateway's key; nothing was signed")

// signingFailure is a signature not made: nothing that needed it is minted
// or written. Its sentence is fixed by the cause (key_service_signer.go).
type signingFailure struct{ cause error }

func (f signingFailure) Error() string { return f.cause.Error() }
func (f signingFailure) Unwrap() error { return f.cause }

// signingKey is one signer with its key and key id, fixed for its life:
// whatever is signed through one carries its key id and its signature, and
// no other's.
type signingKey struct {
	signer signer
	public []byte
	alg    string
	keyID  string
}

// held is the key with its algorithm.
func (k *signingKey) held() heldKey { return heldKey{alg: k.alg, key: k.public} }

func newSigningKey(s signer) *signingKey {
	public := s.publicKey()
	return &signingKey{signer: s, public: public, alg: s.algorithm(), keyID: keyIDFor(public)}
}

// signVerified signs message and holds the signature to the key before
// anything is written with it: a signature of another length, or one that
// does not verify under the key by its algorithm -- for ES256 a high-S one
// among them -- is errSignatureNotVerified.
func (k *signingKey) signVerified(message []byte) ([]byte, error) {
	signature, err := k.signer.sign(message)
	if err != nil {
		return nil, signingFailure{err}
	}
	if !verifyByAlgorithm(k.alg, k.held(), message, signature) {
		return nil, signingFailure{errSignatureNotVerified}
	}
	return signature, nil
}

// signerHolder is the gateway's current key, switched whole (registryWriter.
// rotateTo): a receipt or a seal reads it once and is signed, and names its
// key id, under what it read.
type signerHolder struct{ current atomic.Pointer[signingKey] }

func newSignerHolder(s signer) *signerHolder {
	h := &signerHolder{}
	h.current.Store(newSigningKey(s))
	return h
}

func (h *signerHolder) key() *signingKey { return h.current.Load() }

func (h *signerHolder) switchTo(k *signingKey) { h.current.Store(k) }

// afterReceiptKeyChosen, where a test sets it, runs once a receipt's key is
// read and its keyId set, before it is signed.
var afterReceiptKeyChosen func()

// ownKey is the gateway's key now: its signer's, which a rotation while
// serving switches whole (registryWriter.rotateTo); the key at start for a
// service made without a store.
func (g *gatewayService) ownKey() ed25519.PublicKey {
	if g.store != nil && g.store.signing != nil {
		return g.store.signing.key().public
	}
	return g.publicKey
}

// ownHeld is ownKey with its algorithm.
func (g *gatewayService) ownHeld() heldKey {
	if g.store != nil && g.store.signing != nil {
		return g.store.signing.key().held()
	}
	return edKey(g.publicKey)
}

// ownKeyID is ownKey's key id.
func (g *gatewayService) ownKeyID() string {
	if g.store != nil && g.store.signing != nil {
		return g.store.signing.key().keyID
	}
	return g.keyID
}
