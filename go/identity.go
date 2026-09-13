package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"
)

// Identity is who may call the engine: tokens from one issuer, naming this
// engine as their audience, signed by a key in a file the operator holds.
// The engine verifies with the standard library and fetches nothing on the
// request path: a token signed by a key not in the file is refused, and
// refreshing the file is the operator's job (docs/design/engine-config.md).
type identityConfig struct {
	issuer   string
	audience string
	keys     map[string]publicKey // by key id
}

// publicKey is one verification key from the issuer's key set, with the
// algorithm it is for.
type publicKey struct {
	alg string
	key crypto.PublicKey
}

// caller is what a verified token proves at the engine's boundary: who
// asked, from which issuer, and the digest of the token as presented -- the
// receipt's `caller` (SPEC.md §1.2a). The token itself is never stored.
type caller struct {
	issuer      string
	subject     string
	tokenDigest string
}

// tokenLeeway is how far a token's validity window is stretched, for
// clocks that disagree by a little.
const tokenLeeway = 30 * time.Second

// maxTokenBytes bounds a token: a JWT is a few hundred bytes to a few
// kilobytes; anything more is not one.
const maxTokenBytes = 8192

// Every JSON text an identity reads -- the key set, a token's header and
// its claims -- is read by the same parser as everything the gateway
// signs (canon.go): member names matched exactly, a duplicate member or
// invalid UTF-8 refused, numbers integers within the safe range. Go's
// encoding/json would match "AUD" to aud, keep the first of two subjects,
// and read a numeric string as a number; none of that may decide who a
// caller is.

// member is the named member of an object as a string: "" and false when
// absent, an error when present and not a string.
func member(obj *vObject, name string) (string, bool, error) {
	v, present := obj.get(name)
	if !present {
		return "", false, nil
	}
	str, ok := v.(vString)
	if !ok {
		return "", true, fmt.Errorf("%s is not a string", name)
	}
	return string(str), true, nil
}

// integerMember is the named member as an integer: an error when present
// and not one. The parser bounds it to the safe range, so no date made
// of it overflows.
func integerMember(obj *vObject, name string) (int64, bool, error) {
	v, present := obj.get(name)
	if !present {
		return 0, false, nil
	}
	n, ok := v.(vInt)
	if !ok {
		return 0, true, fmt.Errorf("%s is not an integer", name)
	}
	return int64(n), true, nil
}

// stringsMember is the named member as an array of strings, or as one
// string where the member may be either (aud); any other shape, or an
// element that is not a string, is an error.
func stringsMember(obj *vObject, name string, oneAllowed bool) ([]string, bool, error) {
	v, present := obj.get(name)
	if !present {
		return nil, false, nil
	}
	switch v := v.(type) {
	case vString:
		if oneAllowed {
			return []string{string(v)}, true, nil
		}
	case vArray:
		out := make([]string, 0, len(v))
		for _, item := range v {
			str, ok := item.(vString)
			if !ok {
				return nil, true, fmt.Errorf("%s is not a string or an array of strings", name)
			}
			out = append(out, string(str))
		}
		return out, true, nil
	}
	return nil, true, fmt.Errorf("%s is not a string or an array of strings", name)
}

// objectOf reads a JSON text as an object, refusing anything else and
// anything the parser refuses.
func objectOf(data []byte, what string) (*vObject, error) {
	v, err := parseJSON(data)
	if err != nil {
		return nil, fmt.Errorf("%s is not a JSON object this engine reads: %v", what, err)
	}
	obj, ok := v.(*vObject)
	if !ok {
		return nil, fmt.Errorf("%s is not a JSON object", what)
	}
	return obj, nil
}

// maxRSAExponent bounds a public exponent to what the verifier takes: a
// value that fits an int on every build, and an odd one.
const maxRSAExponent = 1<<31 - 1

// parseKeySet reads a JSON Web Key Set (RFC 7517) holding the issuer's
// public keys: RSA (RS256), EC P-256 (ES256) and Ed25519 (EdDSA). Every
// key must carry a key id; a use other than signing, or key operations
// that do not include verifying, refuse the key; a key of another kind is
// refused rather than skipped, since a file the engine would silently
// read only part of is a file the operator misreads.
func parseKeySet(data []byte) (map[string]publicKey, error) {
	set, err := objectOf(data, "key set")
	if err != nil {
		return nil, err
	}
	keysValue, present := set.get("keys")
	if !present {
		return nil, errors.New("key set: no keys")
	}
	list, ok := keysValue.(vArray)
	if !ok {
		return nil, errors.New("key set: keys is not an array")
	}
	if len(list) == 0 {
		return nil, errors.New("key set: no keys")
	}
	keys := map[string]publicKey{}
	for i, item := range list {
		jwk, ok := item.(*vObject)
		if !ok {
			return nil, fmt.Errorf("key set: key %d is not an object", i)
		}
		kid, _, err := member(jwk, "kid")
		if err != nil {
			return nil, fmt.Errorf("key set: key %d: %v", i, err)
		}
		if kid == "" {
			return nil, fmt.Errorf("key set: key %d has no kid", i)
		}
		if _, dup := keys[kid]; dup {
			return nil, fmt.Errorf("key set: kid %q appears twice", kid)
		}
		use, _, err := member(jwk, "use")
		if err != nil {
			return nil, fmt.Errorf("key set: key %q: %v", kid, err)
		}
		if use != "" && use != "sig" {
			return nil, fmt.Errorf("key set: key %q is for %q, not signing", kid, use)
		}
		ops, present, err := stringsMember(jwk, "key_ops", false)
		if err != nil {
			return nil, fmt.Errorf("key set: key %q: %v", kid, err)
		}
		if present && !slices.Contains(ops, "verify") {
			return nil, fmt.Errorf("key set: key %q is not for verifying (key_ops %q)", kid, ops)
		}
		decode := func(name string) ([]byte, error) {
			s, _, err := member(jwk, name)
			if err != nil {
				return nil, fmt.Errorf("key set: key %q: %v", kid, err)
			}
			if s == "" {
				return nil, fmt.Errorf("key set: key %q has no %s", kid, name)
			}
			b, err := base64.RawURLEncoding.Strict().DecodeString(s)
			if err != nil || base64.RawURLEncoding.EncodeToString(b) != s {
				return nil, fmt.Errorf("key set: key %q: %s is not base64url", kid, name)
			}
			return b, nil
		}
		kty, _, err := member(jwk, "kty")
		if err != nil {
			return nil, fmt.Errorf("key set: key %q: %v", kid, err)
		}
		crv, _, err := member(jwk, "crv")
		if err != nil {
			return nil, fmt.Errorf("key set: key %q: %v", kid, err)
		}
		var pk publicKey
		switch kty {
		case "RSA":
			n, err := decode("n")
			if err != nil {
				return nil, err
			}
			e, err := decode("e")
			if err != nil {
				return nil, err
			}
			modulus := new(big.Int).SetBytes(n)
			exponent := new(big.Int).SetBytes(e)
			if modulus.BitLen() < 2048 {
				return nil, fmt.Errorf("key set: key %q is an RSA key of under 2048 bits", kid)
			}
			if !exponent.IsInt64() || exponent.Int64() < 3 || exponent.Int64() > maxRSAExponent || exponent.Bit(0) == 0 {
				return nil, fmt.Errorf("key set: key %q has an RSA exponent that is even or outside 3 to 2^31-1", kid)
			}
			pk = publicKey{alg: "RS256", key: &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}}
		case "EC":
			if crv != "P-256" {
				return nil, fmt.Errorf("key set: key %q is on curve %q; only P-256 is read", kid, crv)
			}
			x, err := decode("x")
			if err != nil {
				return nil, err
			}
			y, err := decode("y")
			if err != nil {
				return nil, err
			}
			if len(x) != 32 || len(y) != 32 {
				return nil, fmt.Errorf("key set: key %q has a coordinate that is not 32 bytes", kid)
			}
			point := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
			if !point.Curve.IsOnCurve(point.X, point.Y) {
				return nil, fmt.Errorf("key set: key %q is not a point on P-256", kid)
			}
			pk = publicKey{alg: "ES256", key: point}
		case "OKP":
			if crv != "Ed25519" {
				return nil, fmt.Errorf("key set: key %q is on curve %q; only Ed25519 is read", kid, crv)
			}
			x, err := decode("x")
			if err != nil {
				return nil, err
			}
			if len(x) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("key set: key %q is not an Ed25519 public key", kid)
			}
			pk = publicKey{alg: "EdDSA", key: ed25519.PublicKey(x)}
		default:
			return nil, fmt.Errorf("key set: key %q has kty %q; RSA, EC and OKP are read", kid, kty)
		}
		alg, _, err := member(jwk, "alg")
		if err != nil {
			return nil, fmt.Errorf("key set: key %q: %v", kid, err)
		}
		if alg != "" && alg != pk.alg {
			return nil, fmt.Errorf("key set: key %q says alg %q; its kind is for %s", kid, alg, pk.alg)
		}
		keys[kid] = pk
	}
	return keys, nil
}

// segment decodes one part of a compact token, which must be exactly the
// unpadded base64url of its bytes (RFC 7515 §5.2): no padding, no line
// break, no bit set that the encoding does not read, so that no second
// spelling of a token verifies and digests differently.
func segment(what, s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, fmt.Errorf("token %s is not canonical base64url", what)
	}
	return b, nil
}

// verifyToken holds a bearer token to the identity configuration and
// returns the caller it proves: a JWT (RFC 7519) in compact form, signed
// with a key the file holds under the header's kid, for the configured
// issuer and audience, within its validity window. Every refusal is one
// reason, and none of them repeats the token.
func verifyToken(token string, id identityConfig, now time.Time) (caller, error) {
	if len(token) > maxTokenBytes {
		return caller{}, errors.New("token is longer than a token")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return caller{}, errors.New("token is not three dot-separated parts")
	}
	headerBytes, err := segment("header", parts[0])
	if err != nil {
		return caller{}, err
	}
	header, err := objectOf(headerBytes, "token header")
	if err != nil {
		return caller{}, err
	}
	if _, present := header.get("crit"); present {
		return caller{}, errors.New("token header names critical extensions this engine does not implement")
	}
	alg, _, err := member(header, "alg")
	if err != nil {
		return caller{}, fmt.Errorf("token header: %v", err)
	}
	kid, _, err := member(header, "kid")
	if err != nil {
		return caller{}, fmt.Errorf("token header: %v", err)
	}
	if kid == "" {
		return caller{}, errors.New("token names no key id")
	}
	key, ok := id.keys[kid]
	if !ok {
		return caller{}, fmt.Errorf("token is signed by key %q, which is not in the key file", kid)
	}
	// The algorithm is the key's, never the token's word: a token that
	// says otherwise is refused, and "none" with it.
	if alg != key.alg {
		return caller{}, fmt.Errorf("token says alg %q; key %q is for %s", alg, kid, key.alg)
	}
	signature, err := segment("signature", parts[2])
	if err != nil {
		return caller{}, err
	}
	signed := []byte(parts[0] + "." + parts[1])
	if err := verifySignature(key, signed, signature); err != nil {
		return caller{}, err
	}
	payloadBytes, err := segment("payload", parts[1])
	if err != nil {
		return caller{}, err
	}
	claims, err := objectOf(payloadBytes, "token payload")
	if err != nil {
		return caller{}, err
	}
	issuer, _, err := member(claims, "iss")
	if err != nil {
		return caller{}, fmt.Errorf("token %v", err)
	}
	if issuer != id.issuer {
		return caller{}, errors.New("token is not from the configured issuer")
	}
	audiences, _, err := stringsMember(claims, "aud", true)
	if err != nil {
		return caller{}, fmt.Errorf("token audience is not a string or an array of strings")
	}
	if !slices.Contains(audiences, id.audience) {
		return caller{}, errors.New("token does not name this engine as its audience")
	}
	subject, _, err := member(claims, "sub")
	if err != nil {
		return caller{}, fmt.Errorf("token %v", err)
	}
	if subject == "" {
		return caller{}, errors.New("token names no subject")
	}
	expires, present, err := integerMember(claims, "exp")
	if err != nil {
		return caller{}, errors.New("token expiry is not an integer")
	}
	if !present {
		return caller{}, errors.New("token has no expiry")
	}
	if !now.Before(time.Unix(expires, 0).Add(tokenLeeway)) {
		return caller{}, errors.New("token has expired")
	}
	notBefore, present, err := integerMember(claims, "nbf")
	if err != nil {
		return caller{}, errors.New("token nbf is not an integer")
	}
	if present && now.Add(tokenLeeway).Before(time.Unix(notBefore, 0)) {
		return caller{}, errors.New("token is not yet valid")
	}
	sum := sha256.Sum256([]byte(token))
	return caller{issuer: issuer, subject: subject, tokenDigest: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

// verifySignature checks a JWS signature with the key's algorithm.
func verifySignature(key publicKey, signed, signature []byte) error {
	digest := sha256.Sum256(signed)
	switch k := key.key.(type) {
	case *rsa.PublicKey:
		if rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], signature) != nil {
			return errors.New("token signature does not verify")
		}
	case *ecdsa.PublicKey:
		// A JWS ECDSA signature is r || s, each 32 bytes for P-256.
		if len(signature) != 64 {
			return errors.New("token signature does not verify")
		}
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		if !ecdsa.Verify(k, digest[:], r, s) {
			return errors.New("token signature does not verify")
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(k, signed, signature) {
			return errors.New("token signature does not verify")
		}
	default:
		return errors.New("token signature does not verify")
	}
	return nil
}

// bearerToken is the token of an Authorization header, or "" when the
// header carries none.
func bearerToken(authorization string) string {
	scheme, token, ok := strings.Cut(authorization, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}
