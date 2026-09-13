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
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
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

// parseKeySet reads a JSON Web Key Set (RFC 7517) holding the issuer's
// public keys: RSA (RS256), EC P-256 (ES256) and Ed25519 (EdDSA). Every
// key must carry a key id and a use compatible with signing; a key of
// another kind is refused rather than skipped, since a file the engine
// would silently read only part of is a file the operator misreads.
func parseKeySet(data []byte) (map[string]publicKey, error) {
	var set struct {
		Keys []map[string]json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("key set: %v", err)
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("key set: no keys")
	}
	keys := map[string]publicKey{}
	for i, jwk := range set.Keys {
		str := func(name string) string {
			var s string
			json.Unmarshal(jwk[name], &s)
			return s
		}
		kid := str("kid")
		if kid == "" {
			return nil, fmt.Errorf("key set: key %d has no kid", i)
		}
		if _, dup := keys[kid]; dup {
			return nil, fmt.Errorf("key set: kid %q appears twice", kid)
		}
		if use := str("use"); use != "" && use != "sig" {
			return nil, fmt.Errorf("key set: key %q is for %q, not signing", kid, use)
		}
		decode := func(name string) ([]byte, error) {
			s := str(name)
			if s == "" {
				return nil, fmt.Errorf("key set: key %q has no %s", kid, name)
			}
			return base64.RawURLEncoding.DecodeString(s)
		}
		var pk publicKey
		switch kty := str("kty"); kty {
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
			if modulus.BitLen() < 2048 || !exponent.IsInt64() || exponent.Int64() < 3 {
				return nil, fmt.Errorf("key set: key %q is an RSA key of under 2048 bits or an unusable exponent", kid)
			}
			pk = publicKey{alg: "RS256", key: &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}}
		case "EC":
			if crv := str("crv"); crv != "P-256" {
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
			point := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
			if !point.Curve.IsOnCurve(point.X, point.Y) {
				return nil, fmt.Errorf("key set: key %q is not a point on P-256", kid)
			}
			pk = publicKey{alg: "ES256", key: point}
		case "OKP":
			if crv := str("crv"); crv != "Ed25519" {
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
		if alg := str("alg"); alg != "" && alg != pk.alg {
			return nil, fmt.Errorf("key set: key %q says alg %q; its kind is for %s", kid, alg, pk.alg)
		}
		keys[kid] = pk
	}
	return keys, nil
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
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return caller{}, errors.New("token header is not base64url")
	}
	var header struct {
		Alg  string          `json:"alg"`
		Kid  string          `json:"kid"`
		Typ  string          `json:"typ"`
		Crit json.RawMessage `json:"crit"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return caller{}, errors.New("token header is not a JSON object")
	}
	if len(header.Crit) > 0 {
		return caller{}, errors.New("token header names critical extensions this engine does not implement")
	}
	if header.Kid == "" {
		return caller{}, errors.New("token names no key id")
	}
	key, ok := id.keys[header.Kid]
	if !ok {
		return caller{}, fmt.Errorf("token is signed by key %q, which is not in the key file", header.Kid)
	}
	// The algorithm is the key's, never the token's word: a token that
	// says otherwise is refused, and "none" with it.
	if header.Alg != key.alg {
		return caller{}, fmt.Errorf("token says alg %q; key %q is for %s", header.Alg, header.Kid, key.alg)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return caller{}, errors.New("token signature is not base64url")
	}
	signed := []byte(parts[0] + "." + parts[1])
	if err := verifySignature(key, signed, signature); err != nil {
		return caller{}, err
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return caller{}, errors.New("token payload is not base64url")
	}
	var claims struct {
		Issuer    string          `json:"iss"`
		Subject   string          `json:"sub"`
		Audience  json.RawMessage `json:"aud"`
		Expires   json.RawMessage `json:"exp"`
		NotBefore json.RawMessage `json:"nbf"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return caller{}, errors.New("token payload is not a JSON object")
	}
	if claims.Issuer != id.issuer {
		return caller{}, errors.New("token is not from the configured issuer")
	}
	if !audienceNames(claims.Audience, id.audience) {
		return caller{}, errors.New("token does not name this engine as its audience")
	}
	if claims.Subject == "" {
		return caller{}, errors.New("token names no subject")
	}
	if len(claims.Expires) == 0 {
		return caller{}, errors.New("token has no expiry")
	}
	exp, ok := numericDate(claims.Expires)
	if !ok {
		return caller{}, errors.New("token expiry is not an integer")
	}
	if !now.Before(exp.Add(tokenLeeway)) {
		return caller{}, errors.New("token has expired")
	}
	if len(claims.NotBefore) > 0 {
		nbf, ok := numericDate(claims.NotBefore)
		if !ok {
			return caller{}, errors.New("token nbf is not an integer")
		}
		if now.Add(tokenLeeway).Before(nbf) {
			return caller{}, errors.New("token is not yet valid")
		}
	}
	sum := sha256.Sum256([]byte(token))
	return caller{issuer: claims.Issuer, subject: claims.Subject, tokenDigest: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

// numericDate reads a NumericDate claim (RFC 7519 §2): seconds since the
// epoch, as a JSON number; an integer here, since a fraction of a second
// decides nothing.
func numericDate(raw json.RawMessage) (time.Time, bool) {
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return time.Time{}, false
	}
	seconds, err := n.Int64()
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(seconds, 0), true
}

// audienceNames reports whether an aud claim -- a string or an array of
// strings -- names the audience exactly.
func audienceNames(raw json.RawMessage, audience string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one != "" && one == audience
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, a := range many {
			if a == audience {
				return true
			}
		}
	}
	return false
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
