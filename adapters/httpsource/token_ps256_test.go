package httpsource

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"testing/cryptotest"
	"time"
)

// PS256 for the certificate form's client assertion (gateway #513, ADR-0027,
// amendment #513).

// mainRS256 and mainRS256Thumbprint are the two assertions the signer made
// before PS256 existed (main at c3ceee1), under cryptotest.SetGlobalRandom
// seed 513: an RSA-2048 key generated first, then the assertion of client-1
// to https://login.example/token at 2026-01-01T00:00:00Z, then the same with
// x5t#S256 of 32 zero bytes. RS256 is deterministic, so the same key, claims
// and clock give these bytes, and the test also rebuilds each one by hand
// below rather than trusting them alone.
const (
	mainRS256 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJjbGllbnQtMSIsInN1YiI6ImNsaWVudC0xIiwiYXVkIjoiaHR" +
		"0cHM6Ly9sb2dpbi5leGFtcGxlL3Rva2VuIiwianRpIjoiNGVmMDYxMDhlMDE2OTE5NjMyMTAzMTNlZDY5MmVhMjgiLCJpYXQ" +
		"iOjE3NjcyMjU2MDAsIm5iZiI6MTc2NzIyNTYwMCwiZXhwIjoxNzY3MjI1OTAwfQ.zLp-fefLWbo7xh3uA4EUIoSMnH7V3ZJe" +
		"Avjyt0QcQ-Fj5smZ_E0_JCaTHo3j2_Q_DgCp-ee5TN28ienvQ3KBuheX6-oVk894cNSaVqZHs49QDEGTxRfuFYXw7mK8NOWL" +
		"Kby1QhCbMThwcu8wBg6qafm10qeaH50NXYmOGzP6Wgm9_10CchEBDq-uv884EZovyRzAzrf1o7nYhlwQlVNV2CAXAWSZHB3g" +
		"7v94aAcbPm1vhaQS3-GipPSYdlzXnOUxzM_7glGgKkTZzlOXzcfnEbzWUcDDbL6wQ2CBPWnJJ3tyTUhuNiXF5-IRAfzFWJec" +
		"ec6ku_ZX0nSwRNgQQRZqEg"
	mainRS256Thumbprint = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIng1dCNTMjU2IjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB" +
		"QUFBQUFBQUFBQSJ9.eyJpc3MiOiJjbGllbnQtMSIsInN1YiI6ImNsaWVudC0xIiwiYXVkIjoiaHR0cHM6Ly9sb2dpbi5leGF" +
		"tcGxlL3Rva2VuIiwianRpIjoiZTM3YTY0YTk5ZDE1ZmEzY2QyNzdlZWZjZjYwMjczMDIiLCJpYXQiOjE3NjcyMjU2MDAsIm5" +
		"iZiI6MTc2NzIyNTYwMCwiZXhwIjoxNzY3MjI1OTAwfQ.qa4zaBeh3wO5dtZC1K8fPLbsU0cr07DUSlxHPyZKkEwOZYZSy_pa" +
		"ZVo6MibMRNun-JHGpx272nBDGP5a2Y22aqyBrUvhhzBq7TT-ee0WW_QuX2MkR1SdsqekPCaAyDfXXl6jY1r_8-WIlYHoUVkb" +
		"tejJ4VZTeW9V74LjNcgoVOJyOZSgYfOxPkkNp4WC3neC2GnI14xUqHwjtNIJD6IkzzKjl-W7b_TPGKkFT4z1moUA2jT165Nq" +
		"Aj4rAJgjz0m3RytF-luPJL0lqP3QKxWj6pn46G7OSDeiZ2feUK4XYOo7QIel4Cg6mpxEt8D4AAOuneEw0eIGyWD0cfPLqn4R" +
		"DQ"
)

// fixedRS256Pair is the two assertions that seed's key signs, in the
// order main's capture made them, with the algorithm asked as given.
func fixedRS256Pair(t *testing.T, algorithm string) (*rsa.PrivateKey, [2]string) {
	t.Helper()
	cryptotest.SetGlobalRandom(t, 513)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	step := &TokenStep{Endpoint: "https://login.example/token", ClientID: "client-1", KeyMember: "CLIENT_KEY", Algorithm: algorithm}
	signer, err := readTokenCredential(step, map[string]string{"CLIENT_KEY": pkcs8PEM(t, key)})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1767225600, 0)
	var out [2]string
	if out[0], err = signer.assertion(step, now); err != nil {
		t.Fatal(err)
	}
	step.X5TS256 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if out[1], err = signer.assertion(step, now); err != nil {
		t.Fatal(err)
	}
	return key, out
}

// An RSA key's RS256 assertion is, byte for byte, what it was before PS256
// existed: with no algorithm asked and with RS256 asked, the same key,
// claims and clock give main's bytes. Each is first rebuilt here from the
// header and claims written by hand, with the jti read from the assertion
// itself (32 hex characters, the one random member), and PKCS #1 v1.5 over
// them, so the hand check holds whatever key the seed gives; the capture is
// compared after it.
func TestTokenStepRS256IsByteForByteAsBefore(t *testing.T) {
	for _, algorithm := range []string{"", "RS256"} {
		t.Run("asked "+algorithm, func(t *testing.T) {
			key, got := fixedRS256Pair(t, algorithm)
			for i, c := range []struct{ header, claims string }{
				{`{"alg":"RS256","typ":"JWT"}`, `{"iss":"client-1","sub":"client-1","aud":"https://login.example/token","jti":"%s","iat":1767225600,"nbf":1767225600,"exp":1767225900}`},
				{`{"alg":"RS256","typ":"JWT","x5t#S256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`, `{"iss":"client-1","sub":"client-1","aud":"https://login.example/token","jti":"%s","iat":1767225600,"nbf":1767225600,"exp":1767225900}`},
			} {
				claims := fmt.Sprintf(c.claims, jtiOf(t, got[i]))
				input := base64.RawURLEncoding.EncodeToString([]byte(c.header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(claims))
				digest := sha256.Sum256([]byte(input))
				signature, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, digest[:])
				if err != nil {
					t.Fatal(err)
				}
				if want := input + "." + base64.RawURLEncoding.EncodeToString(signature); got[i] != want {
					t.Fatalf("assertion %d is not the one written by hand:\n%s\n%s", i, got[i], want)
				}
			}
			if got[0] != mainRS256 || got[1] != mainRS256Thumbprint {
				t.Fatalf("the RS256 assertion changed:\n%s\n%s", got[0], got[1])
			}
		})
	}
}

// jtiOf reads an assertion's jti, which must be 32 lowercase hex characters.
func jtiOf(t *testing.T, assertion string) string {
	t.Helper()
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %s", assertion)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if len(claims.JTI) != 32 || strings.Trim(claims.JTI, "0123456789abcdef") != "" {
		t.Fatalf("jti %q is not 32 hex characters", claims.JTI)
	}
	return claims.JTI
}

// pssSaltOf is an EMSA-PSS decoding (RFC 8017 sections 8.1.2 and 9.1.2)
// written for this test and not Go's: the signature raised to e mod n, the
// trailer 0xbc, MGF1-SHA-256 unmasking, the zeros and the 0x01 that end the
// padding, and H checked against SHA-256 of eight zeros, the digest and the
// salt. It answers the salt, so its length is read, not assumed.
func pssSaltOf(t *testing.T, public *rsa.PublicKey, digest, signature []byte) []byte {
	t.Helper()
	k := (public.N.BitLen() + 7) / 8
	if len(signature) != k {
		t.Fatalf("a signature of %d bytes for a %d-byte modulus", len(signature), k)
	}
	m := new(big.Int).Exp(new(big.Int).SetBytes(signature), big.NewInt(int64(public.E)), public.N)
	emBits := public.N.BitLen() - 1
	emLen := (emBits + 7) / 8
	em := m.FillBytes(make([]byte, emLen))
	if em[emLen-1] != 0xbc {
		t.Fatal("EMSA-PSS: no 0xbc trailer")
	}
	const hLen = sha256.Size
	maskedDB, h := em[:emLen-hLen-1], em[emLen-hLen-1:emLen-1]
	mask := make([]byte, 0, len(maskedDB)+hLen)
	for counter := uint32(0); len(mask) < len(maskedDB); counter++ {
		block := sha256.New()
		block.Write(h)
		binary.Write(block, binary.BigEndian, counter)
		mask = block.Sum(mask)
	}
	db := make([]byte, len(maskedDB))
	subtle.XORBytes(db, maskedDB, mask[:len(maskedDB)])
	db[0] &= 0xff >> (8*emLen - emBits)
	one := bytes.IndexByte(db, 0x01)
	if one < 0 || !bytes.Equal(db[:one], make([]byte, one)) {
		t.Fatal("EMSA-PSS: the padding is not zeros and 0x01")
	}
	salt := db[one+1:]
	check := sha256.New()
	check.Write(make([]byte, 8))
	check.Write(digest)
	check.Write(salt)
	if !bytes.Equal(check.Sum(nil), h) {
		t.Fatal("EMSA-PSS: H does not match the digest and salt")
	}
	return salt
}

// With PS256 asked beside an RSA key the assertion is RSASSA-PSS with
// SHA-256, MGF1 SHA-256 and a 32-byte salt: its header is exactly alg
// PS256, typ JWT and the thumbprint given, its claims RFC 7523's, and its
// signature holds under rsa.VerifyPSS with the salt length fixed at 32 and
// under this test's own decoding, which reads a salt of 32 bytes. Two
// assertions of the same claims differ in their bytes, as PSS does, and
// both verify.
func TestTokenStepSignsPS256WhenAsked(t *testing.T) {
	rsaKey, _ := testKeys(t)
	thumb := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	step := &TokenStep{Endpoint: "https://login.example/token", ClientID: "client-7", KeyMember: "CLIENT_KEY", Algorithm: "PS256", X5TS256: thumb}
	if _, err := holdTokenStep(step); err != nil {
		t.Fatal(err)
	}
	signer, err := readTokenCredential(step, map[string]string{"CLIENT_KEY": pkcs8PEM(t, rsaKey)})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1767225600, 0)
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		assertion, err := signer.assertion(step, now)
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(assertion, ".")
		if len(parts) != 3 {
			t.Fatalf("not a compact JWS: %q", assertion)
		}
		header, _ := base64.RawURLEncoding.DecodeString(parts[0])
		if string(header) != `{"alg":"PS256","typ":"JWT","x5t#S256":"`+thumb+`"}` {
			t.Fatalf("the header: %s", header)
		}
		raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims map[string]any
		if err := json.Unmarshal(raw, &claims); err != nil || claims["iss"] != "client-7" || claims["sub"] != "client-7" ||
			claims["aud"] != "https://login.example/token" || claims["iat"] != float64(now.Unix()) || claims["exp"] != float64(now.Add(5*time.Minute).Unix()) {
			t.Fatalf("the claims: %s", raw)
		}
		signature, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPSS(&rsaKey.PublicKey, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}); err != nil {
			t.Fatalf("PS256 with a 32-byte salt does not verify: %v", err)
		}
		if rsa.VerifyPKCS1v15(&rsaKey.PublicKey, crypto.SHA256, digest[:], signature) == nil {
			t.Fatal("a PS256 assertion verifies as RS256")
		}
		if salt := pssSaltOf(t, &rsaKey.PublicKey, digest[:], signature); len(salt) != 32 {
			t.Fatalf("a salt of %d bytes", len(salt))
		}
		seen[parts[2]] = true
	}
	if len(seen) != 2 {
		t.Fatal("two PSS signatures are the same bytes")
	}
}

// The verifier above tells a 32-byte salt from another: a PSS signature of
// the same digest with the longest salt the key allows, or with none, does
// not verify under SaltLength 32, and the decoding reads its own length.
func TestPS256VerifierRefusesAnotherSaltLength(t *testing.T) {
	rsaKey, _ := testKeys(t)
	digest := sha256.Sum256([]byte("e30.e30"))
	for _, salt := range []int{rsa.PSSSaltLengthAuto, 0, 20, 64} {
		signature, err := rsa.SignPSS(rand.Reader, rsaKey, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: salt, Hash: crypto.SHA256})
		if err != nil {
			t.Fatal(err)
		}
		if rsa.VerifyPSS(&rsaKey.PublicKey, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}) == nil {
			t.Fatalf("a salt of length %d verifies as 32", salt)
		}
		if got := len(pssSaltOf(t, &rsaKey.PublicKey, digest[:], signature)); got == 32 {
			t.Fatalf("the decoding reads 32 for a salt of length %d", salt)
		}
	}
}

// End to end, the token endpoint takes a PS256 assertion it verifies with a
// 32-byte salt, and the source is sent the token it issued.
func TestTokenStepPS256ReachesTheEndpoint(t *testing.T) {
	rsaKey, _ := testKeys(t)
	stub := newTokenStub(t, &rsaKey.PublicKey)
	stub.pss = true
	cfg := stub.tokenConfig(t, pkcs8PEM(t, rsaKey))
	cfg.Token.Algorithm = "PS256"
	out, err := Acquire(context.Background(), cfg, Request{Path: "/read", Method: "GET"})
	if err != nil || !strings.Contains(string(out), `"ok":true`) {
		t.Fatalf("acquire: %v %s", err, out)
	}
	stub.check(t)
	if stub.tokenHits.Load() != 1 || stub.sourceHits.Load() != 1 {
		t.Fatalf("%d token requests, %d source requests", stub.tokenHits.Load(), stub.sourceHits.Load())
	}
}

// An algorithm is asked of an RSA key alone: beside a P-256 key, RS256 and
// PS256 are each refused as no credential in a sentence naming the one
// asked, and no token request is sent; a P-384 key's and an Ed25519
// key's refusals name the one asked too. An unknown algorithm, or one beside
// a federated token, is refused before any credential is read, and the
// refusal repeats no value; and ES256 a P-256 key still signs when none is
// asked.
func TestTokenStepRefusesAnAlgorithmTheKeyDoesNotSign(t *testing.T) {
	_, ecKey := testKeys(t)
	for _, algorithm := range []string{"PS256", "RS256"} {
		stub := newTokenStub(t, &ecKey.PublicKey)
		cfg := stub.tokenConfig(t, pkcs8PEM(t, ecKey))
		cfg.Token.Algorithm = algorithm
		_, err := Acquire(context.Background(), cfg, Request{Path: "/read", Method: "GET"})
		want := "the token step's key is EC P-256, which signs ES256; --assertion-alg=" + algorithm + " is for an RSA key"
		if failureKind(err) != TokenNoCredential || err.Error() != want {
			t.Fatalf("%s beside a P-256 key: %v", algorithm, err)
		}
		if stub.tokenHits.Load() != 0 || stub.sourceHits.Load() != 0 {
			t.Fatalf("%s beside a P-256 key sent a request", algorithm)
		}
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, algorithm := range []string{"PS256", "RS256", ""} {
		_, err := readTokenCredential(&TokenStep{KeyMember: "K", Algorithm: algorithm}, map[string]string{"K": pkcs8PEM(t, p384)})
		want := "the token step's EC key is not on P-256"
		if algorithm != "" {
			want += "; --assertion-alg=" + algorithm + " is for an RSA key"
		}
		if failureKind(err) != TokenNoCredential || err.Error() != want {
			t.Fatalf("%q beside a P-384 key: %v", algorithm, err)
		}
	}
	for _, algorithm := range []string{"PS256", "RS256", ""} {
		_, err := readTokenCredential(&TokenStep{KeyMember: "K", Algorithm: algorithm}, map[string]string{"K": pkcs8PEM(t, edKey)})
		want := "the token step's key is neither RSA nor EC P-256"
		if algorithm != "" {
			want += "; --assertion-alg=" + algorithm + " is for an RSA key"
		}
		if failureKind(err) != TokenNoCredential || err.Error() != want {
			t.Fatalf("%q beside an Ed25519 key: %v", algorithm, err)
		}
	}
	signer, err := readTokenCredential(&TokenStep{KeyMember: "K"}, map[string]string{"K": pkcs8PEM(t, ecKey)})
	if err != nil || signer.alg != "ES256" {
		t.Fatalf("a P-256 key with no algorithm asked: %v", err)
	}
	if _, ok := signer.key.(*ecdsa.PrivateKey); !ok {
		t.Fatal("not the EC key")
	}
	base := TokenStep{Endpoint: "https://login.example/token", ClientID: "client-7", KeyMember: "CLIENT_KEY"}
	for _, value := range []string{"ES256", "ps256", "PS384", "RS512", "none", " PS256"} {
		step := base
		step.Algorithm = value
		if _, err := holdTokenStep(&step); err == nil || err.Error() != "--assertion-alg is RS256 or PS256" {
			t.Fatalf("%q: %v", value, err)
		}
	}
	federated := TokenStep{Endpoint: base.Endpoint, ClientID: base.ClientID, FederatedTokenFile: "/run/federated", Algorithm: "PS256"}
	if _, err := holdTokenStep(&federated); err == nil || err.Error() != "--assertion-alg is the algorithm of an assertion this adapter signs, with --assertion-key" {
		t.Fatalf("beside a federated token: %v", err)
	}
}

// The seal is bound to the algorithm asked, and a step that asks none is
// bound as it was before --assertion-alg existed.
func TestSealBindsTheAlgorithmAsked(t *testing.T) {
	step := TokenStep{Endpoint: "https://login.example/token", ClientID: "c", KeyMember: "K", Scope: "s"}
	cfg := Config{Endpoint: "https://records.example", Token: &step}
	const before = `["adapter-http sealed token 1","https://records.example","https://login.example/token","c","K","","","","","s"]`
	if got := string(sealAAD(cfg)); got != before {
		t.Fatalf("no algorithm asked: %s", got)
	}
	for _, algorithm := range []string{"RS256", "PS256"} {
		step.Algorithm = algorithm
		if got, want := string(sealAAD(cfg)), strings.TrimSuffix(before, "]")+`,"assertion-alg","`+algorithm+`"]`; got != want {
			t.Fatalf("%s: %s", algorithm, got)
		}
	}
}
