package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A test issuer: one key of each kind, published as a key set, minting
// tokens the way an OpenID provider does.
type testIssuer struct {
	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
	edPub  ed25519.PublicKey
	edPriv ed25519.PrivateKey
}

func newIssuer(t *testing.T) *testIssuer {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testIssuer{rsaKey: rsaKey, ecKey: ecKey, edPub: edPub, edPriv: edPriv}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (i *testIssuer) keySet() []byte {
	set := map[string]any{"keys": []any{
		map[string]any{"kty": "RSA", "kid": "rsa-1", "use": "sig", "alg": "RS256", "n": b64(i.rsaKey.N.Bytes()), "e": b64(big.NewInt(int64(i.rsaKey.E)).Bytes())},
		map[string]any{"kty": "EC", "kid": "ec-1", "crv": "P-256", "x": b64(i.ecKey.X.FillBytes(make([]byte, 32))), "y": b64(i.ecKey.Y.FillBytes(make([]byte, 32)))},
		map[string]any{"kty": "OKP", "kid": "ed-1", "crv": "Ed25519", "x": b64(i.edPub)},
	}}
	data, _ := json.Marshal(set)
	return data
}

// mint signs claims under kid, with the header as given plus alg and kid.
func (i *testIssuer) mint(t *testing.T, kid string, header map[string]any, claims map[string]any) string {
	t.Helper()
	algs := map[string]string{"rsa-1": "RS256", "ec-1": "ES256", "ed-1": "EdDSA"}
	h := map[string]any{"alg": algs[kid], "kid": kid, "typ": "JWT"}
	for k, v := range header {
		h[k] = v
	}
	hb, _ := json.Marshal(h)
	cb, _ := json.Marshal(claims)
	signed := b64(hb) + "." + b64(cb)
	digest := sha256.Sum256([]byte(signed))
	var sig []byte
	switch kid {
	case "rsa-1":
		sig, _ = rsa.SignPKCS1v15(rand.Reader, i.rsaKey, crypto.SHA256, digest[:])
	case "ec-1":
		r, s, _ := ecdsa.Sign(rand.Reader, i.ecKey, digest[:])
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	case "ed-1":
		sig = ed25519.Sign(i.edPriv, []byte(signed))
	}
	return signed + "." + b64(sig)
}

// mintRaw signs a header and a payload written by hand, as text, so a
// token can carry what json.Marshal would never write: a member twice, a
// member by another case, a value of the wrong type.
func (i *testIssuer) mintRaw(t *testing.T, kid, header, payload string) string {
	t.Helper()
	signed := b64([]byte(header)) + "." + b64([]byte(payload))
	digest := sha256.Sum256([]byte(signed))
	var sig []byte
	switch kid {
	case "rsa-1":
		sig, _ = rsa.SignPKCS1v15(rand.Reader, i.rsaKey, crypto.SHA256, digest[:])
	case "ec-1":
		r, s, _ := ecdsa.Sign(rand.Reader, i.ecKey, digest[:])
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	case "ed-1":
		sig = ed25519.Sign(i.edPriv, []byte(signed))
	}
	return signed + "." + b64(sig)
}

// mintSegments signs a header segment and a payload segment spelled as
// given, so a token can be signed over a spelling the engine must refuse.
func (i *testIssuer) mintSegments(t *testing.T, kid, headerSeg, payloadSeg string) string {
	t.Helper()
	signed := headerSeg + "." + payloadSeg
	digest := sha256.Sum256([]byte(signed))
	var sig []byte
	switch kid {
	case "rsa-1":
		sig, _ = rsa.SignPKCS1v15(rand.Reader, i.rsaKey, crypto.SHA256, digest[:])
	case "ec-1":
		r, s, _ := ecdsa.Sign(rand.Reader, i.ecKey, digest[:])
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	case "ed-1":
		sig = ed25519.Sign(i.edPriv, []byte(signed))
	}
	return signed + "." + b64(sig)
}

// dirty is another spelling of a base64url segment that a permissive
// decoder reads as the same bytes: its last character with the bits the
// encoding does not read set otherwise.
func dirty(t *testing.T, seg string) string {
	t.Helper()
	want, _ := base64.RawURLEncoding.DecodeString(seg)
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for _, c := range alphabet {
		candidate := seg[:len(seg)-1] + string(c)
		if candidate == seg {
			continue
		}
		if got, err := base64.RawURLEncoding.DecodeString(candidate); err == nil && string(got) == string(want) {
			return candidate
		}
	}
	t.Fatalf("no other spelling of %q decodes to the same bytes", seg)
	return ""
}

// withDirtyBits is the token with the unused bits of its signature's last
// base64url character set: the same bytes, another spelling.
func withDirtyBits(t *testing.T, token string) string {
	t.Helper()
	dot := strings.LastIndex(token, ".")
	return token[:dot+1] + dirty(t, token[dot+1:])
}

// unevenPayload is a payload whose base64url has unused bits, so that a
// second spelling of it exists.
func unevenPayload(exp string) string {
	payload := `{"iss":"https://login.example","sub":"u","aud":"gateway:acme","exp":` + exp + `}`
	for len(payload)%3 == 0 {
		payload = payload[:len(payload)-1] + `,"pad":"a"}`
	}
	return payload
}

func identityFor(t *testing.T, issuer *testIssuer) identityConfig {
	t.Helper()
	keys, err := parseKeySet(issuer.keySet())
	if err != nil {
		t.Fatal(err)
	}
	return identityConfig{issuer: "https://login.example", audience: "gateway:acme", keys: keys}
}

func goodClaims(now time.Time) map[string]any {
	return map[string]any{"iss": "https://login.example", "sub": "user-7", "aud": "gateway:acme", "exp": now.Add(time.Hour).Unix(), "iat": now.Unix()}
}

func TestVerifyTokenAcceptsEachKeyKind(t *testing.T) {
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	now := time.Now()
	for _, kid := range []string{"rsa-1", "ec-1", "ed-1"} {
		token := issuer.mint(t, kid, nil, goodClaims(now))
		c, err := verifyToken(token, id, now)
		if err != nil {
			t.Fatalf("%s: %v", kid, err)
		}
		if c.issuer != "https://login.example" || c.subject != "user-7" || c.tokenDigest != "sha256:"+hexOf([]byte(token)) {
			t.Fatalf("%s: caller %+v", kid, c)
		}
	}
	// An audience array naming the engine among others is accepted.
	claims := goodClaims(now)
	claims["aud"] = []string{"other", "gateway:acme"}
	if _, err := verifyToken(issuer.mint(t, "ec-1", nil, claims), id, now); err != nil {
		t.Fatalf("audience array: %v", err)
	}
	// Within the leeway on either side.
	claims = goodClaims(now)
	claims["exp"] = now.Add(-10 * time.Second).Unix()
	claims["nbf"] = now.Add(10 * time.Second).Unix()
	if _, err := verifyToken(issuer.mint(t, "ed-1", nil, claims), id, now); err != nil {
		t.Fatalf("leeway: %v", err)
	}
}

func TestVerifyTokenRefusals(t *testing.T) {
	issuer := newIssuer(t)
	other := newIssuer(t)
	id := identityFor(t, issuer)
	now := time.Now()
	with := func(change func(c map[string]any)) map[string]any {
		c := goodClaims(now)
		change(c)
		return c
	}
	good := issuer.mint(t, "rsa-1", nil, goodClaims(now))
	exp := strconv.FormatInt(now.Add(time.Hour).Unix(), 10)
	tamper := func(token string) string {
		dot := strings.LastIndex(token, ".")
		return token[:dot-1] + "x" + token[dot:]
	}
	for _, tc := range []struct {
		name  string
		token string
		want  string
	}{
		{"unknown kid", issuer.mint(t, "rsa-1", map[string]any{"kid": "rsa-9"}, goodClaims(now)), `signed by key "rsa-9", which is not in the key file`},
		{"no kid", issuer.mint(t, "rsa-1", map[string]any{"kid": ""}, goodClaims(now)), "names no key id"},
		{"alg none", issuer.mint(t, "rsa-1", map[string]any{"alg": "none"}, goodClaims(now)), `says alg "none"; key "rsa-1" is for RS256`},
		{"alg of another kind", issuer.mint(t, "rsa-1", map[string]any{"alg": "ES256"}, goodClaims(now)), `says alg "ES256"`},
		{"critical header", issuer.mint(t, "rsa-1", map[string]any{"crit": []string{"b64"}}, goodClaims(now)), "critical extensions"},
		{"another issuer's key", other.mint(t, "rsa-1", nil, goodClaims(now)), "signature does not verify"},
		{"another issuer's EC key", other.mint(t, "ec-1", nil, goodClaims(now)), "signature does not verify"},
		{"another issuer's Ed25519 key", other.mint(t, "ed-1", nil, goodClaims(now)), "signature does not verify"},
		{"tampered payload", tamper(good), "signature does not verify"},
		{"tampered payload under ES256", tamper(issuer.mint(t, "ec-1", nil, goodClaims(now))), "signature does not verify"},
		{"tampered payload under EdDSA", tamper(issuer.mint(t, "ed-1", nil, goodClaims(now))), "signature does not verify"},
		{"signature with its unused bits set", withDirtyBits(t, good), "signature is not canonical base64url"},
		{"payload with its unused bits set", issuer.mintSegments(t, "ec-1", b64([]byte(`{"alg":"ES256","kid":"ec-1"}`)), dirty(t, b64([]byte(unevenPayload(exp))))), "payload is not canonical base64url"},
		{"line break inside the payload", issuer.mintSegments(t, "ec-1", b64([]byte(`{"alg":"ES256","kid":"ec-1"}`)), func() string { s := b64([]byte(unevenPayload(exp))); return s[:10] + "\n" + s[10:] }()), "payload is not canonical base64url"},
		{"line break inside the header", func() string { h := b64([]byte(`{"alg":"ES256","kid":"ec-1"}`)); return issuer.mintSegments(t, "ec-1", h[:5]+"\n"+h[5:], b64([]byte(unevenPayload(exp)))) }(), "header is not canonical base64url"},
		{"padded header", "=" + good, "header is not canonical base64url"},
		{"audience by another case", issuer.mintRaw(t, "ec-1", `{"alg":"ES256","kid":"ec-1"}`, `{"iss":"https://login.example","sub":"u","aud":"other","AUD":"gateway:acme","exp":`+exp+`}`), "does not name this engine"},
		{"subject twice", issuer.mintRaw(t, "ec-1", `{"alg":"ES256","kid":"ec-1"}`, `{"iss":"https://login.example","sub":"alice","sub":null,"aud":"gateway:acme","exp":`+exp+`}`), `duplicate member name "sub"`},
		{"kid twice in the header", issuer.mintRaw(t, "ec-1", `{"alg":"ES256","kid":"rsa-1","kid":"ec-1"}`, `{"iss":"https://login.example","sub":"u","aud":"gateway:acme","exp":`+exp+`}`), `duplicate member name "kid"`},
		{"expiry as a numeric string", issuer.mintRaw(t, "ec-1", `{"alg":"ES256","kid":"ec-1"}`, `{"iss":"https://login.example","sub":"u","aud":"gateway:acme","exp":"`+exp+`"}`), "expiry is not an integer"},
		{"expiry as a float", issuer.mintRaw(t, "ec-1", `{"alg":"ES256","kid":"ec-1"}`, `{"iss":"https://login.example","sub":"u","aud":"gateway:acme","exp":`+exp+`.5}`), "token payload is not a JSON object this engine reads"},
		{"not-before beyond the domain", issuer.mintRaw(t, "ec-1", `{"alg":"ES256","kid":"ec-1"}`, `{"iss":"https://login.example","sub":"u","aud":"gateway:acme","exp":`+exp+`,"nbf":9223372036854775807}`), "token payload is not a JSON object this engine reads"},
		{"not-before at the edge of the domain", issuer.mintRaw(t, "ec-1", `{"alg":"ES256","kid":"ec-1"}`, `{"iss":"https://login.example","sub":"u","aud":"gateway:acme","exp":`+exp+`,"nbf":9007199254740991}`), "not yet valid"},
		{"audience array with a null", issuer.mintRaw(t, "ec-1", `{"alg":"ES256","kid":"ec-1"}`, `{"iss":"https://login.example","sub":"u","aud":[null,"gateway:acme"],"exp":`+exp+`}`), "audience is not a string or an array of strings"},
		{"audience as an object", issuer.mintRaw(t, "ec-1", `{"alg":"ES256","kid":"ec-1"}`, `{"iss":"https://login.example","sub":"u","aud":{"gateway:acme":true},"exp":`+exp+`}`), "audience is not a string or an array of strings"},
		{"issuer as a number", issuer.mintRaw(t, "ec-1", `{"alg":"ES256","kid":"ec-1"}`, `{"iss":7,"sub":"u","aud":"gateway:acme","exp":`+exp+`}`), "iss is not a string"},
		{"alg as an array", issuer.mintRaw(t, "ec-1", `{"alg":["ES256"],"kid":"ec-1"}`, `{"iss":"https://login.example","sub":"u","aud":"gateway:acme","exp":`+exp+`}`), "alg is not a string"},
		{"invalid UTF-8 in the payload", issuer.mintRaw(t, "ec-1", `{"alg":"ES256","kid":"ec-1"}`, "{\"iss\":\"https://login.example\",\"sub\":\"u\xff\",\"aud\":\"gateway:acme\",\"exp\":"+exp+"}"), "token payload is not a JSON object this engine reads"},
		{"wrong issuer", issuer.mint(t, "rsa-1", nil, with(func(c map[string]any) { c["iss"] = "https://evil.example" })), "not from the configured issuer"},
		{"wrong audience", issuer.mint(t, "rsa-1", nil, with(func(c map[string]any) { c["aud"] = "gateway:other" })), "does not name this engine"},
		{"audience array without it", issuer.mint(t, "rsa-1", nil, with(func(c map[string]any) { c["aud"] = []string{"a", "b"} })), "does not name this engine"},
		{"no audience", issuer.mint(t, "rsa-1", nil, with(func(c map[string]any) { delete(c, "aud") })), "does not name this engine"},
		{"no subject", issuer.mint(t, "rsa-1", nil, with(func(c map[string]any) { c["sub"] = "" })), "names no subject"},
		{"no expiry", issuer.mint(t, "rsa-1", nil, with(func(c map[string]any) { delete(c, "exp") })), "has no expiry"},
		{"expired", issuer.mint(t, "rsa-1", nil, with(func(c map[string]any) { c["exp"] = now.Add(-time.Minute).Unix() })), "has expired"},
		{"not yet valid", issuer.mint(t, "rsa-1", nil, with(func(c map[string]any) { c["nbf"] = now.Add(time.Minute).Unix() })), "not yet valid"},
		{"expiry not an integer", issuer.mint(t, "rsa-1", nil, with(func(c map[string]any) { c["exp"] = "soon" })), "expiry is not an integer"},
		{"two parts", "a.b", "not three dot-separated parts"},
		{"header not base64url", "!!.b.c", "header is not canonical base64url"},
		{"header not an object", b64([]byte("[]")) + ".b.c", "header is not a JSON object"},
		{"too long", strings.Repeat("a", maxTokenBytes+1), "longer than a token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verifyToken(tc.token, id, now)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
			// A refusal never repeats the token.
			if err != nil && len(tc.token) > 40 && strings.Contains(err.Error(), tc.token[:40]) {
				t.Fatalf("the refusal repeats the token: %v", err)
			}
		})
	}
}

func TestParseKeySetRefusals(t *testing.T) {
	issuer := newIssuer(t)
	rsaN, rsaE := b64(issuer.rsaKey.N.Bytes()), b64(big.NewInt(int64(issuer.rsaKey.E)).Bytes())
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	for _, tc := range []struct{ name, set, want string }{
		{"no keys", `{"keys":[]}`, "no keys"},
		{"not a set", `[]`, "key set is not a JSON object"},
		{"no kid", `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + b64(issuer.edPub) + `"}]}`, "has no kid"},
		{"kid twice", `{"keys":[{"kty":"OKP","kid":"k","crv":"Ed25519","x":"` + b64(issuer.edPub) + `"},{"kty":"OKP","kid":"k","crv":"Ed25519","x":"` + b64(issuer.edPub) + `"}]}`, `kid "k" appears twice`},
		{"for encryption", `{"keys":[{"kty":"RSA","kid":"r","use":"enc","n":"` + rsaN + `","e":"` + rsaE + `"}]}`, `is for "enc", not signing`},
		{"small RSA", `{"keys":[{"kty":"RSA","kid":"r","n":"` + b64(small.N.Bytes()) + `","e":"` + rsaE + `"}]}`, "under 2048 bits"},
		{"RSA without n", `{"keys":[{"kty":"RSA","kid":"r","e":"` + rsaE + `"}]}`, "has no n"},
		{"EC on another curve", `{"keys":[{"kty":"EC","kid":"e","crv":"P-384","x":"AA","y":"AA"}]}`, "only P-256 is read"},
		{"EC off the curve", `{"keys":[{"kty":"EC","kid":"e","crv":"P-256","x":"` + b64(make([]byte, 32)) + `","y":"` + b64(make([]byte, 32)) + `"}]}`, "not a point on P-256"},
		{"OKP on another curve", `{"keys":[{"kty":"OKP","kid":"o","crv":"X25519","x":"` + b64(issuer.edPub) + `"}]}`, "only Ed25519 is read"},
		{"OKP wrong size", `{"keys":[{"kty":"OKP","kid":"o","crv":"Ed25519","x":"AA"}]}`, "not an Ed25519 public key"},
		{"unknown kty", `{"keys":[{"kty":"oct","kid":"s","k":"AA"}]}`, `has kty "oct"`},
		{"alg not the kind's", `{"keys":[{"kty":"OKP","kid":"o","alg":"RS256","crv":"Ed25519","x":"` + b64(issuer.edPub) + `"}]}`, `says alg "RS256"; its kind is for EdDSA`},
		{"key operations without verify", `{"keys":[{"kty":"OKP","kid":"o","key_ops":["encrypt"],"crv":"Ed25519","x":"` + b64(issuer.edPub) + `"}]}`, `is not for verifying (key_ops ["encrypt"])`},
		{"key operations not strings", `{"keys":[{"kty":"OKP","kid":"o","key_ops":[1],"crv":"Ed25519","x":"` + b64(issuer.edPub) + `"}]}`, "key_ops is not a string or an array of strings"},
		{"use as a number", `{"keys":[{"kty":"OKP","kid":"o","use":1,"crv":"Ed25519","x":"` + b64(issuer.edPub) + `"}]}`, "use is not a string"},
		{"alg as an array", `{"keys":[{"kty":"OKP","kid":"o","alg":["EdDSA"],"crv":"Ed25519","x":"` + b64(issuer.edPub) + `"}]}`, "alg is not a string"},
		{"kid twice in one key", `{"keys":[{"kty":"OKP","kid":"o","kid":"p","crv":"Ed25519","x":"` + b64(issuer.edPub) + `"}]}`, `duplicate member name "kid"`},
		{"keys not an array", `{"keys":{}}`, "keys is not an array"},
		{"a key not an object", `{"keys":[1]}`, "key 0 is not an object"},
		{"even RSA exponent", `{"keys":[{"kty":"RSA","kid":"r","n":"` + rsaN + `","e":"BA"}]}`, "exponent that is even or outside"},
		{"RSA exponent beyond 2^31-1", `{"keys":[{"kty":"RSA","kid":"r","n":"` + rsaN + `","e":"` + b64([]byte{1, 0, 0, 0, 3}) + `"}]}`, "exponent that is even or outside"},
		{"EC coordinate of 31 bytes", `{"keys":[{"kty":"EC","kid":"e","crv":"P-256","x":"` + b64(issuer.ecKey.X.FillBytes(make([]byte, 32))[1:]) + `","y":"` + b64(issuer.ecKey.Y.FillBytes(make([]byte, 32))) + `"}]}`, "coordinate that is not 32 bytes"},
		{"padded base64 in a key", `{"keys":[{"kty":"OKP","kid":"o","crv":"Ed25519","x":"` + b64(issuer.edPub) + `="}]}`, "x is not base64url"},
		{"key material with its unused bits set", `{"keys":[{"kty":"OKP","kid":"o","crv":"Ed25519","x":"` + dirty(t, b64(issuer.edPub)) + `"}]}`, "x is not base64url"},
		{"line break inside key material", `{"keys":[{"kty":"OKP","kid":"o","crv":"Ed25519","x":"` + b64(issuer.edPub)[:10] + `\n` + b64(issuer.edPub)[10:] + `"}]}`, "x is not base64url"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseKeySet([]byte(tc.set)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
	if keys, err := parseKeySet(issuer.keySet()); err != nil || len(keys) != 3 {
		t.Fatalf("the issuer's set reads: %v %d", err, len(keys))
	}
	if keys, err := parseKeySet([]byte(`{"keys":[{"kty":"OKP","kid":"o","use":"sig","key_ops":["verify","sign"],"crv":"Ed25519","x":"` + b64(issuer.edPub) + `","x5c":["ignored"]}]}`)); err != nil || len(keys) != 1 {
		t.Fatalf("key operations that include verify, and members not read, are allowed: %v", err)
	}
}

// The identity a configuration names is what the service holds requests
// to, through the same path serve takes: the configuration loaded, the
// keys read at start, the options built, the service built.
func TestConfiguredIdentityHoldsTheServiceThroughStart(t *testing.T) {
	t.Setenv(envSourceHelper, "1")
	issuer := newIssuer(t)
	keys := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(keys, issuer.keySet(), 0o600); err != nil {
		t.Fatal(err)
	}
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	cfg, _, err := load(t, engineJSON(t, catalog, `,"identity":{"issuer":"https://login.example","audience":"gateway:acme","keys":"`+abs(t, keys)+`"}`, platformJSON(t, "warehouse", "postgres@"+digestOf(postgresBinding), "engine-warehouse", ``)))
	if err != nil {
		t.Fatal(err)
	}
	identity, err := loadIdentity(cfg.identity)
	if err != nil {
		t.Fatal(err)
	}
	// The test source stands in for the derived ones; the identity is
	// what is under test.
	sources := map[string]sourceSpec{"screening": {argv: []string{os.Args[0]}, env: helperEnv}}
	service, err := buildService(cfg.store, testSeed, cfg.authority, cfg.registry, engineServeOptions(cfg, sources, identity))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(service.handler())
	defer server.Close()
	body := `{"session":"cfg-who-1","source":"screening","arguments":{"q":"x"}}`
	if code, out := post(t, server, "/acquire", body); code != http.StatusUnauthorized {
		t.Fatalf("without a token, through the configuration: %d %v", code, out)
	}
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/acquire", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	token := issuer.mint(t, "ed-1", nil, goodClaims(time.Now()))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	who, _ := out["receipt"].(map[string]any)["caller"].(map[string]any)
	if resp.StatusCode != http.StatusOK || who["subject"] != "user-7" || who["tokenDigest"] != "sha256:"+hexOf([]byte(token)) {
		t.Fatalf("with a token, the receipt names the caller: %d %v", resp.StatusCode, out)
	}
}

func TestBearerToken(t *testing.T) {
	for header, want := range map[string]string{
		"Bearer abc.def.ghi": "abc.def.ghi",
		"bearer abc":         "abc",
		"Bearer   abc  ":     "abc",
		"Basic abc":          "",
		"abc":                "",
		"":                   "",
		"Bearer":             "",
		"Bearer ":            "",
	} {
		if got := bearerToken(header); got != want {
			t.Errorf("%q: got %q, want %q", header, got, want)
		}
	}
}

// With an identity configured, a request that acquires, seals or verifies
// carries a token the issuer signed and the receipt names the caller it
// proved; the anchors a verifier fetches stay open; without an identity
// every receipt carries caller null.
func TestIdentityDecidesWhoMayCall(t *testing.T) {
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	service, server := testService(t)
	service.identity = &id
	now := time.Now()
	token := issuer.mint(t, "ec-1", nil, goodClaims(now))
	request := func(path, body, authorization string) (int, map[string]any, http.Header) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out, resp.Header
	}
	acquire := `{"session":"who-1","source":"screening","arguments":{"q":"x"}}`
	for _, tc := range []struct{ name, authorization, want string }{
		{"no token", "", "a bearer token from the configured issuer is required"},
		{"not bearer", "Basic abc", "a bearer token from the configured issuer is required"},
		{"another issuer", "Bearer " + newIssuer(t).mint(t, "ec-1", nil, goodClaims(now)), "signature does not verify"},
		{"expired", "Bearer " + issuer.mint(t, "ec-1", nil, map[string]any{"iss": "https://login.example", "sub": "u", "aud": "gateway:acme", "exp": now.Add(-time.Hour).Unix()}), "has expired"},
	} {
		code, body, header := request("/acquire", acquire, tc.authorization)
		if code != http.StatusUnauthorized || !strings.Contains(fmt.Sprint(body["error"]), tc.want) || header.Get("WWW-Authenticate") != "Bearer" {
			t.Fatalf("%s: %d %v %q", tc.name, code, body, header.Get("WWW-Authenticate"))
		}
		if tc.authorization != "" && strings.Contains(body["error"].(string), tc.authorization[7:]) {
			t.Fatalf("%s: the refusal repeats the token", tc.name)
		}
	}
	if service.started.Load() != 0 {
		t.Fatal("no source ran for a request that was not admitted")
	}
	code, body, _ := request("/acquire", acquire, "Bearer "+token)
	if code != http.StatusOK {
		t.Fatalf("admitted: %d %v", code, body)
	}
	receipt := body["receipt"].(map[string]any)
	who, _ := receipt["caller"].(map[string]any)
	if who["issuer"] != "https://login.example" || who["subject"] != "user-7" || who["tokenDigest"] != "sha256:"+hexOf([]byte(token)) {
		t.Fatalf("the receipt names the caller the token proved: %v", receipt["caller"])
	}
	if code, body, _ := request("/seal", `{"session":"who-1"}`, ""); code != http.StatusUnauthorized {
		t.Fatalf("seal without a token: %d %v", code, body)
	}
	if code, body, _ := request("/seal", `{"session":"who-1"}`, "Bearer "+token); code != http.StatusOK {
		t.Fatalf("seal: %d %v", code, body)
	}
	if code, _, _ := request("/verify", ``, ""); code != http.StatusUnauthorized {
		t.Fatalf("verify without a token: %d", code)
	}
	if code, body, _ := request("/verify", ``, "Bearer "+token); code != http.StatusOK || body["ok"] != true {
		t.Fatalf("verify with the token, and the store with a caller verifies: %d %v", code, body)
	}
	for _, open := range []string{"/publickey", "/registry"} {
		resp, err := http.Get(server.URL + open)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s is an anchor a verifier fetches without a token: %d", open, resp.StatusCode)
		}
	}
	// The store verifies under the command-line verifier too, caller and all.
	report, err := verifyWithRegistry(service.storeRoot, service.regPath, service.authority, service.publicKey)
	if err != nil || !report.OK {
		t.Fatalf("the store must verify: %v %v", err, report)
	}
	// Without an identity, nothing is asked and nothing is recorded.
	plain, plainServer := testService(t)
	if plain.identity != nil {
		t.Fatal("no identity by default")
	}
	code, body = post(t, plainServer, "/acquire", `{"session":"anon-1","source":"screening","arguments":{"q":"x"}}`)
	if code != http.StatusOK || body["receipt"].(map[string]any)["caller"] != nil {
		t.Fatalf("caller null without an identity: %d %v", code, body)
	}
}

func TestIdentityIsConfiguredAndItsKeysReadAtStart(t *testing.T) {
	issuer := newIssuer(t)
	keys := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(keys, issuer.keySet(), 0o600); err != nil {
		t.Fatal(err)
	}
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	cfg, _, err := load(t, engineJSON(t, catalog, `,"identity":{"issuer":"https://login.example","audience":"gateway:acme","keys":"`+abs(t, keys)+`"}`, platformJSON(t, "warehouse", "postgres@"+digestOf(postgresBinding), "engine-warehouse", ``)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.identity == nil || cfg.identity.issuer != "https://login.example" || cfg.identity.audience != "gateway:acme" || cfg.identity.keys != keys {
		t.Fatalf("identity as written: %+v", cfg.identity)
	}
	id, err := loadIdentity(cfg.identity)
	if err != nil || id == nil || len(id.keys) != 3 || id.issuer != cfg.identity.issuer || id.audience != cfg.identity.audience {
		t.Fatalf("the keys are read at start: %v %+v", err, id)
	}
	if id, err := loadIdentity(nil); err != nil || id != nil {
		t.Fatalf("no identity: %v %v", err, id)
	}
	if err := os.WriteFile(keys, []byte(`{"keys":[{"kty":"oct","kid":"s"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentity(cfg.identity); err == nil || !strings.Contains(err.Error(), `identity.keys: key set: key "s" has kty "oct"`) {
		t.Fatalf("a key file the engine cannot read is refused at start: %v", err)
	}
	cfg.identity.keys = filepath.Join(t.TempDir(), "absent.json")
	if _, err := loadIdentity(cfg.identity); err == nil || !strings.Contains(err.Error(), "identity.keys:") {
		t.Fatalf("an absent key file is refused at start: %v", err)
	}
}
