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
	"os"
	"path/filepath"
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
		{"tampered payload", good[:strings.LastIndex(good, ".")-1] + "x" + good[strings.LastIndex(good, "."):], "signature does not verify"},
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
		{"header not base64url", "!!.b.c", "header is not base64url"},
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
		{"not a set", `[]`, "key set:"},
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
