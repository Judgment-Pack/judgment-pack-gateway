package httpsource

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// pkcs8PEM is key as the PEM text a credentials member holds.
func pkcs8PEM(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

var (
	testKeysOnce sync.Once
	testRSA      *rsa.PrivateKey
	testEC       *ecdsa.PrivateKey
)

func testKeys(t *testing.T) (*rsa.PrivateKey, *ecdsa.PrivateKey) {
	testKeysOnce.Do(func() {
		var err error
		if testRSA, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if testEC, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			panic(err)
		}
	})
	return testRSA, testEC
}

// tokenStub is a stand-in token endpoint and a stand-in source behind it.
// The endpoint holds every assertion to its form under the public key it
// was given (or to the federated token it expects), and answers what
// answer says; the source admits only the token the endpoint issued.
type tokenStub struct {
	t          *testing.T
	token      *httptest.Server
	source     *httptest.Server
	public     crypto.PublicKey
	federated  func() string
	clientID   string
	thumbprint [2]string // header member and value expected, or empty
	answer     func(w http.ResponseWriter)
	issued     string
	tokenHits  atomic.Int64
	sourceHits atomic.Int64
	mu         sync.Mutex
	jtis       map[string]bool
	assertions []string
	problems   []string
}

func newTokenStub(t *testing.T, public crypto.PublicKey) *tokenStub {
	s := &tokenStub{t: t, public: public, clientID: "client-7", issued: "issued-access-token-0123456789", jtis: map[string]bool{}}
	s.answer = func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		io.WriteString(w, `{"access_token":"`+s.issued+`","token_type":"Bearer","expires_in":3600,"ext_expires_in":3600}`)
	}
	s.token = httptest.NewServer(http.HandlerFunc(s.serveToken))
	s.source = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.sourceHits.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+s.issued {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, "refused: "+r.Header.Get("Authorization"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(func() { s.token.Close(); s.source.Close() })
	return s
}

func (s *tokenStub) problem(format string) {
	s.mu.Lock()
	s.problems = append(s.problems, format)
	s.mu.Unlock()
}

func (s *tokenStub) serveToken(w http.ResponseWriter, r *http.Request) {
	s.tokenHits.Add(1)
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.ParseForm() != nil {
		s.problem("not a form POST")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f := r.PostForm
	if f.Get("grant_type") != "client_credentials" || f.Get("client_id") != s.clientID ||
		f.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		s.problem("grant, client or assertion type")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	assertion := f.Get("client_assertion")
	s.mu.Lock()
	s.assertions = append(s.assertions, assertion)
	s.mu.Unlock()
	if s.federated != nil {
		if assertion != s.federated() {
			s.problem("the federated token is not the one in the file")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	} else if problem := s.checkAssertion(assertion, s.token.URL+"/token"); problem != "" {
		s.problem(problem)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	s.answer(w)
}

// checkAssertion holds a signed assertion to RFC 7523's form under the
// stub's public key.
func (s *tokenStub) checkAssertion(assertion, audience string) string {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return "not a compact JWS"
	}
	var header map[string]any
	var claims map[string]any
	for i, into := range []*map[string]any{&header, &claims} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil || json.Unmarshal(raw, into) != nil {
			return "a part is not base64url JSON"
		}
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "signature not base64url"
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch key := s.public.(type) {
	case *rsa.PublicKey:
		if header["alg"] != "RS256" || rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
			return "RS256 signature"
		}
	case *ecdsa.PublicKey:
		if header["alg"] != "ES256" || len(signature) != 64 ||
			!ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
			return "ES256 signature"
		}
	}
	if header["typ"] != "JWT" {
		return "typ"
	}
	want := map[string]bool{"alg": true, "typ": true}
	if s.thumbprint[0] != "" {
		want[s.thumbprint[0]] = true
		if header[s.thumbprint[0]] != s.thumbprint[1] {
			return "thumbprint"
		}
	}
	if len(header) != len(want) {
		return "header members"
	}
	if claims["iss"] != s.clientID || claims["sub"] != s.clientID || claims["aud"] != audience {
		return "iss, sub or aud"
	}
	jti, _ := claims["jti"].(string)
	now := float64(time.Now().Unix())
	iat, _ := claims["iat"].(float64)
	nbf, _ := claims["nbf"].(float64)
	exp, _ := claims["exp"].(float64)
	if jti == "" || iat > now+5 || iat < now-60 || nbf > now+5 || exp <= now || exp-iat > 600 {
		return "jti, iat, nbf or exp"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.jtis[jti] {
		return "jti repeated"
	}
	s.jtis[jti] = true
	return ""
}

func (s *tokenStub) check(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.problems) > 0 {
		t.Fatalf("the token endpoint found: %v", s.problems)
	}
}

// tokenConfig is a configuration of the stub's source with a token step
// whose key is member CLIENT_KEY of a credentials file holding pemText.
func (s *tokenStub) tokenConfig(t *testing.T, pemText string) Config {
	t.Helper()
	creds := filepath.Join(t.TempDir(), "credentials.json")
	data, _ := json.Marshal(map[string]string{"CLIENT_KEY": pemText, "UNUSED": "never-sent-value"})
	if err := os.WriteFile(creds, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return Config{
		Endpoint: s.source.URL, Credentials: creds, Paths: []string{"/read"}, Methods: []string{"GET"}, MaxOutput: 1 << 20,
		Token: &TokenStep{Endpoint: s.token.URL + "/token", ClientID: s.clientID, KeyMember: "CLIENT_KEY"},
	}
}

func failureKind(err error) TokenFailureKind {
	var f *TokenFailure
	if errors.As(err, &f) {
		return f.Kind
	}
	return 0
}

// The assertion is RFC 7523's, held so by the endpoint under the public
// key: RS256 for an RSA key and ES256 for a P-256 key, the algorithm the
// key's type gives; iss and sub the client, aud the token endpoint, a jti
// never repeated, a lifetime of minutes, and the thumbprint configured in
// the header. The source is sent the token the endpoint issued, as the
// bearer, and nothing of the credentials file.
func TestTokenStepSignsTheAssertionTheEndpointChecks(t *testing.T) {
	rsaKey, ecKey := testKeys(t)
	thumb := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	thumb1 := base64.RawURLEncoding.EncodeToString(make([]byte, 20))
	for _, c := range []struct {
		name       string
		private    any
		public     crypto.PublicKey
		thumbprint [2]string
	}{
		{"RS256", rsaKey, &rsaKey.PublicKey, [2]string{}},
		{"ES256", ecKey, &ecKey.PublicKey, [2]string{}},
		{"RS256 x5t#S256", rsaKey, &rsaKey.PublicKey, [2]string{"x5t#S256", thumb}},
		{"ES256 x5t", ecKey, &ecKey.PublicKey, [2]string{"x5t", thumb1}},
	} {
		t.Run(c.name, func(t *testing.T) {
			stub := newTokenStub(t, c.public)
			stub.thumbprint = c.thumbprint
			cfg := stub.tokenConfig(t, pkcs8PEM(t, c.private))
			switch c.thumbprint[0] {
			case "x5t":
				cfg.Token.X5T = c.thumbprint[1]
			case "x5t#S256":
				cfg.Token.X5TS256 = c.thumbprint[1]
			}
			for i := 0; i < 2; i++ {
				out, err := Acquire(context.Background(), cfg, Request{Path: "/read", Method: "GET"})
				if err != nil {
					t.Fatalf("acquire: %v", err)
				}
				if !strings.Contains(string(out), `"ok":true`) {
					t.Fatalf("the source's answer is not the result: %s", out)
				}
			}
			stub.check(t)
			if stub.tokenHits.Load() != 2 || stub.sourceHits.Load() != 2 {
				t.Fatalf("without a sealed token each acquisition obtains one: %d token requests, %d source requests", stub.tokenHits.Load(), stub.sourceHits.Load())
			}
		})
	}
}

// A federated token is read from its file at each token request and sent
// as the assertion as read: a renewed file is the next request's.
func TestTokenStepReadsTheFederatedTokenAtEachRequest(t *testing.T) {
	stub := newTokenStub(t, nil)
	file := filepath.Join(t.TempDir(), "federated")
	current := "eyJhbGciOiJSUzI1NiJ9.first.federated-signature"
	stub.federated = func() string { return current }
	write := func() {
		if err := os.WriteFile(file, []byte(current+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	cfg := Config{Endpoint: stub.source.URL, Paths: []string{"/read"}, Methods: []string{"GET"}, MaxOutput: 1 << 20,
		Token: &TokenStep{Endpoint: stub.token.URL + "/token", ClientID: stub.clientID, FederatedTokenFile: file, Scope: "api://records/.default"}}
	if _, err := Acquire(context.Background(), cfg, Request{Path: "/read", Method: "GET"}); err != nil {
		t.Fatal(err)
	}
	current = "eyJhbGciOiJSUzI1NiJ9.second.federated-signature"
	write()
	if _, err := Acquire(context.Background(), cfg, Request{Path: "/read", Method: "GET"}); err != nil {
		t.Fatal(err)
	}
	stub.check(t)
	if len(stub.assertions) != 2 || stub.assertions[1] != current {
		t.Fatalf("the renewed federated token was not the second assertion: %d assertions", len(stub.assertions))
	}
}

// The token endpoint is held as the source's endpoint is: https, or http
// on a loopback host; a credential sent in the clear elsewhere is given
// away.
func TestTokenStepEndpointIsHTTPSOrLoopback(t *testing.T) {
	_, ecKey := testKeys(t)
	stub := newTokenStub(t, &ecKey.PublicKey)
	for _, endpoint := range []string{"http://login.example/token", "ftp://login.example/token", "https://user@login.example/token", "https://login.example/token?x=1", ""} {
		cfg := stub.tokenConfig(t, pkcs8PEM(t, ecKey))
		cfg.Token.Endpoint = endpoint
		if _, err := Acquire(context.Background(), cfg, Request{Path: "/read", Method: "GET"}); err == nil || !strings.Contains(err.Error(), "--token-endpoint") {
			t.Fatalf("%q: %v", endpoint, err)
		}
	}
	if stub.tokenHits.Load()+stub.sourceHits.Load() != 0 {
		t.Fatal("a refused endpoint was reached")
	}
}

// What the token endpoint answers is read strictly, and every answer
// refused is TokenRefused, says no body and reaches no source.
func TestTokenStepReadsTheAnswerStrictly(t *testing.T) {
	_, ecKey := testKeys(t)
	elsewhere := atomic.Int64{}
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { elsewhere.Add(1) }))
	defer other.Close()
	json := func(body string) func(w http.ResponseWriter) {
		return func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, body)
		}
	}
	const tok = `"access_token":"issued-access-token-0123456789"`
	for _, c := range []struct {
		name   string
		answer func(w http.ResponseWriter)
	}{
		{"a redirect", func(w http.ResponseWriter) {
			w.Header().Set("Location", other.URL+"/token")
			w.WriteHeader(http.StatusTemporaryRedirect)
		}},
		{"a refusal", func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"error":"invalid_client","error_description":"QUOTED-BODY"}`)
		}},
		{"past 64 KiB", json(`{` + tok + `,"token_type":"Bearer","pad":"` + strings.Repeat("x", 64<<10) + `"}`)},
		{"not JSON's media type", func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, `{`+tok+`,"token_type":"Bearer"}`)
		}},
		{"no access_token", json(`{"token_type":"Bearer","expires_in":60}`)},
		{"access_token not a string", json(`{"access_token":7,"token_type":"Bearer"}`)},
		{"access_token out of form", json(`{"access_token":"a b","token_type":"Bearer"}`)},
		{"token_type mac", json(`{` + tok + `,"token_type":"mac"}`)},
		{"no token_type", json(`{` + tok + `}`)},
		{"expires_in zero", json(`{` + tok + `,"token_type":"Bearer","expires_in":0}`)},
		{"expires_in negative", json(`{` + tok + `,"token_type":"Bearer","expires_in":-5}`)},
		{"expires_in past the bound", json(`{` + tok + `,"token_type":"Bearer","expires_in":86401}`)},
		{"expires_in a string with a sign", json(`{` + tok + `,"token_type":"Bearer","expires_in":"+3600"}`)},
		{"expires_in a string with a space", json(`{` + tok + `,"token_type":"Bearer","expires_in":" 3600"}`)},
		{"expires_in a string with a fraction", json(`{` + tok + `,"token_type":"Bearer","expires_in":"3600.5"}`)},
		{"expires_in an empty string", json(`{` + tok + `,"token_type":"Bearer","expires_in":""}`)},
		{"expires_in a string of zero", json(`{` + tok + `,"token_type":"Bearer","expires_in":"0"}`)},
		{"expires_in a string past the bound", json(`{` + tok + `,"token_type":"Bearer","expires_in":"86401"}`)},
		{"expires_in a string past an int", json(`{` + tok + `,"token_type":"Bearer","expires_in":"99999999999999999999"}`)},
		{"expires_in null", json(`{` + tok + `,"token_type":"Bearer","expires_in":null}`)},
		{"expires_in a fraction", json(`{` + tok + `,"token_type":"Bearer","expires_in":3600.5}`)},
		{"a member twice", json(`{` + tok + `,"token_type":"Bearer",` + tok + `}`)},
	} {
		t.Run(c.name, func(t *testing.T) {
			stub := newTokenStub(t, &ecKey.PublicKey)
			stub.answer = c.answer
			_, err := ObtainSealed(context.Background(), stub.tokenConfig(t, pkcs8PEM(t, ecKey)))
			if failureKind(err) != TokenRefused {
				t.Fatalf("not TokenRefused: %v", err)
			}
			if strings.Contains(err.Error(), "QUOTED-BODY") || strings.Contains(err.Error(), "issued-access-token") {
				t.Fatalf("the refusal quotes the answer: %v", err)
			}
			if stub.sourceHits.Load() != 0 || elsewhere.Load() != 0 {
				t.Fatal("a source or a redirect's target was reached")
			}
		})
	}
	for _, c := range []struct {
		name string
		body string
		want string
	}{
		{"bearer in lower case, at the bound", `{` + tok + `,"token_type":"bearer","expires_in":86400}`, `"expiresIn":86400`},
		{"no expires_in", `{` + tok + `,"token_type":"BEARER"}`, `"expiresIn":null`},
		{"expires_in a string of digits", `{` + tok + `,"token_type":"Bearer","expires_in":"3599"}`, `"expiresIn":3599`},
	} {
		t.Run(c.name, func(t *testing.T) {
			stub := newTokenStub(t, &ecKey.PublicKey)
			stub.answer = json(c.body)
			out, err := ObtainSealed(context.Background(), stub.tokenConfig(t, pkcs8PEM(t, ecKey)))
			if err != nil || !strings.Contains(string(out), c.want) || strings.Contains(string(out), "issued-access-token") {
				t.Fatalf("%s %v", out, err)
			}
		})
	}
}

// A credential that is not there fails as TokenNoCredential before any
// token request: the member absent, a key of no kind the step signs with,
// the federated file absent or empty.
func TestTokenStepWithNoCredentialRequestsNothing(t *testing.T) {
	rsaKey, _ := testKeys(t)
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stub := newTokenStub(t, &rsaKey.PublicKey)
	empty := filepath.Join(t.TempDir(), "empty")
	os.WriteFile(empty, []byte("\n"), 0o600)
	for _, c := range []struct {
		name  string
		shape func(cfg *Config)
	}{
		{"the member absent", func(cfg *Config) { cfg.Token.KeyMember = "ABSENT" }},
		{"no credentials file", func(cfg *Config) { cfg.Credentials = "" }},
		{"the credentials file absent", func(cfg *Config) { cfg.Credentials = filepath.Join(t.TempDir(), "absent.json") }},
		{"a key under 2048 bits", func(cfg *Config) { cfg.Credentials = stub.tokenConfig(t, pkcs8PEM(t, small)).Credentials }},
		{"a P-384 key", func(cfg *Config) { cfg.Credentials = stub.tokenConfig(t, pkcs8PEM(t, p384)).Credentials }},
		{"not PEM", func(cfg *Config) { cfg.Credentials = stub.tokenConfig(t, "not a key").Credentials }},
		{"the federated file absent", func(cfg *Config) {
			cfg.Token.KeyMember, cfg.Token.FederatedTokenFile = "", filepath.Join(t.TempDir(), "absent")
		}},
		{"the federated file empty", func(cfg *Config) { cfg.Token.KeyMember, cfg.Token.FederatedTokenFile = "", empty }},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := stub.tokenConfig(t, pkcs8PEM(t, rsaKey))
			c.shape(&cfg)
			_, err := Acquire(context.Background(), cfg, Request{Path: "/read", Method: "GET"})
			if failureKind(err) != TokenNoCredential {
				t.Fatalf("not TokenNoCredential: %v", err)
			}
			if _, err := ObtainSealed(context.Background(), cfg); failureKind(err) != TokenNoCredential {
				t.Fatalf("token only, not TokenNoCredential: %v", err)
			}
		})
	}
	if stub.tokenHits.Load()+stub.sourceHits.Load() != 0 {
		t.Fatal("a token request or a source request was sent without a credential")
	}
}

// A sealed token is opened by the configuration and credential it was
// sealed under and no other, before its time, and an acquisition handed
// one sends it without a token request. A 401 from the source is
// TokenRejectedBySource, quotes nothing, and the source is asked once.
func TestTokenStepSealsTheTokenToItsConfiguration(t *testing.T) {
	_, ecKey := testKeys(t)
	stub := newTokenStub(t, &ecKey.PublicKey)
	cfg := stub.tokenConfig(t, pkcs8PEM(t, ecKey))
	out, err := ObtainSealed(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var answer struct {
		Sealed    string `json:"sealed"`
		ExpiresIn int    `json:"expiresIn"`
	}
	if err := json.Unmarshal(out, &answer); err != nil || answer.ExpiresIn != 3600 || answer.Sealed == "" {
		t.Fatalf("%s %v", out, err)
	}
	if strings.Contains(string(out), stub.issued) {
		t.Fatal("the token is on stdout in the clear")
	}
	handed := cfg
	handed.SealedToken = answer.Sealed
	for i := 0; i < 3; i++ {
		if _, err := Acquire(context.Background(), handed, Request{Path: "/read", Method: "GET"}); err != nil {
			t.Fatal(err)
		}
	}
	if stub.tokenHits.Load() != 1 || stub.sourceHits.Load() != 3 {
		t.Fatalf("a sealed token is sent without a token request: %d, %d", stub.tokenHits.Load(), stub.sourceHits.Load())
	}
	unusable := map[string]Config{}
	tampered := handed
	tampered.SealedToken = answer.Sealed[:len(answer.Sealed)-2] + "AA"
	unusable["tampered"] = tampered
	otherEndpoint := handed
	otherEndpoint.Token = &TokenStep{Endpoint: stub.token.URL + "/other", ClientID: stub.clientID, KeyMember: "CLIENT_KEY"}
	unusable["another token endpoint"] = otherEndpoint
	otherClient := handed
	otherClient.Token = &TokenStep{Endpoint: stub.token.URL + "/token", ClientID: "client-8", KeyMember: "CLIENT_KEY"}
	unusable["another client"] = otherClient
	otherSource := handed
	otherSource.Endpoint = "http://127.0.0.1:9"
	unusable["another source endpoint"] = otherSource
	otherScope := handed
	scoped := *handed.Token
	scoped.Scope = "another.scope"
	otherScope.Token = &scoped
	unusable["another requestScope"] = otherScope
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rekeyed := stub.tokenConfig(t, pkcs8PEM(t, otherKey))
	rekeyed.SealedToken = answer.Sealed
	unusable["another key"] = rekeyed
	expired := handed
	if expired.SealedToken, err = sealToken(cfg, []byte(pkcs8PEM(t, ecKey)), stub.issued, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	unusable["past its time"] = expired
	for name, c := range unusable {
		if _, err := Acquire(context.Background(), c, Request{Path: "/read", Method: "GET"}); failureKind(err) != TokenSealUnusable {
			t.Fatalf("%s: not TokenSealUnusable: %v", name, err)
		}
	}
	if stub.tokenHits.Load() != 1 || stub.sourceHits.Load() != 3 {
		t.Fatal("an unusable sealed token reached the source or the token endpoint")
	}
	// The source refuses the token.
	stub.issued = "another-issued-token-ABCDEFGH"
	_, err = Acquire(context.Background(), handed, Request{Path: "/read", Method: "GET"})
	if failureKind(err) != TokenRejectedBySource {
		t.Fatalf("not TokenRejectedBySource: %v", err)
	}
	if strings.Contains(err.Error(), "refused:") || strings.Contains(err.Error(), "issued-access-token") {
		t.Fatalf("the refusal quotes the answer: %v", err)
	}
	if stub.sourceHits.Load() != 4 {
		t.Fatalf("the source was asked %d times for one refused acquisition", stub.sourceHits.Load()-3)
	}
}

// A static credential is not named beside a token step: the token is what
// is sent.
func TestTokenStepRefusesAStaticCredentialBesideIt(t *testing.T) {
	_, ecKey := testKeys(t)
	stub := newTokenStub(t, &ecKey.PublicKey)
	for _, shape := range []func(*Config){
		func(c *Config) { c.Bearer = "UNUSED" },
		func(c *Config) { c.CredentialHeader = "X-Key=UNUSED" },
		func(c *Config) { c.Token.FederatedTokenFile = "/x" },
		func(c *Config) {
			c.Token.X5T, c.Token.X5TS256 = "AAAAAAAAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		},
		func(c *Config) { c.Token.X5TS256 = "short" },
		func(c *Config) { c.Token.ClientID = "has space" },
		func(c *Config) { c.Token.Scope = "a  b" },
	} {
		cfg := stub.tokenConfig(t, pkcs8PEM(t, ecKey))
		shape(&cfg)
		if _, err := Acquire(context.Background(), cfg, Request{Path: "/read", Method: "GET"}); err == nil || failureKind(err) != 0 {
			t.Fatalf("not refused as a configuration: %v", err)
		}
	}
	if stub.tokenHits.Load()+stub.sourceHits.Load() != 0 {
		t.Fatal("a refused configuration reached an endpoint")
	}
}

// No diagnostic the adapter writes, through every outcome, carries the
// key, the assertion, the federated token or the access token.
func TestTokenStepDiagnosticsCarryNoSecret(t *testing.T) {
	_, ecKey := testKeys(t)
	keyText := pkcs8PEM(t, ecKey)
	stub := newTokenStub(t, &ecKey.PublicKey)
	var texts []string
	run := func(cfg Config) {
		if _, err := Acquire(context.Background(), cfg, Request{Path: "/read", Method: "GET"}); err != nil {
			texts = append(texts, err.Error())
		}
		if _, err := Check(context.Background(), cfg); err != nil {
			texts = append(texts, err.Error())
		}
	}
	cfg := stub.tokenConfig(t, keyText)
	cfg.CheckPath = "/read"
	run(cfg)
	// The endpoint refuses, quoting the assertion and the key it was sent.
	stub.answer = func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusUnauthorized)
		stub.mu.Lock()
		io.WriteString(w, strings.Join(stub.assertions, " ")+keyText)
		stub.mu.Unlock()
	}
	run(cfg)
	// The source refuses the token, quoting it back.
	stub.answer = func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"`+stub.issued+`X","token_type":"Bearer"}`)
	}
	run(cfg)
	missing := cfg
	missing.Token = &TokenStep{Endpoint: cfg.Token.Endpoint, ClientID: cfg.Token.ClientID, KeyMember: "ABSENT"}
	run(missing)
	if len(texts) < 6 {
		t.Fatalf("expected refusals to search, have %d", len(texts))
	}
	stub.mu.Lock()
	needles := append([]string{stub.issued, "issued-access-token", strings.TrimSpace(strings.Split(keyText, "\n")[1])}, stub.assertions...)
	stub.mu.Unlock()
	for _, text := range texts {
		for _, needle := range needles {
			if needle != "" && strings.Contains(text, needle) {
				t.Fatalf("a diagnostic carries a secret: %q", text)
			}
		}
	}
}
