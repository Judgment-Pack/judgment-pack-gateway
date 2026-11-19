package httpsource

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"go/parser"
	gotoken "go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Every name, address and token here is invented; every server is a local
// stand-in (ADR-0045).
const (
	testServiceAccount = "directory-reader@example-project.iam.gserviceaccount.com"
	testSubject        = "admin@example.com"
	testScopes         = "https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/admin.reports.audit.readonly"
	testMetadataToken  = "meta-access-7f3c"
	testWorkspaceToken = "workspace-access-91ab"
)

// delegatedStubs are the stand-in metadata server, credentials API, token
// endpoint and source, each recording what it was asked.
type delegatedStubs struct {
	mu                     sync.Mutex
	metaPaths, metaQueries []string
	signPaths, signAuth    []string
	signPayloads           []map[string]json.RawMessage
	tokenForms             []url.Values
	meta, sign, tok, src   *httptest.Server
	metaHits, signHits     atomic.Int64
	tokenHits, sourceHits  atomic.Int64
	metaAnswer, signAnswer func(w http.ResponseWriter, r *http.Request, payload string)
}

func pointCredentialsAPIAt(t *testing.T, base string) {
	t.Helper()
	previous := credentialsAPIBase
	credentialsAPIBase = base
	t.Cleanup(func() { credentialsAPIBase = previous })
}

// signedBy is a signed JWT of the payload as the credentials API answers
// one, its signature a stand-in: the token endpoint verifies it, the
// adapter does not.
func signedBy(payload string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"stand-in","typ":"JWT"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".c3RhbmQtaW4tc2lnbmF0dXJl"
}

func newDelegatedStubs(t *testing.T) *delegatedStubs {
	t.Helper()
	s := &delegatedStubs{}
	s.metaAnswer = func(w http.ResponseWriter, r *http.Request, _ string) {
		w.Header().Set("Metadata-Flavor", "Google")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"`+testMetadataToken+`","expires_in":3599,"token_type":"Bearer"}`)
	}
	s.signAnswer = func(w http.ResponseWriter, r *http.Request, payload string) {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		answer, _ := json.Marshal(map[string]string{"keyId": "0123abcd", "signedJwt": signedBy(payload)})
		w.Write(answer)
	}
	s.meta = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.metaHits.Add(1)
		s.mu.Lock()
		s.metaPaths, s.metaQueries = append(s.metaPaths, r.Method+" "+r.URL.Path+" "+strings.Join(r.Header.Values("Metadata-Flavor"), ",")), append(s.metaQueries, r.URL.RawQuery)
		answer := s.metaAnswer
		s.mu.Unlock()
		answer(w, r, "")
	}))
	s.sign = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.signHits.Add(1)
		var body struct {
			Payload string `json:"payload"`
		}
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &body)
		var claims map[string]json.RawMessage
		json.Unmarshal([]byte(body.Payload), &claims)
		s.mu.Lock()
		s.signPaths, s.signAuth = append(s.signPaths, r.Method+" "+r.URL.EscapedPath()), append(s.signAuth, r.Header.Get("Authorization"))
		s.signPayloads = append(s.signPayloads, claims)
		answer := s.signAnswer
		s.mu.Unlock()
		answer(w, r, body.Payload)
	}))
	s.tok = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.tokenHits.Add(1)
		r.ParseForm()
		s.mu.Lock()
		s.tokenForms = append(s.tokenForms, r.PostForm)
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"`+testWorkspaceToken+`","expires_in":3599,"token_type":"Bearer"}`)
	}))
	s.src = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.sourceHits.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+testWorkspaceToken || r.Method != "GET" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"kind":"admin#directory#user","id":"115813357217846539498"}`)
	}))
	for _, server := range []*httptest.Server{s.meta, s.sign, s.tok, s.src} {
		t.Cleanup(server.Close)
	}
	pointMetadataAt(t, s.meta.URL)
	pointCredentialsAPIAt(t, s.sign.URL)
	return s
}

// config is a configuration of the stand-in source with a credentials API
// token step, whose credentials file holds sealKey and nothing else.
func (s *delegatedStubs) config(t *testing.T) Config {
	t.Helper()
	creds := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(creds, []byte(`{"sealKey":"`+testSealKey+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return Config{
		Endpoint: s.src.URL, Credentials: creds, Paths: []string{"/admin/directory/v1/users/{numericId}"}, Methods: []string{"GET"}, MaxOutput: 1 << 20,
		Token: &TokenStep{Endpoint: s.tok.URL + "/token", ServiceAccount: testServiceAccount, Subject: testSubject, Scope: testScopes},
	}
}

// The metadata server is asked, at its fixed address, for the compute's
// access token with no query; the credentials API, at its fixed address,
// is asked under that token to sign exactly iss the service account, sub
// the subject, scope the scopes and aud the token endpoint, with exp five
// minutes after iat; and the signed JWT is the JWT-bearer grant's
// assertion, with no client and no scope beside it. The access token is
// answered sealed, an acquisition handed it asks nothing, and the seal is
// bound to the subject. No key is held: the credentials file holds sealKey
// alone, and a key file the platform's libraries would read is not there.
func TestDelegatedTokenIsSignedByTheCredentialsAPIForTheFixedClaims(t *testing.T) {
	if credentialsAPIBase != "https://iamcredentials.googleapis.com" || metadataBase != "http://169.254.169.254" {
		t.Fatalf("the built-in addresses are %q and %q", credentialsAPIBase, metadataBase)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "absent", "key.json"))
	s := newDelegatedStubs(t)
	cfg := s.config(t)
	before := time.Now().Unix()
	out, err := ObtainSealed(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{testMetadataToken, testWorkspaceToken, "c3RhbmQtaW4tc2lnbmF0dXJl"} {
		if strings.Contains(string(out), secret) {
			t.Fatalf("a token is on stdout in the clear: %s", out)
		}
	}
	if !reflect.DeepEqual(s.metaPaths, []string{"GET " + metadataTokenPath + " Google"}) || s.metaQueries[0] != "" {
		t.Fatalf("the metadata request: %q %q", s.metaPaths, s.metaQueries)
	}
	if !reflect.DeepEqual(s.signPaths, []string{"POST /v1/projects/-/serviceAccounts/" + testServiceAccount + ":signJwt"}) || s.signAuth[0] != "Bearer "+testMetadataToken {
		t.Fatalf("the signing request: %q %q", s.signPaths, s.signAuth)
	}
	claims := s.signPayloads[0]
	names := []string{}
	for name := range claims {
		names = append(names, name)
	}
	if len(claims) != 6 {
		t.Fatalf("the claims asked for: %v", names)
	}
	for name, want := range map[string]string{"iss": testServiceAccount, "sub": testSubject, "scope": testScopes, "aud": cfg.Token.Endpoint} {
		if string(claims[name]) != strconv.Quote(want) {
			t.Fatalf("claim %s: %s, want %q", name, claims[name], want)
		}
	}
	iat, _ := strconv.ParseInt(string(claims["iat"]), 10, 64)
	exp, _ := strconv.ParseInt(string(claims["exp"]), 10, 64)
	if iat < before || iat > time.Now().Unix() || exp-iat != 300 || exp-iat > 3600 {
		t.Fatalf("iat %d, exp %d", iat, exp)
	}
	signed := signedBy(`{"iss":"` + testServiceAccount + `","sub":"` + testSubject + `","scope":"` + testScopes + `","aud":"` + cfg.Token.Endpoint + `","iat":` + string(claims["iat"]) + `,"exp":` + string(claims["exp"]) + `}`)
	if want := (url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {signed}}); len(s.tokenForms) != 1 || !reflect.DeepEqual(s.tokenForms[0], want) {
		t.Fatalf("the token request: %v", s.tokenForms)
	}
	var answer struct {
		Sealed string `json:"sealed"`
	}
	if err := json.Unmarshal(out, &answer); err != nil {
		t.Fatal(err)
	}
	handed := cfg
	handed.SealedToken = answer.Sealed
	if _, err := Acquire(context.Background(), handed, Request{Path: "/admin/directory/v1/users/115813357217846539498", Method: "GET"}); err != nil {
		t.Fatal(err)
	}
	if s.metaHits.Load() != 1 || s.signHits.Load() != 1 || s.tokenHits.Load() != 1 || s.sourceHits.Load() != 1 {
		t.Fatalf("a sealed token is sent without asking anything: %d %d %d %d", s.metaHits.Load(), s.signHits.Load(), s.tokenHits.Load(), s.sourceHits.Load())
	}
	other := handed
	step := *handed.Token
	step.Subject = "another-admin@example.com"
	other.Token = &step
	if _, err := Acquire(context.Background(), other, Request{Path: "/admin/directory/v1/users/1", Method: "GET"}); failureKind(err) != TokenSealUnusable {
		t.Fatalf("a seal for another subject: %v", err)
	}
}

// The flow's file opens no file: it imports nothing that reads one, so no
// key file is opened, whatever the environment names.
func TestDelegatedFlowOpensNoFile(t *testing.T) {
	file, err := parser.ParseFile(gotoken.NewFileSet(), "delegated.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range file.Imports {
		switch path, _ := strconv.Unquote(spec.Path.Value); path {
		case "os", "io/fs", "io/ioutil", "path/filepath", "os/exec", "syscall":
			t.Fatalf("delegated.go imports %s", path)
		}
	}
}

// Every failure before the token request is no credential, one fixed
// sentence that repeats nothing of an answer, the subject, the scopes or
// the service account, and no token request is sent; a redirect is not
// followed.
func TestDelegatedFailuresAreNoCredentialAndSendNoTokenRequest(t *testing.T) {
	elsewhere := atomic.Int64{}
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { elsewhere.Add(1) }))
	t.Cleanup(other.Close)
	redirect := func(w http.ResponseWriter, r *http.Request, _ string) {
		w.Header().Set("Metadata-Flavor", "Google")
		http.Redirect(w, r, other.URL+"/elsewhere", http.StatusTemporaryRedirect)
	}
	meta := "the token step's metadata server "
	sign := "the token step's credentials API "
	for _, c := range []struct {
		name       string
		metaAnswer func(w http.ResponseWriter, r *http.Request, payload string)
		signAnswer func(w http.ResponseWriter, r *http.Request, payload string)
		signClosed bool
		want       string
	}{
		{"metadata without the flavor header", func(w http.ResponseWriter, r *http.Request, _ string) {
			io.WriteString(w, `{"access_token":"x","token_type":"Bearer"}`)
		}, nil, false, meta + "answered without Metadata-Flavor: Google"},
		{"metadata 500", func(w http.ResponseWriter, r *http.Request, _ string) {
			w.Header().Set("Metadata-Flavor", "Google")
			w.WriteHeader(500)
		}, nil, false, meta + "refused the access token request (500)"},
		{"metadata redirect", redirect, nil, false, meta + "answered with a redirect, which is not followed"},
		{"metadata no token", func(w http.ResponseWriter, r *http.Request, _ string) {
			w.Header().Set("Metadata-Flavor", "Google")
			io.WriteString(w, `{"access_token":"has space","token_type":"Bearer"}`)
		}, nil, false, meta + "answered with no access token this adapter takes"},
		{"signJwt 403", nil, func(w http.ResponseWriter, r *http.Request, _ string) {
			w.WriteHeader(403)
			io.WriteString(w, `{"error":{"message":"`+testServiceAccount+`"}}`)
		}, false, sign + "refused the signing request (403)"},
		{"signJwt redirect", nil, redirect, false, sign + "answered with a redirect, which is not followed"},
		{"signJwt of other claims", nil, func(w http.ResponseWriter, r *http.Request, payload string) {
			w.Header().Set("Content-Type", "application/json")
			answer, _ := json.Marshal(map[string]string{"keyId": "k", "signedJwt": signedBy(strings.Replace(payload, testSubject, "another-admin@example.com", 1))})
			w.Write(answer)
		}, false, sign + "answered with a signed JWT of other claims than were asked for"},
		{"signJwt of another scope", nil, func(w http.ResponseWriter, r *http.Request, payload string) {
			w.Header().Set("Content-Type", "application/json")
			answer, _ := json.Marshal(map[string]string{"keyId": "k", "signedJwt": signedBy(strings.Replace(payload, ".readonly", ".security", 1))})
			w.Write(answer)
		}, false, sign + "answered with a signed JWT of other claims than were asked for"},
		{"signJwt of a claim named in another case", nil, func(w http.ResponseWriter, r *http.Request, payload string) {
			w.Header().Set("Content-Type", "application/json")
			answer, _ := json.Marshal(map[string]string{"keyId": "k", "signedJwt": signedBy(strings.Replace(payload, `"iss":`, `"ISS":`, 1))})
			w.Write(answer)
		}, false, sign + "answered with a signed JWT of other claims than were asked for"},
		{"signJwt of a claim named twice, the asked value last", nil, func(w http.ResponseWriter, r *http.Request, payload string) {
			w.Header().Set("Content-Type", "application/json")
			answer, _ := json.Marshal(map[string]string{"keyId": "k", "signedJwt": signedBy(`{"sub":"another-admin@example.com",` + payload[1:])})
			w.Write(answer)
		}, false, sign + "answered with a signed JWT of other claims than were asked for"},
		{"signJwt of one claim more", nil, func(w http.ResponseWriter, r *http.Request, payload string) {
			w.Header().Set("Content-Type", "application/json")
			answer, _ := json.Marshal(map[string]string{"keyId": "k", "signedJwt": signedBy(payload[:len(payload)-1] + `,"act":"x"}`)})
			w.Write(answer)
		}, false, sign + "answered with a signed JWT of other claims than were asked for"},
		{"signJwt with another member", nil, func(w http.ResponseWriter, r *http.Request, payload string) {
			w.Header().Set("Content-Type", "application/json")
			answer, _ := json.Marshal(map[string]string{"keyId": "k", "signedJwt": signedBy(payload), "extra": "x"})
			w.Write(answer)
		}, false, sign + "answered with no signed JWT this adapter takes"},
		{"signJwt not JSON", nil, func(w http.ResponseWriter, r *http.Request, payload string) {
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, signedBy(payload))
		}, false, sign + "answered with no signed JWT this adapter takes"},
		{"signJwt unreachable", nil, nil, true, sign + "could not be reached in time"},
	} {
		s := newDelegatedStubs(t)
		if c.metaAnswer != nil {
			s.metaAnswer = c.metaAnswer
		}
		if c.signAnswer != nil {
			s.signAnswer = c.signAnswer
		}
		if c.signClosed {
			s.sign.Close()
		}
		_, err := ObtainSealed(context.Background(), s.config(t))
		var throttledErr *Throttled
		if failureKind(err) != TokenNoCredential || errors.As(err, &throttledErr) || err.Error() != c.want+"; no token was requested" {
			t.Fatalf("%s: %v", c.name, err)
		}
		if s.tokenHits.Load() != 0 || elsewhere.Load() != 0 {
			t.Fatalf("%s: a token request was sent, or a redirect followed", c.name)
		}
		for _, value := range []string{testServiceAccount, testSubject, "admin.directory", testMetadataToken, "elsewhere"} {
			if strings.Contains(err.Error(), value) {
				t.Fatalf("%s: the refusal repeats %q: %v", c.name, value, err)
			}
		}
	}
}

// A 429 or 503 of the metadata server (with its flavor header) or of the
// credentials API is the token step's throttled answer (ADR-0029), and no
// token request follows it.
func TestDelegatedThrottledAnswersAreTheTokenStepsThrottling(t *testing.T) {
	for _, c := range []struct {
		name     string
		metadata bool
		status   int
		want     string
	}{
		{"metadata 429", true, 429, "the token step's metadata server refused the access token request (429)"},
		{"metadata 503", true, 503, "the token step's metadata server refused the access token request (503)"},
		{"signJwt 429", false, 429, "the token step's credentials API refused the signing request (429)"},
		{"signJwt 503", false, 503, "the token step's credentials API refused the signing request (503)"},
	} {
		s := newDelegatedStubs(t)
		answer := func(w http.ResponseWriter, r *http.Request, _ string) {
			w.Header().Set("Metadata-Flavor", "Google")
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(c.status)
		}
		if c.metadata {
			s.metaAnswer = answer
		} else {
			s.signAnswer = answer
		}
		_, err := ObtainSealed(context.Background(), s.config(t))
		var throttledErr *Throttled
		if !errors.As(err, &throttledErr) || throttledErr.Error() != c.want {
			t.Fatalf("%s: %v", c.name, err)
		}
		if s.tokenHits.Load() != 0 || (c.metadata && s.signHits.Load() != 0) {
			t.Fatalf("%s: a request followed the throttled answer", c.name)
		}
	}
}

// The step's forms: no client identifier beside it, a user-managed service
// account's address, a subject's address, and the read-only scopes alone,
// each once. --token-subject is for this form alone, and a credentials
// file holding sealKey is required. A refusal repeats no value.
func TestDelegatedStepIsHeldToItsForms(t *testing.T) {
	s := newDelegatedStubs(t)
	good := s.config(t)
	clientForm := "--client-id is not given beside --signed-by-service-account"
	accountForm := "--signed-by-service-account is NAME@PROJECT.iam.gserviceaccount.com"
	subjectForm := "--token-subject is an address of at most 254 bytes"
	scopeForm := "--token-scope is one or more of the Admin SDK's read-only scopes ADR-0045 lists"
	for _, c := range []struct {
		name string
		edit func(*TokenStep)
		want string
	}{
		{"a client identifier", func(t *TokenStep) { t.ClientID = "client-7" }, clientForm},
		{"an uppercase account", func(t *TokenStep) { t.ServiceAccount = "Directory-reader@example-project.iam.gserviceaccount.com" }, accountForm},
		{"an account with a slash", func(t *TokenStep) { t.ServiceAccount = "directory-reader/x@example-project.iam.gserviceaccount.com" }, accountForm},
		{"an account percent-encoded", func(t *TokenStep) { t.ServiceAccount = "directory-reader%40x@example-project.iam.gserviceaccount.com" }, accountForm},
		{"a default compute account", func(t *TokenStep) { t.ServiceAccount = "123456789012-compute@developer.gserviceaccount.com" }, accountForm},
		{"an account of another domain", func(t *TokenStep) { t.ServiceAccount = "directory-reader@example-project.iam.example.com" }, accountForm},
		{"a short name", func(t *TokenStep) { t.ServiceAccount = "dir@example-project.iam.gserviceaccount.com" }, accountForm},
		{"no subject", func(t *TokenStep) { t.Subject = "" }, subjectForm},
		{"a subject without @", func(t *TokenStep) { t.Subject = "admin.example.com" }, subjectForm},
		{"a subject with a space", func(t *TokenStep) { t.Subject = "ad min@example.com" }, subjectForm},
		{"a subject of 255 bytes", func(t *TokenStep) { t.Subject = "admin@" + strings.Repeat("a.", 124) + "com" }, subjectForm},
		{"a subject without a dot", func(t *TokenStep) { t.Subject = "admin@localhost" }, subjectForm},
		{"no scope", func(t *TokenStep) { t.Scope = "" }, scopeForm},
		{"the security scope", func(t *TokenStep) { t.Scope = "https://www.googleapis.com/auth/admin.directory.user.security" }, scopeForm},
		{"a write scope", func(t *TokenStep) { t.Scope = "https://www.googleapis.com/auth/admin.directory.user" }, scopeForm},
		{"the platform scope", func(t *TokenStep) { t.Scope = "https://www.googleapis.com/auth/cloud-platform" }, scopeForm},
		{"a scope twice", func(t *TokenStep) {
			t.Scope = "https://www.googleapis.com/auth/admin.reports.audit.readonly https://www.googleapis.com/auth/admin.reports.audit.readonly"
		}, scopeForm},
		{"two spaces", func(t *TokenStep) { t.Scope = strings.Replace(testScopes, " ", "  ", 1) }, scopeForm},
		{"beside a key", func(t *TokenStep) { t.KeyMember = "KEY" }, "a token step takes exactly one of --assertion-key, --federated-token-file, --federated-token-metadata-audience and --signed-by-service-account"},
		{"a thumbprint", func(t *TokenStep) { t.X5T = base64.RawURLEncoding.EncodeToString(make([]byte, 20)) }, "a certificate thumbprint is for an assertion this adapter signs"},
		{"a subject without the account", func(t *TokenStep) { t.ServiceAccount, t.ClientID, t.MetadataAudience = "", "client-7", "api://x" }, "--token-subject is the subject of an assertion the credentials API signs"},
	} {
		cfg := good
		step := *good.Token
		c.edit(&step)
		cfg.Token = &step
		_, err := ObtainSealed(context.Background(), cfg)
		if err == nil || !strings.HasPrefix(err.Error(), c.want) {
			t.Fatalf("%s: %v", c.name, err)
		}
		for _, value := range []string{"directory-reader", "admin@", "ad min", "client-7", "cloud-platform", "compute@"} {
			if strings.Contains(err.Error(), value) {
				t.Fatalf("%s: the refusal repeats %q: %v", c.name, value, err)
			}
		}
	}
	noFile := good
	noFile.Credentials = ""
	noKey := good
	noKey.Credentials = filepath.Join(t.TempDir(), "credentials.json")
	os.WriteFile(noKey.Credentials, []byte(`{"key":"`+testSealKey+`"}`), 0o600)
	for name, cfg := range map[string]Config{"no credentials file": noFile, "no sealKey": noKey} {
		if _, err := ObtainSealed(context.Background(), cfg); failureKind(err) != TokenNoCredential {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if s.metaHits.Load() != 0 || s.signHits.Load() != 0 || s.tokenHits.Load() != 0 {
		t.Fatal("a step out of form asked something")
	}
}
