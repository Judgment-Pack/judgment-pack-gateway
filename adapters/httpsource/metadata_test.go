package httpsource

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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

// metadataRequest is what the stand-in metadata server was asked.
type metadataRequest struct {
	method, path, rawQuery string
	query                  map[string][]string
	flavor, forwarded      []string
}

// metadataStub is a stand-in metadata server, which metadataBase points at
// for the test: it records each request and answers what answer says, by
// default the identity token token() gives, with Metadata-Flavor: Google
// and the text/html type the platform answers it with.
type metadataStub struct {
	server   *httptest.Server
	hits     atomic.Int64
	mu       sync.Mutex
	requests []metadataRequest
	answer   func(w http.ResponseWriter, r *http.Request)
}

func newMetadataStub(t *testing.T, token func() string) *metadataStub {
	t.Helper()
	s := &metadataStub{}
	s.answer = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Metadata-Flavor", "Google")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, token())
	}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.mu.Lock()
		s.requests = append(s.requests, metadataRequest{method: r.Method, path: r.URL.Path, rawQuery: r.URL.RawQuery, query: r.URL.Query(),
			flavor: r.Header.Values("Metadata-Flavor"), forwarded: r.Header.Values("X-Forwarded-For")})
		answer := s.answer
		s.mu.Unlock()
		answer(w, r)
	}))
	t.Cleanup(s.server.Close)
	pointMetadataAt(t, s.server.URL)
	return s
}

// pointMetadataAt points metadataBase at base for the rest of the test and
// restores it when the test ends, so no test leaves another the stand-in's
// address in place of the fixed one, in whatever order they run.
func pointMetadataAt(t *testing.T, base string) {
	t.Helper()
	previous := metadataBase
	metadataBase = base
	t.Cleanup(func() { metadataBase = previous })
}

func (s *metadataStub) answerWith(answer func(w http.ResponseWriter, r *http.Request)) {
	s.mu.Lock()
	s.answer = answer
	s.mu.Unlock()
}

// identityJWT is an identity token of the platform's form, its signature a
// stand-in (the token endpoint verifies it, the adapter does not): a
// compact JWS whose payload holds claims.
func identityJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"stand-in","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".c3RhbmQtaW4tc2lnbmF0dXJl"
}

func identityFor(t *testing.T, audience string, exp time.Time, subject string) string {
	return identityJWT(t, map[string]any{"aud": audience, "exp": exp.Unix(), "iat": time.Now().Unix(), "iss": "https://accounts.example", "sub": subject})
}

const testSealKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// metadataConfig is a configuration of the token stub's source with a
// metadata token step for audience, whose credentials file holds sealKey.
func metadataConfig(t *testing.T, stub *tokenStub, audience string) Config {
	t.Helper()
	creds := filepath.Join(t.TempDir(), "credentials.json")
	data, _ := json.Marshal(map[string]string{"sealKey": testSealKey, "UNUSED": "never-sent-value"})
	if err := os.WriteFile(creds, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return Config{
		Endpoint: stub.source.URL, Credentials: creds, Paths: []string{"/read"}, Methods: []string{"GET"}, MaxOutput: 1 << 20,
		Token: &TokenStep{Endpoint: stub.token.URL + "/token", ClientID: stub.clientID, MetadataAudience: audience},
	}
}

// refusedWith is whether err is no credential with exactly the fixed
// sentence the metadata server's refusal why gives.
func refusedWith(err error, why string) bool {
	var throttledErr *Throttled
	return failureKind(err) == TokenNoCredential && !errors.As(err, &throttledErr) &&
		err.Error() == "the token step's metadata server "+why+"; no token was requested"
}

// The metadata server is the platform's fixed link-local address, written
// as an IP literal; the identity token is asked of it by GET for the one
// audience configured, percent-encoded, with Metadata-Flavor: Google and
// format=full, and presented to the token endpoint as the assertion. The
// token is answered sealed, and an acquisition handed it asks the metadata
// server nothing.
func TestMetadataTokenIsAskedOfTheFixedAddressForItsAudience(t *testing.T) {
	if metadataBase != "http://169.254.169.254" {
		t.Fatalf("the metadata server is %q, not the platform's fixed address", metadataBase)
	}
	const audience = "api://records-reader"
	stub := newTokenStub(t, nil)
	identity := identityFor(t, audience, time.Now().Add(time.Hour), "first")
	stub.federated = func() string { return identity }
	meta := newMetadataStub(t, func() string { return identity + "\n" })
	cfg := metadataConfig(t, stub, audience)
	out, err := ObtainSealed(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	stub.check(t)
	if strings.Contains(string(out), identity) || strings.Contains(string(out), stub.issued) {
		t.Fatalf("a token is on stdout in the clear: %s", out)
	}
	want := metadataRequest{method: "GET", path: "/computeMetadata/v1/instance/service-accounts/default/identity",
		rawQuery: "audience=api%3A%2F%2Frecords-reader&format=full", query: map[string][]string{"audience": {audience}, "format": {"full"}},
		flavor: []string{"Google"}}
	if len(meta.requests) != 1 || !reflect.DeepEqual(meta.requests[0], want) {
		t.Fatalf("the metadata request:\n%+v\nwant\n%+v", meta.requests, want)
	}
	var answer struct {
		Sealed    string `json:"sealed"`
		ExpiresIn int    `json:"expiresIn"`
	}
	if err := json.Unmarshal(out, &answer); err != nil || answer.ExpiresIn != 3600 {
		t.Fatalf("%s %v", out, err)
	}
	handed := cfg
	handed.SealedToken = answer.Sealed
	for i := 0; i < 2; i++ {
		if _, err := Acquire(context.Background(), handed, Request{Path: "/read", Method: "GET"}); err != nil {
			t.Fatal(err)
		}
	}
	if meta.hits.Load() != 1 || stub.tokenHits.Load() != 1 || stub.sourceHits.Load() != 2 {
		t.Fatalf("a sealed token is sent without asking anything: %d metadata, %d token, %d source requests", meta.hits.Load(), stub.tokenHits.Load(), stub.sourceHits.Load())
	}
	// The seal is bound to the audience and to the sealKey.
	otherAudience := handed
	step := *handed.Token
	step.MetadataAudience = "api://another"
	otherAudience.Token = &step
	rekeyed := handed
	creds := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(creds, []byte(`{"sealKey":"`+strings.Repeat("f", 64)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rekeyed.Credentials = creds
	for name, c := range map[string]Config{"another audience": otherAudience, "another sealKey": rekeyed} {
		if _, err := Acquire(context.Background(), c, Request{Path: "/read", Method: "GET"}); failureKind(err) != TokenSealUnusable {
			t.Fatalf("%s: not TokenSealUnusable: %v", name, err)
		}
	}
	if meta.hits.Load() != 1 || stub.sourceHits.Load() != 2 {
		t.Fatal("an unusable sealed token asked the metadata server or reached the source")
	}
	// A step of the key form is bound as it was before the metadata form.
	keyed := Config{Endpoint: "https://records.example", Token: &TokenStep{Endpoint: "https://login.example/token", ClientID: "c", KeyMember: "K", Scope: "s"}}
	if got := string(sealAAD(keyed)); got != `["adapter-http sealed token 1","https://records.example","https://login.example/token","c","K","","","","","s"]` {
		t.Fatalf("the key form's seal binding changed: %s", got)
	}
}

// An answer is taken only when it carries Metadata-Flavor: Google, once and
// exactly: anything else at that address is not the metadata server, and
// its 429 is not a throttled answer of the token step.
func TestMetadataAnswerWithoutTheFlavorHeaderIsRefused(t *testing.T) {
	const audience = "api://records-reader"
	stub := newTokenStub(t, nil)
	identity := identityFor(t, audience, time.Now().Add(time.Hour), "s")
	stub.federated = func() string { return identity }
	meta := newMetadataStub(t, func() string { return identity })
	cfg := metadataConfig(t, stub, audience)
	for _, c := range []struct {
		name   string
		flavor []string
		status int
	}{
		{"none", nil, 200},
		{"another value", []string{"google"}, 200},
		{"twice", []string{"Google", "Google"}, 200},
		{"empty", []string{""}, 200},
		{"none, on a 429", nil, 429},
		{"none, on a 503", nil, 503},
	} {
		meta.answerWith(func(w http.ResponseWriter, r *http.Request) {
			for _, v := range c.flavor {
				w.Header().Add("Metadata-Flavor", v)
			}
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(c.status)
			io.WriteString(w, identity)
		})
		if _, err := ObtainSealed(context.Background(), cfg); !refusedWith(err, "answered without Metadata-Flavor: Google") {
			t.Fatalf("%s: %v", c.name, err)
		}
	}
	if stub.tokenHits.Load() != 0 {
		t.Fatalf("an answer without the flavor header reached the token endpoint: %d", stub.tokenHits.Load())
	}
}

// A redirect is refused and not followed, even to the same server.
func TestMetadataRedirectIsRefused(t *testing.T) {
	const audience = "api://records-reader"
	stub := newTokenStub(t, nil)
	identity := identityFor(t, audience, time.Now().Add(time.Hour), "s")
	stub.federated = func() string { return identity }
	meta := newMetadataStub(t, func() string { return identity })
	cfg := metadataConfig(t, stub, audience)
	for _, status := range []int{http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		meta.answerWith(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Metadata-Flavor", "Google")
			if r.URL.Path == "/elsewhere" {
				io.WriteString(w, identity)
				return
			}
			w.Header().Set("Location", "/elsewhere")
			w.WriteHeader(status)
		})
		if _, err := ObtainSealed(context.Background(), cfg); !refusedWith(err, "answered with a redirect, which is not followed") {
			t.Fatalf("%d: %v", status, err)
		}
	}
	for _, r := range meta.requests {
		if r.path == "/elsewhere" {
			t.Fatal("a redirect was followed")
		}
	}
	if stub.tokenHits.Load() != 0 {
		t.Fatal("a redirected answer reached the token endpoint")
	}
}

// The answer is bounded to 16 KiB, as the federated token file is: an
// identity token of exactly that size is taken, one byte more is not.
func TestMetadataAnswerIsBoundedTo16KiB(t *testing.T) {
	const audience = "api://records-reader"
	stub := newTokenStub(t, nil)
	base := identityFor(t, audience, time.Now().Add(time.Hour), "s")
	sized := func(n int) string {
		head := base[:strings.LastIndex(base, ".")+1]
		return head + strings.Repeat("A", n-len(head))
	}
	current := sized(maxFederatedToken)
	stub.federated = func() string { return current }
	newMetadataStub(t, func() string { return current })
	cfg := metadataConfig(t, stub, audience)
	if _, err := ObtainSealed(context.Background(), cfg); err != nil {
		t.Fatalf("an identity token of 16 KiB: %v", err)
	}
	current = sized(maxFederatedToken + 1)
	if _, err := ObtainSealed(context.Background(), cfg); !refusedWith(err, "answered with more than 16 KiB") {
		t.Fatalf("an identity token of 16 KiB and one byte: %v", err)
	}
	if stub.tokenHits.Load() != 1 {
		t.Fatalf("an oversized answer reached the token endpoint: %d token requests", stub.tokenHits.Load())
	}
}

// The answer's header block is bounded to 64 KiB, as a source's answer is.
// An answer whose header exceeds it fails the request before its flavor,
// status or body is read, even though it carries the flavor header and an
// identity token of the audience. It is refused as not reached, and no
// token is requested.
func TestMetadataAnswerHeaderIsBoundedTo64KiB(t *testing.T) {
	const audience = "api://records-reader"
	stub := newTokenStub(t, nil)
	identity := identityFor(t, audience, time.Now().Add(time.Hour), "s")
	stub.federated = func() string { return identity }
	meta := newMetadataStub(t, func() string { return identity })
	meta.answerWith(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Metadata-Flavor", "Google")
		w.Header().Set("X-Padding", strings.Repeat("p", maxHeaderBytes))
		io.WriteString(w, identity)
	})
	cfg := metadataConfig(t, stub, audience)
	if _, err := ObtainSealed(context.Background(), cfg); !refusedWith(err, "could not be reached in time") {
		t.Fatalf("an answer whose header exceeds 64 KiB: %v", err)
	}
	if meta.hits.Load() != 1 || stub.tokenHits.Load() != 0 {
		t.Fatalf("an answer whose header exceeds 64 KiB: %d metadata requests, %d token requests", meta.hits.Load(), stub.tokenHits.Load())
	}
}

// Each token request asks the metadata server anew, and an identity token
// is presented only while more than 60 seconds remain before its exp: one
// that lapses within them is refused, and the renewed one is the next
// request's. An answer that is not an identity token of the audience asked
// is refused, and none of these reach the token endpoint.
func TestMetadataTokenIsPresentedOnlyUntil60SecondsBeforeItsExp(t *testing.T) {
	const audience = "api://records-reader"
	stub := newTokenStub(t, nil)
	var mu sync.Mutex
	current := identityFor(t, audience, time.Now().Add(time.Hour), "first")
	token := func() string { mu.Lock(); defer mu.Unlock(); return current }
	set := func(v string) { mu.Lock(); current = v; mu.Unlock() }
	stub.federated = token
	meta := newMetadataStub(t, token)
	cfg := metadataConfig(t, stub, audience)
	if _, err := ObtainSealed(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	set(identityFor(t, audience, time.Now().Add(identityMargin), "lapsing"))
	if _, err := ObtainSealed(context.Background(), cfg); !refusedWith(err, "answered with an identity token that lapses within 60 seconds") {
		t.Fatalf("a token lapsing within the margin: %v", err)
	}
	renewed := identityFor(t, audience, time.Now().Add(time.Hour), "renewed")
	set(renewed)
	if _, err := ObtainSealed(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	stub.check(t)
	if meta.hits.Load() != 3 || stub.tokenHits.Load() != 2 || stub.assertions[1] != renewed {
		t.Fatalf("each token request asks anew and presents the renewed token: %d metadata, %d token requests", meta.hits.Load(), stub.tokenHits.Load())
	}
	now := time.Now().Add(time.Hour).Unix()
	for name, answer := range map[string]string{
		"another audience":   identityFor(t, "api://another", time.Now().Add(time.Hour), "s"),
		"no aud":             identityJWT(t, map[string]any{"exp": now}),
		"an aud list":        identityJWT(t, map[string]any{"aud": []string{audience}, "exp": now}),
		"no exp":             identityJWT(t, map[string]any{"aud": audience}),
		"an exp as a string": identityJWT(t, map[string]any{"aud": audience, "exp": strconv.FormatInt(now, 10)}),
		"a fractional exp":   identityJWT(t, map[string]any{"aud": audience, "exp": float64(now) + 0.5}),
		"two parts":          "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJ4In0",
		"not base64url":      "eyJhbGciOiJSUzI1NiJ9.e30=.sig",
		"a payload not JSON": "eyJhbGciOiJSUzI1NiJ9.bm90LWpzb24.sig",
		"empty":              "",
	} {
		set(answer)
		want := "answered with no identity token this adapter takes"
		if name == "another audience" {
			want = "answered with an identity token of another audience"
		}
		if _, err := ObtainSealed(context.Background(), cfg); !refusedWith(err, want) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if stub.tokenHits.Load() != 2 {
		t.Fatal("a refused identity token reached the token endpoint")
	}
}

// A 429 or 503 carrying the flavor header is the token step's throttled
// answer (ADR-0029), with the wait it asked for; any other status is no
// credential, naming the status alone.
func TestMetadataThrottledAnswerIsTheTokenStepsThrottling(t *testing.T) {
	const audience = "api://records-reader"
	stub := newTokenStub(t, nil)
	meta := newMetadataStub(t, func() string { return "" })
	cfg := metadataConfig(t, stub, audience)
	for _, c := range []struct {
		status     int
		retryAfter string
		want       *int
	}{{429, "7", ptrInt(7)}, {503, "", nil}} {
		meta.answerWith(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Metadata-Flavor", "Google")
			if c.retryAfter != "" {
				w.Header().Set("Retry-After", c.retryAfter)
			}
			w.WriteHeader(c.status)
			io.WriteString(w, "slow down: the body is never quoted")
		})
		_, err := ObtainSealed(context.Background(), cfg)
		var throttledErr *Throttled
		if !errors.As(err, &throttledErr) || throttledErr.Status != c.status || !reflect.DeepEqual(throttledErr.RetryAfter, c.want) || strings.Contains(err.Error(), "slow down") {
			t.Fatalf("%d: %v", c.status, err)
		}
	}
	for _, status := range []int{404, 500, 204} {
		meta.answerWith(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Metadata-Flavor", "Google")
			w.WriteHeader(status)
		})
		if _, err := ObtainSealed(context.Background(), cfg); !refusedWith(err, "refused the identity token request ("+strconv.Itoa(status)+")") {
			t.Fatalf("%d: %v", status, err)
		}
	}
	if stub.tokenHits.Load() != 0 {
		t.Fatal("a refused metadata request reached the token endpoint")
	}
}

func ptrInt(n int) *int { return &n }

// A metadata server that is not there, or does not answer in time, fails
// the step closed with one fixed sentence.
func TestMetadataServerUnreachableFailsClosed(t *testing.T) {
	const audience = "api://records-reader"
	stub := newTokenStub(t, nil)
	meta := newMetadataStub(t, func() string { return "" })
	cfg := metadataConfig(t, stub, audience)
	meta.answerWith(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := ObtainSealed(ctx, cfg); !refusedWith(err, "could not be reached in time") {
		t.Fatalf("a metadata server that does not answer: %v", err)
	}
	closed := httptest.NewServer(http.NotFoundHandler())
	pointMetadataAt(t, closed.URL)
	closed.Close()
	if _, err := ObtainSealed(context.Background(), cfg); !refusedWith(err, "could not be reached in time") {
		t.Fatalf("a metadata server that is not there: %v", err)
	}
	if stub.tokenHits.Load() != 0 {
		t.Fatal("an unreachable metadata server reached the token endpoint")
	}
}

// Nothing the adapter is given reaches the metadata server's address: the
// step names an audience and no address, the environment variables the
// platform's own client libraries take for another host are not read, and
// the client dials the metadata server's address alone.
func TestMetadataAddressIsReachedFromNothingTheAdapterIsGiven(t *testing.T) {
	const audience = "api://records-reader"
	stub := newTokenStub(t, nil)
	identity := identityFor(t, audience, time.Now().Add(time.Hour), "decoy")
	stub.federated = func() string { return identity }
	decoy := newMetadataStub(t, func() string { return identity })
	closed := httptest.NewServer(http.NotFoundHandler())
	pointMetadataAt(t, closed.URL)
	closed.Close()
	host := strings.TrimPrefix(decoy.server.URL, "http://")
	t.Setenv("GCE_METADATA_HOST", host)
	t.Setenv("GCE_METADATA_IP", host)
	cfg := metadataConfig(t, stub, audience)
	if _, err := ObtainSealed(context.Background(), cfg); !refusedWith(err, "could not be reached in time") {
		t.Fatalf("an environment naming another host: %v", err)
	}
	if decoy.hits.Load() != 0 || stub.tokenHits.Load() != 0 {
		t.Fatal("the environment steered the metadata request")
	}
	// The client dials the metadata server's address and port alone.
	pointMetadataAt(t, decoy.server.URL)
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("another address was dialed") }))
	defer other.Close()
	client, err := metadataClient()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(other.URL + metadataIdentityPath); !errors.Is(err, errMetadataAddress) {
		t.Fatalf("a request to another address: %v", err)
	}
	// The step names the audience, and no member names an address.
	for _, field := range reflect.VisibleFields(reflect.TypeOf(TokenStep{})) {
		if strings.Contains(field.Name, "Metadata") && field.Name != "MetadataAudience" {
			t.Fatalf("TokenStep.%s names more of the metadata server than its audience", field.Name)
		}
	}
}

// The metadata request takes no proxy from the environment, since a proxy
// would carry it off the link. The client's transport has no proxy function
// at all: Go's environment proxy lets a loopback address by, so the
// stand-in's hits alone could not tell. With every proxy variable naming a
// stand-in proxy, the request reaches the metadata server directly and the
// proxy is asked nothing. The request is made with the metadata client
// alone, so no other client of this package reads the proxy variables (Go
// reads them once per process) while they are set.
func TestMetadataRequestTakesNoProxyFromTheEnvironment(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("the proxy was asked") }))
	defer proxy.Close()
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(name, proxy.URL)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	meta := newMetadataStub(t, func() string { return "identity" })
	client, err := metadataClient()
	if err != nil {
		t.Fatal(err)
	}
	if transport, ok := client.Transport.(*http.Transport); !ok || transport.Proxy != nil {
		t.Fatal("the metadata client's transport takes a proxy")
	}
	resp, err := client.Get(metadataBase + metadataIdentityPath)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if meta.hits.Load() != 1 {
		t.Fatalf("the metadata server was asked %d times, not once", meta.hits.Load())
	}
}

// The audience is held to its closed form before anything is read or
// asked, so it can add no query member; one that passes is sent as the one
// audience parameter, percent-encoded. A metadata step is one kind of
// assertion, alone, and needs its sealKey.
func TestMetadataAudienceIsHeldToItsForm(t *testing.T) {
	stub := newTokenStub(t, nil)
	meta := newMetadataStub(t, func() string { return "" })
	step := func(audience string) *TokenStep {
		return &TokenStep{Endpoint: "https://login.example/token", ClientID: "client-7", MetadataAudience: audience}
	}
	for _, good := range []string{"api://TokenExchange", "//iam.example/projects/1/locations/global/pools/p/providers/q", "sts.example", "a.b_c~d:e/f@g-h", strings.Repeat("a", 256)} {
		if _, err := holdTokenStep(step(good)); err != nil {
			t.Fatalf("%q: %v", good, err)
		}
	}
	for _, bad := range []string{strings.Repeat("a", 257), "records&audience=other", "a=b", "a?b", "a#b", "a%26b", "a b", "a+b", "a\nb", "a\x00b", "é", "a,b", "a;b", "a'b", "(a)"} {
		if _, err := holdTokenStep(step(bad)); err == nil || err.Error() != "--federated-token-metadata-audience is 1 to 256 ASCII letters, digits and the characters . _ ~ : / @ -" {
			t.Fatalf("%q: %v", bad, err)
		}
		if _, err := metadataIdentityToken(context.Background(), bad, time.Now()); !refusedWith(err, "was not asked, the audience being out of form") {
			t.Fatalf("%q asked: %v", bad, err)
		}
	}
	exactlyOne := "a token step takes exactly one of --assertion-key, --federated-token-file and --federated-token-metadata-audience"
	for name, s := range map[string]*TokenStep{
		"a key beside it":        {Endpoint: "https://login.example/token", ClientID: "c", KeyMember: "K", MetadataAudience: "api://r"},
		"a file beside it":       {Endpoint: "https://login.example/token", ClientID: "c", FederatedTokenFile: "/run/token", MetadataAudience: "api://r"},
		"all three":              {Endpoint: "https://login.example/token", ClientID: "c", KeyMember: "K", FederatedTokenFile: "/run/token", MetadataAudience: "api://r"},
		"none":                   {Endpoint: "https://login.example/token", ClientID: "c"},
		"a directory beside it":  {Endpoint: "https://login.example/token", ClientID: "c", FederatedTokenDir: "/run", MetadataAudience: "api://r"},
		"a thumbprint beside it": {Endpoint: "https://login.example/token", ClientID: "c", X5T: base64.RawURLEncoding.EncodeToString(make([]byte, 20)), MetadataAudience: "api://r"},
	} {
		_, err := holdTokenStep(s)
		switch name {
		case "a directory beside it":
			if err == nil || !strings.Contains(err.Error(), "--federated-token-dir is the directory of --federated-token-file") {
				t.Fatalf("%s: %v", name, err)
			}
		case "a thumbprint beside it":
			if err == nil || !strings.Contains(err.Error(), "with --assertion-key") {
				t.Fatalf("%s: %v", name, err)
			}
		default:
			if err == nil || err.Error() != exactlyOne {
				t.Fatalf("%s: %v", name, err)
			}
		}
	}
	// The one audience parameter, percent-encoded, is what the server sees.
	const special = "a.b_c~d:e/f@g-h"
	identity := identityFor(t, special, time.Now().Add(time.Hour), "s")
	meta.answerWith(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Metadata-Flavor", "Google")
		io.WriteString(w, identity)
	})
	if token, err := metadataIdentityToken(context.Background(), special, time.Now()); err != nil || token != identity {
		t.Fatalf("%v", err)
	}
	last := meta.requests[len(meta.requests)-1]
	if last.rawQuery != "audience=a.b_c~d%3Ae%2Ff%40g-h&format=full" || !reflect.DeepEqual(last.query, map[string][]string{"audience": {special}, "format": {"full"}}) {
		t.Fatalf("the query: %q", last.rawQuery)
	}
	// No credentials file, and a sealKey absent or short, are no
	// credential, before the metadata server is asked.
	before := meta.hits.Load()
	noFile := metadataConfig(t, stub, "api://records-reader")
	noFile.Credentials = ""
	short := metadataConfig(t, stub, "api://records-reader")
	if err := os.WriteFile(short.Credentials, []byte(`{"sealKey":"`+strings.Repeat("k", minSealKey-1)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	absent := metadataConfig(t, stub, "api://records-reader")
	if err := os.WriteFile(absent.Credentials, []byte(`{"other":"`+testSealKey+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]Config{"no credentials file": noFile, "a short sealKey": short, "no sealKey": absent} {
		if _, err := ObtainSealed(context.Background(), c); failureKind(err) != TokenNoCredential {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if meta.hits.Load() != before || stub.tokenHits.Load() != 0 {
		t.Fatal("a refused configuration asked the metadata server or the token endpoint")
	}
}
