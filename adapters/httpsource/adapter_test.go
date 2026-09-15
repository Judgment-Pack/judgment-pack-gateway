package httpsource

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// endpoint is a stand-in provider over TLS: it records every request it
// received and answers what the test handed it.
type endpoint struct {
	server   *httptest.Server
	caFile   string
	mu       sync.Mutex
	requests []*http.Request
	bodies   [][]byte
	handler  http.HandlerFunc
}

func newEndpoint(t *testing.T, handler http.HandlerFunc) *endpoint {
	t.Helper()
	e := &endpoint{handler: handler}
	e.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		e.mu.Lock()
		e.requests = append(e.requests, r.Clone(context.Background()))
		e.bodies = append(e.bodies, body)
		e.mu.Unlock()
		e.handler(w, r)
	}))
	t.Cleanup(e.server.Close)
	e.caFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(e.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *endpoint) received() []*http.Request {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]*http.Request(nil), e.requests...)
}

func (e *endpoint) peerIdentity() string {
	sum := sha256.Sum256(e.server.Certificate().Raw)
	return "tls:sha256:" + hex.EncodeToString(sum[:])
}

func credentialsFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func (e *endpoint) config(t *testing.T) Config {
	t.Helper()
	return Config{
		Endpoint: e.server.URL, Credentials: credentialsFile(t, `{"TOKEN":"secret-token-value"}`), Bearer: "TOKEN",
		Paths: []string{"/search"}, MaxOutput: 1 << 20, CAFile: e.caFile,
	}
}

func parseRequest(t *testing.T, text string) Request {
	t.Helper()
	req, err := ParseRequest(strings.NewReader(text))
	if err != nil {
		t.Fatalf("request %s: %v", text, err)
	}
	return req
}

func decodeEnvelope(t *testing.T, out []byte) (acquisition map[string]any, result map[string]any) {
	t.Helper()
	var env map[string]json.RawMessage
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("envelope is not JSON: %v\n%s", err, out)
	}
	if len(env) != 2 || env["acquisition"] == nil || env["result"] == nil {
		t.Fatalf("an envelope is exactly acquisition and result: %s", out)
	}
	if err := json.Unmarshal(env["acquisition"], &acquisition); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(env["result"], &result); err != nil {
		t.Fatal(err)
	}
	return acquisition, result
}

func TestAcquireCarriesAJSONAnswerIntoTheCanonDomain(t *testing.T) {
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret-token-value" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("ETag", `"v7"`)
		w.Header().Set("Last-Modified", "Fri, 11 Sep 2026 14:43:20 GMT")
		w.Header().Set("Set-Cookie", "session=never-carried")
		w.Header().Set("Date", "Mon, 14 Sep 2026 12:00:00 GMT")
		io.WriteString(w, `{"results":[{"title":"Policy","score":0.98,"url":"https://example.org/p"}],"response_time":1.5,"count":1}`)
	})
	cfg := e.config(t)
	cfg.Headers = []string{"X-Return-Format=markdown"}
	before := time.Now().UTC().Truncate(time.Second)
	out, err := Acquire(context.Background(), cfg, parseRequest(t, `{"path":"/search","body":{"query":"federal skilled worker","max_results":5}}`))
	if err != nil {
		t.Fatal(err)
	}
	acq, result := decodeEnvelope(t, out)
	adapter := acq["adapter"].(map[string]any)
	exe, _ := os.Executable()
	exe, _ = filepath.EvalSymlinks(exe)
	self, _ := os.ReadFile(exe)
	sum := sha256.Sum256(self)
	if adapter["name"] != adapterName || adapter["version"] != Version || adapter["digest"] != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("the adapter names itself by its own executable's digest: %v", adapter)
	}
	if acq["endpoint"] != e.server.URL+"/search" {
		t.Fatalf("endpoint is the URL sent to: %v", acq["endpoint"])
	}
	if acq["statement"] != `{"body":{"max_results":5,"query":"federal skilled worker"},"method":"POST","path":"/search"}` {
		t.Fatalf("the statement is the request as sent: %v", acq["statement"])
	}
	if acq["snapshot"] != `"v7"` {
		t.Fatalf("the ETag is the snapshot: %v", acq["snapshot"])
	}
	if acq["peerIdentity"] != e.peerIdentity() {
		t.Fatalf("the peer's certificate is the peer identity: %v", acq["peerIdentity"])
	}
	if acq["schema"] != nil || acq["upstreamToken"] != nil {
		t.Fatalf("an HTTP answer carries no schema and no upstream token: %v", acq)
	}
	for _, name := range []string{"adapter", "endpoint", "statement", "snapshot", "peerIdentity", "schema", "upstreamToken", "observedAt"} {
		if _, present := acq[name]; !present {
			t.Fatalf("acquisition member %s is stated, null or not: %v", name, acq)
		}
	}
	if len(acq) != 8 {
		t.Fatalf("an acquisition has exactly the eight members: %v", acq)
	}
	stamp, err := time.Parse(stampLayout, acq["observedAt"].(string))
	if err != nil || stamp.Before(before) || stamp.After(time.Now().Add(time.Second)) {
		t.Fatalf("observedAt is a UTC whole-second stamp of the read: %v %v", acq["observedAt"], err)
	}
	if result["status"] != float64(200) || result["bodyEncoding"] != "json" {
		t.Fatalf("status and encoding: %v", result)
	}
	if !reflect.DeepEqual(result["headers"], map[string]any{
		"content-type": "application/json; charset=utf-8", "etag": `"v7"`, "last-modified": "Fri, 11 Sep 2026 14:43:20 GMT",
		"date": "Mon, 14 Sep 2026 12:00:00 GMT", "content-length": "105",
	}) {
		t.Fatalf("the carried headers, and never a cookie: %v", result["headers"])
	}
	if !reflect.DeepEqual(result["body"], map[string]any{
		"results": []any{map[string]any{"title": "Policy", "score": "0.98", "url": "https://example.org/p"}}, "response_time": "1.5", "count": float64(1),
	}) {
		t.Fatalf("the body, with a non-integer number carried as its text: %v", result["body"])
	}
	if strings.Contains(string(out), "secret-token") {
		t.Fatal("nothing of the credentials reaches the envelope")
	}
	sent := e.received()
	if len(sent) != 1 || sent[0].Method != http.MethodPost || sent[0].URL.Path != "/search" || sent[0].Header.Get("Content-Type") != "application/json" ||
		sent[0].Header.Get("Accept") != "application/json" || sent[0].Header.Get("X-Return-Format") != "markdown" || !strings.HasPrefix(sent[0].Header.Get("User-Agent"), "judgment-pack-adapter-http/") {
		t.Fatalf("the request as sent: %v", sent)
	}
	if string(e.bodies[0]) != `{"max_results":5,"query":"federal skilled worker"}` {
		t.Fatalf("the body as sent is the canonical body: %s", e.bodies[0])
	}
}

func TestAcquireCarriesAnyOtherAnswerAsBase64(t *testing.T) {
	pdf := []byte("%PDF-1.7\n\x00\x01binary\xff")
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Last-Modified", "Fri, 11 Sep 2026 14:43:20 GMT")
		w.Write(pdf)
	})
	cfg := e.config(t)
	cfg.Paths = []string{"/doc.pdf"}
	cfg.Methods = []string{"GET"}
	out, err := Acquire(context.Background(), cfg, parseRequest(t, `{"path":"/doc.pdf","method":"GET","query":{"lang":"en","v":"2"}}`))
	if err != nil {
		t.Fatal(err)
	}
	acq, result := decodeEnvelope(t, out)
	if result["bodyEncoding"] != "base64" || result["body"] != base64.StdEncoding.EncodeToString(pdf) {
		t.Fatalf("bytes carried whole: %v", result)
	}
	if acq["snapshot"] != "Fri, 11 Sep 2026 14:43:20 GMT" {
		t.Fatalf("Last-Modified stands in for a missing ETag: %v", acq["snapshot"])
	}
	if acq["endpoint"] != e.server.URL+"/doc.pdf" || acq["statement"] != `{"method":"GET","path":"/doc.pdf","query":{"lang":"en","v":"2"}}` {
		t.Fatalf("the query is in the statement, not the endpoint: %v %v", acq["endpoint"], acq["statement"])
	}
	sent := e.received()
	if sent[0].URL.RawQuery != "lang=en&v=2" || sent[0].Method != http.MethodGet {
		t.Fatalf("the query as sent: %v", sent[0].URL)
	}
}

func TestAcquireRefusesAPathOrMethodOutsideTheConfigurationBeforeAnyRequest(t *testing.T) {
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{}`) })
	cfg := e.config(t)
	for text, want := range map[string]string{
		`{"path":"/extract","body":{}}`:           `path "/extract" is not one this source may request`,
		`{"path":"/search","method":"GET"}`:       `method GET is not one this source may use`,
		`{"path":"/search/../extract","body":{}}`: ``,
	} {
		req, err := ParseRequest(strings.NewReader(text))
		if want == "" {
			if err == nil {
				t.Fatalf("%s: parsed", text)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Acquire(context.Background(), cfg, req); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: %v", text, err)
		}
	}
	if len(e.received()) != 0 {
		t.Fatal("a refused request never reaches the endpoint")
	}
}

func TestAcquireFailsARefusingAnswerWithItsReasonRedacted(t *testing.T) {
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":"the key secret-token-value is not valid"}`)
	})
	_, err := Acquire(context.Background(), e.config(t), parseRequest(t, `{"path":"/search","body":{}}`))
	if err == nil || !strings.Contains(err.Error(), "the endpoint answered 401 Unauthorized") || !strings.Contains(err.Error(), "[redacted]") || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("a refusal names the status and its reason, redacted: %v", err)
	}
}

func TestAcquireNeverFollowsARedirect(t *testing.T) {
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/search" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		io.WriteString(w, `{}`)
	})
	_, err := Acquire(context.Background(), e.config(t), parseRequest(t, `{"path":"/search","body":{}}`))
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("a redirect is reported: %v", err)
	}
	for _, r := range e.received() {
		if r.URL.Path != "/search" {
			t.Fatalf("the redirect target was requested: %s", r.URL)
		}
	}
}

func TestAcquireHoldsTheOutputBound(t *testing.T) {
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"text":"`+strings.Repeat("x", 3000)+`"}`)
	})
	cfg := e.config(t)
	cfg.MaxOutput = 2048
	_, err := Acquire(context.Background(), cfg, parseRequest(t, `{"path":"/search","body":{}}`))
	if err == nil || !strings.Contains(err.Error(), "exceeds the output bound of 2048 bytes") {
		t.Fatalf("an answer past the bound is refused, not cut: %v", err)
	}
	cfg.MaxOutput = 3200
	_, err = Acquire(context.Background(), cfg, parseRequest(t, `{"path":"/search","body":{}}`))
	if err == nil || !strings.Contains(err.Error(), "the envelope exceeds the output bound") {
		t.Fatalf("the envelope as a whole is bounded too: %v", err)
	}
}

func TestAcquireReportsTheDeadline(t *testing.T) {
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := Acquire(ctx, e.config(t), parseRequest(t, `{"path":"/search","body":{}}`))
	if err == nil || !strings.Contains(err.Error(), "did not answer in time") {
		t.Fatalf("the deadline is reported as such: %v", err)
	}
}

func TestAcquireRefusesAnAnswerOutsideTheCanonDomain(t *testing.T) {
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"a":1,"a":2}`)
	})
	_, err := Acquire(context.Background(), e.config(t), parseRequest(t, `{"path":"/search","body":{}}`))
	if err == nil || !strings.Contains(err.Error(), "not JSON in the canonical domain") {
		t.Fatalf("a duplicate member is refused, never repaired: %v", err)
	}
}

func TestParseRequestIsStrict(t *testing.T) {
	for text, want := range map[string]string{
		`{"path":"/search","body":{}} trailing`:      "trailing content",
		`{"path":"/search","extra":1}`:               `unknown member "extra"`,
		`{"path":"/search","PATH":"/x"}`:             `unknown member "PATH"`,
		`{"body":{}}`:                                `"path" is required`,
		`{"path":"search"}`:                          `"path" must begin with "/"`,
		`{"path":"/search?x=1"}`:                     `carries a query`,
		`{"path":"/a//b"}`:                           `empty segment`,
		`{"path":"/search","method":"post"}`:         `must be GET or POST, spelled so`,
		`{"path":"/search","method":"DELETE"}`:       `must be GET or POST`,
		`{"path":"/search","method":"GET","body":1}`: `a GET carries no body`,
		`{"path":"/search","query":{"k":1}}`:         `"query" must be an object of strings`,
		`{"path":"/search","query":{"":"v"}}`:        `non-empty names`,
		`{"path":"/search","body":{"n":1.5}}`:        `outside the canon domain`,
		`{"path":"/search","path":"/x"}`:             `duplicate member name`,
		`[]`:                                         `not a JSON object`,
	} {
		if _, err := ParseRequest(strings.NewReader(text)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", text, err, want)
		}
	}
	req := parseRequest(t, `{"path":"/"}`)
	if req.Method != http.MethodPost || req.Body != nil || req.Query != nil {
		t.Fatalf("defaults: %+v", req)
	}
}

func TestConfigurationRefusals(t *testing.T) {
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{}`) })
	base := e.config(t)
	cases := map[string]struct {
		change func(*Config)
		want   string
	}{
		"no endpoint":             {func(c *Config) { c.Endpoint = "" }, "an endpoint is required"},
		"plaintext off loopback":  {func(c *Config) { c.Endpoint = "http://api.example" }, "http is accepted on a loopback host only"},
		"user in endpoint":        {func(c *Config) { c.Endpoint = "https://user:pw@api.example" }, "carries a user"},
		"query in endpoint":       {func(c *Config) { c.Endpoint = "https://api.example/?k=v" }, "carries a query or a fragment"},
		"no paths":                {func(c *Config) { c.Paths = nil }, "--paths must name"},
		"bad path":                {func(c *Config) { c.Paths = []string{"search"} }, `--paths "search"`},
		"bad method":              {func(c *Config) { c.Methods = []string{"PUT"} }, "GET and POST are the methods"},
		"no bound":                {func(c *Config) { c.MaxOutput = 0 }, "max-output must be positive"},
		"bound past the ceiling":  {func(c *Config) { c.MaxOutput = 1<<63 - 1 }, "at most"},
		"content-type header":     {func(c *Config) { c.Headers = []string{"Content-Type=text/plain"} }, "written by the adapter itself"},
		"user-agent header":       {func(c *Config) { c.Headers = []string{"User-Agent=custom"} }, "written by the adapter itself"},
		"accept-encoding header":  {func(c *Config) { c.Headers = []string{"Accept-Encoding=gzip"} }, "written by the adapter itself"},
		"credential header":       {func(c *Config) { c.Headers = []string{"Authorization=Bearer x"} }, "a credential's; it goes in the credentials file"},
		"bad header":              {func(c *Config) { c.Headers = []string{"no-equals"} }, "is not NAME=VALUE"},
		"both credential forms":   {func(c *Config) { c.CredentialHeader = "X-Api-Key=TOKEN" }, "not both"},
		"member absent":           {func(c *Config) { c.Bearer = "OTHER" }, "does not carry the member"},
		"file without member":     {func(c *Config) { c.Bearer = "" }, "neither --bearer nor --credential-header"},
		"member without file":     {func(c *Config) { c.Credentials = "" }, "no --credentials file"},
		"credentials not object":  {func(c *Config) { c.Credentials = credentialsFile(t, `["x"]`) }, "not a JSON object of strings"},
		"credentials not strings": {func(c *Config) { c.Credentials = credentialsFile(t, `{"TOKEN":1}`) }, "not a string"},
		"credentials duplicate":   {func(c *Config) { c.Credentials = credentialsFile(t, `{"TOKEN":"a","TOKEN":"b"}`) }, "member name twice"},
		"credentials missing":     {func(c *Config) { c.Credentials = filepath.Join(t.TempDir(), "none") }, "could not be read"},
		"ca file missing":         {func(c *Config) { c.CAFile = filepath.Join(t.TempDir(), "none") }, "--ca-file could not be read"},
		"ca file empty":           {func(c *Config) { c.CAFile = credentialsFile(t, "") }, "carries no certificate"},
	}
	for name, tc := range cases {
		cfg := base
		cfg.Paths = append([]string(nil), base.Paths...)
		tc.change(&cfg)
		_, err := Acquire(context.Background(), cfg, Request{Path: "/search", Method: http.MethodPost})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
		if strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), "TOKEN") {
			t.Errorf("%s: a refusal names no member and no value: %v", name, err)
		}
	}
	if len(e.received()) != 0 {
		t.Fatal("a refused configuration never reaches the endpoint")
	}
}

func TestCredentialHeaderAndNoCredentialAtAll(t *testing.T) {
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	})
	cfg := e.config(t)
	cfg.Bearer, cfg.CredentialHeader = "", "X-Subscription-Token=TOKEN"
	if _, err := Acquire(context.Background(), cfg, parseRequest(t, `{"path":"/search","body":{}}`)); err != nil {
		t.Fatal(err)
	}
	// A keyless endpoint: no file, no member, nothing sent.
	cfg.Credentials, cfg.CredentialHeader = "", ""
	if _, err := Acquire(context.Background(), cfg, parseRequest(t, `{"path":"/search","body":{}}`)); err != nil {
		t.Fatal(err)
	}
	sent := e.received()
	if sent[0].Header.Get("X-Subscription-Token") != "secret-token-value" || sent[0].Header.Get("Authorization") != "" {
		t.Fatalf("the credential goes under the named header: %v", sent[0].Header)
	}
	if sent[1].Header.Get("X-Subscription-Token") != "" || sent[1].Header.Get("Authorization") != "" {
		t.Fatalf("a keyless source sends no credential: %v", sent[1].Header)
	}
}

func TestPlaintextLoopbackRecordsNoPeerIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	defer server.Close()
	cfg := Config{Endpoint: server.URL, Paths: []string{"/"}, MaxOutput: 1 << 20}
	out, err := Acquire(context.Background(), cfg, parseRequest(t, `{"path":"/","body":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	acq, _ := decodeEnvelope(t, out)
	if acq["peerIdentity"] != nil {
		t.Fatalf("no TLS, no peer identity: %v", acq["peerIdentity"])
	}
}

func TestBasePathIsKeptUnderTheEndpoint(t *testing.T) {
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"path":"`+r.URL.Path+`"}`)
	})
	cfg := e.config(t)
	cfg.Endpoint = e.server.URL + "/v2/"
	cfg.Paths = []string{"/search"}
	out, err := Acquire(context.Background(), cfg, parseRequest(t, `{"path":"/search","body":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	acq, result := decodeEnvelope(t, out)
	if result["body"].(map[string]any)["path"] != "/v2/search" || acq["endpoint"] != e.server.URL+"/v2/search" {
		t.Fatalf("the request path follows the base path: %v %v", result, acq["endpoint"])
	}
}

func TestCheckReachesTheEndpoint(t *testing.T) {
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" && r.Method == http.MethodGet && r.Header.Get("Authorization") == "Bearer secret-token-value" {
			io.WriteString(w, "ok")
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	cfg := e.config(t)
	out, err := Check(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]map[string]any
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatal(err)
	}
	check := report["check"]
	if check["status"] != "succeeded" || check["endpoint"] != e.server.URL || check["peerIdentity"] != e.peerIdentity() || check["probe"] != nil {
		t.Fatalf("a handshake check: %v", check)
	}
	if len(e.received()) != 0 {
		t.Fatal("a handshake check requests nothing")
	}
	cfg.CheckPath = "/health"
	out, err = Check(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatal(err)
	}
	if probe, _ := report["check"]["probe"].(map[string]any); probe["path"] != "/health" || probe["status"] != float64(200) {
		t.Fatalf("a probed check reports the path and its status: %v", report)
	}
	cfg.CheckPath = "/broken"
	if _, err := Check(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "answered 500") {
		t.Fatalf("a probe that did not answer 2xx fails the check: %v", err)
	}
	if !strings.HasPrefix(string(FailedCheck("why")), `{"check":{"message":"why","status":"failed"}}`) {
		t.Fatalf("FailedCheck: %s", FailedCheck("why"))
	}
}

func TestAcquireRefusesAnAnswerThatRepeatsTheCredential(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"in the JSON body": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"echo":"secret-token-value"}`)
		},
		"escaped in the JSON body": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"echo":"secret\u002dtoken\u002dvalue"}`)
		},
		"in the ETag": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", `"secret-token-value"`)
			io.WriteString(w, `{}`)
		},
		"in raw bytes": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/pdf")
			io.WriteString(w, "%PDF secret-token-value")
		},
	} {
		e := newEndpoint(t, handler)
		out, err := Acquire(context.Background(), e.config(t), parseRequest(t, `{"path":"/search","body":{}}`))
		if err == nil || out != nil || !strings.Contains(err.Error(), "repeats a credential") || strings.Contains(err.Error(), "secret-token") {
			t.Fatalf("%s: %v %s", name, err, out)
		}
	}
}

func TestRefusalDiagnosticIsRedactedBeforeItIsTrimmed(t *testing.T) {
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, "TOPSECRET ")
	})
	cfg := e.config(t)
	cfg.Credentials = credentialsFile(t, `{"TOKEN":"TOPSECRET "}`)
	_, err := Acquire(context.Background(), cfg, parseRequest(t, `{"path":"/search","body":{}}`))
	if err == nil || strings.Contains(err.Error(), "TOPSECRET") || !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("a credential ending in whitespace is matched whole: %v", err)
	}
}

func TestAcquireAsksForNoEncodingAndRefusesAnEncodedAnswer(t *testing.T) {
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		io.WriteString(zw, `{"ok":true}`)
		zw.Close()
	})
	_, err := Acquire(context.Background(), e.config(t), parseRequest(t, `{"path":"/search","body":{}}`))
	if err == nil || !strings.Contains(err.Error(), `content-encoding "gzip"`) {
		t.Fatalf("an encoded answer is refused, never decoded: %v", err)
	}
	if sent := e.received(); sent[0].Header.Get("Accept-Encoding") != "" {
		t.Fatalf("the adapter asked for an encoding: %v", sent[0].Header)
	}
}

// untrustedEndpoint is a TLS server under a certificate freshly made here, so
// it is trusted by no --ca-file a test wrote for another server: httptest's
// own servers all share one certificate, and a second of those would be
// trusted by the first's CA file.
func untrustedEndpoint(t *testing.T) *endpoint {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "other"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	e := &endpoint{handler: func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}}
	e.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.requests = append(e.requests, r.Clone(context.Background()))
		e.mu.Unlock()
		e.handler(w, r)
	}))
	e.server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	e.server.StartTLS()
	t.Cleanup(e.server.Close)
	return e
}

func TestAcquireRefusesAnUntrustedCertificate(t *testing.T) {
	trusted := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{}`) })
	other := untrustedEndpoint(t)
	cfg := trusted.config(t)
	cfg.Endpoint = other.server.URL
	_, err := Acquire(context.Background(), cfg, parseRequest(t, `{"path":"/search","body":{}}`))
	if err == nil || !strings.Contains(err.Error(), "could not be reached") || !strings.Contains(strings.ToLower(err.Error()), "certificate") {
		t.Fatalf("a certificate outside --ca-file is refused: %v", err)
	}
	if len(other.received()) != 0 {
		t.Fatal("the request reached an endpoint whose certificate was not trusted")
	}
	if _, err := Check(context.Background(), cfg); err == nil || !strings.Contains(strings.ToLower(err.Error()), "certificate") {
		t.Fatalf("a check refuses it too: %v", err)
	}
}

// loopbackBuffering is the most a loopback connection holds between a writer
// and a reader that has stopped reading: the writer's send buffer and the
// reader's receive buffer, each at its ceiling on this platform. Linux states
// both ceilings; elsewhere a generous figure stands in.
func loopbackBuffering() int64 {
	var total int64
	for _, name := range []string{"/proc/sys/net/ipv4/tcp_wmem", "/proc/sys/net/ipv4/tcp_rmem"} {
		data, err := os.ReadFile(name)
		fields := strings.Fields(string(data))
		if err != nil || len(fields) != 3 {
			return 64 << 20
		}
		ceiling, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			return 64 << 20
		}
		total += ceiling
	}
	return total
}

// Reading stops at the bound. What the endpoint manages to write is the
// adapter's reading plus whatever the connection's two ends buffer after the
// adapter stops, and the kernel sizes those buffers as it sees fit up to their
// ceilings -- so the allowance is the bound, both ceilings and the chunk in
// hand, not a round figure the buffering can outgrow. An adapter that kept
// reading would take everything: the endpoint stops at twice the allowance, so
// such an adapter fails here rather than reading forever.
func TestReadingStopsAtTheBound(t *testing.T) {
	const maxOutput = 256 << 10
	chunk := bytes.Repeat([]byte("x"), 64<<10)
	allowance := int64(maxOutput) + loopbackBuffering() + int64(len(chunk))
	var written int64
	var mu sync.Mutex
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		flusher, _ := w.(http.Flusher)
		for {
			mu.Lock()
			enough := written >= 2*allowance
			mu.Unlock()
			if enough {
				return
			}
			n, err := w.Write(chunk)
			mu.Lock()
			written += int64(n)
			mu.Unlock()
			if err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
			select {
			case <-r.Context().Done():
				return
			default:
			}
		}
	})
	cfg := e.config(t)
	cfg.MaxOutput = maxOutput
	_, err := Acquire(context.Background(), cfg, parseRequest(t, `{"path":"/search","body":{}}`))
	if err == nil || !strings.Contains(err.Error(), "exceeds the output bound") {
		t.Fatalf("%v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if written > allowance {
		t.Fatalf("the adapter kept reading past its bound: %d bytes were written, past the %d a stopped reader allows", written, allowance)
	}
}

func TestCheckDialsAPlaintextLoopbackEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	cfg := Config{Endpoint: server.URL, Paths: []string{"/"}, MaxOutput: 1 << 20}
	if _, err := Check(context.Background(), cfg); err != nil {
		t.Fatalf("a listening port: %v", err)
	}
	server.Close()
	if _, err := Check(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "could not be reached") {
		t.Fatalf("a closed port fails the check: %v", err)
	}
}

func TestSecretsReadsTheCredentialsFileForRedaction(t *testing.T) {
	cfg := Config{Credentials: credentialsFile(t, `{"TOKEN":"secret-token-value","OTHER":"x"}`)}
	secrets := Secrets(cfg)
	if !contains(secrets, "secret-token-value") || !contains(secrets, "x") {
		t.Fatalf("secrets: %v", secrets)
	}
	if Secrets(Config{}) != nil || Secrets(Config{Credentials: filepath.Join(t.TempDir(), "none")}) != nil {
		t.Fatal("no file, no secrets")
	}
}
