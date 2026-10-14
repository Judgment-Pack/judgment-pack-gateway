package mcp

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"adapters/internal/fakemcp"
	"adapters/internal/redact"
)

// The remote form's markers: the credential --bearer sends, another member
// of the same file that is never sent, and the session id the server
// issues. None of them may reach an envelope, a report or a diagnostic.
const (
	bearerMarker  = "bearer-marker-6f1c2a9e"
	otherMarker   = "other-marker-0b7d4c11"
	sessionMarker = "session-marker-5e3a77d0"
)

// remote starts the in-process Streamable HTTP server -- over TLS, with its
// certificate as the configuration's --ca-file, or in the clear on
// loopback -- and returns it with a configuration that reaches it with the
// bearer credential.
func remote(t *testing.T, overTLS bool, script fakemcp.Script) (*fakemcp.HTTPServer, Config) {
	t.Helper()
	if script.Session == "" {
		script.Session = sessionMarker
	}
	srv := fakemcp.NewHTTP(overTLS, script)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	credentials := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(credentials, []byte(`{"OTHER":"`+otherMarker+`","TOKEN":"`+bearerMarker+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{URL: srv.URL, Credentials: credentials, Bearer: "TOKEN", MaxOutput: 1 << 20}
	if overTLS {
		cfg.CAFile = filepath.Join(dir, "ca.pem")
		if err := srv.WriteCA(cfg.CAFile); err != nil {
			t.Fatal(err)
		}
	}
	return srv, cfg
}

func within(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// noMarker fails the test when any text holds the credential, the other
// member of its file, or the session id.
func noMarker(t *testing.T, what string, texts ...string) {
	t.Helper()
	for _, text := range texts {
		for _, marker := range []string{bearerMarker, otherMarker, sessionMarker} {
			if strings.Contains(text, marker) {
				t.Fatalf("%s carries %q: %s", what, marker, text)
			}
		}
	}
}

func selfIdentity(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// A remote acquisition: one session -- initialize, the client initialized,
// the tool list, the one call, the session ended -- at the URL exactly as
// configured, the credential from the member --bearer names on every
// request, the session id on every request after initialize and nowhere
// in the record; and the acquisition names the transport, the URL, the
// TLS identity the answer came under, and the server as it named itself,
// with this adapter as the adapter.
func TestRemoteAcquireCallsOneToolAndRecordsTheAcquisition(t *testing.T) {
	srv, cfg := remote(t, true, fakemcp.Script{})
	cfg.Tools = []string{"query"}
	out, err := Acquire(within(t), cfg, query("select 1"))
	if err != nil {
		t.Fatal(err)
	}
	noMarker(t, "the envelope", string(out))
	acq, result := decode(t, out)
	if string(result) != `{"content":[{"text":"1 row","type":"text"}],"structuredContent":{"rows":[{"amount":"12.5","id":101}]}}` {
		t.Fatalf("the result is the tool's whole answer, canonical, as the stdio form carries it: %s", result)
	}
	if len(acq) != 10 {
		t.Fatalf("the eight members and transport and server: %v", acq)
	}
	adapter := acq["adapter"].(map[string]any)
	if adapter["name"] != "adapter-mcp" || adapter["version"] != Version || adapter["digest"] != selfIdentity(t) {
		t.Fatalf("the adapter is this program, pinned by its own digest: %v", adapter)
	}
	leaf := sha256.Sum256(srv.Leaf())
	if acq["transport"] != "http" || acq["endpoint"] != srv.URL || acq["peerIdentity"] != "tls:sha256:"+hex.EncodeToString(leaf[:]) {
		t.Fatalf("transport, the URL as configured, and the TLS identity the answer came under: %v", acq)
	}
	if server := acq["server"].(map[string]any); server["name"] != "fake-remote-mcp" || server["version"] != "2.0" || len(server) != 2 {
		t.Fatalf("the server as its initialize answer named it: %v", server)
	}
	schemaSum := sha256.Sum256([]byte(queryOutputSchema))
	if acq["statement"] != `{"arguments":{"sql":"select 1"},"tool":"query"}` || acq["schema"] != "sha256:"+hex.EncodeToString(schemaSum[:]) ||
		acq["snapshot"] != nil || acq["upstreamToken"] != nil || !stampForm.MatchString(acq["observedAt"].(string)) {
		t.Fatalf("the call, the schema and the stamp as the stdio form records them: %v", acq)
	}
	if got := strings.Join(srv.Methods(), " "); got != "initialize notifications/initialized tools/list tools/call DELETE" {
		t.Fatalf("one session, one call, ended: %s", got)
	}
	for i, r := range srv.Requests() {
		if r.Path != "/mcp" {
			t.Fatalf("request %d went to %q: the URL is used as written, nothing appended", i, r.Path)
		}
		if r.Header.Get("Authorization") != "Bearer "+bearerMarker || len(r.Header.Values("Authorization")) != 1 {
			t.Fatalf("request %d: the member --bearer names, as the bearer: %q", i, r.Header.Values("Authorization"))
		}
		if session := r.Header.Get("Mcp-Session-Id"); (i == 0) != (session == "") || (i > 0 && session != sessionMarker) {
			t.Fatalf("request %d: the session id on every request after initialize: %q", i, session)
		}
		if version := r.Header.Get("Mcp-Protocol-Version"); i > 0 && version != "2025-06-18" {
			t.Fatalf("request %d: the negotiated version: %q", i, version)
		}
	}
	var call struct {
		Params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	json.Unmarshal(srv.Requests()[3].Body, &call)
	if call.Params.Name != "query" || string(call.Params.Arguments) != `{"sql":"select 1"}` {
		t.Fatalf("the call carries the tool and the arguments: %s", srv.Requests()[3].Body)
	}
}

// Over plaintext loopback no transport identity is established, and the
// record says so; the server's answers as an event stream are read as JSON
// answers are.
func TestRemoteAcquireOverLoopbackAndEvents(t *testing.T) {
	srv, cfg := remote(t, false, fakemcp.Script{Events: true})
	out, err := Acquire(within(t), cfg, query("select 1"))
	if err != nil {
		t.Fatal(err)
	}
	acq, _ := decode(t, out)
	if acq["transport"] != "http" || acq["endpoint"] != srv.URL || acq["peerIdentity"] != nil || !strings.HasPrefix(srv.URL, "http://127.0.0.1:") {
		t.Fatalf("plaintext loopback: the URL, and no peer identity: %v", acq)
	}
}

// The form's rules, each refused before anything is sent: the fake counts
// what it was sent, and the credential is in no refusal.
func TestRemoteFormRulesAreHeldBeforeAnythingIsSent(t *testing.T) {
	for _, tc := range []struct {
		name  string
		edit  func(*Config)
		req   Request
		refus string
	}{
		{"with an image", func(c *Config) { c.Image = "ghcr.io/example/mcp:1@" + testDigest; c.Runtime = "docker" }, query("select 1"), "exactly one of --image, --url"},
		{"with a command", func(c *Config) { c.Command = []string{os.Args[0]} }, query("select 1"), "takes no command and no arguments"},
		{"with server arguments", func(c *Config) { c.Args = []string{"--mode"} }, query("select 1"), "takes no command and no arguments"},
		{"with an endpoint", func(c *Config) { c.Endpoint = "warehouse.internal:5432" }, query("select 1"), "a remote server's endpoint is its --url"},
		{"http off loopback", func(c *Config) { c.URL = "http://mcp.example/mcp" }, query("select 1"), "http is accepted at a loopback address"},
		{"http at a name for loopback", func(c *Config) { c.URL = strings.Replace(c.URL, "https://127.0.0.1", "http://localhost", 1) }, query("select 1"), "http is accepted at a loopback address"},
		{"a user", func(c *Config) { c.URL = strings.Replace(c.URL, "https://", "https://user:pw@", 1) }, query("select 1"), "carries a user"},
		{"a query", func(c *Config) { c.URL += "?key=" + bearerMarker }, query("select 1"), "carries a query or a fragment"},
		{"a fragment", func(c *Config) { c.URL += "#x" }, query("select 1"), "carries a query or a fragment"},
		{"a scheme in upper case", func(c *Config) { c.URL = strings.Replace(c.URL, "https://", "HTTPS://", 1) }, query("select 1"), "must begin https://"},
		{"another scheme", func(c *Config) { c.URL = strings.Replace(c.URL, "https://", "wss://", 1) }, query("select 1"), "must begin https://"},
		{"credentials without --bearer", func(c *Config) { c.Bearer = "" }, query("select 1"), "--bearer names no member"},
		{"--bearer without credentials", func(c *Config) { c.Credentials = "" }, query("select 1"), "no --credentials file"},
		{"a member the file lacks", func(c *Config) { c.Bearer = "MISSING" }, query("select 1"), "does not carry the member --bearer names"},
		{"Authorization fixed", func(c *Config) { c.Headers = []string{"Authorization=Bearer x"} }, query("select 1"), "--header Authorization is a credential's"},
		{"Mcp-Session-Id fixed", func(c *Config) { c.Headers = []string{"Mcp-Session-Id=abc"} }, query("select 1"), "--header Mcp-Session-Id is the protocol's"},
		{"Content-Type fixed", func(c *Config) { c.Headers = []string{"content-type=text/plain"} }, query("select 1"), "--header content-type is the client's"},
		{"Accept fixed", func(c *Config) { c.Headers = []string{"Accept=*/*"} }, query("select 1"), "--header Accept is the client's"},
		{"Host fixed", func(c *Config) { c.Headers = []string{"Host=elsewhere.example"} }, query("select 1"), "--header Host is the transport's"},
		{"a header that is no pair", func(c *Config) { c.Headers = []string{"X-MCP-Readonly"} }, query("select 1"), "is not NAME=VALUE"},
		{"a tool outside --tools", func(c *Config) { c.Tools = []string{"query"} }, Request{Tool: "drop_table", Arguments: json.RawMessage(`{}`)}, `tool "drop_table" is not one this source may call`},
		{"a CA file with no certificate", func(c *Config) { os.WriteFile(c.CAFile, []byte("not a certificate"), 0o600) }, query("select 1"), "--ca-file carries no certificate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, cfg := remote(t, true, fakemcp.Script{})
			tc.edit(&cfg)
			_, err := Acquire(within(t), cfg, tc.req)
			if err == nil || !strings.Contains(err.Error(), tc.refus) {
				t.Fatalf("want a refusal saying %q, got %v", tc.refus, err)
			}
			noMarker(t, "the refusal", err.Error())
			if n := len(srv.Requests()); n != 0 {
				t.Fatalf("%d request(s) sent for a configuration refused", n)
			}
			// The check holds the same rules the same way.
			_, err = Check(within(t), cfg)
			if tc.req.Tool == "query" && (err == nil || !strings.Contains(err.Error(), tc.refus)) {
				t.Fatalf("the check: want a refusal saying %q, got %v", tc.refus, err)
			}
		})
	}
	// What only a remote server takes is refused beside a stdio one.
	for _, edit := range []func(*Config){
		func(c *Config) { c.Bearer = "TOKEN" },
		func(c *Config) { c.Headers = []string{"X-MCP-Readonly=true"} },
		func(c *Config) { c.CAFile = "/nonexistent" },
	} {
		cfg := fake(t)
		edit(&cfg)
		mustFail(t, cfg, query("select 1"), "are for a remote server, given by --url")
	}
}

// A fixed header is sent on every request as written; it is the
// operator's to send and nothing in the record claims it.
func TestRemoteFixedHeadersAreSentAsWritten(t *testing.T) {
	srv, cfg := remote(t, true, fakemcp.Script{})
	cfg.Headers = []string{"X-MCP-Readonly=true", "X-Trace=a=b"}
	out, err := Acquire(within(t), cfg, query("select 1"))
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range srv.Requests() {
		if r.Header.Get("X-MCP-Readonly") != "true" || r.Header.Get("X-Trace") != "a=b" {
			t.Fatalf("request %d lacks the fixed headers: %v", i, r.Header)
		}
	}
	if strings.Contains(string(out), "Readonly") {
		t.Fatalf("the record claims nothing of a header: %s", out)
	}
}

// What a server answers instead of a result: a redirect, named by its
// status and never followed or located; a refusal at the HTTP level or in
// JSON-RPC, in the server's words, redacted; a body that is not JSON, or
// of another content type; an answer that repeats the credential. None
// carries the credential, the other member or the session id.
func TestRemoteAnswersThatAreNotResults(t *testing.T) {
	elsewhere := fakemcp.NewHTTP(true, fakemcp.Script{})
	defer elsewhere.Close()
	answer := func(status int, header, contentType, body string) func(http.ResponseWriter, string, json.RawMessage) bool {
		return func(w http.ResponseWriter, method string, id json.RawMessage) bool {
			if method != "tools/call" && status != http.StatusTemporaryRedirect {
				return false
			}
			if header != "" {
				name, value, _ := strings.Cut(header, ": ")
				w.Header().Set(name, value)
			}
			if contentType != "" {
				w.Header().Set("Content-Type", contentType)
			}
			w.WriteHeader(status)
			fmt.Fprint(w, strings.ReplaceAll(body, "{id}", string(id)))
			return true
		}
	}
	for _, tc := range []struct {
		name   string
		script fakemcp.Script
		refus  string
	}{
		{"a redirect", fakemcp.Script{Answer: answer(http.StatusTemporaryRedirect, "Location: "+elsewhere.URL+"?to="+otherMarker, "", "")},
			"the server answered 307 Temporary Redirect, a redirect, which is not followed"},
		{"a refusal by status", fakemcp.Script{Answer: answer(http.StatusForbidden, "", "text/plain", "forbidden for "+otherMarker)}, "the server answered 403 Forbidden"},
		{"a refusal in JSON-RPC", fakemcp.Script{Refuse: `{"code":-32000,"message":"permission denied for ` + otherMarker + `"}`},
			"the server answered with an error: permission denied for [redacted] (code -32000)"},
		{"a refusal as an error result", fakemcp.Script{Result: `{"content":[{"type":"text","text":"not permitted: ` + otherMarker + `"}],"isError":true}`},
			"the tool reported an error: not permitted: [redacted]"},
		{"a body that is not JSON", fakemcp.Script{Answer: answer(http.StatusOK, "", "application/json", "Connected to database")}, "is not a JSON message"},
		{"a body of another content type", fakemcp.Script{Answer: answer(http.StatusOK, "", "text/html", "<html></html>")},
			"neither application/json nor text/event-stream"},
		{"an answer repeating the credential", fakemcp.Script{Result: `{"content":[{"type":"text","text":"token ` + bearerMarker + `"}]}`},
			"the server's answer repeats the credential"},
		{"an answer repeating the credential escaped", fakemcp.Script{Result: `{"content":[{"type":"text","text":"token b` + bearerMarker[1:] + `"}]}`},
			"the server's answer repeats the credential"},
		{"a response to another request", fakemcp.Script{Answer: answer(http.StatusOK, "", "application/json", `{"jsonrpc":"2.0","id":99,"result":{}}`)},
			"answered another request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, cfg := remote(t, true, tc.script)
			_, err := Acquire(within(t), cfg, query("select 1"))
			if err == nil || !strings.Contains(err.Error(), tc.refus) {
				t.Fatalf("want %q, got %v", tc.refus, err)
			}
			noMarker(t, "the refusal", err.Error())
			if strings.Contains(err.Error(), elsewhere.URL) || strings.Contains(err.Error(), "Location") {
				t.Fatalf("a redirect is named by its status, not its location: %v", err)
			}
		})
	}
	if n := len(elsewhere.Requests()); n != 0 {
		t.Fatalf("a redirect was followed: the server it named was sent %d request(s)", n)
	}
	// An executor's refusal is the target's answer, enveloped.
	_, cfg := remote(t, true, fakemcp.Script{Result: `{"content":[{"type":"text","text":"refused"}],"isError":true}`})
	cfg.ErrorResults = true
	out, err := Acquire(within(t), cfg, query("update t set x = 1"))
	if err != nil || !strings.Contains(string(out), `"isError":true`) {
		t.Fatalf("an error result enveloped for an executor: %s %v", out, err)
	}
}

// pad is a tool result of exactly n bytes as the server writes it.
func pad(t *testing.T, n int) string {
	t.Helper()
	head, tail := `{"content":[{"type":"text","text":"`, `"}]}`
	if n < len(head)+len(tail) {
		t.Fatalf("a result of %d bytes is too short to write", n)
	}
	return head + strings.Repeat("x", n-len(head)-len(tail)) + tail
}

// The output bound holds a remote result as it holds a stdio one: a result
// at the bound is read, one byte past it is refused, never cut. The check's
// probe, whose result is discarded, shows the result at the bound read;
// the acquisition, the one past it refused for what it is.
func TestRemoteOutputBound(t *testing.T) {
	const bound = 4096
	for _, n := range []int{bound, bound + 1} {
		_, cfg := remote(t, true, fakemcp.Script{Result: pad(t, n)})
		cfg.MaxOutput, cfg.Probe, cfg.Tools = bound, "query", []string{"query"}
		report, err := Check(within(t), cfg)
		if n == bound && (err != nil || !strings.Contains(string(report), `"probe":{"tool":"query","answered":true}`)) {
			t.Fatalf("a result at the bound is read: %s %v", report, err)
		}
		if n > bound && (err == nil || !strings.Contains(err.Error(), fmt.Sprintf("the probe's result exceeds the output bound of %d bytes", bound))) {
			t.Fatalf("a result past the bound is refused: %v", err)
		}
		_, err = Acquire(within(t), cfg, query("select 1"))
		if n > bound && (err == nil || !strings.Contains(err.Error(), fmt.Sprintf("the tool's result exceeds the output bound of %d bytes", bound))) {
			t.Fatalf("an acquisition past the bound is refused for its result: %v", err)
		}
	}
}

// A check over HTTP: the handshake, the server's name and version, the
// tool list held to the same rules, and the transport, the endpoint and
// the TLS identity reported; nothing called, the session id nowhere; and
// descriptors captured as for stdio, the snapshot naming the endpoint it
// was captured at, so a pin is of that one server.
func TestRemoteCheckReportsTheServerAndItsTools(t *testing.T) {
	srv, cfg := remote(t, true, fakemcp.Script{})
	cfg.Tools = []string{"query"}
	cfg.Descriptors = &DescriptorTarget{Platform: "warehouse", Binding: "remote@" + testDigest}
	out, err := Check(within(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	noMarker(t, "the report", string(out))
	var report struct {
		Check struct {
			Status       string            `json:"status"`
			Adapter      map[string]string `json:"adapter"`
			Transport    string            `json:"transport"`
			Endpoint     string            `json:"endpoint"`
			PeerIdentity string            `json:"peerIdentity"`
			Server       map[string]string `json:"server"`
			Protocol     string            `json:"protocolVersion"`
			Tools        []string          `json:"tools"`
			Descriptors  struct {
				Endpoint string                     `json:"endpoint"`
				Server   map[string]string          `json:"server"`
				Tools    map[string]json.RawMessage `json:"tools"`
			} `json:"descriptors"`
		} `json:"check"`
	}
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatal(err)
	}
	c := report.Check
	leaf := sha256.Sum256(srv.Leaf())
	if c.Status != "succeeded" || c.Adapter["name"] != "adapter-mcp" || c.Transport != "http" || c.Endpoint != srv.URL ||
		c.PeerIdentity != "tls:sha256:"+hex.EncodeToString(leaf[:]) || c.Server["name"] != "fake-remote-mcp" || c.Server["version"] != "2.0" ||
		c.Protocol != "2025-06-18" || strings.Join(c.Tools, ",") != "query" {
		t.Fatalf("report: %s", out)
	}
	if c.Descriptors.Server["name"] != "fake-remote-mcp" || c.Descriptors.Tools["query"] == nil || c.Descriptors.Endpoint != srv.URL {
		t.Fatalf("descriptors captured as for stdio: %s", out)
	}
	if got := strings.Join(srv.Methods(), " "); got != "initialize notifications/initialized tools/list DELETE" {
		t.Fatalf("a check calls nothing: %s", got)
	}
	// A tool allowed that the server does not offer fails the check, as
	// for stdio.
	_, cfg = remote(t, true, fakemcp.Script{})
	cfg.Tools = []string{"drop_table"}
	if _, err := Check(within(t), cfg); err == nil || !strings.Contains(err.Error(), "allowed by the configuration but not offered by the server") {
		t.Fatalf("a tool the server lacks: %v", err)
	}
	// Over plaintext loopback the report names no identity.
	_, cfg = remote(t, false, fakemcp.Script{})
	out, err = Check(within(t), cfg)
	if err != nil || strings.Contains(string(out), "peerIdentity") || !strings.Contains(string(out), `"transport":"http"`) {
		t.Fatalf("a loopback check: %s %v", out, err)
	}
}

// An initialize this client does not take is refused as the stdio form
// refuses it.
func TestRemoteHandshakeIsHeldToTheStdioRules(t *testing.T) {
	_, cfg := remote(t, true, fakemcp.Script{Protocol: "2099-01-01"})
	if _, err := Acquire(within(t), cfg, query("select 1")); err == nil || !strings.Contains(err.Error(), "speaks protocol version '2099-01-01'") {
		t.Fatalf("a protocol version this client does not speak: %v", err)
	}
	_, cfg = remote(t, true, fakemcp.Script{ServerInfo: `{"name":"x"}`})
	if _, err := Acquire(within(t), cfg, query("select 1")); err == nil || !strings.Contains(err.Error(), "serverInfo carries no version string") {
		t.Fatalf("a server without a version: %v", err)
	}
	// A server that issues no session is talked to without one.
	srv, cfg := remote(t, true, fakemcp.Script{})
	srv.Set(func(s *fakemcp.Script) { s.Session = "" })
	if _, err := Acquire(within(t), cfg, query("select 1")); err != nil {
		t.Fatalf("a server without sessions: %v", err)
	}
	for _, r := range srv.Requests() {
		if r.Header.Get("Mcp-Session-Id") != "" {
			t.Fatalf("a session id sent that the server never issued: %v", r.Header)
		}
	}
}

// The bearer is held to RFC 6750's token68 form when it is read: a value
// with a quote, a backslash or a control character -- one a server could
// echo in a form the client's refusal would not find -- or an empty one is
// refused before anything is sent, by a sentence that names the rule and
// not the value; a token68 token is sent as it is.
func TestRemoteBearerIsHeldToToken68(t *testing.T) {
	for _, tc := range []struct{ name, json string }{
		{"a quote", `"tok\"en-` + otherMarker + `"`},
		{"a backslash", `"tok\\en-` + otherMarker + `"`},
		{"a tab", `"tok\ten-` + otherMarker + `"`},
		{"a newline", `"tok\nen-` + otherMarker + `"`},
		{"a space", `"tok en-` + otherMarker + `"`},
		{"padding inside", `"tok=en-` + otherMarker + `"`},
		{"empty", `""`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, cfg := remote(t, true, fakemcp.Script{})
			if err := os.WriteFile(cfg.Credentials, []byte(`{"TOKEN":`+tc.json+`}`), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, run := range []func() error{
				func() error { _, err := Acquire(within(t), cfg, query("select 1")); return err },
				func() error { _, err := Check(within(t), cfg); return err },
			} {
				err := run()
				if err == nil || !strings.Contains(err.Error(), "is not a bearer token of RFC 6750's form (token68") {
					t.Fatalf("want the token68 refusal, got %v", err)
				}
				noMarker(t, "the refusal", err.Error())
			}
			if n := len(srv.Requests()); n != 0 {
				t.Fatalf("%d request(s) sent with a bearer out of its form", n)
			}
		})
	}
	srv, cfg := remote(t, true, fakemcp.Script{})
	const token = "Ab9.-_~+/xyz=="
	if err := os.WriteFile(cfg.Credentials, []byte(`{"TOKEN":"`+token+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(within(t), cfg, query("select 1")); err != nil {
		t.Fatalf("a token68 bearer: %v", err)
	}
	for _, r := range srv.Requests() {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Fatalf("the token68 bearer as it is: %q", r.Header.Get("Authorization"))
		}
	}
}

// A check's probe is held to --tools before the server is reached: a
// probe the source may not call sends nothing, the bearer included.
func TestRemoteCheckRefusesAProbeOutsideTheToolsBeforeAnythingIsSent(t *testing.T) {
	srv, cfg := remote(t, true, fakemcp.Script{})
	cfg.Tools, cfg.Probe = []string{"lookup"}, "delete"
	if _, err := Check(within(t), cfg); err == nil || err.Error() != `probe "delete" is not one this source may call: [lookup]` {
		t.Fatalf("a probe outside --tools: %v", err)
	}
	if n := len(srv.Requests()); n != 0 {
		t.Fatalf("%d request(s) sent for a probe the source may not call", n)
	}
}

// A server that reflects the session id it issued -- in a result, in an
// error's text, in its initialize answer -- has that answer refused, so
// the id reaches neither the envelope nor a diagnostic nor a report.
func TestRemoteSessionIdIsNeverCarried(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script fakemcp.Script
	}{
		{"in a result", fakemcp.Script{Result: `{"content":[{"type":"text","text":"your session is ` + sessionMarker + `"}]}`}},
		{"in a result, escaped", fakemcp.Script{Result: `{"content":[{"type":"text","text":"your session is s` + sessionMarker[1:] + `"}]}`}},
		{"in an error's text", fakemcp.Script{Refuse: `{"code":-32000,"message":"session ` + sessionMarker + ` has expired"}`}},
		{"in the initialize answer", fakemcp.Script{ServerInfo: `{"name":"` + sessionMarker + `","version":"1"}`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, cfg := remote(t, true, tc.script)
			out, err := Acquire(within(t), cfg, query("select 1"))
			if err == nil || !strings.Contains(err.Error(), "repeats its session id") {
				t.Fatalf("want the session refusal, got %s %v", out, err)
			}
			noMarker(t, "the refusal", err.Error())
			cfg.Tools, cfg.Probe = []string{"query"}, "query"
			report, err := Check(within(t), cfg)
			if err == nil {
				t.Fatalf("a check whose probe or handshake reflects the session succeeded: %s", report)
			}
			noMarker(t, "the check's refusal", err.Error(), string(FailedCheck(err.Error())))
		})
	}
}

// Behind the client's refusal, the adapter's redaction set holds the
// session id once initialize has been answered, so a diagnostic or a
// report that carried it would carry it redacted.
func TestRemoteSessionIdIsInTheRedactionSet(t *testing.T) {
	_, cfg := remote(t, true, fakemcp.Script{})
	srv, secrets, err := openRemote(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.stop()
	if got := srv.sessionSecret(secrets); len(got) != len(secrets) {
		t.Fatalf("a session id before the server issued one: %q", got)
	}
	if _, err := srv.rpc.call(within(t), "initialize", map[string]any{"protocolVersion": protocolVersion, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "t", "version": "0"}}); err != nil {
		t.Fatal(err)
	}
	if got := redact.Redact("the session "+sessionMarker+" ended", srv.sessionSecret(secrets)); strings.Contains(got, sessionMarker) {
		t.Fatalf("the session id is not redacted: %s", got)
	}
}

// sized answers one kind of request with a body of exactly n bytes -- the
// response, then spaces; or, past the limit, ending in a byte that no JSON
// parser would take -- and records the bytes it wrote. Every other request
// is the server's own.
func sized(method string, n int, garbage bool, wrote *int) func(w http.ResponseWriter, got string, id json.RawMessage) bool {
	result := map[string]string{
		"initialize": `{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fake-remote-mcp","version":"2.0"}}`,
		"tools/list": `{"tools":` + fakemcp.DefaultTools + `}`,
		"tools/call": fakemcp.DefaultResult,
	}[method]
	return func(w http.ResponseWriter, got string, id json.RawMessage) bool {
		if got != method {
			return false
		}
		body := `{"jsonrpc":"2.0","id":` + string(id) + `,"result":` + result + `}`
		body += strings.Repeat(" ", n-len(body))
		if garbage {
			body = body[:n-1] + "x"
		}
		w.Header().Set("Content-Type", "application/json")
		if method == "initialize" {
			w.Header().Set("Mcp-Session-Id", sessionMarker)
		}
		*wrote += len(body)
		io.WriteString(w, body)
		return true
	}
}

// The remote form bounds each answer by its kind before parsing it: a tool
// call's by --max-output and the envelope's allowance, initialize's and a
// tool list page's by limits of their own, which --max-output does not
// bound. At its limit an answer is read; one byte past, it is refused with
// a sentence naming the bound, and (the tail being no JSON) never parsed.
func TestRemoteAnswersAreBoundedByKindBeforeParsing(t *testing.T) {
	const bound = 4096
	for _, tt := range []struct {
		method string
		output int64
		limit  int
	}{
		{"tools/call", bound, bound + callOverhead},
		{"initialize", bound, initializeLimit},
		{"tools/list", 16 << 20, listLimit},
	} {
		for _, past := range []bool{false, true} {
			var wrote int
			n := tt.limit
			if past {
				n++
			}
			_, cfg := remote(t, true, fakemcp.Script{Answer: sized(tt.method, n, past, &wrote)})
			cfg.MaxOutput, cfg.Tools = tt.output, []string{"query"}
			_, err := Acquire(within(t), cfg, query("select 1"))
			if wrote != n {
				t.Fatalf("%s: the server wrote %d bytes, not %d", tt.method, wrote, n)
			}
			if !past && err != nil {
				t.Fatalf("%s at its limit of %d bytes: %v", tt.method, tt.limit, err)
			}
			if past && (err == nil || !strings.Contains(err.Error(), fmt.Sprintf("the server's answer to %s exceeds the bound of %d bytes", tt.method, tt.limit))) {
				t.Fatalf("%s one byte past its limit of %d bytes: %v", tt.method, tt.limit, err)
			}
		}
	}
}

// An encoded answer is refused before any of it is read: the transport does
// not ask for an encoding or decode one, so a body cannot grow past the
// bound once the limiter has counted it. One request is made -- the one the
// answer was refused for -- and the server is told no encoding is accepted.
func TestRemoteRefusesAnEncodedAnswer(t *testing.T) {
	for _, encoding := range []string{"gzip", "br", "GZIP"} {
		var zipped bytes.Buffer
		gz := gzip.NewWriter(&zipped)
		gz.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}` + strings.Repeat(" ", 1<<20)))
		gz.Close()
		var acceptEncoding []string
		srv, cfg := remote(t, true, fakemcp.Script{Answer: func(w http.ResponseWriter, method string, id json.RawMessage) bool {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", encoding)
			w.Write(zipped.Bytes())
			return true
		}})
		cfg.MaxOutput = 4096
		_, err := Acquire(within(t), cfg, query("select 1"))
		if err == nil || !strings.Contains(err.Error(), "encoded") {
			t.Fatalf("%s: an encoded answer is refused for its encoding: %v", encoding, err)
		}
		if got := srv.Requests(); len(got) != 1 {
			t.Fatalf("%s: %d requests, not the one", encoding, len(got))
		} else {
			acceptEncoding = got[0].Header.Values("Accept-Encoding")
		}
		if len(acceptEncoding) != 0 {
			t.Fatalf("%s: the client asked for an encoding: %v", encoding, acceptEncoding)
		}
	}
}
