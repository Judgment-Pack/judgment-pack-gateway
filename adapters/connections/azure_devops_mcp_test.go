//go:build linux || darwin

package connections

import (
	"adapters/agreement"
	"adapters/internal/canon"
	"adapters/internal/fakemcp"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Every test here answers from in-process servers: the Streamable HTTP fake
// of adapter-mcp's remote form stands in for the remote MCP server, and the
// API profile's fake organization for the REST API. The test's transport
// sends a request for mcp.dev.azure.com to the fake and one for the
// organization's URL to the fake organization, dialing each whatever the
// name; nothing reaches a real organization or Entra.
const (
	adoMCPSession = "session-marker-ado-7c3e9b"
	// adoMCPTools is what the fake's tools/list offers: two read tools of
	// the remote server's names, the first with an output schema, a write
	// tool, and one more.
	adoMCPTools = `[{"name":"wit_work_item","inputSchema":{"type":"object"},"outputSchema":{"type":"object","properties":{"id":{"type":"integer"}}}},` +
		`{"name":"repo_repository","inputSchema":{"type":"object"}},{"name":"wit_work_item_write","inputSchema":{"type":"object"}},{"name":"other","inputSchema":{"type":"object"}}]`
	adoMCPResult = `{"content":[{"type":"text","text":"Example item"}],"structuredContent":{"id":12,"fields":{"System.Title":"Example item","System.State":"Active"}}}`
	adoMCPHost   = "mcp.dev.azure.com"
)

// adoMCPServers is a connection's remote server with two read tools.
func adoMCPServers() []AzureDevOpsMCPServer {
	return []AzureDevOpsMCPServer{{Server: "remote", Tools: []string{"wit_work_item", "repo_repository"}}}
}

// adoFakeMCP is the Streamable HTTP fake with the tools above and a session.
func adoFakeMCP(t *testing.T, change func(*fakemcp.Script)) *fakemcp.HTTPServer {
	t.Helper()
	script := fakemcp.Script{Session: adoMCPSession, Tools: adoMCPTools, Result: adoMCPResult}
	if change != nil {
		change(&script)
	}
	f := fakemcp.NewHTTP(true, script)
	t.Cleanup(f.Close)
	return f
}

// adoRoutes sends a request for the remote MCP server's host to the MCP
// fake, and any other to the organization's API, where the test has one.
type adoRoutes struct{ mcp, api http.RoundTripper }

func (r adoRoutes) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == adoMCPHost {
		return r.mcp.RoundTrip(req)
	}
	if r.api == nil || req.URL.Host != "dev.azure.com" && req.URL.Host != "example.visualstudio.com" {
		return nil, errors.New("a request to an unexpected host: " + req.URL.Host)
	}
	return r.api.RoundTrip(req)
}

// adoMCPServe is the connection's own provider, its redirect rule, timeouts
// and transport settings included, whose requests for the remote server go
// to f and whose others go to api.
func adoMCPServe(api *adoFake, f *fakemcp.HTTPServer) provider {
	p := azureDevOpsProvider()
	routes := adoRoutes{}
	if api != nil {
		routes.api = api.provider().client.Transport
	}
	leaf, _ := x509.ParseCertificate(f.Leaf())
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	u, _ := url.Parse(f.URL)
	transport := azureDevOpsProvider().client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, ServerName: "example.com"}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, u.Host)
	}
	routes.mcp = transport
	p.client = &http.Client{Transport: routes, CheckRedirect: p.client.CheckRedirect, Timeout: p.client.Timeout}
	return p
}
func adoMCPLeaf(f *fakemcp.HTTPServer) string {
	sum := sha256.Sum256(f.Leaf())
	return "tls:sha256:" + hex.EncodeToString(sum[:])
}
func adoConfigureMCP(b *Broker, fields map[string]string, servers any) error {
	all := map[string]any{"mcp": servers}
	for k, v := range fields {
		all[k] = v
	}
	raw, _ := json.Marshal(all)
	_, err := b.Handle(context.Background(), "configure", raw)
	return err
}

// adoMCPFixture is a store holding one connection made of fields and
// enabling servers.
func adoMCPFixture(t *testing.T, fields map[string]string, servers any) (*Store, *Broker, AzureDevOpsConnection, string) {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	s, err := OpenAzureDevOpsStore(dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	b := NewAzureDevOps(s, false)
	t.Cleanup(b.Close)
	if err = adoConfigureMCP(b, fields, servers); err != nil {
		t.Fatal(err)
	}
	return s, b, adoConnection(t, s, fields["id"]), dir
}
func adoMCPRead(c AzureDevOpsConnection, tool, arguments string) AzureDevOpsRequest {
	q := AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: "mcp", Server: "remote", Tool: tool}
	if arguments != "" {
		q.Arguments = json.RawMessage(arguments)
	}
	return q
}
func adoMethods(f *fakemcp.HTTPServer) string { return strings.Join(f.Methods(), ",") }

// A read is one session with the organization's remote server at
// https://mcp.dev.azure.com/{organization}, whichever form the organization
// URL takes: initialize, the tool's listing, one call with the arguments as
// given, and the session's end, each under the access token, the session and
// the read-only header; the record names what was asked of whom.
func TestAzureDevOpsMCPReadsTheRemoteServer(t *testing.T) {
	schema, _ := canon.Canonicalize([]byte(`{"type":"object","properties":{"id":{"type":"integer"}}}`), canon.CarryNumbersAsText)
	sum := sha256.Sum256(schema)
	for _, k := range []struct{ organization, tool, schema string }{
		{adoOrganization, "wit_work_item", "sha256:" + hex.EncodeToString(sum[:])},
		{adoLegacy, "repo_repository", ""},
	} {
		fields := adoBearerFields()
		fields["organization-url"] = k.organization
		s, _, c, _ := adoMCPFixture(t, fields, adoMCPServers())
		f := adoFakeMCP(t, nil)
		arguments := `{ "action": "get", "id": 12, "project": "example-project", "fields": ["System.Title"], "extra": {"b": [1, "two"], "a": null} }`
		out, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, k.tool, arguments), adoMCPServe(nil, f))
		if err != nil {
			t.Fatal(k.organization, err)
		}
		if got := adoMethods(f); got != "initialize,notifications/initialized,tools/list,tools/call,DELETE" {
			t.Fatalf("%s: %s", k.organization, got)
		}
		sent, _ := canon.Canonicalize([]byte(arguments), canon.RefuseNumbers)
		for _, r := range f.Requests() {
			if r.Path != "/example" || r.Header.Get("Authorization") != "Bearer "+adoBearer || r.Header.Get("X-MCP-Readonly") != "true" || len(r.Header.Values("X-MCP-Readonly")) != 1 {
				t.Errorf("%s: %s %s under %q, read-only %q", k.organization, r.Verb, r.Path, r.Header.Get("Authorization"), r.Header.Values("X-MCP-Readonly"))
			}
			if r.Method != "initialize" && r.Header.Get("Mcp-Session-Id") != adoMCPSession {
				t.Errorf("%s: %s without the session", k.organization, r.Method)
			}
			if r.Method == "tools/call" {
				var call struct {
					Params struct {
						Name      string          `json:"name"`
						Arguments json.RawMessage `json:"arguments"`
					} `json:"params"`
				}
				json.Unmarshal(r.Body, &call)
				if call.Params.Name != k.tool || !bytes.Equal(call.Params.Arguments, sent) {
					t.Errorf("%s: called %s with %s", k.organization, call.Params.Name, call.Params.Arguments)
				}
			}
		}
		e, err := agreement.Parse(out)
		if err != nil {
			t.Fatal("the envelope is not of the signer's form:", err)
		}
		a := e.Acquisition
		if a.Adapter.Name != "adapter-sources" || !canon.IsDigestString(a.Adapter.Digest) || a.Endpoint == nil || *a.Endpoint != "https://mcp.dev.azure.com/example" ||
			a.Snapshot == nil || *a.Snapshot != digest([]byte(adoMCPResult)) || a.PeerIdentity == nil || *a.PeerIdentity != adoMCPLeaf(f) || a.UpstreamToken != nil {
			t.Fatalf("%s: acquisition %+v", k.organization, a)
		}
		if k.schema == "" && a.Schema != nil || k.schema != "" && (a.Schema == nil || *a.Schema != k.schema) {
			t.Fatalf("%s: schema %v", k.organization, a.Schema)
		}
		if observed, err := time.Parse("2006-01-02T15:04:05Z", a.ObservedAt); err != nil || time.Since(observed) > time.Minute {
			t.Fatal("observedAt", a.ObservedAt)
		}
		want, _ := canon.Canonicalize([]byte(adoMCPResult), canon.CarryNumbersAsText)
		if !bytes.Equal(e.Result, want) {
			t.Fatalf("%s: the result is not the tool's result: %s", k.organization, e.Result)
		}
		members, err := agreement.Statement(e)
		if err != nil {
			t.Fatal(err)
		}
		for name, value := range map[string]string{"connection": `"board"`, "revision": `"` + c.Revision + `"`, "provider": `"azure-devops"`, "project": `"` + adoProject + `"`, "read": `"mcp"`,
			"server": `"remote"`, "endpoint": `"https://mcp.dev.azure.com/example"`, "tool": `"` + k.tool + `"`, "arguments": string(sent)} {
			if string(members[name]) != value {
				t.Errorf("%s: statement %s = %s", k.organization, name, members[name])
			}
		}
		if len(members) != 9 || bytes.Contains(out, []byte(adoMCPSession)) || bytes.Contains(out, []byte(adoBearer)) {
			t.Fatalf("%s: %s", k.organization, out)
		}
	}
}

// A read the connection does not allow is refused before anything is sent:
// a tool not on the server's list (an empty list allows none), a server it
// does not enable, and a request out of its form; and a connection that
// enables no server reaches none. A listed tool the server does not offer
// is not called.
func TestAzureDevOpsMCPRefusesWhatTheConnectionDoesNotAllow(t *testing.T) {
	s, _, c, _ := adoMCPFixture(t, adoBearerFields(), adoMCPServers())
	f := adoFakeMCP(t, nil)
	p := adoMCPServe(nil, f)
	with := func(change func(*AzureDevOpsRequest)) AzureDevOpsRequest {
		q := adoMCPRead(c, "wit_work_item", "")
		change(&q)
		return q
	}
	for name, k := range map[string]struct {
		q    AzureDevOpsRequest
		want error
	}{
		"a tool outside the list":       {adoMCPRead(c, "wit_work_item_write", ""), databricksNotAllowed},
		"a tool the server offers":      {adoMCPRead(c, "other", ""), databricksNotAllowed},
		"a listed tool in capitals":     {adoMCPRead(c, "WIT_WORK_ITEM", ""), databricksNotAllowed},
		"a server not enabled":          {with(func(q *AzureDevOpsRequest) { q.Server = "local" }), databricksNotEnabled},
		"the server in capitals":        {with(func(q *AzureDevOpsRequest) { q.Server = "Remote" }), databricksNotEnabled},
		"no server":                     {with(func(q *AzureDevOpsRequest) { q.Server = "" }), databricksNotEnabled},
		"no tool":                       {adoMCPRead(c, "", ""), ErrRequest},
		"a tool name with a space":      {adoMCPRead(c, "wit work_item", ""), ErrRequest},
		"arguments that are a list":     {adoMCPRead(c, "wit_work_item", `["get"]`), ErrRequest},
		"arguments that are a string":   {adoMCPRead(c, "wit_work_item", `"get"`), ErrRequest},
		"a query beside":                {with(func(q *AzureDevOpsRequest) { q.Query = "SELECT [System.Id] FROM WorkItems" }), ErrRequest},
		"a repository beside":           {with(func(q *AzureDevOpsRequest) { q.Repository = "example-repo" }), ErrRequest},
		"an API read with a tool":       {AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: "repos.list", Tool: "wit_work_item"}, ErrRequest},
		"an API read with a server":     {AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: "repos.list", Server: "remote"}, ErrRequest},
		"an API read with arguments":    {AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: "pipelines.list", Arguments: json.RawMessage(`{}`)}, ErrRequest},
		"the read in capitals":          {with(func(q *AzureDevOpsRequest) { q.Read = "MCP" }), ErrRequest},
		"a stale revision":              {with(func(q *AzureDevOpsRequest) { q.Revision = strings.Repeat("0", 64) }), ErrChanged},
		"another connection":            {with(func(q *AzureDevOpsRequest) { q.Connection = "other" }), ErrConnect},
		"a tool of 129 characters":      {adoMCPRead(c, strings.Repeat("a", 129), ""), ErrRequest},
		"a tool with a slash":           {adoMCPRead(c, "wit/work_item", ""), ErrRequest},
		"arguments that are a number":   {adoMCPRead(c, "wit_work_item", `12`), ErrRequest},
		"arguments with a fraction":     {adoMCPRead(c, "wit_work_item", `{"id":1.5}`), ErrRequest},
		"a tool on no list, as written": {adoMCPRead(c, "wit_query_by_wiql", ""), databricksNotAllowed},
	} {
		out, err := azureDevOpsAcquire(context.Background(), s, k.q, p)
		if out != nil || err != k.want {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := len(f.Requests()); n != 0 {
		t.Fatalf("a refused read was sent: %d requests, %s", n, adoMethods(f))
	}
	// An empty list allows nothing, and a connection without a server
	// enables none.
	es, _, ec, _ := adoMCPFixture(t, adoBearerFields(), []AzureDevOpsMCPServer{{Server: "remote", Tools: []string{}}})
	ns, _, nc, _ := adoMCPFixture(t, adoBearerFields(), nil)
	if _, err := azureDevOpsAcquire(context.Background(), es, adoMCPRead(ec, "wit_work_item", ""), p); err != databricksNotAllowed {
		t.Fatal("an empty list:", err)
	}
	if _, err := azureDevOpsAcquire(context.Background(), ns, adoMCPRead(nc, "wit_work_item", ""), p); err != databricksNotEnabled {
		t.Fatal("no server:", err)
	}
	if n := len(f.Requests()); n != 0 {
		t.Fatalf("a refused read was sent: %d requests", n)
	}
	// A tool on the list that the server does not offer is not called.
	offered := adoFakeMCP(t, func(script *fakemcp.Script) { script.Tools = `[{"name":"other","inputSchema":{"type":"object"}}]` })
	out, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", ""), adoMCPServe(nil, offered))
	if out != nil || err == nil || err.Error() != "tool-not-offered: the MCP server remote does not offer the tool the read names; nothing was called" || strings.Contains(adoMethods(offered), "tools/call") {
		t.Fatal(err, adoMethods(offered))
	}
}

// The read-only header is sent on every request of a session -- the
// handshake, the listing, the call, the session's end -- unless the operator
// turned it off for the server, and then on none; configure takes only the
// two settings, and status says which is set.
func TestAzureDevOpsMCPTheReadOnlyHeader(t *testing.T) {
	for _, setting := range []string{"", "send", "off"} {
		servers := []map[string]any{{"server": "remote", "tools": []string{"wit_work_item"}}}
		if setting != "" {
			servers[0]["readOnlyHeader"] = setting
		}
		s, b, c, _ := adoMCPFixture(t, adoBearerFields(), servers)
		f := adoFakeMCP(t, nil)
		if _, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", ""), adoMCPServe(nil, f)); err != nil {
			t.Fatal(setting, err)
		}
		requests := f.Requests()
		if len(requests) != 5 {
			t.Fatal(setting, adoMethods(f))
		}
		for _, r := range requests {
			got := r.Header.Values("X-MCP-Readonly")
			if setting == "off" && len(got) != 0 || setting != "off" && (len(got) != 1 || got[0] != "true") {
				t.Errorf("%q: %s %s carried %q", setting, r.Verb, r.Method, got)
			}
		}
		want := "send"
		if setting == "off" {
			want = "off"
		}
		status, err := b.Handle(context.Background(), "status", []byte(`{}`))
		raw, _ := json.Marshal(status)
		if err != nil || !bytes.Contains(raw, []byte(`"mcp":[{"server":"remote","tools":["wit_work_item"],"readOnlyHeader":"`+want+`"}]`)) {
			t.Fatalf("%q: status %s %v", setting, raw, err)
		}
	}
	_, b, _, dir := adoMCPFixture(t, adoBearerFields(), nil)
	for _, setting := range []any{"true", "on", "OFF", "Off", "none", " off", false, true} {
		fields := adoBearerFields()
		fields["id"] = "other"
		if err := adoConfigureMCP(b, fields, []map[string]any{{"server": "remote", "tools": []string{}, "readOnlyHeader": setting}}); err != ErrRequest || bytes.Contains(adoState(t, dir), []byte(`"other"`)) {
			t.Errorf("%v: %v", setting, err)
		}
	}
}

// A server's refusal is reported in the API profile's words for its status,
// or in the client's, after one request where it came first: nothing is
// retried, a redirect is not followed, and a result that reports an error is
// refused with its text.
func TestAzureDevOpsMCPServerRefusals(t *testing.T) {
	s, _, c, _ := adoMCPFixture(t, adoBearerFields(), adoMCPServers())
	status := func(code int, header ...string) func(*fakemcp.Script) {
		return func(script *fakemcp.Script) {
			var mu sync.Mutex
			answered := false
			script.Answer = func(w http.ResponseWriter, method string, _ json.RawMessage) bool {
				mu.Lock()
				defer mu.Unlock()
				// A request after the first -- a retry, or a redirect
				// followed -- is answered as the server would.
				if method != "initialize" || answered {
					return false
				}
				answered = true
				for i := 0; i+1 < len(header); i += 2 {
					w.Header().Set(header[i], header[i+1])
				}
				w.WriteHeader(code)
				return true
			}
		}
	}
	body := func(kind, text string) func(*fakemcp.Script) {
		return func(script *fakemcp.Script) {
			script.Answer = func(w http.ResponseWriter, method string, _ json.RawMessage) bool {
				if method != "tools/call" {
					return false
				}
				w.Header().Set("Content-Type", kind)
				w.Write([]byte(text))
				return true
			}
		}
	}
	all := "initialize,notifications/initialized,tools/list,tools/call,DELETE"
	for name, k := range map[string]struct {
		change  func(*fakemcp.Script)
		want    string
		methods string
	}{
		"401": {status(401, "WWW-Authenticate", `Bearer resource_metadata="https://mcp.dev.azure.com/.well-known/oauth-protected-resource"`), "credentials-required: the MCP server remote: the server answered 401 Unauthorized", "initialize"},
		"403": {status(403), "permission-denied: the MCP server remote: the server answered 403 Forbidden", "initialize"},
		"404": {status(404), "request-refused: the MCP server remote: the server answered 404 Not Found", "initialize"},
		"429": {status(429, "Retry-After", "7"), "rate-limited: the MCP server remote: the server answered 429 Too Many Requests; it was not retried", "initialize"},
		"503": {status(503), "provider-unavailable: the MCP server remote: the server answered 503 Service Unavailable", "initialize"},
		"a redirect": {status(307, "Location", "https://mcp.dev.azure.com/elsewhere"),
			"provider-unavailable: the MCP server remote: the server answered 307 Temporary Redirect, a redirect, which is not followed", "initialize"},
		"a JSON-RPC refusal": {func(script *fakemcp.Script) { script.Refuse = `{"code":-32602,"message":"Unknown action: delete"}` },
			"provider-unavailable: the MCP server remote: the server answered with an error: Unknown action: delete (code -32602)", all},
		"a body that is not JSON": {body("application/json", "<html>sign in</html>"),
			"provider-unavailable: the MCP server remote: the server's answer is not a JSON message in the canonical domain", all},
		"a body of another type": {body("text/html", "<html>sign in</html>"),
			"provider-unavailable: the MCP server remote: the server's answer is of a content type that is neither application/json nor text/event-stream", all},
		"a result that reports an error": {func(script *fakemcp.Script) {
			script.Result = `{"content":[{"type":"text","text":"TF401232: Work item 12 does not exist"},{"type":"text","text":"or you lack permission"}],"isError":true}`
		}, "tool-error: TF401232: Work item 12 does not exist or you lack permission", all},
		"a result that is not one": {func(script *fakemcp.Script) { script.Result = `{"value":[]}` },
			"provider-unavailable: the MCP server's answer is not a tool result: tools/call: the tool's result has no content array", all},
		"a protocol this client does not speak": {func(script *fakemcp.Script) { script.Protocol = "2024-01-01" },
			"provider-unavailable: the MCP server remote: initialize: the server speaks a protocol version this client does not", "initialize,DELETE"},
	} {
		f := adoFakeMCP(t, k.change)
		out, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", `{"action":"get","id":12}`), adoMCPServe(nil, f))
		if out != nil || err == nil || err.Error() != k.want {
			t.Errorf("%s: %v", name, err)
		}
		if got := adoMethods(f); got != k.methods {
			t.Errorf("%s: %s", name, got)
		}
	}
}

// The connection's bound holds the tool's result as received: one of the
// bound's size is kept, one a byte past it is not; and the client's own
// bound holds the whole answer, read no further than it.
func TestAzureDevOpsMCPResultBound(t *testing.T) {
	fields := adoBearerFields()
	fields["max-result-bytes"] = "65536"
	s, _, c, _ := adoMCPFixture(t, fields, adoMCPServers())
	sized := func(n int) string {
		short := `{"content":[{"type":"text","text":""}]}`
		return `{"content":[{"type":"text","text":"` + strings.Repeat("x", n-len(short)) + `"}]}`
	}
	for _, k := range []struct {
		size int
		want string
	}{
		{65536, ""},
		{65537, "result-too-large: the MCP server's result is larger than the connection's bound of 65536 bytes"},
		{8<<20 + 1, "result-too-large: the MCP server remote: the server's answer exceeds the bound of 8388608 bytes"},
	} {
		result := sized(k.size)
		if len(result) != k.size {
			t.Fatal("fixture size", len(result))
		}
		f := adoFakeMCP(t, func(script *fakemcp.Script) { script.Result = result })
		out, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", ""), adoMCPServe(nil, f))
		if k.want == "" {
			if err != nil || out == nil {
				t.Errorf("%d bytes: %v", k.size, err)
			}
			continue
		}
		if out != nil || err == nil || err.Error() != k.want {
			t.Errorf("%d bytes: %v", k.size, err)
		}
	}
}

// A server that answers as an event stream is read alike, and its result's
// digest is of the result as it came.
func TestAzureDevOpsMCPAnEventStreamIsReadAlike(t *testing.T) {
	s, _, c, _ := adoMCPFixture(t, adoBearerFields(), adoMCPServers())
	f := adoFakeMCP(t, func(script *fakemcp.Script) { script.Events = true })
	out, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", `{"action":"get","id":12}`), adoMCPServe(nil, f))
	if err != nil {
		t.Fatal(err)
	}
	e, err := agreement.Parse(out)
	if err != nil || *e.Acquisition.Snapshot != digest([]byte(adoMCPResult)) || *e.Acquisition.PeerIdentity != adoMCPLeaf(f) {
		t.Fatal(err, e.Acquisition)
	}
}

// A test makes the API profile's one request and reaches the remote server:
// initialize and its tools, reporting what it offers and which names on the
// list it does not, and calls no tool. Each is reported on its own, so an
// API that refuses the token does not hide the server's answer. A connection
// that enables no server answers as the API profile does. Status names the
// server, its list and its header setting, and never a credential.
func TestAzureDevOpsMCPTestListsTheToolsAndCallsNone(t *testing.T) {
	servers := []AzureDevOpsMCPServer{{Server: "remote", Tools: []string{"wit_work_item", "missing_tool"}}}
	_, b, c, _ := adoMCPFixture(t, adoBearerFields(), servers)
	api := newADOFake(t)
	f := adoFakeMCP(t, nil)
	b.provider = adoMCPServe(api, f)
	answer, err := b.Handle(context.Background(), "test", []byte(`{"id":"board","revision":"`+c.Revision+`"}`))
	raw, _ := json.Marshal(answer)
	offered := `["wit_work_item","repo_repository","wit_work_item_write","other"]`
	if err != nil || string(raw) != `{"api":{"ok":true},"mcp":[{"server":"remote","ok":true,"offered":`+offered+`,"notOffered":["missing_tool"]}],"ok":true}` {
		t.Fatalf("test %s %v", raw, err)
	}
	if got := adoMethods(f); got != "initialize,notifications/initialized,tools/list,DELETE" {
		t.Fatal("a test called a tool, or not only the listing:", got)
	}
	if api.count() != 1 || !strings.HasPrefix(api.since(0)[0].line, "POST /example/example-project/_apis/wit/wiql?$top=1") {
		t.Fatal("the API test was not its one request", api.since(0))
	}
	for _, r := range f.Requests() {
		if r.Header.Get("Authorization") != "Bearer "+adoBearer || r.Header.Get("X-MCP-Readonly") != "true" {
			t.Fatal("a test's request without the bearer or the header")
		}
	}
	// The API refusing, the server is still reached and reported.
	api.set(func(w http.ResponseWriter, r *http.Request, _ []byte) { w.WriteHeader(401) })
	answer, err = b.Handle(context.Background(), "test", []byte(`{"id":"board","revision":"`+c.Revision+`"}`))
	raw, _ = json.Marshal(answer)
	if err != nil || string(raw) != `{"api":{"error":"credentials-required: the organization answered 401","ok":false},"mcp":[{"server":"remote","ok":true,"offered":`+offered+`,"notOffered":["missing_tool"]}],"ok":false}` {
		t.Fatalf("test %s %v", raw, err)
	}
	// The server refusing, the answer says so, and no tool is called.
	api.set(func(w http.ResponseWriter, r *http.Request, _ []byte) {
		io.WriteString(w, `{"queryResultType":"workItem","workItems":[]}`)
	})
	refusing := adoFakeMCP(t, func(script *fakemcp.Script) {
		script.Answer = func(w http.ResponseWriter, method string, _ json.RawMessage) bool {
			w.WriteHeader(403)
			return true
		}
	})
	b.provider = adoMCPServe(api, refusing)
	answer, err = b.Handle(context.Background(), "test", []byte(`{"id":"board","revision":"`+c.Revision+`"}`))
	raw, _ = json.Marshal(answer)
	if err != nil || string(raw) != `{"api":{"ok":true},"mcp":[{"server":"remote","ok":false,"offered":[],"notOffered":[],"error":"permission-denied: the MCP server remote: the server answered 403 Forbidden"}],"ok":false}` ||
		strings.Contains(adoMethods(refusing), "tools/call") {
		t.Fatalf("test %s %v", raw, err)
	}
	// Status names the server, its list and its header setting.
	status, err := b.Handle(context.Background(), "status", []byte(`{}`))
	raw, _ = json.Marshal(status)
	if err != nil || !bytes.Contains(raw, []byte(`"mcp":[{"server":"remote","tools":["wit_work_item","missing_tool"],"readOnlyHeader":"send"}],"ready":true`)) ||
		bytes.Contains(raw, []byte(adoBearer)) || bytes.Contains(raw, []byte(`"access-token"`)) || !bytes.Contains(raw, []byte(`"maxMCPTools":32`)) {
		t.Fatalf("status %s %v", raw, err)
	}
	// A connection that enables no server answers as the API profile does,
	// and reaches no server.
	_, nb, nc, _ := adoMCPFixture(t, adoBearerFields(), nil)
	none := adoFakeMCP(t, nil)
	nb.provider = adoMCPServe(api, none)
	answer, err = nb.Handle(context.Background(), "test", []byte(`{"id":"board","revision":"`+nc.Revision+`"}`))
	raw, _ = json.Marshal(answer)
	if err != nil || string(raw) != `{"ok":true}` || len(none.Requests()) != 0 {
		t.Fatalf("test %s %v", raw, err)
	}
	// A test of a connection that is not there reaches nothing.
	before := api.count()
	if _, err = b.Handle(context.Background(), "test", []byte(`{"id":"missing","revision":"`+c.Revision+`"}`)); err != ErrConnect || api.count() != before {
		t.Fatal("a missing connection's test", err)
	}
}

// The servers a connection enables are held to their forms, case by case,
// each refused by configure with nothing kept; and the MCP profile is
// refused under a personal access token, which the remote server does not
// take.
func TestAzureDevOpsMCPConfigurationForms(t *testing.T) {
	tools := func(n int) []string {
		out := []string{}
		for i := range n {
			out = append(out, "tool_"+strings.Repeat("x", i))
		}
		return out
	}
	accepted := map[string]any{
		"none":                         []AzureDevOpsMCPServer{},
		"the remote server":            adoMCPServers(),
		"an empty list":                []AzureDevOpsMCPServer{{Server: "remote", Tools: []string{}}},
		"no list":                      []map[string]any{{"server": "remote"}},
		"a null list":                  []map[string]any{{"server": "remote", "tools": nil}},
		"thirty-two tools":             []AzureDevOpsMCPServer{{Server: "remote", Tools: tools(32)}},
		"a tool of 128 characters":     []AzureDevOpsMCPServer{{Server: "remote", Tools: []string{strings.Repeat("a", 128)}}},
		"a tool with dots and hyphens": []AzureDevOpsMCPServer{{Server: "remote", Tools: []string{"wit.work-item_v2"}}},
		"the header turned off":        []map[string]any{{"server": "remote", "tools": []string{}, "readOnlyHeader": "off"}},
		"the header setting null":      []map[string]any{{"server": "remote", "tools": []string{}, "readOnlyHeader": nil}},
	}
	refused := map[string]any{
		"another server":                     []AzureDevOpsMCPServer{{Server: "local", Tools: []string{}}},
		"the server in capitals":             []AzureDevOpsMCPServer{{Server: "Remote", Tools: []string{}}},
		"a server with a key":                []AzureDevOpsMCPServer{{Server: "remote:example", Tools: []string{}}},
		"a server named by its URL":          []AzureDevOpsMCPServer{{Server: "https://mcp.dev.azure.com/example", Tools: []string{}}},
		"no server":                          []AzureDevOpsMCPServer{{Server: "", Tools: []string{}}},
		"the server twice":                   []AzureDevOpsMCPServer{{Server: "remote", Tools: []string{}}, {Server: "remote", Tools: []string{"a"}}},
		"thirty-three tools":                 []AzureDevOpsMCPServer{{Server: "remote", Tools: tools(33)}},
		"a tool of 129 characters":           []AzureDevOpsMCPServer{{Server: "remote", Tools: []string{strings.Repeat("a", 129)}}},
		"an empty tool":                      []AzureDevOpsMCPServer{{Server: "remote", Tools: []string{""}}},
		"a tool with a space":                []AzureDevOpsMCPServer{{Server: "remote", Tools: []string{"wit work_item"}}},
		"a tool with a comma":                []AzureDevOpsMCPServer{{Server: "remote", Tools: []string{"wit_work_item,repo_repository"}}},
		"a tool as a pattern":                []AzureDevOpsMCPServer{{Server: "remote", Tools: []string{"wit_*"}}},
		"a tool outside ASCII":               []AzureDevOpsMCPServer{{Server: "remote", Tools: []string{"índice"}}},
		"a tool twice":                       []AzureDevOpsMCPServer{{Server: "remote", Tools: []string{"a", "a"}}},
		"the server as a member in capitals": []map[string]any{{"Server": "remote", "tools": []string{}}},
		"a member beside":                    []map[string]any{{"server": "remote", "tools": []string{}, "toolsets": "wit"}},
		"the header setting in capitals":     []map[string]any{{"server": "remote", "tools": []string{}, "ReadOnlyHeader": "off"}},
		"a list that is not one":             map[string]any{"server": "remote"},
		"tools that are text":                []map[string]any{{"server": "remote", "tools": "wit_work_item"}},
	}
	_, b, _, dir := adoMCPFixture(t, adoBearerFields(), nil)
	for name, servers := range accepted {
		fields := adoBearerFields()
		fields["id"] = "kept"
		if err := adoConfigureMCP(b, fields, servers); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		c := adoConnection(t, b.store, "kept")
		for _, server := range c.MCP {
			if server.Tools == nil || server.ReadOnlyHeader != "send" && server.ReadOnlyHeader != "off" {
				t.Errorf("%s: kept as %+v", name, server)
			}
		}
		if _, err := b.Handle(context.Background(), "disconnect", []byte(`{"id":"kept","revision":"`+c.Revision+`"}`)); err != nil {
			t.Fatal(err)
		}
	}
	for name, servers := range refused {
		fields := adoBearerFields()
		fields["id"] = "other"
		if err := adoConfigureMCP(b, fields, servers); err != ErrRequest || bytes.Contains(adoState(t, dir), []byte(`"other"`)) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A personal access token: refused with the MCP profile, and taken
	// without it; a server written into custody by another hand under one
	// is not ready, and reaches nothing.
	fields := adoTokenFields()
	fields["id"] = "other"
	if err := adoConfigureMCP(b, fields, adoMCPServers()); err != azureDevOpsMCPBearer || bytes.Contains(adoState(t, dir), []byte(`"other"`)) {
		t.Fatal("the MCP profile under a personal access token:", err)
	}
	ts, tb, tc, _ := adoMCPFixture(t, adoTokenFields(), nil)
	ts.locked(func(v *state) error {
		v.AzureDevOps.Connections[0].MCP = adoMCPServers()
		v.AzureDevOps.Connections[0].MCP[0].ReadOnlyHeader = "send"
		return ts.write("state.json", v)
	})
	status, _ := tb.Handle(context.Background(), "status", []byte(`{}`))
	raw, _ := json.Marshal(status)
	f := adoFakeMCP(t, nil)
	if _, err := azureDevOpsAcquire(context.Background(), ts, adoMCPRead(tc, "wit_work_item", ""), adoMCPServe(nil, f)); err != ErrSetup || len(f.Requests()) != 0 || !bytes.Contains(raw, []byte(`"ready":false`)) {
		t.Fatalf("a PAT connection's MCP read: %v, %d requests, %s", err, len(f.Requests()), raw)
	}
	// The endpoint each organization URL stands for.
	for organization, endpoint := range map[string]string{
		"https://dev.azure.com/example":        "https://mcp.dev.azure.com/example",
		"https://dev.azure.com/Example-Org":    "https://mcp.dev.azure.com/Example-Org",
		"https://example.visualstudio.com":     "https://mcp.dev.azure.com/example",
		"https://example-org.visualstudio.com": "https://mcp.dev.azure.com/example-org",
	} {
		if got := (AzureDevOpsConnection{Organization: organization}).mcpEndpoint(); got != endpoint {
			t.Errorf("%s: %s", organization, got)
		}
	}
}

// The live check reads one tool's result from the remote server of an
// organization the environment names, under an access token it gives. Without
// them, it is not run, and says so.
func TestAzureDevOpsMCPLiveCheck(t *testing.T) {
	organization, token, tool := os.Getenv("JPACK_AZURE_DEVOPS_LIVE_ORGANIZATION"), os.Getenv("JPACK_AZURE_DEVOPS_LIVE_ACCESS_TOKEN"), os.Getenv("JPACK_AZURE_DEVOPS_LIVE_MCP_TOOL")
	if organization == "" || token == "" || tool == "" {
		t.Skip("not run: JPACK_AZURE_DEVOPS_LIVE_ORGANIZATION, JPACK_AZURE_DEVOPS_LIVE_PROJECT, JPACK_AZURE_DEVOPS_LIVE_ACCESS_TOKEN, JPACK_AZURE_DEVOPS_LIVE_EXPIRES_AT, JPACK_AZURE_DEVOPS_LIVE_MCP_TOOL and JPACK_AZURE_DEVOPS_LIVE_MCP_ARGUMENTS name no organization's remote server")
	}
	fields := map[string]string{"id": "live", "name": "Live", "organization-url": organization, "project": os.Getenv("JPACK_AZURE_DEVOPS_LIVE_PROJECT"), "auth": "bearer", "access-token": token, "expires-at": os.Getenv("JPACK_AZURE_DEVOPS_LIVE_EXPIRES_AT")}
	s, b, c, _ := adoMCPFixture(t, fields, []AzureDevOpsMCPServer{{Server: "remote", Tools: []string{tool}}})
	answer, err := b.Handle(context.Background(), "test", []byte(`{"id":"live","revision":"`+c.Revision+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("test: %v", answer)
	raw, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, tool, os.Getenv("JPACK_AZURE_DEVOPS_LIVE_MCP_ARGUMENTS")), azureDevOpsProvider())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = agreement.Parse(raw); err != nil {
		t.Fatal(err)
	}
}
