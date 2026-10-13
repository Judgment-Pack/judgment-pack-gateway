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
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
)

// Every test here answers from in-process servers: the Streamable HTTP fake
// of adapter-mcp's remote form for the MCP servers, and the API profile's
// fake workspace for the token endpoint and the API. The workspace's host
// name is of a workspace's form, and the test's transport dials the servers
// whatever the name; nothing reaches a real workspace.
const (
	dbSession = "session-marker-5e1d0c9a"
	dbSpace   = "01f0a1b2c3d4e5f60718293a4b5c6d7e"
	// dbMCPTools is what the fake's tools/list offers: one tool for each
	// server kind, the first with an output schema, and one more.
	dbMCPTools = `[{"name":"execute_sql","inputSchema":{"type":"object"},"outputSchema":{"type":"object","properties":{"rows":{"type":"array"}}}},` +
		`{"name":"ask","inputSchema":{"type":"object"}},{"name":"main__finance__rate","inputSchema":{"type":"object"}},` +
		`{"name":"main__docs__chunks","inputSchema":{"type":"object"}},{"name":"other","inputSchema":{"type":"object"}}]`
	dbMCPResult = `{"content":[{"type":"text","text":"1 row"}],"structuredContent":{"rows":[{"region":"EMEA","total":12.5}]}}`
)

// dbServers are a connection's servers, one of each kind.
func dbServers() []DatabricksMCPServer {
	return []DatabricksMCPServer{
		{Server: "sql", Tools: []string{"execute_sql"}},
		{Server: "genie:" + dbSpace, Tools: []string{"ask"}},
		{Server: "functions:main.finance.rate", Tools: []string{"main__finance__rate"}},
		{Server: "ai-search:main.docs.chunks", Tools: []string{"main__docs__chunks"}},
	}
}

// dbFakeMCP is the Streamable HTTP fake with the tools above and a session.
func dbFakeMCP(t *testing.T, change func(*fakemcp.Script)) *fakemcp.HTTPServer {
	t.Helper()
	script := fakemcp.Script{Session: dbSession, Tools: dbMCPTools, Result: dbMCPResult}
	if change != nil {
		change(&script)
	}
	f := fakemcp.NewHTTP(true, script)
	t.Cleanup(f.Close)
	return f
}

// dbRoutes sends a request to the fake whose path prefix is the longest
// that names it, and any other to the workspace's API.
type dbRoutes struct {
	prefixes []string
	fakes    []http.RoundTripper
	api      http.RoundTripper
}

func (r dbRoutes) RoundTrip(req *http.Request) (*http.Response, error) {
	best, at := -1, 0
	for i, prefix := range r.prefixes {
		if strings.HasPrefix(req.URL.Path, prefix) && len(prefix) > at {
			best, at = i, len(prefix)
		}
	}
	if best < 0 {
		return r.api.RoundTrip(req)
	}
	return r.fakes[best].RoundTrip(req)
}

// dbServe is the connection's own provider, its redirect rule and timeouts
// included, whose requests under each prefix go to that fake, and whose
// other requests go to api.
func dbServe(api *dbFake, fakes map[string]*fakemcp.HTTPServer) provider {
	p := api.provider()
	routes := dbRoutes{api: p.client.Transport}
	for prefix, f := range fakes {
		leaf, _ := x509.ParseCertificate(f.Leaf())
		pool := x509.NewCertPool()
		pool.AddCert(leaf)
		u, _ := url.Parse(f.URL)
		transport := databricksProvider().client.Transport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, ServerName: "example.com"}
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, u.Host)
		}
		routes.prefixes = append(routes.prefixes, prefix)
		routes.fakes = append(routes.fakes, transport)
	}
	p.client = &http.Client{Transport: routes, CheckRedirect: p.client.CheckRedirect, Timeout: p.client.Timeout}
	return p
}
func dbServeOne(api *dbFake, f *fakemcp.HTTPServer) provider {
	return dbServe(api, map[string]*fakemcp.HTTPServer{"/api/2.0/mcp/": f})
}
func dbLeaf(f *fakemcp.HTTPServer) string {
	sum := sha256.Sum256(f.Leaf())
	return "tls:sha256:" + hex.EncodeToString(sum[:])
}

// dbMCPFixture is a store holding one connection made of fields and
// enabling servers.
func dbMCPFixture(t *testing.T, fields map[string]string, servers []DatabricksMCPServer) (*Store, *Broker, DatabricksConnection, string) {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	s, err := OpenDatabricksStore(dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	b := NewDatabricks(s, false)
	t.Cleanup(b.Close)
	if err = dbConfigureMCP(b, fields, servers); err != nil {
		t.Fatal(err)
	}
	return s, b, dbConnection(t, s, fields["id"]), dir
}
func dbConfigureMCP(b *Broker, fields map[string]string, servers any) error {
	all := map[string]any{"mcp": servers}
	for k, v := range fields {
		all[k] = v
	}
	raw, _ := json.Marshal(all)
	_, err := b.Handle(context.Background(), "configure", raw)
	return err
}
func dbMCPRead(c DatabricksConnection, server, tool, arguments string) DatabricksRequest {
	q := DatabricksRequest{Connection: c.ID, Revision: c.Revision, Read: "mcp", Server: server, Tool: tool}
	if arguments != "" {
		q.Arguments = json.RawMessage(arguments)
	}
	return q
}
func dbMethods(f *fakemcp.HTTPServer) string { return strings.Join(f.Methods(), ",") }

// A read on each server kind is one session at the server's own endpoint
// under the workspace: initialize, the tool's listing, one call with the
// arguments as given, and the end of the session, each under the
// credential, and the record names what was asked of whom.
func TestDatabricksMCPReadsEachServerKind(t *testing.T) {
	s, _, c, _ := dbMCPFixture(t, dbTokenFields(), dbServers())
	api := newDBFake(t)
	schema, _ := canon.Canonicalize([]byte(`{"type":"object","properties":{"rows":{"type":"array"}}}`), canon.CarryNumbersAsText)
	sum := sha256.Sum256(schema)
	for _, k := range []struct{ server, tool, path, schema string }{
		{"sql", "execute_sql", "/api/2.0/mcp/sql", "sha256:" + hex.EncodeToString(sum[:])},
		{"genie:" + dbSpace, "ask", "/api/2.0/mcp/genie/" + dbSpace, ""},
		{"functions:main.finance.rate", "main__finance__rate", "/api/2.0/mcp/functions/main/finance/rate", ""},
		{"ai-search:main.docs.chunks", "main__docs__chunks", "/api/2.0/mcp/ai-search/main/docs/chunks", ""},
	} {
		result := strings.Replace(dbMCPResult, "1 row", "from "+k.server, 1)
		f := dbFakeMCP(t, func(script *fakemcp.Script) { script.Result = result })
		arguments := `{ "region": "EMEA", "limit": 10, "nested": {"b": [1, "two"], "a": null} }`
		out, err := databricksAcquire(context.Background(), s, dbMCPRead(c, k.server, k.tool, arguments), dbServeOne(api, f))
		if err != nil {
			t.Fatal(k.server, err)
		}
		if got := dbMethods(f); got != "initialize,notifications/initialized,tools/list,tools/call,DELETE" {
			t.Fatalf("%s: %s", k.server, got)
		}
		sentArguments, _ := canon.Canonicalize([]byte(arguments), canon.RefuseNumbers)
		for _, r := range f.Requests() {
			if r.Path != k.path || r.Header.Get("Authorization") != "Bearer "+dbPAT {
				t.Errorf("%s: %s %s under %q", k.server, r.Verb, r.Path, r.Header.Get("Authorization"))
			}
			if r.Method != "initialize" && r.Header.Get("Mcp-Session-Id") != dbSession {
				t.Errorf("%s: %s without the session", k.server, r.Method)
			}
			if r.Method == "tools/call" {
				var call struct {
					Params struct {
						Name      string          `json:"name"`
						Arguments json.RawMessage `json:"arguments"`
					} `json:"params"`
				}
				json.Unmarshal(r.Body, &call)
				if call.Params.Name != k.tool || !bytes.Equal(call.Params.Arguments, sentArguments) {
					t.Errorf("%s: called %s with %s", k.server, call.Params.Name, call.Params.Arguments)
				}
			}
		}
		if api.api.Load() != 0 {
			t.Fatal("the API was asked")
		}
		e, err := agreement.Parse(out)
		if err != nil {
			t.Fatal("the envelope is not of the signer's form:", err)
		}
		a := e.Acquisition
		if a.Adapter.Name != "adapter-sources" || !canon.IsDigestString(a.Adapter.Digest) || a.Endpoint == nil || *a.Endpoint != dbWorkspace+k.path ||
			a.Snapshot == nil || *a.Snapshot != digest([]byte(result)) || a.PeerIdentity == nil || *a.PeerIdentity != dbLeaf(f) || a.UpstreamToken != nil {
			t.Fatalf("%s: acquisition %+v", k.server, a)
		}
		if k.schema == "" && a.Schema != nil || k.schema != "" && (a.Schema == nil || *a.Schema != k.schema) {
			t.Fatalf("%s: schema %v", k.server, a.Schema)
		}
		want, _ := canon.Canonicalize([]byte(result), canon.CarryNumbersAsText)
		if !bytes.Equal(e.Result, want) {
			t.Fatalf("%s: the result is not the tool's result: %s", k.server, e.Result)
		}
		members, err := agreement.Statement(e)
		if err != nil {
			t.Fatal(err)
		}
		for name, value := range map[string]string{"connection": `"lake"`, "revision": `"` + c.Revision + `"`, "provider": `"databricks"`, "read": `"mcp"`,
			"server": `"` + k.server + `"`, "endpoint": `"` + dbWorkspace + k.path + `"`, "tool": `"` + k.tool + `"`, "arguments": string(sentArguments)} {
			if string(members[name]) != value {
				t.Errorf("%s: statement %s = %s", k.server, name, members[name])
			}
		}
		if len(members) != 8 || bytes.Contains(out, []byte(dbSession)) || bytes.Contains(out, []byte(dbPAT)) {
			t.Fatalf("%s: %s", k.server, out)
		}
	}
}

// A read the connection does not allow is refused before anything is sent:
// a server it does not enable, a tool not on the server's list (an empty
// list allows none), and a request out of its form.
func TestDatabricksMCPRefusesWhatTheConnectionDoesNotAllow(t *testing.T) {
	servers := append(dbServers(), DatabricksMCPServer{Server: "functions:main.finance.none", Tools: []string{}})
	s, _, c, _ := dbMCPFixture(t, dbTokenFields(), servers)
	api := newDBFake(t)
	f := dbFakeMCP(t, nil)
	p := dbServeOne(api, f)
	for name, k := range map[string]struct {
		q    DatabricksRequest
		want error
	}{
		"a tool outside the list":      {dbMCPRead(c, "sql", "other", ""), databricksNotAllowed},
		"a tool of another server":     {dbMCPRead(c, "sql", "ask", ""), databricksNotAllowed},
		"a server whose list is empty": {dbMCPRead(c, "functions:main.finance.none", "main__finance__none", ""), databricksNotAllowed},
		"a server not enabled":         {dbMCPRead(c, "functions:main.finance.other", "main__finance__rate", ""), databricksNotEnabled},
		"a server named in capitals":   {dbMCPRead(c, "SQL", "execute_sql", ""), databricksNotEnabled},
		"no server":                    {dbMCPRead(c, "", "execute_sql", ""), databricksNotEnabled},
		"arguments that are a list":    {dbMCPRead(c, "sql", "execute_sql", `["SELECT 1"]`), ErrRequest},
		"arguments that are a string":  {dbMCPRead(c, "sql", "execute_sql", `"SELECT 1"`), ErrRequest},
		"a tool name with a space":     {dbMCPRead(c, "sql", "execute sql", ""), ErrRequest},
		"no tool":                      {dbMCPRead(c, "sql", "", ""), ErrRequest},
		"a statement beside": {func() DatabricksRequest {
			q := dbMCPRead(c, "sql", "execute_sql", "")
			q.Statement = "SELECT 1"
			return q
		}(), ErrRequest},
		"a catalog beside":             {func() DatabricksRequest { q := dbMCPRead(c, "sql", "execute_sql", ""); q.Catalog = "main"; return q }(), ErrRequest},
		"a statement read with a tool": {DatabricksRequest{Connection: c.ID, Revision: c.Revision, Read: "statement", Statement: "SELECT 1", Tool: "execute_sql"}, ErrRequest},
		"a listing with a server":      {DatabricksRequest{Connection: c.ID, Revision: c.Revision, Read: "catalog", List: "catalogs", Server: "sql"}, ErrRequest},
		"a listing with arguments":     {DatabricksRequest{Connection: c.ID, Revision: c.Revision, Read: "catalog", List: "catalogs", Arguments: json.RawMessage(`{}`)}, ErrRequest},
		"a read in capitals":           {func() DatabricksRequest { q := dbMCPRead(c, "sql", "execute_sql", ""); q.Read = "MCP"; return q }(), ErrRequest},
		"a stale revision": {func() DatabricksRequest {
			q := dbMCPRead(c, "sql", "execute_sql", "")
			q.Revision = strings.Repeat("0", 64)
			return q
		}(), ErrChanged},
		"a tool the list holds in case": {dbMCPRead(c, "sql", "EXECUTE_SQL", ""), databricksNotAllowed},
	} {
		out, err := databricksAcquire(context.Background(), s, k.q, p)
		if out != nil || err != k.want {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(f.Requests()) != 0 || api.api.Load() != 0 || api.mints.Load() != 0 {
		t.Fatalf("a refused read was sent: %s", dbMethods(f))
	}
	// A tool on the list that the server does not offer is not called.
	offered := dbFakeMCP(t, func(script *fakemcp.Script) { script.Tools = `[{"name":"other","inputSchema":{"type":"object"}}]` })
	out, err := databricksAcquire(context.Background(), s, dbMCPRead(c, "sql", "execute_sql", ""), dbServeOne(api, offered))
	if out != nil || err == nil || err.Error() != "tool-not-offered: the MCP server sql does not offer the tool the read names; nothing was called" || strings.Contains(dbMethods(offered), "tools/call") {
		t.Fatal(err, dbMethods(offered))
	}
}

// A server's refusal is reported in the API profile's words for its status,
// or in the client's, after one request where it came first: nothing is
// retried, a redirect is not followed, and a result that reports an error
// is refused with its text.
func TestDatabricksMCPServerRefusals(t *testing.T) {
	s, _, c, _ := dbMCPFixture(t, dbTokenFields(), dbServers())
	api := newDBFake(t)
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
	for name, k := range map[string]struct {
		change  func(*fakemcp.Script)
		want    string
		methods string
	}{
		"401": {status(401), "credentials-required: the MCP server sql: the server answered 401 Unauthorized", "initialize"},
		"403": {status(403), "permission-denied: the MCP server sql: the server answered 403 Forbidden", "initialize"},
		"404": {status(404), "request-refused: the MCP server sql: the server answered 404 Not Found", "initialize"},
		"429": {status(429, "Retry-After", "7"), "rate-limited: the MCP server sql: the server answered 429 Too Many Requests; it was not retried", "initialize"},
		"503": {status(503), "provider-unavailable: the MCP server sql: the server answered 503 Service Unavailable", "initialize"},
		"a redirect": {status(307, "Location", "/api/2.0/mcp/sql/elsewhere"),
			"provider-unavailable: the MCP server sql: the server answered 307 Temporary Redirect, a redirect, which is not followed", "initialize"},
		"a JSON-RPC refusal": {func(script *fakemcp.Script) { script.Refuse = `{"code":-32602,"message":"Unknown tool: execute_sql"}` },
			"provider-unavailable: the MCP server sql: the server answered with an error: Unknown tool: execute_sql (code -32602)", "initialize,notifications/initialized,tools/list,tools/call,DELETE"},
		"a body that is not JSON": {body("application/json", "<html>sign in</html>"),
			"provider-unavailable: the MCP server sql: the server's answer is not a JSON message in the canonical domain", "initialize,notifications/initialized,tools/list,tools/call,DELETE"},
		"a body of another type": {body("text/html", "<html>sign in</html>"),
			"provider-unavailable: the MCP server sql: the server's answer is of a content type that is neither application/json nor text/event-stream", "initialize,notifications/initialized,tools/list,tools/call,DELETE"},
		"a result that reports an error": {func(script *fakemcp.Script) {
			script.Result = `{"content":[{"type":"text","text":"PERMISSION_DENIED: no USE SCHEMA on main.sales"},{"type":"text","text":"ask an admin"}],"isError":true}`
		}, "tool-error: PERMISSION_DENIED: no USE SCHEMA on main.sales ask an admin", "initialize,notifications/initialized,tools/list,tools/call,DELETE"},
		"a result that is not one": {func(script *fakemcp.Script) { script.Result = `{"rows":[]}` },
			"provider-unavailable: the MCP server's answer is not a tool result: tools/call: the tool's result has no content array", "initialize,notifications/initialized,tools/list,tools/call,DELETE"},
		"a protocol this client does not speak": {func(script *fakemcp.Script) { script.Protocol = "2024-01-01" },
			"provider-unavailable: the MCP server sql: the server's answer is not of the form the protocol states", "initialize,DELETE"},
	} {
		f := dbFakeMCP(t, k.change)
		out, err := databricksAcquire(context.Background(), s, dbMCPRead(c, "sql", "execute_sql", `{"query":"SELECT 1"}`), dbServeOne(api, f))
		if out != nil || err == nil || err.Error() != k.want {
			t.Errorf("%s: %v", name, err)
		}
		if got := dbMethods(f); got != k.methods {
			t.Errorf("%s: %s", name, got)
		}
	}
}

// A server that answers as an event stream is read alike, and its result's
// digest is of the result as it came.
func TestDatabricksMCPAnEventStreamIsReadAlike(t *testing.T) {
	s, _, c, _ := dbMCPFixture(t, dbTokenFields(), dbServers())
	f := dbFakeMCP(t, func(script *fakemcp.Script) { script.Events = true })
	out, err := databricksAcquire(context.Background(), s, dbMCPRead(c, "genie:"+dbSpace, "ask", `{"question":"total by region"}`), dbServeOne(newDBFake(t), f))
	if err != nil {
		t.Fatal(err)
	}
	e, err := agreement.Parse(out)
	if err != nil || *e.Acquisition.Snapshot != digest([]byte(dbMCPResult)) || *e.Acquisition.PeerIdentity != dbLeaf(f) {
		t.Fatal(err, e.Acquisition)
	}
}

// The connection's bound holds the tool's result as received: one of the
// bound's size is kept, one a byte past it is not; and the client's own
// bound holds the whole answer, read no further than it.
func TestDatabricksMCPResultBound(t *testing.T) {
	fields := dbTokenFields()
	fields["max-result-bytes"] = "65536"
	s, _, c, _ := dbMCPFixture(t, fields, dbServers())
	api := newDBFake(t)
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
		{8<<20 + 1, "result-too-large: the MCP server sql: the server's answer exceeds the bound of 8388608 bytes"},
	} {
		result := sized(k.size)
		if len(result) != k.size {
			t.Fatal("fixture size", len(result))
		}
		f := dbFakeMCP(t, func(script *fakemcp.Script) { script.Result = result })
		out, err := databricksAcquire(context.Background(), s, dbMCPRead(c, "sql", "execute_sql", ""), dbServeOne(api, f))
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

// The session id the server issues is the client's alone: an answer that
// repeats it, in a result, an error, the server's own name or a tool's
// description, as written or in escapes, is refused, and no error says it.
func TestDatabricksMCPTheSessionIdIsNeverCarried(t *testing.T) {
	s, b, c, _ := dbMCPFixture(t, dbTokenFields(), dbServers())
	api := newDBFake(t)
	for name, k := range map[string]struct {
		change  func(*fakemcp.Script)
		listing bool
	}{
		"in a result": {func(script *fakemcp.Script) {
			script.Result = `{"content":[{"type":"text","text":"` + dbSession + `"}]}`
		}, false},
		"escaped in a result": {func(script *fakemcp.Script) {
			script.Result = `{"content":[{"type":"text","text":"` + dbEscaped(dbSession) + `"}]}`
		}, false},
		"in a refusal": {func(script *fakemcp.Script) {
			script.Refuse = `{"code":-32000,"message":"no session ` + dbSession + `"}`
		}, false},
		"in the server's name": {func(script *fakemcp.Script) { script.ServerInfo = `{"name":"` + dbSession + `","version":"1"}` }, true},
		"in a tool description": {func(script *fakemcp.Script) {
			script.Tools = strings.Replace(dbMCPTools, `"name":"other"`, `"name":"other","description":"`+dbSession+`"`, 1)
		}, true},
	} {
		f := dbFakeMCP(t, k.change)
		out, err := databricksAcquire(context.Background(), s, dbMCPRead(c, "sql", "execute_sql", ""), dbServeOne(api, f))
		if out != nil || err == nil || !strings.HasSuffix(err.Error(), "the server's answer repeats its session id") || strings.Contains(err.Error(), dbSession) {
			t.Errorf("%s: %v", name, err)
		}
		// A test reads the server's name and its tools, and reports neither
		// the id nor anything of an answer that repeats it.
		b.provider = dbServeOne(api, f)
		answer, err := b.Handle(context.Background(), "test", []byte(`{"id":"lake","revision":"`+c.Revision+`"}`))
		raw, _ := json.Marshal(answer)
		if err != nil || bytes.Contains(raw, []byte(dbSession)) || k.listing != bytes.Contains(raw, []byte(`"ok":false`)) {
			t.Errorf("%s: test %s %v", name, raw, err)
		}
	}
}

// The set an answer is refused by, and every error and report redacted by,
// holds the session id once the server has issued one.
func TestDatabricksMCPTheSessionIdIsInTheRefusalSet(t *testing.T) {
	_, _, c, _ := dbMCPFixture(t, dbTokenFields(), dbServers())
	f := dbFakeMCP(t, nil)
	client, err := dbServeOne(newDBFake(t), f).databricksMCPOpen(c, dbServers()[0], dbPAT)
	if err != nil {
		t.Fatal(err)
	}
	base := c.secrets(dbPAT)
	if got := databricksMCPSecrets(base, client); strings.Join(got, ",") != strings.Join(base, ",") {
		t.Fatal("a session before initialize", got)
	}
	if err = client.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer databricksMCPClose(context.Background(), client)
	got := databricksMCPSecrets(base, client)
	if len(got) != len(base)+1 || got[len(got)-1] != dbSession {
		t.Fatal(got)
	}
}

// The personal access token, the client secret and the minted token are in
// no record, error or test answer, whatever the server sends back: an answer
// that repeats one, as written or in escapes, is refused; a refusal or a
// result that reports an error has each replaced.
func TestDatabricksMCPCredentialsInAnswersAreRefused(t *testing.T) {
	var seen []string
	refused := func(name string, s *Store, c DatabricksConnection, api *dbFake, change func(*fakemcp.Script), want string) {
		t.Helper()
		f := dbFakeMCP(t, change)
		out, err := databricksAcquire(context.Background(), s, dbMCPRead(c, "sql", "execute_sql", ""), dbServeOne(api, f))
		if out != nil || err == nil || err.Error() != want {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil {
			seen = append(seen, err.Error())
		}
	}
	result := func(text string) func(*fakemcp.Script) {
		return func(script *fakemcp.Script) { script.Result = `{"content":[{"type":"text","text":"` + text + `"}]}` }
	}
	byClient := "provider-unavailable: the MCP server sql: the server's answer repeats the credential"
	byConnection := "provider-unavailable: the MCP server's answer repeats the credential or its session id, and is not kept"
	ts, _, tc, _ := dbMCPFixture(t, dbTokenFields(), dbServers())
	tapi := newDBFake(t)
	refused("the token", ts, tc, tapi, result(dbPAT), byClient)
	refused("the token escaped", ts, tc, tapi, result(dbEscaped(dbPAT)), byClient)
	ss, sb, sc, _ := dbMCPFixture(t, dbPrincipalFields(), dbServers())
	sapi := newDBFake(t)
	refused("the minted token escaped", ss, sc, sapi, result(dbEscaped(dbMinted)), byClient)
	refused("the client secret", ss, sc, sapi, result(dbSecret), byConnection)
	refused("the client secret escaped", ss, sc, sapi, result(dbEscaped(dbSecret)), byConnection)
	refused("the client secret escaped in a member name", ss, sc, sapi, func(script *fakemcp.Script) {
		script.Result = `{"content":[{"type":"text","text":"1"}],"structuredContent":{"` + dbEscaped(dbSecret) + `":1}}`
	}, byConnection)
	refused("the client secret in a refusal", ss, sc, sapi, func(script *fakemcp.Script) {
		script.Refuse = `{"code":-32000,"message":"denied for ` + dbEscaped(dbSecret) + `"}`
	}, "provider-unavailable: the MCP server sql: the server answered with an error: denied for [redacted] (code -32000)")
	refused("the client secret in an error result", ss, sc, sapi, func(script *fakemcp.Script) {
		script.Result = `{"content":[{"type":"text","text":"denied for ` + dbEscaped(dbSecret) + `"}],"isError":true}`
	}, "tool-error: denied for [redacted]")
	// A long error's text has the secret replaced before it is cut.
	long := strings.Repeat("x", databricksMessageBytes-len("tool-error: ")-len(dbSecret)+1) + dbSecret
	refused("the client secret across the cut", ss, sc, sapi, func(script *fakemcp.Script) {
		script.Result = `{"content":[{"type":"text","text":"` + long + `"}],"isError":true}`
	}, databricksClip("tool-error: "+strings.Repeat("x", databricksMessageBytes-len("tool-error: ")-len(dbSecret)+1)+"[redacted]"))
	// A test reports no secret among the names a server offers.
	sb.provider = dbServeOne(sapi, dbFakeMCP(t, func(script *fakemcp.Script) {
		script.Tools = `[{"name":"execute_sql","inputSchema":{"type":"object"}},{"name":"` + dbEscaped(dbSecret) + `","inputSchema":{"type":"object"}}]`
	}))
	answer, err := sb.Handle(context.Background(), "test", []byte(`{"id":"lake","revision":"`+sc.Revision+`"}`))
	raw, _ := json.Marshal(answer)
	if err != nil || !bytes.Contains(raw, []byte(`"offered":["execute_sql","[redacted]"]`)) {
		t.Fatalf("test %s %v", raw, err)
	}
	seen = append(seen, string(raw))
	for _, text := range seen {
		for _, marker := range []string{dbPAT, dbSecret, dbMinted, dbSession} {
			if strings.Contains(text, marker) {
				t.Errorf("a credential in %q", text)
			}
		}
	}
}

// A read whose arguments, tool or server carry the connection's credential
// is refused before anything is sent: the token as written or in escapes,
// in a value or a member name; the client secret before a token is asked
// for; the token held for it before another is; one minted now before the
// server is reached.
func TestDatabricksMCPArgumentsCarryingTheCredentialAreNotSent(t *testing.T) {
	refused := func(name string, s *Store, q DatabricksRequest, api *dbFake, mints int32) {
		t.Helper()
		f := dbFakeMCP(t, nil)
		out, err := databricksAcquire(context.Background(), s, q, dbServeOne(api, f))
		if out != nil || err != databricksInRequest || len(f.Requests()) != 0 || api.mints.Load() != mints {
			t.Errorf("%s: %v, %d requests, %d token requests", name, err, len(f.Requests()), api.mints.Load())
		}
	}
	s, _, c, _ := dbMCPFixture(t, dbTokenFields(), dbServers())
	api := newDBFake(t)
	refused("the token in a value", s, dbMCPRead(c, "sql", "execute_sql", `{"query":"SELECT '`+dbPAT+`'"}`), api, 0)
	refused("the token escaped", s, dbMCPRead(c, "sql", "execute_sql", `{"query":"`+dbEscaped(dbPAT)+`"}`), api, 0)
	refused("the token as a member name", s, dbMCPRead(c, "sql", "execute_sql", `{"`+dbEscaped(dbPAT)+`":1}`), api, 0)
	refused("the token nested", s, dbMCPRead(c, "sql", "execute_sql", `{"a":{"b":["x","`+dbPAT+`"]}}`), api, 0)
	// A token of a tool name's form, as the tool.
	plain := "dapiABCDEF0123456789abcdef"
	fields := dbTokenFields()
	fields["token"] = plain
	ps, _, pc, _ := dbMCPFixture(t, fields, []DatabricksMCPServer{{Server: "sql", Tools: []string{plain}}})
	refused("the token as the tool", ps, dbMCPRead(pc, "sql", plain, ""), api, 0)
	// A service principal.
	ss, _, sc, _ := dbMCPFixture(t, dbPrincipalFields(), dbServers())
	sapi := newDBFake(t)
	refused("the client secret", ss, dbMCPRead(sc, "sql", "execute_sql", `{"query":"`+dbSecret+`"}`), sapi, 0)
	refused("a token minted for it", ss, dbMCPRead(sc, "sql", "execute_sql", `{"query":"`+dbEscaped(dbMinted)+`"}`), sapi, 1)
	f := dbFakeMCP(t, nil)
	if _, err := databricksAcquire(context.Background(), ss, dbMCPRead(sc, "sql", "execute_sql", `{}`), dbServeOne(sapi, f)); err != nil || sapi.mints.Load() != 1 {
		t.Fatal(err, sapi.mints.Load())
	}
	if r := f.Requests(); len(r) == 0 || r[0].Header.Get("Authorization") != "Bearer "+dbMinted {
		t.Fatal("the minted token is not the bearer")
	}
	refused("the token it holds", ss, dbMCPRead(sc, "sql", "execute_sql", `{"query":"`+dbMinted+`"}`), sapi, 1)
}

// The members a result is decided by are read by their exact names: a
// result that also names one in another case, or twice, is refused, and so
// is a tool descriptor whose output schema is named in another case.
func TestDatabricksMCPTheMembersDecidedByAreReadByExactName(t *testing.T) {
	s, _, c, _ := dbMCPFixture(t, dbTokenFields(), dbServers())
	api := newDBFake(t)
	malformed := "provider-unavailable: the MCP server's answer is not of the form this connection reads, or names a member it reads in another case"
	// A member named twice the client refuses first, as JSON outside the
	// canonical domain.
	twice := "provider-unavailable: the MCP server sql: the server's answer is not a JSON message in the canonical domain"
	text := `[{"type":"text","text":"1 row"}]`
	for name, k := range map[string]struct{ result, tools, want string }{
		"isError beside a capital that says otherwise": {`{"content":` + text + `,"isError":false,"IsError":true}`, "", malformed},
		"isError in capitals alone":                    {`{"content":` + text + `,"ISERROR":true}`, "", malformed},
		"isError twice":                                {`{"content":` + text + `,"isError":false,"isError":true}`, "", twice},
		"content beside its capital":                   {`{"content":` + text + `,"Content":[{"type":"text","text":"other"}]}`, "", malformed},
		"structured content beside a capital":          {`{"content":` + text + `,"structuredContent":{},"StructuredContent":{"rows":[]}}`, "", malformed},
		"a text beside its capital":                    {`{"content":[{"type":"text","text":"a","Text":"b"}]}`, "", malformed},
		"isError beside its long s":                    {`{"content":` + text + `,"isError":false,"iſError":true}`, "", malformed},
		"a type twice":                                 {`{"content":[{"type":"text","text":"a","type":"image"}]}`, "", twice},
		"an output schema beside its capital": {dbMCPResult, `[{"name":"execute_sql","inputSchema":{"type":"object"},"outputSchema":{"type":"object"},"OutputSchema":{"type":"string"}}]`,
			"provider-unavailable: the MCP server's tool descriptor names a member it is read by in another case"},
	} {
		f := dbFakeMCP(t, func(script *fakemcp.Script) {
			script.Result = k.result
			if k.tools != "" {
				script.Tools = k.tools
			}
		})
		out, err := databricksAcquire(context.Background(), s, dbMCPRead(c, "sql", "execute_sql", ""), dbServeOne(api, f))
		if out != nil || err == nil || err.Error() != k.want {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A member the connection does not decide by is the result's own.
	f := dbFakeMCP(t, func(script *fakemcp.Script) {
		script.Result = `{"content":[{"type":"text","text":"1","Annotations":{}}],"_meta":{"Total":1},"Meta":true}`
	})
	if _, err := databricksAcquire(context.Background(), s, dbMCPRead(c, "sql", "execute_sql", ""), dbServeOne(api, f)); err != nil {
		t.Fatal(err)
	}
}

// The servers a connection enables are held to their forms, case by case,
// each refused by configure with nothing kept.
func TestDatabricksMCPConfigurationForms(t *testing.T) {
	tools := func(n int) []string {
		out := []string{}
		for i := range n {
			out = append(out, "tool_"+strings.Repeat("x", i))
		}
		return out
	}
	many := func(n int) []DatabricksMCPServer {
		out := []DatabricksMCPServer{{Server: "sql", Tools: []string{}}}
		for i := 1; i < n; i++ {
			out = append(out, DatabricksMCPServer{Server: "functions:main.finance.f" + strings.Repeat("x", i), Tools: []string{"t"}})
		}
		return out
	}
	accepted := map[string]any{
		"none":                                   []DatabricksMCPServer{},
		"each kind":                              dbServers(),
		"an empty list":                          []DatabricksMCPServer{{Server: "sql", Tools: []string{}}},
		"no list":                                []map[string]any{{"server": "sql"}},
		"a null list":                            []map[string]any{{"server": "sql", "tools": nil}},
		"sixteen servers":                        many(16),
		"thirty-two tools":                       []DatabricksMCPServer{{Server: "sql", Tools: tools(32)}},
		"a tool of 128 characters":               []DatabricksMCPServer{{Server: "sql", Tools: []string{strings.Repeat("a", 128)}}},
		"a tool with dots and hyphens":           []DatabricksMCPServer{{Server: "sql", Tools: []string{"admin.tools-list_v2"}}},
		"a name a path segment escapes":          []DatabricksMCPServer{{Server: "functions:main.fin?ance.r%ate", Tools: []string{"t"}}},
		"a Unity Catalog name in another script": []DatabricksMCPServer{{Server: "ai-search:main.docs.índice", Tools: []string{"t"}}},
	}
	refused := map[string]any{
		"sql with a key":                         []DatabricksMCPServer{{Server: "sql:main", Tools: []string{}}},
		"a space of 31 characters":               []DatabricksMCPServer{{Server: "genie:" + dbSpace[1:], Tools: []string{}}},
		"a space in capitals":                    []DatabricksMCPServer{{Server: "genie:" + strings.ToUpper(dbSpace), Tools: []string{}}},
		"a space with hyphens":                   []DatabricksMCPServer{{Server: "genie:01f0a1b2-c3d4-e5f6-0718-293a4b5c6d7e", Tools: []string{}}},
		"genie without a space":                  []DatabricksMCPServer{{Server: "genie", Tools: []string{}}},
		"a schema's functions":                   []DatabricksMCPServer{{Server: "functions:main.finance", Tools: []string{}}},
		"a function of four names":               []DatabricksMCPServer{{Server: "functions:main.finance.rate.x", Tools: []string{}}},
		"a function with an empty name":          []DatabricksMCPServer{{Server: "functions:main..rate", Tools: []string{}}},
		"a function with a space":                []DatabricksMCPServer{{Server: "functions:main.fin ance.rate", Tools: []string{}}},
		"a function with a slash":                []DatabricksMCPServer{{Server: "functions:main.fin/ance.rate", Tools: []string{}}},
		"a function with a control character":    []DatabricksMCPServer{{Server: "functions:main.fin\tance.rate", Tools: []string{}}},
		"an index of two names":                  []DatabricksMCPServer{{Server: "ai-search:main.docs", Tools: []string{}}},
		"the former vector search prefix":        []DatabricksMCPServer{{Server: "vector-search:main.docs.chunks", Tools: []string{}}},
		"a kind in capitals":                     []DatabricksMCPServer{{Server: "SQL", Tools: []string{}}},
		"an unknown kind":                        []DatabricksMCPServer{{Server: "external:slack", Tools: []string{}}},
		"no server":                              []DatabricksMCPServer{{Server: "", Tools: []string{}}},
		"a server twice":                         []DatabricksMCPServer{{Server: "sql", Tools: []string{}}, {Server: "sql", Tools: []string{"a"}}},
		"seventeen servers":                      many(17),
		"thirty-three tools":                     []DatabricksMCPServer{{Server: "sql", Tools: tools(33)}},
		"a tool of 129 characters":               []DatabricksMCPServer{{Server: "sql", Tools: []string{strings.Repeat("a", 129)}}},
		"an empty tool":                          []DatabricksMCPServer{{Server: "sql", Tools: []string{""}}},
		"a tool with a space":                    []DatabricksMCPServer{{Server: "sql", Tools: []string{"execute sql"}}},
		"a tool with a slash":                    []DatabricksMCPServer{{Server: "sql", Tools: []string{"a/b"}}},
		"a tool outside ASCII":                   []DatabricksMCPServer{{Server: "sql", Tools: []string{"índice"}}},
		"a tool twice":                           []DatabricksMCPServer{{Server: "sql", Tools: []string{"a", "a"}}},
		"a server named in capitals as a member": []map[string]any{{"Server": "sql", "tools": []string{}}},
		"a member beside":                        []map[string]any{{"server": "sql", "tools": []string{}, "scope": "sql"}},
		"a list that is not one":                 map[string]any{"server": "sql"},
		"tools that are text":                    []map[string]any{{"server": "sql", "tools": "execute_sql"}},
	}
	_, b, _, dir := dbFixture(t, dbTokenFields())
	for name, servers := range accepted {
		fields := dbTokenFields()
		fields["id"] = "kept"
		if err := dbConfigureMCP(b, fields, servers); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		c := dbConnection(t, b.store, "kept")
		if _, err := b.Handle(context.Background(), "disconnect", []byte(`{"id":"kept","revision":"`+c.Revision+`"}`)); err != nil {
			t.Fatal(err)
		}
	}
	for name, servers := range refused {
		fields := dbTokenFields()
		fields["id"] = "other"
		if err := dbConfigureMCP(b, fields, servers); err != ErrRequest || bytes.Contains(dbState(t, dir), []byte(`"other"`)) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The path each server's name stands for.
	for name, path := range map[string]string{
		"sql":                           "/api/2.0/mcp/sql",
		"genie:" + dbSpace:              "/api/2.0/mcp/genie/" + dbSpace,
		"functions:main.finance.rate":   "/api/2.0/mcp/functions/main/finance/rate",
		"functions:main.fin?ance.r%ate": "/api/2.0/mcp/functions/main/fin%3Fance/r%25ate",
		"ai-search:main.docs.índice":    "/api/2.0/mcp/ai-search/main/docs/%C3%ADndice",
		"ai-search:main.docs.a#b":       "/api/2.0/mcp/ai-search/main/docs/a%23b",
	} {
		if got := databricksMCPPath(name); got != path {
			t.Errorf("%s: %s", name, got)
		}
	}
}

// A test reaches each server: initialize and its tools, reporting what each
// offers and which names on its list it does not, and calls no tool; a
// server that refuses is reported, and the others still are. Status names
// the servers and their lists, and never a credential.
func TestDatabricksMCPTestListsEachServersToolsAndCallsNone(t *testing.T) {
	servers := []DatabricksMCPServer{
		{Server: "sql", Tools: []string{"execute_sql", "missing_tool"}},
		{Server: "genie:" + dbSpace, Tools: []string{"ask"}},
		{Server: "functions:main.finance.rate", Tools: []string{}},
	}
	_, b, c, _ := dbMCPFixture(t, dbTokenFields(), servers)
	api := newDBFake(t)
	api.set(func(w http.ResponseWriter, r *http.Request, _ []byte) {
		w.Write([]byte(`{"catalogs":[{"name":"main"}]}`))
	})
	sql := dbFakeMCP(t, nil)
	genie := dbFakeMCP(t, func(script *fakemcp.Script) {
		script.Answer = func(w http.ResponseWriter, method string, _ json.RawMessage) bool {
			w.WriteHeader(403)
			return true
		}
	})
	b.provider = dbServe(api, map[string]*fakemcp.HTTPServer{"/api/2.0/mcp/": sql, "/api/2.0/mcp/genie/": genie})
	answer, err := b.Handle(context.Background(), "test", []byte(`{"id":"lake","revision":"`+c.Revision+`"}`))
	raw, _ := json.Marshal(answer)
	want := `{"mcp":[` +
		`{"server":"sql","ok":true,"offered":["execute_sql","ask","main__finance__rate","main__docs__chunks","other"],"notOffered":["missing_tool"]},` +
		`{"server":"genie:` + dbSpace + `","ok":false,"offered":[],"notOffered":[],"error":"permission-denied: the MCP server genie:` + dbSpace + `: the server answered 403 Forbidden"},` +
		`{"server":"functions:main.finance.rate","ok":true,"offered":["execute_sql","ask","main__finance__rate","main__docs__chunks","other"],"notOffered":[]}],"ok":false}`
	if err != nil || string(raw) != want {
		t.Fatalf("test %s %v", raw, err)
	}
	for _, f := range []*fakemcp.HTTPServer{sql, genie} {
		if strings.Contains(dbMethods(f), "tools/call") {
			t.Fatal("a test called a tool:", dbMethods(f))
		}
	}
	if got := dbMethods(sql); got != "initialize,notifications/initialized,tools/list,DELETE,initialize,notifications/initialized,tools/list,DELETE" {
		t.Fatal(got)
	}
	if api.api.Load() != 1 {
		t.Fatal("the API test was not one request", api.api.Load())
	}
	status, err := b.Handle(context.Background(), "status", []byte(`{}`))
	raw, _ = json.Marshal(status)
	if err != nil || !bytes.Contains(raw, []byte(`"mcp":[{"server":"sql","tools":["execute_sql","missing_tool"]},{"server":"genie:`+dbSpace+`","tools":["ask"]},{"server":"functions:main.finance.rate","tools":[]}]`)) ||
		bytes.Contains(raw, []byte(dbPAT)) || !bytes.Contains(raw, []byte(`"maxMCPServers":16`)) {
		t.Fatalf("status %s %v", raw, err)
	}
	// Every server answering, the test is ok.
	b.provider = dbServeOne(api, sql)
	answer, err = b.Handle(context.Background(), "test", []byte(`{"id":"lake","revision":"`+c.Revision+`"}`))
	raw, _ = json.Marshal(answer)
	if err != nil || !bytes.HasSuffix(raw, []byte(`"ok":true}`)) {
		t.Fatalf("test %s %v", raw, err)
	}
	// An API test that fails reaches no server.
	api.set(func(w http.ResponseWriter, r *http.Request, _ []byte) { w.WriteHeader(403) })
	before := len(sql.Requests())
	answer, err = b.Handle(context.Background(), "test", []byte(`{"id":"lake","revision":"`+c.Revision+`"}`))
	if err == nil || err.Error() != "permission-denied: the workspace answered 403" || len(sql.Requests()) != before {
		t.Fatal(answer, err)
	}
}

// The live check reads one tool's result from a workspace's server the
// environment names. Without it, it is not run, and says so.
func TestDatabricksMCPLiveCheck(t *testing.T) {
	workspace, server, tool := os.Getenv("JPACK_DATABRICKS_LIVE_WORKSPACE"), os.Getenv("JPACK_DATABRICKS_LIVE_MCP_SERVER"), os.Getenv("JPACK_DATABRICKS_LIVE_MCP_TOOL")
	if workspace == "" || server == "" || tool == "" {
		t.Skip("not run: JPACK_DATABRICKS_LIVE_WORKSPACE, JPACK_DATABRICKS_LIVE_WAREHOUSE, JPACK_DATABRICKS_LIVE_TOKEN (or _CLIENT_ID and _CLIENT_SECRET), JPACK_DATABRICKS_LIVE_MCP_SERVER, JPACK_DATABRICKS_LIVE_MCP_TOOL and JPACK_DATABRICKS_LIVE_MCP_ARGUMENTS name no workspace server")
	}
	fields := map[string]string{"id": "live", "name": "Live", "workspace-url": workspace, "warehouse-id": os.Getenv("JPACK_DATABRICKS_LIVE_WAREHOUSE"), "auth": "token", "token": os.Getenv("JPACK_DATABRICKS_LIVE_TOKEN")}
	if id := os.Getenv("JPACK_DATABRICKS_LIVE_CLIENT_ID"); id != "" {
		fields["auth"], fields["token"], fields["client-id"], fields["client-secret"] = "service-principal", "", id, os.Getenv("JPACK_DATABRICKS_LIVE_CLIENT_SECRET")
	}
	s, b, c, _ := dbMCPFixture(t, fields, []DatabricksMCPServer{{Server: server, Tools: []string{tool}}})
	answer, err := b.Handle(context.Background(), "test", []byte(`{"id":"live","revision":"`+c.Revision+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("test: %v", answer)
	raw, err := databricksAcquire(context.Background(), s, dbMCPRead(c, server, tool, os.Getenv("JPACK_DATABRICKS_LIVE_MCP_ARGUMENTS")), databricksProvider())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = agreement.Parse(raw); err != nil {
		t.Fatal(err)
	}
}
