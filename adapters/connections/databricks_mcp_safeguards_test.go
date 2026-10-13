//go:build linux || darwin

package connections

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// The safeguards a cross-vendor review of the MCP profile asked for (round
// 1, at 00f28b7), held by its probes, adopted as regressions: a workspace
// answering in process, without a listener, as each probe scripts it.

// dbMCPTransport is a workspace whose token endpoint, API and managed MCP
// servers answer in process: initialize, tools/list and tools/call as
// scripted, counting what it was asked.
type dbMCPTransport struct {
	t                                     *testing.T
	c                                     DatabricksConnection
	init, list, result, rpcError, session string
	redirect                              bool
	oversize, path                        string
	requests, calls, lists                int
}

func (x *dbMCPTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	x.requests++
	if r.URL.Scheme != "https" || r.URL.Host != dbHost {
		x.t.Fatal("the endpoint changed:", r.URL)
	}
	header := http.Header{"Content-Type": {"application/json"}}
	answer := func(status int, body string) *http.Response {
		return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), ContentLength: -1, Request: r,
			TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: []byte("result peer")}}}}
	}
	if x.redirect {
		header.Set("Location", "https://other.cloud.databricks.com/")
		return answer(307, ""), nil
	}
	if r.URL.Path == "/oidc/v1/token" {
		return answer(200, dbMintedAnswer), nil
	}
	if strings.HasPrefix(r.URL.Path, "/api/2.0/mcp/") && x.path != "" && r.URL.Path != x.path {
		x.t.Fatal("another MCP endpoint:", r.URL.Path)
	}
	bearer := x.c.Token
	if bearer == "" {
		bearer = dbMinted
	}
	if r.Header.Get("Authorization") != "Bearer "+bearer {
		x.t.Fatal("another bearer")
	}
	switch r.Method {
	case "GET":
		return answer(200, `{"catalogs":[]}`), nil
	case "DELETE":
		return answer(200, ""), nil
	}
	var q struct {
		ID     int    `json:"id"`
		Method string `json:"method"`
	}
	raw, _ := io.ReadAll(r.Body)
	if json.Unmarshal(raw, &q) != nil {
		x.t.Fatal("a request that is not JSON")
	}
	result := "{}"
	switch q.Method {
	case "initialize":
		result = x.init
		if result == "" {
			result = `{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}`
		}
		if x.session != "" {
			header.Set("Mcp-Session-Id", x.session)
		}
	case "notifications/initialized":
		return answer(202, ""), nil
	case "tools/list":
		x.lists++
		result = x.list
		if result == "" {
			result = `{"tools":` + dbMCPTools + `}`
		}
	case "tools/call":
		x.calls++
		result = x.result
		if result == "" {
			result = dbMCPResult
		}
		if x.rpcError != "" {
			return answer(200, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"error":%s}`, q.ID, x.rpcError)), nil
		}
	default:
		x.t.Fatal("an unexpected method:", q.Method)
	}
	if x.oversize == q.Method {
		result = strings.Repeat(" ", max(x.c.resultBound()+databricksErrorBytes, 8<<20)+1) + "{}"
	}
	return answer(200, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":%s}`, q.ID, result)), nil
}
func dbMCPThrough(x *dbMCPTransport) provider {
	p := databricksProvider()
	p.client = &http.Client{Transport: x}
	return p
}

// dbErrorText is a tool's error result whose text is JSON holding secret
// in escapes, as a reader that decodes it would find it.
func dbErrorText(secret string) string {
	raw, _ := json.Marshal(map[string]any{"content": []any{map[string]any{"type": "text", "text": `{"secret":"` + dbEscaped(secret) + `"}`}}, "isError": true})
	return string(raw)
}

// dbAbsent fails where text holds any of the credentials or the session id,
// as written or in escapes.
func dbAbsent(t *testing.T, name, text string) {
	t.Helper()
	for _, marker := range []string{dbPAT, dbSecret, dbMinted, dbSession} {
		if strings.Contains(text, marker) || strings.Contains(text, dbEscaped(marker)) || databricksSpells(text, []string{marker}) {
			t.Errorf("%s: %q holds a credential or the session id", name, text)
		}
	}
}

// A server's text -- a tool's error, a JSON-RPC error's message -- that
// spells a credential or the session id once the JSON it holds is decoded
// is not reported at all; the refusal says why, in words of its own.
func TestDatabricksMCPAServersTextThatSpellsASecretIsNotReported(t *testing.T) {
	for _, kind := range []string{"token", "session id", "client secret"} {
		fields, secret := dbTokenFields(), dbPAT
		switch kind {
		case "session id":
			secret = dbSession
		case "client secret":
			fields, secret = dbPrincipalFields(), dbSecret
		}
		s, _, c, _ := dbMCPFixture(t, fields, dbServers())
		x := &dbMCPTransport{t: t, c: c, session: dbSession, result: dbErrorText(secret)}
		out, err := databricksAcquire(context.Background(), s, dbMCPRead(c, "sql", "execute_sql", ""), dbMCPThrough(x))
		if out != nil || err == nil || err.Error() != "tool-error: the tool reported an error whose text repeats the credential or its session id; the text is not reported" || x.calls != 1 {
			t.Errorf("%s in a tool's error: %v", kind, err)
		}
		if err != nil {
			dbAbsent(t, kind, err.Error())
		}
		message, _ := json.Marshal(map[string]any{"code": -32000, "message": `{"secret":"` + dbEscaped(secret) + `"}`})
		x = &dbMCPTransport{t: t, c: c, session: dbSession, rpcError: string(message)}
		out, err = databricksAcquire(context.Background(), s, dbMCPRead(c, "sql", "execute_sql", ""), dbMCPThrough(x))
		if out != nil || err == nil || err.Error() != "provider-unavailable: the MCP server sql: the server's text repeats the credential or its session id, and is not reported" {
			t.Errorf("%s in a JSON-RPC error: %v", kind, err)
		}
		if err != nil {
			dbAbsent(t, kind, err.Error())
		}
	}
}

// A server's name or a tool on its list that names the connection's
// credential is refused by configure; one that names a token held for it
// is not reported by status; and the session id, where it is a name the
// operator configured, is in no test answer and no error.
func TestDatabricksMCPConfiguredNamesNeverCarryASecret(t *testing.T) {
	_, b, _, dir := dbFixture(t, dbTokenFields())
	plain := "dapiABCDEF0123456789abcdef"
	for name, k := range map[string]struct {
		token   string
		servers []DatabricksMCPServer
	}{
		"the token as a tool":                {plain, []DatabricksMCPServer{{Server: "sql", Tools: []string{"execute_sql", plain}}}},
		"the token in a server's name":       {dbPAT, []DatabricksMCPServer{{Server: "functions:main.finance." + dbPAT, Tools: []string{}}}},
		"the token escaped in a server name": {dbPAT, []DatabricksMCPServer{{Server: "functions:main.finance." + dbEscaped(dbPAT), Tools: []string{}}}},
	} {
		fields := dbTokenFields()
		fields["id"] = "other"
		fields["token"] = k.token
		if err := dbConfigureMCP(b, fields, k.servers); err != ErrRequest || bytes.Contains(dbState(t, dir), []byte(`"other"`)) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A token held for a service principal that a tool's name spells.
	held := "held-marker-access-token-9a7c"
	ss, sb, sc, _ := dbMCPFixture(t, dbPrincipalFields(), []DatabricksMCPServer{{Server: "sql", Tools: []string{"execute_sql", held}}})
	ss.locked(func(v *state) error {
		v.Databricks.Tokens = []databricksToken{{sc.ID, sc.Revision, held, 1 << 40}}
		return ss.write("state.json", v)
	})
	status, err := sb.Handle(context.Background(), "status", []byte(`{}`))
	raw, _ := json.Marshal(status)
	if err != nil || bytes.Contains(raw, []byte(held)) || !bytes.Contains(raw, []byte(`"ready":false`)) {
		t.Fatalf("status %s %v", raw, err)
	}
	// The session id, as a tool on the list the server does not offer, and
	// as a part of a server's name.
	s, _, c, _ := dbMCPFixture(t, dbTokenFields(), []DatabricksMCPServer{{Server: "sql", Tools: []string{dbSession}}, {Server: "functions:main.schema." + dbSession, Tools: []string{"missing"}}})
	x := &dbMCPTransport{t: t, c: c, session: dbSession}
	reports, err := dbMCPThrough(x).databricksMCPTest(context.Background(), s, c.ID, c.Revision)
	raw, _ = json.Marshal(reports)
	if err != nil || x.calls != 0 || !bytes.Contains(raw, []byte(`"notOffered":["[redacted]"]`)) || !bytes.Contains(raw, []byte(`"server":"functions:main.schema.[redacted]"`)) {
		t.Fatalf("test %s %v", raw, err)
	}
	dbAbsent(t, "test", string(raw))
	server := "functions:main.schema." + dbSession
	out, err := databricksAcquire(context.Background(), s, dbMCPRead(c, server, "missing", ""), dbMCPThrough(&dbMCPTransport{t: t, c: c, session: dbSession}))
	if out != nil || err == nil || err.Error() != "tool-not-offered: the MCP server functions:main.schema.[redacted] does not offer the tool the read names; nothing was called" {
		t.Fatal(err)
	}
}

// Every answer is screened before it is read -- initialize, each tools/list
// page -- for the client secret, which the client itself does not know:
// one that names it, as written or in escapes, ends the read, and no tool
// is called.
func TestDatabricksMCPEveryAnswerIsScreenedBeforeItIsRead(t *testing.T) {
	for name, k := range map[string]struct{ init, list string }{
		"the client secret as the server's name": {`{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"` + dbSecret + `","version":"1"}}`, ""},
		"the client secret escaped in a schema":  {"", `{"tools":[{"name":"execute_sql","outputSchema":{"type":"object","description":"` + dbEscaped(dbSecret) + `"}}]}`},
		"the client secret in another tool":      {"", `{"tools":[{"name":"other","description":"` + dbSecret + `"},{"name":"execute_sql"}]}`},
	} {
		s, _, c, _ := dbMCPFixture(t, dbPrincipalFields(), dbServers())
		x := &dbMCPTransport{t: t, c: c, init: k.init, list: k.list}
		out, err := databricksAcquire(context.Background(), s, dbMCPRead(c, "sql", "execute_sql", ""), dbMCPThrough(x))
		if out != nil || err == nil || err.Error() != "provider-unavailable: the MCP server sql: the server's answer repeats the credential or its session id, and is not kept" || x.calls != 0 {
			t.Errorf("%s: %v, %d calls", name, err, x.calls)
		}
	}
}

// The handshake and the listing are read by the exact names of the members
// they are decided by: an alias in another case, or a handshake without
// its shape, is refused, and no tool is called.
func TestDatabricksMCPTheHandshakeAndTheListingAreReadByExactName(t *testing.T) {
	initialize := "provider-unavailable: the MCP server sql: initialize: the server's answer is not an initialize result of the protocol's form, or names a member it is read by in another case"
	listing := "provider-unavailable: the MCP server sql: tools/list: the server's answer is not a tool list of the protocol's form, or names a member it is read by in another case"
	shape := `"capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}`
	for name, k := range map[string]struct{ init, list, want string }{
		"a protocol version beside its alias":     {`{"protocolVersion":"unsupported","ProtocolVersion":"2025-11-25",` + shape + `}`, "", initialize},
		"a protocol version an alias contradicts": {`{"protocolVersion":"2025-11-25","ProtocolVersion":"unsupported",` + shape + `}`, "", initialize},
		"a protocol version as an alias alone":    {`{"ProtocolVersion":"2025-11-25",` + shape + `}`, "", initialize},
		"no capabilities":                         {`{"protocolVersion":"2025-11-25","serverInfo":{"name":"fixture","version":"1"}}`, "", initialize},
		"no tools capability":                     {`{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}`, "", initialize},
		"a tools capability beside its alias":     {`{"protocolVersion":"2025-11-25","capabilities":{"tools":{},"Tools":null},"serverInfo":{"name":"fixture","version":"1"}}`, "", initialize},
		"no server info":                          {`{"protocolVersion":"2025-11-25","capabilities":{"tools":{}}}`, "", initialize},
		"a server's name beside its alias":        {`{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","Name":"other","version":"1"}}`, "", initialize},
		"tools beside their alias":                {"", `{"tools":` + dbMCPTools + `,"Tools":[]}`, listing},
		"a next cursor as an alias":               {"", `{"tools":` + dbMCPTools + `,"NextCursor":"more"}`, listing},
		"a tool's name beside its alias":          {"", `{"tools":[{"name":"execute_sql","Name":"other"}]}`, listing},
		"no tools":                                {"", `{"nextCursor":"2"}`, listing},
	} {
		s, _, c, _ := dbMCPFixture(t, dbTokenFields(), dbServers())
		x := &dbMCPTransport{t: t, c: c, init: k.init, list: k.list}
		out, err := databricksAcquire(context.Background(), s, dbMCPRead(c, "sql", "execute_sql", ""), dbMCPThrough(x))
		if out != nil || err == nil || err.Error() != k.want || x.calls != 0 {
			t.Errorf("%s: %v, %d calls", name, err, x.calls)
		}
	}
}

// What the review found held, held: each answer's bound at every stage; no
// request for a read the list refuses or whose arguments carry the
// credential; one request for a redirect; nothing called for a tool not
// offered or a listing that does not end.
func TestDatabricksMCPTheReviewsHoldsStillHold(t *testing.T) {
	for _, stage := range []string{"initialize", "tools/list", "tools/call"} {
		s, _, c, _ := dbMCPFixture(t, dbTokenFields(), dbServers())
		x := &dbMCPTransport{t: t, c: c, oversize: stage}
		out, err := databricksAcquire(context.Background(), s, dbMCPRead(c, "sql", "execute_sql", ""), dbMCPThrough(x))
		if out != nil || err == nil || !strings.Contains(err.Error(), "exceeds the bound") || stage != "tools/call" && x.calls != 0 {
			t.Errorf("an answer past the bound at %s: %v", stage, err)
		}
	}
	for _, kind := range []string{"success", "outside the list", "not offered", "a secret in the arguments", "a redirect", "not JSON", "past the result bound", "a listing that does not end"} {
		s, _, c, _ := dbMCPFixture(t, dbTokenFields(), dbServers())
		x := &dbMCPTransport{t: t, c: c}
		q := dbMCPRead(c, "sql", "execute_sql", "")
		switch kind {
		case "outside the list":
			q.Tool = "other"
		case "not offered":
			x.list = `{"tools":[]}`
		case "a secret in the arguments":
			q.Arguments = json.RawMessage(`{"value":"` + dbEscaped(dbPAT) + `"}`)
		case "a redirect":
			x.redirect = true
		case "not JSON":
			x.result = `not json`
		case "past the result bound":
			x.result = `{"content":[{"type":"text","text":"` + strings.Repeat("x", c.resultBound()) + `"}]}`
		case "a listing that does not end":
			x.list = `{"tools":[],"nextCursor":"again"}`
		}
		out, err := databricksAcquire(context.Background(), s, q, dbMCPThrough(x))
		if (kind == "success") != (err == nil && out != nil) {
			t.Errorf("%s: %v", kind, err)
		}
		if (kind == "outside the list" || kind == "a secret in the arguments") && x.requests != 0 || kind == "a redirect" && x.requests != 1 || (kind == "not offered" || kind == "a listing that does not end") && x.calls != 0 {
			t.Errorf("%s: %d requests, %d calls", kind, x.requests, x.calls)
		}
	}
}

// Each server kind's record: the configured path, the bearer, the eight
// members, the read committed, the result as received in the snapshot,
// the listed schema's digest, and the peer the result came from; a test
// lists each server and calls nothing.
func TestDatabricksMCPRecordsHoldTheirForm(t *testing.T) {
	s, _, c, _ := dbMCPFixture(t, dbTokenFields(), dbServers())
	statements := map[string]bool{}
	paths := []string{"/api/2.0/mcp/sql", "/api/2.0/mcp/genie/" + dbSpace, "/api/2.0/mcp/functions/main/finance/rate", "/api/2.0/mcp/ai-search/main/docs/chunks"}
	for i, server := range dbServers() {
		x := &dbMCPTransport{t: t, c: c, path: paths[i], session: dbSession}
		q := dbMCPRead(c, server.Server, server.Tools[0], `{"query":"sample"}`)
		out, err := databricksAcquire(context.Background(), s, q, dbMCPThrough(x))
		if err != nil {
			t.Fatal(err)
		}
		var envelope struct{ Acquisition map[string]any }
		if json.Unmarshal(out, &envelope) != nil {
			t.Fatal("not an envelope")
		}
		a := envelope.Acquisition
		if len(a) != 8 || a["endpoint"] != c.Workspace+paths[i] || a["snapshot"] != digest([]byte(dbMCPResult)) || a["peerIdentity"] != "tls:"+digest([]byte("result peer")) || a["upstreamToken"] != nil {
			t.Fatalf("%s: %v", server.Server, a)
		}
		want := any(nil)
		if i == 0 {
			want = digest([]byte(`{"properties":{"rows":{"type":"array"}},"type":"object"}`))
		}
		if a["schema"] != want {
			t.Fatalf("%s: schema %v", server.Server, a["schema"])
		}
		statement := a["statement"].(string)
		if statements[statement] {
			t.Fatal("two reads, one commitment")
		}
		statements[statement] = true
		var record map[string]any
		json.Unmarshal([]byte(statement), &record)
		if len(record) != 8 || record["server"] != server.Server || record["endpoint"] != a["endpoint"] || record["tool"] != q.Tool || record["connection"] != c.ID || record["revision"] != c.Revision ||
			record["provider"] != "databricks" || record["read"] != "mcp" || record["arguments"].(map[string]any)["query"] != "sample" {
			t.Fatalf("%s: statement %v", server.Server, record)
		}
	}
	x := &dbMCPTransport{t: t, c: c, session: dbSession}
	reports, err := dbMCPThrough(x).databricksMCPTest(context.Background(), s, c.ID, c.Revision)
	if err != nil || len(reports) != 4 || x.calls != 0 || x.lists != 4 {
		t.Fatal(reports, err, x.calls, x.lists)
	}
}
