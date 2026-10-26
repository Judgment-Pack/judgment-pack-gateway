//go:build linux || darwin

package connections

import (
	"adapters/agreement"
	"adapters/internal/canon"
	"adapters/internal/fakemcp"
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// Unity Gateway services: an MCP service registered in Unity Catalog,
// enabled by its exact name and reached at the workspace's
// /ai-gateway/mcp-services/ endpoint under the same credential and the same
// safeguards as the four workspace endpoints.
const (
	dbGateway       = "unity-gateway:system.ai.dbsql"
	dbGatewayPath   = "/ai-gateway/mcp-services/system.ai.dbsql"
	dbGatewayEscape = "unity-gateway:main.default.tick?ets"
)

func dbGatewayServers() []DatabricksMCPServer {
	return []DatabricksMCPServer{
		{Server: dbGateway, Tools: []string{"execute_sql"}},
		{Server: dbGatewayEscape, Tools: []string{"ask"}},
	}
}
func dbGatewayPrincipal() map[string]string {
	fields := dbPrincipalFields()
	fields["scope"] = "ai-gateway sql"
	return fields
}

// A read on a Unity Gateway service is one session at the service's URL
// under the workspace, built from the configuration, and its record names
// what was asked of whom, as for the other servers.
func TestDatabricksMCPUnityGatewayServiceIsReadAsTheOthers(t *testing.T) {
	s, _, c, _ := dbMCPFixture(t, dbTokenFields(), dbGatewayServers())
	api := newDBFake(t)
	for _, k := range []struct{ server, tool, path string }{
		{dbGateway, "execute_sql", dbGatewayPath},
		{dbGatewayEscape, "ask", "/ai-gateway/mcp-services/main.default.tick%3Fets"},
	} {
		f := dbFakeMCP(t, nil)
		out, err := databricksAcquire(context.Background(), s, dbMCPRead(c, k.server, k.tool, `{"query":"SELECT 1"}`), dbServe(api, map[string]*fakemcp.HTTPServer{"/ai-gateway/mcp-services/": f}))
		if err != nil {
			t.Fatal(k.server, err)
		}
		writeEnvelope(t, "databricks.mcp-"+k.tool, out)
		if got := dbMethods(f); got != "initialize,notifications/initialized,tools/list,tools/call,DELETE" {
			t.Fatalf("%s: %s", k.server, got)
		}
		for _, r := range f.Requests() {
			if r.Path != k.path || r.Header.Get("Authorization") != "Bearer "+dbPAT {
				t.Errorf("%s: %s %s", k.server, r.Verb, r.Path)
			}
		}
		e, err := agreement.Parse(out)
		if err != nil {
			t.Fatal(err)
		}
		a := e.Acquisition
		if *a.Endpoint != dbWorkspace+k.path || *a.Snapshot != digest([]byte(dbMCPResult)) || *a.PeerIdentity != dbLeaf(f) || a.UpstreamToken != nil {
			t.Fatalf("%s: %+v", k.server, a)
		}
		if k.tool == "execute_sql" && a.Schema == nil || k.tool == "ask" && a.Schema != nil {
			t.Fatalf("%s: schema %v", k.server, a.Schema)
		}
		want, _ := canon.Canonicalize([]byte(dbMCPResult), canon.CarryNumbersAsText)
		members, err := agreement.Statement(e)
		if err != nil || !bytes.Equal(e.Result, want) {
			t.Fatal(err, string(e.Result))
		}
		for name, value := range map[string]string{"read": `"mcp"`, "server": `"` + k.server + `"`, "endpoint": `"` + dbWorkspace + k.path + `"`, "tool": `"` + k.tool + `"`, "arguments": `{"query":"SELECT 1"}`} {
			if string(members[name]) != value {
				t.Errorf("%s: statement %s = %s", k.server, name, members[name])
			}
		}
	}
}

// Only a service the connection enables by its exact name is reached, and
// only a tool on its list is called: anything else is refused before any
// request.
func TestDatabricksMCPUnityGatewayReachesOnlyWhatIsEnabled(t *testing.T) {
	s, _, c, _ := dbMCPFixture(t, dbTokenFields(), dbGatewayServers())
	api := newDBFake(t)
	f := dbFakeMCP(t, nil)
	p := dbServe(api, map[string]*fakemcp.HTTPServer{"/ai-gateway/mcp-services/": f})
	for name, k := range map[string]struct {
		q    DatabricksRequest
		want error
	}{
		"a service not enabled":          {dbMCPRead(c, "unity-gateway:system.ai.gmail", "execute_sql", ""), databricksNotEnabled},
		"a service in another catalog":   {dbMCPRead(c, "unity-gateway:main.ai.dbsql", "execute_sql", ""), databricksNotEnabled},
		"a service's name in capitals":   {dbMCPRead(c, "unity-gateway:SYSTEM.AI.DBSQL", "execute_sql", ""), databricksNotEnabled},
		"a pattern":                      {dbMCPRead(c, "unity-gateway:system.ai.*", "execute_sql", ""), databricksNotEnabled},
		"a part of a name":               {dbMCPRead(c, "unity-gateway:system.ai", "execute_sql", ""), databricksNotEnabled},
		"the kind in capitals":           {dbMCPRead(c, "Unity-Gateway:system.ai.dbsql", "execute_sql", ""), databricksNotEnabled},
		"a tool outside the list":        {dbMCPRead(c, dbGateway, "drop_table", ""), databricksNotAllowed},
		"a tool of another service":      {dbMCPRead(c, dbGateway, "ask", ""), databricksNotAllowed},
		"the credential in the argument": {dbMCPRead(c, dbGateway, "execute_sql", `{"query":"`+dbEscaped(dbPAT)+`"}`), databricksInRequest},
	} {
		out, err := databricksAcquire(context.Background(), s, k.q, p)
		if out != nil || err != k.want {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(f.Requests()) != 0 || api.api.Load() != 0 {
		t.Fatalf("a refused read was sent: %s", dbMethods(f))
	}
}

// A service's name is held to its form, case by case, and configure keeps
// nothing it refuses; a service principal enables a service only where its
// configured scope names ai-gateway, refused in words that name the rule.
func TestDatabricksMCPUnityGatewayNamesAndScope(t *testing.T) {
	_, b, _, dir := dbFixture(t, dbTokenFields())
	for name, server := range map[string]string{
		"a service":                       "unity-gateway:main.default.tickets",
		"a Databricks-provided service":   "unity-gateway:system.ai.genie_one_mcp",
		"a name a path segment escapes":   "unity-gateway:main.default.tick?ets",
		"a name in another script":        "unity-gateway:main.default.índice",
		"a name of 255 bytes":             "unity-gateway:main.default." + strings.Repeat("s", 255),
		"a name with hyphens and numbers": "unity-gateway:main-1.default.svc-2",
	} {
		fields := dbTokenFields()
		fields["id"] = "kept"
		if err := dbConfigureMCP(b, fields, []DatabricksMCPServer{{Server: server, Tools: []string{"t"}}}); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		c := dbConnection(t, b.store, "kept")
		b.Handle(context.Background(), "disconnect", []byte(`{"id":"kept","revision":"`+c.Revision+`"}`))
	}
	for name, server := range map[string]string{
		"a wildcard service":            "unity-gateway:system.ai.*",
		"a wildcard schema":             "unity-gateway:system.*.dbsql",
		"a wildcard in a name":          "unity-gateway:system.ai.db*",
		"a catalog and a schema":        "unity-gateway:system.ai",
		"a catalog":                     "unity-gateway:system",
		"no name":                       "unity-gateway:",
		"no key":                        "unity-gateway",
		"an empty schema":               "unity-gateway:system..dbsql",
		"four names":                    "unity-gateway:system.ai.dbsql.x",
		"a space":                       "unity-gateway:system.ai.db sql",
		"a slash":                       "unity-gateway:system.ai/dbsql.x",
		"a control character":           "unity-gateway:system.ai.db\tsql",
		"a name of 256 bytes":           "unity-gateway:main.default." + strings.Repeat("s", 256),
		"the kind in capitals":          "Unity-Gateway:system.ai.dbsql",
		"the URL's own path":            "unity-gateway:/ai-gateway/mcp-services/system.ai.dbsql",
		"a URL":                         "unity-gateway:https://example.cloud.databricks.com/ai-gateway/mcp-services/system.ai.dbsql",
		"the kind spelled another way":  "unity_gateway:system.ai.dbsql",
		"the former vector search kind": "vector-search:system.ai.dbsql",
	} {
		fields := dbTokenFields()
		fields["id"] = "other"
		if err := dbConfigureMCP(b, fields, []DatabricksMCPServer{{Server: server, Tools: []string{"t"}}}); err != ErrRequest || bytes.Contains(dbState(t, dir), []byte(`"other"`)) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, k := range map[string]struct {
		auth, scope string
		servers     []DatabricksMCPServer
		want        error
	}{
		"a service principal with the default scope": {"service-principal", "", dbGatewayServers(), databricksGatewayScope},
		"a service principal with all-apis":          {"service-principal", "all-apis", dbGatewayServers(), databricksGatewayScope},
		"a service principal with sql alone":         {"service-principal", "sql", dbGatewayServers(), databricksGatewayScope},
		"a scope that only contains the word":        {"service-principal", "ai-gateway-extra", dbGatewayServers(), databricksGatewayScope},
		"a service principal with ai-gateway":        {"service-principal", "ai-gateway", dbGatewayServers(), nil},
		"ai-gateway among others":                    {"service-principal", "sql ai-gateway genie", dbGatewayServers(), nil},
		"a workspace endpoint with the default":      {"service-principal", "", dbServers(), nil},
		"a personal access token":                    {"token", "", dbGatewayServers(), nil},
	} {
		fields := dbTokenFields()
		if k.auth == "service-principal" {
			fields = dbPrincipalFields()
			if k.scope != "" {
				fields["scope"] = k.scope
			}
		}
		fields["id"] = "scoped"
		err := dbConfigureMCP(b, fields, k.servers)
		if err != k.want {
			t.Errorf("%s: %v", name, err)
		}
		if err == nil {
			c := dbConnection(t, b.store, "scoped")
			b.Handle(context.Background(), "disconnect", []byte(`{"id":"scoped","revision":"`+c.Revision+`"}`))
		} else if bytes.Contains(dbState(t, dir), []byte(`"scoped"`)) {
			t.Errorf("%s: kept", name)
		}
	}
	if !strings.Contains(databricksGatewayScope.Error(), "ai-gateway") || strings.Contains(databricksGatewayScope.Error(), dbSecret) {
		t.Fatal(databricksGatewayScope)
	}
}

// Every safeguard holds on this kind: an answer that names a credential or
// the session id, as written or in escapes, is refused, and nothing of it is
// kept or reported; a test lists each service's tools and calls none; and
// status names the services.
func TestDatabricksMCPUnityGatewayHoldsEverySafeguard(t *testing.T) {
	byClient := "provider-unavailable: the MCP server " + dbGateway + ": the server's answer repeats the credential"
	// Since round 1 of #256 the whole message is screened before anything of
	// it is read, so a secret the client does not know is refused there, at
	// every stage, in the same words.
	early := "provider-unavailable: the MCP server " + dbGateway + ": the server's answer repeats the credential or its session id, and is not kept"
	session := "provider-unavailable: the MCP server " + dbGateway + ": the server's answer repeats its session id"
	result := func(text string) string { return `{"content":[{"type":"text","text":"` + text + `"}]}` }
	for name, k := range map[string]struct {
		fields                   map[string]string
		init, list, answer, want string
	}{
		"the token escaped":                      {dbTokenFields(), "", "", result(dbEscaped(dbPAT)), byClient},
		"the session id escaped":                 {dbTokenFields(), "", "", result(dbEscaped(dbSession)), session},
		"the minted token escaped":               {dbGatewayPrincipal(), "", "", result(dbEscaped(dbMinted)), byClient},
		"the client secret escaped":              {dbGatewayPrincipal(), "", "", result(dbEscaped(dbSecret)), early},
		"the client secret in the server's name": {dbGatewayPrincipal(), `{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"` + dbSecret + `","version":"1"}}`, "", "", early},
		"the client secret escaped in a listing": {dbGatewayPrincipal(), "", `{"tools":[{"name":"execute_sql","description":"` + dbEscaped(dbSecret) + `"}]}`, "", early},
		"the client secret in a tool's error":    {dbGatewayPrincipal(), "", "", dbErrorText(dbSecret), early},
	} {
		s, _, c, _ := dbMCPFixture(t, k.fields, dbGatewayServers())
		x := &dbMCPTransport{t: t, c: c, path: dbGatewayPath, session: dbSession, init: k.init, list: k.list, result: k.answer}
		out, err := databricksAcquire(context.Background(), s, dbMCPRead(c, dbGateway, "execute_sql", ""), dbMCPThrough(x))
		if out != nil || err == nil || err.Error() != k.want {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil {
			dbAbsent(t, name, err.Error())
		}
		if k.answer == "" && x.calls != 0 {
			t.Errorf("%s: a tool was called", name)
		}
	}
	// A test lists each service's tools and calls none; status names them.
	_, b, c, _ := dbMCPFixture(t, dbGatewayPrincipal(), dbGatewayServers())
	f := dbFakeMCP(t, nil)
	api := newDBFake(t)
	b.provider = dbServe(api, map[string]*fakemcp.HTTPServer{"/ai-gateway/mcp-services/": f})
	answer, err := b.Handle(context.Background(), "test", []byte(`{"id":"lake","revision":"`+c.Revision+`"}`))
	raw, _ := json.Marshal(answer)
	want := `{"mcp":[{"server":"` + dbGateway + `","ok":true,"offered":["execute_sql","ask","main__finance__rate","main__docs__chunks","other"],"notOffered":[]},` +
		`{"server":"` + dbGatewayEscape + `","ok":true,"offered":["execute_sql","ask","main__finance__rate","main__docs__chunks","other"],"notOffered":[]}],"ok":true}`
	if err != nil || string(raw) != want || strings.Contains(dbMethods(f), "tools/call") {
		t.Fatalf("test %s %v %s", raw, err, dbMethods(f))
	}
	dbAbsent(t, "test", string(raw))
	status, err := b.Handle(context.Background(), "status", []byte(`{}`))
	raw, _ = json.Marshal(status)
	if err != nil || !bytes.Contains(raw, []byte(`"mcp":[{"server":"`+dbGateway+`","tools":["execute_sql"]},{"server":"`+dbGatewayEscape+`","tools":["ask"]}]`)) || !bytes.Contains(raw, []byte(`"scope":"ai-gateway sql"`)) {
		t.Fatalf("status %s %v", raw, err)
	}
	dbAbsent(t, "status", string(raw))
}
