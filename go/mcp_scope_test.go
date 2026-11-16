package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The MCP server on platforms fixed to a scope identifier (ADR-0038): the
// synthetic subject of these tests that reaches every source.
const subjectEvery = "caller-of-every-scope"

// scopedCallers grants each of two subjects its own scope identifier, and a
// third every source.
var scopedCallers = callerScopes{entries: map[string]callerEntry{
	subjectA:     {grants: map[string]bool{callerScopeA: true}},
	subjectB:     {grants: map[string]bool{callerScopeB: true}},
	subjectEvery: {installation: true},
}}

// scopedMCPFixture is a signer with a live source on each of three platforms
// -- a fixed to scope A, b to scope B, plain to none -- whose identity grants
// each caller its own, and the MCP server of the given form in front of it,
// over HTTP. Platform a's binding has a write operation too, which the
// platform does not enable. Each source echoes the arguments it was given.
func scopedMCPFixture(t *testing.T, form mcpConfig) *mcpFixture {
	t.Helper()
	t.Setenv(envSourceHelper, "1")
	t.Setenv(envSourceEchoStdin, "1")
	root := t.TempDir()
	source := func(scope string) sourceSpec {
		return sourceSpec{argv: []string{os.Args[0]}, env: helperEnv, scope: scope}
	}
	service, err := newGatewayService(filepath.Join(root, "store"), testSeed, "gateway:test", filepath.Join(root, "registry.jsonl"),
		map[string]sourceSpec{"a/live": source(callerScopeA), "b/live": source(callerScopeB), "plain/live": source("")})
	if err != nil {
		t.Fatal(err)
	}
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	id.callers = scopedCallers
	service.identity = &id
	signer := httptest.NewServer(service.handler())
	t.Cleanup(signer.Close)
	u, _ := net.ResolveTCPAddr("tcp", strings.TrimPrefix(signer.URL, "http://"))
	m := form
	m.listen, m.resource, m.sessions, m.idleSeconds, m.concurrency, m.callsPerMinute = "127.0.0.1:0", "https://engine.test/mcp", 8, 60, 4, 100
	cfg := engineConfig{
		authority: "gateway:test",
		listen:    u.String(),
		identity:  &identitySpec{issuer: id.issuer, audience: id.audience, keys: "/keys.json", callers: scopedCallers},
		platforms: []platformConfig{{name: "a", scope: callerScopeA}, {name: "b", scope: callerScopeB}, {name: "plain"}},
		mcp:       &m,
	}
	live := func() *operation { return &operation{shape: "mcp", tools: []string{"lookup"}} }
	bindings := map[string]binding{
		"a":     {platform: "a", live: live(), write: &operation{shape: "mcp", tools: []string{"update"}}},
		"b":     {platform: "b", live: live()},
		"plain": {platform: "plain", live: live()},
	}
	server, err := newDeclaredMCPTestServer(t, cfg, bindings, &id, "")
	if err != nil {
		t.Fatal(err)
	}
	f := &mcpFixture{service: service, signer: signer, server: server, issuer: issuer, root: root}
	f.front = httptest.NewServer(server.httpHandler())
	t.Cleanup(f.front.Close)
	return f
}

// listed is the names tools/list answers on a transport session.
func (f *mcpFixture) listed(t *testing.T, sid string) string {
	t.Helper()
	_, _, body := f.call(t, http.MethodPost, sid, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`, nil)
	var names []string
	for _, tool := range resultOf(t, body)["tools"].([]any) {
		names = append(names, tool.(map[string]any)["name"].(string))
	}
	return strings.Join(names, ",")
}

// rpcErrorOf is a JSON-RPC error's message, or the test fails.
func rpcErrorOf(t *testing.T, body map[string]any) string {
	t.Helper()
	e, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("no JSON-RPC error: %v", body)
	}
	return e["message"].(string)
}

// acquired is a tool call's success, both ways, or the test fails.
func acquired(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	result := resultOf(t, body)
	if result["isError"] != nil {
		t.Fatalf("the call errored: %v", result)
	}
	return sameBothWays(t, result)
}

// The argument naming a scope identifier that each call below sends, as a
// tool's own argument and in the call's metadata.
var (
	argumentNamingB = `{"q":"acme","scope":"` + callerScopeB + `"}`
	metaNamingB     = `{"io.judgment-pack/scope":"` + callerScopeB + `","scope":"` + callerScopeB + `"}`
)

// A server fixed to scope A lists the tools of A's platforms and no other's,
// answers a call to another platform's tool, a write tool's among them, as a
// tool it does not hold, and forwards every call naming A, whatever the
// call's arguments name: the receipt carries A, and the tool is given its own
// argument as sent. A caller whose token does not reach A is listed the seal
// tool alone, and its call of A's tool is answered as one of a tool the
// server does not hold.
func TestAnMCPServerFixedToAScopeIdentifierServesThatScopeAlone(t *testing.T) {
	f := scopedMCPFixture(t, mcpConfig{scope: callerScopeA})
	f.token = tokenFor(t, f.issuer, subjectA, []any{callerScopeA})
	sid := f.open(t)
	if names := f.listed(t, sid); names != "a.lookup,engine.seal" {
		t.Fatalf("tools/list: %s", names)
	}
	started := f.service.started.Load()
	for i, name := range []string{"b.lookup", "plain.lookup", "a.update"} {
		_, _, body := f.call(t, http.MethodPost, sid, toolCall(10+i, name, `{}`, ""), nil)
		if got := rpcErrorOf(t, body); got != "unknown tool: "+name {
			t.Fatalf("%s: %s", name, got)
		}
	}
	if f.service.started.Load() != started {
		t.Fatal("a source started for a tool the server does not hold")
	}
	_, _, body := f.call(t, http.MethodPost, sid, toolCall(20, "a.lookup", argumentNamingB, metaNamingB), nil)
	structured := acquired(t, body)
	if scope := structured["receipt"].(map[string]any)["scope"]; scope != callerScopeA {
		t.Fatalf("the receipt's scope is %v", scope)
	}
	given := structured["result"].(map[string]any)["arguments"].(map[string]any)
	if given["scope"] != callerScopeB || given["q"] != "acme" {
		t.Fatalf("the tool was given %v", given)
	}
	// a caller of B, and one of the sources of no scope identifier, reach
	// nothing of A through it
	for _, token := range []string{tokenFor(t, f.issuer, subjectB, []any{callerScopeB}), tokenFor(t, f.issuer, "caller-of-no-scope", nil)} {
		f.token = token
		sidOther := f.open(t)
		if names := f.listed(t, sidOther); names != "engine.seal" {
			t.Fatalf("another caller lists %s", names)
		}
		started = f.service.started.Load()
		_, _, body = f.call(t, http.MethodPost, sidOther, toolCall(21, "a.lookup", `{}`, ""), nil)
		if got := rpcErrorOf(t, body); got != "unknown tool: a.lookup" || f.service.started.Load() != started {
			t.Fatalf("another caller on A: %s", got)
		}
	}
}

// Over stdio a server fixed to scope A reads what the token given at start
// reaches, once: a token of A is served A's tool and its receipt names A, and
// a token of B is listed the seal tool alone.
func TestAnMCPServerFixedToAScopeIdentifierOverStdio(t *testing.T) {
	f := scopedMCPFixture(t, mcpConfig{scope: callerScopeA})
	initialize := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`
	in := initialize + "\n" + `{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n" + toolCall(3, "a.lookup", argumentNamingB, metaNamingB) + "\n"
	answers := func(token string) map[float64]map[string]any {
		t.Helper()
		var out bytes.Buffer
		if err := f.server.serveStdio(context.Background(), strings.NewReader(in), &out, token); err != nil {
			t.Fatal(err)
		}
		byID := map[float64]map[string]any{}
		for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
			var answer map[string]any
			if err := json.Unmarshal([]byte(line), &answer); err != nil {
				t.Fatalf("%v: %q", err, line)
			}
			byID[answer["id"].(float64)] = answer
		}
		return byID
	}
	names := func(answer map[string]any) string {
		var listed []string
		for _, tool := range resultOf(t, answer)["tools"].([]any) {
			listed = append(listed, tool.(map[string]any)["name"].(string))
		}
		return strings.Join(listed, ",")
	}
	ofA := answers(tokenFor(t, f.issuer, subjectA, []any{callerScopeA}))
	if got := names(ofA[2]); got != "a.lookup,engine.seal" {
		t.Fatalf("A's token lists %s", got)
	}
	if scope := acquired(t, ofA[3])["receipt"].(map[string]any)["scope"]; scope != callerScopeA {
		t.Fatalf("the receipt's scope is %v", scope)
	}
	started := f.service.started.Load()
	ofB := answers(tokenFor(t, f.issuer, subjectB, []any{callerScopeB}))
	if got := names(ofB[2]); got != "engine.seal" {
		t.Fatalf("B's token lists %s", got)
	}
	if got := rpcErrorOf(t, ofB[3]); got != "unknown tool: a.lookup" || f.service.started.Load() != started {
		t.Fatalf("B's token calls A's tool: %s", got)
	}
}

// A server that takes its callers' scope identifiers lists each caller the
// tools of the sources its token reaches, answers a call to any other as a
// tool it does not hold, and forwards each call naming its platform's scope
// identifier, never the call's; a token wider than its subject's entry is
// refused at the server's transport, as at the signer's.
func TestAnMCPServerOfSeveralScopesServesEachCallerItsOwn(t *testing.T) {
	f := scopedMCPFixture(t, mcpConfig{scopeFromCaller: true})
	tokenA := tokenFor(t, f.issuer, subjectA, []any{callerScopeA})
	tokenB := tokenFor(t, f.issuer, subjectB, []any{callerScopeB})
	tokenEvery := tokenFor(t, f.issuer, subjectEvery, nil)
	open := func(token string) string {
		f.token = token
		return f.open(t)
	}
	sidA, sidB, sidEvery := open(tokenA), open(tokenB), open(tokenEvery)
	for _, tc := range []struct{ who, token, sid, want string }{
		{"A's caller", tokenA, sidA, "a.lookup,engine.seal"},
		{"B's caller", tokenB, sidB, "b.lookup,engine.seal"},
		{"a caller of every scope", tokenEvery, sidEvery, "a.lookup,b.lookup,engine.seal,plain.lookup"},
	} {
		f.token = tc.token
		if names := f.listed(t, tc.sid); names != tc.want {
			t.Fatalf("%s lists %s", tc.who, names)
		}
	}
	f.token = tokenA
	started := f.service.started.Load()
	_, _, absent := f.call(t, http.MethodPost, sidA, toolCall(9, "c.lookup", `{}`, ""), nil)
	for i, name := range []string{"b.lookup", "plain.lookup"} {
		_, _, body := f.call(t, http.MethodPost, sidA, toolCall(10+i, name, `{}`, ""), nil)
		if got := rpcErrorOf(t, body); got != "unknown tool: "+name || strings.Replace(got, name, "c.lookup", 1) != rpcErrorOf(t, absent) {
			t.Fatalf("A's caller calls %s: %s", name, got)
		}
	}
	if f.service.started.Load() != started {
		t.Fatal("a source started for a tool the caller does not reach")
	}
	for _, tc := range []struct{ who, token, sid, tool, scope string }{
		{"A's caller", tokenA, sidA, "a.lookup", callerScopeA},
		{"B's caller", tokenB, sidB, "b.lookup", callerScopeB},
		{"a caller of every scope", tokenEvery, sidEvery, "plain.lookup", ""},
	} {
		f.token = tc.token
		_, _, body := f.call(t, http.MethodPost, tc.sid, toolCall(20, tc.tool, argumentNamingB, metaNamingB), nil)
		scope, named := acquired(t, body)["receipt"].(map[string]any)["scope"]
		if (tc.scope == "") == named || (named && scope != tc.scope) {
			t.Fatalf("%s's receipt of %s names scope %v", tc.who, tc.tool, scope)
		}
	}
	// a claim wider than the subject's entry: refused before the body is read
	f.token = tokenFor(t, f.issuer, subjectA, []any{callerScopeA, callerScopeB})
	code, header, body := f.call(t, http.MethodPost, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`, nil)
	if code != http.StatusUnauthorized || body["error"] != errScopeClaimWider.Error() || !strings.Contains(header.Get("WWW-Authenticate"), "resource_metadata=") {
		t.Fatalf("a wider claim: %d %v %v", code, header, body)
	}
}

// The token is verified before the tool's name is looked up: a call of a
// tool the caller does not reach and one of a name the table does not hold
// read the clock -- once for the window, once for the token -- alike, so
// neither answers sooner for the name.
func TestAnMCPServerOfSeveralScopesVerifiesTheTokenWhateverTheName(t *testing.T) {
	f := scopedMCPFixture(t, mcpConfig{scopeFromCaller: true})
	tokenA := tokenFor(t, f.issuer, subjectA, []any{callerScopeA})
	clock := f.server.now
	reads := 0
	f.server.now = func() time.Time { reads++; return clock() }
	counted := map[string]int{}
	for _, name := range []string{"c.lookup", "b.lookup"} {
		reads = 0
		params, _ := json.Marshal(map[string]any{"name": name, "arguments": map[string]any{}})
		out := f.server.admitCall(f.server.newSession(), tokenA, mcpRequest{id: json.RawMessage("1"), method: "tools/call", params: params})
		if out.run != nil || !strings.Contains(string(out.response), "unknown tool: "+name) {
			t.Fatalf("%s: %s", name, out.response)
		}
		counted[name] = reads
	}
	if counted["c.lookup"] != counted["b.lookup"] {
		t.Fatalf("the clock is read %v times", counted)
	}
}

// Over stdio one token is given at start, and no call carries its caller's:
// a server that takes its callers' scope identifiers is not served there,
// and nothing is written.
func TestAnMCPServerOfSeveralScopesIsNotServedOverStdio(t *testing.T) {
	f := scopedMCPFixture(t, mcpConfig{scopeFromCaller: true})
	var out bytes.Buffer
	in := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}` + "\n"
	if err := f.server.serveStdio(context.Background(), strings.NewReader(in), &out, tokenFor(t, f.issuer, subjectEvery, nil)); err != errStdioScopeFromCaller || out.Len() != 0 {
		t.Fatalf("served over stdio: %v %q", err, out.String())
	}
	config := filepath.Join(t.TempDir(), "engine.json")
	text := strings.Replace(engineJSON(t, t.TempDir(), `,"identity":{"issuer":"https://login.example","audience":"gateway:acme","keys":"`+abs(t, t.TempDir(), "keys.json")+`"},"mcp":{"listen":"127.0.0.1:8788","scopeFrom":"caller"}`, ``), `"engineVersion":"1"`, `"engineVersion":"28"`, 1)
	if err := os.WriteFile(config, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	inPlace := mcpReachHost{euid: frontendUID, gid: frontendUID, groups: func() ([]int, error) { return nil, nil }, caps: func() (bool, string) { return true, "" }, open: func(string) error { return fs.ErrPermission }}
	var stderr bytes.Buffer
	if got := runMCP(context.Background(), []string{"--config", config, "--stdio"}, strings.NewReader(in), io.Discard, &stderr, inPlace); got != 1 || !strings.Contains(stderr.String(), "start: "+errStdioScopeFromCaller.Error()) {
		t.Fatalf("gateway mcp --stdio: exit %d: %s", got, stderr.String())
	}
}

// The server is built of the platforms it can name a scope identifier for:
// one fixed to an identifier no platform is fixed to serves nothing, and one
// of neither form serves no platform fixed to one.
func TestAnMCPServerServesNoPlatformItCannotNameAScopeFor(t *testing.T) {
	bindings := map[string]binding{"a": {live: &operation{tools: []string{"lookup"}}}, "plain": {live: &operation{tools: []string{"lookup"}}}}
	cfg := engineConfig{listen: "127.0.0.1:8787", platforms: []platformConfig{{name: "a", scope: callerScopeA}, {name: "plain"}},
		mcp: &mcpConfig{listen: "127.0.0.1:8788", sessions: 1, idleSeconds: 60, concurrency: 1, callsPerMinute: 1, scope: callerScopeB}}
	if _, err := newDeclaredMCPTestServer(t, cfg, bindings, nil, ""); err == nil || err.Error() != "mcp.scope names a scope identifier no platform is fixed to, so the server would serve no platform's tool" {
		t.Fatalf("a server fixed to a scope of no platform: %v", err)
	}
	cfg.mcp.scope = ""
	if _, err := newDeclaredMCPTestServer(t, cfg, bindings, nil, ""); err == nil || !strings.Contains(err.Error(), "platform a is fixed to a scope identifier, and mcp names neither scope nor scopeFrom") {
		t.Fatalf("a server of neither form beside a scoped platform: %v", err)
	}
}

// mcp.scope and mcp.scopeFrom (engineVersion 28): one or neither, scope a
// scope identifier and scopeFrom "caller", the second only where callers
// are held to scope identifiers; a platform's scope beside mcp only with
// one of them. A refusal quotes nothing of the value.
func TestTheMCPScopeConfiguration(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	ref := "postgres@" + digestOf(postgresBinding)
	keys := abs(t, t.TempDir(), "keys.json")
	identity := func(callers string) string {
		return `,"identity":{"issuer":"https://login.example","audience":"gateway:acme","keys":"` + keys + `"` + callers + `}`
	}
	at := func(version, extra, mcp, platformExtra string) string {
		text := engineJSON(t, catalog, extra+`,"mcp":`+mcp, platformJSONFor(t, "warehouse", ref, "engine-warehouse", platformExtra, "history", "live"))
		return strings.Replace(text, `"engineVersion":"1"`, `"engineVersion":"`+version+`"`, 1)
	}
	fixed := `{"listen":"127.0.0.1:8788","scope":` + jsonText(t, callerScopeA) + `}`
	fromCaller := `{"listen":"127.0.0.1:8788","scopeFrom":"caller"}`
	scoped := `,"scope":` + jsonText(t, callerScopeA)
	if cfg, _, err := load(t, at("28", ``, fixed, scoped)); err != nil || cfg.mcp.scope != callerScopeA || cfg.mcp.scopeFromCaller || cfg.platforms[0].scope != callerScopeA {
		t.Fatalf("a server fixed to A beside a platform of A: %v %+v", err, cfg.mcp)
	}
	for _, callers := range []string{``, `,"callerScopes":{"caller-of-a":["` + callerScopeA + `"]}`} {
		if cfg, _, err := load(t, at("28", identity(callers), fromCaller, scoped)); err != nil || !cfg.mcp.scopeFromCaller || cfg.mcp.scope != "" {
			t.Fatalf("a server taking its callers' scope identifiers, callers %q: %v %+v", callers, err, cfg.mcp)
		}
	}
	if cfg, _, err := load(t, at("27", ``, `{"listen":"127.0.0.1:8788"}`, ``)); err != nil || cfg.mcp.scoped() {
		t.Fatalf("version 27 without the members: %v %+v", err, cfg.mcp)
	}
	const outOfForm = "mcp.scope must be a scope identifier, 1 to 128 bytes"
	const fromForm = `mcp.scopeFrom must be the string "caller", the one value it has`
	const needsChecked = `mcp.scopeFrom "caller" serves each caller the scope identifiers its token reaches, which needs identity with callerScopes checked`
	for _, tc := range []struct{ name, text, want, quoted string }{
		{"a scoped platform beside mcp of neither form", at("28", ``, `{"listen":"127.0.0.1:8788"}`, scoped), "platform warehouse: scope is refused beside mcp unless mcp names scope or scopeFrom", "quipe"},
		{"mcp.scope at version 27", at("27", ``, fixed, ``), "mcp.scope is a version-28 member; engineVersion 27 has no mcp.scope", "quipe"},
		{"mcp.scopeFrom at version 27", at("27", identity(``), fromCaller, ``), "mcp.scopeFrom is a version-28 member; engineVersion 27 has no mcp.scopeFrom", ""},
		{"both", at("28", identity(``), `{"listen":"127.0.0.1:8788","scope":"`+callerScopeA+`","scopeFrom":"caller"}`, scoped), "mcp.scope and mcp.scopeFrom are two forms of the server", "quipe"},
		{"scope empty", at("28", ``, `{"listen":"127.0.0.1:8788","scope":""}`, ``), outOfForm, ""},
		{"scope null", at("28", ``, `{"listen":"127.0.0.1:8788","scope":null}`, ``), outOfForm, ""},
		{"scope an array", at("28", ``, `{"listen":"127.0.0.1:8788","scope":["`+callerScopeA+`"]}`, ``), outOfForm, "quipe"},
		{"scope with a tab", at("28", ``, `{"listen":"127.0.0.1:8788","scope":"kappa\ta"}`, ``), outOfForm, "kappa"},
		{"scope the unscoped marker", at("28", ``, `{"listen":"127.0.0.1:8788","scope":"unscoped"}`, ``), `mcp.scope is "unscoped", the marker of the sources of no scope identifier`, ""},
		{"scope too long", at("28", ``, `{"listen":"127.0.0.1:8788","scope":"`+strings.Repeat("x", 129)+`"}`, ``), outOfForm, strings.Repeat("x", 129)},
		{"scopeFrom another word", at("28", identity(``), `{"listen":"127.0.0.1:8788","scopeFrom":"token"}`, ``), fromForm, "token"},
		{"scopeFrom true", at("28", identity(``), `{"listen":"127.0.0.1:8788","scopeFrom":true}`, ``), fromForm, ""},
		{"scopeFrom without identity", at("28", ``, fromCaller, scoped), needsChecked, ""},
		{"scopeFrom with callerScopes unchecked", at("28", identity(`,"callerScopes":"unchecked"`), fromCaller, scoped), needsChecked, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := load(t, tc.text)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
			if tc.quoted != "" && strings.Contains(err.Error(), tc.quoted) {
				t.Fatalf("the refusal quotes the value: %v", err)
			}
		})
	}
}
