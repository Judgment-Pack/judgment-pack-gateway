package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// The MCP server in front of an operator's own read-only tool servers, each
// on a platform fixed to a scope identifier, with each caller's scope
// identifiers taken from its signed token (mcp.scopeFrom "caller"), end to
// end: connect registers each server as an operator's own binding
// ("customer": true, ADR-0021) and pins its snapshot; the configuration
// fixes each platform to a scope identifier (ADR-0026) and grants each
// subject its own (ADR-0037); the front (ADR-0038) forwards through the
// signer and the real adapter-mcp to the server; and the repo's verifier
// reads the receipts. Every tool server
// is a stand-in in the test's own process, over Streamable HTTP; the tool
// names and their answers are invented.

// recordsReadTools are the stand-in's read tools, each declared operation
// read and effect read-external: every tool of an MCP operation reaches a
// server outside the engine, and effect read, the engine's own state, is
// refused there (taxonomy.go, parseTaxonomyOperation).
var recordsReadTools = []string{"list_records", "get_record", "get_item_state", "get_item_timeline", "list_related_records"}

const (
	// recordsWriteTool is the tool of a binding's write operation, declared
	// operation act and effect act, as every write tool is.
	recordsWriteTool = "close_record"
	// recordsActTool is a live tool its owner declares operation act and
	// effect act.
	recordsActTool = "assign_record"
	// recordsCallers grants each of two subjects one scope identifier.
	recordsCallers = `{"` + subjectA + `":["` + callerScopeA + `"],"` + subjectB + `":["` + callerScopeB + `"]}`
)

// recordsStandIn is an operator's MCP tool server over Streamable HTTP in
// the test's own process: it issues a session and holds every later request
// to it, lists every tool it has, and answers a call with an invented answer
// that names the server, the tool and the arguments it was given. It
// records each call: the tool, the arguments and the bearer.
type recordsStandIn struct {
	*httptest.Server
	label string
	mu    sync.Mutex
	calls []recordsCall
}

type recordsCall struct {
	tool, bearer string
	arguments    json.RawMessage
}

const recordsToolList = `[` +
	`{"name":"list_records","description":"List the records that match a filter","inputSchema":{"type":"object","properties":{"filter":{"type":"string"}}}},` +
	`{"name":"get_record","description":"Get one record by its id","inputSchema":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}},` +
	`{"name":"get_item_state","description":"Get the current state of one item","inputSchema":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}},` +
	`{"name":"get_item_timeline","description":"Get the timeline of one item","inputSchema":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}},` +
	`{"name":"list_related_records","description":"List the records related to one","inputSchema":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}},` +
	`{"name":"close_record","description":"Close one record","inputSchema":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}},` +
	`{"name":"assign_record","description":"Assign one record","inputSchema":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}}` +
	`]`

func newRecordsStandIn(t *testing.T, label string) *recordsStandIn {
	t.Helper()
	s := &recordsStandIn{label: label}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		json.Unmarshal(body, &m)
		if m.Method != "initialize" && r.Header.Get("Mcp-Session-Id") != "records-session" {
			http.Error(w, "unknown session", http.StatusNotFound)
			return
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if len(m.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		var result string
		switch m.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "records-session")
			result = `{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"records-standin","version":"1.0"}}`
		case "tools/list":
			result = `{"tools":` + recordsToolList + `}`
		case "tools/call":
			var call struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			}
			json.Unmarshal(m.Params, &call)
			s.mu.Lock()
			s.calls = append(s.calls, recordsCall{tool: call.Name, bearer: r.Header.Get("Authorization"), arguments: call.Arguments})
			s.mu.Unlock()
			answer := s.answer(call.Name, call.Arguments)
			text, _ := json.Marshal(string(answer))
			result = `{"content":[{"type":"text","text":` + string(text) + `}],"structuredContent":` + string(answer) + `}`
		default:
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(m.ID)+`,"error":{"code":-32601,"message":"method not found"}}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(m.ID)+`,"result":`+result+`}`)
	}))
	t.Cleanup(s.Close)
	return s
}

// answer is the invented answer to a call of the tool.
func (s *recordsStandIn) answer(tool string, arguments json.RawMessage) []byte {
	var answer any
	switch tool {
	case "list_records":
		answer = []any{map[string]any{"id": "R-101", "title": "First record", "status": "open"}, map[string]any{"id": "R-102", "title": "Second record", "status": "closed"}}
	case "get_record":
		answer = map[string]any{"id": "R-101", "title": "First record", "status": "open", "version": 3}
	case "get_item_state":
		answer = map[string]any{"id": "item-7", "state": "active", "revision": 2}
	case "get_item_timeline":
		answer = []any{map[string]any{"at": "2026-11-01T09:00:00Z", "event": "created"}, map[string]any{"at": "2026-11-12T14:30:00Z", "event": "updated"}}
	case "list_related_records":
		answer = []any{"R-102", "R-117"}
	default:
		answer = map[string]any{"done": true}
	}
	encoded, _ := json.Marshal(map[string]any{"server": s.label, "tool": tool, "arguments": arguments, "answer": answer})
	return encoded
}

func (s *recordsStandIn) called() []recordsCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recordsCall(nil), s.calls...)
}

// recordsServerBinding is an operator's own binding ("customer": true) of the
// server at url: a live operation of the given read tools and act tools,
// and a write operation of the given tools where there are any.
func recordsServerBinding(t *testing.T, name, url string, read, act, write []string) string {
	t.Helper()
	operation := func(tools ...[]string) map[string]any {
		var names []string
		taxonomies := map[string]any{}
		for i, group := range tools {
			for _, tool := range group {
				names = append(names, tool)
				taxonomies[tool] = map[string]string{"operation": "read", "effect": "read-external"}
				if i > 0 {
					taxonomies[tool] = map[string]string{"operation": "act", "effect": "act"}
				}
			}
		}
		return map[string]any{"shape": "mcp", "server": map[string]any{"url": url, "bearer": "token"}, "tools": names, "toolTaxonomies": taxonomies, "licence": "fixture"}
	}
	operations := map[string]any{"live": operation(read, act)}
	if len(write) > 0 {
		operations["write"] = operation(nil, write)
	}
	encoded, err := json.Marshal(map[string]any{"bindingVersion": "2", "customer": true, "platform": name, "operations": operations})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// recordsPlatform is a platform of the gateway: its name, which is also its
// binding's, its scope identifier, its user and that user's id, and its
// binding's text.
type recordsPlatform struct {
	name, scope, user string
	uid               int
	binding           string
}

// recordsGateway is the signer and the MCP front of a configuration that
// connect wrote, raised to version 28 with each platform fixed to its scope
// identifier, an identity granting recordsCallers, and the front taking
// its callers' scope identifiers.
type recordsGateway struct {
	*mcpFixture
	connect  *connectFixture
	cfg      engineConfig
	bindings map[string]binding
	bin      string
	real     map[string]string // the credentials file of each platform
	asked    int               // the adapter checks run
}

// adapt runs the source as the built adapter, as the test's own user, with
// the platform's credentials file. The user and the sandbox are stripped,
// as in the end-to-end tests of the http shape: the switching and the
// sandbox are proved where they are implemented, and neither reads a scope.
func (g *recordsGateway) adapt(platform string, spec sourceSpec) sourceSpec {
	spec.user, spec.sandbox = "", nil
	spec.argv = append([]string(nil), spec.argv...)
	exe := "adapter-mcp"
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	spec.argv[0] = filepath.Join(g.bin, exe)
	for i, arg := range spec.argv {
		if strings.HasPrefix(arg, "--credentials=") {
			spec.argv[i] = "--credentials=" + g.real[platform]
		}
	}
	return spec
}

// check is the platform's adapter check, run by the built adapter.
func (g *recordsGateway) check(platform string) func(context.Context, sourceSpec) ([]byte, error) {
	return func(ctx context.Context, spec sourceSpec) ([]byte, error) {
		g.asked++
		return runCheck(ctx, g.adapt(platform, spec))
	}
}

// request is connect's request for the platform.
func (g *recordsGateway) request(p recordsPlatform) connectRequest {
	req := g.connect.request()
	req.platform, req.binding, req.user = p.name, p.name, p.user
	req.credentials = map[string]string{"live": filepath.Join(filepath.Dir(g.connect.credentials), p.name)}
	return req
}

func newRecordsGateway(t *testing.T, platforms []recordsPlatform) *recordsGateway {
	t.Helper()
	bin, _ := buildMCPStandIns(t, t.TempDir())
	f := newConnectFixture(t, restrictedBinding, "")
	g := &recordsGateway{connect: f, bin: bin, real: map[string]string{}}
	for _, p := range platforms {
		if err := os.WriteFile(filepath.Join(f.catalog, p.name+".json"), []byte(p.binding), 0o600); err != nil {
			t.Fatal(err)
		}
		req := g.request(p)
		f.fs[req.credentials["live"]] = fileOwnership{uid: p.uid, mode: 0o600}
		g.real[p.name] = filepath.Join(t.TempDir(), p.name+".json")
		if err := os.WriteFile(g.real[p.name], []byte(`{"token":"credential-of-`+p.name+`"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := connect(context.Background(), req, f.host, g.check(p.name)); err != nil {
			t.Fatalf("connect %s: %v", p.name, err)
		}
	}
	// what connect has no flag for, written in the file: the version, each
	// platform's scope identifier, the identity and the front
	raw, err := os.ReadFile(f.config)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	top := parsed.(*vObject)
	top.set("engineVersion", vString("28"))
	top.set("listen", vString("127.0.0.1:8787"))
	entries, _ := top.get("platforms")
	for _, p := range platforms {
		entry, _ := entries.(*vObject).get(p.name)
		entry.(*vObject).set("scope", vString(p.scope))
	}
	g.mcpFixture = &mcpFixture{issuer: newIssuer(t), root: f.dir}
	keys := filepath.Join(t.TempDir(), "issuer-keys.json")
	if err := os.WriteFile(keys, g.issuer.keySet(), 0o600); err != nil {
		t.Fatal(err)
	}
	callers, err := parseJSON([]byte(recordsCallers))
	if err != nil {
		t.Fatal(err)
	}
	identity := newObject()
	identity.set("issuer", vString("https://login.example"))
	identity.set("audience", vString("gateway:acme"))
	identity.set("keys", vString(keys))
	identity.set("callerScopes", callers)
	top.set("identity", identity)
	front, err := parseJSON([]byte(`{"listen":"127.0.0.1:8788","resource":"https://engine.test/mcp","scopeFrom":"caller"}`))
	if err != nil {
		t.Fatal(err)
	}
	top.set("mcp", front)
	if err := os.WriteFile(f.config, canon(top), 0o640); err != nil {
		t.Fatal(err)
	}

	// the configuration loaded, and the processes built of it as serve and
	// gateway mcp --http build them
	g.cfg, g.bindings, err = loadEngineConfig(f.config, stubAccounts(stubUsers))
	if err != nil {
		t.Fatal(err)
	}
	if g.cfg.mcp == nil || !g.cfg.mcp.scopeFromCaller || g.cfg.mcp.resource == "" || g.cfg.identity == nil || validIssuerURL(g.cfg.identity.issuer) != nil {
		t.Fatalf("the front's configuration: %+v", g.cfg.mcp)
	}
	id, err := loadIdentity(g.cfg.identity)
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string]sourceSpec{}
	for name, spec := range deriveSources(g.cfg, g.bindings) {
		sources[name] = g.adapt(strings.SplitN(name, "/", 2)[0], spec)
	}
	seed, err := loadSeed(g.cfg.seed)
	if err != nil {
		t.Fatal(err)
	}
	g.service, err = newGatewayService(g.cfg.store, seed, g.cfg.authority, g.cfg.registry, sources)
	if err != nil {
		t.Fatal(err)
	}
	g.service.identity = id
	g.signer = httptest.NewServer(g.service.handler())
	t.Cleanup(g.signer.Close)
	// the signer's address is the test server's, which the front finds it by
	u, _ := net.ResolveTCPAddr("tcp", strings.TrimPrefix(g.signer.URL, "http://"))
	g.cfg.listen = u.String()
	if g.server, err = newMCPServer(g.cfg, g.bindings, id, f.config); err != nil {
		t.Fatal(err)
	}
	g.front = httptest.NewServer(g.server.httpHandler())
	t.Cleanup(g.front.Close)
	return g
}

// listing is what tools/list answers on the transport session, by name.
func (g *recordsGateway) listing(t *testing.T, sid string) map[string]map[string]any {
	t.Helper()
	_, _, body := g.call(t, http.MethodPost, sid, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`, nil)
	byName := map[string]map[string]any{}
	for _, tool := range resultOf(t, body)["tools"].([]any) {
		entry := tool.(map[string]any)
		byName[entry["name"].(string)] = entry
	}
	return byName
}

// sameAsAbsent holds a call of name to the answer of the same call of a
// name the table does not hold, byte for byte but for the name.
func (g *recordsGateway) sameAsAbsent(t *testing.T, sid, name string) {
	t.Helper()
	absent := "records-c." + name[strings.Index(name, ".")+1:]
	_, _, got := g.call(t, http.MethodPost, sid, toolCall(40, name, `{"id":"R-101"}`, ""), nil)
	_, _, want := g.call(t, http.MethodPost, sid, toolCall(40, absent, `{"id":"R-101"}`, ""), nil)
	if message := rpcErrorOf(t, got); message != "unknown tool: "+name {
		t.Fatalf("%s: %s", name, message)
	}
	gotText, _ := json.Marshal(got)
	wantText, _ := json.Marshal(want)
	if strings.ReplaceAll(string(gotText), name, absent) != string(wantText) {
		t.Fatalf("%s is answered otherwise than a tool the server does not hold:\n%s\n%s", name, gotText, wantText)
	}
}

// verdicts are the verifier's statuses of the session's receipts and seal.
func (g *recordsGateway) verdicts(t *testing.T, session string) (bool, []string) {
	t.Helper()
	rep, err := verifyWithRegistry(g.service.storeRoot, g.service.regPath, g.service.authority, g.service.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	var statuses []string
	for _, f := range rep.Findings {
		if f["sessionId"] == session {
			statuses = append(statuses, f["status"].(string))
		}
	}
	return rep.OK, statuses
}

// An operator's read-only tool servers, one on each of two platforms fixed
// to scope identifiers A and B, on one gateway: a caller of A is listed and
// served A's tools alone and a caller of B B's, each call forwarded to its
// own platform's server and receipted with the caller and its platform's
// scope identifier, which the verifier holds to the signature; a caller of
// B gets nothing of A, a token claiming a scope its subject is not granted
// is refused 401, the write operation's tool is served to no one, and a
// platform with a scope takes no write.
func TestMCPFrontServesOperatorReadToolsByCallerScope(t *testing.T) {
	serverA, serverB := newRecordsStandIn(t, "server-a"), newRecordsStandIn(t, "server-b")
	bindingA := recordsServerBinding(t, "records-a", serverA.URL, recordsReadTools, nil, []string{recordsWriteTool})
	g := newRecordsGateway(t, []recordsPlatform{
		{name: "records-a", scope: callerScopeA, user: "engine-warehouse", uid: 1001, binding: bindingA},
		{name: "records-b", scope: callerScopeB, user: "engine-docs", uid: 1002, binding: recordsServerBinding(t, "records-b", serverB.URL, recordsReadTools, nil, nil)},
	})

	// registered: each an operator's own binding ("customer": true) whose
	// live tools are declared read, pinned by a snapshot of version 3
	// holding exactly them; the write operation is declared and not
	// enabled, which a scope refuses
	for _, p := range g.cfg.platforms {
		b := g.bindings[p.name]
		pin := p.operationDescriptors["live"]
		if !b.customer || p.scope == "" || pin == "" || len(p.operationDescriptors) != 1 || p.write {
			t.Fatalf("platform %s: %+v", p.name, p)
		}
		raw, err := os.ReadFile(filepath.Join(g.connect.config+".descriptors", strings.TrimPrefix(pin, "sha256:")+".json"))
		if err != nil {
			t.Fatal(err)
		}
		snap, err := parseSnapshot(raw)
		if err != nil || snap.version != "3" || snap.operation != "live" || len(snap.tools) != len(recordsReadTools) {
			t.Fatalf("platform %s: the snapshot: %v %+v", p.name, err, snap)
		}
		for _, tool := range recordsReadTools {
			if got := b.live.taxonomies[tool]; got != (ToolTaxonomy{Operation: "read", Effect: "read-external"}) {
				t.Fatalf("platform %s: %s is declared %+v", p.name, tool, got)
			}
		}
	}
	if w := g.bindings["records-a"].write; w == nil || len(w.tools) != 1 || w.taxonomies[recordsWriteTool] != (ToolTaxonomy{Operation: "act", Effect: "act"}) {
		t.Fatalf("binding records-a's write operation: %+v", w)
	}
	// effect read is the engine's own state, which no tool of a server
	// outside the engine declares: the binding is refused
	if _, err := parseBinding([]byte(strings.ReplaceAll(bindingA, `"effect":"read-external"`, `"effect":"read"`))); err == nil || !strings.Contains(err.Error(), "missing or invalid owner taxonomy for allowed tool") {
		t.Fatalf("a tool of effect read: %v", err)
	}

	tokenA := tokenFor(t, g.issuer, subjectA, []any{callerScopeA})
	tokenB := tokenFor(t, g.issuer, subjectB, []any{callerScopeB})
	arguments := map[string]string{
		"list_records":         `{"filter":"status:open","scope":"` + callerScopeB + `"}`,
		"get_record":           `{"id":"R-101"}`,
		"get_item_state":       `{"id":"item-7"}`,
		"get_item_timeline":    `{"id":"item-7"}`,
		"list_related_records": `{"id":"R-101"}`,
	}
	// each caller, side by side on the one gateway
	type scopeCase struct {
		who, platform, scope, subject, token, session, label string
		server, other                                        *recordsStandIn
	}
	cases := []scopeCase{
		{"A's caller", "records-a", callerScopeA, subjectA, tokenA, "records-a-session", "server-a", serverA, serverB},
		{"B's caller", "records-b", callerScopeB, subjectB, tokenB, "records-b-session", "server-b", serverB, serverA},
	}
	sids := map[string]string{}
	for _, tc := range cases {
		g.token = tc.token
		sid := g.open(t)
		sids[tc.platform] = sid
		listed := g.listing(t, sid)
		var names []string
		for _, name := range g.server.order {
			if listed[name] != nil {
				names = append(names, name)
			}
		}
		want := "engine.seal"
		for _, tool := range []string{"get_item_state", "get_item_timeline", "get_record", "list_records", "list_related_records"} {
			want += "," + tc.platform + "." + tool
		}
		if got := strings.Join(names, ","); got != want || len(listed) != len(names) {
			t.Fatalf("%s lists %s", tc.who, got)
		}
		for _, tool := range recordsReadTools {
			entry := listed[tc.platform+"."+tool]
			meta := entry["_meta"].(map[string]any)
			hints := entry["annotations"].(map[string]any)
			if meta["operation"] != "read" || meta["effect"] != "read-external" || hints["readOnlyHint"] != true || hints["destructiveHint"] != false {
				t.Fatalf("%s: %s is listed %v", tc.who, tool, entry)
			}
		}
		calledBefore, otherBefore := len(tc.server.called()), len(tc.other.called())
		meta := `{"` + mcpSessionMeta + `":"` + tc.session + `","scope":"` + callerScopeB + `"}`
		for i, tool := range recordsReadTools {
			_, _, body := g.call(t, http.MethodPost, sid, toolCall(10+i, tc.platform+"."+tool, arguments[tool], meta), nil)
			structured := acquired(t, body)
			receipt := structured["receipt"].(map[string]any)
			caller, _ := receipt["caller"].(map[string]any)
			if receipt["scope"] != tc.scope || receipt["source"] != tc.platform+"/live" || caller["subject"] != tc.subject || caller["issuer"] != "https://login.example" || caller["tokenDigest"] != "sha256:"+hexOf([]byte(tc.token)) {
				t.Fatalf("%s: the receipt of %s: %v", tc.who, tool, receipt)
			}
			answer := structured["result"].(map[string]any)["structuredContent"].(map[string]any)
			given, _ := json.Marshal(answer["arguments"])
			if answer["server"] != tc.label || answer["tool"] != tool || canonicalOf(t, given) != canonicalOf(t, []byte(arguments[tool])) {
				t.Fatalf("%s: %s was answered %v", tc.who, tool, answer)
			}
		}
		calls := tc.server.called()[calledBefore:]
		if len(calls) != len(recordsReadTools) || len(tc.other.called()) != otherBefore {
			t.Fatalf("%s: %d calls reached its server, %d the other's", tc.who, len(calls), len(tc.other.called())-otherBefore)
		}
		for i, call := range calls {
			if call.tool != recordsReadTools[i] || call.bearer != "Bearer credential-of-"+tc.platform {
				t.Fatalf("%s: call %d reached its server as %s under %q", tc.who, i, call.tool, call.bearer)
			}
		}
		if n := g.receiptsOf(tc.session); n != len(recordsReadTools) {
			t.Fatalf("%s: %d receipts", tc.who, n)
		}
	}

	// a caller of B gets nothing of A: no tool of A's is listed to it
	// (above), a call of each is answered as a tool the server does not
	// hold, and a seal of A's session as a session the gateway does not
	// hold; nothing reaches A's server or A's session
	g.token = tokenB
	before := len(serverA.called())
	for _, tool := range append(append([]string(nil), recordsReadTools...), recordsWriteTool) {
		g.sameAsAbsent(t, sids["records-b"], "records-a."+tool)
	}
	sealOf := func(session string) map[string]any {
		_, _, body := g.call(t, http.MethodPost, sids["records-b"], toolCall(50, mcpSealTool, `{"session":"`+session+`"}`, ""), nil)
		return body
	}
	ofA, ofNone := sealOf("records-a-session"), sealOf("records-z-session")
	textA, _ := json.Marshal(ofA)
	textNone, _ := json.Marshal(ofNone)
	if resultOf(t, ofA)["isError"] != true || strings.ReplaceAll(string(textA), "records-a-session", "records-z-session") != string(textNone) {
		t.Fatalf("B's caller seals A's session:\n%s\n%s", textA, textNone)
	}
	if len(serverA.called()) != before || g.receiptsOf("records-a-session") != len(recordsReadTools) {
		t.Fatal("a call of B's caller reached A's server or A's session")
	}

	// the write operation's tool is served to no one: A's own caller is
	// answered as for a tool the server does not hold
	g.token = tokenA
	g.sameAsAbsent(t, sids["records-a"], "records-a."+recordsWriteTool)
	for _, call := range serverA.called() {
		if call.tool == recordsWriteTool {
			t.Fatal("the write operation's tool reached the server")
		}
	}
	if _, derived := deriveSources(g.cfg, g.bindings)["records-a/write"]; derived {
		t.Fatal("a write source was derived for a platform with a scope")
	}

	// a token claiming a scope identifier its subject's entry does not
	// grant, or naming none where the entry is a list without the marker,
	// is refused 401 at the front's transport, before any session, with the
	// signer's sentence, as the signer refuses it
	for _, tc := range []struct {
		who   string
		claim any
	}{
		{"A's subject claiming B", []any{callerScopeB}},
		{"A's subject claiming A and B", []any{callerScopeA, callerScopeB}},
		{"A's subject claiming none", nil},
	} {
		g.token = tokenFor(t, g.issuer, subjectA, tc.claim)
		for _, sid := range []string{"", sids["records-a"]} {
			message := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`
			if sid != "" {
				message = toolCall(60, "records-a.get_record", `{"id":"R-101"}`, "")
			}
			code, header, body := g.call(t, http.MethodPost, sid, message, nil)
			if code != http.StatusUnauthorized || body["error"] != errScopeClaimWider.Error() || !strings.Contains(header.Get("WWW-Authenticate"), "resource_metadata=") {
				t.Fatalf("%s at the front (session %q): %d %v %v", tc.who, sid, code, header, body)
			}
		}
		req, _ := http.NewRequest(http.MethodPost, g.signer.URL+"/acquire", strings.NewReader(acquireBodyFor("direct", "records-a/live", callerScopeA)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+g.token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var refused map[string]any
		json.NewDecoder(resp.Body).Decode(&refused)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized || refused["error"] != errScopeClaimWider.Error() {
			t.Fatalf("%s at the signer: %d %v", tc.who, resp.StatusCode, refused)
		}
	}
	if len(serverA.called()) != before || g.receiptsOf("records-a-session") != len(recordsReadTools) {
		t.Fatal("a refused token reached A's server or A's session")
	}

	// each caller seals its own session, and the verifier finds every
	// receipt and both seals good; a receipt whose scope or caller is
	// changed after signing no longer verifies
	for _, tc := range cases {
		g.token = tc.token
		_, _, body := g.call(t, http.MethodPost, sids[tc.platform], toolCall(70, mcpSealTool, `{"session":"`+tc.session+`"}`, ""), nil)
		if result := resultOf(t, body); result["isError"] != nil {
			t.Fatalf("%s seals its session: %v", tc.who, result)
		}
	}
	for _, tc := range cases {
		ok, statuses := g.verdicts(t, tc.session)
		if !ok || len(statuses) != len(recordsReadTools) {
			t.Fatalf("%s's session: ok %v, %v", tc.who, ok, statuses)
		}
		for _, status := range statuses {
			if status != "ok" {
				t.Fatalf("%s's session: %v", tc.who, statuses)
			}
		}
	}
	path := filepath.Join(g.service.storeRoot, "receipts", "records-a-session", "0.json")
	minted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct{ name, from, to string }{
		{"the scope", `"scope":` + jsonText(t, callerScopeA), `"scope":` + jsonText(t, callerScopeB)},
		{"the caller", `"subject":"` + subjectA + `"`, `"subject":"` + subjectB + `"`},
	} {
		if !strings.Contains(string(minted), change.from) {
			t.Fatalf("%s: the receipt holds no %s: %s", change.name, change.from, minted)
		}
		if err := os.WriteFile(path, []byte(strings.Replace(string(minted), change.from, change.to, 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		if ok, statuses := g.verdicts(t, "records-a-session"); ok || len(statuses) == 0 || statuses[0] != "signature-mismatch" {
			t.Fatalf("%s changed: ok %v, %v", change.name, ok, statuses)
		}
	}
	if err := os.WriteFile(path, minted, 0o600); err != nil {
		t.Fatal(err)
	}

	// a platform with a scope takes no write: connect --replace --write is
	// refused before anything is asked, and the file with write: true is
	// refused by name
	written := g.connect.fileText(t)
	asked := g.asked
	replace := g.request(recordsPlatform{name: "records-a", user: "engine-warehouse"})
	replace.replace, replace.write = true, true
	replace.credentials["write"] = replace.credentials["live"]
	if _, err := connect(context.Background(), replace, g.connect.host, g.check("records-a")); err == nil || !strings.Contains(err.Error(), "platform records-a carries a scope, which --replace keeps, and a platform with a scope allows no write") {
		t.Fatalf("connect --replace --write: %v", err)
	}
	if g.asked != asked || g.connect.fileText(t) != written {
		t.Fatal("connect --replace --write asked the adapter or wrote the file")
	}
	withWrite := strings.Replace(written, `"scope":`+jsonText(t, callerScopeA), `"scope":`+jsonText(t, callerScopeA)+`,"write":true`, 1)
	if withWrite == written {
		t.Fatalf("the file holds no scope A: %s", written)
	}
	if err := os.WriteFile(g.connect.config, []byte(withWrite), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadEngineConfig(g.connect.config, stubAccounts(stubUsers)); err == nil || !strings.Contains(err.Error(), "platform records-a: scope fixes the platform's reads to a scope identifier, /act takes none, and the platform sets write: true; a platform with a scope allows no write") {
		t.Fatalf("a platform with a scope and write: true: %v", err)
	}
}

// Current behaviour, by design (ADR-0021; docs/design/mcp-server.md,
// "Writes"): the front serves a binding's live tools whatever effect their
// owner declares. A live tool declared operation act and effect act is
// listed with readOnlyHint false and destructiveHint true, and a call of it
// is forwarded to /acquire and receipted with its platform's scope
// identifier, as any live tool is; what holds a live tool to reading is the
// credential the operator gives it. Whether the front of scoped platforms
// should serve such a tool is pending the maintainer's decision: a change
// that refuses it fails this test, which is then rewritten to the refusal.
func TestMCPFrontServesLiveActToolToday(t *testing.T) {
	server := newRecordsStandIn(t, "server-a")
	g := newRecordsGateway(t, []recordsPlatform{
		{name: "records-a", scope: callerScopeA, user: "engine-warehouse", uid: 1001, binding: recordsServerBinding(t, "records-a", server.URL, []string{"list_records"}, []string{recordsActTool}, nil)},
	})
	g.token = tokenFor(t, g.issuer, subjectA, []any{callerScopeA})
	sid := g.open(t)
	listed := g.listing(t, sid)
	entry := listed["records-a."+recordsActTool]
	if len(listed) != 3 || entry == nil {
		t.Fatalf("A's caller is listed %v", listed)
	}
	meta := entry["_meta"].(map[string]any)
	hints := entry["annotations"].(map[string]any)
	if meta["operation"] != "act" || meta["effect"] != "act" || hints["readOnlyHint"] != false || hints["destructiveHint"] != true {
		t.Fatalf("the act tool is listed %v", entry)
	}
	_, _, body := g.call(t, http.MethodPost, sid, toolCall(10, "records-a."+recordsActTool, `{"id":"R-101"}`, `{"`+mcpSessionMeta+`":"act-session"}`), nil)
	structured := acquired(t, body)
	if receipt := structured["receipt"].(map[string]any); receipt["scope"] != callerScopeA || receipt["source"] != "records-a/live" {
		t.Fatalf("the act tool's receipt: %v", receipt)
	}
	if calls := server.called(); len(calls) != 1 || calls[0].tool != recordsActTool {
		t.Fatalf("the server was called %+v", calls)
	}
}
