package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// mcpFixture is a signer with one platform's live source and the MCP
// server in front of it, over HTTP, with an identity when asked.
type mcpFixture struct {
	service *gatewayService
	signer  *httptest.Server
	server  *mcpServer
	front   *httptest.Server
	issuer  *testIssuer
	token   string
	root    string
}

func mcpTestConfig(t *testing.T, signer *httptest.Server, identity *identitySpec) engineConfig {
	t.Helper()
	u, _ := net.ResolveTCPAddr("tcp", strings.TrimPrefix(signer.URL, "http://"))
	return engineConfig{
		authority: "gateway:test",
		listen:    u.String(),
		identity:  identity,
		platforms: []platformConfig{{name: "screen", binding: "screen@sha256:" + strings.Repeat("ab", 32)}},
		mcp:       &mcpConfig{listen: "127.0.0.1:0", resource: "https://engine.test/mcp", sessions: 4, idleSeconds: 60, concurrency: 2, callsPerMinute: 100},
	}
}

func mcpBindings() map[string]binding {
	return map[string]binding{"screen": {platform: "screen", live: &operation{shape: "mcp", tools: []string{"lookup", "search"}}}}
}

// newMCPFixture builds the pair; with identity, the signer and the front
// share one issuer and the fixture holds a good token.
func newMCPFixture(t *testing.T, withIdentity bool) *mcpFixture {
	t.Helper()
	t.Setenv(envSourceHelper, "1")
	root := t.TempDir()
	service, err := newGatewayService(filepath.Join(root, "store"), testSeed, "gateway:test", filepath.Join(root, "registry.jsonl"),
		map[string]sourceSpec{"screen/live": {argv: []string{os.Args[0]}, env: helperEnv}})
	if err != nil {
		t.Fatal(err)
	}
	signer := httptest.NewServer(service.handler())
	t.Cleanup(signer.Close)
	f := &mcpFixture{service: service, signer: signer, root: root}
	var spec *identitySpec
	var identity *identityConfig
	if withIdentity {
		f.issuer = newIssuer(t)
		id := identityFor(t, f.issuer)
		service.identity = &id
		identity = &id
		spec = &identitySpec{issuer: id.issuer, audience: id.audience, keys: "/keys.json"}
		f.token = f.issuer.mint(t, "ec-1", nil, goodClaims(time.Now()))
	}
	cfg := mcpTestConfig(t, signer, spec)
	server, err := newMCPServer(cfg, mcpBindings(), identity)
	if err != nil {
		t.Fatal(err)
	}
	f.server = server
	f.front = httptest.NewServer(server.httpHandler())
	t.Cleanup(f.front.Close)
	return f
}

// call sends one message to the front and returns the status, the headers
// and the decoded body (nil when there is none).
func (f *mcpFixture) call(t *testing.T, method, session, body string, headers map[string]string) (int, http.Header, map[string]any) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, f.front.URL+mcpEndpoint, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if f.token != "" {
		req.Header.Set("Authorization", "Bearer "+f.token)
	}
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	for k, v := range headers {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var decoded map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("%s %s: body is not JSON: %s", method, body, raw)
		}
	}
	return resp.StatusCode, resp.Header, decoded
}

// open initializes a transport session and returns its id.
func (f *mcpFixture) open(t *testing.T) string {
	t.Helper()
	code, header, body := f.call(t, http.MethodPost, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`, nil)
	if code != http.StatusOK || header.Get("Mcp-Session-Id") == "" {
		t.Fatalf("initialize: %d %v %v", code, header, body)
	}
	result := body["result"].(map[string]any)
	if result["protocolVersion"] != mcpProtocolVersion || header.Get("MCP-Protocol-Version") != mcpProtocolVersion {
		t.Fatalf("initialize answered %v with header %q", result, header.Get("MCP-Protocol-Version"))
	}
	if code, _, _ := f.call(t, http.MethodPost, header.Get("Mcp-Session-Id"), `{"jsonrpc":"2.0","method":"notifications/initialized"}`, nil); code != http.StatusAccepted {
		t.Fatalf("initialized notification answered %d", code)
	}
	return header.Get("Mcp-Session-Id")
}

func toolCall(id int, name, arguments, meta string) string {
	params := `{"name":` + fmt.Sprintf("%q", name) + `,"arguments":` + arguments
	if meta != "" {
		params += `,"_meta":` + meta
	}
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":%s}}`, id, params)
}

func canonicalOf(t *testing.T, data []byte) string {
	t.Helper()
	v, err := parseJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	return string(canon(v))
}

func TestMCPToolTableAndCollisions(t *testing.T) {
	cfg := engineConfig{listen: "127.0.0.1:8787", platforms: []platformConfig{{name: "a"}, {name: "a.b"}}, mcp: &mcpConfig{listen: "127.0.0.1:8788", sessions: 1, idleSeconds: 60, concurrency: 1, callsPerMinute: 1}}
	bindings := map[string]binding{
		"a":   {live: &operation{tools: []string{"b.c", "x"}}},
		"a.b": {live: &operation{tools: []string{"c"}}},
	}
	if _, err := newMCPServer(cfg, bindings, nil); err == nil || !strings.Contains(err.Error(), `tool name "a.b.c" would name both`) {
		t.Fatalf("a colliding name started: %v", err)
	}
	cfg.platforms = []platformConfig{{name: "engine"}}
	if _, err := newMCPServer(cfg, map[string]binding{"engine": {live: &operation{tools: []string{"seal"}}}}, nil); err == nil || !strings.Contains(err.Error(), "the engine's seal tool") {
		t.Fatalf("a platform tool shadowing the seal tool started: %v", err)
	}
	cfg.platforms = []platformConfig{{name: "z"}, {name: "a"}}
	s, err := newMCPServer(cfg, map[string]binding{"z": {live: &operation{tools: []string{"t"}}}, "a": {live: &operation{tools: []string{"u"}}}, "noLive": {}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(s.order, ",") != "a.u,engine.seal,z.t" {
		t.Fatalf("the table lists %v", s.order)
	}
	cfg.mcp = nil
	if _, err := newMCPServer(cfg, bindings, nil); err == nil {
		t.Fatal("a configuration without mcp built a server")
	}
}

func TestMCPHTTPConformanceAndTheDifferential(t *testing.T) {
	f := newMCPFixture(t, false)
	sid := f.open(t)
	// ping and tools/list
	if code, _, body := f.call(t, http.MethodPost, sid, `{"jsonrpc":"2.0","id":2,"method":"ping"}`, nil); code != 200 || body["result"] == nil {
		t.Fatalf("ping: %d %v", code, body)
	}
	_, _, listed := f.call(t, http.MethodPost, sid, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`, nil)
	tools := listed["result"].(map[string]any)["tools"].([]any)
	var names []string
	for _, tool := range tools {
		names = append(names, tool.(map[string]any)["name"].(string))
	}
	if strings.Join(names, ",") != "engine.seal,screen.lookup,screen.search" {
		t.Fatalf("tools/list: %v", names)
	}
	seal := tools[0].(map[string]any)["inputSchema"].(map[string]any)
	if seal["additionalProperties"] != false || seal["required"].([]any)[0] != "session" {
		t.Fatalf("the seal tool's schema is open: %v", seal)
	}
	// a call: the answer carries the four members, and the receipt is the
	// store's own
	args := `{"subject": "acme", "n": 7}`
	code, _, body := f.call(t, http.MethodPost, sid, toolCall(4, "screen.lookup", args, ""), nil)
	if code != 200 {
		t.Fatalf("call: %d %v", code, body)
	}
	result := body["result"].(map[string]any)
	if result["isError"] != nil {
		t.Fatalf("the call errored: %v", result)
	}
	structured := result["structuredContent"].(map[string]any)
	session := structured["session"].(string)
	if !regexp.MustCompile(`^mcp-[0-9a-f]{32}$`).MatchString(session) {
		t.Fatalf("the generated session is %q", session)
	}
	receipt := structured["receipt"].(map[string]any)
	if receipt["sessionId"] != session || receipt["callIndex"] != float64(0) || receipt["kind"] != "acquisition" {
		t.Fatalf("the receipt is %v", receipt)
	}
	text := result["content"].([]any)[0].(map[string]any)["text"].(string)
	var fromText map[string]any
	if err := json.Unmarshal([]byte(text), &fromText); err != nil || fromText["session"] != session {
		t.Fatalf("the text block does not carry the same object: %s", text)
	}
	onDisk, err := os.ReadFile(filepath.Join(f.root, "store", "receipts", session, "0.json"))
	if err != nil {
		t.Fatal(err)
	}
	receiptJSON, _ := json.Marshal(receipt)
	if canonicalOf(t, onDisk) != canonicalOf(t, receiptJSON) {
		t.Fatalf("structuredContent.receipt is not the file the store holds:\n%s\n%s", onDisk, receiptJSON)
	}
	// the differential: the same call by a direct /acquire commits to the
	// same canonical arguments, and each commitment recomputes from its own
	// salt
	directBody := `{"session":"direct-1","source":"screen/live","arguments":{"tool":"lookup","arguments":` + args + `}}`
	resp, err := http.Post(f.signer.URL+"/acquire", "application/json", strings.NewReader(directBody))
	if err != nil {
		t.Fatal(err)
	}
	var direct map[string]any
	json.NewDecoder(resp.Body).Decode(&direct)
	resp.Body.Close()
	wrapper := canonicalOf(t, []byte(`{"tool":"lookup","arguments":`+args+`}`))
	for name, answer := range map[string]map[string]any{"through the server": structured, "direct": direct} {
		salt, err := hex.DecodeString(answer["salts"].(map[string]any)["args"].(string))
		if err != nil {
			t.Fatal(err)
		}
		want := commitmentOver(salt, "args:", []byte(wrapper))
		if got := answer["receipt"].(map[string]any)["argumentsCommitment"]; got != want {
			t.Fatalf("%s: the commitment does not recompute from its salt over the canonical wrapper: %v vs %s", name, got, want)
		}
	}
	if structured["receipt"].(map[string]any)["argumentsCommitment"] == direct["receipt"].(map[string]any)["argumentsCommitment"] {
		t.Fatal("two acquisitions share a salted commitment")
	}
	// arguments reach the signer as the client's bytes: a fraction, which
	// the signer's parser refuses, is the signer's refusal, not a rounding
	code, _, body = f.call(t, http.MethodPost, sid, toolCall(5, "screen.lookup", `{"x": 1.5}`, ""), nil)
	result = body["result"].(map[string]any)
	if code != 200 || result["isError"] != true || result["structuredContent"].(map[string]any)["status"] != float64(400) {
		t.Fatalf("a fraction was not the signer's refusal: %d %v", code, result)
	}
	if !strings.Contains(result["content"].([]any)[0].(map[string]any)["text"].(string), `"status":400`) {
		t.Fatalf("the error's text block does not carry the object: %v", result["content"])
	}
	// absent arguments are the engine's default
	if code, _, body = f.call(t, http.MethodPost, sid, `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"screen.search"}}`, nil); code != 200 || body["result"].(map[string]any)["isError"] != nil {
		t.Fatalf("absent arguments: %d %v", code, body)
	}
	// method not found, unknown tool, invalid params
	for _, c := range []struct {
		body string
		code float64
	}{
		{`{"jsonrpc":"2.0","id":7,"method":"resources/list"}`, rpcMethodNotFound},
		{toolCall(8, "screen.nothing", `{}`, ""), rpcInvalidParams},
		{`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{}}`, rpcInvalidParams},
		{`[{"jsonrpc":"2.0","id":10,"method":"ping"}]`, rpcInvalidRequest},
		{`{"jsonrpc":"2.0","id":10,"method":"ping","method":"ping"}`, rpcInvalidRequest},
		{`{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"screen.lookup","arguments":{"a":1,"a":2}}}`, rpcInvalidRequest},
		{`{"jsonrpc":"1.0","id":11,"method":"ping"}`, rpcInvalidRequest},
		{`not json`, rpcParse},
	} {
		code, _, body := f.call(t, http.MethodPost, sid, c.body, nil)
		if code != 200 || body["error"] == nil || body["error"].(map[string]any)["code"] != c.code {
			t.Fatalf("%s: %d %v", c.body, code, body)
		}
	}
}

func TestMCPHTTPMatrix(t *testing.T) {
	f := newMCPFixture(t, true)
	sid := f.open(t)
	ping := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{}}}`
	rows := []struct {
		name    string
		method  string
		session string
		body    string
		headers map[string]string
		want    int
	}{
		{"an origin not admitted", http.MethodPost, sid, ping, map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		{"a loopback origin", http.MethodPost, sid, ping, map[string]string{"Origin": "http://localhost:5173"}, http.StatusOK},
		{"no token", http.MethodPost, sid, ping, map[string]string{"Authorization": ""}, http.StatusUnauthorized},
		{"a token for another issuer", http.MethodPost, sid, ping, map[string]string{"Authorization": "Bearer " + newIssuer(t).mint(t, "ec-1", nil, goodClaims(time.Now()))}, http.StatusUnauthorized},
		{"a protocol version not spoken", http.MethodPost, sid, ping, map[string]string{"MCP-Protocol-Version": "2024-11-05"}, http.StatusBadRequest},
		{"the protocol version spoken", http.MethodPost, sid, ping, map[string]string{"MCP-Protocol-Version": "2025-06-18"}, http.StatusOK},
		{"a body over the bound", http.MethodPost, sid, `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"` + strings.Repeat("x", mcpMaxMessageBytes) + `"}}`, nil, http.StatusRequestEntityTooLarge},
		{"no session id", http.MethodPost, "", ping, nil, http.StatusBadRequest},
		{"an unknown session id", http.MethodPost, "mcp-" + strings.Repeat("0", 32), ping, nil, http.StatusNotFound},
		{"initialize with a session id", http.MethodPost, sid, init, nil, http.StatusBadRequest},
		{"initialize proposing another version is answered this one", http.MethodPost, "", init, nil, http.StatusOK},
		{"GET", http.MethodGet, sid, "", map[string]string{"Accept": "text/event-stream"}, http.StatusMethodNotAllowed},
		{"GET without a session", http.MethodGet, "", "", nil, http.StatusBadRequest},
		{"SSE alone", http.MethodPost, sid, ping, map[string]string{"Accept": "text/event-stream"}, http.StatusNotAcceptable},
		{"JSON excluded by quality", http.MethodPost, sid, ping, map[string]string{"Accept": "application/json;q=0, text/event-stream"}, http.StatusNotAcceptable},
		{"JSON and SSE both", http.MethodPost, sid, ping, map[string]string{"Accept": "application/json, text/event-stream"}, http.StatusOK},
		{"any type", http.MethodPost, sid, ping, map[string]string{"Accept": "*/*"}, http.StatusOK},
		{"a notification", http.MethodPost, sid, `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}`, nil, http.StatusAccepted},
		{"a client's response", http.MethodPost, sid, `{"jsonrpc":"2.0","id":"x","result":{}}`, nil, http.StatusAccepted},
		{"PUT", http.MethodPut, sid, ping, nil, http.StatusMethodNotAllowed},
	}
	for _, row := range rows {
		code, header, body := f.call(t, row.method, row.session, row.body, row.headers)
		if code != row.want {
			t.Errorf("%s: %d, want %d: %v", row.name, code, row.want, body)
		}
		if code == http.StatusUnauthorized && header.Get("WWW-Authenticate") != `Bearer resource_metadata="https://engine.test/.well-known/oauth-protected-resource/mcp"` {
			t.Errorf("%s: the challenge is %q", row.name, header.Get("WWW-Authenticate"))
		}
		if header.Get("MCP-Protocol-Version") != mcpProtocolVersion {
			t.Errorf("%s: the response names no protocol version", row.name)
		}
	}
	// a body over the bound sent without a length -- chunked -- is refused
	// by the read, not by the header
	big := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"` + strings.Repeat("x", mcpMaxMessageBytes) + `"}}`
	req, _ := http.NewRequest(http.MethodPost, f.front.URL+mcpEndpoint, io.NopCloser(strings.NewReader(big)))
	req.ContentLength = -1
	req.Header.Set("Authorization", "Bearer "+f.token)
	req.Header.Set("Mcp-Session-Id", sid)
	req.Header.Set("Content-Type", "application/json")
	chunked, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	chunked.Body.Close()
	if chunked.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("a chunked body over the bound answered %d", chunked.StatusCode)
	}
	// the unauthorized refusal repeats no token
	_, _, body := f.call(t, http.MethodPost, sid, ping, map[string]string{"Authorization": "Bearer " + f.token + "x"})
	if strings.Contains(fmt.Sprint(body["error"]), f.token) {
		t.Fatal("the refusal repeats the token")
	}
	// DELETE ends the transport session and seals nothing; afterwards 404
	before := len(f.service.sessions)
	if code, _, _ := f.call(t, http.MethodDelete, sid, "", nil); code != http.StatusOK {
		t.Fatalf("DELETE answered %d", code)
	}
	if code, _, _ := f.call(t, http.MethodPost, sid, ping, nil); code != http.StatusNotFound {
		t.Fatalf("an ended session answered %d", code)
	}
	if code, _, _ := f.call(t, http.MethodDelete, sid, "", nil); code != http.StatusNotFound {
		t.Fatalf("DELETE of an ended session answered %d", code)
	}
	if len(f.service.sessions) != before {
		t.Fatal("ending a transport session touched a receipt session")
	}
	// idle expiry
	sid = f.open(t)
	later := time.Now().Add(61 * time.Second)
	f.server.now = func() time.Time { return later }
	if code, _, _ := f.call(t, http.MethodPost, sid, ping, nil); code != http.StatusNotFound {
		t.Fatalf("an idle session answered %d", code)
	}
	f.server.now = time.Now
	// the sessions bound: 503 once every one is open (a matrix row above
	// opened one and left it)
	f.server.mu.Lock()
	already := len(f.server.sessions)
	f.server.mu.Unlock()
	var open []string
	for i := already; i < 4; i++ {
		open = append(open, f.open(t))
	}
	if code, _, _ := f.call(t, http.MethodPost, "", init, nil); code != http.StatusServiceUnavailable {
		t.Fatalf("a fifth session answered %d", code)
	}
	f.call(t, http.MethodDelete, open[0], "", nil)
	if code, _, _ := f.call(t, http.MethodPost, "", init, nil); code != http.StatusOK {
		t.Fatalf("after one ended, a new session answered %d", code)
	}
	// the metadata document, readable without a bearer, where RFC 9728
	// derives it
	resp, err := http.Get(f.front.URL + "/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	json.NewDecoder(resp.Body).Decode(&doc)
	resp.Body.Close()
	if resp.StatusCode != 200 || doc["resource"] != "https://engine.test/mcp" || doc["authorization_servers"].([]any)[0] != f.server.cfg.identity.issuer {
		t.Fatalf("the metadata document: %d %v", resp.StatusCode, doc)
	}
}

func TestMCPRefusalKindsAndSessions(t *testing.T) {
	f := newMCPFixture(t, false)
	sid := f.open(t)
	// a named session, chained twice, then sealed through the tool
	meta := `{"` + mcpSessionMeta + `":"named-1"}`
	for i := 0; i < 2; i++ {
		_, _, body := f.call(t, http.MethodPost, sid, toolCall(10+i, "screen.lookup", `{}`, meta), nil)
		structured := body["result"].(map[string]any)["structuredContent"].(map[string]any)
		if structured["session"] != "named-1" || structured["receipt"].(map[string]any)["callIndex"] != float64(i) {
			t.Fatalf("call %d in the named session: %v", i, structured)
		}
	}
	_, _, body := f.call(t, http.MethodPost, sid, toolCall(12, mcpSealTool, `{"session":"named-1"}`, ""), nil)
	result := body["result"].(map[string]any)
	if result["isError"] != nil || result["structuredContent"].(map[string]any)["finalCount"] != float64(2) {
		t.Fatalf("seal: %v", result)
	}
	// the sealed session refuses another receipt: the signer's refusal,
	// with the session named
	_, _, body = f.call(t, http.MethodPost, sid, toolCall(13, "screen.lookup", `{}`, meta), nil)
	result = body["result"].(map[string]any)
	structured := result["structuredContent"].(map[string]any)
	if result["isError"] != true || structured["status"] != float64(400) || structured["session"] != "named-1" || !strings.Contains(structured["error"].(string), "sealed") {
		t.Fatalf("a sealed session: %v", result)
	}
	// the seal tool's schema is closed; an unknown session is the signer's refusal
	if _, _, body = f.call(t, http.MethodPost, sid, toolCall(14, mcpSealTool, `{"session":"named-1","force":true}`, ""), nil); body["error"] == nil || body["error"].(map[string]any)["code"] != float64(rpcInvalidParams) {
		t.Fatalf("an extra seal member: %v", body)
	}
	_, _, body = f.call(t, http.MethodPost, sid, toolCall(15, mcpSealTool, `{"session":"never-1"}`, ""), nil)
	if result = body["result"].(map[string]any); result["isError"] != true || result["structuredContent"].(map[string]any)["session"] != "never-1" {
		t.Fatalf("sealing an unknown session: %v", result)
	}
	// a source that fails is the signer's refusal
	t.Setenv(envSourceFail, "1")
	_, _, body = f.call(t, http.MethodPost, sid, toolCall(16, "screen.lookup", `{}`, ""), nil)
	result = body["result"].(map[string]any)
	if result["isError"] != true || result["structuredContent"].(map[string]any)["status"] == nil {
		t.Fatalf("a failed source: %v", result)
	}
	t.Setenv(envSourceFail, "")
	// an outcome the server does not know: the signer accepts and stalls
	stalled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(2 * time.Second) }))
	t.Cleanup(stalled.Close)
	f.server.signer = stalled.URL
	f.server.forwardTimeout = 200 * time.Millisecond
	_, _, body = f.call(t, http.MethodPost, sid, toolCall(17, "screen.lookup", `{}`, ""), nil)
	result = body["result"].(map[string]any)
	if result["isError"] != true || result["structuredContent"].(map[string]any)["outcome"] != "unknown" {
		t.Fatalf("a stalled signer: %v", result)
	}
	f.server.signer = f.signer.URL
	f.server.forwardTimeout = mcpForwardTimeout
}

// A token the front accepts and the signer refuses -- the two holding
// different keys -- is the transport's 401 with the front's own challenge.
func TestMCPSignerRefusalOfTheTokenIsTheTransports(t *testing.T) {
	f := newMCPFixture(t, true)
	sid := f.open(t)
	other := identityFor(t, newIssuer(t))
	f.service.identity = &other
	code, header, body := f.call(t, http.MethodPost, sid, toolCall(1, "screen.lookup", `{}`, ""), nil)
	if code != http.StatusUnauthorized || !strings.HasPrefix(header.Get("WWW-Authenticate"), `Bearer resource_metadata=`) || body["error"] == nil {
		t.Fatalf("the signer's refusal came back as %d %q %v", code, header.Get("WWW-Authenticate"), body)
	}
}

var _ = bytes.Compare
