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
		platforms: []platformConfig{{name: "other", binding: "other@sha256:" + strings.Repeat("cd", 32)}, {name: "screen", binding: "screen@sha256:" + strings.Repeat("ab", 32)}},
		mcp:       &mcpConfig{listen: "127.0.0.1:0", resource: "https://engine.test/mcp", sessions: 4, idleSeconds: 60, concurrency: 2, callsPerMinute: 100},
	}
}

func mcpBindings() map[string]binding {
	return map[string]binding{
		"other":  {platform: "other", live: &operation{shape: "mcp", tools: []string{"lookup"}}},
		"screen": {platform: "screen", live: &operation{shape: "mcp", tools: []string{"lookup", "search"}}},
	}
}

// newMCPFixture builds the pair; with identity, the signer and the front
// share one issuer and the fixture holds a good token.
func newMCPFixture(t *testing.T, withIdentity bool) *mcpFixture {
	t.Helper()
	t.Setenv(envSourceHelper, "1")
	root := t.TempDir()
	service, err := newGatewayService(filepath.Join(root, "store"), testSeed, "gateway:test", filepath.Join(root, "registry.jsonl"),
		map[string]sourceSpec{"screen/live": {argv: []string{os.Args[0]}, env: helperEnv}, "other/live": {argv: []string{os.Args[0]}, env: helperEnv}})
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
		switch {
		case k == "Accept-Second":
			req.Header.Add("Accept", v)
		case v == "":
			req.Header.Del(k)
		default:
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

// receiptsOf counts the receipt files the store holds for a session: what
// reached the signer and was minted, which no size of any map stands in
// for.
func (f *mcpFixture) receiptsOf(session string) int {
	entries, _ := os.ReadDir(filepath.Join(f.root, "store", "receipts", session))
	n := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			n++
		}
	}
	return n
}

// waitUntil polls a condition for up to five seconds, so a test that
// needs a call to have taken its place waits for that and not for a clock.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("waited five seconds for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// resultOf is a message's result, or the test fails saying what came
// instead.
func resultOf(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	result, ok := body["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", body)
	}
	return result
}

// sameBothWays holds a tool result's text block to its structuredContent,
// whole: the one decoded is the other.
func sameBothWays(t *testing.T, result map[string]any) map[string]any {
	t.Helper()
	content := result["content"].([]any)
	if len(content) != 1 || content[0].(map[string]any)["type"] != "text" {
		t.Fatalf("the content is %v", content)
	}
	var fromText any
	if err := json.Unmarshal([]byte(content[0].(map[string]any)["text"].(string)), &fromText); err != nil {
		t.Fatalf("the text block is not JSON: %v", err)
	}
	structured := result["structuredContent"]
	a, _ := json.Marshal(fromText)
	b, _ := json.Marshal(structured)
	if canonicalOf(t, a) != canonicalOf(t, b) {
		t.Fatalf("the text block and structuredContent differ:\n%s\n%s", a, b)
	}
	return structured.(map[string]any)
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
	if strings.Join(names, ",") != "engine.seal,other.lookup,screen.lookup,screen.search" {
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
	structured := sameBothWays(t, result)
	session := structured["session"].(string)
	if !regexp.MustCompile(`^mcp-[0-9a-f]{32}$`).MatchString(session) {
		t.Fatalf("the generated session is %q", session)
	}
	receipt := structured["receipt"].(map[string]any)
	if receipt["sessionId"] != session || receipt["callIndex"] != float64(0) || receipt["kind"] != "acquisition" || receipt["source"] != "screen/live" {
		t.Fatalf("the receipt is %v", receipt)
	}
	// another platform's tool of the same name is that platform's source,
	// not the first's: no substitution across the table
	_, _, otherBody := f.call(t, http.MethodPost, sid, toolCall(40, "other.lookup", args, ""), nil)
	otherReceipt := sameBothWays(t, otherBody["result"].(map[string]any))["receipt"].(map[string]any)
	if otherReceipt["source"] != "other/live" || otherReceipt["callIndex"] != float64(1) {
		t.Fatalf("the other platform's receipt is %v", otherReceipt)
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
	if sameBothWays(t, result)["status"] != float64(400) {
		t.Fatalf("the error's text block does not carry the object: %v", result["content"])
	}
	// and so do the numbers the frontend's own parser would refuse: an
	// exponent past its range reaches the signer as bytes and is the
	// signer's refusal too
	_, _, body = f.call(t, http.MethodPost, sid, toolCall(41, "screen.lookup", `{"x": 1e400}`, ""), nil)
	if result = body["result"].(map[string]any); result["isError"] != true || sameBothWays(t, result)["status"] != float64(400) {
		t.Fatalf("1e400 was not the signer's refusal: %v", body)
	}
	// duplicate members inside the arguments are the signer's to judge as
	// well, and a duplicate anywhere else in the message is this server's
	_, _, body = f.call(t, http.MethodPost, sid, toolCall(42, "screen.lookup", `{"a":1,"a":2}`, ""), nil)
	if result = body["result"].(map[string]any); result["isError"] != true || sameBothWays(t, result)["status"] != float64(400) {
		t.Fatalf("a duplicate inside the arguments was not the signer's refusal: %v", body)
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
		{`{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"screen.lookup","_meta":{"a":1,"a":2}}}`, rpcInvalidRequest},
		{`{"jsonrpc":"1.0","id":11,"method":"ping"}`, rpcInvalidRequest},
		{`{"jsonrpc":"2.0","id":true,"method":"ping"}`, rpcInvalidRequest},
		{`{"jsonrpc":"2.0","id":[1],"method":"ping"}`, rpcInvalidRequest},
		{`{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}`, rpcInvalidRequest},
		{`{"jsonrpc":"2.0","id":1.5,"method":"ping"}`, rpcInvalidRequest},
		{`{"jsonrpc":"2.0","id":1,"method":"ping","result":{}}`, rpcInvalidRequest},
		{`{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"x"}}`, rpcInvalidRequest},
		{`{"jsonrpc":"2.0","id":1,"method":"ping","params":"x"}`, rpcInvalidRequest},
		{`{"jsonrpc":"2.0","id":1,"method":"ping","extra":1}`, rpcInvalidRequest},
		{`{"jsonrpc":"2.0","id":1,"method":""}`, rpcInvalidRequest},
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"screen.lookup","arguments":[1]}}`, rpcInvalidParams},
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"NAME":"screen.lookup"}}`, rpcInvalidParams},
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"screen.lookup","_meta":"x"}}`, rpcInvalidParams},
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"screen.lookup","_meta":{"` + mcpSessionMeta + `":1}}}`, rpcInvalidParams},
		{`not json`, rpcParse},
		{`{"jsonrpc":"2.0","id":1,"method":"ping"} trailing`, rpcParse},
	} {
		code, _, body := f.call(t, http.MethodPost, sid, c.body, nil)
		if code != 200 || body["error"] == nil || body["error"].(map[string]any)["code"] != c.code {
			t.Fatalf("%s: %d %v", c.body, code, body)
		}
	}
	// a message whose id is null is neither a request nor a notification
	// under the pinned protocol's schema: refused, not taken for either
	if _, _, body := f.call(t, http.MethodPost, sid, `{"jsonrpc":"2.0","id":null,"method":"ping"}`, nil); body["error"] == nil || body["error"].(map[string]any)["code"] != float64(rpcInvalidRequest) || body["result"] != nil {
		t.Fatalf("id null: %v", body)
	}
	// the members are read by their exact names: METHOD is not method, and
	// a message with no method is a response, acknowledged
	if code, _, _ := f.call(t, http.MethodPost, sid, `{"jsonrpc":"2.0","id":1,"METHOD":"ping"}`, nil); code != http.StatusOK {
		t.Fatalf("METHOD answered %d", code)
	}
	// a case-folded member inside a call is not the member: no session is
	// named by _META, and the call lands in the generated session
	_, _, body = f.call(t, http.MethodPost, sid, `{"jsonrpc":"2.0","id":43,"method":"tools/call","params":{"name":"screen.lookup","_META":{"`+mcpSessionMeta+`":"named-x"}}}`, nil)
	if body["error"] == nil || body["error"].(map[string]any)["code"] != float64(rpcInvalidParams) {
		t.Fatalf("_META was read as _meta or tolerated: %v", body)
	}
	// initialize again on an initialized session is a lifecycle error, and
	// a tool is not callable on a session that never initialized
	if _, _, body = f.call(t, http.MethodPost, sid, `{"jsonrpc":"2.0","id":44,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`, nil); body["error"] == nil || !strings.Contains(body["error"].(map[string]any)["message"].(string), "initialized already") {
		t.Fatalf("a second initialize: %v", body)
	}
	for _, params := range []string{`{}`, `{"protocolVersion":"2025-06-18"}`, `{"protocolVersion":"2025-06-18","capabilities":{}}`, `{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t"}}`, `{"protocolVersion":"2025-06-18","capabilities":[],"clientInfo":{"name":"t","version":"0"}}`, `{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"},"x":1}`, `{"capabilities":{},"clientInfo":{"name":"t","version":"0"}}`, `{"protocolVersion":"2025-06-18","clientInfo":{"name":"t","version":"0"}}`, `{"protocolVersion":1,"capabilities":{},"clientInfo":{"name":"t","version":"0"}}`, `{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":0}}`} {
		code, header, body := f.call(t, http.MethodPost, "", `{"jsonrpc":"2.0","id":45,"method":"initialize","params":`+params+`}`, nil)
		if code != http.StatusOK || body["error"] == nil || body["error"].(map[string]any)["code"] != float64(rpcInvalidParams) {
			t.Fatalf("initialize with params %s: %d %v", params, code, body)
		}
		// the session it opened is not initialized: a call on it is refused
		// and nothing reaches the signer
		if _, _, body := f.call(t, http.MethodPost, header.Get("Mcp-Session-Id"), toolCall(46, "screen.lookup", `{}`, ""), nil); body["error"] == nil || !strings.Contains(body["error"].(map[string]any)["message"].(string), "initialize first") {
			t.Fatalf("a call before initialization: %v", body)
		}
		f.call(t, http.MethodDelete, header.Get("Mcp-Session-Id"), "", nil)
	}
	// three receipts in the generated session: the first call, the other
	// platform's, and the one with absent arguments; the refusals minted none
	if f.receiptsOf(session) != 3 {
		t.Fatalf("the generated session holds %d receipts, not the three minted above", f.receiptsOf(session))
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
		{"initialize with a live session id is a request on it", http.MethodPost, sid, init, nil, http.StatusOK},
		{"initialize with an unknown session id", http.MethodPost, "mcp-" + strings.Repeat("1", 32), init, nil, http.StatusNotFound},
		{"initialize proposing another version is answered this one", http.MethodPost, "", init, nil, http.StatusOK},
		{"an origin that is no origin", http.MethodPost, sid, ping, map[string]string{"Origin": "null"}, http.StatusForbidden},
		{"a loopback origin with userinfo", http.MethodPost, sid, ping, map[string]string{"Origin": "http://u@localhost"}, http.StatusForbidden},
		{"a loopback origin with a query", http.MethodPost, sid, ping, map[string]string{"Origin": "http://localhost?x"}, http.StatusForbidden},
		{"an origin spelled as a host that resolves to loopback", http.MethodPost, sid, ping, map[string]string{"Origin": "http://localhost.evil.example"}, http.StatusForbidden},
		// combined failures: the first row that fails answers
		{"a bad origin and no token", http.MethodPost, sid, ping, map[string]string{"Origin": "https://evil.example", "Authorization": ""}, http.StatusForbidden},
		{"no token and a bad version", http.MethodPost, sid, ping, map[string]string{"Authorization": "", "MCP-Protocol-Version": "2024-11-05"}, http.StatusUnauthorized},
		{"a bad version and a body over the bound", http.MethodPost, sid, `{"pad":"` + strings.Repeat("x", mcpMaxMessageBytes) + `"}`, map[string]string{"MCP-Protocol-Version": "2024-11-05"}, http.StatusBadRequest},
		{"a body over the bound and no session", http.MethodPost, "", `{"pad":"` + strings.Repeat("x", mcpMaxMessageBytes) + `"}`, nil, http.StatusRequestEntityTooLarge},
		{"DELETE with a body over the bound", http.MethodDelete, sid, `{"pad":"` + strings.Repeat("x", mcpMaxMessageBytes) + `"}`, nil, http.StatusRequestEntityTooLarge},
		{"DELETE of an unknown session", http.MethodDelete, "mcp-" + strings.Repeat("2", 32), "", nil, http.StatusNotFound},
		{"GET with an unknown session", http.MethodGet, "mcp-" + strings.Repeat("3", 32), "", nil, http.StatusNotFound},
		{"GET accepting JSON is still no stream", http.MethodGet, sid, "", map[string]string{"Accept": "application/json"}, http.StatusMethodNotAllowed},
		{"Accept on two lines, JSON on the second", http.MethodPost, sid, ping, map[string]string{"Accept": "text/event-stream\nAccept: application/json"}, http.StatusOK},
		{"a media-type parameter on the JSON range", http.MethodPost, sid, ping, map[string]string{"Accept": "application/json;charset=utf-8"}, http.StatusNotAcceptable},
		{"an invalid quality", http.MethodPost, sid, ping, map[string]string{"Accept": "application/json;q=x"}, http.StatusNotAcceptable},
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
		headers := row.headers
		if v, ok := headers["Accept"]; ok && strings.Contains(v, "\n") {
			// two field lines, which the fixture's one header cannot say
			headers = map[string]string{"Accept": strings.Split(v, "\n")[0], "Accept-Second": strings.TrimPrefix(strings.Split(v, "\n")[1], "Accept: ")}
		}
		code, header, body := f.call(t, row.method, row.session, row.body, headers)
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
	// origins given and empty admit no origin at all; given, the exact ones
	f.server.cfg.mcp.originsGiven = true
	if code, _, _ := f.call(t, http.MethodPost, sid, ping, map[string]string{"Origin": "http://localhost:5173"}); code != http.StatusForbidden {
		t.Fatalf("a loopback origin under origins [] answered %d", code)
	}
	if code, _, _ := f.call(t, http.MethodPost, sid, ping, nil); code != http.StatusOK {
		t.Fatalf("no origin under origins [] answered %d", code)
	}
	f.server.cfg.mcp.origins = []string{"https://desk.example"}
	if code, _, _ := f.call(t, http.MethodPost, sid, ping, map[string]string{"Origin": "https://desk.example"}); code != http.StatusOK {
		t.Fatalf("the configured origin answered %d", code)
	}
	if code, _, _ := f.call(t, http.MethodPost, sid, ping, map[string]string{"Origin": "https://desk.example:443"}); code != http.StatusForbidden {
		t.Fatalf("an origin spelled otherwise answered %d", code)
	}
	f.server.cfg.mcp.originsGiven, f.server.cfg.mcp.origins = false, nil
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
	// DELETE ends the transport session and seals nothing: the receipt
	// session it generated still takes an acquisition afterwards, from
	// another transport session that names it
	_, _, body = f.call(t, http.MethodPost, sid, toolCall(2, "screen.lookup", `{}`, ""), nil)
	generated := sameBothWays(t, body["result"].(map[string]any))["session"].(string)
	if code, _, _ := f.call(t, http.MethodDelete, sid, "", nil); code != http.StatusOK {
		t.Fatalf("DELETE answered %d", code)
	}
	if code, _, _ := f.call(t, http.MethodPost, sid, ping, nil); code != http.StatusNotFound {
		t.Fatalf("an ended session answered %d", code)
	}
	if code, _, _ := f.call(t, http.MethodDelete, sid, "", nil); code != http.StatusNotFound {
		t.Fatalf("DELETE of an ended session answered %d", code)
	}
	another := f.open(t)
	_, _, body = f.call(t, http.MethodPost, another, toolCall(3, "screen.lookup", `{}`, `{"`+mcpSessionMeta+`":"`+generated+`"}`), nil)
	if chained := sameBothWays(t, body["result"].(map[string]any)); chained["session"] != generated || chained["receipt"].(map[string]any)["callIndex"] != float64(1) {
		t.Fatalf("after DELETE the generated session did not take a receipt: %v", body)
	}
	f.call(t, http.MethodDelete, another, "", nil)
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
	if resp.StatusCode != 200 || doc["resource"] != "https://engine.test/mcp" || doc["authorization_servers"].([]any)[0] != f.server.cfg.identity.issuer || doc["bearer_methods_supported"].([]any)[0] != "header" {
		t.Fatalf("the metadata document: %d %v", resp.StatusCode, doc)
	}
	if resp, _ := http.Post(f.front.URL+"/.well-known/oauth-protected-resource/mcp", "application/json", nil); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST of the metadata document answered %d", resp.StatusCode)
	}
}

// The signer is the one destination: a redirect from it is not followed,
// and is answered as the status it is; and the answer that does not arrive
// names no address.
func TestMCPForwardFollowsNothingAndNamesNoAddress(t *testing.T) {
	f := newMCPFixture(t, false)
	sid := f.open(t)
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result":{},"receipt":{"forged":true},"salts":{}}`))
	}))
	t.Cleanup(elsewhere.Close)
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/acquire", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirecting.Close)
	f.server.signer = redirecting.URL
	_, _, body := f.call(t, http.MethodPost, sid, toolCall(1, "screen.lookup", `{}`, ""), nil)
	result := body["result"].(map[string]any)
	if result["isError"] != true || sameBothWays(t, result)["status"] != float64(http.StatusTemporaryRedirect) {
		t.Fatalf("a redirect: %v", result)
	}
	stalled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(2 * time.Second) }))
	t.Cleanup(stalled.Close)
	f.server.signer = stalled.URL
	f.server.forwardTimeout = 100 * time.Millisecond
	var diagnostics bytes.Buffer
	f.server.log = &diagnostics
	_, _, body = f.call(t, http.MethodPost, sid, toolCall(2, "screen.lookup", `{}`, ""), nil)
	result = body["result"].(map[string]any)
	structured := sameBothWays(t, result)
	if result["isError"] != true || structured["outcome"] != "unknown" {
		t.Fatalf("a stalled signer: %v", result)
	}
	if text := fmt.Sprint(structured["error"]); strings.Contains(text, stalled.URL) || strings.Contains(text, "127.0.0.1") {
		t.Fatalf("the unknown outcome names the signer's address: %s", text)
	}
	if !strings.Contains(diagnostics.String(), "did not answer") {
		t.Fatalf("the diagnostics stream did not record the failed forward: %q", diagnostics.String())
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
	// an empty session name is the signer's to refuse, as any name is
	_, _, body = f.call(t, http.MethodPost, sid, toolCall(17, mcpSealTool, `{"session":""}`, ""), nil)
	if result = body["result"].(map[string]any); result["isError"] != true || sameBothWays(t, result)["status"] != float64(400) {
		t.Fatalf("sealing the empty session name: %v", body)
	}
	if f.receiptsOf("named-1") != 2 {
		t.Fatalf("named-1 holds %d receipts, not 2", f.receiptsOf("named-1"))
	}
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
