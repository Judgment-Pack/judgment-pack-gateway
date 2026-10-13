package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// remoteStandIn is a remote MCP server over Streamable HTTP, in the test's
// own process: initialize with a session id it then requires, the tool
// list, a call that echoes what it was asked, the session's end; and every
// request it was sent, counted, with the bearer each carried.
type remoteStandIn struct {
	*httptest.Server
	mu       sync.Mutex
	requests []string
	bearers  []string
}

func newRemoteStandIn(t *testing.T, overTLS bool) *remoteStandIn {
	t.Helper()
	s := &remoteStandIn{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		json.Unmarshal(body, &m)
		s.mu.Lock()
		s.requests = append(s.requests, r.Method+" "+r.URL.RequestURI()+" "+m.Method)
		s.bearers = append(s.bearers, r.Header.Get("Authorization"))
		s.mu.Unlock()
		if m.Method != "initialize" && r.Header.Get("Mcp-Session-Id") != "remote-session" {
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
		var result any
		switch m.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "remote-session")
			result = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "remote-standin", "version": "3.1"}}
		case "tools/list":
			result = map[string]any{"tools": []any{map[string]any{"name": "lookup", "inputSchema": map[string]any{"type": "object"}}, map[string]any{"name": "update", "inputSchema": map[string]any{"type": "object"}}}}
		case "tools/call":
			result = map[string]any{"content": []any{map[string]any{"type": "text", "text": "done"}}, "structuredContent": map[string]any{"params": m.Params}}
		}
		w.Header().Set("Content-Type", "application/json")
		out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": result})
		w.Write(out)
	})
	if overTLS {
		s.Server = httptest.NewTLSServer(handler)
	} else {
		s.Server = httptest.NewServer(handler)
	}
	t.Cleanup(s.Close)
	return s
}

func (s *remoteStandIn) sent() ([]string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...), append([]string(nil), s.bearers...)
}

// The remote form across the process boundary: this gateway spawns the
// real adapter-mcp binary as a source declared mcp with --url, the adapter
// reaches a server over TLS under the roots of --ca-file with the bearer
// from its credentials file, and the receipt records the transport, the
// URL, the TLS identity the answer came under and the server's own name and
// version, with the adapter as the adapter; the store verifies.
func TestGatewaySpawnsTheMCPAdapterRemoteFormEndToEnd(t *testing.T) {
	dir := t.TempDir()
	bin, _ := buildMCPStandIns(t, dir)
	remote := newRemoteStandIn(t, true)
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: remote.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	credentials := filepath.Join(dir, "remote.json")
	if err := os.WriteFile(credentials, []byte(`{"TOKEN":"remote-secret-token"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	url := remote.URL + "/api/mcp"
	adapter := filepath.Join(bin, "adapter-mcp")
	args := []string{
		filepath.Join(dir, "store"), "seed-is-loaded-separately", "gateway:test", filepath.Join(dir, "registry.jsonl"),
		"--source", "live=" + adapter + " --url " + url + " --ca-file " + ca + " --credentials " + credentials + " --bearer TOKEN --tools lookup",
		"--source-shape", "live=mcp",
	}
	opts, msg, ok := parseServeOptions(args)
	if !ok {
		t.Fatal(msg)
	}
	service, err := buildService(args[0], testSeed, args[2], args[3], opts)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(service.handler())
	defer httpServer.Close()
	code, first := post(t, httpServer, "/acquire", `{"session":"remote-e2e","source":"live","arguments":{"tool":"lookup","arguments":{"id":7}}}`)
	if code != http.StatusOK {
		t.Fatalf("acquire failed: %d %v", code, first)
	}
	acquisition := first["receipt"].(map[string]any)["acquisition"].(map[string]any)
	// The binary as built: on Windows the build wrote adapter-mcp.exe.
	exe := adapter
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	self, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	selfSum := sha256.Sum256(self)
	leaf := sha256.Sum256(remote.Certificate().Raw)
	adapterOut := acquisition["adapter"].(map[string]any)
	if acquisition["shape"] != "mcp" || acquisition["transport"] != "http" || acquisition["endpoint"] != url ||
		acquisition["peerIdentity"] != "tls:sha256:"+hex.EncodeToString(leaf[:]) ||
		fmt.Sprint(acquisition["server"]) != "map[name:remote-standin version:3.1]" ||
		adapterOut["name"] != "adapter-mcp" || adapterOut["digest"] != "sha256:"+hex.EncodeToString(selfSum[:]) {
		t.Fatalf("the receipt names the remote server: %v", acquisition)
	}
	if encoded, _ := json.Marshal(first); strings.Contains(string(encoded), "remote-secret-token") || strings.Contains(string(encoded), "remote-session") {
		t.Fatal("the credential or the session id reached the response")
	}
	requests, bearers := remote.sent()
	if strings.Join(requests, "|") != "POST /api/mcp initialize|POST /api/mcp notifications/initialized|POST /api/mcp tools/list|POST /api/mcp tools/call|DELETE /api/mcp " {
		t.Fatalf("one session at the URL as written: %q", requests)
	}
	for _, b := range bearers {
		if b != "Bearer remote-secret-token" {
			t.Fatalf("the bearer from the credentials file: %q", bearers)
		}
	}
	if code, body := post(t, httpServer, "/seal", `{"session":"remote-e2e"}`); code != http.StatusOK {
		t.Fatalf("seal failed: %d %v", code, body)
	}
	report, err := verifyWithRegistry(service.storeRoot, service.regPath, "gateway:test", service.publicKey)
	if err != nil || !report.OK {
		t.Fatalf("the store must verify: %v %v", err, report)
	}
}

// The executor through the remote form: a platform whose binding names a
// remote server for its write, held to a decision policy. A write the
// policy refuses sends nothing -- the server is never reached; a write it
// admits goes to the server's URL with the write credential, and the action
// receipt names that URL as the tool's endpoint; the store, the registry
// and the records verify.
func TestEngineWritesThroughARemoteServerEndToEnd(t *testing.T) {
	dir := t.TempDir()
	bin, fake := buildMCPStandIns(t, dir)
	remote := newRemoteStandIn(t, false)
	url := remote.URL + "/mcp"
	binding := `{"bindingVersion":"1","platform":"tickets","operations":{` +
		`"live":{"shape":"mcp","server":{"image":"ghcr.io/example/mcp-tickets:1@` + testImageDigest + `"},"tools":["query"],"licence":"MIT"},` +
		`"write":{"shape":"mcp","server":{"url":"` + url + `","bearer":"WRITE_TOKEN","headers":["X-MCP-Readonly=false"]},"tools":["update"],"licence":"MIT"}}}`
	live := filepath.Join(dir, "live.json")
	write := filepath.Join(dir, "write.json")
	if err := os.WriteFile(live, []byte(`{"SERVICE_TOKEN":"secret-token"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(write, []byte(`{"WRITE_TOKEN":"write-secret-token"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	catalog := catalogWith(t, map[string]string{"tickets": binding})
	escape := func(p string) string { return strings.ReplaceAll(p, `\`, `\\`) }
	policy := `{"outcomes":["approve"],"packs":["` + packA + `"],"bind":[{"argument":"/ticket","fact":"/ticket/id"}]}`
	text := `{"engineVersion":"4","authority":"gateway:test","seed":"` + escape(filepath.Join(dir, "gateway.seed")) + `","store":"` + escape(filepath.Join(dir, "store")) + `",` +
		`"registry":"` + escape(filepath.Join(dir, "registry.jsonl")) + `","decisionRecords":"` + escape(filepath.Join(dir, "decisions")) + `",` +
		`"listen":"127.0.0.1:0","catalog":"` + escape(catalog) + `","runtime":"` + escape(fake) + `","adapters":"` + escape(bin) + `",` +
		`"platforms":{"tickets":{"binding":"tickets@` + digestOf(binding) + `","credentials":{"live":{"file":"` + escape(live) + `"},"write":{"file":"` + escape(write) + `"}},` +
		`"user":"engine-tickets","endpoint":"tickets.internal","write":true,"decisionPolicy":{"update":` + policy + `}}}}`
	path := filepath.Join(dir, "engine.json")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, bindings, err := loadEngineConfig(path, stubAccounts(map[string]int{"engine-tickets": 1001}))
	if err != nil {
		t.Fatal(err)
	}
	sources := deriveSources(cfg, bindings)
	for name, spec := range sources {
		spec.user = ""
		sources[name] = spec
	}
	service, err := buildService(cfg.store, testSeed, cfg.authority, cfg.registry, engineServeOptions(cfg, sources, nil))
	if err != nil {
		t.Fatal(err)
	}
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	service.identity = &id
	token := issuer.mint(t, "ec-1", nil, goodClaims(time.Now()))
	server := httptest.NewServer(service.handler())
	defer server.Close()
	code, first := authed(t, server, "/acquire", `{"session":"remote-write","source":"tickets/live","arguments":{"tool":"query","arguments":{"sql":"select * from tickets where id = 'T-1'"}}}`, token)
	if code != http.StatusOK {
		t.Fatalf("acquire failed: %d %v", code, first)
	}
	signature := first["receipt"].(map[string]any)["signature"].(string)
	line := `{"recordVersion":"1","trail":"` + strings.Repeat("8d", 16) + `","sequence":1,"kind":"evaluation","pack":{"id":"ticket-approval","version":"2.0.0","digest":"` + packA + `"},` +
		`"inputs":{"facts":{"ticket":{"id":"T-1"}}},"cites":[{"sessionId":"remote-write","callIndex":0,"signature":"` + signature + `"}],` +
		`"disposition":{"handoff":{"state":"none"},"kind":"outcome","outcomeId":"approve","reasons":[]}}`
	if err := os.MkdirAll(cfg.decisionRecords, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.decisionRecords, "evaluations.jsonl"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	act := func(ticket string) string {
		return `{"session":"remote-write","platform":"tickets","tool":"update","arguments":{"ticket":"` + ticket + `","status":"approved"},` +
			`"decision":{"recordDigest":"sha256:` + hexOf([]byte(line)) + `","packDigest":"` + packA + `"},` +
			`"cites":[{"sessionId":"remote-write","callIndex":0,"signature":"` + signature + `"}]}`
	}
	// Decided on T-1, written to T-2: refused before the executor starts,
	// and the remote server is never reached.
	if code, body := authed(t, server, "/act", act("T-2"), token); code != http.StatusBadRequest || body["refusedAt"] != "policy-bind" {
		t.Fatalf("a write to another ticket than the one decided: %d %v", code, body)
	}
	if requests, _ := remote.sent(); len(requests) != 0 {
		t.Fatalf("a write the policy refused reached the server: %q", requests)
	}
	code, acted := authed(t, server, "/act", act("T-1"), token)
	if code != http.StatusOK {
		t.Fatalf("act failed: %d %v", code, acted)
	}
	inner := acted["receipt"].(map[string]any)["action"].(map[string]any)
	tool := inner["tool"].(map[string]any)
	if tool["shape"] != "mcp" || tool["endpoint"] != url || tool["name"] != "update" || inner["adapter"].(map[string]any)["name"] != "adapter-mcp" {
		t.Fatalf("the action receipt names the URL the write went to: %v", inner)
	}
	requests, bearers := remote.sent()
	if strings.Join(requests, "|") != "POST /mcp initialize|POST /mcp notifications/initialized|POST /mcp tools/list|POST /mcp tools/call|DELETE /mcp " {
		t.Fatalf("the write is one session at the URL: %q", requests)
	}
	for _, b := range bearers {
		if b != "Bearer write-secret-token" {
			t.Fatalf("the write credential, from the write file: %q", bearers)
		}
	}
	echoed := acted["result"].(map[string]any)["structuredContent"].(map[string]any)["params"].(map[string]any)
	if echoed["name"] != "update" || echoed["arguments"].(map[string]any)["ticket"] != "T-1" {
		t.Fatalf("the target got the write as sent: %v", echoed)
	}
	if code, body := authed(t, server, "/seal", `{"session":"remote-write"}`, token); code != http.StatusOK {
		t.Fatalf("seal failed: %d %v", code, body)
	}
	report, err := verifyWithRegistryAndRecords(service.storeRoot, service.regPath, "gateway:test", cfg.decisionRecords, service.publicKey)
	if err != nil || !report.OK {
		t.Fatalf("the store, the registry and the records must verify together: %v %+v", err, report)
	}
}
