package main

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// From a configuration to a receipt: the sources `serve --config` derives
// from a platform's binding run the real adapter-mcp binary against a
// stand-in runtime built here, and the store verifies with a receipt whose
// acquisition names the binding's pinned image. The platform's user is
// stripped before the service is built, since this test does not run as a
// user that can switch; what it proves is that the derivation is right end
// to end, the switching being proved where it is implemented.
func TestEngineConfigDrivesTheMCPAdapterEndToEnd(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain on PATH")
	}
	dir := t.TempDir()
	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	build := exec.Command(goTool, "build", "-buildvcs=false", "-o", filepath.Join(bin, "adapter-mcp"+exe), "./cmd/adapter-mcp")
	build.Dir = filepath.Join("..", "adapters")
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the adapter: %v\n%s", err, out)
	}
	// The stand-in runtime: `run ... IMAGE` speaks JSON-RPC as the server
	// the image would be, answering only when the env file the adapter
	// mounted carried the credential; kill and inspect as for a container
	// that is gone.
	fakeDir := filepath.Join(dir, "fake")
	if err := os.MkdirAll(fakeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	fakeSource := `package main

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	switch os.Args[1] {
	case "kill":
		os.Exit(0)
	case "inspect":
		os.Stderr.WriteString("Error: No such object: " + os.Args[2] + "\n")
		os.Exit(1)
	}
	envFile := ""
	for i, a := range os.Args {
		if a == "--env-file" && i+1 < len(os.Args) {
			data, _ := os.ReadFile(os.Args[i+1])
			envFile = string(data)
		}
	}
	if !strings.Contains(envFile, "SERVICE_TOKEN=secret-token") {
		os.Stderr.WriteString("no token in the env file\n")
		os.Exit(1)
	}
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		var m struct {
			ID     json.RawMessage ` + "`json:\"id\"`" + `
			Method string          ` + "`json:\"method\"`" + `
			Params json.RawMessage ` + "`json:\"params\"`" + `
		}
		if json.Unmarshal(in.Bytes(), &m) != nil || len(m.ID) == 0 {
			continue
		}
		var result any
		switch m.Method {
		case "initialize":
			result = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "standin", "version": "0.1"}}
		case "tools/list":
			result = map[string]any{"tools": []any{map[string]any{"name": "query", "inputSchema": map[string]any{"type": "object"}}, map[string]any{"name": "execute", "inputSchema": map[string]any{"type": "object"}}}}
		case "tools/call":
			result = map[string]any{"content": []any{map[string]any{"type": "text", "text": "1 row"}}, "structuredContent": map[string]any{"rows": []any{map[string]any{"id": 101}}, "params": json.RawMessage(m.Params)}}
		default:
			continue
		}
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": result})
		os.Stdout.Write(append(b, '\n'))
	}
}
`
	if err := os.WriteFile(filepath.Join(fakeDir, "main.go"), []byte(fakeSource), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeDir, "go.mod"), []byte("module fake\n\ngo 1.26\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(dir, "fake-runtime"+exe)
	build = exec.Command(goTool, "build", "-buildvcs=false", "-o", fake, ".")
	build.Dir = fakeDir
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the stand-in runtime: %v\n%s", err, out)
	}
	credentials := filepath.Join(dir, "warehouse.json")
	if err := os.WriteFile(credentials, []byte(`{"SERVICE_TOKEN":"secret-token"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	escape := func(p string) string { return strings.ReplaceAll(p, `\`, `\\`) }
	text := `{"engineVersion":"1","authority":"gateway:test","seed":"` + escape(filepath.Join(dir, "gateway.seed")) + `","store":"` + escape(filepath.Join(dir, "store")) + `",` +
		`"registry":"` + escape(filepath.Join(dir, "registry.jsonl")) + `","decisionRecords":"` + escape(filepath.Join(dir, "decisions")) + `",` +
		`"listen":"127.0.0.1:0","catalog":"` + escape(catalog) + `","runtime":"` + escape(fake) + `","adapters":"` + escape(bin) + `",` +
		`"platforms":{"warehouse":{"binding":"postgres@` + digestOf(postgresBinding) + `","credentials":{"history":{"file":"` + escape(credentials) + `"},"live":{"file":"` + escape(credentials) + `"},"write":{"file":"` + escape(credentials) + `"}},"user":"engine-warehouse","endpoint":"warehouse.internal:5432","write":true}}}`
	path := filepath.Join(dir, "engine.json")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, bindings, err := loadEngineConfig(path, stubAccounts(map[string]int{"engine-warehouse": 1001}))
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
	// An identity, so that an action has a requester; every request below
	// carries its token.
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	service.identity = &id
	token := issuer.mint(t, "ec-1", nil, goodClaims(time.Now()))
	post := func(t *testing.T, server *httptest.Server, path, body string) (int, map[string]any) {
		t.Helper()
		return authed(t, server, path, body, token)
	}
	server := httptest.NewServer(service.handler())
	defer server.Close()
	code, first := post(t, server, "/acquire", `{"session":"cfg-1","source":"warehouse/live","arguments":{"tool":"query","arguments":{"sql":"select 1"}}}`)
	if code != http.StatusOK {
		t.Fatalf("acquire failed: %d %v", code, first)
	}
	receipt := first["receipt"].(map[string]any)
	acquisition := receipt["acquisition"].(map[string]any)
	adapter := acquisition["adapter"].(map[string]any)
	if receipt["source"] != "warehouse/live" || acquisition["shape"] != "mcp" || adapter["name"] != "ghcr.io/example/mcp-postgres" || adapter["version"] != "2.1" || adapter["digest"] != testImageDigest || acquisition["endpoint"] != "warehouse.internal:5432" {
		t.Fatalf("the receipt names the derived source, the binding's pinned image and the platform's endpoint: %v", receipt)
	}
	result, _ := first["result"].(map[string]any)
	structured, _ := result["structuredContent"].(map[string]any)
	rows, _ := structured["rows"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["id"] != float64(101) {
		t.Fatalf("the tool's result came back through the derived source: %v", first["result"])
	}
	if code, body := post(t, server, "/acquire", `{"session":"cfg-1","source":"warehouse/history","arguments":{"stream":"decisions"}}`); code == http.StatusOK {
		t.Fatalf("the history source runs adapter-airbyte, which is not built here, so it must fail: %v", body)
	}
	// The join, end to end (docs/design/executor.md): a decision record
	// that cites the acquisition, written where the engine looks for one;
	// an action that cites both; the executor is adapter-mcp on the write
	// binding, calling the write tool; and the store, the registry and the
	// records verify together with every receipt ok.
	signature := receipt["signature"].(string)
	line := `{"recordVersion":"1","kind":"evaluation","cites":[{"sessionId":"cfg-1","callIndex":0,"signature":"` + signature + `"}]}`
	if err := os.MkdirAll(cfg.decisionRecords, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.decisionRecords, "evaluations.jsonl"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	act := `{"session":"cfg-1","platform":"warehouse","tool":"execute","arguments":{"sql":"update t set s = 1"},` +
		`"decision":{"recordDigest":"sha256:` + hexOf([]byte(line)) + `","packDigest":"sha256:` + strings.Repeat("b", 64) + `"},` +
		`"cites":[{"sessionId":"cfg-1","callIndex":0,"signature":"` + signature + `"}]}`
	code, acted := post(t, server, "/act", act)
	if code != http.StatusOK {
		t.Fatalf("act failed: %d %v", code, acted)
	}
	action := acted["receipt"].(map[string]any)
	inner := action["action"].(map[string]any)
	tool := inner["tool"].(map[string]any)
	requester := inner["requester"].(map[string]any)
	cited := inner["cites"].([]any)[0].(map[string]any)
	if action["kind"] != "action" || action["source"] != "warehouse/write" || action["callIndex"] != float64(1) || action["prevSignature"] != signature ||
		tool["shape"] != "mcp" || tool["name"] != "execute" || tool["endpoint"] != "warehouse.internal:5432" ||
		requester["subject"] != "user-7" || cited["signature"] != signature || cited["callIndex"] != float64(0) ||
		inner["decision"].(map[string]any)["recordDigest"] != "sha256:"+hexOf([]byte(line)) ||
		inner["adapter"].(map[string]any)["digest"] != testImageDigest || !strings.HasPrefix(fmt.Sprint(inner["request"]), "sha256:") {
		t.Fatalf("the action receipt names the executor, the tool, the requester, the decision and the citation: %v", action)
	}
	// The target received exactly the arguments the requester sent -- the
	// stand-in echoes its call's params -- and both commitments recompute
	// from the returned salts over those same bytes: what was committed to
	// is what was sent.
	echoed := acted["result"].(map[string]any)["structuredContent"].(map[string]any)["params"].(map[string]any)
	if echoed["name"] != "execute" || echoed["arguments"].(map[string]any)["sql"] != "update t set s = 1" {
		t.Fatalf("the target got the tool and the arguments as sent: %v", echoed)
	}
	salts := acted["salts"].(map[string]any)
	argsSalt, err := hex.DecodeString(fmt.Sprint(salts["args"]))
	if err != nil {
		t.Fatal(err)
	}
	requestSalt, err := hex.DecodeString(fmt.Sprint(salts["request"]))
	if err != nil {
		t.Fatal(err)
	}
	argumentsV, _ := parseJSON([]byte(`{"sql":"update t set s = 1"}`))
	requestV, _ := parseJSON([]byte(`{"tool":"execute","arguments":{"sql":"update t set s = 1"}}`))
	if action["argumentsCommitment"] != commitmentOver(argsSalt, "args:", canon(argumentsV)) || inner["request"] != commitmentOver(requestSalt, "request:", canon(requestV)) {
		t.Fatalf("the commitments recompute from the salts over the bytes sent: %v %v", action["argumentsCommitment"], inner["request"])
	}
	if code, body := post(t, server, "/seal", `{"session":"cfg-1"}`); code != http.StatusOK {
		t.Fatalf("seal failed: %d %v", code, body)
	}
	// /verify on the engine reads the configured decision-record directory,
	// as the command does when handed it: every receipt ok, the action's
	// citation and record resolved.
	code, verified := post(t, server, "/verify", ``)
	if code != http.StatusOK || verified["ok"] != true {
		t.Fatalf("/verify with the records: %d %v", code, verified)
	}
	for _, f := range verified["findings"].([]any) {
		if f.(map[string]any)["status"] != "ok" {
			t.Fatalf("every receipt ok over /verify: %v", verified["findings"])
		}
	}
	report, err := verifyWithRegistryAndRecords(service.storeRoot, service.regPath, "gateway:test", cfg.decisionRecords, service.publicKey)
	if err != nil || !report.OK {
		t.Fatalf("the store, the registry and the records must verify together: %v %v", err, report)
	}
}
