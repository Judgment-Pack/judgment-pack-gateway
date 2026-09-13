package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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
		}
		if json.Unmarshal(in.Bytes(), &m) != nil || len(m.ID) == 0 {
			continue
		}
		var result any
		switch m.Method {
		case "initialize":
			result = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "standin", "version": "0.1"}}
		case "tools/list":
			result = map[string]any{"tools": []any{map[string]any{"name": "query", "inputSchema": map[string]any{"type": "object"}}}}
		case "tools/call":
			result = map[string]any{"content": []any{map[string]any{"type": "text", "text": "1 row"}}, "structuredContent": map[string]any{"rows": []any{map[string]any{"id": 101}}}}
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
		`"platforms":{"warehouse":{"binding":"postgres@` + digestOf(postgresBinding) + `","credentials":{"history":{"file":"` + escape(credentials) + `"},"live":{"file":"` + escape(credentials) + `"}},"user":"engine-warehouse","endpoint":"warehouse.internal:5432"}}}`
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
	service, err := buildService(cfg.store, testSeed, cfg.authority, cfg.registry, engineServeOptions(cfg, sources))
	if err != nil {
		t.Fatal(err)
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
	if code, body := post(t, server, "/seal", `{"session":"cfg-1"}`); code != http.StatusOK {
		t.Fatalf("seal failed: %d %v", code, body)
	}
	report, err := verifyWithRegistry(service.storeRoot, service.regPath, "gateway:test", service.publicKey)
	if err != nil || !report.OK {
		t.Fatalf("the store must verify: %v %v", err, report)
	}
}
