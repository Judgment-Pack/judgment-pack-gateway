package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// The whole chain for the MCP shape, across the process boundary and never
// the import one: this gateway spawns the real adapter-mcp binary as a
// source declared mcp, the adapter starts a stand-in server built here from
// a few lines of Go and speaks JSON-RPC to it over stdio, the envelope comes
// back over the source contract, and the store verifies with a version 3
// receipt whose acquisition is what the adapter reported.
func TestGatewaySpawnsTheMCPAdapterEndToEnd(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain on PATH")
	}
	dir := t.TempDir()
	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	adapter := filepath.Join(dir, "adapter-mcp"+exe)
	build := exec.Command(goTool, "build", "-buildvcs=false", "-o", adapter, "./cmd/adapter-mcp")
	build.Dir = filepath.Join("..", "adapters")
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the adapter: %v\n%s", err, out)
	}
	// The stand-in server: JSON-RPC over stdio, one tool, and an answer
	// only when its credential reached its environment.
	serverDir := filepath.Join(dir, "server")
	if err := os.MkdirAll(serverDir, 0o700); err != nil {
		t.Fatal(err)
	}
	serverSource := `package main

import (
	"bufio"
	"encoding/json"
	"os"
)

func main() {
	if os.Getenv("SERVICE_TOKEN") != "secret-token" || len(os.Args) != 3 || os.Args[1] != "--mode" || os.Args[2] != "readonly" {
		os.Stderr.WriteString("no token, or not started with --mode readonly\n")
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
			result = map[string]any{"tools": []any{map[string]any{"name": "lookup", "inputSchema": map[string]any{"type": "object"}}}}
		case "tools/call":
			result = map[string]any{"content": []any{map[string]any{"type": "text", "text": "found"}}, "structuredContent": map[string]any{"status": "open", "score": 0.5}}
		default:
			continue
		}
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": result})
		os.Stdout.Write(append(b, '\n'))
	}
}
`
	if err := os.WriteFile(filepath.Join(serverDir, "main.go"), []byte(serverSource), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(serverDir, "go.mod"), []byte("module standin\n\ngo 1.26\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := filepath.Join(dir, "standin-server"+exe)
	build = exec.Command(goTool, "build", "-buildvcs=false", "-o", server, ".")
	build.Dir = serverDir
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the stand-in server: %v\n%s", err, out)
	}
	credentials := filepath.Join(dir, "service.json")
	if err := os.WriteFile(credentials, []byte(`{"SERVICE_TOKEN":"secret-token"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{
		filepath.Join(dir, "store"), "seed-is-loaded-separately", "gateway:test", filepath.Join(dir, "registry.jsonl"),
		"--source", "live=" + adapter + " --credentials " + credentials + " --endpoint api.example --tools lookup -- " + server + " --mode readonly",
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
	code, first := post(t, httpServer, "/acquire", `{"session":"mcp-1","source":"live","arguments":{"tool":"lookup","arguments":{"id":7}}}`)
	if code != http.StatusOK {
		t.Fatalf("acquire failed: %d %v", code, first)
	}
	receipt := first["receipt"].(map[string]any)
	acquisition := receipt["acquisition"].(map[string]any)
	adapterOut := acquisition["adapter"].(map[string]any)
	image, _ := os.ReadFile(server)
	sum := sha256.Sum256(image)
	if acquisition["shape"] != "mcp" || adapterOut["name"] != server || adapterOut["version"] != "0.1" || adapterOut["digest"] != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("the receipt names the server command, its version and its digest under the declared shape: %v", acquisition)
	}
	if acquisition["endpoint"] != "api.example" || acquisition["snapshot"] != nil || acquisition["schema"] != nil || acquisition["peerIdentity"] != nil {
		t.Fatalf("endpoint as named; no snapshot, no schema (the tool declares no output schema), no peer identity: %v", acquisition)
	}
	if _, present := acquisition["pageItems"]; present {
		t.Fatal("a tool call is one result, not a page")
	}
	if _, present := first["salts"].(map[string]any)["statement"]; !present {
		t.Fatal("the statement's salt comes back")
	}
	if encoded, _ := json.Marshal(first); strings.Contains(string(encoded), "secret-token") {
		t.Fatal("nothing of the credentials reaches the response")
	}
	if !reflect.DeepEqual(first["result"], map[string]any{
		"content":           []any{map[string]any{"text": "found", "type": "text"}},
		"structuredContent": map[string]any{"score": "0.5", "status": "open"},
	}) {
		t.Fatalf("the tool's whole result, carried into the canon domain: %v", first["result"])
	}
	if code, body := post(t, httpServer, "/seal", `{"session":"mcp-1"}`); code != http.StatusOK {
		t.Fatalf("seal failed: %d %v", code, body)
	}
	report, err := verifyWithRegistry(service.storeRoot, service.regPath, "gateway:test", service.publicKey)
	if err != nil || !report.OK {
		t.Fatalf("the store must verify: %v %v", err, report)
	}
}
