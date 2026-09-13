package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The whole chain, across the process boundary and never the import one:
// this gateway spawns the real adapter-airbyte binary as a source declared
// airbyte, the adapter runs a stand-in for the container runtime built here
// from a few lines of Go, the envelope comes back over the source contract,
// and the store verifies with a version 3 receipt whose acquisition is what
// the adapter reported. Both binaries are built from this checkout with the
// same toolchain running the test.
func TestGatewaySpawnsTheAirbyteAdapterEndToEnd(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain on PATH")
	}
	dir := t.TempDir()
	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	adapter := filepath.Join(dir, "adapter-airbyte"+exe)
	build := exec.Command(goTool, "build", "-buildvcs=false", "-o", adapter, "./cmd/adapter-airbyte")
	build.Dir = filepath.Join("..", "adapters")
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the adapter: %v\n%s", err, out)
	}
	// The stand-in runtime: answers `run ... discover` and `run ... read`
	// with fixed connector output and `kill` with nothing.
	fakeDir := filepath.Join(dir, "fake")
	if err := os.MkdirAll(fakeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	fakeSource := `package main

import (
	"os"
	"strings"
)

const discover = "{\"type\":\"CATALOG\",\"catalog\":{\"streams\":[{\"name\":\"decisions\",\"json_schema\":{\"type\":\"object\"},\"supported_sync_modes\":[\"full_refresh\",\"incremental\"],\"default_cursor_field\":[\"updated_at\"]}]}}\n"
const read = "{\"type\":\"RECORD\",\"record\":{\"stream\":\"decisions\",\"emitted_at\":1,\"data\":{\"id\":101,\"amount\":12.5,\"status\":\"approved\"}}}\n" +
	"{\"type\":\"RECORD\",\"record\":{\"stream\":\"decisions\",\"emitted_at\":2,\"data\":{\"id\":102,\"amount\":7,\"status\":\"denied\"}}}\n" +
	"{\"type\":\"STATE\",\"state\":{\"type\":\"STREAM\",\"stream\":{\"stream_descriptor\":{\"name\":\"decisions\"},\"stream_state\":{\"updated_at\":\"2026-09-12T10:00:02Z\"}}}}\n"

func main() {
	args := strings.Join(os.Args[1:], " ")
	switch {
	case strings.Contains(args, " discover "):
		os.Stdout.WriteString(discover)
	case strings.Contains(args, " read "):
		os.Stdout.WriteString(read)
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
	if err := os.WriteFile(credentials, []byte(`{"host":"warehouse.internal","password":"hunter2"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	args := []string{
		filepath.Join(dir, "store"), "seed-is-loaded-separately", "gateway:test", filepath.Join(dir, "registry.jsonl"),
		"--source", "history=" + adapter + " --image airbyte/source-postgres:3.6.1@" + digest +
			" --credentials " + credentials + " --runtime " + fake + " --endpoint warehouse.internal:5432",
		"--source-shape", "history=airbyte",
	}
	opts, msg, ok := parseServeOptions(args)
	if !ok {
		t.Fatal(msg)
	}
	service, err := buildService(args[0], testSeed, args[2], args[3], opts)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(service.handler())
	defer server.Close()
	code, first := post(t, server, "/acquire", `{"session":"e2e-1","source":"history","arguments":{"stream":"decisions","limit":10}}`)
	if code != http.StatusOK {
		t.Fatalf("acquire failed: %d %v", code, first)
	}
	receipt := first["receipt"].(map[string]any)
	acquisition := receipt["acquisition"].(map[string]any)
	adapterOut := acquisition["adapter"].(map[string]any)
	if acquisition["shape"] != "airbyte" || adapterOut["name"] != "airbyte/source-postgres" || adapterOut["version"] != "3.6.1" || adapterOut["digest"] != digest {
		t.Fatalf("the receipt names the pinned image under the declared shape: %v", acquisition)
	}
	if acquisition["endpoint"] != "warehouse.internal:5432" || acquisition["snapshot"] == nil || acquisition["schema"] == nil || acquisition["peerIdentity"] != nil {
		t.Fatalf("endpoint, snapshot and schema as the adapter reported; peer identity null: %v", acquisition)
	}
	if items, _ := acquisition["pageItems"].([]any); len(items) != 2 {
		t.Fatalf("two page items: %v", acquisition["pageItems"])
	}
	if _, present := first["salts"].(map[string]any)["statement"]; !present {
		t.Fatal("the statement's salt comes back")
	}
	if encoded, _ := json.Marshal(receipt); strings.Contains(string(encoded), "hunter2") || strings.Contains(string(encoded), "SELECT") {
		t.Fatal("nothing of the credentials reaches the receipt")
	}
	result, _ := first["result"].([]any)
	if len(result) != 2 || result[0].(map[string]any)["amount"] != "12.5" || result[1].(map[string]any)["amount"] != float64(7) {
		t.Fatalf("the records, carried into the canon domain: %v", first["result"])
	}
	if code, body := post(t, server, "/seal", `{"session":"e2e-1"}`); code != http.StatusOK {
		t.Fatalf("seal failed: %d %v", code, body)
	}
	report, err := verifyWithRegistry(service.storeRoot, service.regPath, "gateway:test", service.publicKey)
	if err != nil || !report.OK {
		t.Fatalf("the store must verify: %v %v", err, report)
	}
}
