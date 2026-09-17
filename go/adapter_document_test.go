package main

import (
	"encoding/base64"
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

// The whole chain for a document, across the process boundary and never
// the import one: this gateway spawns the real adapter-document binary as
// a bare source, hands it a PDF fixture inline in the arguments, the
// record comes back as the result, the receipt carries the command shape
// with the adapter named by the command's first word and the digest of the
// file the gateway read before starting it, a request the adapter refuses
// reaches the caller as the adapter's refusal line, and the store verifies.
func TestGatewaySpawnsTheDocumentAdapterEndToEnd(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain on PATH")
	}
	dir := t.TempDir()
	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	adapter := filepath.Join(dir, "adapter-document"+exe)
	build := exec.Command(goTool, "build", "-buildvcs=false", "-o", adapter, "./cmd/adapter-document")
	build.Dir = filepath.Join("..", "adapters")
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the adapter: %v\n%s", err, out)
	}
	fixture, err := os.ReadFile(filepath.Join("..", "adapters", "document", "testdata", "normal.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	args := []string{
		filepath.Join(dir, "store"), "seed-is-loaded-separately", "gateway:test", filepath.Join(dir, "registry.jsonl"),
		"--source", "documents=" + adapter + " --max-output 4194304 --max-bytes 65536",
		"--source-max-output", "4194304",
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
	request := map[string]any{
		"session": "doc-1", "source": "documents",
		"arguments": map[string]any{"document": map[string]any{"name": "normal.pdf", "mediaType": "application/pdf", "bytes": base64.StdEncoding.EncodeToString(fixture)}},
	}
	body, _ := json.Marshal(request)
	code, first := post(t, httpServer, "/acquire", string(body))
	if code != http.StatusOK {
		t.Fatalf("acquire failed: %d %v", code, first)
	}
	result := first["result"].(map[string]any)
	if result["attachmentVersion"] != "1" {
		t.Fatalf("result is not a version 1 record: %v", result)
	}
	processing := result["processing"].(map[string]any)
	if processing["status"] != "complete" {
		t.Fatalf("processing: %v", processing)
	}
	pages := result["content"].(map[string]any)["pages"].([]any)
	if len(pages) != 3 || !strings.HasPrefix(pages[0].(map[string]any)["text"].(string), "Federal Skilled Worker Program") {
		t.Fatalf("pages: %v", pages)
	}
	receipt := first["receipt"].(map[string]any)
	acq := receipt["acquisition"].(map[string]any)
	if acq["shape"] != "command" || acq["endpoint"] != nil || acq["statement"] != nil || acq["upstreamToken"] != nil {
		t.Fatalf("acquisition: %v", acq)
	}
	adapterIdentity := acq["adapter"].(map[string]any)
	recordIdentity := result["provenance"].(map[string]any)["adapter"].(map[string]any)
	if adapterIdentity["name"] != adapter || adapterIdentity["version"] != "" || adapterIdentity["digest"] != recordIdentity["digest"] {
		t.Fatalf("the receipt names the command as configured and the digest the record also reports: receipt %v record %v", adapterIdentity, recordIdentity)
	}
	if _, ok := first["salts"].(map[string]any)["args"]; !ok {
		t.Fatal("no args salt returned")
	}
	// A request the adapter refuses is a failed acquisition with nothing
	// minted: a document within the gateway's request bound and past the
	// adapter's read bound, answered with the adapter's refusal line.
	big := map[string]any{
		"session": "doc-1", "source": "documents",
		"arguments": map[string]any{"document": map[string]any{"name": "big.txt", "mediaType": "text/plain", "bytes": base64.StdEncoding.EncodeToString(make([]byte, 200<<10))}},
	}
	body, _ = json.Marshal(big)
	code, refused := post(t, httpServer, "/acquire", string(body))
	if code != http.StatusBadRequest {
		t.Fatalf("a document past the adapter's read bound: %d %v", code, refused)
	}
	if message, _ := refused["error"].(string); !strings.HasPrefix(message, "source failed: request-over-bound: ") {
		t.Fatalf("the refusal the caller receives: %q", message)
	}
	// Seal and verify the store: the record is an artifact like any other.
	if code, _ := post(t, httpServer, "/seal", `{"session":"doc-1"}`); code != http.StatusOK {
		t.Fatalf("seal: %d", code)
	}
	report, err := verifyWithRegistry(service.storeRoot, service.regPath, "gateway:test", service.publicKey)
	if err != nil || !report.OK {
		t.Fatalf("the store does not verify: %v %+v", err, report)
	}
	receipts, _ := os.ReadDir(filepath.Join(dir, "store", "receipts", "doc-1"))
	if len(receipts) != 1 {
		t.Fatalf("%d receipts after a refused acquisition, want 1", len(receipts))
	}
}
