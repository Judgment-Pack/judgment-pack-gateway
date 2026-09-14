package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// The whole chain for the HTTP shape, across the process boundary and never
// the import one: this gateway spawns the real adapter-http binary as a
// source declared http, the adapter sends one request over TLS to a stand-in
// provider served here with the credential it read from its file, the
// envelope comes back over the source contract, and the store verifies with
// a version 3 receipt whose acquisition is what the adapter reported: the
// URL it sent to, the provider's ETag as the snapshot, and the provider's
// certificate as the peer identity.
func TestGatewaySpawnsTheHTTPAdapterEndToEnd(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain on PATH")
	}
	dir := t.TempDir()
	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	adapter := filepath.Join(dir, "adapter-http"+exe)
	build := exec.Command(goTool, "build", "-buildvcs=false", "-o", adapter, "./cmd/adapter-http")
	build.Dir = filepath.Join("..", "adapters")
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the adapter: %v\n%s", err, out)
	}
	// The stand-in provider: a JSON answer only when the credential
	// reached it under the header the configuration names.
	var providerRequests atomic.Int64
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerRequests.Add(1)
		body, _ := io.ReadAll(r.Body)
		// Any path with the credential is answered, so a path the adapter
		// should have refused would succeed if it were ever sent.
		if r.Header.Get("Authorization") != "Bearer secret-token" || string(body) != `{"url":"https://example.org/policy"}` {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, "the request or its credential was not as configured")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"policy-v3"`)
		io.WriteString(w, `{"data":{"title":"Policy","content":"A claim of $50 or less is approved.","score":0.5}}`)
	}))
	defer provider.Close()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	credentials := filepath.Join(dir, "provider.json")
	if err := os.WriteFile(credentials, []byte(`{"PROVIDER_KEY":"secret-token"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{
		filepath.Join(dir, "store"), "seed-is-loaded-separately", "gateway:test", filepath.Join(dir, "registry.jsonl"),
		"--source", "read=" + adapter + " --endpoint " + provider.URL + " --paths /read --credentials " + credentials + " --bearer PROVIDER_KEY --ca-file " + ca,
		"--source-shape", "read=http",
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
	code, first := post(t, httpServer, "/acquire", `{"session":"http-1","source":"read","arguments":{"path":"/read","body":{"url":"https://example.org/policy"}}}`)
	if code != http.StatusOK {
		t.Fatalf("acquire failed: %d %v", code, first)
	}
	receipt := first["receipt"].(map[string]any)
	acquisition := receipt["acquisition"].(map[string]any)
	adapterOut := acquisition["adapter"].(map[string]any)
	binary, _ := os.ReadFile(adapter)
	sum := sha256.Sum256(binary)
	if acquisition["shape"] != "http" || adapterOut["name"] != "adapter-http" || adapterOut["digest"] != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("the receipt names the adapter by its own digest under the declared shape: %v", acquisition)
	}
	peer := sha256.Sum256(provider.Certificate().Raw)
	if acquisition["endpoint"] != provider.URL+"/read" || acquisition["snapshot"] != `"policy-v3"` || acquisition["peerIdentity"] != "tls:sha256:"+hex.EncodeToString(peer[:]) {
		t.Fatalf("the URL sent to, the ETag as the snapshot, the peer's certificate as its identity: %v", acquisition)
	}
	if acquisition["schema"] != nil || acquisition["upstreamToken"] != nil {
		t.Fatalf("no schema and no upstream token: %v", acquisition)
	}
	if _, present := acquisition["pageItems"]; present {
		t.Fatal("one request is one result, not a page")
	}
	if _, present := first["salts"].(map[string]any)["statement"]; !present {
		t.Fatal("the statement's salt comes back")
	}
	if encoded, _ := json.Marshal(first); strings.Contains(string(encoded), "secret-token") {
		t.Fatal("nothing of the credentials reaches the response")
	}
	result := first["result"].(map[string]any)
	headers := result["headers"].(map[string]any)
	if result["status"] != float64(200) || result["bodyEncoding"] != "json" || headers["content-type"] != "application/json" || headers["etag"] != `"policy-v3"` || headers["content-length"] != "87" {
		t.Fatalf("the status, the encoding and the carried headers: %v", result)
	}
	if !reflect.DeepEqual(result["body"], map[string]any{"data": map[string]any{"title": "Policy", "content": "A claim of $50 or less is approved.", "score": "0.5"}}) {
		t.Fatalf("the answer, carried into the canon domain: %v", result["body"])
	}
	// A request the configuration does not admit is refused by the adapter
	// before any connection: the provider, which would have answered it,
	// sees no second request, and the gateway mints nothing.
	if code, body := post(t, httpServer, "/acquire", `{"session":"http-1","source":"read","arguments":{"path":"/write","body":{"url":"https://example.org/policy"}}}`); code == http.StatusOK {
		t.Fatalf("a path outside --paths minted a receipt: %v", body)
	}
	if got := providerRequests.Load(); got != 1 {
		t.Fatalf("the provider saw %d requests; the refused path reached it", got)
	}
	receipts, _ := os.ReadDir(filepath.Join(dir, "store", "receipts", "http-1"))
	if len(receipts) != 1 {
		t.Fatalf("%d receipts after a refused acquisition, want 1", len(receipts))
	}
	if code, body := post(t, httpServer, "/seal", `{"session":"http-1"}`); code != http.StatusOK {
		t.Fatalf("seal failed: %d %v", code, body)
	}
	report, err := verifyWithRegistry(service.storeRoot, service.regPath, "gateway:test", service.publicKey)
	if err != nil || !report.OK {
		t.Fatalf("the store must verify: %v %v", err, report)
	}
}
