package main

import (
	"context"
	"errors"
	"fmt"
	"io"
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

// The report beside an expired reference's status is read strictly:
// exactly the one member, of exactly the class 410, and nothing around it.
func TestReferenceExpiredReportIsReadStrictly(t *testing.T) {
	for _, c := range []struct {
		report string
		taken  bool
	}{
		{`{"referenceExpired":{"status":410}}`, true},
		{`{ "referenceExpired": { "status": 410 } }`, true},
		{`{"referenceExpired":{"status":404}}`, false},
		{`{"referenceExpired":{"status":"410"}}`, false},
		{`{"referenceExpired":{"status":-410}}`, false},
		{`{"referenceExpired":{"status":410.0}}`, false},
		{`{"referenceExpired":{}}`, false},
		{`{"referenceExpired":{"status":410,"body":"x"}}`, false},
		{`{"referenceExpired":{"status":410},"error":"x"}`, false},
		{`{"referenceExpired":{"status":410,"status":410}}`, false},
		{`{"referenceExpired":{"status":410}}{}`, false},
		{`{"referenceExpired":{"status":410}}` + "\n", false},
		{" " + `{"referenceExpired":{"status":410}}`, false},
		{`{"referenceExpired":410}`, false},
		{`{"throttled":{"retryAfter":30,"status":429}}`, false},
		{`{}`, false},
		{``, false},
	} {
		if got := referenceExpiredReport([]byte(c.report)); got != c.taken {
			t.Errorf("%q: taken %v", c.report, got)
		}
	}
	// adapter-conform classes the answer as the adapter's own refusal.
	if class := sourceRefusalClass((&sourceReferenceExpired{}).Error()); class != refusalSourceFailed {
		t.Errorf("an expired reference is classed %s", class)
	}
}

// /acquire answers an http adapter's expired-reference report 410 with the
// code and the gateway's own sentence, mints and keeps nothing, and leaves
// the session open to the caller's next read. A report out of its form, the
// report beside another status, and the status from a source of another
// shape are a failed source, answered 400 with what it wrote on stderr, as
// before.
func TestAnExpiredReferenceIsAnsweredWithItsCode(t *testing.T) {
	const expired = `{"code":"source_reference_expired","error":"source failed: the source's endpoint answered 410 Gone: the reference the request sent has expired; nothing was retained or minted"}`
	const failed = `{"error":"source failed: adapter-http: the endpoint answered 429 Too Many Requests: slow down, key k-7f2c"}`
	for _, c := range []struct {
		name, shape, out string
		exit, code       int
		body             string
	}{
		{"the report", "http", `{"referenceExpired":{"status":410}}`, 8, 410, expired},
		{"another class", "http", `{"referenceExpired":{"status":404}}`, 8, 400, failed},
		{"no report", "http", ``, 8, 400, failed},
		{"another status", "http", `{"referenceExpired":{"status":410}}`, 1, 400, failed},
		{"the throttled status", "http", `{"referenceExpired":{"status":410}}`, 7, 400, failed},
		{"another shape", "mcp", `{"referenceExpired":{"status":410}}`, 8, 400, failed},
		{"a bare command", "", `{"referenceExpired":{"status":410}}`, 8, 400, failed},
	} {
		t.Run(c.name, func(t *testing.T) {
			service, server := testService(t)
			service.sources["expired"] = sourceSpec{argv: []string{os.Args[0], "-test.run=^TestThrottleStandIn$"}, shape: c.shape,
				env: []string{"THROTTLE_STAND_IN=1", "THROTTLE_STAND_IN_OUT=" + c.out, fmt.Sprintf("THROTTLE_STAND_IN_EXIT=%d", c.exit)}}
			got := postRaw(t, server.URL, "/acquire", `{"session":"changes-1","source":"expired","arguments":{"path":"/r"}}`)
			if got.code != c.code || got.header.Get("Retry-After") != "" || got.header.Get("Content-Type") != "application/json" || got.body != c.body {
				t.Fatalf("%d Retry-After %q %s: %s", got.code, got.header.Values("Retry-After"), got.header.Get("Content-Type"), got.body)
			}
			requireNothingKept(t, service, "changes-1")
			// The session was not taken: the caller reads again from its
			// first value in it, minted as the session's first receipt.
			service.sources["expired"] = sourceSpec{argv: []string{os.Args[0]}, env: helperEnv}
			if code, body := post(t, server, "/acquire", `{"session":"changes-1","source":"expired","arguments":{}}`); code != http.StatusOK || body["receipt"].(map[string]any)["callIndex"] != float64(0) {
				t.Fatalf("the read again: %d %v", code, body)
			}
		})
	}
}

// Under a token step, the source's 410 is the acquisition's answer and the
// sealed token is kept, since the source did not refuse it; the report
// beside a token request's status is not read, and that run is a failed
// source as any other.
func TestATokenStepSourceExpiredReferenceKeepsTheToken(t *testing.T) {
	service, _ := testService(t)
	dir := t.TempDir()
	spec := standInSpec(dir, `{"sealed":"c2VhbGVk","expiresIn":600}`, 0, "expired")
	for i := 1; i <= 2; i++ {
		_, _, _, err := service.runAcquisitionSource("expired/live", spec, tokenStandInRequest)
		var expired *sourceReferenceExpired
		if !errors.As(err, &expired) || strings.Contains(err.Error(), "stand-in-stderr") {
			t.Fatalf("an expired reference: %v", err)
		}
	}
	if runs, handed := standInLines(dir, "token-runs"), standInLines(dir, "acquisitions"); len(runs) != 1 || len(handed) != 2 {
		t.Fatalf("the sealed token is kept: %d token requests for %d acquisitions", len(runs), len(handed))
	}
	spec = standInSpec(t.TempDir(), `{"referenceExpired":{"status":410}}`, sourceExitReferenceExpired, "ok")
	if _, _, err := service.obtainToken(context.Background(), time.Minute, "records/live", spec); err == nil || err.Error() != "source failed: stand-in-stderr-4e1a" {
		t.Fatalf("the report beside a token request: %v", err)
	}
}

// The whole chain with the real adapter-http: a stand-in provider answers
// 410, and /acquire answers 410 with the code and nothing of the provider's
// body; a 404 and a 400 are answered as before, byte for byte; nothing is
// minted for any of them.
func TestAnExpiredReferenceHTTPSourceEndToEnd(t *testing.T) {
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
	var status int
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		io.WriteString(w, "cursor c-17 for scope tenant-4 is gone")
	}))
	defer provider.Close()
	args := []string{
		filepath.Join(t.TempDir(), "store"), "seed-is-loaded-separately", "gateway:test", filepath.Join(t.TempDir(), "registry.jsonl"),
		"--source", "read=" + adapter + " --endpoint " + provider.URL + " --paths /read --timeout 5s",
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
	server := httptest.NewServer(service.handler())
	defer server.Close()
	const request = `{"session":"changes-1","source":"read","arguments":{"path":"/read","body":{"cursor":"c-17"}}}`
	status = http.StatusGone
	got := postRaw(t, server.URL, "/acquire", request)
	const want = `{"code":"source_reference_expired","error":"source failed: the source's endpoint answered 410 Gone: the reference the request sent has expired; nothing was retained or minted"}`
	if got.code != http.StatusGone || got.body != want || got.header.Get("Content-Type") != "application/json" || got.header.Get("Retry-After") != "" {
		t.Fatalf("a 410: %d %s", got.code, got.body)
	}
	requireNothingKept(t, service, "changes-1")
	for _, c := range []struct {
		status int
		want   string
	}{
		{404, `{"error":"source failed: adapter-http: the endpoint answered 404 Not Found: cursor c-17 for scope tenant-4 is gone"}`},
		{400, `{"error":"source failed: adapter-http: the endpoint answered 400 Bad Request: cursor c-17 for scope tenant-4 is gone"}`},
	} {
		status = c.status
		got := postRaw(t, server.URL, "/acquire", request)
		if got.code != http.StatusBadRequest || got.body != c.want {
			t.Fatalf("a %d: %d %s", c.status, got.code, got.body)
		}
		requireNothingKept(t, service, "changes-1")
	}
}
