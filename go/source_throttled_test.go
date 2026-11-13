package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The report beside a throttled status is read strictly: exactly the one
// member, of exactly a class and a wait, the class 429 or 503 and the wait
// 0 to 3600 seconds or null. Anything else is no report.
func TestThrottleReportIsReadStrictly(t *testing.T) {
	for _, c := range []struct {
		report     string
		status     int
		retryAfter int // -1 for none; status 0 for no report
	}{
		{`{"throttled":{"retryAfter":30,"status":429}}`, 429, 30},
		{`{"throttled":{"status":503,"retryAfter":null}}`, 503, -1},
		{`{"throttled":{"retryAfter":0,"status":429}}`, 429, 0},
		{`{"throttled":{"retryAfter":3600,"status":503}}`, 503, 3600},
		{`{"throttled":{"retryAfter":3601,"status":429}}`, 0, 0},
		{`{"throttled":{"retryAfter":-1,"status":429}}`, 0, 0},
		{`{"throttled":{"retryAfter":"30","status":429}}`, 0, 0},
		{`{"throttled":{"retryAfter":1.5,"status":429}}`, 0, 0},
		{`{"throttled":{"retryAfter":30,"status":500}}`, 0, 0},
		{`{"throttled":{"retryAfter":30,"status":"429"}}`, 0, 0},
		{`{"throttled":{"status":429}}`, 0, 0},
		{`{"throttled":{"retryAfter":30}}`, 0, 0},
		{`{"throttled":{"retryAfter":30,"status":429,"body":"x"}}`, 0, 0},
		{`{"throttled":{"retryAfter":30,"status":429},"error":"x"}`, 0, 0},
		{`{"throttled":{"retryAfter":30,"status":429,"status":429}}`, 0, 0},
		{`{"throttled":{"retryAfter":30,"status":429}}{}`, 0, 0},
		{`{"throttled":[429,30]}`, 0, 0},
		{`{}`, 0, 0},
		{``, 0, 0},
	} {
		got, ok := throttleReport([]byte(c.report))
		switch {
		case c.status == 0 && ok:
			t.Errorf("%s: taken as a report: %+v", c.report, got)
		case c.status != 0 && (!ok || got.status != c.status || got.retryAfter != c.retryAfter):
			t.Errorf("%s: %+v %v", c.report, got, ok)
		}
	}
}

// TestThrottleStandIn is an adapter standing in for adapter-http when
// THROTTLE_STAND_IN is set, and nothing otherwise: it writes
// THROTTLE_STAND_IN_OUT on stdout and a line on stderr, and exits with
// THROTTLE_STAND_IN_EXIT.
func TestThrottleStandIn(t *testing.T) {
	if os.Getenv("THROTTLE_STAND_IN") == "" {
		return
	}
	io.ReadAll(os.Stdin)
	os.Stderr.WriteString("adapter-http: the endpoint answered 429 Too Many Requests: slow down, key k-7f2c\n")
	os.Stdout.WriteString(os.Getenv("THROTTLE_STAND_IN_OUT"))
	n, _ := strconv.Atoi(os.Getenv("THROTTLE_STAND_IN_EXIT"))
	os.Exit(n)
}

// rawAnswer is one POST's whole answer: status, headers and body bytes.
type rawAnswer struct {
	code   int
	header http.Header
	body   string
}

func postRaw(t *testing.T, url, path, body string) rawAnswer {
	t.Helper()
	resp, err := http.Post(url+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return rawAnswer{code: resp.StatusCode, header: resp.Header, body: string(raw)}
}

// Nothing of a failed acquisition is kept: no receipt, no artifact, no
// registry line, and no session held open for it.
func requireNothingKept(t *testing.T, service *gatewayService, session string) {
	t.Helper()
	if entries, err := os.ReadDir(filepath.Join(service.storeRoot, "receipts", session)); err == nil && len(entries) != 0 {
		t.Fatalf("a throttled acquisition left %d receipts", len(entries))
	}
	if entries, _ := os.ReadDir(filepath.Join(service.storeRoot, "artifacts")); len(entries) != 0 {
		t.Fatalf("a throttled acquisition left %d artifacts", len(entries))
	}
	if raw, _ := os.ReadFile(service.regPath); len(strings.TrimSpace(string(raw))) != 0 {
		t.Fatalf("a throttled acquisition wrote the registry: %q", raw)
	}
	service.mu.Lock()
	_, held := service.sessions[session]
	service.mu.Unlock()
	if held {
		t.Fatal("a throttled acquisition left its session held")
	}
}

// /acquire answers an http adapter's throttled report with its class, the
// gateway's own sentence and a Retry-After of the reported seconds, and
// mints and keeps nothing. A report out of its form, the report beside
// another status, and the status from a source of another shape -- what an
// adapter written before the report says -- are a failed source, answered
// 400 with what it wrote on stderr, as before.
func TestAThrottledSourceIsAnsweredWithItsClass(t *testing.T) {
	const say429 = `{"error":"source failed: the source's endpoint answered 429 Too Many Requests; nothing was retained or minted"}`
	const say503 = `{"error":"source failed: the source's endpoint answered 503 Service Unavailable; nothing was retained or minted"}`
	const failed = `{"error":"source failed: adapter-http: the endpoint answered 429 Too Many Requests: slow down, key k-7f2c"}`
	for _, c := range []struct {
		name, shape, out string
		exit             int
		code             int
		retryAfter, body string
	}{
		{"429 with a wait", "http", `{"throttled":{"retryAfter":30,"status":429}}`, 7, 429, "30", say429},
		{"429 with no wait", "http", `{"throttled":{"retryAfter":null,"status":429}}`, 7, 429, "", say429},
		{"503 with a wait", "http", `{"throttled":{"retryAfter":3600,"status":503}}`, 7, 503, "3600", say503},
		{"503 with no wait", "http", `{"throttled":{"retryAfter":null,"status":503}}`, 7, 503, "", say503},
		{"a wait of none", "http", `{"throttled":{"retryAfter":0,"status":429}}`, 7, 429, "0", say429},
		{"a wait past the bound", "http", `{"throttled":{"retryAfter":3601,"status":429}}`, 7, 400, "", failed},
		{"another class", "http", `{"throttled":{"retryAfter":30,"status":502}}`, 7, 400, "", failed},
		{"no report", "http", ``, 7, 400, "", failed},
		{"another status", "http", `{"throttled":{"retryAfter":30,"status":429}}`, 1, 400, "", failed},
		{"another shape", "mcp", `{"throttled":{"retryAfter":30,"status":429}}`, 7, 400, "", failed},
		{"a bare command", "", `{"throttled":{"retryAfter":30,"status":429}}`, 7, 400, "", failed},
	} {
		t.Run(c.name, func(t *testing.T) {
			service, server := testService(t)
			service.sources["throttled"] = sourceSpec{argv: []string{os.Args[0], "-test.run=^TestThrottleStandIn$"}, shape: c.shape,
				env: []string{"THROTTLE_STAND_IN=1", "THROTTLE_STAND_IN_OUT=" + c.out, fmt.Sprintf("THROTTLE_STAND_IN_EXIT=%d", c.exit)}}
			got := postRaw(t, server.URL, "/acquire", `{"session":"paged-1","source":"throttled","arguments":{"path":"/r"}}`)
			if got.code != c.code || got.header.Get("Retry-After") != c.retryAfter || len(got.header.Values("Retry-After")) > 1 ||
				got.header.Get("Content-Type") != "application/json" || got.body != c.body {
				t.Fatalf("%d Retry-After %q %s: %s", got.code, got.header.Values("Retry-After"), got.header.Get("Content-Type"), got.body)
			}
			requireNothingKept(t, service, "paged-1")
			// The session was not taken: it is open to the caller's retry,
			// which is minted as the session's first receipt.
			service.sources["throttled"] = sourceSpec{argv: []string{os.Args[0]}, env: helperEnv}
			if code, body := post(t, server, "/acquire", `{"session":"paged-1","source":"throttled","arguments":{}}`); code != http.StatusOK || body["receipt"].(map[string]any)["callIndex"] != float64(0) {
				t.Fatalf("the retry: %d %v", code, body)
			}
		})
	}
}

// A token step's throttled token request fails the acquisition with the
// class, sends nothing to the source, and leaves nothing in the token
// cache: the next acquisition asks again. A throttled request to the
// source keeps the sealed token, which the source did not refuse.
func TestATokenStepThrottledIsAnsweredWithItsClass(t *testing.T) {
	service, _ := testService(t)
	dir := t.TempDir()
	spec := standInSpec(dir, `{"throttled":{"retryAfter":12,"status":503}}`, sourceExitThrottled, "ok")
	for i := 1; i <= 2; i++ {
		_, _, _, err := service.runAcquisitionSource("records/live", spec, tokenStandInRequest)
		var throttled *sourceThrottled
		if !errors.As(err, &throttled) || throttled.status != 503 || throttled.retryAfter != 12 || strings.Contains(err.Error(), "stand-in-stderr") {
			t.Fatalf("a throttled token request: %v", err)
		}
		if runs, handed := standInLines(dir, "token-runs"), standInLines(dir, "acquisitions"); len(runs) != i || len(handed) != 0 {
			t.Fatalf("%d token requests and %d source requests after %d throttled token requests", len(runs), len(handed), i)
		}
	}
	// A report out of form beside the status is the token step's failure
	// said as any source's.
	spec = standInSpec(t.TempDir(), `{"throttled":{"retryAfter":12,"status":500}}`, sourceExitThrottled, "ok")
	if _, _, err := service.obtainToken(context.Background(), time.Minute, "records/live", spec); err == nil || err.Error() != "source failed: stand-in-stderr-4e1a" {
		t.Fatalf("a report out of form: %v", err)
	}

	dir = t.TempDir()
	spec = standInSpec(dir, `{"sealed":"c2VhbGVk","expiresIn":600}`, 0, "throttled")
	for i := 1; i <= 2; i++ {
		_, _, _, err := service.runAcquisitionSource("throttled/live", spec, tokenStandInRequest)
		var throttled *sourceThrottled
		if !errors.As(err, &throttled) || throttled.status != 429 || throttled.retryAfter != 45 {
			t.Fatalf("a throttled request to the source: %v", err)
		}
	}
	if runs, handed := standInLines(dir, "token-runs"), standInLines(dir, "acquisitions"); len(runs) != 1 || len(handed) != 2 {
		t.Fatalf("the sealed token is kept: %d token requests for %d acquisitions", len(runs), len(handed))
	}
}

// The whole chain with the real adapter-http: a stand-in provider answers
// 429 and 503 with every form of Retry-After, and /acquire answers the
// class, with a Retry-After only for a wait the adapter took; a 500, a 502,
// a 504 and an endpoint that cannot be reached are answered as before, byte
// for byte; nothing is minted for any of them.
func TestAThrottledHTTPSourceEndToEnd(t *testing.T) {
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
	var retryAfter []string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, v := range retryAfter {
			w.Header().Add("Retry-After", v)
		}
		w.WriteHeader(status)
		io.WriteString(w, "upstream says: slow down")
	}))
	defer provider.Close()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unreachable := "http://" + closed.Addr().String()
	closed.Close()
	serve := func(endpoint string) (*gatewayService, *httptest.Server) {
		args := []string{
			filepath.Join(t.TempDir(), "store"), "seed-is-loaded-separately", "gateway:test", filepath.Join(t.TempDir(), "registry.jsonl"),
			"--source", "read=" + adapter + " --endpoint " + endpoint + " --paths /read --timeout 5s",
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
		t.Cleanup(server.Close)
		return service, server
	}
	service, server := serve(provider.URL)
	const request = `{"session":"page-1","source":"read","arguments":{"path":"/read","body":{"page":2}}}`
	soon := time.Now().Add(90 * time.Second).UTC().Format(http.TimeFormat)
	past := time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)
	far := time.Now().Add(48 * time.Hour).UTC().Format(http.TimeFormat)
	for _, c := range []struct {
		name       string
		status     int
		header     []string
		retryAfter string // "~90" for a date about 90 seconds away
	}{
		{"429 with delta-seconds", 429, []string{"120"}, "120"},
		{"429 with none", 429, nil, ""},
		{"503 with an HTTP-date", 503, []string{soon}, "~90"},
		{"503 with none", 503, nil, ""},
		{"a malformed value", 429, []string{"soon"}, ""},
		{"a negative value", 429, []string{"-5"}, ""},
		{"a fraction", 503, []string{"1.5"}, ""},
		{"a date in the past", 503, []string{past}, ""},
		{"a huge value", 429, []string{strings.Repeat("9", 40)}, "3600"},
		{"a date past the bound", 503, []string{far}, "3600"},
		{"two lines", 429, []string{"10", "10"}, ""},
		{"a list", 429, []string{"10, 20"}, ""},
	} {
		status, retryAfter = c.status, c.header
		got := postRaw(t, server.URL, "/acquire", request)
		want := fmt.Sprintf(`{"error":"source failed: the source's endpoint answered %d %s; nothing was retained or minted"}`, c.status, http.StatusText(c.status))
		wait := got.header.Get("Retry-After")
		waitOK := wait == c.retryAfter
		if strings.HasPrefix(c.retryAfter, "~") {
			n, err := strconv.Atoi(wait)
			waitOK = err == nil && n >= 80 && n <= 91
		}
		if got.code != c.status || !waitOK || len(got.header.Values("Retry-After")) > 1 || got.body != want || got.header.Get("Content-Type") != "application/json" {
			t.Fatalf("%s: %d Retry-After %q: %s", c.name, got.code, got.header.Values("Retry-After"), got.body)
		}
		requireNothingKept(t, service, "page-1")
	}
	// Every other failure, as before: the bytes main answers.
	for _, c := range []struct {
		status int
		want   string
	}{
		{500, `{"error":"source failed: adapter-http: the endpoint answered 500 Internal Server Error: upstream says: slow down"}`},
		{502, `{"error":"source failed: adapter-http: the endpoint answered 502 Bad Gateway: upstream says: slow down"}`},
		{504, `{"error":"source failed: adapter-http: the endpoint answered 504 Gateway Timeout: upstream says: slow down"}`},
		{404, `{"error":"source failed: adapter-http: the endpoint answered 404 Not Found: upstream says: slow down"}`},
	} {
		status, retryAfter = c.status, []string{"30"}
		got := postRaw(t, server.URL, "/acquire", request)
		if got.code != http.StatusBadRequest || got.body != c.want || got.header.Get("Retry-After") != "" {
			t.Fatalf("a %d: %d Retry-After %q: %s", c.status, got.code, got.header.Get("Retry-After"), got.body)
		}
		requireNothingKept(t, service, "page-1")
	}
	service, server = serve(unreachable)
	got := postRaw(t, server.URL, "/acquire", request)
	if got.code != http.StatusBadRequest || !strings.HasPrefix(got.body, `{"error":"source failed: adapter-http: the endpoint could not be reached: `) || got.header.Get("Retry-After") != "" {
		t.Fatalf("an endpoint that cannot be reached: %d %s", got.code, got.body)
	}
	requireNothingKept(t, service, "page-1")
}
