package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
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

func TestMCPBounds(t *testing.T) {
	f := newMCPFixture(t, false)
	f.server.cfg.mcp.callsPerMinute = 2
	// the window is what is shifted below, not the transport session's idle bound
	f.server.cfg.mcp.idleSeconds = 86400
	sid := f.open(t)
	// the window: the third call in a minute is an overload naming the
	// seconds until the window turns, and nothing is forwarded; the three
	// arrive at one instant, so the seconds are the whole window
	instant := time.Now()
	f.server.now = func() time.Time { return instant }
	var generated string
	for i := 0; i < 2; i++ {
		_, _, body := f.call(t, http.MethodPost, sid, toolCall(i, "screen.lookup", `{}`, ""), nil)
		if body["result"].(map[string]any)["isError"] != nil {
			t.Fatalf("call %d: %v", i, body)
		}
		generated = sameBothWays(t, body["result"].(map[string]any))["session"].(string)
	}
	_, _, body := f.call(t, http.MethodPost, sid, toolCall(2, "screen.lookup", `{}`, `{"`+mcpSessionMeta+`":"named-w"}`), nil)
	result := body["result"].(map[string]any)
	structured := sameBothWays(t, result)
	if result["isError"] != true || structured["outcome"] != "overload" || structured["retryAfterSeconds"] == nil || structured["session"] != "named-w" {
		t.Fatalf("the third call: %v", result)
	}
	if secs := structured["retryAfterSeconds"].(float64); secs != 60 {
		t.Fatalf("retryAfterSeconds is %v, not the whole window", secs)
	}
	if f.receiptsOf(generated) != 2 || f.receiptsOf("named-w") != 0 {
		t.Fatalf("an overloaded call reached the signer: %d and %d receipts", f.receiptsOf(generated), f.receiptsOf("named-w"))
	}
	// a call refused for what it says spent its quota too, at arrival: an
	// unknown tool, then a well-formed call, and the second is the overload
	f.server.now = func() time.Time { return time.Now().Add(61 * time.Second) }
	f.call(t, http.MethodPost, sid, toolCall(3, "screen.nothing", `{}`, ""), nil)
	f.call(t, http.MethodPost, sid, toolCall(4, mcpSealTool, `{"nonsense":1}`, ""), nil)
	_, _, body = f.call(t, http.MethodPost, sid, toolCall(5, "screen.lookup", `{}`, ""), nil)
	if result = body["result"].(map[string]any); result["isError"] != true || sameBothWays(t, result)["outcome"] != "overload" {
		t.Fatalf("refused calls did not spend the quota: %v", body)
	}
	// and the window turns
	f.server.now = func() time.Time { return time.Now().Add(122 * time.Second) }
	if _, _, body := f.call(t, http.MethodPost, sid, toolCall(6, "screen.lookup", `{}`, ""), nil); body["result"].(map[string]any)["isError"] != nil {
		t.Fatalf("after the window turned: %v", body)
	}
	f.server.now = time.Now

	// the forward slots and the queue: with one slot and a stalled
	// source, a second call waits and a third is refused at once
	f.server.cfg.mcp.callsPerMinute = 100
	f.server.forwards = make(chan struct{}, 1)
	f.server.queue = make(chan struct{}, 1)
	barrier := t.TempDir()
	release := filepath.Join(barrier, "release")
	started := filepath.Join(barrier, "started")
	t.Setenv(envSourceWait, release)
	t.Setenv(envSourceReady, started)
	results := make(chan map[string]any, 8)
	var wg sync.WaitGroup
	launch := func(id int) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, body := f.call(t, http.MethodPost, sid, toolCall(id, "screen.lookup", `{}`, ""), nil)
			results <- resultOf(t, body)
		}()
	}
	queued := func(n int) func() bool { return func() bool { return len(f.server.queue) == n } }
	launch(20)
	waitForFile(t, started)
	launch(21)
	waitUntil(t, "the second call to queue", queued(1))
	// one is forwarded and stalled, one waits in the queue: a third finds
	// the queue full
	_, _, body = f.call(t, http.MethodPost, sid, toolCall(22, "screen.lookup", `{}`, ""), nil)
	third := body["result"].(map[string]any)
	if third["isError"] != true || !strings.Contains(sameBothWays(t, third)["error"].(string), "full") {
		t.Fatalf("the third call with a full queue: %v", third)
	}
	os.WriteFile(release, []byte("go"), 0o600)
	wg.Wait()
	for i := 0; i < 2; i++ {
		if r := <-results; r["isError"] != nil {
			t.Fatalf("a queued call failed: %v", r)
		}
	}
	if f.receiptsOf(generated) != 5 {
		t.Fatalf("the generated session holds %d receipts, not 5", f.receiptsOf(generated))
	}
	// the queue's wait: a call that finds no slot within it is an overload
	// naming the wait, and the slot it did not get is not leaked
	os.Remove(release)
	os.Remove(started)
	f.server.queueWait = 300 * time.Millisecond
	launch(23)
	waitForFile(t, started)
	_, _, body = f.call(t, http.MethodPost, sid, toolCall(24, "screen.lookup", `{}`, ""), nil)
	if timedOut := body["result"].(map[string]any); timedOut["isError"] != true || !strings.Contains(sameBothWays(t, timedOut)["error"].(string), "no forward slot within 300ms") {
		t.Fatalf("the queued call past the wait: %v", timedOut)
	}
	// a queued call whose client goes away releases its place: the queue
	// is empty again once the request's context ends
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, f.front.URL+mcpEndpoint, strings.NewReader(toolCall(25, "screen.lookup", `{}`, "")))
	req.Header.Set("Mcp-Session-Id", sid)
	req.Header.Set("Content-Type", "application/json")
	gone := make(chan struct{})
	go func() {
		defer close(gone)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	waitUntil(t, "the call to queue", queued(1))
	cancel()
	<-gone
	waitUntil(t, "the cancelled call to leave the queue", queued(0))
	os.WriteFile(release, []byte("go"), 0o600)
	wg.Wait()
	close(results)
	for r := range results {
		if r["isError"] != nil {
			t.Fatalf("the call that waited out the others failed: %v", r)
		}
	}
	t.Setenv(envSourceWait, "")
	t.Setenv(envSourceReady, "")
}

// The stdio transport over real pipes: the lifecycle, a call, a seal,
// concurrent handling with arrival-time accounting, and a shutdown that
// does not wait for a reader that never ends.
func TestMCPOverStdio(t *testing.T) {
	f := newMCPFixture(t, true)
	initialize := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`
	start := func(t *testing.T, token string) (in *os.File, answers *bufio.Scanner, done chan error, cancel context.CancelFunc) {
		t.Helper()
		inR, inW, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		outR, outW, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancelCtx := context.WithCancel(context.Background())
		done = make(chan error, 1)
		go func() {
			done <- f.server.serveStdio(ctx, inR, outW, token)
			outW.Close()
		}()
		t.Cleanup(func() { cancelCtx(); inW.Close(); inR.Close(); outR.Close() })
		answers = bufio.NewScanner(outR)
		answers.Buffer(make([]byte, 0, 64*1024), mcpMaxAnswerBytes)
		return inW, answers, done, cancelCtx
	}
	next := func(t *testing.T, answers *bufio.Scanner) map[string]any {
		t.Helper()
		if !answers.Scan() {
			t.Fatal("no answer")
		}
		var m map[string]any
		if err := json.Unmarshal(answers.Bytes(), &m); err != nil {
			t.Fatalf("not JSON: %s", answers.Bytes())
		}
		return m
	}
	in, answers, done, cancel := start(t, f.token)
	// a call written before the initialize, without waiting, is refused
	// in the reader's order; the initialize answers; a second initialize
	// is refused; a notification is silent; then a call and a seal
	fmt.Fprintln(in, toolCall(0, "screen.lookup", `{}`, "")+"\n"+initialize+"\n"+initialize)
	if early := next(t, answers); early["id"] != float64(0) || early["error"] == nil || !strings.Contains(early["error"].(map[string]any)["message"].(string), "initialize first") {
		t.Fatalf("a call before initialize: %v", early)
	}
	if init := next(t, answers); init["result"] == nil || init["result"].(map[string]any)["protocolVersion"] != mcpProtocolVersion {
		t.Fatalf("initialize: %v", init)
	}
	if again := next(t, answers); again["error"] == nil || !strings.Contains(again["error"].(map[string]any)["message"].(string), "initialized already") {
		t.Fatalf("a second initialize: %v", again)
	}
	fmt.Fprintln(in, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	fmt.Fprintln(in, toolCall(2, "screen.lookup", `{"q":"x"}`, ""))
	call := next(t, answers)
	structured := sameBothWays(t, resultOf(t, call))
	session := structured["session"].(string)
	if call["id"] != float64(2) || !strings.HasPrefix(session, "mcp-") || structured["receipt"] == nil || structured["receipt"].(map[string]any)["caller"] == nil {
		t.Fatalf("the stdio call: %v", call)
	}
	// a named session, sealed through the tool; the generated one goes on
	fmt.Fprintln(in, toolCall(30, "screen.lookup", `{}`, `{"`+mcpSessionMeta+`":"stdio-1"}`))
	if named := next(t, answers); sameBothWays(t, resultOf(t, named))["session"] != "stdio-1" {
		t.Fatalf("the named session over stdio: %v", named)
	}
	fmt.Fprintln(in, toolCall(3, mcpSealTool, `{"session":"stdio-1"}`, ""))
	if sealed := next(t, answers); sealed["result"].(map[string]any)["structuredContent"].(map[string]any)["finalCount"] != float64(1) {
		t.Fatalf("the stdio seal: %v", sealed)
	}
	// two calls at once, the first stalled: the second is handled while
	// the first waits, in the order the answers come
	barrier := t.TempDir()
	release := filepath.Join(barrier, "release")
	t.Setenv(envSourceWait, release)
	t.Setenv(envSourceReady, filepath.Join(barrier, "started"))
	fmt.Fprintln(in, toolCall(4, "screen.lookup", `{}`, ""))
	waitForFile(t, filepath.Join(barrier, "started"))
	fmt.Fprintln(in, `{"jsonrpc":"2.0","id":5,"method":"ping"}`)
	if pong := next(t, answers); pong["id"] != float64(5) {
		t.Fatalf("the ping waited behind the stalled call: %v", pong)
	}
	os.WriteFile(release, []byte("go"), 0o600)
	if stalledAnswer := next(t, answers); stalledAnswer["id"] != float64(4) || stalledAnswer["result"].(map[string]any)["isError"] != nil {
		t.Fatalf("the stalled call: %v", stalledAnswer)
	}
	t.Setenv(envSourceWait, "")
	t.Setenv(envSourceReady, "")
	// the window over stdio is the process's: with a bound of one call a
	// minute, the calls above have spent it
	f.server.cfg.mcp.callsPerMinute = 1
	fmt.Fprintln(in, toolCall(6, "screen.lookup", `{}`, ""))
	if refused := next(t, answers); sameBothWays(t, refused["result"].(map[string]any))["outcome"] != "overload" {
		t.Fatalf("the window over stdio: %v", refused)
	}
	f.server.cfg.mcp.callsPerMinute = 100
	// shutdown: the input is still open and nothing is written, and the
	// transport returns at once when its context ends
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the transport did not return when its context ended")
	}
	// the input ending, ends the transport, after every answer is written
	in, answers, done, _ = start(t, f.token)
	fmt.Fprintln(in, initialize)
	next(t, answers)
	fmt.Fprintln(in, toolCall(7, "screen.lookup", `{}`, ""))
	in.Close()
	if last := next(t, answers); last["id"] != float64(7) {
		t.Fatalf("the last answer: %v", last)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// no token, with an identity: refused at start, nothing served
	out := &bytes.Buffer{}
	if err := f.server.serveStdio(context.Background(), strings.NewReader(initialize+"\n"), out, ""); err == nil || !strings.Contains(err.Error(), mcpTokenEnv) || out.Len() != 0 {
		t.Fatalf("stdio without a token started: %v %q", err, out.String())
	}
	// the signer refusing the token over stdio is an error result
	other := identityFor(t, newIssuer(t))
	f.service.identity = &other
	out.Reset()
	f.server.serveStdio(context.Background(), strings.NewReader(initialize+"\n"+toolCall(8, "screen.lookup", `{}`, "")+"\n"), out, f.token)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var refused map[string]any
	json.Unmarshal([]byte(lines[len(lines)-1]), &refused)
	if r := refused["result"].(map[string]any); r["isError"] != true || sameBothWays(t, r)["status"] != float64(401) {
		t.Fatalf("the signer's refusal over stdio: %s", out.String())
	}
	// a line over the bound ends the transport with an error, said on stdout
	out.Reset()
	if err := f.server.serveStdio(context.Background(), strings.NewReader(strings.Repeat("x", mcpMaxMessageBytes+2)+"\n"), out, f.token); err == nil || !strings.Contains(out.String(), "exceeds the bound") {
		t.Fatalf("a line over the bound: %v %s", err, out.String())
	}
}

// What the forward carries as authorization: the caller's token when the
// engine has an identity, and nothing at all when it has none -- whatever
// the environment held.
func TestMCPForwardCarriesTheTokenOnlyUnderAnIdentity(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	capture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result":{},"receipt":{"kind":"acquisition"},"salts":{}}`))
	}))
	t.Cleanup(capture.Close)
	initialize := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`
	for _, c := range []struct {
		name         string
		withIdentity bool
		want         string
	}{{"no identity", false, ""}, {"an identity", true, "Bearer "}} {
		f := newMCPFixture(t, c.withIdentity)
		f.server.signer = capture.URL
		token := f.token
		if !c.withIdentity {
			token = "stray-token-from-the-environment"
		}
		out := &bytes.Buffer{}
		if err := f.server.serveStdio(context.Background(), strings.NewReader(initialize+"\n"+toolCall(2, "screen.lookup", `{}`, "")+"\n"), out, token); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		got := seen[len(seen)-1]
		captured := len(seen)
		mu.Unlock()
		if !strings.Contains(out.String(), `"kind":"acquisition"`) || captured == 0 {
			t.Fatalf("%s: the call did not reach the stand-in signer: %s", c.name, out.String())
		}
		if c.want == "" && got != "" {
			t.Fatalf("%s: the forward carried %q", c.name, got)
		}
		if c.want != "" && got != c.want+f.token {
			t.Fatalf("%s: the forward carried %q", c.name, got)
		}
	}
}

func TestMCPReachCheck(t *testing.T) {
	cfg := engineConfig{seed: "/s/seed", store: "/s/store", platforms: []platformConfig{{name: "p", credentials: map[string]string{"live": "/c/live", "history": "/c/history"}}}}
	denied := func(string) error { return fs.ErrPermission }
	good := mcpReachHost{euid: 65533, gid: 65533, groups: func() ([]int, error) { return []int{65533}, nil }, caps: func() (bool, string) { return true, "" }, open: denied}
	if err := mcpReachCheck(cfg, good); err != nil {
		t.Fatalf("a deployment in place is refused: %v", err)
	}
	// a container runtime lists no supplementary group at all for a user
	// in no group's member list, or the primary group alone: both are in
	// place
	none := good
	none.groups = func() ([]int, error) { return nil, nil }
	if err := mcpReachCheck(cfg, none); err != nil {
		t.Fatalf("no supplementary group is refused: %v", err)
	}
	for _, c := range []struct {
		name string
		host func(h mcpReachHost) mcpReachHost
		want string
	}{
		{"root", func(h mcpReachHost) mcpReachHost { h.euid = 0; return h }, "runs as root"},
		{"another user", func(h mcpReachHost) mcpReachHost { h.euid = 1000; return h }, "runs as uid 1000; it runs as engine-mcp (uid 65533)"},
		{"the signer's user", func(h mcpReachHost) mcpReachHost { h.euid = 65532; return h }, "runs as uid 65532"},
		{"another group", func(h mcpReachHost) mcpReachHost { h.gid = 65532; return h }, "runs as gid 65532"},
		{"a capability", func(h mcpReachHost) mcpReachHost {
			h.caps = func() (bool, string) { return false, "effective 0x20" }
			return h
		}, "holds a capability"},
		{"a supplementary group", func(h mcpReachHost) mcpReachHost {
			h.groups = func() ([]int, error) { return []int{65533, 65532}, nil }
			return h
		}, "supplementary group 65532"},
		{"groups unreadable", func(h mcpReachHost) mcpReachHost {
			h.groups = func() ([]int, error) { return nil, fmt.Errorf("no") }
			return h
		}, "cannot read its groups"},
		{"a readable seed", func(h mcpReachHost) mcpReachHost {
			h.open = func(p string) error {
				if p == "/s/seed" {
					return nil
				}
				return fs.ErrPermission
			}
			return h
		}, "can open the seed"},
		{"a readable credentials file", func(h mcpReachHost) mcpReachHost {
			h.open = func(p string) error {
				if p == "/c/history" {
					return nil
				}
				return fs.ErrPermission
			}
			return h
		}, "can open platform p's history credentials"},
		{"a readable store", func(h mcpReachHost) mcpReachHost {
			h.open = func(p string) error {
				if p == "/s/store" {
					return nil
				}
				return fs.ErrPermission
			}
			return h
		}, "can open the store"},
		{"a missing seed", func(h mcpReachHost) mcpReachHost {
			h.open = func(p string) error {
				if p == "/s/seed" {
					return fs.ErrNotExist
				}
				return fs.ErrPermission
			}
			return h
		}, "not a denial"},
	} {
		if err := mcpReachCheck(cfg, c.host(good)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want %q, got %v", c.name, c.want, err)
		}
	}
	// against the real filesystem, with the process's identity stood in
	// as the frontend's: a file this user cannot read is denied, a
	// readable one is refused, a missing one is refused
	if os.Geteuid() == 0 {
		t.Skip("root can open anything; the filesystem case needs an unprivileged user")
	}
	if runtime.GOOS == "windows" {
		t.Skip("mode bits do not deny a file's owner on Windows, so the fixture cannot express a denial; the stand-in cases above hold the check, and the process runs in the engine's Linux image")
	}
	dir := t.TempDir()
	seed := filepath.Join(dir, "seed")
	store := filepath.Join(dir, "store")
	credentials := filepath.Join(dir, "credentials")
	os.WriteFile(seed, []byte("x"), 0o000)
	os.Mkdir(store, 0o000)
	os.WriteFile(credentials, []byte("x"), 0o000)
	host := osMCPReachHost()
	host.euid, host.gid = frontendUID, frontendUID
	host.caps = func() (bool, string) { return true, "" }
	host.groups = func() ([]int, error) { return nil, nil }
	real := engineConfig{seed: seed, store: store, platforms: []platformConfig{{name: "p", credentials: map[string]string{"live": credentials}}}}
	if err := mcpReachCheck(real, host); err != nil {
		t.Fatalf("denied files refused: %v", err)
	}
	os.Chmod(seed, 0o600)
	if err := mcpReachCheck(real, host); err == nil || !strings.Contains(err.Error(), "can open the seed") {
		t.Fatalf("a readable seed: %v", err)
	}
	os.Chmod(seed, 0o000)
	os.Chmod(credentials, 0o400)
	if err := mcpReachCheck(real, host); err == nil || !strings.Contains(err.Error(), "can open platform p's live credentials") {
		t.Fatalf("a readable credentials file: %v", err)
	}
	os.Chmod(credentials, 0o000)
	os.Chmod(store, 0o500)
	if err := mcpReachCheck(real, host); err == nil || !strings.Contains(err.Error(), "can open the store") {
		t.Fatalf("a readable store: %v", err)
	}
	os.Chmod(store, 0o000)
	real.seed = filepath.Join(dir, "absent")
	if err := mcpReachCheck(real, host); err == nil || !strings.Contains(err.Error(), "not a denial") {
		t.Fatalf("a missing seed: %v", err)
	}
}

func TestMCPCommandRefusals(t *testing.T) {
	catalog := t.TempDir()
	write := func(text string) string {
		path := filepath.Join(t.TempDir(), "engine.json")
		os.WriteFile(path, []byte(text), 0o600)
		return path
	}
	v2 := func(mcp, extra string) string {
		text := engineJSON(t, catalog, `,"mcp":`+mcp+extra, ``)
		return strings.Replace(text, `"engineVersion":"1"`, `"engineVersion":"2"`, 1)
	}
	inPlace := mcpReachHost{euid: frontendUID, gid: frontendUID, groups: func() ([]int, error) { return nil, nil }, caps: func() (bool, string) { return true, "" }, open: func(string) error { return fs.ErrPermission }}
	elsewhere := inPlace
	elsewhere.euid = 1000
	for _, c := range []struct {
		name  string
		args  []string
		reach mcpReachHost
		want  int
		says  string
	}{
		{"no arguments", nil, inPlace, 2, "usage:"},
		{"no transport", []string{"--config", write(v2(`{"listen":"127.0.0.1:8788"}`, ``))}, inPlace, 2, "usage:"},
		{"two transports", []string{"--config", write(v2(`{"listen":"127.0.0.1:8788"}`, ``)), "--http", "--stdio"}, inPlace, 2, "usage:"},
		{"an unknown flag", []string{"--config", "x", "--tcp"}, inPlace, 2, "usage:"},
		{"a configuration that does not load", []string{"--config", filepath.Join(t.TempDir(), "none.json"), "--stdio"}, inPlace, 1, "start:"},
		{"no mcp member", []string{"--config", write(engineJSON(t, catalog, ``, ``)), "--stdio"}, inPlace, 1, "no mcp member"},
		{"http without a resource", []string{"--config", write(v2(`{"listen":"127.0.0.1:8788"}`, ``)), "--http"}, inPlace, 1, "--http needs mcp.resource"},
		{"http without an identity", []string{"--config", write(v2(`{"listen":"127.0.0.1:8788","resource":"https://e/mcp"}`, ``)), "--http"}, inPlace, 1, "--http needs an identity"},
		{"http with an issuer that is no identifier", []string{"--config", write(v2(`{"listen":"127.0.0.1:8788","resource":"https://e/mcp"}`, `,"identity":{"issuer":"login.example","audience":"gateway:acme","keys":"`+abs(t, t.TempDir(), "keys.json")+`"}`)), "--http"}, inPlace, 1, "identity.issuer:"},
		{"a process that is not the frontend's user", []string{"--config", write(v2(`{"listen":"127.0.0.1:8788"}`, ``)), "--stdio"}, elsewhere, 1, "runs as uid 1000"},
	} {
		var stderr bytes.Buffer
		if got := runMCP(context.Background(), c.args, strings.NewReader(""), io.Discard, &stderr, c.reach); got != c.want || !strings.Contains(stderr.String(), c.says) {
			t.Errorf("%s: exit %d, want %d, saying %q, want %q", c.name, got, c.want, stderr.String(), c.says)
		}
	}
}

// A connection that does not finish its request is closed by the server's
// own deadline, before any of the four bounds could see it.
func TestMCPHTTPServerDeadlines(t *testing.T) {
	f := newMCPFixture(t, false)
	f.server.readTimeout = 300 * time.Millisecond
	srv := httptest.NewUnstartedServer(nil)
	srv.Config = f.server.httpServer()
	srv.Start()
	t.Cleanup(srv.Close)
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// headers and the start of a body that never ends
	fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: engine.test\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{", mcpEndpoint)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err == nil {
		// an answer is fine too, as long as the connection does not hang;
		// a request refused on its session id is what such a body earns
		if !strings.Contains(string(buf[:n]), "HTTP/1.1") {
			t.Fatalf("read %q", buf[:n])
		}
		return
	}
	if !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "reset") && !strings.Contains(err.Error(), "closed") {
		t.Fatalf("the stalled connection was not closed within the read timeout: %v", err)
	}
}

func TestAcceptsJSON(t *testing.T) {
	for _, c := range []struct {
		accept []string
		want   bool
	}{
		{nil, true},
		{[]string{""}, true},
		{[]string{"application/json"}, true},
		{[]string{"application/json, text/event-stream"}, true},
		{[]string{"text/event-stream, application/json"}, true},
		{[]string{"*/*"}, true},
		{[]string{"application/*"}, true},
		{[]string{"text/event-stream"}, false},
		{[]string{"application/json;q=0, text/event-stream"}, false},
		{[]string{"*/*;q=0"}, false},
		{[]string{"application/*;q=0.5, application/json;q=0"}, false},
		{[]string{"text/*, */*;q=0.1"}, true},
		{[]string{"APPLICATION/JSON"}, true},
		{[]string{"text/event-stream", "application/json"}, true},
		{[]string{"text/event-stream", "*/*;q=0"}, false},
		{[]string{"application/json;charset=utf-8"}, false},
		{[]string{"application/json;charset=utf-8, */*"}, true},
		{[]string{`application/json;q="0"`}, false},
		{[]string{"application/json;q=x"}, false},
		{[]string{"application/json;q=2"}, false},
		{[]string{"application/json;Q=0.5"}, true},
		{[]string{"application/json;q=.5"}, false},
		{[]string{"application/json;q=+0.5"}, false},
		{[]string{"application/json;q=1e-1"}, false},
		{[]string{"application/json;q=0.5555"}, false},
		{[]string{"application/json;q=NaN"}, false},
		{[]string{"application/json;q=1.000"}, true},
		{[]string{"application/json;q=0."}, false},
		{[]string{"application/json;q=0.001"}, true},
		{[]string{"application/json;q=1.001"}, false},
		{[]string{`text/plain;x="a,b", application/json`}, true},
		{[]string{"*/*;q=0, application/json"}, true},
	} {
		if got := acceptsJSON(c.accept); got != c.want {
			t.Errorf("Accept %q: %v, want %v", c.accept, got, c.want)
		}
	}
}

func TestMetadataPathAndDuplicates(t *testing.T) {
	for resource, path := range map[string]string{
		"https://engine.example/mcp":          "/.well-known/oauth-protected-resource/mcp",
		"https://engine.example":              "/.well-known/oauth-protected-resource",
		"https://engine.example/":             "/.well-known/oauth-protected-resource",
		"https://engine.example/a/b/mcp":      "/.well-known/oauth-protected-resource/a/b/mcp",
		"https://engine.example/a%20b/mcp":    "/.well-known/oauth-protected-resource/a%20b/mcp",
		"https://engine.example/mcp?tenant=1": "/.well-known/oauth-protected-resource/mcp",
	} {
		if got := metadataPath(resource); got != path {
			t.Errorf("%s: %s, want %s", resource, got, path)
		}
	}
	for resource, want := range map[string]string{
		"https://engine.example:8443/mcp":     "https://engine.example:8443/.well-known/oauth-protected-resource/mcp",
		"https://engine.example/mcp?tenant=1": "https://engine.example/.well-known/oauth-protected-resource/mcp?tenant=1",
		"https://engine.example/a%20b":        "https://engine.example/.well-known/oauth-protected-resource/a%20b",
	} {
		if got := metadataURL(resource); got != want {
			t.Errorf("%s: %s, want %s", resource, got, want)
		}
	}
	for text, ok := range map[string]bool{
		`{"a":1,"b":{"c":2,"d":[{"e":1},{"e":2}]}}`: true,
		`{"a":1,"a":2}`:             false,
		`{"a":{"b":1,"b":2}}`:       false,
		`{"a":[{"b":1,"b":2}]}`:     false,
		`{"a":"x","a":"y"}`:         false,
		`[{"a":1},{"a":1}]`:         true,
		`{"a":{"b":1},"c":{"b":1}}`: true,
		// under the skipped path, another reader's: stepped over whole
		`{"params":{"arguments":{"a":1,"a":2}}}`:                       true,
		`{"params":{"arguments":[{"a":1,"a":2}],"name":"x"}}`:          true,
		`{"params":{"arguments":{"a":1,"a":2},"name":"x","name":"y"}}`: false,
		`{"params":{"arguments":1,"name":"x"},"params":{}}`:            false,
		`{"other":{"arguments":{"a":1,"a":2}}}`:                        false,
		`{"params":{"_meta":{"a":1,"a":2}}}`:                           false,
		// escaped spellings are the names they decode to, on the path as
		// in a duplicate; a lookalike at another depth is no exception
		`{"p\u0061rams":{"arguments":{"a":1,"a":2}}}`:         true,
		`{"params":{"argum\u0065nts":{"a":1,"a":2}}}`:         true,
		`{"params":{"x":{"arguments":{"a":1,"a":2}}}}`:        false,
		`{"x":{"params":{"arguments":{"a":1,"a":2}}}}`:        false,
		`{"params":[{"arguments":{"a":1,"a":2}}]}`:            false,
		`{"params":{"arguments":{"a":1},"argum\u0065nts":2}}`: false,
		`{"a":1,"\u0061":2}`:                                  false,
	} {
		if err := noDuplicateMembers([]byte(text), [][]string{{"params", "arguments"}}); (err == nil) != ok {
			t.Errorf("%s: %v", text, err)
		}
	}
	// JSON-RPC ids: strings and integers, nothing else
	for id, ok := range map[string]bool{`1`: true, `"x"`: true, `0`: true, `-1`: true, `1.0`: true, `1e2`: true, `1.5`: false, `1e-2`: false, `true`: false, `null`: false, `[1]`: false, `{}`: false, `""`: true, `9007199254740993`: true, `1e400`: true, `1e99999`: false, `"` + strings.Repeat("a", 63) + `"`: false} {
		if validID(json.RawMessage(id)) != ok {
			t.Errorf("id %s: %v", id, !ok)
		}
	}
	_ = io.EOF
}
