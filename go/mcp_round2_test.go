package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fastSigner is a stand-in signer that answers every forward at once with
// an acquisition, recording each request's body and authorization.
func fastSigner(t *testing.T) (*httptest.Server, func() [][]byte) {
	t.Helper()
	var mu sync.Mutex
	var bodies [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, body)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result":{},"receipt":{"kind":"acquisition"},"salts":{}}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() [][]byte {
		mu.Lock()
		defer mu.Unlock()
		return append([][]byte(nil), bodies...)
	}
}

// A closure and a free slot ready at once: the call that gets the slot
// after the gate closed -- or after it closed and reopened while the call
// waited -- is refused and gives the slot back; a queued seal is woken by
// neither.
func TestMCPClosureBeatsASlot(t *testing.T) {
	f := newMCPFixture(t, false)
	signer, bodies := fastSigner(t)
	f.server.signer = signer.URL
	sid := f.open(t)
	f.server.forwards = make(chan struct{}, 1)
	f.server.queue = make(chan struct{}, 1)
	queued := func(n int) func() bool { return func() bool { return len(f.server.queue) == n } }
	sess := f.server.sessions[sid]
	// admitted under an open gate, then run after the gate closed, with a
	// slot free: the wake and the slot are both ready at the select, and
	// whichever it takes, the call is refused -- twenty rounds, so a
	// select that takes the slot and forwards cannot hide
	for round := 0; round < 20; round++ {
		admitted := f.server.admit(sess, "", time.Now(), []byte(toolCall(round, "screen.lookup", `{}`, "")))
		if admitted.run == nil {
			t.Fatalf("round %d: the call was not admitted: %s", round, admitted.response)
		}
		f.server.closeAdmission()
		outcome := admitted.run(context.Background())
		var answer map[string]any
		json.Unmarshal(outcome.response, &answer)
		if r := resultOf(t, answer); r["isError"] != true || !strings.Contains(sameBothWays(t, r)["error"].(string), "closed for maintenance while the call waited") {
			t.Fatalf("round %d, both ready: %v", round, r)
		}
		f.server.openAdmission()
		// admitted, then the gate closed and reopened before it ran: its
		// wake channel is the new, open one, the slot is free, and only the
		// generation says a closure came between
		admitted = f.server.admit(sess, "", time.Now(), []byte(toolCall(100+round, "screen.lookup", `{}`, "")))
		f.server.closeAdmission()
		f.server.openAdmission()
		outcome = admitted.run(context.Background())
		json.Unmarshal(outcome.response, &answer)
		if r := resultOf(t, answer); r["isError"] != true || !strings.Contains(sameBothWays(t, r)["error"].(string), "closed for maintenance while the call waited") {
			t.Fatalf("round %d, closed and reopened: %v", round, r)
		}
		if len(f.server.forwards) != 0 || len(f.server.queue) != 0 {
			t.Fatalf("round %d: a refused call kept a slot (%d) or a place (%d)", round, len(f.server.forwards), len(f.server.queue))
		}
	}
	if len(bodies()) != 0 {
		t.Fatalf("%d calls were forwarded across a closure", len(bodies()))
	}
	// and a call admitted after the reopen goes on
	if outcome := f.server.handle(context.Background(), sess, "", time.Now(), []byte(toolCall(999, "screen.lookup", `{}`, ""))); !strings.Contains(string(outcome.response), `"receipt"`) || len(bodies()) != 1 {
		t.Fatalf("after the reopen: %s", outcome.response)
	}
	// over the transport: a queued call is woken by the closure
	for round := 0; round < 4; round++ {
		f.server.forwards <- struct{}{} // the one slot, held
		answer := make(chan map[string]any, 1)
		go func() {
			_, _, body := f.call(t, http.MethodPost, sid, toolCall(round, "screen.lookup", `{}`, ""), nil)
			answer <- resultOf(t, body)
		}()
		waitUntil(t, "the call to queue", queued(1))
		f.server.closeAdmission()
		if round%2 == 1 {
			// closed and reopened while the call waited: refused all the same
			f.server.openAdmission()
		}
		<-f.server.forwards // the slot frees: both ready
		refused := <-answer
		if refused["isError"] != true || !strings.Contains(sameBothWays(t, refused)["error"].(string), "closed for maintenance while the call waited") {
			t.Fatalf("round %d: %v", round, refused)
		}
		if len(f.server.forwards) != 0 || len(f.server.queue) != 0 {
			t.Fatalf("round %d: the refused call kept a slot (%d) or a place (%d)", round, len(f.server.forwards), len(f.server.queue))
		}
		f.server.openAdmission()
	}
	if len(bodies()) != 1 {
		t.Fatalf("%d calls were forwarded under a closure", len(bodies())-1)
	}
	// a queued seal is woken by nothing: it waits out the slot and goes on
	f.server.forwards <- struct{}{}
	sealed := make(chan map[string]any, 1)
	go func() {
		_, _, body := f.call(t, http.MethodPost, sid, toolCall(99, mcpSealTool, `{"session":"quiet-1"}`, ""), nil)
		sealed <- resultOf(t, body)
	}()
	waitUntil(t, "the seal to queue", queued(1))
	f.server.closeAdmission()
	select {
	case r := <-sealed:
		t.Fatalf("the queued seal was woken by the closure: %v", r)
	case <-time.After(300 * time.Millisecond):
	}
	<-f.server.forwards
	if r := <-sealed; len(bodies()) != 2 || !strings.Contains(string(bodies()[1]), `"quiet-1"`) {
		t.Fatalf("the seal did not go on once the slot freed: %v %q", r, bodies())
	}
	f.server.openAdmission()
}

// The stdio transport's work is bounded and its output is not silently
// lost: past the backlog the reader waits; an answer that cannot be
// written ends the transport with the failure, and nothing more is run.
func TestMCPStdioBacklogAndBrokenOutput(t *testing.T) {
	f := newMCPFixture(t, false)
	signer, bodies := fastSigner(t)
	f.server.signer = signer.URL
	f.server.cfg.mcp.callsPerMinute = 6000
	f.server.stdioBacklog = 8
	backlog := f.server.stdioBacklog
	initialize := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`
	// an output that takes the first answer and then blocks until released;
	// released on every way out of the test, so a failure cannot hang it
	gate := &gatedWriter{release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(gate.release) })
	defer release()
	inR, inW := io.Pipe()
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { done <- f.server.serveStdio(ctx, inR, gate, "") }()
	fmt.Fprintln(inW, initialize)
	waitUntil(t, "the initialize answer", func() bool { return gate.count() == 1 })
	// the backlog fills: the reader takes this many, admits them (two
	// forwarded, two queued, the rest overloads, each an answer that then
	// waits on the output), and then waits itself, so the line after the
	// next is not even read and its write on the pipe does not complete
	for i := 0; i < backlog; i++ {
		fmt.Fprintln(inW, toolCall(10+i, "screen.lookup", `{}`, ""))
	}
	written := make(chan struct{})
	go func() {
		fmt.Fprintln(inW, toolCall(1000, "screen.lookup", `{}`, "")) // admitted, then waits for a token
		fmt.Fprintln(inW, toolCall(1001, "screen.lookup", `{}`, "")) // not even read
		close(written)
	}()
	select {
	case <-written:
		t.Fatal("the reader kept reading past the backlog")
	case <-time.After(300 * time.Millisecond):
	}
	if n := len(bodies()); n == 0 || n > backlog {
		t.Fatalf("%d forwards with the output blocked", n)
	}
	release()
	<-written
	waitUntil(t, "every answer to be written", func() bool { return gate.count() == 1+backlog+2 })
	inW.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// a broken output: the first failed answer ends the transport with
	// the failure as a category, and the call behind it is not run
	bodiesBefore := len(bodies())
	broken := &failingWriter{}
	err := f.server.serveStdio(context.Background(), strings.NewReader(initialize+"\n"+toolCall(2, "screen.lookup", `{}`, "")+"\n"), broken, "")
	if err == nil || !strings.Contains(err.Error(), "could not be written") || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("a broken output: %v", err)
	}
	if len(bodies()) != bodiesBefore {
		t.Fatal("a call behind a failed answer was forwarded")
	}
	// the same over a real pipe whose reader is gone
	outR, outW, _ := os.Pipe()
	outR.Close()
	if err := f.server.serveStdio(context.Background(), strings.NewReader(initialize+"\n"), outW, ""); err == nil || !strings.Contains(err.Error(), "could not be written") {
		t.Fatalf("a pipe without a reader: %v", err)
	}
	outW.Close()
}

// Ending the stdio transport does not wait on an answer stuck on the
// output: with every write blocked, the context's end returns at once.
func TestMCPStdioEndsWithTheOutputStuck(t *testing.T) {
	f := newMCPFixture(t, false)
	gate := &gatedWriter{release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(gate.release) })
	defer release()
	gate.n = 1 // every write blocks
	inR, inW := io.Pipe()
	defer inW.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.server.serveStdio(ctx, inR, gate, "") }()
	fmt.Fprintln(inW, `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	waitUntil(t, "the answer to block on the output", func() bool { return gate.count() == 2 })
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the transport waited on a write stuck on the output")
	}
}

// gatedWriter passes its first write through and holds every later one
// until released; it counts what it wrote.
type gatedWriter struct {
	mu      sync.Mutex
	n       int
	release chan struct{}
}

func (g *gatedWriter) Write(p []byte) (int, error) {
	g.mu.Lock()
	first := g.n == 0
	g.n++
	g.mu.Unlock()
	if !first {
		<-g.release
	}
	return len(p), nil
}

func (g *gatedWriter) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.n
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, &url.Error{Op: "write", URL: "http://127.0.0.1:1/x", Err: errors.New("broken pipe")}
}

// Over stdio the window and the lifecycle are decided in the reader's
// order, not in the order the answers happen to be written: of two calls
// written back to back under a bound of one, the second is always the one
// refused, and a call written just before the initialize is always the
// one refused.
func TestMCPStdioAdmitsInReaderOrder(t *testing.T) {
	f := newMCPFixture(t, false)
	signer, _ := fastSigner(t)
	f.server.signer = signer.URL
	f.server.cfg.mcp.callsPerMinute = 1
	initialize := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`
	for round := 0; round < 5; round++ {
		out := &bytes.Buffer{}
		in := toolCall(0, "screen.lookup", `{}`, "") + "\n" + initialize + "\n" + toolCall(2, "screen.lookup", `{}`, "") + "\n" + toolCall(3, "screen.lookup", `{}`, "") + "\n"
		if err := f.server.serveStdio(context.Background(), strings.NewReader(in), out, ""); err != nil {
			t.Fatal(err)
		}
		byID := map[float64]map[string]any{}
		for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
			var m map[string]any
			json.Unmarshal([]byte(line), &m)
			byID[m["id"].(float64)] = m
		}
		if e, ok := byID[0]["error"].(map[string]any); !ok || !strings.Contains(e["message"].(string), "initialize first") {
			t.Fatalf("round %d: the call before initialize: %v", round, byID[0])
		}
		if byID[2]["result"] == nil || byID[2]["result"].(map[string]any)["isError"] != nil {
			t.Fatalf("round %d: the first call: %v", round, byID[2])
		}
		if r, ok := byID[3]["result"].(map[string]any); !ok || sameBothWays(t, r)["outcome"] != "overload" {
			t.Fatalf("round %d: the second call under a bound of one: %v", round, byID[3])
		}
	}
}

// The seal tool's arguments are this server's own, read exactly: a member
// named twice, however spelled, and a session that is not a string are
// refused here; and the metadata's session must be a string too. A call
// whose name is malformed still resolves its metadata's session, so the
// window's refusal names it.
func TestMCPSealArgumentsAndMetadataAreReadExactly(t *testing.T) {
	f := newMCPFixture(t, false)
	sid := f.open(t)
	for _, c := range []struct{ name, arguments string }{
		{"a duplicate session", `{"session":"a","session":"b"}`},
		{"an escaped duplicate", `{"session":"a","session":"b"}`},
		{"a null session", `{"session":null}`},
		{"a numeric session", `{"session":1}`},
		{"no session", `{}`},
		{"arguments that are not an object", `"a"`},
	} {
		_, _, body := f.call(t, http.MethodPost, sid, toolCall(1, mcpSealTool, c.arguments, ""), nil)
		if body["error"] == nil || body["error"].(map[string]any)["code"] != float64(rpcInvalidParams) {
			t.Fatalf("%s: %v", c.name, body)
		}
	}
	for _, meta := range []string{`{"` + mcpSessionMeta + `":null}`, `{"` + mcpSessionMeta + `":1}`, `{"` + mcpSessionMeta + `":["a"]}`} {
		_, _, body := f.call(t, http.MethodPost, sid, toolCall(2, "screen.lookup", `{}`, meta), nil)
		if body["error"] == nil || body["error"].(map[string]any)["code"] != float64(rpcInvalidParams) {
			t.Fatalf("_meta %s: %v", meta, body)
		}
	}
	// the window spent, a malformed name with valid metadata is refused
	// naming the metadata's session
	f.server.cfg.mcp.callsPerMinute = 1
	_, _, body := f.call(t, http.MethodPost, sid, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"","_meta":{"`+mcpSessionMeta+`":"named-z"}}}`, nil)
	if r, ok := body["result"].(map[string]any); !ok || sameBothWays(t, r)["session"] != "named-z" || sameBothWays(t, r)["outcome"] != "overload" {
		t.Fatalf("a malformed name with metadata: %v", body)
	}
}

// The answer's budget starts when the request is read: a body that takes
// its time and a forward that takes its time each within their own bound
// are answered, though their sum is past the budget.
func TestMCPResponseBudgetStartsAfterTheBody(t *testing.T) {
	f := newMCPFixture(t, false)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(700 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result":{},"receipt":{"kind":"acquisition"},"salts":{}}`))
	}))
	t.Cleanup(slow.Close)
	f.server.signer = slow.URL
	f.server.readTimeout = 5 * time.Second
	f.server.queueWait = 100 * time.Millisecond
	f.server.forwardTimeout = 2 * time.Second
	f.server.responseMargin = 100 * time.Millisecond // budget 2.2 s from the body's end
	srv := httptest.NewUnstartedServer(nil)
	srv.Config = f.server.httpServer()
	srv.Start()
	t.Cleanup(srv.Close)
	sid := f.open(t)
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	body := toolCall(1, "screen.lookup", `{}`, "")
	fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: engine.test\r\nContent-Type: application/json\r\nMcp-Session-Id: %s\r\nTransfer-Encoding: chunked\r\n\r\n", mcpEndpoint, sid)
	// the body over 1.8 seconds, in three chunks
	for i, part := range []string{body[:10], body[10:20], body[20:]} {
		if i > 0 {
			time.Sleep(900 * time.Millisecond)
		}
		fmt.Fprintf(conn, "%x\r\n%s\r\n", len(part), part)
	}
	fmt.Fprint(conn, "0\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no answer after a slow body and a slow forward within their bounds: %v", err)
	}
	answer, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(answer), `"receipt"`) {
		t.Fatalf("%d %s", resp.StatusCode, answer)
	}
}

// The answer's own deadline bounds a client that stops reading it: past
// the queue's wait, the forward's deadline and the margin from the body's
// end, the handler gives up, long before the server's ceiling would.
func TestMCPResponseDeadlineBoundsASlowReader(t *testing.T) {
	f := newMCPFixture(t, false)
	big := strings.Repeat("x", 3<<20)
	signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result":{"blob":"` + big + `"},"receipt":{"kind":"acquisition"},"salts":{}}`))
	}))
	t.Cleanup(signer.Close)
	f.server.signer = signer.URL
	f.server.readTimeout = 20 * time.Second
	f.server.queueWait = 100 * time.Millisecond
	f.server.forwardTimeout = time.Second
	f.server.responseMargin = 100 * time.Millisecond // an answer's budget 1.2 s; the ceiling 21.2 s
	sid := f.open(t)
	returned := make(chan struct{})
	once := sync.OnceFunc(func() { close(returned) })
	srv := httptest.NewUnstartedServer(nil)
	srv.Config = f.server.httpServer()
	inner := srv.Config.Handler
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner.ServeHTTP(w, r)
		once()
	})
	srv.Start()
	t.Cleanup(srv.Close)
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.(*net.TCPConn).SetReadBuffer(4096)
	body := toolCall(1, "screen.lookup", `{}`, "")
	fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: engine.test\r\nContent-Type: application/json\r\nMcp-Session-Id: %s\r\nContent-Length: %d\r\n\r\n%s", mcpEndpoint, sid, len(body), body)
	// the client reads nothing
	select {
	case <-returned:
	case <-time.After(6 * time.Second):
		t.Fatal("the handler was still writing to a client that reads nothing, past the answer's budget")
	}
}

// The bearer is judged before the body is read: the handler refuses
// without touching a body that would fail the test if read, and over the
// wire a request whose body never arrives is answered 401 at once and the
// connection closed.
func TestMCPAuthorizationBeforeTheBody(t *testing.T) {
	f := newMCPFixture(t, true)
	for _, c := range []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{"a refused origin", map[string]string{"Origin": "https://evil.example", "Authorization": "Bearer " + f.token}, http.StatusForbidden},
		{"no token", nil, http.StatusUnauthorized},
		{"a bad token", map[string]string{"Authorization": "Bearer not-a-token"}, http.StatusUnauthorized},
		{"a version not spoken", map[string]string{"Authorization": "Bearer " + f.token, "MCP-Protocol-Version": "2024-11-05"}, http.StatusBadRequest},
	} {
		req := httptest.NewRequest(http.MethodPost, mcpEndpoint, sentinelBody{t, c.name})
		for k, v := range c.headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		f.server.serveMCP(rec, req)
		if rec.Code != c.want || rec.Header().Get("Connection") != "close" {
			t.Fatalf("%s: %d, Connection %q", c.name, rec.Code, rec.Header().Get("Connection"))
		}
	}
	conn, err := net.Dial("tcp", strings.TrimPrefix(f.front.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: engine.test\r\nAuthorization: Bearer not-a-token\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n", mcpEndpoint)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no answer before the body: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Bearer resource_metadata=") {
		t.Fatalf("%d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
}

// sentinelBody fails the test that reads it.
type sentinelBody struct {
	t    *testing.T
	name string
}

func (b sentinelBody) Read([]byte) (int, error) {
	b.t.Errorf("%s: the body was read before the refusal", b.name)
	return 0, io.EOF
}

// The tool's arguments reach the signer as the client's bytes: spacing,
// member order and number spellings as they were.
func TestMCPArgumentsReachTheSignerByteForByte(t *testing.T) {
	f := newMCPFixture(t, false)
	signer, bodies := fastSigner(t)
	f.server.signer = signer.URL
	sid := f.open(t)
	arguments := `{"z":  [1,   2.50, 1E3],"a" : "x",  "n":10000000000000000000000}`
	if _, _, body := f.call(t, http.MethodPost, sid, toolCall(1, "screen.lookup", arguments, ""), nil); resultOf(t, body)["isError"] != nil {
		t.Fatalf("%v", body)
	}
	want := `{"session":"` + f.server.sessions[sid].receiptSession + `","source":"screen/live","arguments":{"tool":"lookup","arguments":` + arguments + `}}`
	if got := bodies(); len(got) != 1 || string(got[0]) != want {
		t.Fatalf("the signer received\n%s\nwant\n%s", got, want)
	}
}

// What the diagnostics stream may say about a failed forward or listener:
// a category, never the address the error carries.
func TestTransportErrorCategory(t *testing.T) {
	addressed := &url.Error{Op: "Post", URL: "http://127.0.0.1:8787/acquire", Err: &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8787}, Err: errors.New("connect: connection refused")}}
	for err, want := range map[error]string{
		addressed:                   "connection failed",
		context.DeadlineExceeded:    "timed out",
		context.Canceled:            "cancelled",
		errAnswerTooLarge:           "the answer exceeded the bound",
		errors.New("x 127.0.0.1 y"): "transport error",
		&net.OpError{Op: "listen", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8788}, Err: os.ErrPermission}: "permission denied",
	} {
		if got := transportErrorCategory(err); got != want || strings.Contains(got, "127.0.0.1") {
			t.Errorf("%v: %q, want %q", err, got, want)
		}
	}
	_ = filepath.Join
}

// A session initializes once, however many initializes race for it:
// exactly one succeeds.
func TestMCPInitializeIsOneTransition(t *testing.T) {
	f := newMCPFixture(t, false)
	initialize := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`)
	for round := 0; round < 50; round++ {
		sess := f.server.newSession()
		start := make(chan struct{})
		var wg sync.WaitGroup
		var mu sync.Mutex
		succeeded := 0
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if f.server.admit(sess, "", time.Now(), initialize).initialized {
					mu.Lock()
					succeeded++
					mu.Unlock()
				}
			}()
		}
		close(start)
		wg.Wait()
		if succeeded != 1 {
			t.Fatalf("round %d: %d initializes succeeded on one session", round, succeeded)
		}
	}
}

// The version initialize names is the build's module version or, where
// the build recorded none -- a checkout built without its history, as the
// image is -- the words that say so; never "(devel)" and never empty.
func TestBuildVersionIsNeverDevel(t *testing.T) {
	v := buildVersion()
	if v == "" || v == "(devel)" || (v != "unversioned build" && !strings.HasPrefix(v, "v")) {
		t.Fatalf("buildVersion() is %q", v)
	}
	f := newMCPFixture(t, false)
	_, _, body := f.call(t, http.MethodPost, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`, nil)
	info := resultOf(t, body)["serverInfo"].(map[string]any)
	if info["version"] != v || info["name"] != "gateway:test" {
		t.Fatalf("serverInfo is %v", info)
	}
}
