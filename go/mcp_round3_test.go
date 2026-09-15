package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// syncBuffer is a diagnostics stream a test can read while the server's
// delivery goroutine writes it.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// A closure is a barrier to dispatch: an acquisition that passed the
// gate's last word before the closure -- paused there, between that word
// and the forward -- holds the closure undrained until it has had its
// answer, so an operator who waits for the drain and then seals seals
// after it; and nothing is dispatched after the drain.
func TestMCPClosureDrainsWhatPassedTheGate(t *testing.T) {
	f := newMCPFixture(t, false)
	diagnostics := &syncBuffer{}
	f.server.log = diagnostics
	sid := f.open(t)
	paused := make(chan struct{})
	resume := make(chan struct{})
	resumeOnce := sync.OnceFunc(func() { close(resume) })
	defer resumeOnce() // on every way out, so a failure cannot hang the handler
	var once sync.Once
	f.server.beforeForward = func() {
		once.Do(func() {
			close(paused)
			<-resume
		})
	}
	answer := make(chan map[string]any, 1)
	go func() {
		_, _, body := f.call(t, http.MethodPost, sid, toolCall(1, "screen.lookup", `{}`, `{"`+mcpSessionMeta+`":"late-1"}`), nil)
		answer <- resultOf(t, body)
	}()
	<-paused
	drained := f.server.closeAdmission()
	select {
	case <-drained:
		t.Fatal("the closure drained with an acquisition between the gate and the forward")
	case <-time.After(300 * time.Millisecond):
	}
	if f.receiptsOf("late-1") != 0 {
		t.Fatal("the paused acquisition reached the signer before it was resumed")
	}
	resumeOnce()
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("the closure did not drain once the acquisition had its answer")
	}
	if r := <-answer; r["isError"] != nil {
		t.Fatalf("the acquisition that passed the gate: %v", r)
	}
	waitUntil(t, "the drain to be said", func() bool { return strings.Contains(diagnostics.String(), "mcp: closure 1 drained") })
	// the operator seals now, directly: the session holds the acquisition
	// that passed the gate, and it is the last
	if code, body := post(t, f.signer, "/seal", `{"session":"late-1"}`); code != http.StatusOK || body["finalCount"] != float64(1) {
		t.Fatalf("/seal after the drain: %d %v", code, body)
	}
	_, _, body := f.call(t, http.MethodPost, sid, toolCall(2, "screen.lookup", `{}`, `{"`+mcpSessionMeta+`":"late-2"}`), nil)
	if r := resultOf(t, body); sameBothWays(t, r)["outcome"] != "overload" || f.receiptsOf("late-2") != 0 {
		t.Fatalf("an acquisition after the drain: %v", r)
	}
	f.server.openAdmission()
	// a closure with nothing dispatching is drained at once
	select {
	case <-f.server.closeAdmission():
	case <-time.After(time.Second):
		t.Fatal("a closure with nothing dispatching did not drain")
	}
	f.server.openAdmission()
}

// The gate's last word is taken with the slot: a call that has its slot
// when the gate closes -- paused there, after the wait and before the last
// word -- is refused by that word, gives the slot back, and is not
// forwarded.
func TestMCPClosureAfterTheSlotIsRefusedAtTheLastWord(t *testing.T) {
	f := newMCPFixture(t, false)
	signer, bodies := fastSigner(t)
	f.server.signer = signer.URL
	sid := f.open(t)
	paused := make(chan struct{})
	resume := make(chan struct{})
	resumeOnce := sync.OnceFunc(func() { close(resume) })
	defer resumeOnce()
	var once sync.Once
	f.server.afterSlot = func() {
		once.Do(func() {
			close(paused)
			<-resume
		})
	}
	answer := make(chan map[string]any, 1)
	go func() {
		_, _, body := f.call(t, http.MethodPost, sid, toolCall(1, "screen.lookup", `{}`, ""), nil)
		answer <- resultOf(t, body)
	}()
	<-paused
	f.server.closeAdmission()
	f.server.openAdmission() // closed and reopened: only the generation says so
	resumeOnce()
	if r := <-answer; r["isError"] != true || !strings.Contains(sameBothWays(t, r)["error"].(string), "closed for maintenance while the call waited") {
		t.Fatalf("a call holding its slot across a closure: %v", r)
	}
	if len(bodies()) != 0 || len(f.server.forwards) != 0 {
		t.Fatalf("forwarded %d, slots held %d", len(bodies()), len(f.server.forwards))
	}
}

// A call admitted before a closure that closed -- and reopened -- before
// the call ran is refused at once, with every slot still taken: it does
// not sit out the queue's wait on the reopened gate's channel.
func TestMCPStaleCallIsRefusedAtOnce(t *testing.T) {
	f := newMCPFixture(t, false)
	signer, bodies := fastSigner(t)
	f.server.signer = signer.URL
	sid := f.open(t)
	sess := f.server.sessions[sid]
	f.server.queueWait = 5 * time.Second
	f.server.forwards = make(chan struct{}, 1)
	f.server.forwards <- struct{}{} // every slot taken
	for _, reopen := range []bool{true, false} {
		admitted := f.server.admit(sess, "", []byte(toolCall(1, "screen.lookup", `{}`, "")))
		if admitted.run == nil {
			t.Fatalf("not admitted: %s", admitted.response)
		}
		f.server.closeAdmission()
		if reopen {
			f.server.openAdmission()
		}
		started := time.Now()
		outcome := admitted.run(context.Background())
		if took := time.Since(started); took > time.Second {
			t.Fatalf("reopen %v: the stale call waited %v", reopen, took)
		}
		var answer map[string]any
		json.Unmarshal(outcome.response, &answer)
		if r := resultOf(t, answer); !strings.Contains(sameBothWays(t, r)["error"].(string), "closed for maintenance while the call waited") {
			t.Fatalf("reopen %v: %v", reopen, r)
		}
		if len(f.server.queue) != 0 {
			t.Fatalf("reopen %v: the stale call kept its queue place", reopen)
		}
		f.server.openAdmission()
	}
	if len(bodies()) != 0 {
		t.Fatal("a stale call was forwarded")
	}
	<-f.server.forwards
}

// A diagnostics stream that never drains holds up nothing: the gate
// closes and opens, a call is refused, a seal goes on, a failed forward is
// reported, and the lines past the buffer are counted, not waited for.
func TestMCPBlockedDiagnosticsBlockNothing(t *testing.T) {
	f := newMCPFixture(t, false)
	blocked := &gatedWriter{release: make(chan struct{})}
	blocked.n = 1 // every write blocks
	defer close(blocked.release)
	f.server.log = blocked
	sid := f.open(t)
	within := func(what string, fn func()) {
		t.Helper()
		done := make(chan struct{})
		go func() { fn(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatalf("%s waited on the diagnostics stream", what)
		}
	}
	for i := 0; i < 300; i++ { // past the buffer
		within("closing and opening", func() { f.server.closeAdmission(); f.server.openAdmission() })
	}
	f.server.closeAdmission()
	within("a refusal", func() {
		_, _, body := f.call(t, http.MethodPost, sid, toolCall(1, "screen.lookup", `{}`, ""), nil)
		if sameBothWays(t, resultOf(t, body))["outcome"] != "overload" {
			t.Errorf("under closure: %v", body)
		}
	})
	within("a seal", func() {
		f.call(t, http.MethodPost, sid, toolCall(2, mcpSealTool, `{"session":"never-1"}`, ""), nil)
	})
	f.server.openAdmission()
	stalled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(time.Second) }))
	t.Cleanup(stalled.Close)
	f.server.signer = stalled.URL
	f.server.forwardTimeout = 100 * time.Millisecond
	within("a failed forward's report", func() {
		f.call(t, http.MethodPost, sid, toolCall(3, "screen.lookup", `{}`, ""), nil)
	})
	// traffic past the buffer is dropped and counted; the operator's
	// reports are not
	for i := 0; i < 400; i++ {
		f.server.diag("mcp: traffic line %d", i)
	}
	if f.server.reports.dropped.Load() == 0 {
		t.Fatal("nothing was counted as dropped with the stream blocked")
	}
}

// The operator's reports survive a stream that stops and starts: every
// closure's report arrives once it drains, in order, with its number, and
// the dropped traffic is counted in a line of its own; a closure asked
// for again says where it stands; and a closure reopened before it
// drained says so, and its drain is never reported for a later one.
func TestMCPClosureReportsAreReliableAndNumbered(t *testing.T) {
	f := newMCPFixture(t, false)
	stream := &gatedWriter{release: make(chan struct{})}
	stream.n = 1 // every write blocks until released
	release := sync.OnceFunc(func() { close(stream.release) })
	defer release()
	lines := &syncBuffer{}
	f.server.log = io.MultiWriter(stream, lines)
	sid := f.open(t)
	// a forward held between the gate's last word and the forward
	paused := make(chan struct{})
	resume := make(chan struct{})
	resumeOnce := sync.OnceFunc(func() { close(resume) })
	defer resumeOnce()
	var once sync.Once
	f.server.beforeForward = func() {
		once.Do(func() {
			close(paused)
			<-resume
		})
	}
	answer := make(chan struct{})
	go func() {
		f.call(t, http.MethodPost, sid, toolCall(1, "screen.lookup", `{}`, ""), nil)
		close(answer)
	}()
	<-paused
	for i := 0; i < 400; i++ { // saturate the traffic buffer
		f.server.diag("mcp: traffic line %d", i)
	}
	first := f.server.closeAdmission() // closure 1: one pending
	f.server.closeAdmission()          // asked again: where it stands
	f.server.openAdmission()           // reopened before it drained
	<-first
	second := f.server.closeAdmission() // closure 2: still one pending
	select {
	case <-second:
		t.Fatal("closure 2 drained with a forward pending")
	case <-time.After(200 * time.Millisecond):
	}
	resumeOnce()
	<-answer
	<-second
	release() // the stream drains
	want := []string{
		"mcp: admission closed (closure 1); 1 acquisitions forwarded before it have not returned",
		"mcp: admission is closed (closure 1); 1 acquisitions forwarded before it have not returned",
		"mcp: closure 1 ended: admission reopened before it drained",
		"mcp: admission open; closure 1 is over",
		"mcp: admission closed (closure 2); 1 acquisitions forwarded before it have not returned",
		"mcp: closure 2 drained: every acquisition forwarded before it has returned; 0 forwards ended without an answer since the last drain",
	}
	waitUntil(t, "every report", func() bool { return strings.Contains(lines.String(), "closure 2 drained") })
	text := lines.String()
	at := 0
	for _, w := range want {
		i := strings.Index(text[at:], w)
		if i < 0 {
			t.Fatalf("missing, or out of order: %q\n---\n%s", w, text)
		}
		at += i + len(w)
	}
	if strings.Contains(text, "closure 1 drained") {
		t.Fatalf("closure 1's drain was reported after it was reopened:\n%s", text)
	}
	if !strings.Contains(text, "diagnostics were dropped") {
		t.Fatalf("the dropped traffic was not counted:\n%s", text)
	}
	f.server.openAdmission()
}

// net/http's own log lines -- an accept error names the listener's
// address -- reach the diagnostics stream as a category and nothing else.
func TestMCPServerLogCarriesNoAddress(t *testing.T) {
	f := newMCPFixture(t, false)
	diagnostics := &syncBuffer{}
	f.server.log = diagnostics
	srv := f.server.httpServer()
	listener := &failingListener{errs: 3}
	go srv.Serve(listener)
	waitUntil(t, "the accept errors to be reported", func() bool {
		return strings.Count(diagnostics.String(), "could not accept a connection") >= 3
	})
	srv.Close()
	if text := diagnostics.String(); strings.Contains(text, "127.0.0.1") || strings.Contains(text, "8788") || strings.Contains(text, "too many") {
		t.Fatalf("the server's log carried the error's text: %q", text)
	}
	// a handler's panic, and anything else, as categories too
	d := serverDiagnostics{f.server}
	d.Write([]byte("http: panic serving 127.0.0.1:54321: boom\ngoroutine 1 [running]:\n"))
	d.Write([]byte("http: something else at 127.0.0.1:1\n"))
	waitUntil(t, "the panic's category", func() bool { return strings.Contains(diagnostics.String(), "handler panicked") })
	waitUntil(t, "the fallback category", func() bool { return strings.Contains(diagnostics.String(), "the HTTP server reported an error") })
	if strings.Contains(diagnostics.String(), "54321") || strings.Contains(diagnostics.String(), "boom") {
		t.Fatalf("a panic's text reached the stream: %q", diagnostics.String())
	}
}

// failingListener answers Accept with a temporary error that names an
// address, a few times, and then waits to be closed.
type failingListener struct {
	errs   int32
	closed atomic.Bool
}

type temporaryError struct{ error }

func (temporaryError) Temporary() bool { return true }
func (temporaryError) Timeout() bool   { return false }

func (l *failingListener) Accept() (net.Conn, error) {
	if atomic.AddInt32(&l.errs, -1) >= 0 {
		return nil, &net.OpError{Op: "accept", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8788}, Err: temporaryError{errors.New("too many open files")}}
	}
	for !l.closed.Load() {
		time.Sleep(10 * time.Millisecond)
	}
	return nil, net.ErrClosed
}
func (l *failingListener) Close() error { l.closed.Store(true); return nil }
func (l *failingListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8788}
}

// Over HTTP a call is counted when its message has been read whole and is
// admitted, in the one order admission happens: a call whose body was
// slow is counted when it arrives, in the window open then, and a refusal
// never names more than the window's sixty seconds.
func TestMCPHTTPWindowCountsAtAdmission(t *testing.T) {
	f := newMCPFixture(t, false)
	signer, _ := fastSigner(t)
	f.server.signer = signer.URL
	f.server.cfg.mcp.callsPerMinute = 1
	f.server.cfg.mcp.idleSeconds = 86400
	var clock atomic.Int64
	base := time.Now()
	f.server.now = func() time.Time { return base.Add(time.Duration(clock.Load()) * time.Second) }
	sid := f.open(t)
	// the window that opens at 0 is spent
	f.call(t, http.MethodPost, sid, toolCall(1, "screen.lookup", `{}`, ""), nil)
	// A's headers at 59, its body withheld; A's handler is at its body
	// before the clock moves on
	clock.Store(59)
	atBody := make(chan struct{})
	var atBodyOnce sync.Once
	f.server.beforeBody = func() { atBodyOnce.Do(func() { close(atBody) }) }
	conn, err := net.Dial("tcp", strings.TrimPrefix(f.front.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	body := toolCall(2, "screen.lookup", `{}`, "")
	fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: engine.test\r\nContent-Type: application/json\r\nMcp-Session-Id: %s\r\nContent-Length: %d\r\n\r\n%s", mcpEndpoint, sid, len(body), body[:10])
	select {
	case <-atBody:
	case <-time.After(5 * time.Second):
		t.Fatal("A's handler never reached its body")
	}
	// B at 61 opens a new window and spends it
	clock.Store(61)
	if _, _, b := f.call(t, http.MethodPost, sid, toolCall(3, "screen.lookup", `{}`, ""), nil); resultOf(t, b)["isError"] != nil {
		t.Fatalf("B: %v", b)
	}
	// A's body arrives at 62: counted then, in B's window, refused, and the
	// wait it names is that window's
	clock.Store(62)
	fmt.Fprint(conn, body[10:])
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	var answer map[string]any
	json.NewDecoder(resp.Body).Decode(&answer)
	resp.Body.Close()
	structured := sameBothWays(t, resultOf(t, answer))
	if structured["outcome"] != "overload" || structured["retryAfterSeconds"] != float64(59) {
		t.Fatalf("A: %v", structured)
	}
}

// The consumer's ceremony over what the MCP server answered (SPEC §5a):
// seal, verify the whole store under the pinned key with its registry,
// require the verdict, check the answer's receipt under the pin, find it
// among the accepted findings, bind it to the source and session the
// consumer asked for, and re-digest the answer's result against it. The
// other platform's receipt -- valid, verified, accepted -- is refused by
// the same consumer for this platform's answer, and so is a result the
// receipt does not cover.
func TestMCPAnswerThroughTheConsumerCeremony(t *testing.T) {
	f := newMCPFixture(t, false)
	sid := f.open(t)
	meta := `{"` + mcpSessionMeta + `":"consume-1"}`
	_, _, screenBody := f.call(t, http.MethodPost, sid, toolCall(1, "screen.lookup", `{"q":"acme"}`, meta), nil)
	_, _, otherBody := f.call(t, http.MethodPost, sid, toolCall(2, "other.lookup", `{"q":"acme"}`, meta), nil)
	screen := sameBothWays(t, resultOf(t, screenBody))
	other := sameBothWays(t, resultOf(t, otherBody))
	if _, _, sealed := f.call(t, http.MethodPost, sid, toolCall(3, mcpSealTool, `{"session":"consume-1"}`, ""), nil); resultOf(t, sealed)["isError"] != nil {
		t.Fatalf("seal: %v", sealed)
	}
	pinned := pinnedKey(t)
	verdict := ceremonyVerify(t, f.service, pinned)
	if !verdict.OK {
		t.Fatalf("the store does not verify: %v", verdict.Findings)
	}
	consume := func(answer map[string]any, wantSource string) error {
		receiptJSON, _ := json.Marshal(answer["receipt"])
		canonical, err := canonText(receiptJSON)
		if err != nil {
			return err
		}
		var receipt map[string]any
		json.Unmarshal(canonical, &receipt)
		sig, err := hex.DecodeString(fmt.Sprint(receipt["signature"]))
		if err != nil {
			return err
		}
		unsigned := map[string]any{}
		for member, value := range receipt {
			if member != "signature" {
				unsigned[member] = value
			}
		}
		unsignedText, _ := json.Marshal(unsigned)
		unsignedCanon, err := canonText(unsignedText)
		if err != nil {
			return err
		}
		prefix := receiptContext
		if receipt["receiptVersion"] == receiptVersion3 {
			prefix = receiptContext3
		}
		if !ed25519.Verify(pinned, append([]byte(prefix), unsignedCanon...), sig) {
			return errors.New("the receipt does not verify under the pin")
		}
		callIndex, _ := receipt["callIndex"].(float64)
		if !acceptedReceipt(t, verdict, fmt.Sprint(receipt["sessionId"]), callIndex) {
			return errors.New("the receipt is not among the accepted findings")
		}
		if receipt["sessionId"] != "consume-1" || receipt["source"] != wantSource {
			return fmt.Errorf("the receipt is for %v in %v, not %s in consume-1", receipt["source"], receipt["sessionId"], wantSource)
		}
		digestHex := strings.TrimPrefix(fmt.Sprint(receipt["resultDigest"]), "sha256:")
		if !digestHexPattern.MatchString(digestHex) {
			return errors.New("the result digest is not 64 lowercase hex characters")
		}
		resultJSON, _ := json.Marshal(answer["result"])
		resultCanon, err := canonText(resultJSON)
		if err != nil {
			return err
		}
		if sum := sha256.Sum256(resultCanon); hex.EncodeToString(sum[:]) != digestHex {
			return errors.New("the result does not re-digest to the receipt's")
		}
		return nil
	}
	if err := consume(screen, "screen/live"); err != nil {
		t.Fatalf("the screen answer: %v", err)
	}
	if err := consume(other, "other/live"); err != nil {
		t.Fatalf("the other answer, for its own platform: %v", err)
	}
	if err := consume(other, "screen/live"); err == nil || !strings.Contains(err.Error(), "not screen/live") {
		t.Fatalf("the other platform's valid receipt accepted for screen: %v", err)
	}
	forged := map[string]any{"receipt": screen["receipt"], "result": map[string]any{"forged": true}}
	if err := consume(forged, "screen/live"); err == nil || !strings.Contains(err.Error(), "re-digest") {
		t.Fatalf("a result the receipt does not cover accepted: %v", err)
	}
}

// An answer past the bound is not carried: the outcome is unknown, the
// diagnostics say the bound was crossed, and nothing of the answer
// reaches the client.
func TestMCPAnswerPastTheBound(t *testing.T) {
	f := newMCPFixture(t, false)
	diagnostics := &syncBuffer{}
	f.server.log = diagnostics
	big := strings.Repeat("y", mcpMaxAnswerBytes)
	huge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"result":{"blob":"`+big+`"},"receipt":{"kind":"acquisition"},"salts":{}}`)
	}))
	t.Cleanup(huge.Close)
	f.server.signer = huge.URL
	sid := f.open(t)
	_, _, body := f.call(t, http.MethodPost, sid, toolCall(1, "screen.lookup", `{}`, ""), nil)
	r := resultOf(t, body)
	if r["isError"] != true || sameBothWays(t, r)["outcome"] != "unknown" || strings.Contains(fmt.Sprint(body), "yyyy") {
		t.Fatalf("an answer past the bound: %.300v", body)
	}
	waitUntil(t, "the bound's diagnostic", func() bool { return strings.Contains(diagnostics.String(), "the answer exceeded the bound") })
}
