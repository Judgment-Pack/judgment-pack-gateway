package main

import (
	"bytes"
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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The signer's gate is the barrier a closure needs: a request that was in
// transit when the MCP server's forward gave up -- held at the signer's
// door, not yet admitted -- is refused when it arrives after the signer's
// gate closed, and opens no session. Without the signer's gate the same
// request is admitted after the MCP server's closure drained, which is why
// the rotation contract closes the signer's.
func TestSignerGateIsTheBarrierForWhatWasInTransit(t *testing.T) {
	for _, closeSigner := range []bool{true, false} {
		t.Run(fmt.Sprintf("signer gate closed %v", closeSigner), func(t *testing.T) {
			f := newMCPFixture(t, false)
			frontReports, signerReports := &syncBuffer{}, &syncBuffer{}
			f.server.log = frontReports
			f.service.reportsOut = signerReports
			f.server.forwardTimeout = 200 * time.Millisecond
			sid := f.open(t)
			held := make(chan struct{})
			let := make(chan struct{})
			letOnce := sync.OnceFunc(func() { close(let) })
			defer letOnce()
			var once sync.Once
			admitted := make(chan struct{})
			f.service.beforeReadAdmit = func() {
				once.Do(func() {
					close(held)
					<-let
					defer close(admitted)
				})
			}
			// the forward gives up; the request is at the signer's door
			_, _, body := f.call(t, http.MethodPost, sid, toolCall(1, "screen.lookup", `{}`, `{"`+mcpSessionMeta+`":"transit-1"}`), nil)
			<-held
			if r := resultOf(t, body); sameBothWays(t, r)["outcome"] != "unknown" {
				t.Fatalf("the forward that gave up: %v", r)
			}
			// the MCP server's closure drains -- and says the forward it
			// cannot vouch for is the signer's to say
			select {
			case <-f.server.closeAdmission():
			case <-time.After(2 * time.Second):
				t.Fatal("the MCP server's closure did not drain")
			}
			waitUntil(t, "the MCP server's drain", func() bool {
				return strings.Contains(frontReports.String(), "mcp: closure 1 drained") && strings.Contains(frontReports.String(), "1 forwards ended without an answer since the last drain")
			})
			if closeSigner {
				select {
				case <-f.service.closeAdmission():
				case <-time.After(2 * time.Second):
					t.Fatal("the signer's closure did not drain with nothing admitted")
				}
				waitUntil(t, "the signer's drain", func() bool { return strings.Contains(signerReports.String(), "serve: closure 1 drained") })
			}
			letOnce()
			<-admitted
			time.Sleep(100 * time.Millisecond) // let a request admitted run to its receipt
			f.service.mu.Lock()
			_, opened := f.service.sessions["transit-1"]
			f.service.mu.Unlock()
			if closeSigner && (f.receiptsOf("transit-1") != 0 || opened) {
				t.Fatalf("a request in transit was admitted after the signer's gate closed: %d receipts, opened %v", f.receiptsOf("transit-1"), opened)
			}
			if !closeSigner {
				waitUntil(t, "the request in transit to be admitted", func() bool { return f.receiptsOf("transit-1") == 1 })
			}
			f.service.openAdmission()
			f.server.openAdmission()
		})
	}
}

// The signer's gate: closed, an acquisition is refused 503 and an action
// is refused at admission, and a seal goes on; a closure waits for what
// was admitted before it, reports each transition with its number, and a
// reopening admits again.
func TestSignerGate(t *testing.T) {
	f := newMCPFixture(t, false)
	reports := &syncBuffer{}
	f.service.reportsOut = reports
	acquire := func(session string) (int, map[string]any) {
		return post(t, f.signer, "/acquire", `{"session":"`+session+`","source":"screen/live","arguments":{"tool":"lookup","arguments":{}}}`)
	}
	if code, body := acquire("gate-1"); code != http.StatusOK {
		t.Fatalf("an open gate: %d %v", code, body)
	}
	// an acquisition in flight when the gate closes
	barrier := t.TempDir()
	t.Setenv(envSourceReady, filepath.Join(barrier, "started"))
	t.Setenv(envSourceWait, filepath.Join(barrier, "release"))
	inFlight := make(chan int, 1)
	go func() { code, _ := acquire("gate-2"); inFlight <- code }()
	waitForFile(t, filepath.Join(barrier, "started"))
	closure := f.service.closeAdmission()
	select {
	case <-closure:
		t.Fatal("the signer's closure drained with an acquisition in flight")
	case <-time.After(200 * time.Millisecond):
	}
	if code, body := acquire("gate-3"); code != http.StatusServiceUnavailable || !strings.Contains(fmt.Sprint(body["error"]), "closed for maintenance") {
		t.Fatalf("an acquisition under a closed gate: %d %v", code, body)
	}
	if err := f.service.admitAction("gate-4"); !errors.As(err, new(unavailable)) {
		t.Fatalf("an action under a closed gate: %v", err)
	}
	if code, body := post(t, f.signer, "/seal", `{"session":"gate-1"}`); code != http.StatusOK {
		t.Fatalf("a seal under a closed gate: %d %v", code, body)
	}
	os.WriteFile(filepath.Join(barrier, "release"), []byte("go"), 0o600)
	if code := <-inFlight; code != http.StatusOK {
		t.Fatalf("the acquisition admitted before the closure: %d", code)
	}
	select {
	case <-closure:
	case <-time.After(5 * time.Second):
		t.Fatal("the signer's closure did not drain once the acquisition finished")
	}
	t.Setenv(envSourceWait, "")
	t.Setenv(envSourceReady, "")
	f.service.closeAdmission() // asked again
	f.service.openAdmission()
	if code, body := acquire("gate-5"); code != http.StatusOK {
		t.Fatalf("after the reopening: %d %v", code, body)
	}
	for _, dir := range []string{"gate-3", "gate-4"} {
		if _, err := os.Stat(filepath.Join(f.root, "store", "receipts", dir)); err == nil {
			t.Fatalf("a refused admission made %s", dir)
		}
	}
	want := []string{
		"serve: admission closed (closure 1); 1 acquisitions and actions admitted and not finished",
		"serve: closure 1 drained: nothing admitted is in flight, and nothing will be admitted until admission reopens",
		"serve: admission is closed (closure 1) and drained",
		"serve: admission open; closure 1 is over",
	}
	waitUntil(t, "the signer's reports", func() bool { return strings.Contains(reports.String(), "closure 1 is over") })
	text, at := reports.String(), 0
	for _, w := range want {
		i := strings.Index(text[at:], w)
		if i < 0 {
			t.Fatalf("missing, or out of order: %q\n---\n%s", w, text)
		}
		at += i + len(w)
	}
}

// A queued call whose wait ran out before its work began is an overload,
// with a slot free and nothing forwarded.
func TestMCPExpiredWaitIsNotForwarded(t *testing.T) {
	f := newMCPFixture(t, false)
	signer, bodies := fastSigner(t)
	f.server.signer = signer.URL
	sid := f.open(t)
	sess := f.server.sessions[sid]
	f.server.cfg.mcp.callsPerMinute = 6000
	f.server.queueWait = 20 * time.Millisecond
	// twenty rounds: a wait that ran out and a free slot are both ready
	// at once, and whichever a select would take, nothing is forwarded
	for round := 0; round < 20; round++ {
		admitted := f.server.admit(sess, "", []byte(toolCall(round, "screen.lookup", `{}`, "")))
		time.Sleep(40 * time.Millisecond)
		outcome := admitted.run(context.Background())
		var answer map[string]any
		json.Unmarshal(outcome.response, &answer)
		if r := resultOf(t, answer); !strings.Contains(sameBothWays(t, r)["error"].(string), "no forward slot within") {
			t.Fatalf("round %d, an expired wait: %v", round, r)
		}
	}
	if len(bodies()) != 0 || len(f.server.queue) != 0 || len(f.server.forwards) != 0 {
		t.Fatalf("forwarded %d, queue %d, slots %d", len(bodies()), len(f.server.queue), len(f.server.forwards))
	}
}

// A message that is not UTF-8 is refused over stdio as over HTTP, and is
// never answered with a repaired id.
func TestMCPStdioRefusesWhatIsNotUTF8(t *testing.T) {
	f := newMCPFixture(t, false)
	out := &bytes.Buffer{}
	in := "{\"jsonrpc\":\"2.0\",\"id\":\"a\xffb\",\"method\":\"ping\"}\n"
	if err := f.server.serveStdio(context.Background(), strings.NewReader(in), out, ""); err != nil {
		t.Fatal(err)
	}
	var answer map[string]any
	if err := json.Unmarshal(out.Bytes(), &answer); err != nil {
		t.Fatalf("not JSON: %q", out.String())
	}
	if e, ok := answer["error"].(map[string]any); !ok || e["code"] != float64(rpcParse) || answer["id"] != nil || strings.Contains(out.String(), "�") {
		t.Fatalf("a message that is not UTF-8: %s", out.String())
	}
}

// The duplicate walk does linear work: a deeply nested message is walked
// without building its ancestors' path at every value.
func TestDuplicateWalkIsLinear(t *testing.T) {
	const depth = 9000
	deep := []byte(strings.Repeat(`{"a":`, depth) + "1" + strings.Repeat("}", depth))
	for _, skip := range [][][]string{nil, {{"params", "arguments"}}} {
		before := walkPathSteps.Load()
		if err := noDuplicateMembers(deep, skip); err != nil {
			t.Fatal(err)
		}
		if steps := walkPathSteps.Load() - before; steps > 16 {
			t.Fatalf("skip %v: %d ancestor steps for a %d-deep message", skip, steps, depth)
		}
	}
}

func BenchmarkDuplicateWalkDeep(b *testing.B) {
	for _, depth := range []int{1000, 9000} {
		deep := []byte(strings.Repeat(`{"a":`, depth) + "1" + strings.Repeat("}", depth))
		b.Run(fmt.Sprint(depth), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				noDuplicateMembers(deep, [][]string{{"params", "arguments"}})
			}
		})
	}
}

// The consumer's ceremony binds the call it intended, not only the
// platform: the tool and the arguments, opened from the receipt's salted
// commitment, and the principal the receipt names. A receipt for another
// tool of the same platform, for other arguments, for another principal,
// with a signature that does not verify, or not in the verified store is
// refused -- each through the same consumer.
func TestMCPConsumerBindsTheIntendedCall(t *testing.T) {
	f := newMCPFixture(t, true)
	sid := f.open(t)
	meta := `{"` + mcpSessionMeta + `":"intend-1"}`
	call := func(id int, tool, args, token string) map[string]any {
		_, _, body := f.call(t, http.MethodPost, sid, toolCall(id, tool, args, meta), map[string]string{"Authorization": "Bearer " + token})
		return sameBothWays(t, resultOf(t, body))
	}
	other := goodClaims(time.Now())
	other["sub"] = "user-8"
	otherToken := f.issuer.mint(t, "ec-1", nil, other)
	intended := call(1, "screen.lookup", `{"q":"acme"}`, f.token)
	sameTool := call(2, "screen.search", `{"q":"acme"}`, f.token)
	otherArgs := call(3, "screen.lookup", `{"q":"globex"}`, f.token)
	otherPrincipal := call(4, "screen.lookup", `{"q":"acme"}`, otherToken)
	if _, _, sealed := f.call(t, http.MethodPost, sid, toolCall(5, mcpSealTool, `{"session":"intend-1"}`, ""), nil); resultOf(t, sealed)["isError"] != nil {
		t.Fatalf("seal: %v", sealed)
	}
	// a receipt under the same key, from another store: valid, and no
	// member of this one
	elsewhere := newMCPFixture(t, true)
	elsewhere.token = elsewhere.issuer.mint(t, "ec-1", nil, goodClaims(time.Now()))
	esid := elsewhere.open(t)
	_, _, eb := elsewhere.call(t, http.MethodPost, esid, toolCall(1, "screen.lookup", `{"q":"acme"}`, `{"`+mcpSessionMeta+`":"elsewhere-1"}`), nil)
	nonmember := sameBothWays(t, resultOf(t, eb))

	pinned := pinnedKey(t)
	verdict := ceremonyVerify(t, f.service, pinned)
	if !verdict.OK {
		t.Fatalf("the store does not verify: %v", verdict.Findings)
	}
	type intent struct {
		source, tool, arguments, issuer, subject string
	}
	want := intent{"screen/live", "lookup", `{"q":"acme"}`, "https://login.example", "user-7"}
	consume := func(answer map[string]any, want intent) error {
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
		if receipt["sessionId"] != "intend-1" || receipt["source"] != want.source {
			return fmt.Errorf("the receipt is for %v in %v", receipt["source"], receipt["sessionId"])
		}
		// the intended call: the tool and the arguments, opened from the
		// salted commitment with the salt the answer carried
		salts, _ := answer["salts"].(map[string]any)
		salt, err := hex.DecodeString(fmt.Sprint(salts["args"]))
		if err != nil {
			return err
		}
		wrapper, err := canonText([]byte(`{"tool":"` + want.tool + `","arguments":` + want.arguments + `}`))
		if err != nil {
			return err
		}
		if receipt["argumentsCommitment"] != commitmentOver(salt, "args:", wrapper) {
			return errors.New("the receipt commits to another call")
		}
		// the principal
		who, _ := receipt["caller"].(map[string]any)
		if who == nil || who["issuer"] != want.issuer || who["subject"] != want.subject {
			return fmt.Errorf("the receipt names another principal: %v", receipt["caller"])
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
	if err := consume(intended, want); err != nil {
		t.Fatalf("the intended call: %v", err)
	}
	tampered := map[string]any{"receipt": map[string]any{}, "result": intended["result"], "salts": intended["salts"]}
	for k, v := range intended["receipt"].(map[string]any) {
		tampered["receipt"].(map[string]any)[k] = v
	}
	tampered["receipt"].(map[string]any)["observedAt"] = "2000-01-01T00:00:00Z"
	for name, c := range map[string]struct {
		answer map[string]any
		says   string
	}{
		"another tool of the same platform": {sameTool, "commits to another call"},
		"other arguments":                   {otherArgs, "commits to another call"},
		"another principal":                 {otherPrincipal, "another principal"},
		"a signature that does not verify":  {tampered, "does not verify under the pin"},
		"a receipt from another store":      {nonmember, "not among the accepted findings"},
	} {
		if err := consume(c.answer, want); err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The command's serving paths never wait on stderr: with a stderr that
// never drains, --http serves and ends when its context does, and --stdio
// answers and ends when its input does, each within the second the last
// words are given.
func TestMCPCommandServesWithAStderrThatNeverDrains(t *testing.T) {
	issuer := newIssuer(t)
	keys := filepath.Join(t.TempDir(), "keys.json")
	os.WriteFile(keys, issuer.keySet(), 0o600)
	catalog := t.TempDir()
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	config := filepath.Join(t.TempDir(), "engine.json")
	text := engineJSON(t, catalog, fmt.Sprintf(`,"mcp":{"listen":"127.0.0.1:%d","resource":"https://engine.test/mcp"},"identity":{"issuer":"https://login.example","audience":"gateway:acme","keys":"%s"}`, port, abs(t, keys)), ``)
	os.WriteFile(config, []byte(strings.Replace(text, `"engineVersion":"1"`, `"engineVersion":"2"`, 1)), 0o600)
	stderr := &gatedWriter{release: make(chan struct{})}
	stderr.n = 1 // every write blocks
	defer close(stderr.release)
	reach := mcpReachHost{euid: frontendUID, gid: frontendUID, groups: func() ([]int, error) { return nil, nil }, caps: func() (bool, string) { return true, "" }, open: func(string) error { return os.ErrPermission }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- runMCP(ctx, []string{"--config", config, "--http"}, strings.NewReader(""), io.Discard, stderr, reach)
	}()
	waitUntil(t, "the transport to serve", func() bool {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/.well-known/oauth-protected-resource/mcp", port))
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("--http did not end with its context while stderr was blocked")
	}
	// --stdio, identity-free
	stdioText := engineJSON(t, catalog, fmt.Sprintf(`,"mcp":{"listen":"127.0.0.1:%d"}`, port), ``)
	stdioConfig := filepath.Join(t.TempDir(), "engine.json")
	os.WriteFile(stdioConfig, []byte(strings.Replace(stdioText, `"engineVersion":"1"`, `"engineVersion":"2"`, 1)), 0o600)
	out := &bytes.Buffer{}
	go func() {
		done <- runMCP(context.Background(), []string{"--config", stdioConfig, "--stdio"}, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"), out, stderr, reach)
	}()
	select {
	case code := <-done:
		if code != 0 || !strings.Contains(out.String(), `"id":1`) {
			t.Fatalf("--stdio: %d %q", code, out.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("--stdio did not end with its input while stderr was blocked")
	}
}

// A panic between the gate's last word and the forward still gives back
// the slot and the pending count: the closure that follows drains at once.
func TestMCPPanicKeepsTheGateBalanced(t *testing.T) {
	f := newMCPFixture(t, false)
	f.server.log = io.Discard
	sid := f.open(t)
	var once sync.Once
	f.server.beforeForward = func() { once.Do(func() { panic("a forward that panics") }) }
	req, _ := http.NewRequest(http.MethodPost, f.front.URL+mcpEndpoint, strings.NewReader(toolCall(1, "screen.lookup", `{}`, "")))
	req.Header.Set("Mcp-Session-Id", sid)
	req.Header.Set("Content-Type", "application/json")
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
	}
	f.server.mu.Lock()
	pending := f.server.gate.pending
	f.server.mu.Unlock()
	if pending != 0 || len(f.server.forwards) != 0 || len(f.server.queue) != 0 {
		t.Fatalf("after a panic: pending %d, slots %d, queue %d", pending, len(f.server.forwards), len(f.server.queue))
	}
	select {
	case <-f.server.closeAdmission():
	case <-time.After(time.Second):
		t.Fatal("the closure after a panic did not drain")
	}
	f.server.openAdmission()
}
