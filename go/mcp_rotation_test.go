package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// keysOf is an identity holding the named keys of the issuer's set alone.
func keysOf(t *testing.T, issuer *testIssuer, kids ...string) identityConfig {
	t.Helper()
	id := identityFor(t, issuer)
	kept := map[string]publicKey{}
	for _, kid := range kids {
		kept[kid] = id.keys[kid]
	}
	id.keys = kept
	return id
}

// The rotation contract of the note, in order, at the frontend: the new
// key beside the old at the frontend first; admission closed, under which
// a new transport session is 503, a new acquisition an overload, a queued
// one woken and refused, and a seal goes on; the signer's own refusal to
// seal a session with an acquisition in flight as the drain signal, and
// /seal directly under the operator's token; the signer restarted; the old
// key retired in both orders, and the stale key.
func TestMCPRotationSequence(t *testing.T) {
	f := newMCPFixture(t, true)
	const old, new = "ec-1", "ed-1"
	oldToken := f.issuer.mint(t, old, nil, goodClaims(time.Now()))
	newToken := f.issuer.mint(t, new, nil, goodClaims(time.Now()))
	setKeys := func(front, signer identityConfig) {
		f.server.identity = &front
		f.service.identity = &signer
	}
	setKeys(keysOf(t, f.issuer, old), keysOf(t, f.issuer, old))
	f.token = oldToken
	sid := f.open(t)
	meta := `{"` + mcpSessionMeta + `":"kept-1"}`
	// the token rides in the request's own header, so concurrent calls
	// share nothing but the fixture
	acquire := func(id int, token string) (int, http.Header, map[string]any) {
		return f.call(t, http.MethodPost, sid, toolCall(id, "screen.lookup", `{}`, meta), map[string]string{"Authorization": "Bearer " + token})
	}
	if _, _, body := acquire(1, oldToken); resultOf(t, body)["isError"] != nil {
		t.Fatalf("under the old key: %v", body)
	}
	// 1. the new key beside the old, the frontend restarted: the old token
	// still works end to end; the new one passes the frontend and is the
	// signer's refusal, made the transport's
	setKeys(keysOf(t, f.issuer, old, new), keysOf(t, f.issuer, old))
	if _, _, body := acquire(2, oldToken); resultOf(t, body)["isError"] != nil {
		t.Fatalf("the old token after the frontend's restart: %v", body)
	}
	if code, header, _ := acquire(3, newToken); code != http.StatusUnauthorized || !strings.HasPrefix(header.Get("WWW-Authenticate"), "Bearer resource_metadata=") {
		t.Fatalf("the new token before the signer's restart: %d %q", code, header.Get("WWW-Authenticate"))
	}
	if f.receiptsOf("kept-1") != 2 {
		t.Fatalf("kept-1 holds %d receipts", f.receiptsOf("kept-1"))
	}
	// 2. close admission, with an acquisition in flight and one queued
	f.server.forwards = make(chan struct{}, 1)
	f.server.queue = make(chan struct{}, 1)
	barrier := t.TempDir()
	release := filepath.Join(barrier, "release")
	t.Setenv(envSourceWait, release)
	t.Setenv(envSourceReady, filepath.Join(barrier, "started"))
	answers := make(chan map[string]any, 2)
	var wg sync.WaitGroup
	launch := func(id int) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, body := acquire(id, oldToken)
			answers <- resultOf(t, body)
		}()
	}
	launch(10)
	waitForFile(t, filepath.Join(barrier, "started"))
	launch(11)
	waitUntil(t, "the second call to queue", func() bool { return len(f.server.queue) == 1 })
	f.server.closeAdmission()
	// the queued call is woken and refused at once, before the barrier lifts
	select {
	case woken := <-answers:
		if woken["isError"] != true || !strings.Contains(sameBothWays(t, woken)["error"].(string), "closed for maintenance while the call waited") {
			t.Fatalf("the queued call under closed admission: %v", woken)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the queued call was not woken when admission closed")
	}
	// a new transport session is 503; a new acquisition is an overload,
	// nothing forwarded
	if code, _, _ := f.call(t, http.MethodPost, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`, nil); code != http.StatusServiceUnavailable {
		t.Fatalf("initialize under closed admission answered %d", code)
	}
	_, _, body := acquire(12, oldToken)
	if refused := resultOf(t, body); refused["isError"] != true || sameBothWays(t, refused)["outcome"] != "overload" || sameBothWays(t, refused)["session"] != "kept-1" || !strings.HasPrefix(sameBothWays(t, refused)["error"].(string), "admission is closed for maintenance") {
		t.Fatalf("an acquisition under closed admission: %v", refused)
	}
	// the drain signal: /seal directly on the signer's loopback surface,
	// under the operator's own token, is refused while the acquisition is
	// in flight, and succeeds once it is not
	sealDirectly := func() int {
		req, _ := http.NewRequest(http.MethodPost, f.signer.URL+"/seal", strings.NewReader(`{"session":"kept-1"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+oldToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := sealDirectly(); code == http.StatusOK {
		t.Fatal("/seal succeeded with an acquisition in flight")
	}
	os.WriteFile(release, []byte("go"), 0o600)
	wg.Wait()
	close(answers)
	for a := range answers {
		if a["isError"] != nil {
			t.Fatalf("the acquisition in flight when admission closed: %v", a)
		}
	}
	t.Setenv(envSourceWait, "")
	t.Setenv(envSourceReady, "")
	if code := sealDirectly(); code != http.StatusOK {
		t.Fatalf("/seal directly, quiet, answered %d", code)
	}
	if f.receiptsOf("kept-1") != 3 {
		t.Fatalf("kept-1 holds %d receipts after the drain, not 3", f.receiptsOf("kept-1"))
	}
	// under closed admission a seal through the tool goes on too: a quiet
	// named session from before is sealed by a transport session that
	// survived, and the sealed one refuses another seal
	_, _, body = f.call(t, http.MethodPost, sid, toolCall(13, mcpSealTool, `{"session":"kept-1"}`, ""), nil)
	if sealing := resultOf(t, body); sealing["isError"] != true || !strings.Contains(sameBothWays(t, sealing)["error"].(string), "sealed") {
		t.Fatalf("sealing the sealed session through the closed frontend: %v", sealing)
	}
	// 3. the signer restarted under both keys; admission reopened; the new
	// token works end to end, and so does the old until retired
	setKeys(keysOf(t, f.issuer, old, new), keysOf(t, f.issuer, old, new))
	f.server.openAdmission()
	sid = f.open(t)
	meta = `{"` + mcpSessionMeta + `":"kept-2"}`
	for id, token := range map[int]string{20: newToken, 21: oldToken} {
		if _, _, body := acquire(id, token); resultOf(t, body)["isError"] != nil {
			t.Fatalf("token %d after the reopen: %v", id, body)
		}
	}
	// 4. retiring the old key in the contract's order: frontend first,
	// then the signer -- the old token is the frontend's refusal
	setKeys(keysOf(t, f.issuer, new), keysOf(t, f.issuer, old, new))
	if code, _, _ := acquire(22, oldToken); code != http.StatusUnauthorized {
		t.Fatalf("the old token after the frontend retired it: %d", code)
	}
	setKeys(keysOf(t, f.issuer, new), keysOf(t, f.issuer, new))
	if code, _, _ := acquire(23, oldToken); code != http.StatusUnauthorized {
		t.Fatalf("the old token after both retired it: %d", code)
	}
	if _, _, body := acquire(24, newToken); resultOf(t, body)["isError"] != nil {
		t.Fatalf("the new token after the retirement: %v", body)
	}
	// and in the other order, a stale key at the frontend: the signer
	// retired it first, the frontend still accepts it, and the signer's
	// refusal is the transport's
	setKeys(keysOf(t, f.issuer, old, new), keysOf(t, f.issuer, new))
	if code, header, _ := acquire(25, oldToken); code != http.StatusUnauthorized || !strings.HasPrefix(header.Get("WWW-Authenticate"), "Bearer resource_metadata=") {
		t.Fatalf("the stale key: %d %q", code, header.Get("WWW-Authenticate"))
	}
	if f.receiptsOf("kept-2") != 3 {
		t.Fatalf("kept-2 holds %d receipts, not 3", f.receiptsOf("kept-2"))
	}
	// closing twice and opening twice are idempotent
	f.server.closeAdmission()
	f.server.closeAdmission()
	f.server.openAdmission()
	f.server.openAdmission()
	if closed, _ := f.server.admission(); closed {
		t.Fatal("admission stayed closed")
	}
}
