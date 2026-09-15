package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The signer's gate on actions, through /act, authenticated and otherwise
// valid: an action admitted and minted, and one admitted that fails after
// its executor ran, each leave nothing pending; a closed gate answers /act
// 503 and starts no executor; and an action whose executor is held when
// the gate closes keeps the closure from draining until it finishes.
func TestSignerGateOnActions(t *testing.T) {
	service, server := testService(t)
	service.reportsOut = &syncBuffer{}
	service.sources["tickets/write"] = sourceSpec{argv: []string{os.Args[0], "--tools=update_ticket,delete_ticket"}, env: helperEnv, shape: "mcp", tools: []string{"update_ticket", "delete_ticket"}, endpoint: "https://mcp.example/"}
	records := filepath.Join(t.TempDir(), "decisions")
	if err := os.MkdirAll(records, 0o700); err != nil {
		t.Fatal(err)
	}
	service.decisionRecords = records
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	service.identity = &id
	token := issuer.mint(t, "ec-1", nil, goodClaims(time.Now()))
	code, first := authed(t, server, "/acquire", `{"session":"act-g","source":"screening","arguments":{"q":"acme"}}`, token)
	if code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, first)
	}
	signature := first["receipt"].(map[string]any)["signature"].(string)
	line := `{"kind":"evaluation","cites":[{"sessionId":"act-g","callIndex":0,"signature":"` + signature + `"}]}`
	if err := os.WriteFile(filepath.Join(records, "evaluations.jsonl"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	act := `{"session":"act-g","platform":"tickets","tool":"update_ticket","arguments":{"id":"T-1"},` +
		`"decision":{"recordDigest":"sha256:` + hexOf([]byte(line)) + `","packDigest":"sha256:` + strings.Repeat("b", 64) + `"},` +
		`"cites":[{"sessionId":"act-g","callIndex":0,"signature":"` + signature + `"}]}`
	pending := func() int {
		service.mu.Lock()
		defer service.mu.Unlock()
		return service.gate.pending
	}
	env, _ := goodEnvelope()
	envelope := envelopeText(t, env)

	// admitted and minted
	t.Setenv(envSourceEnvelope, envelope)
	if code, body := authed(t, server, "/act", act, token); code != http.StatusOK || body["receipt"].(map[string]any)["kind"] != "action" {
		t.Fatalf("an action with the gate open: %d %v", code, body)
	}
	if n := pending(); n != 0 {
		t.Fatalf("after a minted action, %d pending", n)
	}
	// admitted, and failed after its executor ran
	t.Setenv(envSourceEnvelope, `[]`)
	if code, body := authed(t, server, "/act", act, token); code == http.StatusOK || body["refusedAt"] != nil {
		t.Fatalf("an action whose executor answers no envelope: %d %v", code, body)
	}
	if n := pending(); n != 0 {
		t.Fatalf("after a failed action, %d pending", n)
	}
	// the gate closed: 503, and no executor starts
	started := service.started.Load()
	select {
	case <-service.closeAdmission():
	case <-time.After(time.Second):
		t.Fatal("a closure with nothing admitted did not drain")
	}
	if code, body := authed(t, server, "/act", act, token); code != http.StatusServiceUnavailable || !strings.Contains(fmt.Sprint(body["error"]), "closed for maintenance") {
		t.Fatalf("an action under a closed gate: %d %v", code, body)
	}
	if service.started.Load() != started {
		t.Fatal("an executor started under a closed gate")
	}
	service.openAdmission()
	// an action whose executor is held when the gate closes
	t.Setenv(envSourceEnvelope, envelope)
	barrier := t.TempDir()
	t.Setenv(envSourceReady, filepath.Join(barrier, "started"))
	t.Setenv(envSourceWait, filepath.Join(barrier, "release"))
	held := make(chan int, 1)
	go func() { code, _ := authed(t, server, "/act", act, token); held <- code }()
	waitForFile(t, filepath.Join(barrier, "started"))
	closure := service.closeAdmission()
	select {
	case <-closure:
		t.Fatal("the closure drained with an action in flight")
	case <-time.After(200 * time.Millisecond):
	}
	if n := pending(); n != 1 {
		t.Fatalf("with an action in flight, %d pending", n)
	}
	os.WriteFile(filepath.Join(barrier, "release"), []byte("go"), 0o600)
	if code := <-held; code != http.StatusOK {
		t.Fatalf("the action in flight when the gate closed: %d", code)
	}
	select {
	case <-closure:
	case <-time.After(5 * time.Second):
		t.Fatal("the closure did not drain once the action finished")
	}
	if n := pending(); n != 0 {
		t.Fatalf("after the drain, %d pending", n)
	}
	t.Setenv(envSourceWait, "")
	t.Setenv(envSourceReady, "")
	service.openAdmission()
}
