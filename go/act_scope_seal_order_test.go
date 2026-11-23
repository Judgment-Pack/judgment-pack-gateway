package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// answerWithout is an answer with a session id put out of it, so that two
// answers about two sessions compare as the same sentence.
func answerWithout(code int, out map[string]any, session string) string {
	return fmt.Sprintf("%d %v", code, strings.ReplaceAll(fmt.Sprint(out), session, "<session>"))
}

// /act into a session of another scope answers ADR-0036's sentence before
// the seal is looked at (ADR-0054, §6): a sealed and an open session of
// scope B answer a request of none the same, and a sealed and an open
// session of none answer a request of scope B the same.
func TestActScopeSessionOfAnotherScopeBeforeItsSeal(t *testing.T) {
	h := actScopeSetup(t)
	if code, out := authed(t, h.server, "/acquire", acquireBodyFor("b-open", "scoped-b", callerScopeB), h.tokenB); code != http.StatusOK {
		t.Fatalf("scope B's open read: %d %v", code, out)
	}
	if code, out := authed(t, h.server, "/acquire", `{"session":"u-open","source":"screening","arguments":{"q":"acme"}}`, h.tokenBoth); code != http.StatusOK {
		t.Fatalf("the open unscoped read: %d %v", code, out)
	}
	for _, session := range []string{"b-read", "u-read"} {
		if code, out := authed(t, h.server, "/seal", `{"session":"`+session+`"}`, h.tokenBoth); code != http.StatusOK {
			t.Fatalf("sealing %s: %d %v", session, code, out)
		}
	}
	key := strings.Repeat("d", 64)
	for _, c := range []struct {
		name, sealed, open, platform, scope, decision, cites, token string
	}{
		{"an action of none into scope B's sessions", "b-read", "b-open", "tickets", "", h.decisionU, h.cite("u-read", h.unscopedSig), h.tokenA},
		{"an action of scope B into sessions of none", "u-read", "u-open", "tickets-b", scopeB, h.decisionB, h.cite("b-read", h.scopedSig), h.tokenBoth},
	} {
		sealedCode, sealed := authed(t, h.server, "/act", h.body(c.sealed, c.platform, c.scope, key, c.decision, c.cites), c.token)
		openCode, open := authed(t, h.server, "/act", h.body(c.open, c.platform, c.scope, key, c.decision, c.cites), c.token)
		if answerWithout(sealedCode, sealed, c.sealed) != answerWithout(openCode, open, c.open) {
			t.Errorf("%s: a sealed and an open session answer differently: %d %v and %d %v", c.name, sealedCode, sealed, openCode, open)
		}
		if sealedCode != http.StatusBadRequest || sealed["refusedAt"] != "session" || sealed["error"] != fmt.Sprintf(refusalActionInScope, c.sealed) {
			t.Errorf("%s: %d %v, want 400 at session with ADR-0036's sentence", c.name, sealedCode, sealed)
		}
	}
	if n := journalFiles(t, h.g.storeRoot); n != 0 {
		t.Fatalf("the journal holds %d file(s) after a refusal", n)
	}
}

// /acquire into a session this process holds of another scope answers
// ADR-0036's sentence before the seal is looked at: a sealed and an open
// session of scope B answer an acquisition of none the same.
func TestAcquireSessionOfAnotherScopeBeforeItsSeal(t *testing.T) {
	h := actScopeSetup(t)
	if code, out := authed(t, h.server, "/acquire", acquireBodyFor("b-open", "scoped-b", callerScopeB), h.tokenB); code != http.StatusOK {
		t.Fatalf("scope B's open read: %d %v", code, out)
	}
	if code, out := authed(t, h.server, "/seal", `{"session":"b-read"}`, h.tokenB); code != http.StatusOK {
		t.Fatalf("sealing scope B's read: %d %v", code, out)
	}
	ask := func(session string) (int, map[string]any) {
		return authed(t, h.server, "/acquire", `{"session":"`+session+`","source":"screening","arguments":{"q":"acme"}}`, h.tokenA)
	}
	sealedCode, sealed := ask("b-read")
	openCode, open := ask("b-open")
	if answerWithout(sealedCode, sealed, "b-read") != answerWithout(openCode, open, "b-open") {
		t.Errorf("a sealed and an open session of scope B answer differently: %d %v and %d %v", sealedCode, sealed, openCode, open)
	}
	if sealedCode != http.StatusBadRequest || !strings.Contains(fmt.Sprint(sealed["error"]), fmt.Sprintf(refusalOtherScope, "b-read")) {
		t.Errorf("%d %v, want 400 with ADR-0036's sentence", sealedCode, sealed)
	}
}
