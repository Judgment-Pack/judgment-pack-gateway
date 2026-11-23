package main

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// A caller that reaches scope B alone and names no scope is refused at the
// scope step (ADR-0054, steps 8 and 9), before its session is looked up in
// the namespace of none, which it does not reach: a sealed and an open
// session of none answer it the same, status and body.
func TestActScopeNoScopeFromACallerThatDoesNotReachNone(t *testing.T) {
	h := actScopeSetup(t)
	if code, out := authed(t, h.server, "/acquire", `{"session":"u-open","source":"screening","arguments":{"q":"acme"}}`, h.tokenBoth); code != http.StatusOK {
		t.Fatalf("the open unscoped read: %d %v", code, out)
	}
	if code, out := authed(t, h.server, "/seal", `{"session":"u-read"}`, h.tokenBoth); code != http.StatusOK {
		t.Fatalf("sealing the unscoped read: %d %v", code, out)
	}
	key := strings.Repeat("c", 64)
	for _, platform := range []string{"tickets", "tickets-b"} {
		sealedCode, sealed := authed(t, h.server, "/act", h.body("u-read", platform, "", key, h.decisionU, h.cite("u-read", h.unscopedSig)), h.tokenB)
		openCode, open := authed(t, h.server, "/act", h.body("u-open", platform, "", key, h.decisionU, h.cite("u-read", h.unscopedSig)), h.tokenB)
		if sealedCode != openCode || !reflect.DeepEqual(sealed, open) {
			t.Errorf("%s: a sealed and an open session of none answer differently: %d %v and %d %v", platform, sealedCode, sealed, openCode, open)
		}
		if sealedCode != http.StatusBadRequest || sealed["refusedAt"] != "scope-identifier" || sealed["error"] != scopeRefusal {
			t.Errorf("%s: %d %v, want 400 at scope-identifier with the scope sentence", platform, sealedCode, sealed)
		}
	}
	if n := journalFiles(t, h.g.storeRoot); n != 0 {
		t.Fatalf("the journal holds %d file(s) after a refusal", n)
	}
}
