package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An action's citations are resolved within the caller's reach (ADR-0037):
// a session of a scope identifier the caller does not reach is answered as
// one the store does not hold, whatever receipt index and signature the
// citation names -- the head signature the open /registry lists for its v2
// seal among them -- so no unscoped action can cite into it, and removing
// its scope identifier is never held up by one.
func TestActCitationsHeldToTheCallersReach(t *testing.T) {
	if !actionJournalSupported {
		t.Skip("the action journal needs this platform's directory sync")
	}
	t.Setenv(envSourceHelper, "1")
	root := t.TempDir()
	actionKeysMode(t, root, "write", "respond")
	actionKeysMode(t, root, "live", "read")
	sources := actionKeysSources(t, root, os.Args[0])
	sources["scoped-b"] = sourceSpec{argv: []string{os.Args[0]}, env: helperEnv, scope: callerScopeB}
	g := actionKeysService(t, root, sources)
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	id.callers = callerScopes{entries: map[string]callerEntry{
		subjectB: {grants: map[string]bool{callerScopeB: true}},
		subjectA: {grants: map[string]bool{callerScopeA: true, unscopedMarker: true}},
	}}
	g.identity = &id
	server := httptest.NewServer(g.handler())
	defer server.Close()
	tokenB := tokenFor(t, issuer, subjectB, []any{callerScopeB})
	// a subject with no entry reaches the sources of none alone
	tokenU := tokenFor(t, issuer, "subject-with-no-entry", nil)
	tokenA := tokenFor(t, issuer, subjectA, []any{callerScopeA, unscopedMarker})

	var sigs []string
	for i := 0; i < 2; i++ {
		code, out := authed(t, server, "/acquire", acquireBodyFor("s-b", "scoped-b", callerScopeB), tokenB)
		if code != http.StatusOK {
			t.Fatalf("scope B's acquisition: %d %v", code, out)
		}
		sigs = append(sigs, out["receipt"].(map[string]any)["signature"].(string))
	}
	code, out := authed(t, server, "/acquire", `{"session":"u-read","source":"screening","arguments":{"q":"acme"}}`, tokenU)
	if code != http.StatusOK {
		t.Fatalf("the unscoped acquisition: %d %v", code, out)
	}
	uSig := out["receipt"].(map[string]any)["signature"].(string)
	line := `{"kind":"evaluation","cites":[{"sessionId":"u-read","callIndex":0,"signature":"` + uSig + `"}]}`
	if err := os.MkdirAll(g.decisionRecords, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(g.decisionRecords, "decision.json"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	record := digestOf(line)
	n := 0
	act := func(token, session, citeSession string, idx int64, sig string) (int, map[string]any) {
		n++
		key := fmt.Sprintf("%064x", n)
		body := `{"session":"` + session + `","platform":"tickets","tool":"query","arguments":{"ticket":"T-1"},"decision":{"recordDigest":"` + record + `","packDigest":"sha256:` + strings.Repeat("d", 64) + `"},"cites":[{"sessionId":"` + citeSession + `","callIndex":` + fmt.Sprint(idx) + `,"signature":"` + sig + `"}],"actionKey":"` + key + `"}`
		return authed(t, server, "/act", body, token)
	}
	absent := func(session string, idx int64) string {
		return fmt.Sprintf("citation %s/%d does not resolve in this engine's store: no such session", session, idx)
	}

	// Another scope's session reads as one the store does not hold: the
	// same status, step and sentence as an absent session, at a receipt
	// that is there, at one past the last, with any signature, its own
	// included -- for a caller of no scope identifier and for one of
	// another, as /seal answers them.
	wrong := strings.Repeat("a", 128)
	for _, who := range []struct{ name, token string }{{"a caller of no scope identifier", tokenU}, {"a caller of scope A and none", tokenA}} {
		for _, tc := range []struct {
			idx int64
			sig string
		}{{0, wrong}, {1, wrong}, {5, wrong}, {0, sigs[0]}, {1, sigs[1]}} {
			gotCode, got := act(who.token, "act-refused", "s-b", tc.idx, tc.sig)
			wantCode, want := act(who.token, "act-refused", "s-absent", tc.idx, tc.sig)
			if gotCode != http.StatusBadRequest || gotCode != wantCode || got["refusedAt"] != "cites" || want["refusedAt"] != "cites" ||
				got["error"] != absent("s-b", tc.idx) || want["error"] != absent("s-absent", tc.idx) {
				t.Errorf("%s citing s-b/%d: %d %v, where an absent session is %d %v", who.name, tc.idx, gotCode, got, wantCode, want)
			}
		}
		if code, out := authed(t, server, "/seal", `{"session":"s-b"}`, who.token); code != http.StatusBadRequest || out["error"] != "no such session: s-b" {
			t.Errorf("%s sealing s-b: %d %v", who.name, code, out)
		}
	}
	// the caller's own session still resolves
	if code, out := act(tokenU, "act-own", "u-read", 0, uSig); code != http.StatusOK {
		t.Fatalf("an action citing the caller's own receipt: %d %v", code, out)
	}

	// The session left open is sealed by the operator; the open /registry
	// then lists its last receipt's signature, and citing it is refused.
	seedPath := writeSeedFile(t, t.TempDir(), testSeed)
	var so, se bytes.Buffer
	if c := cmdSealOpenAt([]string{"--store", g.storeRoot, "--seed", seedPath, "--registry", g.regPath, "--authority", g.authority, "--session", "s-b"}, &so, &se, fixedStamp("2026-11-16T00:00:01Z")); c != 0 {
		t.Fatalf("seal-open: %d %s %s", c, so.String(), se.String())
	}
	resp, err := http.Get(server.URL + "/registry")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	head, final := "", int64(-1)
	for _, l := range strings.Split(string(raw), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) != nil || m["sessionId"] != "s-b" {
			continue
		}
		head, _ = m["headSignature"].(string)
		if f, ok := m["finalCount"].(float64); ok {
			final = int64(f)
		}
	}
	if head != sigs[len(sigs)-1] || final != int64(len(sigs)) {
		t.Fatalf("the registry's seal of s-b: headSignature %q finalCount %d, want the last receipt's of %d: %s", head, final, len(sigs), raw)
	}
	if code, out := act(tokenU, "act-head", "s-b", final-1, head); code != http.StatusBadRequest || out["refusedAt"] != "cites" || out["error"] != absent("s-b", final-1) || out["receipt"] != nil {
		t.Fatalf("citing s-b's last receipt by the registry's headSignature: %d %v", code, out)
	}

	// Nothing outside scope B cites into it, so removing it succeeds.
	rcode, rout, rerr := removeScopeOn(t, g, seedPath, "--scope", callerScopeB, "--by", "operator")
	if rcode != 0 {
		t.Fatalf("remove-scope B: exit %d\nstdout %s\nstderr %s", rcode, rout, rerr)
	}
	if _, err := os.Stat(filepath.Join(g.storeRoot, "receipts", "s-b")); !os.IsNotExist(err) {
		t.Fatalf("s-b is still in the store after remove-scope: %v", err)
	}
}
