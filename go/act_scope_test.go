package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// /act's scope identifier (ADR-0054, decision 1), with synthetic sources:
// one write platform of none ("tickets"), one fixed to scope B
// ("tickets-b"), and a read source of scope B whose receipts a scoped action
// cites.
type actScopeHarness struct {
	root, unscopedSig, scopedSig string
	g                            *gatewayService
	server                       *httptest.Server
	tokenA, tokenB, tokenBoth    string
	tokenC                       string
	decisionB, decisionU         string
}

func actScopeSetup(t *testing.T) *actScopeHarness {
	t.Helper()
	if !actionJournalSupported {
		t.Skip("the action journal needs this platform's directory sync")
	}
	t.Setenv(envSourceHelper, "1")
	h := &actScopeHarness{root: t.TempDir()}
	actionKeysMode(t, h.root, "write", "respond")
	actionKeysMode(t, h.root, "live", "read")
	sources := actionKeysSources(t, h.root, os.Args[0])
	write, live := sources["tickets/write"], sources["tickets/live"]
	write.scope, write.decisionRecords, live.scope = callerScopeB, filepath.Join(h.root, "decisions-b"), callerScopeB
	sources["tickets-b/write"], sources["tickets-b/live"] = write, live
	sources["scoped-b"] = sourceSpec{argv: []string{os.Args[0]}, env: helperEnv, scope: callerScopeB}
	h.g = actionKeysService(t, h.root, sources)
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	id.callers = callerScopes{entries: map[string]callerEntry{
		subjectA:   {grants: map[string]bool{callerScopeA: true, unscopedMarker: true}},
		subjectB:   {grants: map[string]bool{callerScopeB: true}},
		"both":     {grants: map[string]bool{callerScopeB: true, unscopedMarker: true}},
		"no-write": {grants: map[string]bool{callerScopeA: true}},
	}}
	h.g.identity = &id
	h.server = httptest.NewServer(h.g.handler())
	t.Cleanup(h.server.Close)
	h.tokenA = tokenFor(t, issuer, subjectA, []any{callerScopeA, unscopedMarker})
	h.tokenB = tokenFor(t, issuer, subjectB, []any{callerScopeB})
	h.tokenBoth = tokenFor(t, issuer, "both", []any{callerScopeB, unscopedMarker})
	h.tokenC = tokenFor(t, issuer, "no-write", []any{callerScopeA})

	code, out := authed(t, h.server, "/acquire", `{"session":"u-read","source":"screening","arguments":{"q":"acme"}}`, h.tokenBoth)
	if code != http.StatusOK {
		t.Fatalf("the unscoped read: %d %v", code, out)
	}
	h.unscopedSig = out["receipt"].(map[string]any)["signature"].(string)
	code, out = authed(t, h.server, "/acquire", acquireBodyFor("b-read", "scoped-b", callerScopeB), h.tokenB)
	if code != http.StatusOK {
		t.Fatalf("scope B's read: %d %v", code, out)
	}
	h.scopedSig = out["receipt"].(map[string]any)["signature"].(string)
	record := func(dir, session, sig string) string {
		line := `{"kind":"evaluation","cites":[{"sessionId":"` + session + `","callIndex":0,"signature":"` + sig + `"}]}`
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "decision.json"), []byte(line), 0600); err != nil {
			t.Fatal(err)
		}
		return `{"recordDigest":"` + digestOf(line) + `","packDigest":"sha256:` + strings.Repeat("d", 64) + `"}`
	}
	h.decisionB = record(filepath.Join(h.root, "decisions-b"), "b-read", h.scopedSig)
	h.decisionU = record(h.g.decisionRecords, "u-read", h.unscopedSig)
	return h
}

func (h *actScopeHarness) cite(session, sig string) string {
	return `[{"sessionId":"` + session + `","callIndex":0,"signature":"` + sig + `"}]`
}

// body is an /act request; scope is raw JSON, or "" for none.
func (h *actScopeHarness) body(session, platform, scope, key, decision, cites string) string {
	b := `{"session":"` + session + `","platform":"` + platform + `","tool":"query","arguments":{"ticket":"T-1"},"decision":` + decision + `,"cites":` + cites + `,"actionKey":"` + key + `","keyScope":"authority"`
	if scope != "" {
		b += `,"scope":` + scope
	}
	return b + "}"
}

// journalFiles counts every file under the store's action journal.
func journalFiles(t *testing.T, storeRoot string) int {
	t.Helper()
	n := 0
	err := filepath.WalkDir(filepath.Join(storeRoot, "actions"), func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			n++
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return n
}

var scopeB = `"` + callerScopeB + `"`

// Each scope refusal comes before the session's lookup and before anything
// of the key (ADR-0054, steps 2, 8, 10, 15 and 17): every request below
// names a key and keyScope that would be reserved, and the journal holds
// nothing after it. A caller naming a scope it does not reach with a sealed
// session of that scope is told the scope sentence, never "sealed".
func TestActScopeRefusalsComeBeforeTheKey(t *testing.T) {
	h := actScopeSetup(t)
	if code, out := authed(t, h.server, "/seal", `{"session":"b-read"}`, h.tokenB); code != http.StatusOK {
		t.Fatalf("sealing scope B's read: %d %v", code, out)
	}
	key := strings.Repeat("e", 64)
	cases := []struct {
		name, token, body, step, want string
		status                        int
	}{
		{"a caller that reaches no write source", h.tokenC, h.body("act-1", "tickets", "", key, h.decisionU, h.cite("u-read", h.unscopedSig)), "scope-identifier", reachRefusalScopedAct, http.StatusForbidden},
		{"a scope the caller does not reach", h.tokenA, h.body("act-1", "tickets-b", scopeB, key, h.decisionB, h.cite("b-read", h.scopedSig)), "scope-identifier", scopeRefusal, http.StatusBadRequest},
		{"a scope the caller does not reach, with that scope's sealed session", h.tokenA, h.body("b-read", "tickets-b", scopeB, key, h.decisionB, h.cite("b-read", h.scopedSig)), "scope-identifier", scopeRefusal, http.StatusBadRequest},
		{"a scope that is not a string", h.tokenBoth, h.body("act-1", "tickets-b", "7", key, h.decisionB, h.cite("b-read", h.scopedSig)), "scope-identifier", scopeRefusal, http.StatusBadRequest},
		{"a scope for a write source of none", h.tokenBoth, h.body("act-1", "tickets", scopeB, key, h.decisionU, h.cite("u-read", h.unscopedSig)), "scope-identifier", scopeRefusal, http.StatusBadRequest},
		{"no scope for a scoped write source", h.tokenBoth, h.body("act-1", "tickets-b", "", key, h.decisionB, h.cite("b-read", h.scopedSig)), "scope-identifier", scopeRefusal, http.StatusBadRequest},
		{"an unknown platform, from a caller that does not reach every source", h.tokenA, h.body("act-1", "nowhere", "", key, h.decisionU, h.cite("u-read", h.unscopedSig)), "scope-identifier", scopeRefusal, http.StatusBadRequest},
		{"a scoped action citing a receipt of none", h.tokenBoth, h.body("act-1", "tickets-b", scopeB, key, h.decisionB, h.cite("u-read", h.unscopedSig)), "cites", "no such session", http.StatusBadRequest},
		{"a scoped action whose record is in the gateway's directory alone", h.tokenBoth, h.body("act-1", "tickets-b", scopeB, key, h.decisionU, h.cite("b-read", h.scopedSig)), "decision", "no candidate", http.StatusBadRequest},
	}
	for _, c := range cases {
		code, out := authed(t, h.server, "/act", c.body, c.token)
		if code != c.status || out["refusedAt"] != c.step || !strings.Contains(fmt.Sprint(out["error"]), c.want) {
			t.Errorf("%s: %d %v, want %d at %s saying %q", c.name, code, out, c.status, c.step, c.want)
		}
		if n := journalFiles(t, h.g.storeRoot); n != 0 {
			t.Fatalf("%s: the journal holds %d file(s) after a refusal", c.name, n)
		}
	}
	if actionKeysSent(h.root, key) != 0 {
		t.Fatal("a refused action reached the target")
	}
}

// A scoped action is minted with its scope and its session's salt, and its
// key lives in its scope's journal, not the journal of none.
func TestActScopeMintsAScopedAction(t *testing.T) {
	h := actScopeSetup(t)
	key := strings.Repeat("a", 64)
	code, out := authed(t, h.server, "/act", h.body("act-b", "tickets-b", scopeB, key, h.decisionB, h.cite("b-read", h.scopedSig)), h.tokenB)
	if code != http.StatusOK {
		t.Fatalf("the scoped action: %d %v", code, out)
	}
	receipt := out["receipt"].(map[string]any)
	if salt, _ := receipt["scopeSalt"].(string); receipt["scope"] != callerScopeB || !isLowerHexOfLen(salt, 64) {
		t.Fatalf("the receipt does not carry the scope and its salt: %v", receipt)
	}
	who := &caller{issuer: h.g.identity.issuer, subject: subjectB}
	if _, err := os.Stat(filepath.Join(scopedActionJournalPath(h.g.storeRoot, callerScopeB), h.g.actionNamespaceIn(who, key, callerScopeB), "action.json")); err != nil {
		t.Fatalf("the key's record is not in its scope's journal: %v", err)
	}
	journalAbsent(t, h.g, h.g.actionNamespace(who, key))
	// the session is of scope B: an action of none is refused in it
	code, out = authed(t, h.server, "/act", h.body("act-b", "tickets", "", strings.Repeat("b", 64), h.decisionU, h.cite("u-read", h.unscopedSig)), h.tokenBoth)
	if code != http.StatusBadRequest || out["refusedAt"] != "session" {
		t.Fatalf("an action of none in a session of scope B: %d %v", code, out)
	}
}

// One key in two scopes names two actions: a key whose first scope another
// subject holds in scope B is a key never seen in the scope of none, and
// each reserves and dispatches.
func TestActScopeOneKeyInTwoScopes(t *testing.T) {
	h := actScopeSetup(t)
	key := strings.Repeat("c", 64)
	if code, out := authed(t, h.server, "/act", h.body("act-b", "tickets-b", scopeB, key, h.decisionB, h.cite("b-read", h.scopedSig)), h.tokenB); code != http.StatusOK {
		t.Fatalf("scope B's action: %d %v", code, out)
	}
	if code, out := authed(t, h.server, "/act", h.body("act-u", "tickets", "", key, h.decisionU, h.cite("u-read", h.unscopedSig)), h.tokenA); code != http.StatusOK {
		t.Fatalf("the same key in the scope of none: %d %v", code, out)
	}
	if n := actionKeysSent(h.root, key); n != 2 {
		t.Fatalf("the key was sent %d time(s), want once in each scope", n)
	}
}

// A delegated request, and a reservation's sender, reach no scope
// identifier: one that names a scope is refused at the scope step.
func TestActScopeDelegatedNamesNoScope(t *testing.T) {
	h := actScopeSetup(t)
	who := &caller{issuer: h.g.identity.issuer, subject: subjectB, tokenDigest: "sha256:" + strings.Repeat("c", 64), delegated: &delegatedSender{kind: "actor"}}
	_, err := h.g.actKeyed(json.RawMessage(`"act-d"`), json.RawMessage(`"tickets-b"`), json.RawMessage(`"query"`), json.RawMessage(`{"ticket":"T-1"}`), json.RawMessage(h.decisionB), json.RawMessage(h.cite("b-read", h.scopedSig)), who, actionKeyMembers{key: json.RawMessage(`"` + strings.Repeat("d", 64) + `"`), scopeIdentifier: json.RawMessage(scopeB)})
	if refusal, ok := err.(actRefusal); !ok || refusal.step != "scope-identifier" || refusal.reason != scopeRefusal {
		t.Fatalf("a delegated request naming a scope: %v", err)
	}
}

// An uncertain scoped action reads back in its own session, of its scope,
// and the read-back's receipt carries the scope. One whose read-back fails
// leaves its key pending, and remove-scope refuses, naming the key, until
// it is settled; the journal goes with the scope.
func TestActScopeReadBackAndRemoval(t *testing.T) {
	h := actScopeSetup(t)
	actionKeysMode(t, h.root, "write", "drop")
	key := strings.Repeat("f", 64)
	code, out := authed(t, h.server, "/act", h.body("act-r", "tickets-b", scopeB, key, h.decisionB, h.cite("b-read", h.scopedSig)), h.tokenB)
	if code != http.StatusOK {
		t.Fatalf("the uncertain scoped action: %d %v", code, out)
	}
	read := out["reconciliation"].(map[string]any)["receipt"].(map[string]any)
	if read["scope"] != callerScopeB || read["sessionId"] != "act-r" {
		t.Fatalf("the read-back is not of the action's scope and session: %v", read)
	}
	if refused, err := pendingScopedKeys(h.g.storeRoot, callerScopeB, nil); err != nil || len(refused) != 1 || !strings.Contains(refused[0], key) {
		t.Fatalf("with no read-back in the store, the uncertain key is pending: %v %v", refused, err)
	}
	actionKeysMode(t, h.root, "live", "drop")
	other := strings.Repeat("9", 64)
	if code, out := authed(t, h.server, "/act", h.body("act-s", "tickets-b", scopeB, other, h.decisionB, h.cite("b-read", h.scopedSig)), h.tokenB); code != http.StatusConflict {
		t.Fatalf("an uncertain action whose read-back fails: %d %v", code, out)
	}
	if refused, _ := pendingScopedKeys(h.g.storeRoot, callerScopeB, nil); len(refused) != 2 || !strings.Contains(strings.Join(refused, "\n"), other) {
		t.Fatalf("both uncertain keys are pending: %v", refused)
	}
	if refused, _ := pendingScopedKeys(h.g.storeRoot, callerScopeA, nil); len(refused) != 0 {
		t.Fatalf("another scope's journal holds nothing: %v", refused)
	}
	var outcome removalOutcome
	if err := removeScopedActionJournal(h.g.storeRoot, callerScopeB, &outcome); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(scopedActionJournalPath(h.g.storeRoot, callerScopeB)); !os.IsNotExist(err) {
		t.Fatalf("the scope's journal is still there: %v", err)
	}
}

// The load checks of a scoped write platform (ADR-0054, decision 1).
func TestActScopePlatformLoadChecks(t *testing.T) {
	checked := &callerScopes{entries: map[string]callerEntry{}}
	member := func(text string) *vObject {
		v, err := parseJSON([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		return v.(*vObject)
	}
	own := member(`{"decisionRecords":"/records/b"}`)
	cases := []struct {
		name    string
		p       *vObject
		version string
		write   bool
		scope   string
		callers *callerScopes
		want    string
	}{
		{"below the version", own, "20", true, callerScopeB, checked, "is a platform member from engineVersion"},
		{"unchecked caller scopes", own, actScopeVersion, true, callerScopeB, &callerScopes{unchecked: true}, "needs identity.callerScopes as an object"},
		{"no caller scopes", own, actScopeVersion, true, callerScopeB, nil, "needs identity.callerScopes as an object"},
		{"no directory of its own", member(`{}`), actScopeVersion, true, callerScopeB, checked, "needs its own decisionRecords"},
		{"a relative directory", member(`{"decisionRecords":"records/b"}`), actScopeVersion, true, callerScopeB, checked, "absolute path"},
		{"a directory on an unscoped write", own, actScopeVersion, true, "", checked, "the platform is not one"},
		{"a directory on a scoped read", own, actScopeVersion, false, callerScopeB, checked, "the platform is not one"},
	}
	for _, c := range cases {
		if _, err := parsePlatformDecisionRecords(c.p, "tickets", c.version, c.write, c.scope, c.callers); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	if dir, err := parsePlatformDecisionRecords(own, "tickets", actScopeVersion, true, callerScopeB, checked); err != nil || dir != "/records/b" {
		t.Fatalf("a scoped write with its own directory: %q %v", dir, err)
	}
	if _, err := parsePlatformScope(vString(callerScopeB), "tickets", actScopeVersion, true, nil); err != nil {
		t.Fatalf("a scope beside write: true from the version: %v", err)
	}
	if _, err := parsePlatformScope(vString(callerScopeB), "tickets", "20", true, nil); err == nil {
		t.Fatal("a scope beside write: true below the version loaded")
	}
	platforms := func(dirs ...string) []platformConfig {
		var out []platformConfig
		for i, d := range dirs {
			scope := callerScopeA
			if i%2 == 1 {
				scope = callerScopeB
			}
			out = append(out, platformConfig{name: fmt.Sprintf("p%d", i), scope: scope, write: true, decisionRecords: d})
		}
		return out
	}
	for _, c := range []struct {
		name, gateway string
		platforms     []platformConfig
	}{
		{"the gateway's directory", "/records", platforms("/records")},
		{"beneath the gateway's", "/records", platforms("/records/a")},
		{"above the gateway's", "/records/gateway", platforms("/records")},
		{"another scope's directory", "", platforms("/records/a", "/records/a")},
		{"beneath another scope's", "", platforms("/records/a", "/records/a/b")},
	} {
		if err := decisionRecordsApart(c.gateway, c.platforms, filepath.Clean); err == nil {
			t.Errorf("%s: loaded", c.name)
		}
	}
	same := []platformConfig{{name: "p0", scope: callerScopeB, decisionRecords: "/records/b"}, {name: "p1", scope: callerScopeB, decisionRecords: "/records/b"}}
	if err := decisionRecordsApart("/records/gateway", append(same, platformConfig{name: "p2", scope: callerScopeA, decisionRecords: "/records/a"}), filepath.Clean); err != nil {
		t.Fatalf("apart directories, one shared within a scope: %v", err)
	}
}
