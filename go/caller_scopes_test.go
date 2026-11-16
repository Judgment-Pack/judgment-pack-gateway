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
	"time"
)

// Caller scope identifiers (ADR-0037): the synthetic scope identifiers and
// subjects of these tests.
const (
	callerScopeA = "équipe-a"
	callerScopeB = "équipe-b"
	subjectA     = "caller-of-a"
	subjectB     = "caller-of-b"
)

// callerScopesService is a gateway with an identity, a source fixed to
// each of two scope identifiers and one fixed to none, its identity's
// callerScopes as given.
func callerScopesService(t *testing.T, callers callerScopes) (*gatewayService, *httptest.Server, *testIssuer) {
	t.Helper()
	t.Setenv(envSourceHelper, "1")
	root := t.TempDir()
	service, err := newGatewayService(
		filepath.Join(root, "store"), testSeed, "gateway:test",
		filepath.Join(root, "registry.jsonl"),
		map[string]sourceSpec{
			"scoped-a": {argv: []string{os.Args[0]}, env: helperEnv, scope: callerScopeA},
			"scoped-b": {argv: []string{os.Args[0]}, env: helperEnv, scope: callerScopeB},
			"plain":    {argv: []string{os.Args[0]}, env: helperEnv},
		})
	if err != nil {
		t.Fatal(err)
	}
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	id.callers = callers
	service.identity = &id
	server := httptest.NewServer(service.handler())
	t.Cleanup(server.Close)
	return service, server, issuer
}

// tokenFor is a token for the subject, carrying scope_ids where claim is
// not nil.
func tokenFor(t *testing.T, issuer *testIssuer, subject string, claim any) string {
	t.Helper()
	claims := goodClaims(time.Now())
	claims["sub"] = subject
	if claim != nil {
		claims[scopeClaimName] = claim
	}
	return issuer.mint(t, "ec-1", nil, claims)
}

func acquireBodyFor(session, source, scope string) string {
	named := ""
	if scope != "" {
		named = `"scope":"` + scope + `",`
	}
	return `{"session":"` + session + `","source":"` + source + `",` + named + `"arguments":{"q":"acme"}}`
}

// the two callers of one scope identifier each, every subject's entry
// granting its own
var twoScopes = callerScopes{entries: map[string]callerEntry{
	subjectA: {grants: map[string]bool{callerScopeA: true}},
	subjectB: {grants: map[string]bool{callerScopeB: true}},
}}

// A caller of scope A is refused on scope B at every route that reaches a
// session of a scope identifier, with the answer a request for a scope or a
// session that is not there gets, and nothing runs or is sealed; the same
// request of B's caller is served.
func TestACallerOfOneScopeIsRefusedOnAnotherAtEveryRoute(t *testing.T) {
	service, server, issuer := callerScopesService(t, twoScopes)
	tokenA := tokenFor(t, issuer, subjectA, []any{callerScopeA})
	tokenB := tokenFor(t, issuer, subjectB, []any{callerScopeB})
	if code, out := authed(t, server, "/acquire", acquireBodyFor("s-b", "scoped-b", callerScopeB), tokenB); code != http.StatusOK {
		t.Fatalf("B's caller on B: %d %v", code, out)
	}
	started := service.started.Load()
	for _, tc := range []struct {
		route, body string
		status      int
		answer      string
	}{
		{"/acquire", acquireBodyFor("s-b", "scoped-b", callerScopeB), http.StatusBadRequest, scopeRefusal},
		{"/acquire", acquireBodyFor("s-new", "scoped-b", callerScopeB), http.StatusBadRequest, scopeRefusal},
		{"/seal", `{"session":"s-b"}`, http.StatusBadRequest, "no such session: s-b"},
		{"/act", `{"session":"s-b"}`, http.StatusForbidden, reachRefusalAct},
		{"/act", `{"session":"s-unknown"}`, http.StatusForbidden, reachRefusalAct},
		{"/verify", ``, http.StatusForbidden, reachRefusalVerify},
	} {
		t.Run(tc.route, func(t *testing.T) {
			code, out := authed(t, server, tc.route, tc.body, tokenA)
			if code != tc.status || fmt.Sprint(out["error"]) != tc.answer {
				t.Fatalf("A's caller: %d %v", code, out)
			}
			if bytes.Contains([]byte(fmt.Sprint(out)), []byte("quipe")) {
				t.Fatalf("the answer names a scope identifier: %v", out)
			}
		})
	}
	// the refused seal is the answer to a session the gateway does not
	// hold, byte for byte but the name
	if code, raw := postRawWith(t, server, "/seal", `{"session":"s-b"}`, tokenA); code != http.StatusBadRequest || string(raw) != strings.Replace(string(postRawBody(t, server, "/seal", `{"session":"s-x"}`, tokenA)), "s-x", "s-b", 1) {
		t.Fatalf("a seal of B's session: %d %s", code, raw)
	}
	if service.started.Load() != started {
		t.Fatal("a source started for a refused request")
	}
	if sessionHeld(service, "s-new") {
		t.Fatal("a refused acquisition was admitted")
	}
	// B's session is open still, and B's caller seals it
	if code, out := authed(t, server, "/seal", `{"session":"s-b"}`, tokenB); code != http.StatusOK {
		t.Fatalf("B's caller seals B's session: %d %v", code, out)
	}
	// /registry is served whole, with no token, and names no caller
	resp, err := http.Get(server.URL + "/registry")
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.Contains(registry, []byte(`"sessionId":"s-b"`)) || bytes.Contains(registry, []byte(subjectB)) || bytes.Contains(registry, []byte("quipe")) {
		t.Fatalf("the registry: %d %s", resp.StatusCode, registry)
	}
}

func postRawBody(t *testing.T, server *httptest.Server, path, body, token string) []byte {
	t.Helper()
	_, raw := postRawWith(t, server, path, body, token)
	return raw
}

// What a token reaches (ADR-0037, decision 3): the claim's scope
// identifiers, each of which the entry grants, the sources of none only
// where both hold the marker; a claimless token the sources of none where
// its entry is "unscoped", absent or holds the marker, every source where it
// is "installation"; a wider claim, and a claimless token of a list without
// the marker, refused 401 with one sentence before any route.
func TestATokenReachesWhatItsClaimAndItsSubjectsEntryBothAllow(t *testing.T) {
	callers := callerScopes{entries: map[string]callerEntry{
		"only-a":       {grants: map[string]bool{callerScopeA: true}},
		"a-and-none":   {grants: map[string]bool{callerScopeA: true, unscopedMarker: true}},
		"unscoped":     unscopedEntry,
		"installation": {installation: true},
	}}
	type want struct{ a, b, plain int }
	const ok, refused, unauthenticated = http.StatusOK, http.StatusBadRequest, http.StatusUnauthorized
	for _, tc := range []struct {
		name, subject string
		claim         any
		want          want
		reason        string
	}{
		{"a claim the list grants", "only-a", []any{callerScopeA}, want{ok, refused, refused}, ""},
		{"a claim with the marker its list holds", "a-and-none", []any{callerScopeA, unscopedMarker}, want{ok, refused, ok}, ""},
		{"a claim without the marker its list holds", "a-and-none", []any{callerScopeA}, want{ok, refused, refused}, ""},
		{"the marker alone", "a-and-none", []any{unscopedMarker}, want{refused, refused, ok}, ""},
		{"a claim wider than the list", "only-a", []any{callerScopeA, callerScopeB}, want{unauthenticated, unauthenticated, unauthenticated}, errScopeClaimWider.Error()},
		{"the marker its list does not hold", "only-a", []any{callerScopeA, unscopedMarker}, want{unauthenticated, unauthenticated, unauthenticated}, errScopeClaimWider.Error()},
		{"a claimless token of a list without the marker", "only-a", nil, want{unauthenticated, unauthenticated, unauthenticated}, errScopeClaimWider.Error()},
		{"a claimless token of a list with the marker", "a-and-none", nil, want{refused, refused, ok}, ""},
		{"a claimless token of unscoped", "unscoped", nil, want{refused, refused, ok}, ""},
		{"a claimless token of a subject with no entry", "no-entry", nil, want{refused, refused, ok}, ""},
		{"a claim of a subject with no entry", "no-entry", []any{callerScopeA}, want{unauthenticated, unauthenticated, unauthenticated}, errScopeClaimWider.Error()},
		{"a claimless installation token", "installation", nil, want{ok, ok, ok}, ""},
		{"an installation token held to its claim", "installation", []any{callerScopeB}, want{refused, ok, refused}, ""},
		{"a claim out of form: empty", "only-a", []any{}, want{unauthenticated, unauthenticated, unauthenticated}, errScopeClaimForm.Error()},
		{"a claim out of form: twice", "only-a", []any{callerScopeA, callerScopeA}, want{unauthenticated, unauthenticated, unauthenticated}, errScopeClaimForm.Error()},
		{"a claim out of form: a string", "only-a", callerScopeA, want{unauthenticated, unauthenticated, unauthenticated}, errScopeClaimForm.Error()},
		{"a claim out of form: a tab", "only-a", []any{"a\tb"}, want{unauthenticated, unauthenticated, unauthenticated}, errScopeClaimForm.Error()},
		{"a claim out of form: null", "only-a", nullClaim{}, want{unauthenticated, unauthenticated, unauthenticated}, errScopeClaimForm.Error()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service, server, issuer := callerScopesService(t, callers)
			claim := tc.claim
			if _, isNull := claim.(nullClaim); isNull {
				claim = nil
			}
			token := tokenFor(t, issuer, tc.subject, claim)
			if _, isNull := tc.claim.(nullClaim); isNull {
				claims := goodClaims(time.Now())
				claims["sub"] = tc.subject
				claims[scopeClaimName] = nil
				token = issuer.mint(t, "ec-1", nil, claims)
			}
			started := service.started.Load()
			for i, call := range []struct {
				source, scope string
				status        int
			}{{"scoped-a", callerScopeA, tc.want.a}, {"scoped-b", callerScopeB, tc.want.b}, {"plain", "", tc.want.plain}} {
				code, out := authed(t, server, "/acquire", acquireBodyFor(fmt.Sprintf("s-%d", i), call.source, call.scope), token)
				if code != call.status {
					t.Fatalf("%s: %d %v", call.source, code, out)
				}
				switch code {
				case unauthenticated:
					if out["error"] != tc.reason {
						t.Fatalf("%s: the refusal says %v, want %q", call.source, out["error"], tc.reason)
					}
				case refused:
					if out["error"] != scopeRefusal {
						t.Fatalf("%s: %v", call.source, out)
					}
				}
			}
			if tc.want == (want{unauthenticated, unauthenticated, unauthenticated}) && service.started.Load() != started {
				t.Fatal("a source started for a refused token")
			}
		})
	}
}

// nullClaim marks a test case whose claim is JSON null.
type nullClaim struct{}

// "unchecked" reads no claim, as before the member: a caller with none, or
// with one out of form or wider than any entry, reaches every source, and the
// start and /posture say so. Without an identity every request reaches
// every source, and that is said too; checked is the default.
func TestUncheckedCallerScopesServeAsBeforeAndAreReported(t *testing.T) {
	service, server, issuer := callerScopesService(t, callerScopes{unchecked: true})
	for i, claim := range []any{nil, []any{}, []any{callerScopeB}} {
		token := tokenFor(t, issuer, subjectA, claim)
		for j, source := range []struct{ name, scope string }{{"scoped-a", callerScopeA}, {"scoped-b", callerScopeB}, {"plain", ""}} {
			if code, out := authed(t, server, "/acquire", acquireBodyFor(fmt.Sprintf("u-%d-%d", i, j), source.name, source.scope), token); code != http.StatusOK {
				t.Fatalf("unchecked, claim %v, %s: %d %v", claim, source.name, code, out)
			}
		}
	}
	if code, out := authed(t, server, "/verify", ``, tokenFor(t, issuer, subjectA, nil)); code != http.StatusOK {
		t.Fatalf("unchecked /verify: %d %v", code, out)
	}
	lineOf := func(id *identityConfig) string {
		service.identity = id
		code, raw := postRawWith(t, server, "/posture", ``, tokenFor(t, issuer, subjectA, nil))
		var report struct {
			Protections []struct{ Name, State string }
		}
		if code != http.StatusOK || json.Unmarshal(raw, &report) != nil {
			t.Fatalf("/posture: %d %s", code, raw)
		}
		for _, p := range report.Protections {
			if p.Name == protectionCallerScopes {
				return p.State
			}
		}
		return ""
	}
	unchecked := *service.identity
	checked := unchecked
	checked.callers = callerScopes{}
	for _, tc := range []struct {
		name  string
		id    *identityConfig
		state string
	}{{"unchecked", &unchecked, postureNotEnforced}, {"checked", &checked, postureEnforced}, {"no identity", nil, postureNotEnforced}} {
		if line := lineOf(tc.id); line != tc.state {
			t.Fatalf("%s: the posture line is %q, want %s", tc.name, line, tc.state)
		}
		if line := callerScopesStartLine(tc.id, service.sources); line == "" || strings.Contains(line, "quipe") {
			t.Fatalf("%s: the start line is %q", tc.name, line)
		}
	}
	if !strings.Contains(callerScopesStartLine(&unchecked, service.sources), `"unchecked"`) || !strings.Contains(callerScopesStartLine(nil, service.sources), "no identity") {
		t.Fatal("the start line does not say which")
	}
	// a configuration fixing no source to a scope identifier gets both
	// where it has an identity, since a token whose claim names a scope
	// identifier is refused 401 there too, and neither where it has none
	plain := map[string]sourceSpec{"plain": service.sources["plain"]}
	if line := callerScopesStartLine(&checked, plain); !strings.Contains(line, "are checked") || !strings.Contains(line, "refused 401") {
		t.Fatalf("checked, no source scoped: the start line is %q", line)
	}
	if lines := callerScopesLine("checked", plain); len(lines) != 1 || lines[0].state != postureEnforced || !strings.Contains(lines[0].reason, "refused 401") {
		t.Fatalf("checked, no source scoped: the posture line is %+v", lines)
	}
	if callerScopesStartLine(&unchecked, plain) == "" || callerScopesLine("unchecked", plain) == nil {
		t.Fatal("unchecked, no source scoped: no line")
	}
	if callerScopesStartLine(nil, plain) != "" || callerScopesLine("no-identity", plain) != nil {
		t.Fatal("a line where there is no identity and no source is scoped")
	}
}

// Where no source is fixed to a scope identifier, /verify is served to a
// caller that reaches the sources of none, as before the member; where
// some is, only to one that reaches every source.
func TestVerifyIsServedToACallerThatReachesWhatItCovers(t *testing.T) {
	service, server, issuer := callerScopesService(t, callerScopes{entries: map[string]callerEntry{"installation": {installation: true}}})
	if code, out := authed(t, server, "/verify", ``, tokenFor(t, issuer, "installation", nil)); code != http.StatusOK {
		t.Fatalf("an installation caller: %d %v", code, out)
	}
	if code, out := authed(t, server, "/verify", ``, tokenFor(t, issuer, "unscoped", nil)); code != http.StatusForbidden || out["error"] != reachRefusalVerify {
		t.Fatalf("an unscoped caller where sources are scoped: %d %v", code, out)
	}
	plain, plainServer := testService(t)
	plain.identity = service.identity
	if code, out := authed(t, plainServer, "/verify", ``, tokenFor(t, issuer, "unscoped", nil)); code != http.StatusOK {
		t.Fatalf("an unscoped caller where no source is scoped: %d %v", code, out)
	}
	// "no source is scoped" holds of the store too: a store holding a
	// session of a scope identifier since removed from the configuration is
	// verified for a caller that reaches every source alone, open or sealed
	service.identity = nil
	for _, session := range []string{"s-open", "s-sealed"} {
		if code, out := authed(t, server, "/acquire", acquireBodyFor(session, "scoped-a", callerScopeA), ""); code != http.StatusOK {
			t.Fatalf("acquire %s: %d %v", session, code, out)
		}
	}
	if code, out := authed(t, server, "/seal", `{"session":"s-sealed"}`, ""); code != http.StatusOK {
		t.Fatalf("seal: %d %v", code, out)
	}
	removed, err := newGatewayService(service.storeRoot, testSeed, "gateway:test", service.regPath, map[string]sourceSpec{"plain": service.sources["plain"]})
	if err != nil {
		t.Fatal(err)
	}
	removed.identity = plain.identity
	removedServer := httptest.NewServer(removed.handler())
	t.Cleanup(removedServer.Close)
	if code, out := authed(t, removedServer, "/verify", ``, tokenFor(t, issuer, "unscoped", nil)); code != http.StatusForbidden || out["error"] != reachRefusalVerify {
		t.Fatalf("an unscoped caller where the store holds a scope's sessions: %d %v", code, out)
	}
	if code, out := authed(t, removedServer, "/verify", ``, tokenFor(t, issuer, "installation", nil)); code != http.StatusOK || !strings.Contains(fmt.Sprint(out["findings"]), "s-sealed") {
		t.Fatalf("an installation caller where the store holds a scope's sessions: %d %v", code, out)
	}
}

// A caller that reaches the sources of none acts as before: its /act is
// not refused for its scope identifiers, and reaches the ladder.
func TestACallerReachingTheSourcesOfNoneActsAsBefore(t *testing.T) {
	_, server, issuer := callerScopesService(t, twoScopes)
	code, out := authed(t, server, "/act", `{"session":"s-1"}`, tokenFor(t, issuer, "unscoped", nil))
	if code == http.StatusForbidden && out["refusedAt"] == "scope-identifier" {
		t.Fatalf("an unscoped caller's /act: %d %v", code, out)
	}
}

// The scope identifiers of a scoped caller's receipts, and its subject, are
// in its scope's receipt alone: neither the seal's answer nor /verify's
// findings nor the registry carries the subject.
func TestAScopedCallersSubjectIsInItsScopesReceiptAlone(t *testing.T) {
	callers := twoScopes
	callers.entries["installation"] = callerEntry{installation: true}
	_, server, issuer := callerScopesService(t, callers)
	tokenA := tokenFor(t, issuer, subjectA, []any{callerScopeA})
	code, out := authed(t, server, "/acquire", acquireBodyFor("s-a", "scoped-a", callerScopeA), tokenA)
	if code != http.StatusOK || !strings.Contains(fmt.Sprint(out["receipt"]), subjectA) {
		t.Fatalf("A's acquisition: %d %v", code, out)
	}
	_, sealed := postRawWith(t, server, "/seal", `{"session":"s-a"}`, tokenA)
	_, verified := postRawWith(t, server, "/verify", ``, tokenFor(t, issuer, "installation", nil))
	resp, err := http.Get(server.URL + "/registry")
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for name, raw := range map[string][]byte{"the seal": sealed, "the verdict": verified, "the registry": registry} {
		if !bytes.Contains(raw, []byte("s-a")) || bytes.Contains(raw, []byte(subjectA)) {
			t.Fatalf("%s: %s", name, raw)
		}
	}
}

// identity.callerScopes is a version-27 member, held to its form.
func TestCallerScopesConfigurationIsHeldToItsForm(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	good := platformJSON(t, "warehouse", "postgres@"+digestOf(postgresBinding), "engine-warehouse", ``)
	withCallers := func(version, callers string) string {
		identity := `,"identity":{"issuer":"https://login.example","audience":"gateway:acme","keys":"` + abs(t, t.TempDir(), "keys.json") + `","callerScopes":` + callers + `}`
		return strings.Replace(engineJSON(t, catalog, identity, good), `"engineVersion":"1"`, `"engineVersion":"`+version+`"`, 1)
	}
	if _, err := parseEngineConfig([]byte(withCallers("26", `"unchecked"`))); err == nil || !strings.Contains(err.Error(), "identity.callerScopes is a version-27 member; engineVersion 26 has no identity.callerScopes") {
		t.Fatalf("version 26: %v", err)
	}
	for callers, want := range map[string]callerScopes{
		`"unchecked"`: {unchecked: true},
		`{"s-1":"unscoped","s-2":"installation","s-3":["équipe-a","unscoped"]}`: {entries: map[string]callerEntry{
			"s-1": unscopedEntry, "s-2": {installation: true}, "s-3": {grants: map[string]bool{callerScopeA: true, unscopedMarker: true}},
		}},
	} {
		cfg, err := parseEngineConfig([]byte(withCallers("27", callers)))
		if err != nil {
			t.Fatalf("%s: %v", callers, err)
		}
		if fmt.Sprint(cfg.identity.callers) != fmt.Sprint(want) {
			t.Fatalf("%s: %+v", callers, cfg.identity.callers)
		}
	}
	tooMany := make([]string, maxCallerScopes+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("%q", fmt.Sprintf("s%d", i))
	}
	for _, callers := range []string{
		`"checked"`, `1`, `null`, `[]`, `{"s":"other"}`, `{"s":[]}`, `{"s":["a","a"]}`, `{"s":[1]}`,
		`{"s":["a\tb"]}`, `{"s":null}`, `{"s":["` + strings.Repeat("a", 129) + `"]}`, `{"s":[` + strings.Join(tooMany, ",") + `]}`,
	} {
		_, err := parseEngineConfig([]byte(withCallers("27", callers)))
		if err == nil || !strings.Contains(err.Error(), "identity.callerScopes must be") {
			t.Fatalf("%s: %v", callers, err)
		}
	}
	if _, err := parseEngineConfig([]byte(withCallers("27", `{"":"unscoped"}`))); err == nil || !strings.Contains(err.Error(), "never empty") {
		t.Fatalf("an empty subject: %v", err)
	}
	// absent, checked with every subject "unscoped"
	cfg, err := parseEngineConfig([]byte(strings.Replace(withCallers("27", `"unchecked"`), `,"callerScopes":"unchecked"`, ``, 1)))
	if err != nil || cfg.identity.callers.unchecked || len(cfg.identity.callers.entries) != 0 {
		t.Fatalf("absent: %+v %v", cfg.identity, err)
	}
}

// After a restart, a session another process left open in a store of the
// filesystem kind is answered by its scope too (ADR-0037): A's caller is told
// of B's session what it is told of one the gateway does not hold, byte for
// byte but the name, and an acquisition of A's into it gets the other
// scope's refusal; B's caller, and an installation caller, are told it was
// left open. A session whose receipt does not say its scope is not there for
// a caller held to scope identifiers.
func TestASessionLeftOpenIsAnsweredByItsScopeAfterARestart(t *testing.T) {
	callers := callerScopes{entries: map[string]callerEntry{
		subjectA:       {grants: map[string]bool{callerScopeA: true}},
		subjectB:       {grants: map[string]bool{callerScopeB: true}},
		"installation": {installation: true},
	}}
	earlier, earlierServer, issuer := callerScopesService(t, callers)
	tokenA := tokenFor(t, issuer, subjectA, []any{callerScopeA})
	tokenB := tokenFor(t, issuer, subjectB, []any{callerScopeB})
	installation := tokenFor(t, issuer, "installation", nil)
	if code, out := authed(t, earlierServer, "/acquire", acquireBodyFor("s-b", "scoped-b", callerScopeB), tokenB); code != http.StatusOK {
		t.Fatalf("B's caller on B: %d %v", code, out)
	}
	earlierServer.Close()
	torn := filepath.Join(earlier.storeRoot, "receipts", "s-torn")
	if err := os.MkdirAll(torn, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(torn, "0.json"), []byte(`{"scope":`), 0o600); err != nil {
		t.Fatal(err)
	}
	restarted, err := newGatewayService(earlier.storeRoot, testSeed, "gateway:test", earlier.regPath, earlier.sources)
	if err != nil {
		t.Fatal(err)
	}
	restarted.identity = earlier.identity
	server := httptest.NewServer(restarted.handler())
	t.Cleanup(server.Close)
	started := restarted.started.Load()
	for _, tc := range []struct {
		name, route, body, token, answer string
	}{
		{"A seals B's", "/seal", `{"session":"s-b"}`, tokenA, "no such session: s-b"},
		{"A seals the torn one", "/seal", `{"session":"s-torn"}`, tokenA, "no such session: s-torn"},
		{"A acquires into B's", "/acquire", acquireBodyFor("s-b", "scoped-a", callerScopeA), tokenA, fmt.Sprintf(refusalOtherScope, "s-b")},
		{"B seals its own", "/seal", `{"session":"s-b"}`, tokenB, fmt.Sprintf(refusalLeftOpen, "s-b")},
		{"B acquires into its own", "/acquire", acquireBodyFor("s-b", "scoped-b", callerScopeB), tokenB, fmt.Sprintf(refusalLeftOpen, "s-b")},
		{"the installation seals B's", "/seal", `{"session":"s-b"}`, installation, fmt.Sprintf(refusalLeftOpen, "s-b")},
		{"the installation seals the torn one", "/seal", `{"session":"s-torn"}`, installation, fmt.Sprintf(refusalLeftOpen, "s-torn")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out := authed(t, server, tc.route, tc.body, tc.token)
			if code != http.StatusBadRequest || fmt.Sprint(out["error"]) != tc.answer {
				t.Fatalf("%d %v", code, out)
			}
		})
	}
	if code, raw := postRawWith(t, server, "/seal", `{"session":"s-b"}`, tokenA); code != http.StatusBadRequest || string(raw) != strings.Replace(string(postRawBody(t, server, "/seal", `{"session":"s-x"}`, tokenA)), "s-x", "s-b", 1) {
		t.Fatalf("a seal of B's session after a restart: %d %s", code, raw)
	}
	if restarted.started.Load() != started {
		t.Fatal("a source started for a refused request")
	}
}

// A caller held to scope identifiers is told of a source no configuration
// names what it is told of a source of a scope it does not reach, byte for
// byte, so it does not learn which names other scopes' sources have; a
// caller that reaches every source is told the source is unknown.
func TestAnUnknownSourceIsAnsweredAsAnotherScopesToACallerHeldToScopes(t *testing.T) {
	callers := callerScopes{entries: map[string]callerEntry{
		subjectA:       {grants: map[string]bool{callerScopeA: true}},
		"installation": {installation: true},
	}}
	service, server, issuer := callerScopesService(t, callers)
	started := service.started.Load()
	for _, token := range []string{tokenFor(t, issuer, subjectA, []any{callerScopeA}), tokenFor(t, issuer, "unscoped", nil)} {
		_, other := postRawWith(t, server, "/acquire", acquireBodyFor("s-1", "scoped-b", callerScopeB), token)
		for _, body := range []string{
			acquireBodyFor("s-1", "nothing/here", callerScopeB),
			acquireBodyFor("s-1", "nothing/here", ""),
			acquireBodyFor("s-1", "plain/write", ""),
		} {
			code, raw := postRawWith(t, server, "/acquire", body, token)
			if code != http.StatusBadRequest || string(raw) != string(other) || !bytes.Contains(raw, []byte(scopeRefusal)) {
				t.Fatalf("%s: %d %s, want %s", body, code, raw, other)
			}
		}
	}
	code, out := authed(t, server, "/acquire", acquireBodyFor("s-1", "nothing/here", ""), tokenFor(t, issuer, "installation", nil))
	if code != http.StatusBadRequest || !strings.HasPrefix(fmt.Sprint(out["error"]), "unknown source: ") {
		t.Fatalf("an installation caller: %d %v", code, out)
	}
	if service.started.Load() != started {
		t.Fatal("a source started for a refused request")
	}
}
