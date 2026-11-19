package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"
)

// With caller scopes checked, /posture is of the sources the caller reaches
// (ADR-0037, ADR-0041), as /acquire does not tell another scope's sources
// from unknown ones: its programs name only them, and its protection lines
// are judged over them alone, so a caller's report is the same, byte for
// byte, whether or not the sources it does not reach exist, and names none of
// them, in a member or in a line's text. The installation's caller and
// "unchecked" read every source, as before.
func TestPostureProgramsNameOnlyTheSourcesTheCallerReaches(t *testing.T) {
	callers := callerScopes{entries: map[string]callerEntry{
		subjectA:       {grants: map[string]bool{callerScopeA: true}},
		subjectB:       {grants: map[string]bool{callerScopeB: true}},
		"installation": {installation: true},
	}}
	service, server, issuer := callerScopesService(t, callers)
	read := func(token string) ([]string, string, []byte) {
		t.Helper()
		code, raw := postRawWith(t, server, "/posture", ``, token)
		var report struct {
			Programs    []struct{ Source string }
			Protections json.RawMessage
		}
		if code != http.StatusOK || json.Unmarshal(raw, &report) != nil {
			t.Fatalf("/posture: %d %s", code, raw)
		}
		var names []string
		for _, p := range report.Programs {
			names = append(names, p.Source)
		}
		sort.Strings(names)
		return names, strings.Join(names, ","), report.Protections
	}
	every := "plain,scoped-a,scoped-b"
	if _, all, _ := read(tokenFor(t, issuer, "installation", nil)); all != every {
		t.Fatalf("the installation's caller reads programs %q, want %q", all, every)
	}
	configured := service.sources
	for _, tc := range []struct {
		name, token, want string
		unreached         []string
	}{
		{"scope A's caller", tokenFor(t, issuer, subjectA, []any{callerScopeA}), "scoped-a", []string{"scoped-b", "plain", callerScopeB}},
		{"scope B's caller", tokenFor(t, issuer, subjectB, []any{callerScopeB}), "scoped-b", []string{"scoped-a", "plain", callerScopeA}},
		{"a caller of no scope identifier", tokenFor(t, issuer, "subject-with-no-entry", nil), "plain", []string{"scoped-a", "scoped-b"}},
	} {
		_, got, _ := read(tc.token)
		if got != tc.want {
			t.Errorf("%s reads programs %q, want %q", tc.name, got, tc.want)
		}
		_, raw := postRawWith(t, server, "/posture", ``, tc.token)
		for _, name := range tc.unreached {
			if bytes.Contains(raw, []byte(`"`+name+`"`)) || bytes.Contains(raw, []byte(`\"`+name+`\"`)) {
				t.Errorf("%s's report names %q: %s", tc.name, name, raw)
			}
		}
		// the gateway with the sources the caller does not reach left out
		// answers it the same bytes
		reached := map[string]sourceSpec{}
		for name, spec := range configured {
			if !contains(tc.unreached, name) {
				reached[name] = spec
			}
		}
		service.sources = reached
		_, alone := postRawWith(t, server, "/posture", ``, tc.token)
		service.sources = configured
		if !bytes.Equal(raw, alone) {
			t.Errorf("%s's report changes with the sources it does not reach:\n%s\n%s", tc.name, raw, alone)
		}
	}
	unchecked := *service.identity
	unchecked.callers = callerScopes{unchecked: true}
	service.identity = &unchecked
	if _, got, _ := read(tokenFor(t, issuer, subjectA, []any{callerScopeA})); got != every {
		t.Fatalf("unchecked, scope A's caller reads programs %q, want %q", got, every)
	}
}
