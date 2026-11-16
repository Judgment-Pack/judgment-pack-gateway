package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"
)

// With caller scopes checked, /posture's programs names only the sources
// the caller reaches (ADR-0037), as /acquire does not tell another scope's
// sources from unknown ones; the installation's caller and "unchecked" read
// every source, as before, and every protection line is the same whoever
// asks, judged over every source.
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
	_, all, lines := read(tokenFor(t, issuer, "installation", nil))
	if all != every {
		t.Fatalf("the installation's caller reads programs %q, want %q", all, every)
	}
	for _, tc := range []struct {
		name, token, want string
		unreached         []string
	}{
		{"scope A's caller", tokenFor(t, issuer, subjectA, []any{callerScopeA}), "scoped-a", []string{"scoped-b", "plain", callerScopeB}},
		{"scope B's caller", tokenFor(t, issuer, subjectB, []any{callerScopeB}), "scoped-b", []string{"scoped-a", "plain", callerScopeA}},
		{"a caller of no scope identifier", tokenFor(t, issuer, "subject-with-no-entry", nil), "plain", []string{"scoped-a", "scoped-b"}},
	} {
		_, got, gotLines := read(tc.token)
		if got != tc.want {
			t.Errorf("%s reads programs %q, want %q", tc.name, got, tc.want)
		}
		if !bytes.Equal(gotLines, lines) {
			t.Errorf("%s reads other protection lines than the installation's caller:\n%s\n%s", tc.name, gotLines, lines)
		}
		_, raw := postRawWith(t, server, "/posture", ``, tc.token)
		for _, name := range tc.unreached {
			if bytes.Contains(raw, []byte(`"`+name+`"`)) {
				t.Errorf("%s's report names %q: %s", tc.name, name, raw)
			}
		}
	}
	unchecked := *service.identity
	unchecked.callers = callerScopes{unchecked: true}
	service.identity = &unchecked
	if _, got, _ := read(tokenFor(t, issuer, subjectA, []any{callerScopeA})); got != every {
		t.Fatalf("unchecked, scope A's caller reads programs %q, want %q", got, every)
	}
}
