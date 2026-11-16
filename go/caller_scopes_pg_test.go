package main

import (
	"fmt"
	"net/http"
	"os"
	"slices"
	"testing"
)

// On the PostgreSQL kind a caller of one scope identifier is held to its
// scope's view (ADR-0037, decision 6): an acquisition naming another scope
// identifier, which the body names and the caller's identity does not
// reach, is refused before any transaction of that scope, and leaves no row
// in its view; a seal of another scope's session is answered as one the
// gateway does not hold.
func TestAPostgresCallerOfOneScopeIsHeldToItsScopesView(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	t.Setenv(envSourceHelper, "1")
	helper := sourceSpec{argv: []string{os.Args[0]}, env: helperEnv}
	scoped := func(scope string) sourceSpec { s := helper; s.scope = scope; return s }
	_, started, server := scopedServiceStart(t, db, dir, map[string]sourceSpec{
		"screening-a": scoped("scope-a"), "screening-b": scoped("scope-b"), "plain": helper,
	})
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	id.callers = callerScopes{entries: map[string]callerEntry{
		subjectA: {grants: map[string]bool{"scope-a": true}},
		subjectB: {grants: map[string]bool{"scope-b": true}},
	}}
	started.service.identity = &id
	tokenA := tokenFor(t, issuer, subjectA, []any{"scope-a"})
	tokenB := tokenFor(t, issuer, subjectB, []any{"scope-b"})
	for _, call := range []struct {
		token, body string
		status      int
		answer      string
	}{
		{tokenA, acquireBodyFor("s-a", "screening-a", "scope-a"), http.StatusOK, ""},
		{tokenB, acquireBodyFor("s-b", "screening-b", "scope-b"), http.StatusOK, ""},
		{tokenA, acquireBodyFor("s-x", "screening-b", "scope-b"), http.StatusBadRequest, scopeRefusal},
		{tokenA, acquireBodyFor("s-b", "screening-b", "scope-b"), http.StatusBadRequest, scopeRefusal},
		{tokenA, acquireBodyFor("s-y", "plain", ""), http.StatusBadRequest, scopeRefusal},
	} {
		code, out := authed(t, server, "/acquire", call.body, call.token)
		if code != call.status || call.answer != "" && fmt.Sprint(out["error"]) != call.answer {
			t.Fatalf("%s: %d %v", call.body, code, out)
		}
	}
	if code, out := authed(t, server, "/seal", `{"session":"s-b"}`, tokenA); code != http.StatusBadRequest || fmt.Sprint(out["error"]) != "no such session: s-b" {
		t.Fatalf("A's caller seals B's session: %d %v", code, out)
	}
	for token, session := range map[string]string{tokenA: "s-a", tokenB: "s-b"} {
		if code, out := authed(t, server, "/seal", `{"session":"`+session+`"}`, token); code != http.StatusOK {
			t.Fatalf("the seal of %s by its scope's caller: %d %v", session, code, out)
		}
	}
	c := db.runtimeConn(t)
	for scope, want := range map[string][]string{"": nil, "scope-a": {"s-a"}, "scope-b": {"s-b"}} {
		pgInScopeOn(t, c, pgRowScope(scope), func() {
			got := pgColumn(t, c, `SELECT name FROM gateway.series ORDER BY name`)
			if !slices.Equal(got, want) && !(len(got) == 0 && len(want) == 0) {
				t.Errorf("scope %q holds the sessions %v, want %v", scope, got, want)
			}
		})
	}
}
