package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// On the PostgreSQL kind, a session this instance does not hold is answered
// by its series' scope (ADR-0037): one an earlier process left open, and one
// another live instance holds, are to a caller of another scope identifier a
// session that is not there, and to a caller of the session's scope what
// they always were.
func TestAPostgresSessionThisInstanceDoesNotHoldIsAnsweredByItsScope(t *testing.T) {
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	id.callers = callerScopes{entries: map[string]callerEntry{
		subjectA: {grants: map[string]bool{"scope-a": true}},
		subjectB: {grants: map[string]bool{"scope-b": true}},
	}}
	tokenA := tokenFor(t, issuer, subjectA, []any{"scope-a"})
	tokenB := tokenFor(t, issuer, subjectB, []any{"scope-b"})
	check := func(t *testing.T, server *httptest.Server, token, body string, status int, answer string) {
		t.Helper()
		code, out := authed(t, server, "/seal", body, token)
		if code != status || fmt.Sprint(out["error"]) != answer {
			t.Fatalf("seal %s: %d %v", body, code, out)
		}
	}

	t.Run("left open by an earlier process", func(t *testing.T) {
		kind, _ := pgTestKind(t, "", nil)
		views, err := kind.scopeViews([]string{"scope-a", "scope-b"})
		if err != nil {
			t.Fatal(err)
		}
		b := views["scope-b"]
		stampSession(t, newStoreOn("", b.artifacts(), b.receipts(), testSeed, "gateway:test"), "left-b", 1)
		if err := kind.registry().createLog(); err != nil {
			t.Fatal(err)
		}
		service, err := newGatewayServiceOn(kind, testSeed, "gateway:test", sealOpenPgSources(t))
		if err != nil {
			t.Fatal(err)
		}
		service.identity = &id
		server := httptest.NewServer(service.handler())
		t.Cleanup(server.Close)
		check(t, server, tokenA, `{"session":"left-b"}`, http.StatusBadRequest, "no such session: left-b")
		check(t, server, tokenB, `{"session":"left-b"}`, http.StatusBadRequest, fmt.Sprintf(refusalLeftOpen, "left-b"))
	})

	t.Run("held by another instance", func(t *testing.T) {
		db := newPgTestDB(t)
		db.migrate(t)
		dir := tempDirAt(t, 0o700)
		_, cfg := instancesPgConfig(t, db, dir, "engine.json", false)
		sources := sealOpenPgSources(t)
		var said bytes.Buffer
		a, err := startEngineOnKind(cfg, testSeed, sources, nil, &said)
		if err != nil {
			t.Fatalf("instance a: %v", err)
		}
		defer a.stop(&said)
		other, err := startEngineOnKind(cfg, testSeed, sources, nil, &said)
		if err != nil {
			t.Fatalf("instance b beside a: %v\n%s", err, said.String())
		}
		defer other.stop(&said)
		a.service.identity, other.service.identity = &id, &id
		serverA := httptest.NewServer(a.service.handler())
		defer serverA.Close()
		serverOther := httptest.NewServer(other.service.handler())
		defer serverOther.Close()
		if code, out := authed(t, serverA, "/acquire", acquireBodyFor("held-b", "screening-b", "scope-b"), tokenB); code != http.StatusOK {
			t.Fatalf("B's caller on instance a: %d %v", code, out)
		}
		check(t, serverOther, tokenA, `{"session":"held-b"}`, http.StatusBadRequest, "no such session: held-b")
		check(t, serverOther, tokenB, `{"session":"held-b"}`, http.StatusConflict, fmt.Sprintf(refusalHeldElsewhere, "held-b"))
		if code, out := authed(t, serverOther, "/acquire", acquireBodyFor("held-b", "screening-a", "scope-a"), tokenA); code != http.StatusBadRequest || fmt.Sprint(out["error"]) != fmt.Sprintf(refusalOtherScope, "held-b") {
			t.Fatalf("A's caller acquires into B's session on the other instance: %d %v", code, out)
		}
	})
}
