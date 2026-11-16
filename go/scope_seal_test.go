package main

// A session is of one scope identifier on every kind, and its seal names it
// (docs/adr/0036-a-session-is-of-one-scope-identifier-and-its-seal-names-it.md,
// gateway #442): the filesystem kind refuses an acquisition of another scope
// into a session, and an action into a scoped one; a scoped session is
// sealed by a seal of version 2, which loads, and whose scope a verifier
// holds the receipts to; a session of no scope is sealed in §3's form, as
// before; and a store gateway v0.30.0 wrote verifies as v0.30.0 verified it.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
)

// scopedVerdict is the report of the service's store, as JSON.
func scopedVerdict(t *testing.T, g *gatewayService) *report {
	t.Helper()
	rep, err := verifyWithRegistry(g.storeRoot, g.regPath, g.authority, g.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// statusesOf are a report's findings that are not ok, as session/status.
func statusesOf(rep *report) []string {
	var out []string
	for _, f := range rep.Findings {
		if f["status"] != "ok" {
			out = append(out, fmt.Sprintf("%v/%v", f["sessionId"], f["status"]))
		}
	}
	return out
}

// An acquisition into a session of another scope -- a source of no scope
// into a scoped session, a scoped source into a session of no scope -- is
// refused before its source starts, in ADR-0033's sentence, which names no
// scope; the sessions keep the receipts of their own scope alone.
func TestASessionIsOfOneScopeOnTheFilesystemKind(t *testing.T) {
	service, server, _ := scopedService(t)
	scoped := `"scope":` + jsonText(t, testScope) + `,`
	acquire := func(session, source, scope string) (int, []byte) {
		return postRawWith(t, server, "/acquire", `{"session":"`+session+`","source":"`+source+`",`+scope+`"arguments":{"q":"a"}}`, "")
	}
	if code, raw := acquire("bound", "scoped", scoped); code != http.StatusOK {
		t.Fatalf("a scoped acquisition: %d %s", code, raw)
	}
	if code, raw := acquire("unbound", "plain", ""); code != http.StatusOK {
		t.Fatalf("an unscoped acquisition: %d %s", code, raw)
	}
	started := service.started.Load()
	for _, tc := range []struct{ session, source, scope string }{
		{"bound", "plain", ""},
		{"unbound", "scoped", scoped},
	} {
		code, raw := acquire(tc.session, tc.source, tc.scope)
		want := fmt.Sprintf(refusalOtherScope, tc.session)
		if code != http.StatusBadRequest || !bytes.Contains(raw, []byte(want)) || bytes.Contains(raw, []byte("quipe")) {
			t.Fatalf("%s into %s: %d %s", tc.source, tc.session, code, raw)
		}
	}
	if service.started.Load() != started {
		t.Fatal("a source started for a session of another scope")
	}
	// the session's own scope is still taken
	if code, raw := acquire("bound", "scoped", scoped); code != http.StatusOK {
		t.Fatalf("a second acquisition of the session's scope: %d %s", code, raw)
	}
	if rep := scopedVerdict(t, service); len(statusesOf(rep)) != 2 {
		t.Fatalf("two open sessions and nothing else: %v", rep.Findings)
	}
}

// An action is refused, at the session step and at its admission, in a
// session of a scope identifier: an action receipt carries no scope.
func TestAnActionIsRefusedInASessionOfAScope(t *testing.T) {
	service, _, _ := scopedService(t)
	service.sessions["bound"] = &sessionState{scope: testScope, created: true, index: 1}
	want := fmt.Sprintf(refusalActionInScope, "bound")
	if got := service.sessionOpen("bound"); got != want {
		t.Fatalf("the session step: %q", got)
	}
	err := service.admitAction("bound")
	if refusal, ok := err.(actRefusal); !ok || refusal.reason != want || strings.Contains(refusal.reason, "quipe") {
		t.Fatalf("the admission: %#v", err)
	}
	if service.sessions["bound"].inFlight != 0 {
		t.Fatal("a refused action was admitted")
	}
}

// A scoped session is sealed by a seal of version 2: its seven members,
// naming the scope by its digest in the session and never by the identifier,
// signed under its own prefix, loading under the gateway's key; a session of
// no scope is sealed in §3's form, the five members it always had. A digest
// changed or taken out, a version taken out or changed, and the identifier
// put on the seal beside its digest, load nothing, and the session reads
// unregistered.
func TestAScopedSessionsSealNamesItsScope(t *testing.T) {
	service, server, _ := scopedService(t)
	scoped := `"scope":` + jsonText(t, testScope) + `,`
	for _, call := range []struct{ session, source, scope string }{
		{"bound", "scoped", scoped}, {"bound", "scoped", scoped}, {"unbound", "plain", ""},
	} {
		if code, out := post(t, server, "/acquire", `{"session":"`+call.session+`","source":"`+call.source+`",`+call.scope+`"arguments":{"q":"a"}}`); code != http.StatusOK {
			t.Fatalf("%v: %d %v", call, code, out)
		}
	}
	code, bound := post(t, server, "/seal", `{"session":"bound"}`)
	if code != http.StatusOK {
		t.Fatalf("seal: %d %v", code, bound)
	}
	if code, out := post(t, server, "/seal", `{"session":"unbound"}`); code != http.StatusOK {
		t.Fatalf("seal: %d %v", code, out)
	}
	registry, err := os.ReadFile(service.regPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(registry), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("the registry: %q", registry)
	}
	var scopedSeal, plainSeal map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &scopedSeal); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &plainSeal); err != nil {
		t.Fatal(err)
	}
	if len(scopedSeal) != 7 || scopedSeal["scopeDigest"] != sealScopeDigest("bound", testScope) || scopedSeal["sealVersion"] != "2" || scopedSeal["finalCount"] != float64(2) {
		t.Fatalf("the seal of a scoped session: %s", lines[0])
	}
	// a registry line carries no scope identifier (ADR-0036; ADR-0033,
	// decision 5): the seal names the scope by its digest alone
	if strings.Contains(string(registry), testScope) || strings.Contains(string(registry), jsonText(t, testScope)) {
		t.Fatalf("the registry holds the scope identifier: %q", registry)
	}
	// §3's form, the bytes of its four members under its prefix
	if len(plainSeal) != 5 {
		t.Fatalf("the seal of a session of no scope: %s", lines[1])
	}
	signature := ed25519.Sign(ed25519.NewKeyFromSeed(testSeed), sealSigningInput("unbound", 1, plainSeal["sealedAt"].(string), service.keyID))
	if want := fmt.Sprintf(`{"finalCount":1,"keyId":"%s","sealedAt":"%s","sessionId":"unbound","signature":"%x"}`, service.keyID, plainSeal["sealedAt"], signature); lines[1] != want {
		t.Fatalf("the seal of a session of no scope is not §3's bytes:\n%s\n%s", lines[1], want)
	}
	if rep := scopedVerdict(t, service); !rep.OK || len(statusesOf(rep)) != 0 {
		t.Fatalf("both sealed sessions verify: %v", rep.Findings)
	}
	member := `"scopeDigest":"` + sealScopeDigest("bound", testScope) + `",`
	for _, tc := range []struct{ name, line string }{
		{"the digest changed", strings.Replace(lines[0], member, `"scopeDigest":"`+sealScopeDigest("bound", "équipe-b")+`",`, 1)},
		{"the digest taken out", strings.Replace(lines[0], member, "", 1)},
		{"the version and the digest taken out", strings.Replace(strings.Replace(lines[0], member, "", 1), `"sealVersion":"2",`, "", 1)},
		{"another version", strings.Replace(lines[0], `"sealVersion":"2"`, `"sealVersion":"3"`, 1)},
		{"a member more", strings.Replace(lines[0], `"finalCount"`, `"extra":1,"finalCount"`, 1)},
		{"the identifier beside its digest", strings.Replace(lines[0], member, `"scope":`+jsonText(t, testScope)+`,`+member, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.line == lines[0] {
				t.Fatal("the line is unchanged")
			}
			if err := os.WriteFile(service.regPath, []byte(tc.line+"\n"+lines[1]+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			rep := scopedVerdict(t, service)
			if got := statusesOf(rep); rep.OK || len(got) != 1 || got[0] != "bound/unregistered-session" {
				t.Fatalf("ok %v, %v", rep.OK, got)
			}
		})
	}
}

// A seal of version 2 is held to the receipts it counts: a session holding
// an accepted receipt of another scope, or of none, is seal-scope-mismatch,
// once, whichever seal of the two kinds names the scope; a seal of §3's form
// asks nothing of its receipts' scopes.
func TestASealNamingAScopeIsHeldToItsReceipts(t *testing.T) {
	service, server, _ := scopedService(t)
	scoped := `"scope":` + jsonText(t, testScope) + `,`
	for _, call := range []struct{ session, source, scope string }{
		{"of-none", "plain", ""}, {"of-none", "plain", ""}, {"of-scope", "scoped", scoped}, {"after", "plain", ""},
	} {
		if code, out := post(t, server, "/acquire", `{"session":"`+call.session+`","source":"`+call.source+`",`+call.scope+`"arguments":{"q":"a"}}`); code != http.StatusOK {
			t.Fatalf("%v: %d %v", call, code, out)
		}
	}
	// sealed by the writer, as no conforming gateway seals them
	if _, err := service.registry.sealOfScope("of-none", 2, "2026-11-16T00:00:00Z", testScope); err != nil {
		t.Fatal(err)
	}
	if _, err := service.registry.sealOfScope("of-scope", 1, "2026-11-16T00:00:00Z", "équipe-b"); err != nil {
		t.Fatal(err)
	}
	head := receiptSignature(t, service.storeRoot, "after", 0)
	if _, err := service.registry.sealAfterInterruptionOfScope("after", 1, head, "2026-11-16T00:00:00Z", sealedViaCommand, testScope); err != nil {
		t.Fatal(err)
	}
	rep := scopedVerdict(t, service)
	got := strings.Join(statusesOf(rep), " ")
	if rep.OK || got != "after/seal-scope-mismatch of-none/seal-scope-mismatch of-scope/seal-scope-mismatch" {
		t.Fatalf("ok %v, %s", rep.OK, got)
	}
}

// bindAsEarlier sets the scope identifier a session this process holds is
// bound to ("" for none), as no release since ADR-0036 does: how a test
// writes a session of several scopes, or seals one in §3's form, as a store
// an earlier release wrote holds them. A session not held is left alone.
func bindAsEarlier(g *gatewayService, session, scope string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if state, held := g.sessions[session]; held {
		state.scope = scope
	}
}

// v030Fixture is the store gateway v0.30.0 wrote by its own service under the
// test seed (testdata/v0.30.0-store), and v0.30.0's report of it.
type v030Fixture struct {
	Authority string            `json:"authority"`
	Files     map[string]string `json:"files"`
	Registry  string            `json:"registry"`
	Report    string            `json:"report"`
}

// A store gateway v0.30.0 wrote -- a sealed session mixing a scoped and an
// unscoped source, a sealed session of one scope, one of none, and a scoped
// session left open, every seal of §3's form -- verifies under this version
// to the report v0.30.0 gave, byte for byte; and the session it left open is
// sealed after the interruption naming its scope, and then verifies.
func TestAStoreV030WroteVerifiesUnchanged(t *testing.T) {
	data, err := os.ReadFile("testdata/v0.30.0-store/store.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture v030Fixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	storeRoot, regPath := materialize(t, fixture.Files, fixture.Registry)
	public := publicOf(ed25519.NewKeyFromSeed(testSeed))
	rep, err := verifyWithRegistry(storeRoot, regPath, fixture.Authority, public)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != fixture.Report {
		t.Fatalf("the report of a store v0.30.0 wrote:\n%s\nv0.30.0's:\n%s", got, fixture.Report)
	}

	seedPath := writeSeedFile(t, t.TempDir(), testSeed)
	var stdout, stderr bytes.Buffer
	if code := cmdSealOpenAt([]string{"--store", storeRoot, "--seed", seedPath, "--registry", regPath, "--authority", fixture.Authority, "--session", "left-open"},
		&stdout, &stderr, fixedStamp("2026-11-16T00:00:00Z")); code != 0 {
		t.Fatalf("seal-open: %d %s %s", code, stdout.String(), stderr.String())
	}
	var line map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &line); err != nil {
		t.Fatalf("%v: %s", err, stdout.String())
	}
	if len(line) != 10 || line["scopeDigest"] != sealScopeDigest("left-open", testScope) || line["sealVersion"] != "2" || line["kind"] != sealKindInterruption ||
		strings.Contains(stdout.String(), testScope) {
		t.Fatalf("the seal after an interruption of a scoped session: %s", stdout.String())
	}
	rep, err = verifyWithRegistry(storeRoot, regPath, fixture.Authority, public)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK || len(statusesOf(rep)) != 0 || len(rep.Observations) != 1 || rep.Observations[0]["observation"] != "sealed-after-interruption" {
		t.Fatalf("the store with the open session sealed: ok %v %v %v", rep.OK, rep.Findings, rep.Observations)
	}
}
