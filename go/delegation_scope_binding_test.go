package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
)

// specScopeBindingSHA256 is the SHA-256 of testdata/delegation/spec-scope-binding.json,
// as the spec repository's conformance/delegation/README.md records it for
// its conformance/delegation/scope-binding.json, of which this file is a
// byte-for-byte copy: spec RFC 0030's table 3, made once by the signer that
// made tables 1 and 2, independent of this repository, and frozen.
const specScopeBindingSHA256 = "04559c4a04d3f64f059beb47f54790382825b0eb9a5f6c13173762470b54a142"

// agentScopeBindingSHA256 is the SHA-256 of testdata/delegation/agent-scope-binding.json,
// a byte-for-byte copy of the agent library's contract/vectors/principal/scope-binding.json
// (judgment-pack-agent, commit 86f6cfa0b040a0d49faf1b1504887207d1015b35):
// the library's own scope-binding vectors, signed by node:crypto.
const agentScopeBindingSHA256 = "660837b405bc50f47d1581f2d3f8bc2a19a880e5924ab625730a48899362129b"

// ed25519StatementsSHA256 is the SHA-256 of testdata/delegation/statements.json,
// the 39 Ed25519 cases, which the spec repository copies byte for byte as
// conformance/delegation/ed25519-statements.json and records by this digest.
const ed25519StatementsSHA256 = "b1bdfe50cbab49f6408395511c0f9fbee897193f6c58f63328a6d677b99c3bd9"

func readFrozen(t *testing.T, path, want string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != want {
		t.Fatalf("%s is not the frozen file: sha256 %x", path, sum)
	}
	return raw
}

// Each copy is its frozen file, byte for byte.
func TestDelegationScopeBindingCasesAreTheFrozenBytes(t *testing.T) {
	readFrozen(t, "../testdata/delegation/spec-scope-binding.json", specScopeBindingSHA256)
	readFrozen(t, "../testdata/delegation/agent-scope-binding.json", agentScopeBindingSHA256)
	readFrozen(t, "../testdata/delegation/statements.json", ed25519StatementsSHA256)
}

type bindingStatement struct {
	Name   string          `json:"name"`
	Kind   string          `json:"kind"`
	Expect string          `json:"expect"`
	Link   *int            `json:"link"`
	Chain  json.RawMessage `json:"chain"`
}

// chainVerdict is steps 1 to 7 for a chain: its chain, or the first refusal's
// name and reason.
func chainVerdict(t *testing.T, raw json.RawMessage, keys delegationKeys) (*delegationChain, string, string) {
	t.Helper()
	value, err := parseJSONWithin(raw, maxArgumentValues)
	if err != nil {
		return nil, refusalMalformed, ""
	}
	chain, refusal := verifyDelegationChain(value, keys)
	if refusal != nil {
		return nil, refusal.name, refusal.reason
	}
	return chain, "ok", ""
}

func checkStatement(t *testing.T, s bindingStatement, keys delegationKeys) {
	t.Helper()
	_, got, at := chainVerdict(t, s.Chain, keys)
	if got != s.Expect {
		t.Fatalf("%s: got %s (%s), want %s", s.Name, got, at, s.Expect)
	}
	if s.Link != nil && !strings.HasPrefix(at, fmt.Sprintf("link %d ", *s.Link)) && !strings.HasPrefix(at, fmt.Sprintf("link %d: ", *s.Link)) {
		t.Fatalf("%s: refused at %q, want link %d", s.Name, at, *s.Link)
	}
}

// requestVerdict is how the gateway decides a request under chain, at an
// issuing host that may bind hostScopeIDs, to a source fixed to sourceScope
// ("" for none): the request check, then /acquire's wrong-scope rule.
func requestVerdict(chain *delegationChain, hostScopeIDs []string, asked requestedScope, sourceScope string) string {
	host := &delegationHost{delegationHostSpec: delegationHostSpec{host: "desk", scopeIDs: map[string]bool{}}}
	for _, id := range hostScopeIDs {
		host.scopeIDs[id] = true
	}
	d := newDelegationService(map[string]*delegationHost{"desk": host}, nil, false)
	sender := &delegatedSender{kind: "actor", credential: &boundCredential{host: "desk", chain: chain}}
	switch {
	case d.scopeIDMismatch(sender, asked):
		return refusalScopeIDMismatch
	case !scopeHolds(sourceSpec{scope: sourceScope}, asked):
		return "wrong-scope"
	}
	return "admitted"
}

func askedOf(t *testing.T, raw json.RawMessage) requestedScope {
	t.Helper()
	if raw == nil || string(raw) == "null" {
		return requestedScope{}
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	return requestedScope{value: s, named: true}
}

// The spec's table 3: every statement row gets its verdict of steps 1 to 7,
// and every request row the gateway decides gets its verdict from the request
// check and /acquire's wrong-scope rule. The library's rows (a run's source
// mapping, a receipt the harness checks, a host source) are the library's
// alone, and are counted, not decided.
func TestDelegationScopeBindingSpecCases(t *testing.T) {
	raw := readFrozen(t, "../testdata/delegation/spec-scope-binding.json", specScopeBindingSHA256)
	var doc struct {
		Keys       map[string][]json.RawMessage `json:"keys"`
		Unbound    struct{ File string }        `json:"unbound"`
		Statements []bindingStatement           `json:"statements"`
		Requests   []struct {
			Name         string   `json:"name"`
			Expect       string   `json:"expect"`
			AppliesTo    []string `json:"appliesTo"`
			HostScopeIDs []string `json:"hostScopeIds"`
			At           []string `json:"at"`
			Request      struct {
				Routes      []string        `json:"routes"`
				Scope       json.RawMessage `json:"scope"`
				SourceScope json.RawMessage `json:"sourceScope"`
			} `json:"request"`
			Chain json.RawMessage `json:"chain"`
		} `json:"requests"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	keys := pinDelegationKeys(t, doc.Keys)
	if len(doc.Statements) != 9 || len(doc.Requests) != 10 {
		t.Fatalf("%d statements and %d requests, want 9 and 10", len(doc.Statements), len(doc.Requests))
	}
	for _, s := range doc.Statements {
		checkStatement(t, s, keys)
	}
	// unbound-unchanged: table 1's chains hold no scopeId, and
	// TestDelegationES256Cases gives each its recorded verdict.
	if doc.Unbound.File != "es256-statements.json" || strings.Contains(string(readFrozen(t, es256StatementsPath, es256StatementsSHA256)), `"scopeId"`) {
		t.Fatal("the unbound row does not name table 1's unbound cases")
	}
	decided, library := 0, []string{}
	for _, r := range doc.Requests {
		if !slices.Contains(r.AppliesTo, "gateway") {
			library = append(library, r.Name)
			continue
		}
		decided++
		chain, got, at := chainVerdict(t, r.Chain, keys)
		if got != "ok" {
			t.Fatalf("%s: the chain is refused %s (%s)", r.Name, got, at)
		}
		if !slices.Contains(r.Request.Routes, "/acquire") {
			t.Fatalf("%s: routes %v", r.Name, r.Request.Routes)
		}
		source := askedOf(t, r.Request.SourceScope)
		if v := requestVerdict(chain, r.HostScopeIDs, askedOf(t, r.Request.Scope), source.value); v != r.Expect {
			t.Fatalf("%s: got %s, want %s", r.Name, v, r.Expect)
		}
		if slices.Contains(r.At, "binding") {
			host := &delegationHost{delegationHostSpec: delegationHostSpec{scopeIDs: map[string]bool{}}}
			for _, id := range r.HostScopeIDs {
				host.scopeIDs[id] = true
			}
			if !(&delegationService{}).bindingRefused(host, chain) {
				t.Fatalf("%s: bound at binding", r.Name)
			}
		}
	}
	if decided != 7 || !slices.Equal(library, []string{"library-bound-mapping-other", "library-receipt-scope-differs", "library-bound-host-source"}) {
		t.Fatalf("decided %d, the library's %v", decided, library)
	}
}

// The agent library's own vectors, read by the gateway: every statement row
// (steps 1 to 7, the form of scopeId and clause 9 among them), and the
// request check of every request row to a gateway source. The request rows'
// host configuration is the gateway's own, so the issuing host is configured
// to bind each chain's scope identifier: the rows test cases 1 and 2.
// Not decided here: library-bound-host-source, a host source the gateway
// does not enforce; and the five bindings rows, which bind a gateway source
// of a run's gate by its mapping and the receipts the host verifies, which
// the gateway has neither of. reads is the library's own port.
func TestDelegationScopeBindingAgentVectors(t *testing.T) {
	raw := readFrozen(t, "../testdata/delegation/agent-scope-binding.json", agentScopeBindingSHA256)
	var doc struct {
		Keys       map[string][]json.RawMessage `json:"keys"`
		Statements []bindingStatement           `json:"statements"`
		Requests   []struct {
			Name  string `json:"name"`
			Chain string `json:"chain"`
			Call  struct {
				Audience struct{ Kind string } `json:"audience"`
				ScopeID  json.RawMessage       `json:"scopeId"`
			} `json:"call"`
			Expect string `json:"expect"`
		} `json:"requests"`
		Bindings []json.RawMessage `json:"bindings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	keys := pinDelegationKeys(t, doc.Keys)
	chains := map[string]*delegationChain{}
	for _, s := range doc.Statements {
		checkStatement(t, s, keys)
		if chain, got, _ := chainVerdict(t, s.Chain, keys); got == "ok" {
			chains[s.Name] = chain
		}
	}
	decided := 0
	for _, r := range doc.Requests {
		if r.Call.Audience.Kind != "gateway" {
			if r.Name != "library-bound-host-source" {
				t.Fatalf("%s: a host source row the test does not name", r.Name)
			}
			continue
		}
		chain := chains[r.Chain]
		if chain == nil {
			t.Fatalf("%s: no chain %s", r.Name, r.Chain)
		}
		id, _ := chain.scopeBinding()
		asked := askedOf(t, r.Call.ScopeID)
		want := map[string]string{"admit": "admitted", "scope-id-mismatch": refusalScopeIDMismatch}[r.Expect]
		if v := requestVerdict(chain, []string{id}, asked, asked.value); v != want {
			t.Fatalf("%s: got %s, want %s", r.Name, v, r.Expect)
		}
		decided++
	}
	if len(doc.Statements) != 17 || decided != 6 || len(doc.Bindings) != 5 {
		t.Fatalf("%d statements, %d requests decided, %d bindings", len(doc.Statements), decided, len(doc.Bindings))
	}
}

// boundScope is the harness's root scope bound to id.
func boundScope(id string, entries ...any) map[string]any {
	if len(entries) == 0 {
		entries = []any{
			scopeOf("tickets/live", []any{"query"}, []any{"read-external"}, map[string]any{"calls": 10}),
			scopeOf("tickets/write", []any{"query"}, []any{"act"}, map[string]any{}),
		}
	}
	return map[string]any{"sources": entries, "scopeId": id}
}

// scopedHarness is a delegation harness whose tickets/live is fixed to
// testScope, whose issuing host may bind ids, and whose subject's entry
// grants testScope.
func scopedHarness(t *testing.T, ids ...string) *delegationHarness {
	h := newDelegationHarness(t, false)
	live := h.g.sources["tickets/live"]
	live.scope = testScope
	h.g.sources["tickets/live"] = live
	h.server.Close()
	h.server = httptest.NewServer(h.g.handler())
	t.Cleanup(h.server.Close)
	h.d.hosts["desk"].scopeIDs = map[string]bool{}
	for _, id := range ids {
		h.d.hosts["desk"].scopeIDs[id] = true
	}
	h.g.identity.callers = callerScopes{entries: map[string]callerEntry{testSubjectSub: {grants: map[string]bool{testScope: true, "équipe-b": true}}}}
	return h
}

// A chain bound to a scope identifier reaches that identifier's sources when
// the request names it, and is counted once. Naming none, or another, is the
// request check's refusal, with /acquire's sentence, before the issuing host
// is read or anything is counted; so is naming it under a chain bound to
// another; and so is a subject whose own entry does not grant it.
func TestABoundChainReachesItsScopeIdentifierAlone(t *testing.T) {
	h := scopedHarness(t, testScope, "équipe-b")
	root := statement(t, map[string]any{"scope": boundScope(testScope)})
	child := childOf(t, root, map[string]any{"scope": boundScope(testScope,
		scopeOf("tickets/live", []any{"query"}, []any{"read-external"}, map[string]any{"calls": 5}))})
	cred := h.credential(t, root, child)
	body := func(scope string) string {
		return strings.Replace(h.acquireBody("s-bound", "query"), `"source":"tickets/live",`, `"source":"tickets/live",`+scope, 1)
	}
	asFixed := `"scope":` + jsonText(t, testScope) + `,`
	refusedUncounted := func(what, b, credential string) {
		t.Helper()
		reads, counted, started := h.host.readCount(), h.host.counted(), h.g.started.Load()
		status, out := h.present(t, "/acquire", b, credential)
		if status != http.StatusBadRequest || out["error"] != scopeRefusal {
			t.Fatalf("%s: %d %v", what, status, out)
		}
		if h.host.counted() != counted || h.host.readCount() != reads || h.g.started.Load() != started || sessionHeld(h.g, "s-bound") {
			t.Fatalf("%s: counted, read, run or admitted", what)
		}
	}
	refusedUncounted("request-bound-names-none", body(``), cred)
	refusedUncounted("request-bound-names-other", body(`"scope":"équipe-b",`), cred)
	refusedUncounted("an empty scope", body(`"scope":"",`), cred)
	// request-bound-source-of-other: a chain bound to équipe-b, naming it,
	// to the source fixed to testScope.
	other := statement(t, map[string]any{"scope": boundScope("équipe-b")})
	refusedUncounted("request-bound-source-of-other", body(`"scope":"équipe-b",`), h.credential(t, other))
	// The subject's own entry does not grant the scope identifier.
	h.g.identity.callers = callerScopes{entries: map[string]callerEntry{testSubjectSub: unscopedEntry}}
	refusedUncounted("a subject not granted the scope identifier", body(asFixed), cred)
	h.g.identity.callers = callerScopes{entries: map[string]callerEntry{testSubjectSub: {grants: map[string]bool{testScope: true}}}}
	// Under a bound chain, a source of no scope identifier is not reached.
	live := h.g.sources["tickets/live"]
	live.scope = ""
	h.g.sources["tickets/live"] = live
	refusedUncounted("a bound chain to a source of none", body(``), cred)
	live.scope = testScope
	h.g.sources["tickets/live"] = live
	counted := h.host.counted()
	status, out := h.present(t, "/acquire", body(asFixed), cred)
	if status != http.StatusOK || out["receipt"].(map[string]any)["scope"] != testScope {
		t.Fatalf("request-bound-names-it: %d %v", status, out)
	}
	if h.host.counted() != counted+1 {
		t.Fatalf("the acquisition is counted once: %d", h.host.counted()-counted)
	}
}

// bound-not-configured: a chain bound to a scope identifier the issuing
// host's entry does not name gets no credential, and a credential bound
// while it was named is refused at the call once it is not, uncounted.
func TestABoundChainTheHostMayNotBindIsRefused(t *testing.T) {
	h := scopedHarness(t)
	root := statement(t, map[string]any{"scope": boundScope(testScope)})
	reads := h.host.readCount()
	status, out := h.bind(t, []map[string]any{root}, nil)
	if status == http.StatusOK || refusalOf(out) != refusalScopeIDMismatch {
		t.Fatalf("at binding: %d %v", status, out)
	}
	if h.host.readCount() != reads {
		t.Fatal("the issuing host was read for a binding the check refuses")
	}
	h.d.hosts["desk"].scopeIDs[testScope] = true
	cred := h.credential(t, root)
	delete(h.d.hosts["desk"].scopeIDs, testScope)
	reads, counted := h.host.readCount(), h.host.counted()
	status, out = h.present(t, "/acquire", strings.Replace(h.acquireBody("s-nc", "query"), `"source":"tickets/live",`, `"source":"tickets/live","scope":`+jsonText(t, testScope)+`,`, 1), cred)
	if status != http.StatusBadRequest || out["error"] != scopeRefusal || h.host.readCount() != reads || h.host.counted() != counted {
		t.Fatalf("at a call: %d %v", status, out)
	}
}

// A delegated /act under a bound chain names no scope here, and no write
// source is fixed to one, so it is refused before the issuing host is read or
// a key is sent: where caller scope identifiers are checked, at the step
// before the body, since a bound chain reaches no source of none; where they
// are unchecked, at the scope step, with /acquire's sentence. An unbound
// chain's /act is unchanged (TestDelegatedCallsAreAdmittedAndReceipted).
func TestADelegatedActUnderABoundChainIsRefusedAtTheScopeStep(t *testing.T) {
	h := scopedHarness(t, testScope)
	cred := h.credential(t, statement(t, map[string]any{"scope": boundScope(testScope)}))
	reads, key := h.host.readCount(), delegationKey(7)
	status, out := h.present(t, "/act", h.actBody("s-act", key, ""), cred)
	if status != http.StatusForbidden || out["refusedAt"] != "scope-identifier" {
		t.Fatalf("checked: %d %v", status, out)
	}
	h.g.identity.callers = callerScopes{unchecked: true}
	status, out = h.present(t, "/act", h.actBody("s-act", key, ""), cred)
	if status != http.StatusBadRequest || out["error"] != scopeRefusal || out["refusedAt"] != "scope-identifier" {
		t.Fatalf("unchecked: %d %v", status, out)
	}
	if h.host.readCount() != reads || h.sent(key) != 0 {
		t.Fatal("a refused /act read the issuing host or sent its key")
	}
}

// scopeIds is a member of an issuing host's entry from its version: a list of
// distinct scope identifiers, never the marker; refused by name before it.
func TestDelegationHostScopeIdsConfig(t *testing.T) {
	pub := hex.EncodeToString(ed25519.NewKeyFromSeed(delegationHostSeed).Public().(ed25519.PublicKey))
	identity := &identitySpec{issuer: testIssuerURL, audience: "gateway:acme", keys: "/k"}
	tokenPath := abs(t, t.TempDir(), "desk-token")
	with := func(ids string) string {
		return strings.Replace(delegationConfigText(pub, "https://desk.example/admission", tokenPath, ""), `"requester":"service:desk"`, `"requester":"service:desk","scopeIds":`+ids, 1)
	}
	parse := func(text, version string) (*delegationSpec, error) {
		v, err := parseJSON([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		return parseDelegationConfig(v, version, identity)
	}
	spec, err := parse(with(`["scope-a","équipe-b"]`), delegationScopeBindingVersion)
	if err != nil || !spec.hosts[0].scopeIDs["scope-a"] || !spec.hosts[0].scopeIDs["équipe-b"] || len(spec.hosts[0].scopeIDs) != 2 {
		t.Fatalf("%+v %v", spec, err)
	}
	if spec, err := parse(delegationConfigText(pub, "https://desk.example/admission", tokenPath, ""), delegationScopeBindingVersion); err != nil || len(spec.hosts[0].scopeIDs) != 0 {
		t.Fatalf("none by default: %v", err)
	}
	for _, c := range []struct{ name, text, version, want string }{
		{"before its version", with(`["scope-a"]`), delegationP256Version, "scopeIds is a version-" + delegationScopeBindingVersion + " member"},
		{"empty", with(`[]`), delegationScopeBindingVersion, "at least one scope identifier"},
		{"the marker", with(`["unscoped"]`), delegationScopeBindingVersion, "is not a scope identifier"},
		{"not a string", with(`[7]`), delegationScopeBindingVersion, "is not a scope identifier"},
		{"a line feed", with(`["a\nb"]`), delegationScopeBindingVersion, "is not a scope identifier"},
		{"a repeat", with(`["scope-a","scope-a"]`), delegationScopeBindingVersion, "repeats a scope identifier"},
	} {
		if _, err := parse(c.text, c.version); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: want %q, got %v", c.name, c.want, err)
		}
	}
}
