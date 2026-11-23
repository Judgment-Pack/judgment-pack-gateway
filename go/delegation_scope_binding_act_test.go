package main

import (
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// A delegated /act that names a scope identifier (ADR-0054, decision 1;
// spec RFC 0030 §2, the request check): the rows of
// testdata/delegation/spec-scope-binding.json whose routes include /act.
// The gateway has three write platforms: tickets, of none; tickets-a, fixed
// to testScope; and tickets-b, fixed to scopeOtherID. The issuing host may
// bind both identifiers, and the subject's own entry grants both and none.
// Each bound chain names the sources of both scopes, so where a request of
// one scope reaches a source of the other, only the gateway's own steps
// stand between them.

const scopeOtherID = "équipe-b"

type boundActHarness struct {
	*delegationHarness
	decisionA, citesA string
}

// boundChain is a root bound to id, with read-external and act on the
// sources of both scopes.
func boundChain(t *testing.T, id, statementID string) map[string]any {
	t.Helper()
	var entries []any
	for _, platform := range []string{"tickets-a", "tickets-b"} {
		entries = append(entries,
			scopeOf(platform+"/live", []any{"query"}, []any{"read-external"}, map[string]any{"calls": 10}),
			scopeOf(platform+"/write", []any{"query"}, []any{"act"}, map[string]any{}))
	}
	return statement(t, map[string]any{"id": statementID, "scope": boundScope(id, entries...)})
}

func newBoundActHarness(t *testing.T) *boundActHarness {
	t.Helper()
	h := newDelegationHarness(t, false)
	for platform, scope := range map[string]string{"tickets-a": testScope, "tickets-b": scopeOtherID} {
		write, live := h.g.sources["tickets/write"], h.g.sources["tickets/live"]
		write.scope, write.decisionRecords, live.scope = scope, filepath.Join(h.root, "decisions-"+platform), scope
		h.g.sources[platform+"/write"], h.g.sources[platform+"/live"] = write, live
	}
	h.server.Close()
	h.server = httptest.NewServer(h.g.handler())
	t.Cleanup(h.server.Close)
	h.d.hosts["desk"].scopeIDs = map[string]bool{testScope: true, scopeOtherID: true}
	h.g.identity.callers = callerScopes{entries: map[string]callerEntry{testSubjectSub: {grants: map[string]bool{testScope: true, scopeOtherID: true, unscopedMarker: true}}}}
	b := &boundActHarness{delegationHarness: h}
	// scope A's read, under a chain bound to it, which scope A's actions cite
	body := `{"session":"s-read-a","source":"tickets-a/live","scope":` + jsonText(t, testScope) + `,"arguments":{"tool":"query","arguments":{"key":"k"}}}`
	status, out := h.present(t, "/acquire", body, h.credential(t, boundChain(t, testScope, strings.Repeat("30", 16))))
	if status != http.StatusOK {
		t.Fatalf("scope A's read: %d %v", status, out)
	}
	receipt := out["receipt"].(map[string]any)
	cite := `[{"sessionId":"` + receipt["sessionId"].(string) + `","callIndex":` + strconv.Itoa(int(receipt["callIndex"].(float64))) + `,"signature":"` + receipt["signature"].(string) + `"}]`
	line := `{"kind":"evaluation","cites":` + cite + `}`
	dir := h.g.sources["tickets-a/write"].decisionRecords
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "decision.json"), []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	b.decisionA = `{"recordDigest":"` + digestOf(line) + `","packDigest":"sha256:` + strings.Repeat("d", 64) + `"}`
	b.citesA = cite
	return b
}

// body is an /act request; scope is raw JSON, or "" for none. A scoped
// platform's request cites scope A's read and relies on its record.
func (b *boundActHarness) body(session, platform, scope, key, extra string) string {
	decision, cites := string(b.call.Decision), string(b.call.Cites)
	if platform != "tickets" {
		decision, cites = b.decisionA, b.citesA
	}
	s := `{"session":"` + session + `","platform":"` + platform + `","tool":"query","arguments":{"ticket":"T-1"},"decision":` + decision + `,"cites":` + cites + `,"actionKey":"` + key + `"`
	if scope != "" {
		s += `,"scope":` + scope
	}
	return s + extra + "}"
}

// filesUnder counts the files beneath dir, none where it is not there.
func filesUnder(t *testing.T, dir string) int {
	t.Helper()
	n := 0
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			n++
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	return n
}

// request-bound-names-it: a chain bound to testScope names it on its
// platform's write. Admitted and counted once; the receipt carries the scope,
// its session's salt and the delegation; the key is in its scope's journal.
func TestADelegatedActNamesItsChainsScope(t *testing.T) {
	b := newBoundActHarness(t)
	cred := b.credential(t, boundChain(t, testScope, strings.Repeat("31", 16)))
	key, counted := delegationKey(1), b.host.counted()
	status, out := b.present(t, "/act", b.body("s-act-a", "tickets-a", jsonText(t, testScope), key, ""), cred)
	if status != http.StatusOK {
		t.Fatalf("request-bound-names-it: %d %v", status, out)
	}
	receipt := out["receipt"].(map[string]any)
	if salt, _ := receipt["scopeSalt"].(string); receipt["scope"] != testScope || !isLowerHexOfLen(salt, 64) || receipt["delegation"] == nil {
		t.Fatalf("the receipt does not carry the scope, its salt and the delegation: %v", receipt)
	}
	if b.host.counted() != counted+1 || b.sent(key) != 1 {
		t.Fatalf("counted %d, sent %d", b.host.counted()-counted, b.sent(key))
	}
	if filesUnder(t, scopedActionJournalPath(b.g.storeRoot, testScope)) == 0 {
		t.Fatal("the key is not in its scope's journal")
	}
}

// The refusals: each is /acquire's sentence at the scope identifier's step,
// before any admission read, leaving no session, label or journal entry and
// sending nothing. Those made at step 8 name a session the gateway holds of
// another scope than the one asked, which the session step would refuse by
// name: so each is shown to come before the session is looked up. The rows
// run once more with session labels, each naming a label never used, and
// leave no label.
func TestADelegatedActScopeRefusalsComeFirst(t *testing.T) {
	b := newBoundActHarness(t)
	credA := b.credential(t, boundChain(t, testScope, strings.Repeat("32", 16)))
	credB := b.credential(t, boundChain(t, scopeOtherID, strings.Repeat("33", 16)))
	unbound := b.credential(t, statement(t, map[string]any{"id": strings.Repeat("34", 16)}))
	notConfigured := b.credential(t, boundChain(t, testScope, strings.Repeat("35", 16)))
	a, other := jsonText(t, testScope), jsonText(t, scopeOtherID)
	cases := []struct {
		name, cred, session, platform, scope string
	}{
		{"request-bound-names-none", credA, "s-read-a", "tickets-a", ""},
		{"request-bound-names-other", credA, "s-read-a", "tickets-b", other},
		{"request-unbound-names-one", unbound, "read", "tickets-a", a},
		{"bound-not-configured", notConfigured, "read", "tickets-a", a},
		// step 10: a chain bound to scopeOtherID names it, on the write of
		// testScope, which its chain names too
		{"request-bound-source-of-other", credB, "s-ten", "tickets-a", other},
	}
	run := func(labelled bool) {
		for i, c := range cases {
			session := c.session
			if labelled {
				session = "label-" + strconv.Itoa(i)
			}
			if c.name == "bound-not-configured" {
				delete(b.d.hosts["desk"].scopeIDs, testScope)
			}
			key := delegationKey(10 + i)
			reads, counted, journal, labels := b.host.readCount(), b.host.counted(), journalFiles(t, b.g.storeRoot), filesUnder(t, filepath.Join(b.g.storeRoot, labelsDir))
			status, out := b.present(t, "/act", b.body(session, c.platform, c.scope, key, ""), c.cred)
			b.d.hosts["desk"].scopeIDs[testScope] = true
			if status != http.StatusBadRequest || out["refusedAt"] != "scope-identifier" || out["error"] != scopeRefusal {
				t.Fatalf("%s (labels %v): %d %v", c.name, labelled, status, out)
			}
			if b.host.readCount() != reads || b.host.counted() != counted || b.sent(key) != 0 {
				t.Fatalf("%s (labels %v): the issuing host was read or the key sent", c.name, labelled)
			}
			if journalFiles(t, b.g.storeRoot) != journal || filesUnder(t, filepath.Join(b.g.storeRoot, labelsDir)) != labels {
				t.Fatalf("%s (labels %v): a journal entry or a label is left", c.name, labelled)
			}
			if (labelled || session == "s-ten") && sessionHeld(b.g, session) {
				t.Fatalf("%s (labels %v): the session is held", c.name, labelled)
			}
		}
	}
	run(false)
	b.g.labels = fsLabels{root: b.g.storeRoot}
	run(true)
}

// A dry-run under a bound chain naming its scope: admitted as a dry-run. Its
// receipt carries the scope and the delegation; its reads of the issuing
// host are at "count": false, so the host counts nothing; nothing is sent
// and the journal is as it was.
func TestADelegatedDryRunNamesItsChainsScope(t *testing.T) {
	b := newBoundActHarness(t)
	b.g.dryRunApprovals = true
	cred := b.credential(t, boundChain(t, testScope, strings.Repeat("36", 16)))
	key, before, counted, journal := delegationKey(3), b.host.readCount(), b.host.counted(), journalFiles(t, b.g.storeRoot)
	status, out := b.present(t, "/act", b.body("s-dry", "tickets-a", jsonText(t, testScope), key, `,"dryRun":true`), cred)
	if status != http.StatusOK || out["dryRun"] == nil {
		t.Fatalf("the dry-run: %d %v", status, out)
	}
	receipt := out["dryRun"].(map[string]any)
	if receipt["scope"] != testScope || receipt["delegation"] == nil {
		t.Fatalf("the dry-run receipt: %v", receipt)
	}
	b.host.mu.Lock()
	reads := append([]map[string]any(nil), b.host.reads[before:]...)
	b.host.mu.Unlock()
	if len(reads) == 0 {
		t.Fatal("the dry-run made no admission read")
	}
	for _, r := range reads {
		if call, _ := r["call"].(map[string]any); call == nil || call["count"] != false {
			t.Fatalf("a read of the dry-run is not at count false: %v", r)
		}
	}
	if b.host.counted() != counted || b.sent(key) != 0 || journalFiles(t, b.g.storeRoot) != journal || sessionHeld(b.g, "s-dry") {
		t.Fatal("the dry-run counted, sent, wrote the journal or held its session")
	}
}

// A scoped delegated action's read-back is acquired with the action's scope
// in the action's session: its receipt carries the scope.
func TestADelegatedScopedActionReadsBackInItsScope(t *testing.T) {
	b := newBoundActHarness(t)
	actionKeysMode(t, b.root, "write", "drop")
	cred := b.credential(t, boundChain(t, testScope, strings.Repeat("37", 16)))
	key := delegationKey(4)
	status, out := b.present(t, "/act", b.body("s-rb", "tickets-a", jsonText(t, testScope), key, ""), cred)
	if status != http.StatusOK || out["reconciliation"] == nil {
		t.Fatalf("the uncertain scoped delegated action: %d %v", status, out)
	}
	read := out["reconciliation"].(map[string]any)["receipt"].(map[string]any)
	if read["scope"] != testScope || read["sessionId"] != "s-rb" {
		t.Fatalf("the read-back is not of the action's scope and session: %v", read)
	}
	if b.sent(key) != 1 {
		t.Fatalf("sent %d", b.sent(key))
	}
}
