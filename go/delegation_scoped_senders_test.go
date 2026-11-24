package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// A reservation sender other than the run's actor -- the subject, the
// issuing host or an operator -- reconciling a scoped delegated key (SPEC.md
// §11.8, "A scoped delegated action"; ADR-0054's amendment of 2026-11-24). It
// names the scope identifier in /act's scope member, as the actor does, and
// is admitted only where (a) the issuing host's scopeIds lists it, (b) the
// subject's caller entry grants it and (c) its own token reaches it. Where
// any of the three fails it is answered byte for byte as for a scope
// identifier that exists nowhere, before any standing, host, key or journal
// is read.

// scopeNowhere is a scope identifier no host, entry or source names.
const scopeNowhere = "équipe-nulle-part"

var senderKinds = []struct{ subject, kind string }{
	{testSubjectSub, "subject"}, {hostRequester, "host"}, {testOperator, "operator"},
}

// newScopedSenderHarness is newBoundActHarness with the issuing host's
// requester and the operator granted both scope identifiers and none, as the
// subject is, and a scoped delegated action already answered under key.
func newScopedSenderHarness(t *testing.T, key string) (*boundActHarness, map[string]any) {
	t.Helper()
	b := newBoundActHarness(t)
	both := callerEntry{grants: map[string]bool{testScope: true, scopeOtherID: true, unscopedMarker: true}}
	b.g.identity.callers.entries[hostRequester] = both
	b.g.identity.callers.entries[testOperator] = both
	cred := b.credential(t, boundChain(t, testScope, strings.Repeat("41", 16)))
	status, out := b.present(t, "/act", b.body("s-act-a", "tickets-a", jsonText(t, testScope), key, ""), cred)
	if status != http.StatusOK {
		t.Fatalf("the scoped delegated action: %d %v", status, out)
	}
	return b, out
}

// scopedToken is a token for subject whose claim names scopes.
func scopedToken(t *testing.T, h *delegationHarness, subject string, scopes ...string) string {
	t.Helper()
	claim := make([]any, len(scopes))
	for i, s := range scopes {
		claim[i] = s
	}
	now := time.Now()
	return h.issuer.mint(t, "ed-1", nil, map[string]any{"iss": testIssuerURL, "sub": subject, "aud": "gateway:acme", "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), scopeClaimName: claim})
}

// senderAnswer is an /act answer as sent: its status, its headers but Date,
// and its body's bytes.
type senderAnswer struct {
	status int
	header http.Header
	body   string
}

func postSenderRaw(t *testing.T, h *delegationHarness, body, token string) senderAnswer {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.server.URL+"/act", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	header := resp.Header.Clone()
	header.Del("Date")
	return senderAnswer{resp.StatusCode, header, string(raw)}
}

func (a senderAnswer) same(b senderAnswer) bool {
	if a.status != b.status || a.body != b.body || len(a.header) != len(b.header) {
		return false
	}
	for name, values := range a.header {
		if strings.Join(values, "\n") != strings.Join(b.header[name], "\n") {
			return false
		}
	}
	return true
}

// actionsTreeDigest is every file beneath the store's actions directory, by
// name and bytes.
func actionsTreeDigest(t *testing.T, storeRoot string) string {
	t.Helper()
	root := filepath.Join(storeRoot, "actions")
	var lines []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			lines = append(lines, rel+"/")
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		lines = append(lines, rel+" "+hex.EncodeToString(sum[:]))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// dispatchMarkers counts the dispatch markers in the store's journals.
func dispatchMarkers(t *testing.T, storeRoot string) int {
	t.Helper()
	n := 0
	_ = filepath.WalkDir(filepath.Join(storeRoot, "actions"), func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasPrefix(d.Name(), "dispatch-") {
			n++
		}
		return nil
	})
	return n
}

// Each sender kind, its own token reaching the scope, the host listing it
// and the subject's entry granting it: served the actor's evidence, a plain
// request and a reconciling one alike. Nothing is sent again, no dispatch
// marker is made, no call is counted, and the journal is as it was.
func TestAReservationSenderReconcilesAScopedDelegatedKey(t *testing.T) {
	key := delegationKey(1)
	b, actor := newScopedSenderHarness(t, key)
	want := actor["receipt"].(map[string]any)["signature"]
	reservation := b.reservationOf(testSub(), rootAgent)
	markers, journal, counted := dispatchMarkers(t, b.g.storeRoot), actionsTreeDigest(t, b.g.storeRoot), b.host.counted()
	for _, c := range senderKinds {
		token := scopedToken(t, b.delegationHarness, c.subject, testScope)
		for _, extra := range []string{reservation, `,"reconcile":true` + reservation} {
			status, out := b.post(t, "/act", b.body("s-"+c.kind, "tickets-a", jsonText(t, testScope), key, extra), map[string]string{"Authorization": "Bearer " + token})
			if status != http.StatusOK {
				t.Fatalf("%s %s: %d %v", c.kind, extra, status, out)
			}
			receipt := out["receipt"].(map[string]any)
			if receipt["signature"] != want || receipt["scope"] != testScope {
				t.Fatalf("%s: not the actor's evidence: %v", c.kind, receipt)
			}
		}
	}
	if b.sent(key) != 1 || dispatchMarkers(t, b.g.storeRoot) != markers || b.host.counted() != counted {
		t.Fatalf("sent %d, markers %d to %d, counted %d", b.sent(key), markers, dispatchMarkers(t, b.g.storeRoot), b.host.counted()-counted)
	}
	if actionsTreeDigest(t, b.g.storeRoot) != journal {
		t.Fatal("a sender's request changed the journal")
	}
}

// The read-back (decision 5): an uncertain scoped key, read back for each
// sender in the action's scope. Its answer carries no member the actor's own
// read-back of the same key does not, beyond the reconciler the table
// records, and nothing is sent again.
func TestAReservationSenderReadsBackAScopedDelegatedKey(t *testing.T) {
	b := newBoundActHarness(t)
	both := callerEntry{grants: map[string]bool{testScope: true, scopeOtherID: true, unscopedMarker: true}}
	b.g.identity.callers.entries[hostRequester] = both
	b.g.identity.callers.entries[testOperator] = both
	actionKeysMode(t, b.root, "write", "drop")
	cred := b.credential(t, boundChain(t, testScope, strings.Repeat("42", 16)))
	key := delegationKey(2)
	if status, out := b.present(t, "/act", b.body("s-rb", "tickets-a", jsonText(t, testScope), key, ""), cred); status != http.StatusOK || out["reconciliation"] == nil {
		t.Fatalf("the uncertain scoped delegated action: %d %v", status, out)
	}
	status, own := b.present(t, "/act", b.body("s-rb", "tickets-a", jsonText(t, testScope), key, `,"reconcile":true`), cred)
	if status != http.StatusOK || own["reconciliation"] == nil {
		t.Fatalf("the actor's own read-back: %d %v", status, own)
	}
	ownRead, _ := reconciledBy(t, own)
	markers, counted := dispatchMarkers(t, b.g.storeRoot), b.host.counted()
	reservation := b.reservationOf(testSub(), rootAgent)
	for _, c := range senderKinds {
		token := scopedToken(t, b.delegationHarness, c.subject, testScope)
		status, out := b.post(t, "/act", b.body("s-"+c.kind, "tickets-a", jsonText(t, testScope), key, `,"reconcile":true`+reservation), map[string]string{"Authorization": "Bearer " + token})
		if status != http.StatusOK {
			t.Fatalf("%s: %d %v", c.kind, status, out)
		}
		read, rec := reconciledBy(t, out)
		if rec["kind"] != c.kind || read["scope"] != testScope {
			t.Fatalf("%s: reconciler %v, scope %v", c.kind, rec, read["scope"])
		}
		for _, pair := range [][2]map[string]any{{out, own}, {out["reconciliation"].(map[string]any), own["reconciliation"].(map[string]any)}, {read, ownRead}} {
			for member := range pair[0] {
				if _, held := pair[1][member]; !held && member != "reconciler" {
					t.Fatalf("%s: the read-back answers %q, which the actor's does not", c.kind, member)
				}
			}
		}
	}
	if b.sent(key) != 1 || dispatchMarkers(t, b.g.storeRoot) != markers || b.host.counted() != counted {
		t.Fatalf("sent %d, markers %d to %d, counted %d", b.sent(key), markers, dispatchMarkers(t, b.g.storeRoot), b.host.counted()-counted)
	}
}

// The core of decision 2: for each sender kind, each condition failing
// alone, the answer is the one the same sender gets for a scope identifier
// that exists nowhere, byte for byte, and neither reads the issuing host
// (no standing, no admission), sends anything or changes the journal. For
// the subject, its own reach is held to its entry, so (b) cannot fail with
// (c) holding: its row fails both.
func TestAReservationSenderNamingAScopeItMayNotIsAnsweredAsAScopeThatExistsNowhere(t *testing.T) {
	if !isScopeIdentifier(scopeNowhere) {
		t.Fatal("the scope that exists nowhere is not of a scope identifier's form")
	}
	key := delegationKey(3)
	b, _ := newScopedSenderHarness(t, key)
	reservation := b.reservationOf(testSub(), rootAgent)
	entries := b.g.identity.callers.entries
	subjectEntry := entries[testSubjectSub]
	for _, c := range senderKinds {
		for _, failing := range []string{"a", "b", "c"} {
			claim := testScope
			switch failing {
			case "a":
				delete(b.d.hosts["desk"].scopeIDs, testScope)
			case "b":
				entries[testSubjectSub] = callerEntry{grants: map[string]bool{scopeOtherID: true, unscopedMarker: true}}
				if c.kind == "subject" {
					claim = scopeOtherID
				}
			case "c":
				claim = scopeOtherID
			}
			token := scopedToken(t, b.delegationHarness, c.subject, claim)
			for _, extra := range []string{reservation, `,"reconcile":true` + reservation} {
				reads, journal, sent := b.host.readCount(), actionsTreeDigest(t, b.g.storeRoot), b.sent(key)
				nowhere := postSenderRaw(t, b.delegationHarness, b.body("s-"+c.kind, "tickets-a", jsonText(t, scopeNowhere), key, extra), token)
				got := postSenderRaw(t, b.delegationHarness, b.body("s-"+c.kind, "tickets-a", jsonText(t, testScope), key, extra), token)
				if !got.same(nowhere) {
					t.Fatalf("%s, (%s) failing: %d %v %s, a scope that exists nowhere %d %v %s", c.kind, failing, got.status, got.header, got.body, nowhere.status, nowhere.header, nowhere.body)
				}
				if got.status != http.StatusBadRequest || !strings.Contains(got.body, `"refusedAt":"scope-identifier"`) || !strings.Contains(got.body, scopeRefusal) {
					t.Fatalf("%s, (%s) failing: %d %s, want the scope step's sentence", c.kind, failing, got.status, got.body)
				}
				if b.host.readCount() != reads || actionsTreeDigest(t, b.g.storeRoot) != journal || b.sent(key) != sent {
					t.Fatalf("%s, (%s) failing: the issuing host was read, the journal changed or the key was sent", c.kind, failing)
				}
			}
			b.d.hosts["desk"].scopeIDs[testScope] = true
			entries[testSubjectSub] = subjectEntry
		}
	}
}

// The subject's standing is read once its scope is held: removed refuses as
// action-key-unauthenticated, unreadable as standing-unknown. After the
// delegation is revoked the actor reaches nothing, and the subject, the host
// and the operator are still served the evidence, in its scope; nothing is
// sent again.
func TestAReservationSenderOnAScopedKeyAfterRemovalAndRevocation(t *testing.T) {
	key := delegationKey(4)
	b, actor := newScopedSenderHarness(t, key)
	reservation := b.reservationOf(testSub(), rootAgent)
	asSender := func(subject, extra string) (int, map[string]any) {
		token := scopedToken(t, b.delegationHarness, subject, testScope)
		return b.post(t, "/act", b.body("s-"+strings.ReplaceAll(subject, ":", "-"), "tickets-a", jsonText(t, testScope), key, extra+reservation), map[string]string{"Authorization": "Bearer " + token})
	}
	b.host.setAnswer(func(map[string]any) (int, string) { return http.StatusOK, `{"standing":"removed"}` })
	if status, out := asSender(testSubjectSub, ""); status != http.StatusForbidden || refusalOf(out) != refusalKeyUnauthenticated {
		t.Fatalf("a removed subject: %d %v", status, out)
	}
	b.host.setAnswer(func(map[string]any) (int, string) { return http.StatusInternalServerError, `` })
	if status, out := asSender(testSubjectSub, ""); status != http.StatusForbidden || refusalOf(out) != refusalStandingUnknown {
		t.Fatalf("an unread standing: %d %v", status, out)
	}
	b.host.setAnswer(nil)
	chain := boundChain(t, testScope, strings.Repeat("41", 16))
	if status, _ := b.post(t, "/delegation/revoke", `{"delegation":"`+chain["id"].(string)+`"}`, map[string]string{"Authorization": "Bearer " + b.token(t, hostRequester)}); status != http.StatusOK {
		t.Fatal("revoke")
	}
	b.host.setAnswer(func(body map[string]any) (int, string) {
		if _, standing := body["standing"]; standing {
			return http.StatusOK, `{"standing":"current"}`
		}
		return http.StatusOK, `{"admission":"refuse","refusal":"revoked"}`
	})
	want := actor["receipt"].(map[string]any)["signature"]
	for _, c := range senderKinds {
		status, out := asSender(c.subject, `,"reconcile":true`)
		if status != http.StatusOK || out["receipt"].(map[string]any)["signature"] != want {
			t.Fatalf("%s after revocation: %d %v", c.kind, status, out)
		}
	}
	if b.sent(key) != 1 {
		t.Fatalf("sent %d", b.sent(key))
	}
}

// An admitted sender is held to the scope it named: naming none on the
// scoped platform, naming the scope on the other scope's platform or on the
// platform of none, is refused at the scope step, never answered about the
// key as if it were of no scope or of another.
func TestAReservationSenderIsHeldToTheScopeItNames(t *testing.T) {
	key := delegationKey(5)
	b, _ := newScopedSenderHarness(t, key)
	reservation := b.reservationOf(testSub(), rootAgent)
	for _, c := range senderKinds {
		token := scopedToken(t, b.delegationHarness, c.subject, testScope)
		for _, r := range []struct{ platform, scope string }{{"tickets-a", ""}, {"tickets-b", jsonText(t, testScope)}, {"tickets", jsonText(t, testScope)}} {
			status, out := b.post(t, "/act", b.body("s-"+c.kind, r.platform, r.scope, key, `,"reconcile":true`+reservation), map[string]string{"Authorization": "Bearer " + token})
			if status != http.StatusBadRequest || out["refusedAt"] != "scope-identifier" || out["error"] != scopeRefusal {
				t.Fatalf("%s on %s, scope %q: %d %v", c.kind, r.platform, r.scope, status, out)
			}
		}
	}
	if b.sent(key) != 1 {
		t.Fatalf("sent %d", b.sent(key))
	}
}

// Decision 6: a delegated reservation records its scope as main did, byte
// for byte: three members, no scope identifier, of no scope and of one
// alike, so a key recorded before this change is found by the same
// derivation (the sender tests above read the actor's scoped records).
func TestADelegatedReservationRecordsItsScopeAsBefore(t *testing.T) {
	const golden = `{"host":"desk","rootActor":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","sub":{"issuer":"https://login.example","kind":"person","subject":"approver-7"}}`
	h := newDelegationHarness(t, false)
	key := delegationKey(6)
	if status, out := h.present(t, "/act", h.actBody("s0", key, ""), h.credential(t, statement(t, nil))); status != http.StatusOK {
		t.Fatalf("the unscoped delegated action: %d %v", status, out)
	}
	who := &caller{delegated: &delegatedSender{scope: reservationScope{sub: principalRef{"person", testIssuerURL, testSubjectSub}, rootActor: rootAgent, host: "desk"}}}
	for _, name := range []string{h.g.actionNamespace(who, key), h.g.actionSubjectNamespace(who.delegated, key)} {
		raw, err := os.ReadFile(filepath.Join(h.g.storeRoot, "actions", name, "scope.json"))
		if err != nil || string(raw) != golden {
			t.Fatalf("%s: %q %v, want main's bytes", name, raw, err)
		}
	}
	first := h.g.actionFirstScope(who, key, h.g.actionNamespace(who, key))
	raw, err := os.ReadFile(filepath.Join(h.g.storeRoot, "actions", actionIndexDirectory, first.file))
	if err != nil || !strings.Contains(string(raw), `"scope":`+golden) || string(raw) != string(first.record) {
		t.Fatalf("the first-scope record: %q %v", raw, err)
	}
	// the scoped one, in its scope's journal
	key = delegationKey(7)
	b, _ := newScopedSenderHarness(t, key)
	journal := scopedActionJournalPath(b.g.storeRoot, testScope)
	for _, name := range []string{b.g.actionNamespaceIn(who, key, testScope), b.g.actionSubjectNamespace(who.delegated, key)} {
		raw, err := os.ReadFile(filepath.Join(journal, name, "scope.json"))
		if err != nil || string(raw) != golden {
			t.Fatalf("scoped %s: %q %v, want the three members alone", name, raw, err)
		}
	}
}

// /posture names the capability where an issuing host may bind a scope
// identifier and some write source is fixed to one, and nowhere else.
func TestDelegationScopedReservationPostureLine(t *testing.T) {
	scoped := map[string]sourceSpec{"tickets/write": {}, "tickets-a/write": {scope: testScope}}
	unscoped := map[string]sourceSpec{"tickets/write": {}, "tickets-a/live": {scope: testScope}}
	for _, c := range []struct {
		binds   bool
		sources map[string]sourceSpec
		want    bool
	}{{true, scoped, true}, {false, scoped, false}, {true, unscoped, false}} {
		lines := delegationLines(&delegationPosture{scopeBinding: c.binds}, c.sources, false)
		found := false
		for _, l := range lines {
			if l.name == protectionDelegationScopedReservation {
				found = l.state == postureEnforced
			}
		}
		if found != c.want || len(lines) != 3+map[bool]int{true: 1, false: 0}[c.want] {
			t.Fatalf("binds %v: %v", c.binds, lines)
		}
	}
}

// Under the request limits (gateway #618 review): a reservation sender whose
// token reaches several scopes is charged at step 8a, as the delegated
// sender it is, to the scope it names and was admitted to; never before its
// scope is held. A scope that exists nowhere, and one that exists but the
// sender does not reach, are answered with the scope step's sentence and
// move no scope's tally. A sender whose token reaches one scope alone is
// charged to that scope at step 3a, before its body is read, whatever it
// names, as any caller of one scope is.
func TestAReservationSenderUnderLimitsIsChargedToTheScopeItNames(t *testing.T) {
	const scopeThird = "équipe-c"
	key := delegationKey(9)
	b, _ := newScopedSenderHarness(t, key)
	write, live := b.g.sources["tickets-a/write"], b.g.sources["tickets-a/live"]
	write.scope, live.scope = scopeThird, scopeThird
	b.g.sources["tickets-c/write"], b.g.sources["tickets-c/live"] = write, live
	one := rateOf(60, 1)
	b.server = limitsOn(t, b.g, &limitsConfig{beforeScope: 64, scopes: map[string]limitEntry{
		testScope:      {scope: one.scope, perCaller: &limitValues{requestsPerMinute: 60, burst: 1}},
		scopeOtherID:   one,
		scopeThird:     one,
		unscopedMarker: one,
	}})
	l := b.g.limiter
	states := func() map[string]string {
		out := map[string]string{}
		for _, s := range []string{testScope, scopeOtherID, scopeThird, unscopedMarker} {
			out[s] = scopeState(l, s)
		}
		return out
	}
	moved := func(before map[string]string) []string {
		var out []string
		for s, was := range before {
			if scopeState(l, s) != was {
				out = append(out, s)
			}
		}
		sort.Strings(out)
		return out
	}
	reservation := b.reservationOf(testSub(), rootAgent)
	both := scopedToken(t, b.delegationHarness, testOperator, testScope, scopeOtherID)

	before := states()
	nowhere := postSenderRaw(t, b.delegationHarness, b.body("s-op", "tickets-a", jsonText(t, scopeNowhere), key, reservation), both)
	unreached := postSenderRaw(t, b.delegationHarness, b.body("s-op", "tickets-a", jsonText(t, scopeThird), key, reservation), both)
	for name, got := range map[string]senderAnswer{"a scope that exists nowhere": nowhere, "a scope the sender does not reach": unreached} {
		if got.status != http.StatusBadRequest || !strings.Contains(got.body, `"refusedAt":"scope-identifier"`) || !strings.Contains(got.body, scopeRefusal) {
			t.Fatalf("%s: %d %s, want the scope step's sentence", name, got.status, got.body)
		}
	}
	if !unreached.same(nowhere) {
		t.Fatalf("a scope not reached is answered unlike one that exists nowhere:\n%s\n%s", unreached.body, nowhere.body)
	}
	if m := moved(before); len(m) != 0 {
		t.Fatalf("a refused scope moved the tally of %v", m)
	}

	before = states()
	admitted := postSenderRaw(t, b.delegationHarness, b.body("s-op", "tickets-a", jsonText(t, testScope), key, reservation), both)
	if admitted.status != http.StatusOK {
		t.Fatalf("the operator naming the action's scope: %d %s", admitted.status, admitted.body)
	}
	if m := moved(before); len(m) != 1 || m[0] != testScope {
		t.Fatalf("the admitted request moved %v, want the scope it names alone", m)
	}
	callers := l.scopes[testScope].callers
	if _, ok := callers[limitCallerKeyOf("delegated", testIssuerURL, testOperator)]; !ok || len(callers) != 1 {
		t.Fatalf("the scope's callers: %v, want the operator as a delegated sender alone", callers)
	}
	again := postSenderRaw(t, b.delegationHarness, b.body("s-op", "tickets-a", jsonText(t, testScope), key, reservation), both)
	if again.status != http.StatusTooManyRequests || !strings.Contains(again.body, `"refusedAt":"limit"`) {
		t.Fatalf("the next request at the limit: %d %s", again.status, again.body)
	}

	before = states()
	onlyOther := scopedToken(t, b.delegationHarness, testOperator, scopeOtherID)
	got := postSenderRaw(t, b.delegationHarness, b.body("s-op", "tickets-a", jsonText(t, testScope), key, reservation), onlyOther)
	if got.status != http.StatusBadRequest || !strings.Contains(got.body, scopeRefusal) {
		t.Fatalf("a sender of one other scope naming the action's: %d %s", got.status, got.body)
	}
	if m := moved(before); len(m) != 1 || m[0] != scopeOtherID {
		t.Fatalf("a sender of one scope moved %v, want its own scope alone (step 3a)", m)
	}
	assertLimitNothingHeld(t, l)
}
