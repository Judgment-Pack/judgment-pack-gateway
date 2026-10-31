package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// reconciledBy is the read-back of an answer that reconciled an uncertain
// action, with its reconciler.
func reconciledBy(t *testing.T, out map[string]any) (receipt, reconciler map[string]any) {
	t.Helper()
	rec, ok := out["reconciliation"].(map[string]any)
	if !ok {
		t.Fatalf("no reconciliation: %v", out)
	}
	receipt = rec["receipt"].(map[string]any)
	if _, carries := receipt["delegation"]; carries {
		t.Fatal("a read-back carries the delegation member")
	}
	reconciler, _ = receipt["reconciler"].(map[string]any)
	return receipt, reconciler
}

// An uncertain delegated write, then a takeover: a new lease's worker under
// a re-issued delegation of the same subject and root actor finds the same
// reservation and reads back, sending nothing; another root actor of the
// same subject finds the key taken (#352 M6, the delegated half).
func TestDelegatedKeyTakeoverSendsOnce(t *testing.T) {
	h := newDelegationHarness(t, false)
	actionKeysMode(t, h.root, "write", "drop")
	key := delegationKey(3)
	first := h.credential(t, statement(t, nil))
	status, out := h.present(t, "/act", h.actBody("s1", key, ""), first)
	if status != http.StatusOK || h.sent(key) != 1 {
		t.Fatalf("first: %d %v, sent %d", status, out, h.sent(key))
	}
	read, rec := reconciledBy(t, out)
	if rec["kind"] != "actor" || rec["issuer"] != "desk" || rec["subject"] != rootAgent {
		t.Fatalf("reconciler: %v", rec)
	}
	if c := read["caller"].(map[string]any); c["subject"] != testSubjectSub || c["tokenDigest"] != tokenDigestOf(first) {
		t.Fatalf("read-back caller: %v", c)
	}
	if action := out["action"].(map[string]any)["receipt"].(map[string]any); action["delegation"] == nil {
		t.Fatal("the uncertain action carries no delegation member")
	}
	counted := h.host.counted()

	// The takeover: a re-issued root, a new credential, a new transport token.
	reissued := statement(t, map[string]any{"id": strings.Repeat("55", 16), "issuedAt": "2026-10-30T00:30:00.000Z"})
	second := h.credential(t, reissued)
	status, out = h.present(t, "/act", h.actBody("s2", key, ""), second)
	if status != http.StatusOK || h.sent(key) != 1 {
		t.Fatalf("takeover: %d %v, sent %d", status, out, h.sent(key))
	}
	if _, rec := reconciledBy(t, out); rec["kind"] != "actor" {
		t.Fatalf("takeover reconciler: %v", rec)
	}
	if h.host.counted() != counted {
		t.Fatal("a request answered by key was counted")
	}

	// Another root actor of the same subject: the key is taken.
	other := h.credential(t, statement(t, map[string]any{"id": strings.Repeat("66", 16), "act": map[string]any{"agent": otherAgent, "software": testSoftware}}))
	status, out = h.present(t, "/act", h.actBody("s3", key, ""), other)
	if status != http.StatusForbidden || refusalOf(out) != "action-key-scope-conflict" || h.sent(key) != 1 {
		t.Fatalf("another root actor: %d %v, sent %d", status, out, h.sent(key))
	}
	// Another subject's key of the same value is its own.
	elsewhere := h.credential(t, statement(t, map[string]any{"id": strings.Repeat("77", 16), "sub": map[string]any{"kind": "person", "issuer": testIssuerURL, "subject": "someone-else"}}))
	actionKeysMode(t, h.root, "write", "respond")
	if status, out := h.present(t, "/act", h.actBody("s4", key, ""), elsewhere); status != http.StatusOK || h.sent(key) != 2 {
		t.Fatalf("another subject's key: %d %v, sent %d", status, out, h.sent(key))
	}
}

// The sender table (SPEC.md §11.8, RFC 0030 §4 rule 4): who reaches a
// delegated reservation by its key, before and after revocation, and what
// each gets -- never a dispatch but the actor's.
func TestDelegatedKeySenderTable(t *testing.T) {
	h := newDelegationHarness(t, false)
	actionKeysMode(t, h.root, "write", "drop")
	key := delegationKey(4)
	root := statement(t, nil)
	actor := h.credential(t, root)
	if status, out := h.present(t, "/act", h.actBody("s0", key, ""), actor); status != http.StatusOK {
		t.Fatalf("dispatch: %d %v", status, out)
	}
	reservation := h.reservationOf(testSub(), rootAgent)
	asToken := func(subject, session, extra string) (int, map[string]any) {
		return h.post(t, "/act", h.actBody(session, key, extra), map[string]string{"Authorization": "Bearer " + h.token(t, subject)})
	}
	for _, c := range []struct {
		subject, kind string
	}{
		{testSubjectSub, "subject"}, {hostRequester, "host"}, {testOperator, "operator"},
	} {
		token := h.token(t, c.subject)
		status, out := h.post(t, "/act", h.actBody("s-"+c.kind, key, reservation), map[string]string{"Authorization": "Bearer " + token})
		if status != http.StatusOK {
			t.Fatalf("%s: %d %v", c.kind, status, out)
		}
		read, rec := reconciledBy(t, out)
		if rec["kind"] != c.kind || rec["subject"] != c.subject || rec["issuer"] != testIssuerURL {
			t.Fatalf("%s reconciler: %v", c.kind, rec)
		}
		if caller := read["caller"].(map[string]any); caller["subject"] != testSubjectSub || caller["tokenDigest"] != tokenDigestOf(token) {
			t.Fatalf("%s caller: %v", c.kind, caller)
		}
	}
	if h.sent(key) != 1 {
		t.Fatalf("a sender other than the actor sent: %d", h.sent(key))
	}
	// Anyone else, or a scope the sender is not, is refused, saying nothing.
	for name, c := range map[string]struct{ subject, extra string }{
		"another subject": {"someone-else", reservation},
	} {
		status, out := asToken(c.subject, "s-x", c.extra)
		if status != http.StatusForbidden || refusalOf(out) != refusalKeyUnauthenticated || out["error"] != refusalKeyUnauthenticated {
			t.Fatalf("%s: %d %v", name, status, out)
		}
	}
	// The subject naming another root actor's scope of its own finds nothing
	// there: it is authenticated, and that scope reserved nothing.
	if status, out := asToken(testSubjectSub, "s-x", h.reservationOf(testSub(), otherAgent)); status != http.StatusForbidden || refusalOf(out) != refusalActorOnly {
		t.Fatalf("another root actor's scope: %d %v", status, out)
	}
	// A credential bound to another scope cannot name this one, and an actor
	// whose leaf does not admit the write reaches nothing by its key (#284 NC1).
	elsewhere := h.credential(t, statement(t, map[string]any{"id": strings.Repeat("77", 16), "sub": map[string]any{"kind": "service", "issuer": testIssuerURL, "subject": testSubjectSub}}))
	if status, out := h.present(t, "/act", h.actBody("s-y", key, reservation), elsewhere); status != http.StatusForbidden || refusalOf(out) != refusalKeyUnauthenticated {
		t.Fatalf("a credential of another scope: %d %v", status, out)
	}
	narrow := h.credential(t, root, childOf(t, root, map[string]any{"act": map[string]any{"agent": rootAgent, "software": testSoftware}}))
	if status, out := h.present(t, "/act", h.actBody("s-z", key, ""), narrow); status != http.StatusForbidden || refusalOf(out) != refusalKeyUnauthenticated {
		t.Fatalf("a leaf not admitting the write: %d %v", status, out)
	}
	// The subject's standing is read: removed, or unreadable, refuses.
	h.host.setAnswer(func(b map[string]any) (int, string) { return http.StatusOK, `{"standing":"removed"}` })
	if status, out := asToken(testSubjectSub, "s-r", reservation); status != http.StatusForbidden || refusalOf(out) != refusalKeyUnauthenticated {
		t.Fatalf("a removed subject: %d %v", status, out)
	}
	h.host.setAnswer(func(b map[string]any) (int, string) { return http.StatusInternalServerError, `` })
	if status, out := asToken(testSubjectSub, "s-r", reservation); status != http.StatusForbidden || refusalOf(out) != refusalStandingUnknown {
		t.Fatalf("an unread standing: %d %v", status, out)
	}
	// The host and the operator read no standing.
	if status, _ := asToken(hostRequester, "s-h2", reservation); status != http.StatusOK {
		t.Fatalf("the host after the read failed: %d", status)
	}
	h.host.setAnswer(nil)
	// After revocation the actor's credential is gone; the subject, the host
	// and the operator still reach the read-back.
	if status, _ := h.post(t, "/delegation/revoke", `{"delegation":"`+root["id"].(string)+`"}`, map[string]string{"Authorization": "Bearer " + h.token(t, hostRequester)}); status != http.StatusOK {
		t.Fatal("revoke")
	}
	if status, _ := h.present(t, "/act", h.actBody("s-a", key, ""), actor); status != http.StatusUnauthorized {
		t.Fatalf("the actor after revocation: %d", status)
	}
	h.host.setAnswer(func(b map[string]any) (int, string) {
		if _, standing := b["standing"]; standing {
			return http.StatusOK, `{"standing":"current"}`
		}
		return http.StatusOK, `{"admission":"refuse","refusal":"revoked"}`
	})
	if status, out := asToken(testSubjectSub, "s-after", reservation); status != http.StatusOK {
		t.Fatalf("the subject after revocation: %d %v", status, out)
	}
	if h.sent(key) != 1 {
		t.Fatalf("sent %d", h.sent(key))
	}
	// A key with no reservation in the scope, or no key, reaches nothing,
	// and leaves no reservation behind.
	other := delegationKey(5)
	status, out := h.post(t, "/act", h.actBody("s-n", other, reservation), map[string]string{"Authorization": "Bearer " + h.token(t, hostRequester)})
	if status != http.StatusForbidden || refusalOf(out) != refusalActorOnly {
		t.Fatalf("an unreserved key: %d %v", status, out)
	}
	who := &caller{delegated: &delegatedSender{scope: reservationScope{sub: principalRef{"person", testIssuerURL, testSubjectSub}, rootActor: rootAgent, host: "desk"}}}
	if _, err := os.Stat(filepath.Join(h.g.storeRoot, "actions", h.g.actionNamespace(who, other))); !os.IsNotExist(err) {
		t.Fatalf("a non-actor made a reservation: %v", err)
	}
	h.g.requireActionKey = false // an engine before version 14 takes a request with no key
	if status, out := h.post(t, "/act", strings.Replace(h.actBody("s-n", other, reservation), `,"actionKey":"`+other+`"`, "", 1), map[string]string{"Authorization": "Bearer " + h.token(t, hostRequester)}); status != http.StatusForbidden || refusalOf(out) != refusalActorOnly {
		t.Fatalf("no key: %d %v", status, out)
	}
	h.g.requireActionKey = true
	// A key the actor reserved and never dispatched under -- its admission
	// refused -- gives another sender nothing.
	unsent := delegationKey(7)
	h.host.setAnswer(nil)
	fresh := h.credential(t, statement(t, map[string]any{"id": strings.Repeat("88", 16)}))
	h.host.setAnswer(func(b map[string]any) (int, string) {
		if _, standing := b["standing"]; standing {
			return http.StatusOK, `{"standing":"current"}`
		}
		if c, ok := b["call"].(map[string]any); ok && c["source"] == "tickets/write" {
			return http.StatusOK, `{"admission":"refuse","refusal":"subject-unauthorized"}`
		}
		return http.StatusOK, `{"admission":"admit"}`
	})
	if status, out := h.present(t, "/act", h.actBody("s-u", unsent, ""), fresh); status != http.StatusForbidden || refusalOf(out) != "subject-unauthorized" {
		t.Fatalf("the actor's refused dispatch: %d %v", status, out)
	}
	if _, err := os.Stat(filepath.Join(h.g.storeRoot, "actions", h.g.actionNamespace(who, unsent))); err != nil {
		t.Fatalf("the actor's reservation: %v", err)
	}
	if status, out := h.post(t, "/act", h.actBody("s-u2", unsent, reservation), map[string]string{"Authorization": "Bearer " + h.token(t, hostRequester)}); status != http.StatusForbidden || refusalOf(out) != refusalActorOnly || h.sent(unsent) != 0 {
		t.Fatalf("a reservation with nothing dispatched: %d %v, sent %d", status, out, h.sent(unsent))
	}
	h.host.setAnswer(nil)
	if status, _ := asToken(hostRequester, "s-m", `,"reservation":{"sub":{"kind":"person"},"rootActor":"x","host":"desk"}`); status != http.StatusBadRequest {
		t.Fatalf("a malformed reservation: %d", status)
	}
	// Every receipt verifies, the action observed committed.
	for _, s := range []string{"read", "s0", "s-subject", "s-host", "s-operator", "s-h2", "s-after"} {
		if _, err := h.g.sealSession(s); err != nil {
			t.Fatalf("seal %s: %v", s, err)
		}
	}
	verdict, err := h.g.verify()
	if err != nil || verdict["ok"] != true {
		t.Fatalf("verify: %v %v", verdict, err)
	}
	observed := false
	for _, o := range verdict["observations"].([]any) {
		if o.(map[string]any)["observation"] == observeActionCommitted {
			observed = true
		}
	}
	if !observed {
		t.Fatalf("no committed observation: %v", verdict["observations"])
	}
}

// The dispatch marker records the admission: a marker found without its
// answer mints the uncertain receipt under the delegation it was admitted
// under, not one made now, and a marker recording none refuses.
func TestDelegatedDispatchMarkerRecordsTheAdmission(t *testing.T) {
	h := newDelegationHarness(t, false)
	actionKeysMode(t, h.root, "write", "drop")
	key := delegationKey(6)
	cred := h.credential(t, statement(t, nil))
	if status, out := h.present(t, "/act", h.actBody("s1", key, ""), cred); status != http.StatusOK {
		t.Fatalf("dispatch: %d %v", status, out)
	}
	who := &caller{delegated: &delegatedSender{scope: reservationScope{sub: principalRef{"person", testIssuerURL, testSubjectSub}, rootActor: rootAgent, host: "desk"}}}
	dir := filepath.Join(h.g.storeRoot, "actions", h.g.actionNamespace(who, key))
	marker, err := os.ReadFile(filepath.Join(dir, "dispatch-1.json"))
	if err != nil || !strings.Contains(string(marker), `"admittedAt":"2026-10-30T01:00:00.000Z"`) {
		t.Fatalf("marker: %s %v", marker, err)
	}
	if scope, err := os.ReadFile(filepath.Join(dir, "scope.json")); err != nil || !strings.Contains(string(scope), `"rootActor":"`+rootAgent+`"`) {
		t.Fatalf("scope: %s %v", scope, err)
	}
	// The crash window: the marker durable, the evidence not.
	if err := os.Remove(filepath.Join(dir, "action.json")); err != nil {
		t.Fatal(err)
	}
	h.setNow(time.Date(2026, 10, 30, 1, 1, 0, 0, time.UTC))
	status, out := h.present(t, "/act", h.actBody("s2", key, ""), cred)
	if status != http.StatusOK || h.sent(key) != 1 {
		t.Fatalf("after the crash: %d %v, sent %d", status, out, h.sent(key))
	}
	action := out["action"].(map[string]any)["receipt"].(map[string]any)
	if action["delegation"].(map[string]any)["admittedAt"] != "2026-10-30T01:00:00.000Z" {
		t.Fatalf("the uncertain receipt's admission: %v", action["delegation"])
	}
	// A scope.json that is not the request's refuses.
	if err := os.Chmod(filepath.Join(dir, "scope.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scope.json"), []byte(`{"host":"desk","rootActor":"`+otherAgent+`","sub":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if status, out := h.present(t, "/act", h.actBody("s2b", key, ""), cred); status != http.StatusBadRequest || !strings.Contains(out["error"].(string), "action-journal-invalid") {
		t.Fatalf("another recorded scope: %d %v", status, out)
	}
	scope, _ := json.Marshal(map[string]any{"host": "desk", "rootActor": rootAgent, "sub": map[string]any{"issuer": testIssuerURL, "kind": "person", "subject": testSubjectSub}})
	if err := os.WriteFile(filepath.Join(dir, "scope.json"), scope, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "action.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "dispatch-1.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dispatch-1.json"), []byte(`{"attempt":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if status, out := h.present(t, "/act", h.actBody("s3", key, ""), cred); status != http.StatusBadRequest || !strings.Contains(out["error"].(string), "action-journal-invalid") {
		t.Fatalf("a marker recording no admission: %d %v", status, out)
	}
	if h.sent(key) != 1 {
		t.Fatalf("sent %d", h.sent(key))
	}
}
