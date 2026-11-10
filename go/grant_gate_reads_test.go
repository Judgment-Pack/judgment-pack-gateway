package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A delegated acquisition and the read-back of a delegated key, each held to
// the platform's connection grant (gateway #372, SPEC.md §10 rule 3), with
// the custody stood in: where in each ladder the grant is asked, and what a
// refusal leaves.

// countReads makes the platform's live program record each run, and
// answers how many it has made.
func (h *delegationHarness) countReads(t *testing.T) func() int {
	t.Helper()
	path := filepath.Join(h.root, "live-reads")
	spec := h.g.sources["tickets/live"]
	spec.env = append(append([]string{}, spec.env...), "ACTION_KEYS_READS="+path)
	h.g.sources["tickets/live"] = spec
	return func() int {
		data, _ := os.ReadFile(path)
		return strings.Count(string(data), "read\n")
	}
}

// A delegated acquisition on a platform that names no grant is refused
// before anything: no custody asked, no admission read, nothing run. A grant
// whose state the custody refuses is refused before the issuing host is read,
// so nothing is counted. The owner read is made after the counting admission
// answers admit (RFC 0030 §2): a call step 12 refuses reports step 12's
// refusal and never reaches the owner read; one the owner read refuses runs
// nothing and leaves its count used. An undelegated acquisition is the
// operator's own and asks no custody.
func TestDelegatedAcquisitionIsHeldToTheGrantFirst(t *testing.T) {
	h := newDelegationHarness(t, false)
	reads := h.countReads(t)
	cred := h.credential(t, statement(t, nil))
	hostReads := h.host.readCount()
	refused := func(name, session, want string, counted, calls int, last string) {
		t.Helper()
		status, raw := h.presentRaw(t, "/acquire", h.acquireBody(session, "query"), cred)
		if status != http.StatusForbidden || raw != want {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		made := grantCalls(t, h.root)
		if reads() != 0 || h.host.readCount() != hostReads+counted || h.host.counted() != counted || len(made) != calls {
			t.Fatalf("%s: reads %d, host reads %d->%d, counted %d, custody %d", name, reads(), hostReads, h.host.readCount(), h.host.counted(), len(made))
		}
		if last != "" && strings.Join(made[len(made)-1].Args, " ") != "-- --grants="+last {
			t.Fatalf("%s: the custody's last call: %+v", name, made[len(made)-1])
		}
	}

	h.setGrant(nil)
	refused("no grant named", "a-none", `{"error":"grant-unknown: platform tickets names no connection grant, and a delegated acquisition is admitted only under one","refusal":"grant-unknown"}`, 0, 0, "")

	h.setGrant(grantStandIn(t, h.root))
	grantAnswer(t, h.root, grantCheck, &grantStandInAnswer{Exit: 1, Stderr: "grants: grant-quarantined\n"})
	refused("a quarantined grant", "a-quarantined", `{"error":"grant-quarantined: the platform's connection grant is quarantined","refusal":"grant-quarantined"}`, 0, 1, grantCheck)

	// Step 12 and the owner read would both refuse: step 12's is reported,
	// and the owner read is not made.
	grantAnswer(t, h.root, grantCheck, nil)
	grantAnswer(t, h.root, grantAdmit, &grantStandInAnswer{Exit: 1, Stderr: "grants: owner-removed\n"})
	h.host.setAnswer(func(b map[string]any) (int, string) {
		return http.StatusOK, `{"admission":"refuse","refusal":"subject-unauthorized"}`
	})
	refused("step 12 before the owner", "a-both", `{"error":"subject-unauthorized: the issuing host answers subject-unauthorized","refusal":"subject-unauthorized"}`, 1, 2, grantCheck)
	// The owner read alone refuses: after the count, nothing run.
	h.host.setAnswer(nil)
	refused("the owner removed", "a-owner", `{"error":"owner-removed: the owner of the platform's connection grant was removed","refusal":"owner-removed"}`, 2, 4, grantAdmit)

	grantAnswer(t, h.root, grantAdmit, nil)
	if status, raw := h.presentRaw(t, "/acquire", h.acquireBody("a-admitted", "query"), cred); status != http.StatusOK || reads() != 1 || h.host.counted() != 3 || len(grantCalls(t, h.root)) != 6 {
		t.Fatalf("the grant admitting: %d %s, reads %d, counted %d", status, raw, reads(), h.host.counted())
	}

	// The operator's own acquisition: the custody is never asked, whatever
	// it would answer.
	grantAnswer(t, h.root, grantCheck, &grantStandInAnswer{Exit: 1, Stderr: "grants: grant-revoked\n"})
	arguments, _ := parseJSON([]byte(`{"tool":"query","arguments":{"key":"k"}}`))
	if out, err := h.g.acquire("a-operator", "tickets/live", arguments, actionKeysWho); err != nil || out["receipt"] == nil || reads() != 2 || len(grantCalls(t, h.root)) != 6 {
		t.Fatalf("an undelegated acquisition: %v %v, reads %d, custody %d", out, err, reads(), len(grantCalls(t, h.root)))
	}
}

// The read-back of a delegated key's uncertain action is a use of the
// platform's grant (RFC 0030 §5, rule 5): a grant the custody does not admit
// -- not live, its owner refused, unreadable, or none named -- serves no
// read-back, for any sender, and the key stays uncertain: it is answered
// with its uncertain record, nothing is sent again, and nothing is counted.
// Before the grant, the run's actor is held to the read-back's own source
// and tool (SPEC.md §11.8, spec #291 L1): a link that excludes either is
// refused as action-key-unauthenticated, a revoked grant included, and the
// custody is not asked. A request answered from retained evidence is not
// held to the read-back's source and tool.
func TestDelegatedReadBackIsHeldToTheGrant(t *testing.T) {
	h := newDelegationHarness(t, false)
	reads := h.countReads(t)
	actionKeysMode(t, h.root, "write", "drop")
	cred := h.credential(t, statement(t, nil))
	key := delegationKey(5)
	status, out := h.present(t, "/act", h.actBody("r-0", key, ""), cred)
	if status != http.StatusOK || h.sent(key) != 1 || reads() != 1 {
		t.Fatalf("the uncertain write: %d %v, sent %d, reads %d", status, out, h.sent(key), reads())
	}
	reconciledBy(t, out)
	// The write's check and admission, and the read-back's admission.
	if calls := grantCalls(t, h.root); len(calls) != 3 || strings.Join(calls[2].Args, " ") != "-- --grants=admit" {
		t.Fatalf("the custody's calls: %+v", calls)
	}
	counted := h.host.counted()

	const prefix = "action-reconciliation-unavailable: the platform's connection grant refused the read-back, and it did not run: "
	stays := func(name string, send func() (int, string), want string, asked bool) {
		t.Helper()
		before := len(grantCalls(t, h.root))
		status, raw := send()
		var body map[string]any
		if err := json.Unmarshal([]byte(raw), &body); err != nil || status != http.StatusConflict || body["error"] != want || body["action"] == nil || len(body) != 2 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		calls := grantCalls(t, h.root)
		if asked && (len(calls) != before+1 || strings.Join(calls[len(calls)-1].Args, " ") != "-- --grants=admit") || !asked && len(calls) != before {
			t.Fatalf("%s: the custody's calls %d->%d", name, before, len(calls))
		}
		if h.sent(key) != 1 || reads() != 1 || h.host.counted() != counted {
			t.Fatalf("%s: sent %d, reads %d, counted %d->%d", name, h.sent(key), reads(), counted, h.host.counted())
		}
	}
	asActor := func(session string, credential string) func() (int, string) {
		return func() (int, string) { return h.presentRaw(t, "/act", h.actBody(session, key, ""), credential) }
	}

	// The probe of #372: a quarantined grant and an uncertain key.
	grantAnswer(t, h.root, grantAdmit, &grantStandInAnswer{Exit: 1, Stderr: "grants: grant-quarantined\n"})
	stays("a quarantined grant", asActor("r-quarantined", cred), prefix+"grant-quarantined: the platform's connection grant is quarantined", true)
	// Any sender the key authenticates: the subject, by its own token.
	subject := func() (int, string) {
		status, out := h.post(t, "/act", h.actBody("r-subject", key, h.reservationOf(testSub(), rootAgent)), map[string]string{"Authorization": "Bearer " + h.token(t, testSubjectSub)})
		raw, _ := json.Marshal(out)
		return status, string(raw)
	}
	stays("the subject, under a quarantined grant", subject, prefix+"grant-quarantined: the platform's connection grant is quarantined", true)
	grantAnswer(t, h.root, grantAdmit, &grantStandInAnswer{Exit: 1, Stderr: "grants: owner-unknown\n"})
	stays("the owner unknown", asActor("r-owner", cred), prefix+"owner-unknown: the standing of the owner of the platform's connection grant could not be read", true)
	grantAnswer(t, h.root, grantAdmit, &grantStandInAnswer{Exit: 3})
	stays("an unreadable custody", asActor("r-unreadable", cred), prefix+"grant-unreadable: the connection custody's answer for the platform's grant could not be read", true)
	h.setGrant(nil)
	stays("no grant named", asActor("r-none", cred), prefix+"grant-unknown: platform tickets names no connection grant, and the read-back of a delegated action is admitted only under one", false)
	h.setGrant(grantStandIn(t, h.root))

	// The read-back's own scope comes first: a revoked grant is not asked.
	grantAnswer(t, h.root, grantAdmit, &grantStandInAnswer{Exit: 1, Stderr: "grants: grant-revoked\n"})
	narrowed := func(id string, sources ...any) string {
		return h.credential(t, statement(t, map[string]any{"id": strings.Repeat(id, 16), "scope": map[string]any{"sources": sources}}))
	}
	write := scopeOf("tickets/write", []any{"query"}, []any{"act"}, map[string]any{})
	for name, credential := range map[string]string{
		"a link without the live source": narrowed("88", write),
		"a link without the read tool":   narrowed("99", scopeOf("tickets/live", []any{"another"}, []any{"read-external"}, map[string]any{}), write),
	} {
		before := len(grantCalls(t, h.root))
		status, raw := h.presentRaw(t, "/act", h.actBody("r-narrow", key, ""), credential)
		if status != http.StatusForbidden || raw != `{"error":"action-key-unauthenticated","refusal":"action-key-unauthenticated","refusedAt":"action-key"}` {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		if len(grantCalls(t, h.root)) != before || h.sent(key) != 1 || reads() != 1 || h.host.counted() != counted {
			t.Fatalf("%s: custody %d->%d, sent %d, reads %d", name, before, len(grantCalls(t, h.root)), h.sent(key), reads())
		}
	}
	stays("a revoked grant", asActor("r-revoked", cred), prefix+"grant-revoked: the platform's connection grant is revoked", true)

	// The grant admitting again: the read-back runs, and nothing is sent
	// again or counted.
	grantAnswer(t, h.root, grantAdmit, nil)
	status, out = h.present(t, "/act", h.actBody("r-admitted", key, ""), cred)
	if status != http.StatusOK || h.sent(key) != 1 || reads() != 2 || h.host.counted() != counted {
		t.Fatalf("the grant admitting: %d %v, sent %d, reads %d", status, out, h.sent(key), reads())
	}
	reconciledBy(t, out)

	// Retained evidence answers a link without the live source: a replay
	// runs no read-back.
	actionKeysMode(t, h.root, "write", "respond")
	done := delegationKey(6)
	status, first := h.present(t, "/act", h.actBody("r-done", done, ""), cred)
	if status != http.StatusOK || h.sent(done) != 1 {
		t.Fatalf("a completed write: %d %v", status, first)
	}
	status, again := h.present(t, "/act", h.actBody("r-replay", done, ""), narrowed("aa", write))
	if status != http.StatusOK || h.sent(done) != 1 || reads() != 2 || again["receipt"].(map[string]any)["signature"] != first["receipt"].(map[string]any)["signature"] {
		t.Fatalf("a replay through a link without the live source: %d %v", status, again)
	}
}

// An actor whose scope holds the write and not the read-back's source
// dispatches, and the outcome is uncertain. The write may have been sent,
// so that request is not refused: no read-back runs, the custody is not
// asked for one, and the key answers its uncertain record. A later request
// on the key, which the key lookup finds uncertain, is refused (SPEC.md
// §11.8, spec #291 L1).
func TestUncertainFirstDispatchOutsideTheReadBacksScope(t *testing.T) {
	h := newDelegationHarness(t, false)
	reads := h.countReads(t)
	actionKeysMode(t, h.root, "write", "drop")
	write := scopeOf("tickets/write", []any{"query"}, []any{"act"}, map[string]any{})
	cred := h.credential(t, statement(t, map[string]any{"id": strings.Repeat("88", 16), "scope": map[string]any{"sources": []any{write}}}))
	key := delegationKey(7)
	status, raw := h.presentRaw(t, "/act", h.actBody("r-0", key, ""), cred)
	var body map[string]any
	if err := json.Unmarshal([]byte(raw), &body); err != nil || status != http.StatusConflict || body["error"] != "action-reconciliation-unavailable: the run's actor's scope does not hold the read-back's source and tool, and it did not run" || body["action"] == nil || len(body) != 2 {
		t.Fatalf("the uncertain first dispatch: %d %s", status, raw)
	}
	// The write's check and admission, and no read-back's.
	if calls := grantCalls(t, h.root); len(calls) != 2 || h.sent(key) != 1 || reads() != 0 {
		t.Fatalf("custody calls %d, sent %d, reads %d", len(calls), h.sent(key), reads())
	}
	status, raw = h.presentRaw(t, "/act", h.actBody("r-1", key, ""), cred)
	if status != http.StatusForbidden || raw != `{"error":"action-key-unauthenticated","refusal":"action-key-unauthenticated","refusedAt":"action-key"}` || h.sent(key) != 1 || reads() != 0 || len(grantCalls(t, h.root)) != 2 {
		t.Fatalf("the key, found uncertain: %d %s", status, raw)
	}
}
