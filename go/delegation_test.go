package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A delegated acquisition and a delegated action: each admitted immediately
// before dispatch with counting, each receipt carrying the delegation member
// under its signature, caller and requester naming the subject, and the store
// verifying.
func TestDelegatedCallsAreAdmittedAndReceipted(t *testing.T) {
	h := newDelegationHarness(t, false)
	root := statement(t, nil)
	child := childOf(t, root, map[string]any{"scope": map[string]any{"sources": []any{
		scopeOf("tickets/live", []any{"query"}, []any{"read-external"}, map[string]any{"calls": 5}),
		scopeOf("tickets/write", []any{"query"}, []any{"act"}, map[string]any{}),
	}}})
	cred := h.credential(t, root, child)
	if h.host.readCount() != 1 || h.host.counted() != 0 {
		t.Fatalf("binding reads the host once, counting nothing: %d %d", h.host.readCount(), h.host.counted())
	}

	status, out := h.present(t, "/acquire", h.acquireBody("s-acq", "query"), cred)
	if status != http.StatusOK {
		t.Fatalf("acquire: %d %v", status, out)
	}
	receipt := out["receipt"].(map[string]any)
	member := receipt["delegation"].(map[string]any)
	if member["id"] != child["id"] || member["host"] != "desk" || member["actor"] != childAgent || member["admittedAt"] != "2026-10-30T01:00:00.000Z" {
		t.Fatalf("delegation member: %v", member)
	}
	chain := member["chain"].([]any)
	if len(chain) != 2 || chain[0] != statementDigest(t, root) || chain[1] != statementDigest(t, child) {
		t.Fatalf("chain digests: %v", chain)
	}
	subject := member["subject"].(map[string]any)
	callerOf := receipt["caller"].(map[string]any)
	if subject["subject"] != testSubjectSub || callerOf["subject"] != testSubjectSub || callerOf["issuer"] != testIssuerURL || callerOf["tokenDigest"] != tokenDigestOf(cred) {
		t.Fatalf("caller %v, subject %v", callerOf, subject)
	}
	if h.host.counted() != 1 {
		t.Fatalf("the acquisition is counted once: %d", h.host.counted())
	}
	read := h.host.reads[len(h.host.reads)-1]
	if c := read["call"].(map[string]any); c["source"] != "tickets/live" || c["tool"] != "query" || c["effect"] != "read-external" {
		t.Fatalf("the read names the call: %v", read)
	}

	key := delegationKey(1)
	status, out = h.present(t, "/act", h.actBody("s-act", key, ""), cred)
	if status != http.StatusOK {
		t.Fatalf("act: %d %v", status, out)
	}
	action := out["receipt"].(map[string]any)
	if action["delegation"].(map[string]any)["id"] != child["id"] {
		t.Fatalf("action delegation: %v", action["delegation"])
	}
	if requester := action["action"].(map[string]any)["requester"].(map[string]any); requester["subject"] != testSubjectSub || requester["tokenDigest"] != tokenDigestOf(cred) {
		t.Fatalf("requester: %v", requester)
	}
	if h.sent(key) != 1 || h.host.counted() != 2 {
		t.Fatalf("one write, counted once: %d %d", h.sent(key), h.host.counted())
	}
	// The same request again is answered from retained evidence: no read, no
	// count, no write.
	before := h.host.readCount()
	status, again := h.present(t, "/act", h.actBody("s-act2", key, ""), cred)
	if status != http.StatusOK || again["receipt"].(map[string]any)["signature"] != action["signature"] {
		t.Fatalf("replay: %d %v", status, again)
	}
	if h.host.readCount() != before || h.sent(key) != 1 {
		t.Fatalf("a replay makes no admission read and sends nothing: %d->%d, %d", before, h.host.readCount(), h.sent(key))
	}
	for _, session := range []string{"read", "s-acq", "s-act"} {
		if _, err := h.g.sealSession(session); err != nil {
			t.Fatal(err)
		}
	}
	verdict, err := h.g.verify()
	if err != nil || verdict["ok"] != true {
		t.Fatalf("verify: %v %v", verdict, err)
	}
}

// Calls outside the scope are refused before anything runs: the source, the
// tool and the effect, each by its reason, the host asked without counting.
func TestDelegatedCallsOutsideScopeAreRefusedBeforeDispatch(t *testing.T) {
	h := newDelegationHarness(t, false)
	root := statement(t, nil)
	child := childOf(t, root, nil) // tickets/live alone
	cred := h.credential(t, root, child)
	started := h.g.started.Load()

	status, out := h.present(t, "/act", h.actBody("s1", delegationKey(2), ""), cred)
	if status != http.StatusForbidden || refusalOf(out) != refusalOutOfScope || out["reason"] != "source" || out["refusedAt"] != "delegation" {
		t.Fatalf("write outside the scope: %d %v", status, out)
	}
	status, out = h.present(t, "/acquire", h.acquireBody("s2", "sibling"), cred)
	if status != http.StatusForbidden || out["reason"] != "tool" {
		t.Fatalf("tool outside the scope: %d %v", status, out)
	}
	live := h.g.sources["tickets/live"]
	live.effects = map[string]string{"query": "read"}
	h.g.sources["tickets/live"] = live
	status, out = h.present(t, "/acquire", h.acquireBody("s3", "query"), cred)
	if status != http.StatusForbidden || out["reason"] != "effect" {
		t.Fatalf("effect outside the scope: %d %v", status, out)
	}
	live.effects = map[string]string{}
	h.g.sources["tickets/live"] = live
	status, out = h.present(t, "/acquire", h.acquireBody("s4", "query"), cred)
	if status != http.StatusForbidden || out["reason"] != "effect" {
		t.Fatalf("an undeclared effect: %d %v", status, out)
	}
	if h.g.started.Load() != started || h.sent(delegationKey(2)) != 0 {
		t.Fatal("a call outside the scope started a source")
	}
	if h.host.counted() != 0 {
		t.Fatal("a call outside the scope consumed budget")
	}
}

// The host's answers: a revoked or unregistered chain, a limit reached, and
// the order of the host's step 9 and 10 refusals before the gateway's own
// step 11.
func TestDelegatedAdmissionReadsTheIssuingHost(t *testing.T) {
	h := newDelegationHarness(t, false)
	root := statement(t, nil)
	cred := h.credential(t, root)
	started := h.g.started.Load()
	for _, c := range []struct {
		answer, refusal string
	}{
		{`{"admission":"refuse","refusal":"revoked"}`, "revoked"},
		{`{"admission":"refuse","refusal":"agent-unregistered"}`, "agent-unregistered"},
		{`{"admission":"refuse","refusal":"subject-unauthorized"}`, "subject-unauthorized"},
		{`{"admission":"refuse","refusal":"out-of-scope","reason":"limit"}`, "out-of-scope"},
	} {
		answer := c.answer
		h.host.setAnswer(func(map[string]any) (int, string) { return http.StatusOK, answer })
		status, out := h.present(t, "/acquire", h.acquireBody("s1", "query"), cred)
		if status != http.StatusForbidden || refusalOf(out) != c.refusal {
			t.Fatalf("%s: %d %v", c.answer, status, out)
		}
	}
	// A call outside the gateway's own scope still reports a revocation the
	// host answers, which comes first; the host answering admit leaves the
	// gateway's own refusal.
	h.host.setAnswer(func(map[string]any) (int, string) { return http.StatusOK, `{"admission":"refuse","refusal":"revoked"}` })
	if status, out := h.present(t, "/acquire", h.acquireBody("s1", "sibling"), cred); status != http.StatusForbidden || refusalOf(out) != "revoked" {
		t.Fatalf("revoked before out-of-scope: %d %v", status, out)
	}
	h.host.setAnswer(func(map[string]any) (int, string) {
		return http.StatusOK, `{"admission":"refuse","refusal":"subject-unauthorized"}`
	})
	if status, out := h.present(t, "/acquire", h.acquireBody("s1", "sibling"), cred); status != http.StatusForbidden || out["reason"] != "tool" {
		t.Fatalf("out-of-scope before step 12: %d %v", status, out)
	}
	if h.g.started.Load() != started {
		t.Fatal("a refused call started a source")
	}
}

// The admission read fails closed: anything but the stated answers refuses as
// admission-unknown, a redirect, another status, an extra member and an
// answer past its bound among them.
func TestDelegatedAdmissionReadFailsClosed(t *testing.T) {
	h := newDelegationHarness(t, false)
	cred := h.credential(t, statement(t, nil))
	started := h.g.started.Load()
	for name, answer := range map[string]func(map[string]any) (int, string){
		"redirect":        func(map[string]any) (int, string) { return http.StatusTemporaryRedirect, `{"admission":"admit"}` },
		"server error":    func(map[string]any) (int, string) { return http.StatusInternalServerError, `{"admission":"admit"}` },
		"another member":  func(map[string]any) (int, string) { return http.StatusOK, `{"admission":"admit","note":"x"}` },
		"another refusal": func(map[string]any) (int, string) { return http.StatusOK, `{"admission":"refuse","refusal":"busy"}` },
		"another verdict": func(map[string]any) (int, string) { return http.StatusOK, `{"admission":"maybe"}` },
		"a duplicate":     func(map[string]any) (int, string) { return http.StatusOK, `{"admission":"admit","admission":"admit"}` },
		"not JSON":        func(map[string]any) (int, string) { return http.StatusOK, `admit` },
		"past its bound": func(map[string]any) (int, string) {
			return http.StatusOK, `{"admission":"admit"}` + strings.Repeat(" ", 5000)
		},
		"an empty answer": func(map[string]any) (int, string) { return http.StatusOK, `` },
		"a reasonless out": func(map[string]any) (int, string) {
			return http.StatusOK, `{"admission":"refuse","refusal":"out-of-scope"}`
		},
	} {
		h.host.setAnswer(answer)
		status, out := h.present(t, "/acquire", h.acquireBody("s1", "query"), cred)
		if status != http.StatusForbidden || refusalOf(out) != refusalAdmissionUnknown {
			t.Fatalf("%s: %d %v", name, status, out)
		}
	}
	h.host.setAnswer(nil)
	h.host.server.Close()
	if status, out := h.present(t, "/acquire", h.acquireBody("s1", "query"), cred); status != http.StatusForbidden || refusalOf(out) != refusalAdmissionUnknown {
		t.Fatalf("an unreachable host: %d %v", status, out)
	}
	if h.g.started.Load() != started {
		t.Fatal("a call whose admission could not be read started a source")
	}
}

// Binding: only the issuing host binds, a chain it signed, for the run's
// software, at a time the chain is valid, and a bearer credential only for a
// read-only chain the operator admits bearer credentials for.
func TestDelegationCredentialBinding(t *testing.T) {
	h := newDelegationHarness(t, false)
	root := statement(t, nil)
	body, _ := json.Marshal(map[string]any{"chain": []any{root}, "software": testSoftware, "key": h.runJWK})
	for name, token := range map[string]string{"the subject": h.token(t, testSubjectSub), "an operator": h.token(t, testOperator)} {
		if status, _ := h.post(t, "/delegation/credential", string(body), map[string]string{"Authorization": "Bearer " + token}); status != http.StatusUnauthorized {
			t.Fatalf("%s binds: %d", name, status)
		}
	}
	if status, _ := h.post(t, "/delegation/credential", string(body), nil); status != http.StatusUnauthorized {
		t.Fatalf("statement bytes alone bind: %d", status)
	}
	for _, c := range []struct {
		name    string
		chain   []map[string]any
		want    string
		mutate  func()
		restore func()
	}{
		{name: "a widened chain", chain: []map[string]any{root, childOf(t, root, map[string]any{"expiresAt": "2026-10-30T09:00:00.000Z"})}, want: "widened"},
		{name: "another host's chain", chain: []map[string]any{statement(t, map[string]any{"host": "desk2"})}, want: "key-mismatch"},
		{name: "a forged signature", chain: []map[string]any{func() map[string]any {
			s := statement(t, nil)
			s["mayDelegate"] = false
			return s
		}()}, want: "signature-mismatch"},
		{name: "another run's software", chain: []map[string]any{statement(t, map[string]any{"act": map[string]any{"agent": rootAgent, "software": map[string]any{"package": "judgment-pack-agent", "version": "0.12.0"}}})}, want: "software-mismatch"},
		{name: "an expired chain", chain: []map[string]any{root}, want: "expired",
			mutate: func() { h.setNow(time.Date(2026, 10, 30, 8, 0, 0, 0, time.UTC)) }, restore: func() { h.setNow(time.Date(2026, 10, 30, 1, 0, 0, 0, time.UTC)) }},
		{name: "a chain not yet valid", chain: []map[string]any{root}, want: "not-yet-valid",
			mutate: func() { h.setNow(time.Date(2026, 10, 29, 23, 59, 59, 999e6, time.UTC)) }, restore: func() { h.setNow(time.Date(2026, 10, 30, 1, 0, 0, 0, time.UTC)) }},
	} {
		if c.mutate != nil {
			c.mutate()
		}
		status, out := h.bind(t, c.chain, nil)
		if c.restore != nil {
			c.restore()
		}
		if status != http.StatusForbidden || refusalOf(out) != c.want {
			t.Fatalf("%s: %d %v", c.name, status, out)
		}
	}
	h.host.setAnswer(func(map[string]any) (int, string) {
		return http.StatusOK, `{"admission":"refuse","refusal":"not-issued"}`
	})
	if status, out := h.bind(t, []map[string]any{root}, nil); status != http.StatusForbidden || refusalOf(out) != "not-issued" {
		t.Fatalf("a link the host never issued: %d %v", status, out)
	}
	h.host.setAnswer(nil)
	// A bearer credential: never for a chain admitting act.
	if status, out := h.bind(t, []map[string]any{root}, "null"); status != http.StatusForbidden || refusalOf(out) != "sender-constraint-required" {
		t.Fatalf("a bearer credential for act: %d %v", status, out)
	}
	readOnly := statement(t, map[string]any{"scope": map[string]any{"sources": []any{scopeOf("tickets/live", []any{"query"}, []any{"read-external"}, map[string]any{})}}})
	if status, out := h.bind(t, []map[string]any{readOnly}, "null"); status != http.StatusForbidden || refusalOf(out) != "sender-constraint-required" {
		t.Fatalf("a bearer credential the operator did not admit: %d %v", status, out)
	}
	// The credential lives five minutes, and never past the leaf's expiry.
	status, out := h.bind(t, []map[string]any{root}, nil)
	if status != http.StatusOK || out["expiresAt"] != "2026-10-30T01:05:00.000Z" || out["tokenType"] != "DPoP" {
		t.Fatalf("lifetime: %d %v", status, out)
	}
	short := statement(t, map[string]any{"expiresAt": "2026-10-30T01:02:00.000Z"})
	if status, out := h.bind(t, []map[string]any{short}, nil); status != http.StatusOK || out["expiresAt"] != "2026-10-30T01:02:00.000Z" {
		t.Fatalf("lifetime under the leaf: %d %v", status, out)
	}
}

// With bearerReadOnly a read-only chain takes a bearer credential, presented
// as Bearer, and a chain admitting act still needs a key.
func TestDelegationBearerReadOnly(t *testing.T) {
	h := newDelegationHarness(t, true)
	readOnly := statement(t, map[string]any{"scope": map[string]any{"sources": []any{scopeOf("tickets/live", []any{"query"}, []any{"read-external"}, map[string]any{})}}})
	status, out := h.bind(t, []map[string]any{readOnly}, "null")
	if status != http.StatusOK || out["tokenType"] != "Bearer" {
		t.Fatalf("bind: %d %v", status, out)
	}
	cred := out["credential"].(string)
	if status, out := h.post(t, "/acquire", h.acquireBody("s1", "query"), map[string]string{"Authorization": "Bearer " + cred}); status != http.StatusOK {
		t.Fatalf("bearer acquire: %d %v", status, out)
	}
	if status, _ := h.post(t, "/acquire", h.acquireBody("s1", "query"), map[string]string{"Authorization": "DPoP " + cred, "DPoP": h.proof(t, "/acquire", cred, nil, nil)}); status != http.StatusUnauthorized {
		t.Fatalf("a bearer credential presented as DPoP: %d", status)
	}
	if status, out := h.bind(t, []map[string]any{statement(t, nil)}, "null"); status != http.StatusForbidden || refusalOf(out) != "sender-constraint-required" {
		t.Fatalf("bearer for act: %d %v", status, out)
	}
}

// Step 0: a credential presented without its proof, with another key's
// proof, a replayed proof, a proof for another URI, another method or
// credential, a stale proof, as Bearer, after it expired or was revoked,
// or with a chain that is not its own.
func TestDelegationCredentialPresentation(t *testing.T) {
	h := newDelegationHarness(t, false)
	root := statement(t, nil)
	cred := h.credential(t, root)
	other := childOf(t, root, nil)
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	body := h.acquireBody("s1", "query")
	replayed := h.proof(t, "/acquire", cred, nil, nil)
	if status, out := h.post(t, "/acquire", body, map[string]string{"Authorization": "DPoP " + cred, "DPoP": replayed}); status != http.StatusOK {
		t.Fatalf("a good proof: %d %v", status, out)
	}
	started := h.g.started.Load()
	for name, headers := range map[string]map[string]string{
		"no proof":            {"Authorization": "DPoP " + cred},
		"another key's proof": {"Authorization": "DPoP " + cred, "DPoP": h.proof(t, "/acquire", cred, otherKey, nil)},
		"a replayed proof":    {"Authorization": "DPoP " + cred, "DPoP": replayed},
		"another URI":         {"Authorization": "DPoP " + cred, "DPoP": h.proof(t, "/act", cred, nil, nil)},
		"another method":      {"Authorization": "DPoP " + cred, "DPoP": h.proof(t, "/acquire", cred, nil, map[string]any{"htm": "GET"})},
		"another credential":  {"Authorization": "DPoP " + cred, "DPoP": h.proof(t, "/acquire", "jpd1_other", nil, nil)},
		"a stale proof":       {"Authorization": "DPoP " + cred, "DPoP": h.proof(t, "/acquire", cred, nil, map[string]any{"iat": h.now.Add(-61 * time.Second).Unix()})},
		"as Bearer":           {"Authorization": "Bearer " + cred},
		"as Bearer, a proof":  {"Authorization": "Bearer " + cred, "DPoP": h.proof(t, "/acquire", cred, nil, nil)},
		"unknown credential":  {"Authorization": "DPoP jpd1_AAAA", "DPoP": h.proof(t, "/acquire", "jpd1_AAAA", nil, nil)},
	} {
		status, out := h.post(t, "/acquire", body, headers)
		if status != http.StatusUnauthorized || refusalOf(out) != refusalCredentialMismatch {
			t.Fatalf("%s: %d %v", name, status, out)
		}
	}
	// A chain presented beside the credential must be its own, byte for byte.
	withChain := func(chain ...map[string]any) string {
		raw, _ := json.Marshal(chain)
		return strings.TrimSuffix(body, "}") + `,"delegation":` + string(raw) + `}`
	}
	if status, out := h.present(t, "/acquire", withChain(root, other), cred); status != http.StatusUnauthorized || refusalOf(out) != refusalCredentialMismatch {
		t.Fatalf("a chain not its own: %d %v", status, out)
	}
	if status, out := h.present(t, "/acquire", withChain(root), cred); status != http.StatusOK {
		t.Fatalf("its own chain: %d %v", status, out)
	}
	started++
	// A token of the issuer is not a credential, and a chain beside it grants
	// nothing.
	if status, out := h.post(t, "/acquire", withChain(root), map[string]string{"Authorization": "Bearer " + h.token(t, testSubjectSub)}); status != http.StatusUnauthorized || refusalOf(out) != refusalCredentialMismatch {
		t.Fatalf("statement bytes beside a token: %d %v", status, out)
	}
	// Past its five minutes, the credential is not live.
	h.setNow(time.Date(2026, 10, 30, 1, 5, 0, 0, time.UTC))
	if status, out := h.present(t, "/acquire", body, cred); status != http.StatusUnauthorized || refusalOf(out) != refusalCredentialMismatch {
		t.Fatalf("an expired credential: %d %v", status, out)
	}
	if h.g.started.Load() != started {
		t.Fatal("a refused presentation started a source")
	}
	// A credential is not accepted where only a token is.
	if status, _ := h.post(t, "/seal", `{"session":"s1"}`, map[string]string{"Authorization": "DPoP " + cred, "DPoP": h.proof(t, "/seal", cred, nil, nil)}); status != http.StatusUnauthorized {
		t.Fatalf("a credential seals: %d", status)
	}
}

// Revocation: of a credential on its own, of a delegation, and of an agent;
// each ends the credentials it names at once, and the host's revocation
// refuses a credential it did not end.
func TestDelegationRevocation(t *testing.T) {
	h := newDelegationHarness(t, false)
	root := statement(t, nil)
	child := childOf(t, root, nil)
	revoke := func(body string, as string) (int, map[string]any) {
		return h.post(t, "/delegation/revoke", body, map[string]string{"Authorization": "Bearer " + h.token(t, as)})
	}
	one, two, three := h.credential(t, root), h.credential(t, root, child), h.credential(t, root, child)
	if status, _ := revoke(`{"credential":"`+tokenDigestOf(one)+`"}`, testSubjectSub); status != http.StatusUnauthorized {
		t.Fatalf("the subject revokes at the gateway: %d", status)
	}
	if status, out := revoke(`{"credential":"`+tokenDigestOf(one)+`"}`, hostRequester); status != http.StatusOK || out["revoked"] != float64(1) {
		t.Fatalf("revoke a credential: %d %v", status, out)
	}
	if status, _ := h.present(t, "/acquire", h.acquireBody("s1", "query"), one); status != http.StatusUnauthorized {
		t.Fatal("a revoked credential is admitted")
	}
	if status, _ := h.present(t, "/acquire", h.acquireBody("s1", "query"), two); status != http.StatusOK {
		t.Fatal("revoking one credential ended another")
	}
	if status, out := revoke(`{"agent":"`+childAgent+`"}`, hostRequester); status != http.StatusOK || out["revoked"] != float64(2) {
		t.Fatalf("revoke an agent: %d %v", status, out)
	}
	for _, c := range []string{two, three} {
		if status, _ := h.present(t, "/acquire", h.acquireBody("s1", "query"), c); status != http.StatusUnauthorized {
			t.Fatal("a credential of a revoked agent is admitted")
		}
	}
	four := h.credential(t, root, child)
	if status, out := revoke(`{"delegation":"`+root["id"].(string)+`"}`, hostRequester); status != http.StatusOK || out["revoked"] != float64(1) {
		t.Fatalf("revoke a delegation's chains: %d %v", status, out)
	}
	if status, _ := h.present(t, "/acquire", h.acquireBody("s1", "query"), four); status != http.StatusUnauthorized {
		t.Fatal("a credential below a revoked link is admitted")
	}
	for _, bad := range []string{`{}`, `{"agent":"x"}`, `{"agent":"` + childAgent + `","delegation":"` + childAgent + `"}`, `{"credential":"sha256:x"}`} {
		if status, _ := revoke(bad, hostRequester); status != http.StatusForbidden && status != http.StatusBadRequest {
			t.Fatalf("%s: %d", bad, status)
		}
	}
	// The host's own revocation answers every admission at once, whether or
	// not the gateway was told.
	five := h.credential(t, root)
	h.host.setAnswer(func(map[string]any) (int, string) { return http.StatusOK, `{"admission":"refuse","refusal":"revoked"}` })
	if status, out := h.present(t, "/act", h.actBody("s9", delegationKey(9), ""), five); status != http.StatusForbidden || refusalOf(out) != "revoked" || h.sent(delegationKey(9)) != 0 {
		t.Fatalf("a revoked delegation acts: %d %v", status, out)
	}
}

// A gateway without a delegation is as it was: no endpoint, no member, no
// credential.
func TestNoDelegationNoSurface(t *testing.T) {
	h := newDelegationHarness(t, false)
	h.g.delegation = nil
	server := httptest.NewServer(h.g.handler())
	defer server.Close()
	for _, path := range []string{"/delegation/credential", "/delegation/revoke"} {
		resp, err := http.Post(server.URL+path, "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
	}
	h.server = server
	if status, out := h.post(t, "/acquire", h.acquireBody("s1", "query")[:len(h.acquireBody("s1", "query"))-1]+`,"delegation":[]}`, map[string]string{"Authorization": "Bearer " + h.token(t, testSubjectSub)}); status != http.StatusBadRequest || !strings.Contains(out["error"].(string), "does not read: delegation") {
		t.Fatalf("a delegation member without a delegation: %d %v", status, out)
	}
}

// Admission repeats what it can of step 0 and steps 1 to 8 at the moment of
// dispatch, not only when the request arrived: a credential ended since, a
// key unpinned since, and a clock now before the chain's issuedAt each
// refuse.
func TestDelegatedAdmissionRepeatsTheEarlierSteps(t *testing.T) {
	h := newDelegationHarness(t, false)
	cred := h.credential(t, statement(t, nil))
	who, refusal := h.d.present(httptest.NewRequest(http.MethodPost, "/acquire", nil), cred, "Bearer")
	if refusal == nil || refusal.name != refusalCredentialMismatch {
		t.Fatal("a DPoP credential presented as Bearer")
	}
	// Step 0 itself refuses an expired credential, whatever comes after it.
	req := httptest.NewRequest(http.MethodPost, h.server.URL+"/acquire", nil)
	h.setNow(time.Date(2026, 10, 30, 1, 5, 0, 0, time.UTC))
	req.Header.Set("DPoP", h.proof(t, "/acquire", cred, nil, nil))
	if _, refusal := h.d.present(req, cred, "DPoP"); refusal == nil || refusal.name != refusalCredentialMismatch {
		t.Fatalf("an expired credential at step 0: %v", refusal)
	}
	h.setNow(time.Date(2026, 10, 30, 1, 0, 0, 0, time.UTC))
	cred = h.credential(t, statement(t, nil))
	// The sender as step 0 left it, then the credential ended.
	digest := tokenDigestOf(cred)
	h.d.mu.Lock()
	bound := h.d.credentials[digest]
	h.d.mu.Unlock()
	leaf := bound.chain.leaf()
	who = &caller{delegated: &delegatedSender{kind: "actor", credential: bound, scope: reservationScope{sub: leaf.sub, rootActor: leaf.agent, host: "desk"}}}
	call := delegatedCall{source: "tickets/live", tool: "query", effect: "read-external", count: true}
	if _, r := h.d.admitDelegated(who.delegated, call); r != nil {
		t.Fatalf("admitted: %v", r)
	}
	h.setNow(time.Date(2026, 10, 29, 23, 0, 0, 0, time.UTC))
	if _, r := h.d.admitDelegated(who.delegated, call); r == nil || r.name != refusalNotYetValid {
		t.Fatalf("a clock before issuedAt: %v", r)
	}
	h.setNow(time.Date(2026, 10, 30, 1, 0, 0, 0, time.UTC))
	keys := h.d.keys["desk"]
	h.d.keys["desk"] = map[string]ed25519.PublicKey{}
	if _, r := h.d.admitDelegated(who.delegated, call); r == nil || r.name != refusalKeyMismatch {
		t.Fatalf("an unpinned key: %v", r)
	}
	h.d.keys["desk"] = keys
	h.d.mu.Lock()
	delete(h.d.credentials, digest)
	h.d.mu.Unlock()
	if _, r := h.d.admitDelegated(who.delegated, call); r == nil || r.name != refusalCredentialMismatch {
		t.Fatalf("an ended credential: %v", r)
	}
	if _, r := h.d.admitDelegated(&delegatedSender{kind: "host"}, call); r == nil || r.name != refusalActorOnly {
		t.Fatalf("a sender other than the actor: %v", r)
	}
}

// A host binds only chains it issued, whatever other hosts' keys the gateway
// pins.
func TestDelegationBindsOnlyTheHostsOwnChains(t *testing.T) {
	h := newDelegationHarness(t, false)
	desk := h.d.hosts["desk"]
	h.d.hosts["desk2"] = &delegationHost{delegationHostSpec: delegationHostSpec{host: "desk2", requester: "service:desk2", keys: desk.keys, admission: desk.admission}, bearer: desk.bearer}
	h.d.keys["desk2"] = desk.keys
	if status, out := h.bind(t, []map[string]any{statement(t, map[string]any{"host": "desk2"})}, nil); status != http.StatusForbidden || refusalOf(out) != "host-unauthenticated" {
		t.Fatalf("another host's chain: %d %v", status, out)
	}
}
