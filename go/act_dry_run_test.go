package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// /act's dry-run and approvals (ADR-0054, decisions 2 and 3), with the
// synthetic sources of actScopeSetup: the write platform of none ("tickets")
// and the one fixed to scope B ("tickets-b").

// dryRunApprovalsJSON is one citation, its members in canonical order.
const dryRunApprovalsJSON = `[{"digest":"sha256:` + "4444444444444444444444444444444444444444444444444444444444444444" + `","id":"change-1042","kind":"single"}]`

// dryRunBody is an /act request with no keyScope; extra is raw members
// appended, each led by a comma.
func (h *actScopeHarness) dryRunBody(session, platform, scope, key, decision, cites, extra string) string {
	b := `{"session":"` + session + `","platform":"` + platform + `","tool":"query","arguments":{"ticket":"T-1"},"decision":` + decision + `,"cites":` + cites + `,"actionKey":"` + key + `"`
	if scope != "" {
		b += `,"scope":` + scope
	}
	return b + extra + "}"
}

// sessionsOf is the service's session state and the gate's count of what
// it admitted, as text.
func sessionsOf(g *gatewayService) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	names := make([]string, 0, len(g.sessions))
	for name := range g.sessions {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		fmt.Fprintf(&b, "%s %+v\n", name, g.sessions[name])
	}
	fmt.Fprintf(&b, "gate pending %d closed %v", g.gate.pending, g.gate.closed)
	return b.String()
}

// A dry-run leaves the journal, the store, the labels, the receipt sink and
// the session state as they were, byte for byte, and answers exactly
// {dryRun, request, salts}: a dry-run receipt that verify-dry-run accepts,
// that every receipt verifier calls malformed, and whose request
// commitment opens with the salt answered.
func TestActDryRunChangesNothing(t *testing.T) {
	h := actScopeSetup(t)
	h.g.dryRunApprovals = true
	h.g.labels = fsLabels{root: h.g.storeRoot}
	// a session of scope B with an action in it, its label recorded
	if code, out := authed(t, h.server, "/act", h.dryRunBody("act-b", "tickets-b", scopeB, strings.Repeat("a", 64), h.decisionB, h.cite("b-read", h.scopedSig), ""), h.tokenB); code != http.StatusOK {
		t.Fatalf("the scoped action: %d %v", code, out)
	}
	var hits atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	t.Cleanup(sink.Close)
	h.g.forwarder = newReceiptForwarder(&receiptSinkSpec{url: sink.URL})
	tree, sessions := treeOf(t, h.root), sessionsOf(h.g)

	for _, c := range []struct{ name, body, token string }{
		{"in the session of the action", h.dryRunBody("act-b", "tickets-b", scopeB, strings.Repeat("e", 64), h.decisionB, h.cite("b-read", h.scopedSig), `,"dryRun":true`), h.tokenB},
		{"the same key as the action", h.dryRunBody("act-b", "tickets-b", scopeB, strings.Repeat("a", 64), h.decisionB, h.cite("b-read", h.scopedSig), `,"dryRun":true`), h.tokenB},
		{"a label never used", h.dryRunBody("dry-new", "tickets-b", scopeB, strings.Repeat("f", 64), h.decisionB, h.cite("b-read", h.scopedSig), `,"dryRun":true,"approvals":`+dryRunApprovalsJSON), h.tokenB},
		{"the scope of none", h.dryRunBody("dry-u", "tickets", "", strings.Repeat("f", 64), h.decisionU, h.cite("u-read", h.unscopedSig), `,"dryRun":true`), h.tokenA},
	} {
		code, out := authed(t, h.server, "/act", c.body, c.token)
		if code != http.StatusOK {
			t.Fatalf("%s: %d %v", c.name, code, out)
		}
		if len(out) != 3 || out["dryRun"] == nil || out["request"] == nil || out["salts"] == nil {
			t.Fatalf("%s: the answer is not exactly {dryRun, request, salts}: %v", c.name, out)
		}
		raw, _ := json.Marshal(out["dryRun"])
		if rep := verifyDryRun(raw, edKey(h.g.store.publicKey)); !rep.OK || !rep.DryRun {
			t.Fatalf("%s: verify-dry-run: %+v %s", c.name, rep, raw)
		}
		if status, err := dryRunAsReceipt(raw, edKey(h.g.store.publicKey)); err != nil || status != "malformed" {
			t.Fatalf("%s: as a receipt: %s %v", c.name, status, err)
		}
		receipt := out["dryRun"].(map[string]any)
		action := receipt["action"].(map[string]any)
		request, _ := json.Marshal(out["request"])
		reqValue, _ := parseJSON(request)
		salt := out["salts"].(map[string]any)["request"].(string)
		saltBytes, _ := hex.DecodeString(salt)
		if action["request"] != commitmentOver(saltBytes, "request:", canon(reqValue)) {
			t.Fatalf("%s: the commitment does not open with the salt answered", c.name)
		}
		if args := out["request"].(map[string]any)["arguments"].(map[string]any); args["ticket"] != "T-1" || len(args) < 2 {
			t.Fatalf("%s: the request is not the one the executor would be handed, idempotency argument set: %v", c.name, args)
		}
		if strings.HasPrefix(c.name, "the scope of none") != (receipt["scope"] == nil) {
			t.Fatalf("%s: scope present where the source is fixed to one, and only there: %v", c.name, receipt)
		}
		if _, cites := action["approvals"]; cites != strings.Contains(c.body, "approvals") {
			t.Fatalf("%s: approvals: %v", c.name, action)
		}
	}
	sameTree(t, "everything under the root (store, journal, labels, registry, target)", treeOf(t, h.root), tree)
	if now := sessionsOf(h.g); now != sessions {
		t.Fatalf("the session state changed:\n%s\n->\n%s", sessions, now)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the receipt sink was sent %d request(s)", n)
	}
}

// An executor whose name resolves to nothing is never started by a dry-run,
// which answers 200; the write of the same request tries to start it and is
// answered action-not-dispatched.
func TestActDryRunStartsNoExecutor(t *testing.T) {
	h := actScopeSetup(t)
	h.g.dryRunApprovals = true
	missing := filepath.Join(t.TempDir(), "no-such-executor")
	write := h.g.sources["tickets-b/write"]
	write.argv = append([]string{missing}, write.argv[1:]...)
	h.g.sources["tickets-b/write"] = write
	body := h.dryRunBody("act-x", "tickets-b", scopeB, strings.Repeat("9", 64), h.decisionB, h.cite("b-read", h.scopedSig), `,"dryRun":true`)
	if code, out := authed(t, h.server, "/act", body, h.tokenB); code != http.StatusOK || out["dryRun"] == nil {
		t.Fatalf("the dry-run: %d %v", code, out)
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatalf("the executor's name resolves to something: %v", err)
	}
	code, out := authed(t, h.server, "/act", strings.Replace(body, `,"dryRun":true`, "", 1), h.tokenB)
	if code == http.StatusOK || !strings.Contains(fmt.Sprint(out["error"]), "action-not-dispatched") {
		t.Fatalf("the write was not refused as one whose executor cannot start: %d %v", code, out)
	}
}

// The dry-run step (ADR-0054, step 5) and the version: a value other than
// true, a dry-run beside keyScope or reconcile, and one under an engine
// that mints version 2 receipts are refused at dry-run; below the version
// dryRun and approvals are members /act does not read.
func TestActDryRunStep(t *testing.T) {
	h := actScopeSetup(t)
	base := h.dryRunBody("act-s", "tickets", "", strings.Repeat("8", 64), h.decisionU, h.cite("u-read", h.unscopedSig), "")
	with := func(extra string) string { return strings.TrimSuffix(base, "}") + extra + "}" }
	for _, extra := range []string{`,"dryRun":true`, `,"approvals":` + dryRunApprovalsJSON} {
		if code, out := authed(t, h.server, "/act", with(extra), h.tokenA); code != http.StatusBadRequest || out["refusedAt"] != nil {
			t.Fatalf("below the version %s: %d %v", extra, code, out)
		}
	}
	h.g.dryRunApprovals = true
	for _, extra := range []string{`,"dryRun":false`, `,"dryRun":"true"`, `,"dryRun":true,"keyScope":"authority"`, `,"dryRun":true,"reconcile":true`} {
		if code, out := authed(t, h.server, "/act", with(extra), h.tokenA); code != http.StatusBadRequest || out["refusedAt"] != "dry-run" {
			t.Fatalf("%s: %d %v", extra, code, out)
		}
	}
	h.g.receiptVersion = "2"
	if code, out := authed(t, h.server, "/act", with(`,"dryRun":true`), h.tokenA); code != http.StatusBadRequest || out["refusedAt"] != "dry-run" {
		t.Fatalf("under version 2 receipts: %d %v", code, out)
	}
}

// A delegated dry-run's one read of the issuing host is the admission read
// at "count": false: the host counts nothing, nothing is sent or reserved,
// and the receipt carries the delegation member. A write then counts once.
func TestActDryRunDelegatedReadsWithoutCounting(t *testing.T) {
	h := newDelegationHarness(t, false)
	h.g.dryRunApprovals = true
	cred := h.credential(t, statement(t, nil))
	key := delegationKey(3)
	before := h.host.readCount()
	status, out := h.present(t, "/act", h.actBody("s1", key, `,"dryRun":true`), cred)
	if status != http.StatusOK || out["dryRun"].(map[string]any)["delegation"] == nil {
		t.Fatalf("the delegated dry-run: %d %v", status, out)
	}
	h.host.mu.Lock()
	reads := append([]map[string]any(nil), h.host.reads[before:]...)
	h.host.mu.Unlock()
	if len(reads) == 0 {
		t.Fatal("the dry-run made no admission read")
	}
	for _, r := range reads {
		if call, _ := r["call"].(map[string]any); call == nil || call["count"] != false {
			t.Fatalf("a read of the dry-run is not at count false: %v", r)
		}
	}
	if n := h.host.counted(); n != 0 || h.sent(key) != 0 {
		t.Fatalf("the host counted %d, the target received %d", n, h.sent(key))
	}
	if status, out := h.present(t, "/act", h.actBody("s1", key, ""), cred); status != http.StatusOK || h.host.counted() != 1 {
		t.Fatalf("the write: %d %v, counted %d", status, out, h.host.counted())
	}
}

// A dry-run from a reservation's sender is refused at the dry-run step,
// before the sender is authenticated: the host is not read.
func TestActDryRunFromAReservationSenderIsRefused(t *testing.T) {
	h := newDelegationHarness(t, false)
	h.g.dryRunApprovals = true
	key := delegationKey(4)
	before := h.host.readCount()
	body := h.actBody("s4", key, h.reservationOf(testSub(), rootAgent)+`,"dryRun":true`)
	for _, token := range []string{h.token(t, hostRequester), h.token(t, testSubjectSub)} {
		status, out := h.post(t, "/act", body, map[string]string{"Authorization": "Bearer " + token})
		if status != http.StatusBadRequest || out["refusedAt"] != "dry-run" {
			t.Fatalf("a reservation sender's dry-run: %d %v", status, out)
		}
	}
	if h.host.readCount() != before || h.sent(key) != 0 {
		t.Fatalf("the refused dry-run read the host or sent: %d reads", h.host.readCount()-before)
	}
}

// Approvals (ADR-0054, decision 3): refused at their step, after the
// citations and before the decision record; carried in the receipt; and in
// the key's approved content. A version 2 reservation replayed with
// approvals is a conflict, as is a version 3 one replayed with none or with
// others.
func TestActApprovalsOnTheKey(t *testing.T) {
	h := actScopeSetup(t)
	h.g.dryRunApprovals = true
	who := &caller{issuer: h.g.identity.issuer, subject: subjectA}
	act := func(key, extra string) (int, map[string]any) {
		return authed(t, h.server, "/act", h.dryRunBody("act-u", "tickets", "", key, h.decisionU, h.cite("u-read", h.unscopedSig), extra), h.tokenA)
	}
	intent := func(key string) string {
		data, err := os.ReadFile(filepath.Join(h.g.storeRoot, "actions", h.g.actionNamespaceIn(who, key, ""), "intent.json"))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	conflict := func(name string, code int, out map[string]any) {
		t.Helper()
		if code != http.StatusBadRequest || out["refusedAt"] != "action-key" || !strings.Contains(fmt.Sprint(out["error"]), "action-key-conflict") {
			t.Fatalf("%s: %d %v", name, code, out)
		}
	}
	other := strings.Replace(dryRunApprovalsJSON, "change-1042", "change-1043", 1)

	// the step's order: a citation that does not resolve first, a record
	// that is not there after
	bad := `,"approvals":[{"kind":"other","id":"x","digest":"sha256:` + strings.Repeat("4", 64) + `"}]`
	if code, out := authed(t, h.server, "/act", h.dryRunBody("act-u", "tickets", "", strings.Repeat("1", 64), h.decisionU, h.cite("u-read", strings.Repeat("0", 128)), bad), h.tokenA); code != http.StatusBadRequest || out["refusedAt"] != "cites" {
		t.Fatalf("bad citation and bad approvals: %d %v", code, out)
	}
	noRecord := `{"recordDigest":"sha256:` + strings.Repeat("7", 64) + `","packDigest":"sha256:` + strings.Repeat("d", 64) + `"}`
	for _, extra := range []string{bad, `,"approvals":[]`, `,"approvals":{}`} {
		if code, out := authed(t, h.server, "/act", h.dryRunBody("act-u", "tickets", "", strings.Repeat("1", 64), noRecord, h.cite("u-read", h.unscopedSig), extra), h.tokenA); code != http.StatusBadRequest || out["refusedAt"] != "approvals" {
			t.Fatalf("approvals out of form %s: %d %v", extra, code, out)
		}
	}
	journalAbsent(t, h.g, h.g.actionNamespaceIn(who, strings.Repeat("1", 64), ""))

	// a version 2 reservation, as before, replayed with approvals
	k2 := strings.Repeat("2", 64)
	code, out := act(k2, "")
	if code != http.StatusOK {
		t.Fatalf("the action with no approvals: %d %v", code, out)
	}
	if action := out["receipt"].(map[string]any)["action"].(map[string]any); action["approvals"] != nil {
		t.Fatalf("an action naming no approvals carries some: %v", action)
	}
	if !strings.Contains(intent(k2), `"identityVersion":"2"`) {
		t.Fatalf("the reservation of no approvals: %s", intent(k2))
	}
	code, out = act(k2, `,"approvals":`+dryRunApprovalsJSON)
	conflict("a version 2 reservation replayed with approvals", code, out)

	// a version 3 reservation: replayed as it was, and with none or others
	k3 := strings.Repeat("3", 64)
	code, out = act(k3, `,"approvals":`+dryRunApprovalsJSON)
	if code != http.StatusOK {
		t.Fatalf("the action with approvals: %d %v", code, out)
	}
	carried, _ := json.Marshal(out["receipt"].(map[string]any)["action"].(map[string]any)["approvals"])
	if string(carried) != dryRunApprovalsJSON {
		t.Fatalf("the receipt's approvals: %s", carried)
	}
	if !strings.Contains(intent(k3), `"identityVersion":"3"`) {
		t.Fatalf("the reservation with approvals: %s", intent(k3))
	}
	if code, again := act(k3, `,"approvals":`+dryRunApprovalsJSON); code != http.StatusOK || fmt.Sprint(again["receipt"]) != fmt.Sprint(out["receipt"]) {
		t.Fatalf("the replay: %d %v", code, again)
	}
	code, out = act(k3, "")
	conflict("a version 3 reservation replayed with none", code, out)
	code, out = act(k3, `,"approvals":`+other)
	conflict("a version 3 reservation replayed with other approvals", code, out)
	if n := actionKeysSent(h.root, k2) + actionKeysSent(h.root, k3); n != 2 {
		t.Fatalf("the target received %d writes, want one per key", n)
	}
}

// preG3Intent is the intent.json the code before approvals were read wrote
// for the request below, captured from that code: a request that names no
// approvals reserves the same bytes.
const preG3Intent = `{"journalVersion":"2","identityVersion":"2","fingerprint":"5445a841fc86e83a73f6b7d41890ea32016496c7e162a25a4fa2abb83ed933f6"}`

func TestActNoApprovalsJournalBytesAsBefore(t *testing.T) {
	if !actionJournalSupported {
		t.Skip("the action journal needs this platform's directory sync")
	}
	sources := actionKeysSources(t, "/synthetic-root", "/synthetic-program")
	spec := sources["tickets/write"]
	args, _ := parseJSON([]byte(`{"ticket":"T-1"}`))
	decisionV, _ := parseJSON([]byte(`{"recordDigest":"sha256:` + strings.Repeat("1", 64) + `","packDigest":"sha256:` + strings.Repeat("d", 64) + `"}`))
	citesV, _ := parseJSON([]byte(`[{"sessionId":"read","callIndex":0,"signature":"` + strings.Repeat("2", 128) + `"}]`))
	approvals, err := requestApprovals(json.RawMessage(dryRunApprovalsJSON))
	if err != nil {
		t.Fatal(err)
	}
	j, err := openActionJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	reserved := func(namespace string, approvals value) (string, *actionClaim) {
		identity, err := actionFingerprintWith("tickets", "query", args, decisionV, citesV, approvals, spec, spec.actionRecovery["query"], sources["tickets/live"])
		if err != nil {
			t.Fatal(err)
		}
		claim, err := j.reserveScoped(namespace, identity, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(claim.close)
		raw, err := claim.read("intent.json", 1024)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw), claim
	}
	if got, _ := reserved(strings.Repeat("e", 64), nil); got != preG3Intent {
		t.Fatalf("a reservation of no approvals:\n%s\nwant\n%s", got, preG3Intent)
	}
	got, claim := reserved(strings.Repeat("f", 64), approvals)
	if !strings.Contains(got, `"identityVersion":"3"`) || strings.Contains(got, "5445a841") {
		t.Fatalf("a reservation with approvals: %s", got)
	}
	// journal compact reads it as the gateway holds it
	if reason := intentReads(claim); reason != "" {
		t.Fatalf("a version 3 intent does not read: %s", reason)
	}
}

// A receipt the session holds for the sink refuses the dry-run as it
// refuses the write (ADR-0049): the same status, code and sentence. The
// dry-run reads the hold and sends nothing: the sink is sent no request,
// and the store, the journal and what the session holds are as they were.
// The write then tries the sink, which acknowledges nothing, and is refused.
func TestActDryRunRefusedWhileAReceiptIsHeldForTheSink(t *testing.T) {
	h := actScopeSetup(t)
	h.g.dryRunApprovals = true
	write := h.dryRunBody("act-h", "tickets-b", scopeB, strings.Repeat("a", 64), h.decisionB, h.cite("b-read", h.scopedSig), "")
	if code, out := authed(t, h.server, "/act", write, h.tokenB); code != http.StatusOK {
		t.Fatalf("the first action: %d %v", code, out)
	}
	var hits atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(sink.Close)
	h.g.forwarder = newReceiptForwarder(&receiptSinkSpec{url: sink.URL})
	h.g.forwarder.backoff = []time.Duration{time.Millisecond, time.Millisecond}
	h.g.mu.Lock()
	state := h.g.sessions["act-h"]
	if state.forward == nil {
		state.forward = newForwardQueue()
	}
	state.forward.add(heldReceipt{index: 1, body: []byte(`{"synthetic":true}`), digest: "sha256:" + strings.Repeat("5", 64)})
	h.g.mu.Unlock()
	tree, sessions := treeOf(t, h.root), sessionsOf(h.g)

	second := h.dryRunBody("act-h", "tickets-b", scopeB, strings.Repeat("b", 64), h.decisionB, h.cite("b-read", h.scopedSig), "")
	dryCode, dry := authed(t, h.server, "/act", strings.TrimSuffix(second, "}")+`,"dryRun":true}`, h.tokenB)
	if dryCode != http.StatusServiceUnavailable || dry["code"] != receiptNotForwardedCode || dry["error"] != (receiptNotForwarded{}).Error() {
		t.Fatalf("the dry-run was not refused as a receipt held for the sink: %d %v", dryCode, dry)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the dry-run sent the sink %d request(s)", n)
	}
	sameTree(t, "everything under the root after the dry-run", treeOf(t, h.root), tree)
	if now := sessionsOf(h.g); now != sessions {
		t.Fatalf("the session state changed:\n%s\n->\n%s", sessions, now)
	}
	if !state.forward.unacknowledged() {
		t.Fatal("the dry-run took the receipt off the hold")
	}

	writeCode, wrote := authed(t, h.server, "/act", second, h.tokenB)
	if writeCode != dryCode || fmt.Sprint(wrote) != fmt.Sprint(dry) {
		t.Fatalf("the write and the dry-run answer differently:\nwrite %d %v\ndry   %d %v", writeCode, wrote, dryCode, dry)
	}
	if hits.Load() == 0 {
		t.Fatal("the write did not try the sink")
	}
}
