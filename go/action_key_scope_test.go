package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	withKeyScope  = `,"keyScope":"authority"`
	withReconcile = `,"reconcile":true`
)

// anotherSubject is a worker that authenticates as someone else: the takeover
// #352 M6 is about.
var anotherSubject = &caller{issuer: "https://issuer.test", subject: "another-subject", tokenDigest: "sha256:" + strings.Repeat("e", 64)}

func scopedAct(g *gatewayService, c actionKeysCall, session, key string, who *caller, scoped, reconcile bool) (map[string]any, error) {
	return scopedActOn(g, c, session, key, who, scoped, reconcile, `{"ticket":"T-1"}`)
}

func scopedActOn(g *gatewayService, c actionKeysCall, session, key string, who *caller, scoped, reconcile bool, arguments string) (map[string]any, error) {
	members := actionKeyMembers{key: json.RawMessage(`"` + key + `"`)}
	if scoped {
		members.keyScope = json.RawMessage(`"authority"`)
	}
	if reconcile {
		members.reconcile = json.RawMessage(`true`)
	}
	return g.actKeyed(json.RawMessage(`"`+session+`"`), json.RawMessage(`"tickets"`), json.RawMessage(`"query"`), json.RawMessage(arguments), c.Decision, c.Cites, who, members)
}

// keyRefusal is the name a refusal goes by on the wire, or the error's text.
func keyRefusal(err error) string {
	var named *delegationRefusal
	switch {
	case err == nil:
		return ""
	case errors.As(err, &named):
		return named.name
	}
	return err.Error()
}

func wantKeyRefusal(t *testing.T, step string, err error, want string) {
	t.Helper()
	if got := keyRefusal(err); got != want {
		t.Fatalf("%s: answered %q, want %q", step, got, want)
	}
}

func wantSent(t *testing.T, root, key string, want int) {
	t.Helper()
	if sent := actionKeysSent(root, key); sent != want {
		t.Fatalf("the target received %d writes, want %d", sent, want)
	}
}

func journalAbsent(t *testing.T, g *gatewayService, name string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(g.storeRoot, "actions", name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s is in the journal: %v", name, err)
	}
}

// The agent's members exactly as its contract vector writes them
// (contract/vectors/job/gateway.json), through the HTTP surface: a first send, a
// reconciliation, and the two a delegated run sends.
func TestActionKeyScopeWireForms(t *testing.T) {
	h := newDelegationHarness(t, false)
	bearer := func(subject string) map[string]string {
		return map[string]string{"Authorization": "Bearer " + h.token(t, subject)}
	}
	exactly := func(step string, out map[string]any, want string) {
		t.Helper()
		if refusalOf(out) != want || out["refusedAt"] != "action-key" || !strings.HasPrefix(out["error"].(string), want) || len(out) != 3 {
			t.Fatalf("%s: %v, want the refusal %s and only {error, refusal, refusedAt}", step, out, want)
		}
	}
	key := delegationKey(1)
	status, out := h.post(t, "/act", h.actBody("w1", key, withKeyScope+withReconcile), bearer("alice"))
	if status != http.StatusConflict {
		t.Fatalf("a close: %d %v", status, out)
	}
	exactly("a close", out, "action-key-not-dispatched")
	status, out = h.post(t, "/act", h.actBody("w2", key, withKeyScope), bearer("alice"))
	if status != http.StatusConflict {
		t.Fatalf("a closed key: %d %v", status, out)
	}
	exactly("a closed key", out, "action-key-closed")
	status, out = h.post(t, "/act", h.actBody("w3", key, withKeyScope), bearer("bob"))
	if status != http.StatusForbidden {
		t.Fatalf("another subject: %d %v", status, out)
	}
	exactly("another subject", out, "action-key-scope-conflict")
	if h.sent(key) != 0 {
		t.Fatalf("sent %d", h.sent(key))
	}
	// A first scope with no reservation: the third refusal of the key's state.
	unknown := delegationKey(6)
	holder := &caller{issuer: testIssuerURL, subject: "alice"}
	j, err := openActionJournal(h.g.storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	if err := j.holdKeyIndex(h.g.actionFirstScope(holder, unknown, h.g.actionNamespace(holder, unknown))); err != nil {
		t.Fatal(err)
	}
	status, out = h.post(t, "/act", h.actBody("w-unknown", unknown, withKeyScope+withReconcile), bearer("alice"))
	if status != http.StatusConflict {
		t.Fatalf("a first scope with no reservation: %d %v", status, out)
	}
	exactly("a first scope with no reservation", out, "action-key-outcome-unknown")

	sent := delegationKey(2)
	if status, out = h.post(t, "/act", h.actBody("w4", sent, withKeyScope), bearer("alice")); status != http.StatusOK || h.sent(sent) != 1 {
		t.Fatalf("a first send: %d %v, sent %d", status, out, h.sent(sent))
	}
	if status, out = h.post(t, "/act", h.actBody("w5", sent, withKeyScope+withReconcile), bearer("bob")); status != http.StatusForbidden || h.sent(sent) != 1 {
		t.Fatalf("another subject reconciling: %d %v", status, out)
	}
	exactly("another subject reconciling", out, "action-key-scope-conflict")
	if status, out = h.post(t, "/act", h.actBody("w6", sent, withKeyScope+withReconcile), bearer("alice")); status != http.StatusOK || out["receipt"] == nil || h.sent(sent) != 1 {
		t.Fatalf("the retained answer: %d %v", status, out)
	}

	// Anything else is refused at the key's step, and leaves nothing.
	for name, extra := range map[string]string{
		"another scope":      `,"keyScope":"subject"`,
		"a scope's type":     `,"keyScope":true`,
		"a null scope":       `,"keyScope":null`,
		"reconcile false":    `,"keyScope":"authority","reconcile":false`,
		"reconcile's type":   `,"keyScope":"authority","reconcile":"true"`,
		"a null reconcile":   `,"keyScope":"authority","reconcile":null`,
		"no scope":           withReconcile,
		"a scope beside":     `,"keyScope":"authority","KEYSCOPE":"authority"`,
		"reconcile repeated": `,"keyScope":"authority","reconcile":true,"reconcile":true`,
	} {
		fresh := delegationKey(3)
		if status, out := h.post(t, "/act", h.actBody("w-bad", fresh, extra), bearer("carol")); status != http.StatusBadRequest {
			t.Fatalf("%s: %d %v", name, status, out)
		}
		journalAbsent(t, h.g, h.g.actionNamespace(&caller{issuer: testIssuerURL, subject: "carol"}, fresh))
		if h.sent(fresh) != 0 {
			t.Fatalf("%s: sent %d", name, h.sent(fresh))
		}
	}
	// With no key there is nothing for them to bear on.
	h.g.requireActionKey = false
	for name, extra := range map[string]string{"a scope": withKeyScope, "a close": withKeyScope + withReconcile} {
		body := strings.Replace(h.actBody("w-nokey", delegationKey(4), extra), `,"actionKey":"`+delegationKey(4)+`"`, "", 1)
		if status, out := h.post(t, "/act", body, bearer("carol")); status != http.StatusBadRequest || out["refusedAt"] != "action-key" {
			t.Fatalf("%s without a key: %d %v", name, status, out)
		}
	}
	h.g.requireActionKey = true

	// A delegated run sends no keyScope, and its own scope is what it holds.
	actor := h.credential(t, statement(t, nil))
	if status, out := h.present(t, "/act", h.actBody("w7", delegationKey(5), withKeyScope), actor); status != http.StatusBadRequest || out["refusedAt"] != "action-key" {
		t.Fatalf("a delegated keyScope: %d %v", status, out)
	}
	if status, out := h.present(t, "/act", h.actBody("w8", delegationKey(5), withReconcile), actor); status != http.StatusConflict || refusalOf(out) != refusalKeyNotDispatched {
		t.Fatalf("a delegated reconciliation: %d %v", status, out)
	}
}

// #352 M6, P4c: a takeover by another subject finds the key taken. One mutation,
// for a request that sends the flag or not, plain or reconciling, for a write that
// answered and one that did not, and after a restart. Nothing is reserved for it.
func TestAnotherSubjectFindsTheKeyTaken(t *testing.T) {
	for _, write := range []string{"respond", "drop"} {
		t.Run(write, func(t *testing.T) {
			root, g, c := actionKeysSetup(t)
			key := strings.Repeat("a", 64)
			actionKeysMode(t, root, "write", write)
			if _, err := scopedAct(g, c, "first", key, actionKeysWho, true, false); err != nil {
				t.Fatal(err)
			}
			wantSent(t, root, key, 1)
			actionKeysMode(t, root, "write", "respond")
			check := func(g *gatewayService, round string) {
				t.Helper()
				for _, req := range []struct {
					name              string
					scoped, reconcile bool
				}{{"plain", true, false}, {"reconciling", true, true}, {"unflagged", false, false}} {
					_, err := scopedAct(g, c, round+"-"+req.name, key, anotherSubject, req.scoped, req.reconcile)
					wantKeyRefusal(t, req.name, err, refusalKeyScopeConflict)
				}
				wantSent(t, root, key, 1)
				journalAbsent(t, g, g.actionNamespace(anotherSubject, key))
			}
			check(g, "before")
			check(actionKeysService(t, root, actionKeysSources(t, root, os.Args[0])), "after")
		})
	}
}

// A takeover by the same subject, with a new token, a fresh session and a restart,
// finds the same reservation: the retained answer, or the read-back. One mutation.
func TestSameSubjectTakeoverFindsItsReservation(t *testing.T) {
	renewed := &caller{issuer: actionKeysWho.issuer, subject: actionKeysWho.subject, tokenDigest: "sha256:" + strings.Repeat("f", 64)}
	t.Run("answered", func(t *testing.T) {
		root, g, c := actionKeysSetup(t)
		key := strings.Repeat("b", 64)
		first, err := scopedAct(g, c, "first", key, actionKeysWho, true, false)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := json.Marshal(first)
		restarted := actionKeysService(t, root, actionKeysSources(t, root, os.Args[0]))
		for _, reconcile := range []bool{false, true} {
			out, err := scopedAct(restarted, c, "takeover", key, renewed, true, reconcile)
			if err != nil {
				t.Fatal(err)
			}
			if got, _ := json.Marshal(out); string(got) != string(want) {
				t.Fatalf("reconcile %v: not the retained answer", reconcile)
			}
		}
		wantSent(t, root, key, 1)
	})
	t.Run("unanswered", func(t *testing.T) {
		root, g, c := actionKeysSetup(t)
		key := strings.Repeat("c", 64)
		actionKeysMode(t, root, "write", "drop")
		if _, err := scopedAct(g, c, "first", key, actionKeysWho, true, false); err != nil {
			t.Fatal(err)
		}
		actionKeysMode(t, root, "write", "respond")
		restarted := actionKeysService(t, root, actionKeysSources(t, root, os.Args[0]))
		for i, reconcile := range []bool{false, true} {
			out, err := scopedAct(restarted, c, fmt.Sprintf("takeover-%d", i), key, renewed, true, reconcile)
			if err != nil {
				t.Fatal(err)
			}
			if out["reconciliation"] == nil {
				t.Fatalf("reconcile %v: not a read-back: %v", reconcile, out)
			}
		}
		wantSent(t, root, key, 1)
	})
}

// H1: a reconcile of a key never seen closes it before it answers. Afterwards no
// request dispatches: not a late first request in the same scope, and not one in
// another, and the answer is the same again, after a restart too. Closing opens no
// session and mints nothing.
func TestReconcileClosesAKeyNeverSeen(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	key := strings.Repeat("d", 64)
	_, err := scopedAct(g, c, "closing", key, actionKeysWho, true, true)
	wantKeyRefusal(t, "the close", err, refusalKeyNotDispatched)
	if _, err := os.Lstat(filepath.Join(g.storeRoot, "receipts", "closing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a close left a session: %v", err)
	}
	check := func(g *gatewayService, round string) {
		t.Helper()
		_, err := scopedAct(g, c, round+"-late", key, actionKeysWho, true, false)
		wantKeyRefusal(t, "a late first request", err, refusalKeyClosed)
		_, err = scopedAct(g, c, round+"-unflagged", key, actionKeysWho, false, false)
		wantKeyRefusal(t, "a late unflagged request", err, refusalKeyClosed)
		_, err = scopedAct(g, c, round+"-again", key, actionKeysWho, true, true)
		wantKeyRefusal(t, "the close again", err, refusalKeyNotDispatched)
		for _, req := range []struct{ scoped, reconcile bool }{{true, false}, {true, true}, {false, false}} {
			_, err = scopedAct(g, c, round+"-other", key, anotherSubject, req.scoped, req.reconcile)
			wantKeyRefusal(t, "another subject", err, refusalKeyScopeConflict)
		}
		// The same content checks: this key names this content.
		_, err = scopedActOn(g, c, round+"-content", key, actionKeysWho, true, true, `{"ticket":"T-2"}`)
		if !strings.Contains(keyRefusal(err), "action-key-conflict") {
			t.Fatalf("other content: %v", err)
		}
		wantSent(t, root, key, 0)
		journalAbsent(t, g, g.actionNamespace(anotherSubject, key))
	}
	check(g, "before")
	check(actionKeysService(t, root, actionKeysSources(t, root, os.Args[0])), "after")
	if _, err := g.sealSession("read"); err != nil {
		t.Fatal(err)
	}
	if report, err := verifyWithRegistryAndRecords(g.storeRoot, g.regPath, g.authority, g.decisionRecords, g.publicKey); err != nil || !report.OK {
		t.Fatalf("the store does not verify after a close: %+v %v", report, err)
	}
}

// H1's third case: another subject reconciles before the first request arrives.
// The first request then finds the key taken and sends nothing.
func TestALateFirstRequestAfterAnotherSubjectsClose(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	key := strings.Repeat("e", 64)
	_, err := scopedAct(g, c, "closing", key, anotherSubject, true, true)
	wantKeyRefusal(t, "the close", err, refusalKeyNotDispatched)
	_, err = scopedAct(g, c, "late", key, actionKeysWho, true, false)
	wantKeyRefusal(t, "the late first request", err, refusalKeyScopeConflict)
	wantSent(t, root, key, 0)
	journalAbsent(t, g, g.actionNamespace(actionKeysWho, key))
}

// reconcile never dispatches, a freed attempt included, though any other request
// would take that attempt. It closes at the attempt it would have taken.
func TestReconcileNeverDispatchesAFreedAttempt(t *testing.T) {
	root, _, c := actionKeysSetup(t)
	key := strings.Repeat("9", 64)
	missing := actionKeysService(t, root, actionKeysSources(t, root, filepath.Join(root, "not-installed", "adapter-mcp")))
	_, err := scopedAct(missing, c, "missing", key, actionKeysWho, true, false)
	if !strings.Contains(keyRefusal(err), "action-not-dispatched") {
		t.Fatalf("a start failure: %v", err)
	}
	installed := actionKeysService(t, root, actionKeysSources(t, root, os.Args[0]))
	_, err = scopedAct(installed, c, "reconciling", key, actionKeysWho, true, true)
	wantKeyRefusal(t, "the close", err, refusalKeyNotDispatched)
	wantSent(t, root, key, 0)
	if installed.started.Load() != 0 {
		t.Fatalf("a reconciling request started %d programs", installed.started.Load())
	}
	raw, err := os.ReadFile(filepath.Join(installed.storeRoot, "actions", installed.actionNamespace(actionKeysWho, key), "dispatch-2.json"))
	if err != nil || !strings.Contains(string(raw), `"closed":true`) {
		t.Fatalf("attempt 2 is not the close: %s %v", raw, err)
	}
	_, err = scopedAct(installed, c, "retry", key, actionKeysWho, true, false)
	wantKeyRefusal(t, "a retry", err, refusalKeyClosed)
	wantSent(t, root, key, 0)
}

// A marker with no answer may have begun: a reconciling request reads back, and
// never closes over it or calls it not dispatched.
func TestReconcileDoesNotCloseOverAMarker(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	key := strings.Repeat("7", 64)
	actionKeysMode(t, root, "write", "drop")
	if _, err := scopedAct(g, c, "first", key, actionKeysWho, true, false); err != nil {
		t.Fatal(err)
	}
	wantSent(t, root, key, 1)
	// The marker with no answer and no record: a request that died after the program.
	entry := filepath.Join(g.storeRoot, "actions", g.actionNamespace(actionKeysWho, key))
	if err := os.Remove(filepath.Join(entry, "action.json")); err != nil {
		t.Fatal(err)
	}
	out, err := scopedAct(g, c, "reconciling", key, actionKeysWho, true, true)
	if err != nil || out["reconciliation"] == nil {
		t.Fatalf("a marker with no answer: %v %v", out, err)
	}
	wantSent(t, root, key, 1)
	raw, err := os.ReadFile(filepath.Join(entry, "dispatch-1.json"))
	if err != nil || string(raw) != `{"attempt":1}` {
		t.Fatalf("the marker: %s %v", raw, err)
	}
}

// H1's second change: a first scope with no reservation answers unknown, never not
// dispatched, whether a first request is on its way or an entry was removed: the
// index outlives compaction, and it is what stops the removal reading as absence.
func TestIndexWithNoReservationAnswersUnknown(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	key := strings.Repeat("6", 64)
	namespace := g.actionNamespace(actionKeysWho, key)
	// A crash between the index and the reservation.
	j, err := openActionJournal(g.storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	if err = j.holdKeyIndex(g.actionFirstScope(actionKeysWho, key, namespace)); err != nil {
		t.Fatal(err)
	}
	_, err = scopedAct(g, c, "unknown", key, actionKeysWho, true, true)
	wantKeyRefusal(t, "index only", err, refusalKeyOutcomeUnknown)
	journalAbsent(t, g, namespace)
	// It does not refuse the key for good: the first request goes on, once.
	if _, err := scopedAct(g, c, "goes-on", key, actionKeysWho, true, false); err != nil {
		t.Fatal(err)
	}
	wantSent(t, root, key, 1)
	// An entry removed by hand: the record is what remembers.
	if err := os.RemoveAll(filepath.Join(g.storeRoot, "actions", namespace)); err != nil {
		t.Fatal(err)
	}
	_, err = scopedAct(g, c, "removed", key, actionKeysWho, true, true)
	wantKeyRefusal(t, "a removed entry", err, refusalKeyOutcomeUnknown)
	journalAbsent(t, g, namespace)
	_, err = scopedAct(g, c, "removed-other", key, anotherSubject, true, false)
	wantKeyRefusal(t, "another subject after a removal", err, refusalKeyScopeConflict)
	wantSent(t, root, key, 1)
}

// #352 L5: what compaction leaves of an indexed entry, its intent and markers
// without action.json, reads as begun: read back, never sent. And the index lets
// an operator tell the entry is indexed, with no key in hand.
func TestCompactedIndexedEntryNeverSendsAgain(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	key := strings.Repeat("5", 64)
	namespace := g.actionNamespace(actionKeysWho, key)
	if _, err := scopedAct(g, c, "first", key, actionKeysWho, true, false); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(g.storeRoot, "actions", namespace, "action.json")); err != nil {
		t.Fatal(err)
	}
	for i, reconcile := range []bool{false, true} {
		out, err := scopedAct(g, c, fmt.Sprintf("after-%d", i), key, actionKeysWho, true, reconcile)
		if i == 0 && (err != nil || out["reconciliation"] == nil) {
			t.Fatalf("plain, after compaction: %v %v", out, err)
		}
		if keyRefusal(err) == refusalKeyNotDispatched {
			t.Fatalf("a compacted entry was called not dispatched (reconcile %v)", reconcile)
		}
	}
	wantSent(t, root, key, 1)
	files, err := filepath.Glob(filepath.Join(g.storeRoot, "actions", actionIndexDirectory, "*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("index files: %v %v", files, err)
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err = json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if record["reservation"] != namespace || record["key"] != key || record["authority"] != g.authority {
		t.Fatalf("the index record: %v", record)
	}
	if !strings.HasPrefix(string(raw), `{"authority":`) || bytes.Contains(raw, []byte("tokenDigest")) {
		t.Fatalf("the record is not canonical, or names a token: %s", raw)
	}
}

// A changed authority string finds the record and answers a conflict. It does not
// find nothing and answer that nothing was sent (H1, "absence is not proof"). A retry
// with the old citations is refused earlier, at the ladder: they verify under the old
// authority. So the request that reaches the key is one citing a read made since.
func TestChangedAuthorityDoesNotRecreateAbsence(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	key := strings.Repeat("4", 64)
	if _, err := scopedAct(g, c, "first", key, actionKeysWho, true, false); err != nil {
		t.Fatal(err)
	}
	renamed := actionKeysService(t, root, actionKeysSources(t, root, os.Args[0]))
	renamed.authority = "gateway:renamed"
	_, err := scopedAct(renamed, c, "old-citations", key, actionKeysWho, true, true)
	if !strings.Contains(keyRefusal(err), "cites:") {
		t.Fatalf("the old citations: %v", err)
	}
	read, err := renamed.acquire("read-renamed", "screening", newObject(), actionKeysWho)
	if err != nil {
		t.Fatal(err)
	}
	signature := read["receipt"].(map[string]any)["signature"].(string)
	line := `{"kind":"evaluation","cites":[{"sessionId":"read-renamed","callIndex":0,"signature":"` + signature + `"}]}`
	if err = os.WriteFile(filepath.Join(renamed.decisionRecords, "decision-renamed.json"), []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	fresh := actionKeysCall{
		Decision: json.RawMessage(`{"recordDigest":"` + digestOf(line) + `","packDigest":"sha256:` + strings.Repeat("d", 64) + `"}`),
		Cites:    json.RawMessage(`[{"sessionId":"read-renamed","callIndex":0,"signature":"` + signature + `"}]`),
	}
	for i, req := range []struct{ reconcile bool }{{true}, {false}} {
		_, err = scopedAct(renamed, fresh, fmt.Sprintf("renamed-%d", i), key, actionKeysWho, true, req.reconcile)
		wantKeyRefusal(t, "a changed authority", err, refusalKeyScopeConflict)
	}
	wantSent(t, root, key, 1)
}

// An index record that does not read refuses every request on the key, and never
// grants: flagged or not, plain or reconciling.
func TestDamagedIndexRecordNeverGrants(t *testing.T) {
	key := strings.Repeat("3", 64)
	for name, damage := range map[string]func(t *testing.T, path, good string){
		"torn":   func(t *testing.T, path, good string) { writeIndexFile(t, path, good[:len(good)/2], 0600) },
		"empty":  func(t *testing.T, path, good string) { writeIndexFile(t, path, "", 0600) },
		"public": func(t *testing.T, path, good string) { writeIndexFile(t, path, good, 0644) },
		"a link": func(t *testing.T, path, good string) { os.Remove(path); os.Symlink("elsewhere", path) },
		"huge": func(t *testing.T, path, good string) {
			writeIndexFile(t, path, strings.Repeat(" ", actionIndexLimit+1), 0600)
		},
		"version": func(t *testing.T, path, good string) {
			writeIndexFile(t, path, strings.Replace(good, `"indexVersion":"1"`, `"indexVersion":"2"`, 1), 0600)
		},
		"another key": func(t *testing.T, path, good string) {
			writeIndexFile(t, path, strings.Replace(good, `"key":"`+key, `"key":"`+strings.Repeat("0", 64), 1), 0600)
		},
		"a member": func(t *testing.T, path, good string) {
			writeIndexFile(t, path, strings.Replace(good, `{"authority"`, `{"added":1,"authority"`, 1), 0600)
		},
	} {
		t.Run(name, func(t *testing.T) {
			root, g, c := actionKeysSetup(t)
			namespace := g.actionNamespace(actionKeysWho, key)
			first := g.actionFirstScope(actionKeysWho, key, namespace)
			j, err := openActionJournal(g.storeRoot)
			if err != nil {
				t.Fatal(err)
			}
			defer j.close()
			if err = j.holdKeyIndex(first); err != nil {
				t.Fatal(err)
			}
			damage(t, filepath.Join(g.storeRoot, "actions", actionIndexDirectory, first.file), string(first.record))
			for i, req := range []struct{ scoped, reconcile bool }{{true, false}, {false, false}, {true, true}} {
				_, err = scopedAct(g, c, fmt.Sprintf("s-%d", i), key, actionKeysWho, req.scoped, req.reconcile)
				if !strings.Contains(keyRefusal(err), "action-journal-invalid") {
					t.Fatalf("%+v: %v", req, err)
				}
			}
			wantSent(t, root, key, 0)
			journalAbsent(t, g, namespace)
		})
	}
}

// An index directory that is not private, or not a directory, is refused for every
// key, sending the members or not: it could say anything. It never reads as no index.
func TestUnsafeIndexDirectoryRefusesEveryKey(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	key := strings.Repeat("3", 64)
	j, err := openActionJournal(g.storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	if err = j.holdKeyIndex(g.actionFirstScope(actionKeysWho, key, g.actionNamespace(actionKeysWho, key))); err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(g.storeRoot, "actions", actionIndexDirectory)
	check := func(name string) {
		t.Helper()
		other := strings.Repeat("4", 64)
		for i, scoped := range []bool{false, true} {
			_, err := scopedAct(g, c, fmt.Sprintf("%s-%d", name, i), other, actionKeysWho, scoped, false)
			if !strings.Contains(keyRefusal(err), "action-journal-invalid") {
				t.Fatalf("%s, flag %v: %v", name, scoped, err)
			}
		}
		wantSent(t, root, other, 0)
		journalAbsent(t, g, g.actionNamespace(actionKeysWho, other))
	}
	if err := os.Chmod(index, 0755); err != nil {
		t.Fatal(err)
	}
	check("public")
	if err := os.Chmod(index, 0700); err != nil {
		t.Fatal(err)
	}
	moved := index + "-moved"
	if err := os.Rename(index, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, index); err != nil {
		t.Fatal(err)
	}
	check("a-link")
}

func writeIndexFile(t *testing.T, path, content string, perm os.FileMode) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		t.Fatal(err)
	}
}

// What a closed marker is, read on its own: the close wins over whatever stands
// beside it, a partial or misnumbered one is no close and counts as begun, and a
// dispatch of that attempt is refused as closed, not as claimed.
func TestActionJournalClosedMarkers(t *testing.T) {
	if !actionJournalSupported {
		t.Skip("durable keyed dispatch is explicitly unsupported")
	}
	key, fingerprint := strings.Repeat("1", 64), strings.Repeat("2", 64)
	setup := func(t *testing.T) (*actionClaim, string) {
		t.Helper()
		dir := t.TempDir()
		j, err := openActionJournal(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(j.close)
		c, err := j.reserve(key, actionIdentity{fingerprint: fingerprint})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.close)
		return c, filepath.Join(dir, "actions", key)
	}
	t.Run("close", func(t *testing.T) {
		c, entry := setup(t)
		if err := c.closeDispatch(1); err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.attempt(); !errors.Is(err, errActionKeyClosed) {
			t.Fatalf("attempt: %v", err)
		}
		if err := c.claimDispatch(1); !errors.Is(err, errActionKeyClosed) {
			t.Fatalf("a dispatch of the closed attempt: %v", err)
		}
		if err := c.closeDispatch(1); !errors.Is(err, errActionKeyClosed) {
			t.Fatalf("a second close: %v", err)
		}
		// An answer beside a close frees nothing: only a dispatch is answered.
		if err := os.WriteFile(filepath.Join(entry, "not-dispatched-1.json"), []byte(`{"attempt":1,"reason":"x"}`), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.attempt(); !errors.Is(err, errActionKeyClosed) {
			t.Fatalf("an answer freed a close: %v", err)
		}
		if info, err := os.Stat(filepath.Join(entry, "dispatch-1.json")); err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("the close's mode: %v %v", info, err)
		}
	})
	t.Run("a dispatch first", func(t *testing.T) {
		c, _ := setup(t)
		if err := c.claimDispatch(1); err != nil {
			t.Fatal(err)
		}
		if err := c.closeDispatch(1); !errors.Is(err, errActionDispatchClaimed) {
			t.Fatalf("a close over a marker: %v", err)
		}
		if n, begun, err := c.attempt(); n != 1 || !begun || err != nil {
			t.Fatalf("attempt: %d %v %v", n, begun, err)
		}
	})
	for name, raw := range map[string]string{
		"partial":     `{"attempt":1,"clo`,
		"misnumbered": `{"attempt":2,"closed":true}`,
		"not closed":  `{"attempt":1,"closed":false}`,
		"a string":    `{"attempt":1,"closed":"true"}`,
		"no attempt":  `{"closed":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			c, entry := setup(t)
			if err := os.WriteFile(filepath.Join(entry, "dispatch-1.json"), []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			if n, begun, err := c.attempt(); n != 1 || !begun || err != nil {
				t.Fatalf("attempt: %d %v %v", n, begun, err)
			}
			if err := c.claimDispatch(1); !errors.Is(err, errActionDispatchClaimed) {
				t.Fatalf("a dispatch: %v", err)
			}
		})
	}
}

// #352 L4: an entry and a record appear whole or not at all. A sync that fails while
// one is being made leaves nothing at its name, so the next request is not refused
// for good, where a directory made first and filled after would have been.
func TestActionJournalPublishesWholeOrNotAtAll(t *testing.T) {
	if !actionJournalSupported {
		t.Skip("durable keyed dispatch is explicitly unsupported")
	}
	key, fingerprint := strings.Repeat("1", 64), strings.Repeat("2", 64)
	scope := newObject()
	scope.set("rootActor", vString("a"))
	publishes := map[string]func(j *actionJournal) error{
		"a reservation": func(j *actionJournal) error {
			c, err := j.reserve(key, actionIdentity{fingerprint: fingerprint})
			if err == nil {
				c.close()
			}
			return err
		},
		"a subject record": func(j *actionJournal) error { return j.holdSubjectKey(key, scope) },
		"a closed entry": func(j *actionJournal) error {
			return j.reserveClosed(key, actionIdentity{fingerprint: fingerprint}, nil)
		},
	}
	for name, publish := range publishes {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			j, err := openActionJournal(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer j.close()
			saved := syncActionFile
			defer func() { syncActionFile = saved }()
			seen := false
			syncActionFile = func(f *os.File) error {
				if info, err := f.Stat(); err == nil && info.Mode().IsRegular() {
					seen = true
					// The name is not there while the bytes are being made durable.
					if _, err := os.Lstat(filepath.Join(dir, "actions", key)); !errors.Is(err, os.ErrNotExist) {
						t.Errorf("the entry is visible before its bytes are durable: %v", err)
					}
					return errors.New("injected sync failure")
				}
				return f.Sync()
			}
			if err := publish(j); err == nil {
				t.Fatal("published through a failed sync")
			}
			if !seen {
				t.Fatal("no record was synced")
			}
			syncActionFile = saved
			if _, err := os.Lstat(filepath.Join(dir, "actions", key)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a failed publish left its entry: %v", err)
			}
			if err := publish(j); err != nil {
				t.Fatalf("refused after a failed publish: %v", err)
			}
			entries, err := os.ReadDir(filepath.Join(dir, "actions"))
			if err != nil || len(entries) != 1 {
				t.Fatalf("left behind: %v %v", entries, err)
			}
		})
	}
	t.Run("an action record", func(t *testing.T) {
		dir := t.TempDir()
		j, err := openActionJournal(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer j.close()
		c, err := j.reserve(key, actionIdentity{fingerprint: fingerprint})
		if err != nil {
			t.Fatal(err)
		}
		defer c.close()
		saved := syncActionFile
		defer func() { syncActionFile = saved }()
		syncActionFile = func(f *os.File) error {
			if info, err := f.Stat(); err == nil && info.Mode().IsRegular() {
				if _, err := c.read("action.json", 1024); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("the record is visible before its bytes are durable: %v", err)
				}
				return errors.New("injected sync failure")
			}
			return f.Sync()
		}
		if err := c.publish("action.json", []byte(`{"a":1}`), 1024); err == nil {
			t.Fatal("published through a failed sync")
		}
		syncActionFile = saved
		if err := c.publish("action.json", []byte(`{"a":1}`), 1024); err != nil {
			t.Fatal(err)
		}
		if err := c.publish("action.json", []byte(`{"a":2}`), 1024); !errors.Is(err, errActionRecordExists) {
			t.Fatalf("a record was overwritten: %v", err)
		}
		raw, err := c.read("action.json", 1024)
		if err != nil || string(raw) != `{"a":1}` {
			t.Fatalf("%s %v", raw, err)
		}
		entries, err := os.ReadDir(filepath.Join(dir, "actions", key))
		if err != nil || len(entries) != 2 {
			t.Fatalf("left behind: %v %v", entries, err)
		}
	})
}

// The order of durability, on a store with no index yet: a record's bytes before its
// name, a staged entry's whole directory before the rename, and each name's directory
// before anything relies on it. What a close rests on is all durable by its answer.
func TestActionKeyDurabilityOrder(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	key := strings.Repeat("a", 64)
	namespace := g.actionNamespace(actionKeysWho, key)
	var log []string
	saved := syncActionFile
	syncActionFile = func(f *os.File) error {
		log = append(log, filepath.Base(filepath.Clean(f.Name())))
		return f.Sync()
	}
	defer func() { syncActionFile = saved }()
	_, err := scopedAct(g, c, "closing", key, actionKeysWho, true, true)
	wantKeyRefusal(t, "the close", err, refusalKeyNotDispatched)
	first := g.actionFirstScope(actionKeysWho, key, namespace)
	last := func(name string) int {
		for i := len(log) - 1; i >= 0; i-- {
			if log[i] == name {
				return i
			}
		}
		return -1
	}
	firstAt := func(match func(string) bool) int {
		for i, name := range log {
			if match(name) {
				return i
			}
		}
		return -1
	}
	marker, stage := firstAt(func(s string) bool { return s == "dispatch-1.json" }), firstAt(func(s string) bool { return strings.HasPrefix(s, ".staging-") })
	entry, record, index, journal := last(namespace), last(first.file), last(actionIndexDirectory), last("actions")
	if marker < 0 || stage < marker {
		t.Fatalf("the entry's directory before its record: %v", log)
	}
	if entry < stage {
		t.Fatalf("the entry was not synced before its answer: %v", log)
	}
	if record < 0 || index < record {
		t.Fatalf("the first scope's name was not synced after its bytes: %v", log)
	}
	if journal < index {
		t.Fatalf("the name of the index directory was not synced after it was made: %v", log)
	}
	// A dispatch's first scope and entry precede its marker, and the marker's write.
	log = nil
	sent := strings.Repeat("b", 64)
	if _, err := scopedAct(g, c, "plain", sent, actionKeysWho, true, false); err != nil {
		t.Fatal(err)
	}
	wantSent(t, root, sent, 1)
	sentFirst := g.actionFirstScope(actionKeysWho, sent, g.actionNamespace(actionKeysWho, sent))
	at := func(name string) int {
		return firstAt(func(s string) bool { return s == name })
	}
	if a, b, m, r := at(sentFirst.file), at("intent.json"), at("dispatch-1.json"), at("action.json"); a < 0 || b < a || m < b || r < m {
		t.Fatalf("the order of a dispatch: %v", log)
	}
	// A reservation's name is durable before its marker: lost, a power cut after the write
	// forgets the key, and a retry sends again.
	named := false
	for _, name := range log[at("intent.json"):at("dispatch-1.json")] {
		named = named || name == "actions"
	}
	if !named {
		t.Fatalf("the reservation's name was not synced before its dispatch marker: %v", log)
	}
	// An action record's name is synced after it is linked.
	if end := last(g.actionNamespace(actionKeysWho, sent)); end < at("action.json") {
		t.Fatalf("the action record's name was not synced after its bytes: %v", log)
	}
}

// A request that finds its reservation writes nothing, as it never did: no record is
// staged or synced for it. And a link at an entry's name stays a refusal an operator
// can read as damage, not a failure to write.
func TestAnEntryFoundWritesNothing(t *testing.T) {
	if !actionJournalSupported {
		t.Skip("durable keyed dispatch is explicitly unsupported")
	}
	dir := t.TempDir()
	j, err := openActionJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	key, identity := strings.Repeat("1", 64), actionIdentity{fingerprint: strings.Repeat("2", 64)}
	first, err := j.reserve(key, identity)
	if err != nil {
		t.Fatal(err)
	}
	first.close()
	scope := newObject()
	scope.set("rootActor", vString("a"))
	subject := strings.Repeat("3", 64)
	if err := j.holdSubjectKey(subject, scope); err != nil {
		t.Fatal(err)
	}
	var log actionSyncLog
	log.install(t)
	again, err := j.reserve(key, identity)
	if err != nil {
		t.Fatal(err)
	}
	defer again.close()
	if again.fresh {
		t.Fatal("an entry found counted as fresh")
	}
	if err := j.holdSubjectKey(subject, scope); err != nil {
		t.Fatal(err)
	}
	for _, name := range log.names {
		if name == "intent.json" || name == "scope.json" || strings.HasPrefix(name, ".staging-") {
			t.Fatalf("a request that found its entry wrote: %v", log.names)
		}
	}
	linked := strings.Repeat("4", 64)
	if err := os.Symlink("absent", filepath.Join(dir, "actions", linked)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.reserve(linked, identity); err == nil || !strings.Contains(err.Error(), "action-journal-invalid") {
		t.Fatalf("a link at an entry's name: %v", err)
	}
}

// A not-dispatched answer follows its durability: with any one sync failed, on either
// way to a close, the answer is not given. Nothing is lost: the next request closes
// or finds the close. A close another request made, found visible, is synced too,
// since its maker may have died before its sync.
func TestNotDispatchedFollowsDurability(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	missing := actionKeysService(t, root, actionKeysSources(t, root, filepath.Join(root, "not-installed", "adapter-mcp")))
	count := func(do func()) int {
		saved := syncActionFile
		defer func() { syncActionFile = saved }()
		total := 0
		syncActionFile = func(f *os.File) error { total++; return f.Sync() }
		do()
		return total
	}
	freed := func(key string) {
		t.Helper()
		if _, err := scopedAct(missing, c, "seed", key, actionKeysWho, true, false); !strings.Contains(keyRefusal(err), "action-not-dispatched") {
			t.Fatalf("seed: %v", err)
		}
	}
	paths := map[string]func(key string){
		"never seen":      func(string) {},
		"a freed attempt": freed,
		"found closed":    func(key string) { closeForTest(t, g, c, key) },
	}
	n := 0
	for name, seed := range paths {
		t.Run(name, func(t *testing.T) {
			n++
			probe := fmt.Sprintf("%063x%x", n, 1)
			seed(probe)
			total := count(func() {
				_, err := scopedAct(g, c, "count", probe, actionKeysWho, true, true)
				wantKeyRefusal(t, "the count", err, refusalKeyNotDispatched)
			})
			for failAt := 1; failAt <= total; failAt++ {
				key := fmt.Sprintf("%060x%04x", n, failAt)
				seed(key)
				saved := syncActionFile
				calls := 0
				syncActionFile = func(f *os.File) error {
					if calls++; calls == failAt {
						return errors.New("injected sync failure")
					}
					return f.Sync()
				}
				_, err := scopedAct(g, c, "failing", key, actionKeysWho, true, true)
				syncActionFile = saved
				if err == nil || keyRefusal(err) == refusalKeyNotDispatched {
					t.Fatalf("answered through failed sync %d of %d: %v", failAt, total, err)
				}
				_, err = scopedAct(g, c, "healed", key, actionKeysWho, true, true)
				wantKeyRefusal(t, "after the failure", err, refusalKeyNotDispatched)
			}
			wantSent(t, root, probe, 0)
		})
	}
	// The found close: the entry and the index are both synced before the answer.
	key := strings.Repeat("8", 64)
	closeForTest(t, g, c, key)
	var log actionSyncLog
	log.install(t)
	_, err := scopedAct(g, c, "found", key, actionKeysWho, true, true)
	wantKeyRefusal(t, "a found close", err, refusalKeyNotDispatched)
	for name, path := range map[string]string{
		"the entry":             filepath.Join(g.storeRoot, "actions", g.actionNamespace(actionKeysWho, key)),
		"the index":             filepath.Join(g.storeRoot, "actions", actionIndexDirectory),
		"the journal directory": filepath.Join(g.storeRoot, "actions"),
	} {
		if log.position(t, path, 0) < 0 {
			t.Fatalf("%s was not synced before the answer", name)
		}
	}
	// A plain flagged request makes a found first scope durable likewise: its
	// publisher may have died before syncing it.
	sent := strings.Repeat("2", 64)
	closeless := g.actionFirstScope(actionKeysWho, sent, g.actionNamespace(actionKeysWho, sent))
	j, err := openActionJournal(g.storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	if err = j.holdKeyIndex(closeless); err != nil {
		t.Fatal(err)
	}
	var again actionSyncLog
	again.install(t)
	if _, err := scopedAct(g, c, "plain", sent, actionKeysWho, true, false); err != nil {
		t.Fatal(err)
	}
	if again.position(t, filepath.Join(g.storeRoot, "actions", actionIndexDirectory), 0) < 0 {
		t.Fatal("the found first scope was not synced before dispatch")
	}
}

func closeForTest(t *testing.T, g *gatewayService, c actionKeysCall, key string) {
	t.Helper()
	_, err := scopedAct(g, c, "closing", key, actionKeysWho, true, true)
	wantKeyRefusal(t, "the close", err, refusalKeyNotDispatched)
}

// delegatedScopeOf is the caller naming the harness's run's scope under a root actor.
func delegatedScopeOf(subject, rootActor string) *caller {
	return &caller{delegated: &delegatedSender{scope: reservationScope{sub: principalRef{"person", testIssuerURL, subject}, rootActor: rootActor, host: "desk"}}}
}

// H1(a), the false answer. A delegated reservation has a first scope, so an entry removed
// by hand reads as what it is: a key seen and no longer held. It is never called not
// dispatched, for a write that answered or one that did not.
func TestDelegatedEntryRemovedAnswersUnknown(t *testing.T) {
	for _, write := range []string{"respond", "drop"} {
		t.Run(write, func(t *testing.T) {
			h := newDelegationHarness(t, false)
			actor := h.credential(t, statement(t, nil))
			key := delegationKey(1)
			actionKeysMode(t, h.root, "write", write)
			if status, out := h.present(t, "/act", h.actBody("first", key, ""), actor); status != http.StatusOK || h.sent(key) != 1 {
				t.Fatalf("first: %d %v, sent %d", status, out, h.sent(key))
			}
			actionKeysMode(t, h.root, "write", "respond")
			namespace := h.g.actionNamespace(delegatedScopeOf(testSubjectSub, rootAgent), key)
			if err := os.Rename(filepath.Join(h.g.storeRoot, "actions", namespace), filepath.Join(h.root, "archived")); err != nil {
				t.Fatal(err)
			}
			for i := range 2 {
				status, out := h.present(t, "/act", h.actBody(fmt.Sprintf("after-%d", i), key, withReconcile), actor)
				if status != http.StatusConflict || refusalOf(out) != refusalKeyOutcomeUnknown {
					t.Fatalf("a delegated reconcile with its entry gone: %d %v", status, out)
				}
			}
			journalAbsent(t, h.g, namespace)
			if h.sent(key) != 1 {
				t.Fatalf("sent %d", h.sent(key))
			}
		})
	}
}

// H1(b), the second mutation. A first scope stops another root actor whether or not the
// subject entry is there, plain or reconciling.
func TestRemovingASubjectEntryAllowsNoSecondMutation(t *testing.T) {
	h := newDelegationHarness(t, false)
	actor := h.credential(t, statement(t, nil))
	other := h.credential(t, statement(t, map[string]any{"id": strings.Repeat("66", 16), "act": map[string]any{"agent": otherAgent, "software": testSoftware}}))
	key := delegationKey(2)
	if status, out := h.present(t, "/act", h.actBody("first", key, ""), actor); status != http.StatusOK {
		t.Fatalf("first: %d %v", status, out)
	}
	subjectEntry := h.g.actionSubjectNamespace(delegatedScopeOf(testSubjectSub, rootAgent).delegated, key)
	if err := os.Rename(filepath.Join(h.g.storeRoot, "actions", subjectEntry), filepath.Join(h.root, "archived")); err != nil {
		t.Fatal(err)
	}
	for i, extra := range []string{"", withReconcile} {
		status, out := h.present(t, "/act", h.actBody(fmt.Sprintf("other-%d", i), key, extra), other)
		if status != http.StatusForbidden || refusalOf(out) != refusalKeyScopeConflict {
			t.Fatalf("another root actor, its subject entry gone: %d %v", status, out)
		}
	}
	journalAbsent(t, h.g, h.g.actionNamespace(delegatedScopeOf(testSubjectSub, otherAgent), key))
	if h.sent(key) != 1 {
		t.Fatalf("sent %d", h.sent(key))
	}
}

// The other way round: with the first-scope record lost (a partial restore), the subject
// record still holds the key against another root actor of that subject, so nothing
// closes over a reservation that exists. It is why the subject entry stays.
func TestSubjectRecordHoldsWhenTheFirstScopeIsLost(t *testing.T) {
	h := newDelegationHarness(t, false)
	actor := h.credential(t, statement(t, nil))
	other := h.credential(t, statement(t, map[string]any{"id": strings.Repeat("66", 16), "act": map[string]any{"agent": otherAgent, "software": testSoftware}}))
	key := delegationKey(3)
	if status, out := h.present(t, "/act", h.actBody("first", key, ""), actor); status != http.StatusOK {
		t.Fatalf("first: %d %v", status, out)
	}
	scope := delegatedScopeOf(testSubjectSub, rootAgent)
	record := h.g.actionFirstScope(scope, key, h.g.actionNamespace(scope, key))
	if err := os.Remove(filepath.Join(h.g.storeRoot, "actions", actionIndexDirectory, record.file)); err != nil {
		t.Fatal(err)
	}
	for i, extra := range []string{withReconcile, ""} {
		status, out := h.present(t, "/act", h.actBody(fmt.Sprintf("other-%d", i), key, extra), other)
		if status != http.StatusForbidden || refusalOf(out) != refusalKeyScopeConflict {
			t.Fatalf("another root actor, the first scope lost: %d %v", status, out)
		}
	}
	if h.sent(key) != 1 {
		t.Fatalf("sent %d", h.sent(key))
	}
}

// H1(c), the key taken from the run's own actor. Another subject holding the key is
// refused plain and reconciling, reserves nothing, and every sender of §11.8's table
// keeps its answer afterwards. An undelegated request is another scope likewise.
func TestAnotherSubjectCannotTakeADelegatedKey(t *testing.T) {
	for _, write := range []string{"respond", "drop"} {
		t.Run(write, func(t *testing.T) {
			h := newDelegationHarness(t, false)
			actor := h.credential(t, statement(t, nil))
			key := delegationKey(4)
			actionKeysMode(t, h.root, "write", write)
			if status, out := h.present(t, "/act", h.actBody("first", key, ""), actor); status != http.StatusOK || h.sent(key) != 1 {
				t.Fatalf("first: %d %v, sent %d", status, out, h.sent(key))
			}
			actionKeysMode(t, h.root, "write", "respond")
			bearer := func(subject string) map[string]string {
				return map[string]string{"Authorization": "Bearer " + h.token(t, subject)}
			}
			elsewhere := h.credential(t, statement(t, map[string]any{"id": strings.Repeat("77", 16), "sub": map[string]any{"kind": "person", "issuer": testIssuerURL, "subject": "another-person"}}))
			for i, extra := range []string{withReconcile, ""} {
				status, out := h.present(t, "/act", h.actBody(fmt.Sprintf("elsewhere-%d", i), key, extra), elsewhere)
				if status != http.StatusForbidden || refusalOf(out) != refusalKeyScopeConflict {
					t.Fatalf("another subject %q: %d %v", extra, status, out)
				}
			}
			for i, extra := range []string{withKeyScope + withReconcile, withKeyScope, ""} {
				status, out := h.post(t, "/act", h.actBody(fmt.Sprintf("token-%d", i), key, extra), bearer("alice"))
				if status != http.StatusForbidden || refusalOf(out) != refusalKeyScopeConflict {
					t.Fatalf("an undelegated request %q: %d %v", extra, status, out)
				}
			}
			journalAbsent(t, h.g, h.g.actionNamespace(delegatedScopeOf("another-person", rootAgent), key))
			journalAbsent(t, h.g, h.g.actionNamespace(&caller{issuer: testIssuerURL, subject: "alice"}, key))
			answered := func(step string, status int, out map[string]any) {
				t.Helper()
				if status != http.StatusOK || (out["receipt"] == nil && out["reconciliation"] == nil) {
					t.Fatalf("%s: %d %v", step, status, out)
				}
			}
			status, out := h.present(t, "/act", h.actBody("actor-again", key, withReconcile), actor)
			answered("the run's actor", status, out)
			reservation := h.reservationOf(testSub(), rootAgent)
			for i, subject := range []string{testSubjectSub, hostRequester, testOperator} {
				status, out := h.post(t, "/act", h.actBody(fmt.Sprintf("table-%d", i), key, reservation+withReconcile), bearer(subject))
				answered(subject, status, out)
			}
			if h.sent(key) != 1 {
				t.Fatalf("sent %d", h.sent(key))
			}
		})
	}
}

// A leaf that does not name the write takes nothing on its way to a refused admission:
// no first scope and no subject record, so it cannot deny the key to anyone.
func TestALeafNotNamingTheWriteTakesNoFirstScope(t *testing.T) {
	h := newDelegationHarness(t, false)
	root := statement(t, nil)
	narrow := h.credential(t, root, childOf(t, root, map[string]any{"act": map[string]any{"agent": rootAgent, "software": testSoftware}}))
	key := delegationKey(5)
	if status, out := h.present(t, "/act", h.actBody("narrow", key, ""), narrow); status == http.StatusOK || refusalOf(out) == refusalKeyScopeConflict {
		t.Fatalf("a leaf not naming the write: %d %v", status, out)
	}
	scope := delegatedScopeOf(testSubjectSub, rootAgent)
	record := h.g.actionFirstScope(scope, key, h.g.actionNamespace(scope, key))
	journalAbsent(t, h.g, filepath.Join(actionIndexDirectory, record.file))
	journalAbsent(t, h.g, h.g.actionSubjectNamespace(scope.delegated, key))
	other := h.credential(t, statement(t, map[string]any{"id": strings.Repeat("66", 16), "act": map[string]any{"agent": otherAgent, "software": testSoftware}}))
	if status, out := h.present(t, "/act", h.actBody("other", key, ""), other); status != http.StatusOK || h.sent(key) != 1 {
		t.Fatalf("another root actor after it: %d %v, sent %d", status, out, h.sent(key))
	}
}

// H2, over real HTTP. Subject A sends neither member. Subject B, holding the key, sends
// both. B's first scope takes nothing A holds: A keeps its retained answer, its salts and
// its read-back, however A asks, for a write that answered and one that did not.
func TestAFirstScopeTakesNothingAScopeHoldsOverHTTP(t *testing.T) {
	for _, tc := range []struct{ name, write string }{{"answered", "respond"}, {"dropped", "drop"}} {
		t.Run(tc.name, func(t *testing.T) {
			h := newDelegationHarness(t, false)
			key := delegationKey(6)
			bearer := func(subject string) map[string]string {
				return map[string]string{"Authorization": "Bearer " + h.token(t, subject)}
			}
			actionKeysMode(t, h.root, "write", tc.write)
			status, first := h.post(t, "/act", h.actBody("a1", key, ""), bearer("alice"))
			if status != http.StatusOK || h.sent(key) != 1 {
				t.Fatalf("A first: %d %v, sent %d", status, first, h.sent(key))
			}
			actionKeysMode(t, h.root, "write", "respond")
			status, before := h.post(t, "/act", h.actBody("a2", key, ""), bearer("alice"))
			if status != http.StatusOK {
				t.Fatalf("A before the plant: %d %v", status, before)
			}
			// B has reserved nothing and holds the key: it takes the first scope. Its own answer
			// speaks for what it can see, which is the Known limit, and it sends nothing.
			status, planted := h.post(t, "/act", h.actBody("b1", key, withKeyScope+withReconcile), bearer("bob"))
			if status != http.StatusConflict || refusalOf(planted) != refusalKeyNotDispatched || h.sent(key) != 1 {
				t.Fatalf("B: %d %v, sent %d", status, planted, h.sent(key))
			}
			for i, extra := range []string{"", withKeyScope, withKeyScope + withReconcile} {
				status, after := h.post(t, "/act", h.actBody(fmt.Sprintf("a-after-%d", i), key, extra), bearer("alice"))
				if status != http.StatusOK {
					t.Fatalf("A after the plant, %q: %d %v", extra, status, after)
				}
				if tc.write == "respond" {
					if keyTestJSON(t, after) != keyTestJSON(t, first) {
						t.Fatalf("A after the plant, %q: not its retained answer", extra)
					}
				} else if after["reconciliation"] == nil || after["action"] == nil {
					t.Fatalf("A after the plant, %q: no read-back: %v", extra, after)
				}
			}
			if h.sent(key) != 1 {
				t.Fatalf("sent %d", h.sent(key))
			}
		})
	}
}

// The other half of H2: under another's first scope a scope's request that would dispatch
// or close is refused, its journal left as it was. A marker with no answer still reads back:
// that is what the scope already holds, and it sends nothing.
func TestAScopeUnderAnothersFirstScopeNeverDispatchesOrCloses(t *testing.T) {
	filesOf := func(t *testing.T, entry string) string {
		t.Helper()
		list, err := os.ReadDir(entry)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, f := range list {
			names = append(names, f.Name())
		}
		return strings.Join(names, " ")
	}
	type setup func(t *testing.T, root, key string, c actionKeysCall)
	nothingBegun := func(t *testing.T, root, key string, c actionKeysCall) {
		t.Helper()
		var out bytes.Buffer
		cmd := actionScopeChild(root, "seed", key, "ACTION_SCOPE_KILL=before-admit")
		cmd.Stdout, cmd.Stderr = &out, &out
		cmd.Run()
		if _, lived := childOutcome(out.String()); lived {
			t.Fatalf("the seed did not die:\n%s", out.String())
		}
	}
	freed := func(t *testing.T, root, key string, c actionKeysCall) {
		t.Helper()
		missing := actionKeysService(t, root, actionKeysSources(t, root, filepath.Join(root, "not-installed", "adapter-mcp")))
		if _, err := actionKeysAct(missing, c, "seed", key); !strings.Contains(keyRefusal(err), "action-not-dispatched") {
			t.Fatalf("seed: %v", err)
		}
	}
	for name, seed := range map[string]setup{"nothing begun": nothingBegun, "a freed attempt": freed} {
		t.Run(name, func(t *testing.T) {
			root, g, c := actionKeysSetup(t)
			key := strings.Repeat("a", 64)
			seed(t, root, key, c)
			entry := filepath.Join(g.storeRoot, "actions", g.actionNamespace(actionKeysWho, key))
			before := filesOf(t, entry)
			_, err := scopedAct(g, c, "b", key, anotherSubject, true, false)
			if err != nil {
				t.Fatalf("B's first request: %v", err)
			}
			wantSent(t, root, key, 1)
			for i, req := range []struct{ scoped, reconcile bool }{{false, false}, {true, false}, {true, true}} {
				_, err := scopedAct(g, c, fmt.Sprintf("a-%d", i), key, actionKeysWho, req.scoped, req.reconcile)
				wantKeyRefusal(t, fmt.Sprintf("A %+v", req), err, refusalKeyScopeConflict)
				if got := filesOf(t, entry); got != before {
					t.Fatalf("A %+v changed its entry: %q, was %q", req, got, before)
				}
			}
			wantSent(t, root, key, 1)
		})
	}
	t.Run("a marker with no answer", func(t *testing.T) {
		root, g, c := actionKeysSetup(t)
		key := strings.Repeat("a", 64)
		nothingBegun(t, root, key, c)
		entry := filepath.Join(g.storeRoot, "actions", g.actionNamespace(actionKeysWho, key))
		if err := os.WriteFile(filepath.Join(entry, "dispatch-1.json"), []byte(`{"attempt":1}`), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := scopedAct(g, c, "b", key, anotherSubject, true, true); keyRefusal(err) != refusalKeyNotDispatched {
			t.Fatalf("B: %v", err)
		}
		out, err := actionKeysAct(g, c, "a", key)
		if err != nil || out["reconciliation"] == nil {
			t.Fatalf("A's read-back: %v %v", out, err)
		}
		wantSent(t, root, key, 0)
	})
}

// M2. A reconcile that sends the member and is answered from evidence holds the first
// scope first: a first scope is held from the first request sending the member. So the
// second subject finds the key taken, where it would have sent again.
func TestAReconcileAnsweredFromEvidenceHoldsTheFirstScope(t *testing.T) {
	for _, write := range []string{"respond", "drop"} {
		t.Run(write, func(t *testing.T) {
			root, g, c := actionKeysSetup(t)
			key := strings.Repeat("b", 64)
			actionKeysMode(t, root, "write", write)
			if _, err := actionKeysAct(g, c, "first", key); err != nil {
				t.Fatal(err)
			}
			actionKeysMode(t, root, "write", "respond")
			journalAbsent(t, g, actionIndexDirectory)
			out, err := scopedAct(g, c, "reconcile", key, actionKeysWho, true, true)
			if err != nil || (out["receipt"] == nil && out["reconciliation"] == nil) {
				t.Fatalf("the reconcile: %v %v", out, err)
			}
			first := g.actionFirstScope(actionKeysWho, key, g.actionNamespace(actionKeysWho, key))
			if _, err := os.Stat(filepath.Join(g.storeRoot, "actions", actionIndexDirectory, first.file)); err != nil {
				t.Fatalf("no first scope after the reconcile: %v", err)
			}
			_, err = scopedAct(g, c, "other", key, anotherSubject, true, false)
			wantKeyRefusal(t, "another subject", err, refusalKeyScopeConflict)
			wantSent(t, root, key, 1)
		})
	}
}

// awaitPoint waits for a request to reach a named point of itself, and fails, rather than
// hanging, if it answers without ever getting there.
func awaitPoint(t *testing.T, what string, reached <-chan struct{}, answer <-chan string) {
	t.Helper()
	select {
	case <-reached:
	case got := <-answer:
		t.Fatalf("%s: the request answered %q without reaching that point", what, got)
	case <-time.After(30 * time.Second):
		t.Fatalf("%s: never reached", what)
	}
}

// A reconcile that goes to hold the first scope and finds another took it just now reads
// what its scope holds, and closes nothing: to close, it would say nothing was dispatched
// under a key another scope is sending.
func TestAReconcileThatLosesTheFirstScopeDoesNotClose(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	key := strings.Repeat("c", 64)
	var seed bytes.Buffer
	seedCmd := actionScopeChild(root, "seed", key, "ACTION_SCOPE_KILL=before-admit")
	seedCmd.Stdout, seedCmd.Stderr = &seed, &seed
	seedCmd.Run()
	reached, proceed := make(chan struct{}), make(chan struct{})
	g.actionStep = func(point string) {
		if point == "before-hold" {
			close(reached)
			<-proceed
		}
	}
	answer := make(chan string, 1)
	go func() {
		_, err := scopedAct(g, c, "a-reconcile", key, actionKeysWho, true, true)
		answer <- keyRefusal(err)
	}()
	awaitPoint(t, "A going to hold its first scope", reached, answer)
	other := actionKeysService(t, root, actionKeysSources(t, root, os.Args[0]))
	if _, err := scopedAct(other, c, "b-first", key, anotherSubject, true, false); err != nil {
		t.Fatal(err)
	}
	close(proceed)
	if got := <-answer; got != refusalKeyScopeConflict {
		t.Fatalf("A answered %q", got)
	}
	wantSent(t, root, key, 1)
	entry := filepath.Join(g.storeRoot, "actions", g.actionNamespace(actionKeysWho, key))
	if _, err := os.Lstat(filepath.Join(entry, "dispatch-1.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("A marked its entry: %v", err)
	}
}

// M4's R2. A close that finds another's first scope as it goes to record its own answers
// the conflict, not that nothing was dispatched: this is the branch that stops a false
// answer in the race. B has closed its own entry; A takes the first scope and dispatches.
func TestACloseThatLosesTheFirstScopeAnswersConflict(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	key := strings.Repeat("d", 64)
	reached, proceed := make(chan struct{}), make(chan struct{})
	g.actionStep = func(point string) {
		if point == "close-durable" {
			close(reached)
			<-proceed
		}
	}
	answer := make(chan string, 1)
	go func() {
		_, err := scopedAct(g, c, "b-close", key, anotherSubject, true, true)
		answer <- keyRefusal(err)
	}()
	awaitPoint(t, "B's close going to record its first scope", reached, answer)
	other := actionKeysService(t, root, actionKeysSources(t, root, os.Args[0]))
	if _, err := scopedAct(other, c, "a-first", key, actionKeysWho, true, false); err != nil {
		t.Fatal(err)
	}
	close(proceed)
	if got := <-answer; got != refusalKeyScopeConflict {
		t.Fatalf("B answered %q with the write at the target", got)
	}
	wantSent(t, root, key, 1)
}

// M4's R24, at the journal alone: another scope's record found by one going to hold it is a
// refusal, whether it is found before publishing or by losing the link.
func TestHoldKeyIndexRefusesAnothersRecord(t *testing.T) {
	_, g, _ := actionKeysSetup(t)
	key := strings.Repeat("e", 64)
	j, err := openActionJournal(g.storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	a := g.actionFirstScope(actionKeysWho, key, g.actionNamespace(actionKeysWho, key))
	b := g.actionFirstScope(anotherSubject, key, g.actionNamespace(anotherSubject, key))
	if err := j.holdKeyIndex(a); err != nil {
		t.Fatal(err)
	}
	if err := j.holdKeyIndex(b); !errors.Is(err, errActionKeyFirstScope) {
		t.Fatalf("another scope held the key: %v", err)
	}
	if err := j.holdKeyIndex(a); err != nil {
		t.Fatalf("its own record: %v", err)
	}
}

// M4's R14. A delegated reconcile whose close loses to a dispatch's marker is answered as
// any request finding that marker is: it is not admitted, and no call is counted for it.
func TestADelegatedCloseThatLosesIsNotCounted(t *testing.T) {
	h := newDelegationHarness(t, false)
	actor := h.credential(t, statement(t, nil))
	// A real dispatch's marker, to lay in another key's slot as if another process claimed it.
	donor := delegationKey(7)
	if status, out := h.present(t, "/act", h.actBody("donor", donor, ""), actor); status != http.StatusOK {
		t.Fatalf("donor: %d %v", status, out)
	}
	scope := delegatedScopeOf(testSubjectSub, rootAgent)
	marker, err := os.ReadFile(filepath.Join(h.g.storeRoot, "actions", h.g.actionNamespace(scope, donor), "dispatch-1.json"))
	if err != nil {
		t.Fatal(err)
	}
	key := delegationKey(8)
	entry := filepath.Join(h.g.storeRoot, "actions", h.g.actionNamespace(scope, key))
	// The reservation, with nothing begun: an admission refused it.
	h.host.setAnswer(func(b map[string]any) (int, string) {
		if c, ok := b["call"].(map[string]any); ok && c["source"] == "tickets/write" {
			return http.StatusOK, `{"admission":"refuse","refusal":"subject-unauthorized"}`
		}
		return http.StatusOK, `{"admission":"admit"}`
	})
	if status, out := h.present(t, "/act", h.actBody("refused", key, ""), actor); status != http.StatusForbidden {
		t.Fatalf("the refused dispatch: %d %v", status, out)
	}
	h.host.setAnswer(nil)
	h.g.actionStep = func(point string) {
		if point == "before-close" {
			if err := os.WriteFile(filepath.Join(entry, "dispatch-1.json"), marker, 0600); err != nil {
				t.Error(err)
			}
		}
	}
	counted := h.host.counted()
	status, out := h.present(t, "/act", h.actBody("reconciling", key, withReconcile), actor)
	h.g.actionStep = nil
	if refusalOf(out) == refusalKeyNotDispatched {
		t.Fatalf("a close that lost said nothing was dispatched: %d %v", status, out)
	}
	if h.host.counted() != counted {
		t.Fatalf("a reconcile that lost its close was counted: %d, was %d", h.host.counted(), counted)
	}
	if h.sent(key) != 0 {
		t.Fatalf("sent %d", h.sent(key))
	}
}

// M1's documented way out. The gateway never closes at a first scope with no reservation.
// An operator who has checked the target may archive the record, and the next reconcile is
// then the first this key has seen: it closes. The record stays, for one who cannot tell.
func TestOutcomeUnknownOperatorPath(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	key := strings.Repeat("f", 64)
	namespace := g.actionNamespace(actionKeysWho, key)
	first := g.actionFirstScope(actionKeysWho, key, namespace)
	saved := syncActionFile
	syncActionFile = func(f *os.File) error {
		if filepath.Base(f.Name()) == "intent.json" {
			return errors.New("injected: no space left on device")
		}
		return f.Sync()
	}
	_, err := scopedAct(g, c, "refused", key, actionKeysWho, true, false)
	syncActionFile = saved
	if err == nil {
		t.Fatal("a first request through a failed journal write")
	}
	wantSent(t, root, key, 0)
	restarted := actionKeysService(t, root, actionKeysSources(t, root, os.Args[0]))
	for i := range 2 {
		_, err = scopedAct(restarted, c, fmt.Sprintf("unknown-%d", i), key, actionKeysWho, true, true)
		wantKeyRefusal(t, "a reconcile", err, refusalKeyOutcomeUnknown)
	}
	journalAbsent(t, restarted, namespace)
	// The record names the key and the entry that is not there, so the operator can find both.
	record := filepath.Join(g.storeRoot, "actions", actionIndexDirectory, first.file)
	raw, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	var named map[string]any
	if err := json.Unmarshal(raw, &named); err != nil || named["key"] != key || named["reservation"] != namespace {
		t.Fatalf("the record: %s %v", raw, err)
	}
	// The target was checked, nothing is in flight: the record goes to the archive.
	if err := os.Rename(record, filepath.Join(root, "archived-record.json")); err != nil {
		t.Fatal(err)
	}
	after := actionKeysService(t, root, actionKeysSources(t, root, os.Args[0]))
	_, err = scopedAct(after, c, "closing", key, actionKeysWho, true, true)
	wantKeyRefusal(t, "the close", err, refusalKeyNotDispatched)
	_, err = scopedAct(after, c, "plain", key, actionKeysWho, true, false)
	wantKeyRefusal(t, "a plain request", err, refusalKeyClosed)
	wantSent(t, root, key, 0)
}

// L5. A marker above a free attempt is damage: no crash leaves it, and it says a dispatch
// may have begun. A reconcile does not close under it or say nothing was dispatched. And a
// close whose lower marker was lost stays a close.
func TestALostLowerMarkerIsNotAbsence(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	seedEntry := func(key string) string {
		t.Helper()
		var out bytes.Buffer
		cmd := actionScopeChild(root, "seed", key, childFlagged, "ACTION_SCOPE_KILL=before-admit")
		cmd.Stdout, cmd.Stderr = &out, &out
		cmd.Run()
		return filepath.Join(g.storeRoot, "actions", g.actionNamespace(actionKeysWho, key))
	}
	key := strings.Repeat("a", 64)
	entry := seedEntry(key)
	if err := os.WriteFile(filepath.Join(entry, "dispatch-2.json"), []byte(`{"attempt":2}`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := scopedAct(g, c, "reconciling", key, actionKeysWho, true, true)
	if keyRefusal(err) == refusalKeyNotDispatched {
		t.Fatal("a reconcile closed under a higher marker")
	}
	if _, err := os.Lstat(filepath.Join(entry, "dispatch-1.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a marker was made at attempt 1: %v", err)
	}
	wantSent(t, root, key, 0)
	// The re-read's N6: not only the next attempt up. One further still is the same damage.
	further := strings.Repeat("d", 64)
	entry = seedEntry(further)
	if err := os.WriteFile(filepath.Join(entry, "dispatch-4.json"), []byte(`{"attempt":4}`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = scopedAct(g, c, "reconciling-further", further, actionKeysWho, true, true)
	if keyRefusal(err) == refusalKeyNotDispatched {
		t.Fatal("a reconcile closed under a marker further up")
	}
	wantSent(t, root, further, 0)
	closedAbove := strings.Repeat("b", 64)
	entry = seedEntry(closedAbove)
	if err := os.WriteFile(filepath.Join(entry, "dispatch-3.json"), []byte(`{"attempt":3,"closed":true,"closedAt":"2026-11-02T00:00:00Z"}`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = scopedAct(g, c, "plain", closedAbove, actionKeysWho, true, false)
	wantKeyRefusal(t, "a plain request", err, refusalKeyClosed)
	_, err = scopedAct(g, c, "reconcile", closedAbove, actionKeysWho, true, true)
	wantKeyRefusal(t, "a reconcile", err, refusalKeyNotDispatched)
	wantSent(t, root, closedAbove, 0)
}

// L6. action-key-closed says the close stands, so the close is synced before it is said:
// its maker may have died first. A failure of that sync is not the answer.
func TestActionKeyClosedFollowsItsDurability(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	key := strings.Repeat("c", 64)
	closeForTest(t, g, c, key)
	entry := filepath.Join(g.storeRoot, "actions", g.actionNamespace(actionKeysWho, key))
	var log actionSyncLog
	log.install(t)
	_, err := scopedAct(g, c, "plain", key, actionKeysWho, true, false)
	wantKeyRefusal(t, "a plain request", err, refusalKeyClosed)
	if log.position(t, entry, 0) < 0 {
		t.Fatal("the close was not synced before action-key-closed")
	}
	log.fail = entry
	_, err = scopedAct(g, c, "failing", key, actionKeysWho, true, false)
	if keyRefusal(err) == refusalKeyClosed {
		t.Fatal("action-key-closed through a failed sync")
	}
	wantSent(t, root, key, 0)
}

// The re-read's R-M1. A leaf that does not name the write's source and tool, first on a
// key and with other content, is refused as its admission would and leaves nothing: no
// reservation bound to its content, no record, no session, and no call counted. So the run's
// actor and a re-issued delegation still have their key.
func TestALeafNotNamingTheWriteCannotDenyTheRunsKey(t *testing.T) {
	h := newDelegationHarness(t, false)
	root := statement(t, nil)
	actor := h.credential(t, root)
	narrow := h.credential(t, root, childOf(t, root, map[string]any{"act": map[string]any{"agent": rootAgent, "software": testSoftware}}))
	key := delegationKey(10)
	counted := h.host.counted()
	body := strings.Replace(h.actBody("narrow", key, ""), `{"ticket":"T-1"}`, `{"ticket":"OTHER"}`, 1)
	status, out := h.present(t, "/act", body, narrow)
	if status != http.StatusForbidden || refusalOf(out) != refusalOutOfScope || out["reason"] != "source" || out["refusedAt"] != "delegation" {
		t.Fatalf("a leaf not naming the write, other content: %d %v", status, out)
	}
	if h.host.counted() != counted {
		t.Fatal("a refused leaf was counted as a call")
	}
	scope := delegatedScopeOf(testSubjectSub, rootAgent)
	record := h.g.actionFirstScope(scope, key, h.g.actionNamespace(scope, key))
	journalAbsent(t, h.g, h.g.actionNamespace(scope, key))
	journalAbsent(t, h.g, h.g.actionSubjectNamespace(scope.delegated, key))
	journalAbsent(t, h.g, filepath.Join(actionIndexDirectory, record.file))
	if _, err := os.Lstat(filepath.Join(h.g.storeRoot, "receipts", "narrow")); !os.IsNotExist(err) {
		t.Fatalf("a refused leaf left a session: %v", err)
	}
	if status, out := h.present(t, "/act", h.actBody("actor", key, ""), actor); status != http.StatusOK || out["receipt"] == nil || h.sent(key) != 1 {
		t.Fatalf("the run's actor after it: %d %v, sent %d", status, out, h.sent(key))
	}
	reissued := h.credential(t, statement(t, map[string]any{"id": strings.Repeat("55", 16), "issuedAt": "2026-10-30T00:30:00.000Z"}))
	if status, out := h.present(t, "/act", h.actBody("reissued", key, withReconcile), reissued); status != http.StatusOK || out["receipt"] == nil || h.sent(key) != 1 {
		t.Fatalf("a re-issued delegation after it: %d %v, sent %d", status, out, h.sent(key))
	}
	// As its admission would, in the admission's order: the host's refusal comes first.
	h.host.setAnswer(func(b map[string]any) (int, string) {
		return http.StatusOK, `{"admission":"refuse","refusal":"revoked"}`
	})
	status, out = h.present(t, "/act", h.actBody("narrow-revoked", delegationKey(11), ""), narrow)
	h.host.setAnswer(nil)
	if status != http.StatusForbidden || refusalOf(out) != "revoked" {
		t.Fatalf("a leaf the host answers revoked: %d %v", status, out)
	}
}

// The re-read's R-L1. Such a leaf reaches nothing by its key: outside its own scope, the
// journal says nothing to it, whether another holds the key, nobody does, or the record does
// not read. In its own scope it can tell one thing, the exact exception SPEC.md §11.8 states:
// whether its scope reserved the key, plain. A reconcile cannot tell even that.
func TestALeafNotNamingTheWriteLearnsNothingByItsKey(t *testing.T) {
	h := newDelegationHarness(t, false)
	root := statement(t, nil)
	actor := h.credential(t, root)
	rootOther := statement(t, map[string]any{"id": strings.Repeat("88", 16), "act": map[string]any{"agent": otherAgent, "software": testSoftware}})
	stranger := h.credential(t, rootOther, childOf(t, rootOther, map[string]any{"act": map[string]any{"agent": otherAgent, "software": testSoftware}}))
	held, damaged, unused := delegationKey(1), delegationKey(2), delegationKey(3)
	for i, key := range []string{held, damaged} {
		if status, out := h.present(t, "/act", h.actBody(fmt.Sprintf("seed-%d", i), key, ""), actor); status != http.StatusOK {
			t.Fatalf("seed: %d %v", status, out)
		}
	}
	scope := delegatedScopeOf(testSubjectSub, rootAgent)
	record := h.g.actionFirstScope(scope, damaged, h.g.actionNamespace(scope, damaged))
	writeIndexFile(t, filepath.Join(h.g.storeRoot, "actions", actionIndexDirectory, record.file), `{"indexVersion"`, 0600)
	session := 0
	ask := func(credential, key, extra string) (int, string, any) {
		t.Helper()
		session++
		status, out := h.present(t, "/act", h.actBody(fmt.Sprintf("ask-%d", session), key, extra), credential)
		return status, refusalOf(out), out["reason"]
	}
	for _, key := range []string{held, damaged, unused} {
		if status, refusal, reason := ask(stranger, key, ""); status != http.StatusForbidden || refusal != refusalOutOfScope || reason != "source" {
			t.Fatalf("another root actor's leaf, plain, key %s: %d %s %v", key[:4], status, refusal, reason)
		}
		if status, refusal, _ := ask(stranger, key, withReconcile); status != http.StatusForbidden || refusal != refusalKeyUnauthenticated {
			t.Fatalf("another root actor's leaf, reconciling, key %s: %d %s", key[:4], status, refusal)
		}
	}
	journalAbsent(t, h.g, h.g.actionNamespace(delegatedScopeOf(testSubjectSub, otherAgent), unused))
	journalAbsent(t, h.g, h.g.actionSubjectNamespace(scope.delegated, unused))
	// The stated exception, in its own scope.
	own := h.credential(t, root, childOf(t, root, map[string]any{"act": map[string]any{"agent": rootAgent, "software": testSoftware}}))
	if status, refusal, _ := ask(own, held, ""); status != http.StatusForbidden || refusal != refusalKeyUnauthenticated {
		t.Fatalf("its own scope, a reservation there, plain: %d %s", status, refusal)
	}
	if status, refusal, reason := ask(own, unused, ""); status != http.StatusForbidden || refusal != refusalOutOfScope || reason != "source" {
		t.Fatalf("its own scope, none there, plain: %d %s %v", status, refusal, reason)
	}
	for _, key := range []string{held, unused} {
		if status, refusal, _ := ask(own, key, withReconcile); status != http.StatusForbidden || refusal != refusalKeyUnauthenticated {
			t.Fatalf("its own scope, reconciling, key %s: %d %s", key[:4], status, refusal)
		}
	}
	if h.sent(held) != 1 || h.sent(unused) != 0 {
		t.Fatalf("sent %d and %d", h.sent(held), h.sent(unused))
	}
}

// The re-read's N13. A sender other than the actor makes no first scope, on the path that can
// reach it now: a reservation whose record was lost. It is answered from the reservation, and
// the record stays absent until the actor asks.
func TestASenderOtherThanTheActorMakesNoFirstScope(t *testing.T) {
	h := newDelegationHarness(t, false)
	actor := h.credential(t, statement(t, nil))
	key := delegationKey(12)
	if status, out := h.present(t, "/act", h.actBody("first", key, ""), actor); status != http.StatusOK {
		t.Fatalf("first: %d %v", status, out)
	}
	scope := delegatedScopeOf(testSubjectSub, rootAgent)
	record := filepath.Join(h.g.storeRoot, "actions", actionIndexDirectory, h.g.actionFirstScope(scope, key, h.g.actionNamespace(scope, key)).file)
	if err := os.Remove(record); err != nil {
		t.Fatal(err)
	}
	reservation := h.reservationOf(testSub(), rootAgent)
	for i, subject := range []string{testSubjectSub, hostRequester, testOperator} {
		status, out := h.post(t, "/act", h.actBody(fmt.Sprintf("sender-%d", i), key, reservation+withReconcile), map[string]string{"Authorization": "Bearer " + h.token(t, subject)})
		if status != http.StatusOK || out["receipt"] == nil {
			t.Fatalf("%s: %d %v", subject, status, out)
		}
		if _, err := os.Lstat(record); !os.IsNotExist(err) {
			t.Fatalf("%s made a first scope: %v", subject, err)
		}
	}
	if status, out := h.present(t, "/act", h.actBody("actor", key, withReconcile), actor); status != http.StatusOK || out["receipt"] == nil {
		t.Fatalf("the actor: %d %v", status, out)
	}
	if _, err := os.Stat(record); err != nil {
		t.Fatalf("the actor's reconcile holds the first scope: %v", err)
	}
	if h.sent(key) != 1 {
		t.Fatalf("sent %d", h.sent(key))
	}
}

// The compaction procedure, followed to the letter by an operator holding only the journal
// (docs/design/action-reconciliation.md), with the retention period taken as passed and the
// target as checked, then a restart. Afterwards nothing is called not dispatched that was
// sent, no key with a first scope sends again, and every entry a record names is there.
func TestCompactionFollowedLiterally(t *testing.T) {
	h := newDelegationHarness(t, false)
	actor := h.credential(t, statement(t, nil))
	other := h.credential(t, statement(t, map[string]any{"id": strings.Repeat("66", 16), "act": map[string]any{"agent": otherAgent, "software": testSoftware}}))
	root := statement(t, nil)
	narrow := h.credential(t, root, childOf(t, root, map[string]any{"act": map[string]any{"agent": rootAgent, "software": testSoftware}}))
	bearer := func() map[string]string {
		return map[string]string{"Authorization": "Bearer " + h.token(t, "alice")}
	}
	session := 0
	next := func() string { session++; return fmt.Sprintf("walk-%d", session) }
	asAlice := func(key, extra string) (int, map[string]any) {
		return h.post(t, "/act", h.actBody(next(), key, extra), bearer())
	}
	asActor := func(key, extra string) (int, map[string]any) {
		return h.present(t, "/act", h.actBody(next(), key, extra), actor)
	}
	k := func(n int) string { return fmt.Sprintf("%064x", 0xe000+n) }
	drop := func(do func()) {
		actionKeysMode(t, h.root, "write", "drop")
		do()
		actionKeysMode(t, h.root, "write", "respond")
	}
	flaggedAnswered, flaggedDropped, flaggedClosed := k(1), k(2), k(3)
	asAlice(flaggedAnswered, withKeyScope)
	drop(func() { asAlice(flaggedDropped, withKeyScope) })
	asAlice(flaggedClosed, withKeyScope+withReconcile)
	unflaggedAnswered, unflaggedDropped := k(4), k(5)
	asAlice(unflaggedAnswered, "")
	drop(func() { asAlice(unflaggedDropped, "") })
	delegatedAnswered, delegatedDropped, delegatedClosed, delegatedNarrow := k(6), k(7), k(8), k(9)
	asActor(delegatedAnswered, "")
	drop(func() { asActor(delegatedDropped, "") })
	asActor(delegatedClosed, withReconcile)
	h.present(t, "/act", h.actBody(next(), delegatedNarrow, ""), narrow)
	sentKeys := map[string]int{flaggedAnswered: 1, flaggedDropped: 1, flaggedClosed: 0, delegatedAnswered: 1, delegatedDropped: 1, delegatedClosed: 0, delegatedNarrow: 0}
	for key, want := range sentKeys {
		if h.sent(key) != want {
			t.Fatalf("before: key %s sent %d", key[60:], h.sent(key))
		}
	}

	// The operator. Step 3 of the procedure, in its order; nothing but the journal is read.
	actions := filepath.Join(h.g.storeRoot, "actions")
	archive := filepath.Join(h.root, "archive")
	if err := os.MkdirAll(archive, 0700); err != nil {
		t.Fatal(err)
	}
	walk := func() map[string]int {
		reservations, subjects := map[string]bool{}, map[string]bool{}
		records, err := filepath.Glob(filepath.Join(actions, actionIndexDirectory, "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range records {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var record struct {
				Reservation   string `json:"reservation"`
				SubjectRecord string `json:"subjectRecord"`
			}
			if err := json.Unmarshal(raw, &record); err != nil {
				t.Fatal(err)
			}
			reservations[record.Reservation] = true
			if record.SubjectRecord != "" {
				subjects[record.SubjectRecord] = true
			}
		}
		classes := map[string]int{}
		entries, err := os.ReadDir(actions)
		if err != nil {
			t.Fatal(err)
		}
		classify := func(dir, name string) string {
			for n := 1; n <= actionDispatchAttempts; n++ {
				raw, err := os.ReadFile(filepath.Join(dir, actionDispatchName(n)))
				if err == nil && strings.Contains(string(raw), `"closed":true`) {
					return "closed"
				}
			}
			held, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			_, scopeErr := os.Stat(filepath.Join(dir, "scope.json"))
			if subjects[name] || (scopeErr == nil && len(held) == 1) {
				return "subject"
			}
			if reservations[name] || scopeErr == nil {
				return "indexed"
			}
			intent, err := os.ReadFile(filepath.Join(dir, "intent.json"))
			if err != nil || !json.Valid(intent) {
				return "does-not-read"
			}
			record, recordErr := os.ReadFile(filepath.Join(dir, "action.json"))
			if recordErr == nil {
				if !json.Valid(record) {
					return "does-not-read"
				}
				if strings.Contains(string(record), `"outcome":"response"`) {
					return "answered"
				}
				return "uncertain"
			}
			for n := 1; n <= actionDispatchAttempts; n++ {
				if _, err := os.Stat(filepath.Join(dir, actionDispatchName(n))); err != nil {
					continue
				}
				if _, err := os.Stat(filepath.Join(dir, actionNotDispatchedName(n))); err != nil {
					return "begun"
				}
			}
			return "never-sent"
		}
		for _, e := range entries {
			if !e.IsDir() || e.Name() == actionIndexDirectory || strings.HasPrefix(e.Name(), ".staging-") {
				continue
			}
			class := classify(filepath.Join(actions, e.Name()), e.Name())
			classes[class]++
			switch class {
			case "indexed":
				record := filepath.Join(actions, e.Name(), "action.json")
				if _, err := os.Stat(record); err == nil {
					if err := os.Rename(record, filepath.Join(archive, fmt.Sprintf("%s-%d-action.json", e.Name(), classes[class]))); err != nil {
						t.Fatal(err)
					}
				}
			case "never-sent", "answered", "uncertain":
				if err := os.Rename(filepath.Join(actions, e.Name()), filepath.Join(archive, e.Name())); err != nil {
					t.Fatal(err)
				}
			}
		}
		return classes
	}
	classes := walk()
	if classes["closed"] != 2 || classes["subject"] != 3 || classes["indexed"] != 4 || classes["answered"] != 1 || classes["uncertain"] != 1 {
		t.Fatalf("the journal's classes: %v", classes)
	}
	// Every entry a record names is still there: they pair, from the journal alone.
	records, err := filepath.Glob(filepath.Join(actions, actionIndexDirectory, "*.json"))
	if err != nil || len(records) != 6 {
		t.Fatalf("records: %v %v", records, err)
	}
	pairedSubjects := 0
	for _, path := range records {
		raw, _ := os.ReadFile(path)
		var record map[string]any
		if err := json.Unmarshal(raw, &record); err != nil {
			t.Fatal(err)
		}
		for _, member := range []string{"reservation", "subjectRecord"} {
			if name, present := record[member].(string); present {
				if _, err := os.Stat(filepath.Join(actions, name)); err != nil {
					t.Fatalf("%s %s is gone: %v", member, name[:8], err)
				}
			}
		}
		// A delegated key's record names its subject entry, which an entry alone cannot
		// say; an undelegated key has none to name.
		_, delegatedScope := record["scope"].(map[string]any)["rootActor"]
		name, names := record["subjectRecord"].(string)
		if names != delegatedScope {
			t.Fatalf("a record's subject entry: delegated %v, names %v: %s", delegatedScope, names, raw)
		}
		if names {
			want := h.g.actionSubjectNamespace(delegatedScopeOf(testSubjectSub, rootAgent).delegated, record["key"].(string))
			if name != want {
				t.Fatalf("the record names %s, the key's subject entry is %s", name[:8], want[:8])
			}
			pairedSubjects++
		}
	}
	if pairedSubjects != classes["subject"] {
		t.Fatalf("%d subject entries pair with a record, of %d", pairedSubjects, classes["subject"])
	}

	check := func(round string) {
		t.Helper()
		for _, tc := range []struct {
			name, key string
			ask       func(key, extra string) (int, map[string]any)
			reconcile string
			closed    bool
		}{
			{"flagged answered", flaggedAnswered, asAlice, withKeyScope + withReconcile, false},
			{"flagged dropped", flaggedDropped, asAlice, withKeyScope + withReconcile, false},
			{"flagged closed", flaggedClosed, asAlice, withKeyScope + withReconcile, true},
			{"delegated answered", delegatedAnswered, asActor, withReconcile, false},
			{"delegated dropped", delegatedDropped, asActor, withReconcile, false},
			{"delegated closed", delegatedClosed, asActor, withReconcile, true},
		} {
			status, out := tc.ask(tc.key, tc.reconcile)
			if tc.closed {
				if status != http.StatusConflict || refusalOf(out) != refusalKeyNotDispatched {
					t.Fatalf("%s %s, reconcile: %d %v", round, tc.name, status, out)
				}
			} else if status != http.StatusOK || out["reconciliation"] == nil {
				t.Fatalf("%s %s, reconcile: %d %v", round, tc.name, status, out)
			}
			if h.sent(tc.key) != sentKeys[tc.key] {
				t.Fatalf("%s %s: sent %d", round, tc.name, h.sent(tc.key))
			}
		}
		// Another root actor stays refused on every key that has a first scope.
		if status, out := h.present(t, "/act", h.actBody(next(), delegatedAnswered, ""), other); status != http.StatusForbidden || refusalOf(out) != refusalKeyScopeConflict {
			t.Fatalf("%s another root actor: %d %v", round, status, out)
		}
		if h.sent(delegatedAnswered) != 1 {
			t.Fatalf("%s: sent %d", round, h.sent(delegatedAnswered))
		}
	}
	check("after one pass")
	// Followed again, it holds: what the first requests recorded goes the same way.
	walk()
	check("after a second pass")
	// Keys with no first scope and past retention send again: the text says so, and that is
	// what the retention period is for.
	if status, out := asAlice(unflaggedAnswered, ""); status != http.StatusOK || h.sent(unflaggedAnswered) != 2 {
		t.Fatalf("an unflagged key past retention: %d %v, sent %d", status, out, h.sent(unflaggedAnswered))
	}
}

// Requests that send neither member behave as they did, and this pins it with
// expectations written by hand: the namespace per subject and the second mutation it
// allows (§1.2b's own rule), the journal's layout and bytes, a freed attempt, a replay,
// a conflict, and the answer's members. No index exists, and nothing is staged.
func TestRequestsWithoutTheMembersAreUnchanged(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	key := strings.Repeat("a", 64)
	first, err := actionKeysAct(g, c, "first", key)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 3 || first["result"] == nil || first["receipt"] == nil || first["salts"] == nil {
		t.Fatalf("the answer's members: %v", first)
	}
	// Another subject of the same value is its own reservation and its own write.
	if _, err := scopedAct(g, c, "another", key, anotherSubject, false, false); err != nil {
		t.Fatal(err)
	}
	wantSent(t, root, key, 2)
	again, err := actionKeysAct(g, c, "again", key)
	if err != nil {
		t.Fatal(err)
	}
	if a, b := keyTestJSON(t, first), keyTestJSON(t, again); a != b {
		t.Fatal("the replay changed")
	}
	wantSent(t, root, key, 2)
	if _, err := scopedActOn(g, c, "conflict", key, actionKeysWho, false, false, `{"ticket":"T-2"}`); keyRefusal(err) != "action-key: action-key-conflict: this key already identifies different approved content" {
		t.Fatalf("a conflict: %q", keyRefusal(err))
	}
	missing := actionKeysService(t, root, actionKeysSources(t, root, filepath.Join(root, "not-installed", "adapter-mcp")))
	freedKey := strings.Repeat("b", 64)
	if _, err := actionKeysAct(missing, c, "missing", freedKey); !strings.Contains(keyRefusal(err), "action-not-dispatched") {
		t.Fatalf("a start failure: %v", err)
	}
	if _, err := actionKeysAct(g, c, "freed", freedKey); err != nil {
		t.Fatalf("a freed attempt: %v", err)
	}
	wantSent(t, root, freedKey, 1)

	// The journal: entries by name, each with exactly today's files and bytes.
	actions := filepath.Join(g.storeRoot, "actions")
	entries, err := os.ReadDir(actions)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
		if info, err := entry.Info(); err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			t.Fatalf("entry %s: %v %v", entry.Name(), info, err)
		}
	}
	want := []string{g.actionNamespace(actionKeysWho, key), g.actionNamespace(anotherSubject, key), g.actionNamespace(actionKeysWho, freedKey)}
	sort.Strings(want)
	sort.Strings(names)
	if strings.Join(names, " ") != strings.Join(want, " ") {
		t.Fatalf("the journal holds %v, want %v: nothing else, no index and no staging", names, want)
	}
	files := func(entry string) string {
		t.Helper()
		list, err := os.ReadDir(filepath.Join(actions, entry))
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, f := range list {
			info, err := f.Info()
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
				t.Fatalf("%s: %v %v", f.Name(), info, err)
			}
			out = append(out, f.Name())
		}
		return strings.Join(out, " ")
	}
	if got := files(g.actionNamespace(actionKeysWho, key)); got != "action.json dispatch-1.json intent.json" {
		t.Fatalf("an answered entry: %s", got)
	}
	if got := files(g.actionNamespace(actionKeysWho, freedKey)); got != "action.json dispatch-1.json dispatch-2.json intent.json not-dispatched-1.json" {
		t.Fatalf("a freed entry: %s", got)
	}
	marker, err := os.ReadFile(filepath.Join(actions, g.actionNamespace(actionKeysWho, key), "dispatch-1.json"))
	if err != nil || string(marker) != `{"attempt":1}` {
		t.Fatalf("the marker: %s %v", marker, err)
	}
	intent, err := os.ReadFile(filepath.Join(actions, g.actionNamespace(actionKeysWho, key), "intent.json"))
	if err != nil || !strings.HasPrefix(string(intent), `{"journalVersion":"2","identityVersion":"2","fingerprint":"`) || len(intent) != len(`{"journalVersion":"2","identityVersion":"2","fingerprint":""}`)+64 {
		t.Fatalf("the intent: %s %v", intent, err)
	}
	// Damage still refuses a request as it did: a partial record at the final name.
	damaged := strings.Repeat("c", 64)
	if _, err := actionKeysAct(g, c, "damaged-first", damaged); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(actions, g.actionNamespace(actionKeysWho, damaged), "action.json")
	if err := os.Remove(record); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record, []byte(`{"result"`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := actionKeysAct(g, c, "damaged", damaged); !strings.Contains(keyRefusal(err), "action-journal-invalid") {
		t.Fatalf("a damaged record: %v", err)
	}
	wantSent(t, root, damaged, 1)
	// An index holding other keys changes nothing for this one: no record for it, its
	// own entry, one write.
	if _, err := scopedAct(g, c, "indexed", strings.Repeat("d", 64), actionKeysWho, true, false); err != nil {
		t.Fatal(err)
	}
	beside := strings.Repeat("e", 64)
	if _, err := actionKeysAct(g, c, "beside", beside); err != nil {
		t.Fatal(err)
	}
	if _, err := scopedAct(g, c, "beside-other", beside, anotherSubject, false, false); err != nil {
		t.Fatal(err)
	}
	wantSent(t, root, beside, 2)
	records, err := os.ReadDir(filepath.Join(actions, actionIndexDirectory))
	if err != nil || len(records) != 1 {
		t.Fatalf("the index holds %v, %v: only the flagged key", records, err)
	}
}

func keyTestJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestActionKeyScopeChild is one gateway process on the shared store: it sends one
// request, and can die or pause at a named point of it.
func TestActionKeyScopeChild(t *testing.T) {
	root := os.Getenv("ACTION_SCOPE_ROOT")
	if root == "" {
		return
	}
	die := func() {
		p, _ := os.FindProcess(os.Getpid())
		p.Kill()
		time.Sleep(time.Hour)
	}
	wait := func(path string) {
		for {
			if _, err := os.Stat(path); err == nil {
				return
			}
			time.Sleep(time.Millisecond)
		}
	}
	kill, pause := os.Getenv("ACTION_SCOPE_KILL"), os.Getenv("ACTION_SCOPE_PAUSE")
	ready, proceed := os.Getenv("ACTION_SCOPE_READY"), os.Getenv("ACTION_SCOPE_GO")
	if tear := os.Getenv("ACTION_SCOPE_TEAR"); tear != "" {
		// Die with half of a record's bytes written: what a power loss can leave.
		syncActionFile = func(f *os.File) error {
			if info, err := f.Stat(); err == nil && info.Mode().IsRegular() && filepath.Base(f.Name()) == tear {
				f.Truncate(info.Size() / 2)
				f.Sync()
				die()
			}
			return f.Sync()
		}
	}
	if barrier := os.Getenv("ACTION_SCOPE_BARRIER"); barrier != "" {
		wait(barrier)
	}
	if delay, err := time.ParseDuration(os.Getenv("ACTION_SCOPE_DELAY")); err == nil {
		time.Sleep(delay)
	}
	var c actionKeysCall
	raw, _ := os.ReadFile(filepath.Join(root, "call.json"))
	if err := json.Unmarshal(raw, &c); err != nil {
		os.Exit(1)
	}
	g := actionKeysService(t, root, actionKeysSources(t, root, os.Args[0]))
	at := func(point string) {
		if point == kill {
			die()
		}
		if point == pause {
			os.WriteFile(ready, nil, 0600)
			wait(proceed)
		}
	}
	g.actionStep = at
	g.beforeAdmit = func() { at("before-admit") }
	who := actionKeysWho
	if os.Getenv("ACTION_SCOPE_ANOTHER") != "" {
		who = anotherSubject
	}
	_, err := scopedAct(g, c, os.Getenv("ACTION_SCOPE_SESSION"), os.Getenv("ACTION_SCOPE_KEY"), who, os.Getenv("ACTION_SCOPE_FLAGGED") != "", os.Getenv("ACTION_SCOPE_RECONCILE") != "")
	fmt.Println("CHILD:" + keyRefusal(err))
	os.Exit(0)
}

// actionScopeChild is the command for one such process.
func actionScopeChild(root, session, key string, extra ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestActionKeyScopeChild$")
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "ACTION_KEYS_") && !strings.HasPrefix(e, "ACTION_SCOPE_") && !strings.HasPrefix(e, envSourceHelper+"=") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, append([]string{"ACTION_SCOPE_ROOT=" + root, "ACTION_SCOPE_SESSION=" + session, "ACTION_SCOPE_KEY=" + key}, extra...)...)
	return cmd
}

const (
	childFlagged   = "ACTION_SCOPE_FLAGGED=1"
	childReconcile = "ACTION_SCOPE_RECONCILE=1"
	childAnother   = "ACTION_SCOPE_ANOTHER=1"
)

// childOutcome is what a finished child answered, and whether it lived to say.
func childOutcome(out string) (answer string, lived bool) {
	for _, line := range strings.Split(out, "\n") {
		if rest, found := strings.CutPrefix(line, "CHILD:"); found {
			return rest, true
		}
	}
	return "", false
}

func waitFor(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("nothing arrived at %s", filepath.Base(path))
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// The window of H1: one gateway process has read that attempt 1 is free and has not
// created the marker; another process's reconcile closes the key in that window. The
// first process's dispatch is then refused, nothing is sent, and the answer was true.
func TestCloseInsideTheDispatchWindowAcrossProcesses(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	key := strings.Repeat("a", 64)
	ready, proceed := filepath.Join(root, "ready"), filepath.Join(root, "proceed")
	cmd := actionScopeChild(root, "in-flight", key, childFlagged, "ACTION_SCOPE_PAUSE=before-admit", "ACTION_SCOPE_READY="+ready, "ACTION_SCOPE_GO="+proceed)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	waitFor(t, ready)
	_, err := scopedAct(g, c, "reconciling", key, actionKeysWho, true, true)
	wantKeyRefusal(t, "the close inside the window", err, refusalKeyNotDispatched)
	if err := os.WriteFile(proceed, nil, 0600); err != nil {
		t.Fatal(err)
	}
	cmd.Wait()
	if answer, lived := childOutcome(out.String()); !lived || answer != refusalKeyClosed {
		t.Fatalf("the in-flight request answered %q (lived %v)\n%s", answer, lived, out.String())
	}
	wantSent(t, root, key, 0)
	entry := filepath.Join(g.storeRoot, "actions", g.actionNamespace(actionKeysWho, key))
	if _, err := os.Stat(filepath.Join(entry, "action.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused dispatch recorded an action: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(g.storeRoot, "receipts", "in-flight")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused dispatch left a session: %v", err)
	}
}

// The other order. The reconcile has read that attempt 1 is free and has not closed;
// another process's dispatch takes the attempt and writes. The close then loses, and
// the answer is not that nothing was dispatched.
func TestDispatchInsideTheCloseWindowAcrossProcesses(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	key := strings.Repeat("b", 64)
	ready, proceed := filepath.Join(root, "ready"), filepath.Join(root, "proceed")
	// A reservation with nothing begun, so the close has an attempt to take.
	seed := actionScopeChild(root, "seed", key, childFlagged, "ACTION_SCOPE_KILL=before-admit")
	seed.Run()
	cmd := actionScopeChild(root, "reconciling", key, childFlagged, childReconcile, "ACTION_SCOPE_PAUSE=before-close", "ACTION_SCOPE_READY="+ready, "ACTION_SCOPE_GO="+proceed)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	waitFor(t, ready)
	if _, err := scopedAct(g, c, "dispatching", key, actionKeysWho, true, false); err != nil {
		t.Fatal(err)
	}
	wantSent(t, root, key, 1)
	if err := os.WriteFile(proceed, nil, 0600); err != nil {
		t.Fatal(err)
	}
	cmd.Wait()
	answer, lived := childOutcome(out.String())
	if !lived || answer == refusalKeyNotDispatched || answer == refusalKeyClosed {
		t.Fatalf("the reconcile answered %q (lived %v) after a dispatch\n%s", answer, lived, out.String())
	}
	wantSent(t, root, key, 1)
	raw, err := os.ReadFile(filepath.Join(g.storeRoot, "actions", g.actionNamespace(actionKeysWho, key), "dispatch-1.json"))
	if err != nil || string(raw) != `{"attempt":1}` {
		t.Fatalf("the marker: %s %v", raw, err)
	}
}

// Three requests: R finds a marker with no answer, and pauses. That marker's owner then
// answers that its program never started, and a reconcile closes at the next attempt,
// answering that nothing was sent. R goes on: the key is closed, it records no
// uncertainty and mints nothing, and the answer stays what it was.
func TestAStaleRequestFindsTheKeyClosed(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	key := strings.Repeat("d", 64)
	ready, proceed := filepath.Join(root, "ready"), filepath.Join(root, "proceed")
	namespace := g.actionNamespace(actionKeysWho, key)
	entry := filepath.Join(g.storeRoot, "actions", namespace)
	// A reservation, and a marker whose owner is sending, as far as anyone can tell.
	seed := actionScopeChild(root, "seed", key, childFlagged, "ACTION_SCOPE_KILL=before-admit")
	seed.Run()
	if err := os.WriteFile(filepath.Join(entry, "dispatch-1.json"), []byte(`{"attempt":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := actionScopeChild(root, "stale", key, childFlagged, "ACTION_SCOPE_PAUSE=before-admit", "ACTION_SCOPE_READY="+ready, "ACTION_SCOPE_GO="+proceed)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	waitFor(t, ready)
	if err := os.WriteFile(filepath.Join(entry, "not-dispatched-1.json"), []byte(`{"attempt":1,"reason":"never started"}`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := scopedAct(g, c, "closing", key, actionKeysWho, true, true)
	wantKeyRefusal(t, "the close", err, refusalKeyNotDispatched)
	if err := os.WriteFile(proceed, nil, 0600); err != nil {
		t.Fatal(err)
	}
	cmd.Wait()
	if answer, lived := childOutcome(out.String()); !lived || answer != refusalKeyClosed {
		t.Fatalf("the stale request answered %q (lived %v)\n%s", answer, lived, out.String())
	}
	if _, err := os.Stat(filepath.Join(entry, "action.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the stale request recorded uncertainty on a closed key: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(g.storeRoot, "receipts", "stale")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the stale request left a session: %v", err)
	}
	_, err = scopedAct(g, c, "again", key, actionKeysWho, true, true)
	wantKeyRefusal(t, "the close again", err, refusalKeyNotDispatched)
	wantSent(t, root, key, 0)
}

// A close outranks a record: a request that raced it and recorded uncertainty changes
// neither the answer nor the refusal. Nothing was sent, as every earlier attempt was
// answered before the close could be made.
func TestACloseOutranksARecordFoundBesideIt(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	key := strings.Repeat("e", 64)
	closeForTest(t, g, c, key)
	entry := filepath.Join(g.storeRoot, "actions", g.actionNamespace(actionKeysWho, key))
	if err := os.WriteFile(filepath.Join(entry, "action.json"), []byte(`{"result":{"outcome":"uncertain"},"receipt":{},"salts":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := scopedAct(g, c, "again", key, actionKeysWho, true, true)
	wantKeyRefusal(t, "the close again", err, refusalKeyNotDispatched)
	_, err = scopedAct(g, c, "plain", key, actionKeysWho, true, false)
	wantKeyRefusal(t, "a plain request", err, refusalKeyClosed)
	wantSent(t, root, key, 0)
}

// A dispatch in flight, its target still writing: a reconcile from another process
// finds the marker and answers uncertain, and the write lands: one mutation, no close.
func TestReconcileWhileADispatchIsInFlight(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	key := strings.Repeat("c", 64)
	actionKeysMode(t, root, "write", "rendezvous")
	cmd := actionScopeChild(root, "in-flight", key, childFlagged)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	waitFor(t, filepath.Join(root, "rendezvous", key))
	// The target gives up at its own deadline: on a slow machine let it go on early.
	// The marker is there, so what the reconcile must answer does not change.
	release := time.AfterFunc(3*time.Second, func() { os.WriteFile(filepath.Join(root, "rendezvous", "release"), nil, 0600) })
	defer release.Stop()
	result, err := scopedAct(g, c, "reconciling", key, actionKeysWho, true, true)
	if keyRefusal(err) == refusalKeyNotDispatched {
		t.Fatal("a dispatch in flight was called not dispatched")
	}
	if err != nil || result["reconciliation"] == nil {
		t.Fatalf("the reconcile: %v %v", result, err)
	}
	if err := os.WriteFile(filepath.Join(root, "rendezvous", "release"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	cmd.Wait()
	wantSent(t, root, key, 1)
}

// Reconciles and dispatches released together, across processes, for many rounds, the
// reconciles a little later each round so that both orders happen. Who wins is the
// race's; what must hold is that an answer of not dispatched is true: no mutation,
// ever. Never two mutations under one scope's key.
func TestCloseAndDispatchRaceAcrossProcesses(t *testing.T) {
	root, _, _ := actionKeysSetup(t)
	actionKeysMode(t, root, "write", "slow")
	closed, dispatched := 0, 0
	for round := range 16 {
		key := fmt.Sprintf("%064x", 1000+round)
		barrier := filepath.Join(root, fmt.Sprintf("race-%d", round))
		type child struct {
			cmd *exec.Cmd
			out *bytes.Buffer
		}
		var children []child
		for i := range 4 {
			flags := []string{childFlagged, "ACTION_SCOPE_BARRIER=" + barrier}
			if i%2 == 1 {
				flags = append(flags, childReconcile, fmt.Sprintf("ACTION_SCOPE_DELAY=%dms", round))
			}
			cmd := actionScopeChild(root, fmt.Sprintf("race-%d-%d", round, i), key, flags...)
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			children = append(children, child{cmd, &out})
		}
		time.Sleep(150 * time.Millisecond)
		if err := os.WriteFile(barrier, nil, 0600); err != nil {
			t.Fatal(err)
		}
		saidNot := false
		for _, c := range children {
			c.cmd.Wait()
			if answer, _ := childOutcome(c.out.String()); answer == refusalKeyNotDispatched {
				saidNot = true
			}
		}
		sent := actionKeysSent(root, key)
		if sent > 1 || (saidNot && sent != 0) {
			for _, c := range children {
				t.Log(c.out.String())
			}
			t.Fatalf("round %d: %d writes, a not-dispatched answer given: %v", round, sent, saidNot)
		}
		if saidNot {
			closed++
		}
		dispatched += sent
	}
	t.Logf("rounds closed %d, rounds dispatched %d", closed, dispatched)
}

// Two subjects' first requests released together: exactly one scope holds the key, and
// the other is refused. One mutation in every round.
func TestFirstScopeRaceAcrossProcesses(t *testing.T) {
	root, _, _ := actionKeysSetup(t)
	actionKeysMode(t, root, "write", "slow")
	for round := range 5 {
		key := fmt.Sprintf("%064x", 2000+round)
		barrier := filepath.Join(root, fmt.Sprintf("first-%d", round))
		var cmds []*exec.Cmd
		var outs []*bytes.Buffer
		for i := range 4 {
			flags := []string{childFlagged, "ACTION_SCOPE_BARRIER=" + barrier}
			if i%2 == 1 {
				flags = append(flags, childAnother)
			}
			cmd := actionScopeChild(root, fmt.Sprintf("first-%d-%d", round, i), key, flags...)
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			cmds, outs = append(cmds, cmd), append(outs, &out)
		}
		time.Sleep(150 * time.Millisecond)
		if err := os.WriteFile(barrier, nil, 0600); err != nil {
			t.Fatal(err)
		}
		conflicts := 0
		for i, cmd := range cmds {
			cmd.Wait()
			if answer, _ := childOutcome(outs[i].String()); answer == refusalKeyScopeConflict {
				conflicts++
			}
		}
		if sent := actionKeysSent(root, key); sent != 1 || conflicts != 2 {
			for _, out := range outs {
				t.Log(out.String())
			}
			t.Fatalf("round %d: %d writes, %d conflicts", round, sent, conflicts)
		}
	}
}

// Every crash point: a process dies there, the gateway restarts, and the requests that
// follow are answered truthfully, with no second mutation and no key refused for good.
func TestActionKeyScopeCrashPoints(t *testing.T) {
	type step struct {
		name              string
		another           bool
		scoped, reconcile bool
		answer            string // "" succeeds
		sent              int
	}
	plain := func(name, answer string, sent int) step {
		return step{name: name, scoped: true, answer: answer, sent: sent}
	}
	reconcile := func(name, answer string, sent int) step {
		return step{name: name, scoped: true, reconcile: true, answer: answer, sent: sent}
	}
	other := func(name, answer string, sent int) step {
		return step{name: name, another: true, scoped: true, answer: answer, sent: sent}
	}
	readBack := "" // uncertain, then a read-back that succeeds
	seedBeforeAdmit := []string{childFlagged, "ACTION_SCOPE_KILL=before-admit"}
	for _, tc := range []struct {
		name  string
		seed  []string // a process that dies first, if any
		kill  []string // the process under test, which dies
		steps []step
	}{
		{name: "a first request dies after the index, and goes on", kill: []string{childFlagged, "ACTION_SCOPE_KILL=index-durable"}, steps: []step{
			other("another subject", refusalKeyScopeConflict, 0),
			reconcile("reconcile", refusalKeyOutcomeUnknown, 0),
			plain("the first request again", "", 1),
			plain("a replay", "", 1),
		}},
		{name: "a first request dies before its marker, then a close", kill: seedBeforeAdmit, steps: []step{
			reconcile("reconcile", refusalKeyNotDispatched, 0),
			plain("the retry", refusalKeyClosed, 0),
			other("another subject", refusalKeyScopeConflict, 0),
		}},
		{name: "a first request dies before its marker, then a retry", kill: seedBeforeAdmit, steps: []step{
			plain("the retry", "", 1),
			reconcile("a retained answer", "", 1),
		}},
		{name: "a first request's marker is torn", kill: []string{childFlagged, "ACTION_SCOPE_TEAR=dispatch-1.json"}, steps: []step{
			reconcile("reconcile", readBack, 0),
			plain("the retry", readBack, 0),
			other("another subject", refusalKeyScopeConflict, 0),
		}},
		{name: "a close of a key never seen dies after its entry", kill: []string{childFlagged, childReconcile, "ACTION_SCOPE_KILL=closed-entry"}, steps: []step{
			plain("the first request", refusalKeyClosed, 0),
			reconcile("the close again", refusalKeyNotDispatched, 0),
			other("another subject", refusalKeyScopeConflict, 0),
		}},
		{name: "a close of a key never seen dies before its index: no answer was given", kill: []string{childFlagged, childReconcile, "ACTION_SCOPE_KILL=close-durable"}, steps: []step{
			other("another subject takes the key", "", 1),
			reconcile("the close again", refusalKeyScopeConflict, 1),
			plain("the first scope's request", refusalKeyScopeConflict, 1),
		}},
		{name: "a close dies after its index, before answering", kill: []string{childFlagged, childReconcile, "ACTION_SCOPE_KILL=close-indexed"}, steps: []step{
			other("another subject", refusalKeyScopeConflict, 0),
			plain("the first request", refusalKeyClosed, 0),
			reconcile("the close again", refusalKeyNotDispatched, 0),
		}},
		{name: "a close's staged marker is torn", seed: seedBeforeAdmit, kill: []string{childFlagged, childReconcile, "ACTION_SCOPE_TEAR=dispatch-1.json"}, steps: []step{
			reconcile("the close again", refusalKeyNotDispatched, 0),
			plain("the retry", refusalKeyClosed, 0),
		}},
		{name: "a close dies after its marker", seed: seedBeforeAdmit, kill: []string{childFlagged, childReconcile, "ACTION_SCOPE_KILL=close-marker"}, steps: []step{
			plain("the retry", refusalKeyClosed, 0),
			reconcile("the close again", refusalKeyNotDispatched, 0),
		}},
		{name: "a close of a key never seen is torn in its entry", kill: []string{childFlagged, childReconcile, "ACTION_SCOPE_TEAR=intent.json"}, steps: []step{
			reconcile("the close again", refusalKeyNotDispatched, 0),
			plain("the first request", refusalKeyClosed, 0),
		}},
		{name: "a flagged intent is torn: not refused for good", kill: []string{childFlagged, "ACTION_SCOPE_TEAR=intent.json"}, steps: []step{
			plain("the retry", "", 1),
		}},
		{name: "an unflagged intent is torn: not refused for good", kill: []string{"ACTION_SCOPE_TEAR=intent.json"}, steps: []step{
			{name: "the retry", answer: "", sent: 1},
		}},
		{name: "a flagged record is torn after the write: not refused for good", kill: []string{childFlagged, "ACTION_SCOPE_TEAR=action.json"}, steps: []step{
			plain("the retry", readBack, 1),
			reconcile("the reconcile", readBack, 1),
		}},
		{name: "an unflagged record is torn after the write: not refused for good", kill: []string{"ACTION_SCOPE_TEAR=action.json"}, steps: []step{
			{name: "the retry", answer: readBack, sent: 1},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, _, c := actionKeysSetup(t)
			key := strings.Repeat("a", 64)
			if tc.seed != nil {
				var out bytes.Buffer
				cmd := actionScopeChild(root, "seed", key, tc.seed...)
				cmd.Stdout, cmd.Stderr = &out, &out
				cmd.Run()
				if _, lived := childOutcome(out.String()); lived {
					t.Fatalf("the seed did not die:\n%s", out.String())
				}
			}
			var out bytes.Buffer
			cmd := actionScopeChild(root, "dying", key, tc.kill...)
			cmd.Stdout, cmd.Stderr = &out, &out
			cmd.Run()
			if answer, lived := childOutcome(out.String()); lived {
				t.Fatalf("the process did not die there: it answered %q\n%s", answer, out.String())
			}
			restarted := actionKeysService(t, root, actionKeysSources(t, root, os.Args[0]))
			for i, s := range tc.steps {
				who := actionKeysWho
				if s.another {
					who = anotherSubject
				}
				_, err := scopedAct(restarted, c, fmt.Sprintf("after-%d", i), key, who, s.scoped, s.reconcile)
				wantKeyRefusal(t, s.name, err, s.answer)
				wantSent(t, root, key, s.sent)
			}
		})
	}
}

// An index record torn while being published is no record: the retry holds the key,
// and it is not refused for good.
func TestTornIndexRecordRefusesNothing(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	key := strings.Repeat("a", 64)
	first := g.actionFirstScope(actionKeysWho, key, g.actionNamespace(actionKeysWho, key))
	var out bytes.Buffer
	cmd := actionScopeChild(root, "dying", key, childFlagged, "ACTION_SCOPE_TEAR="+first.file)
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.Run()
	if answer, lived := childOutcome(out.String()); lived {
		t.Fatalf("the process did not die there: %q\n%s", answer, out.String())
	}
	if _, err := os.Lstat(filepath.Join(g.storeRoot, "actions", actionIndexDirectory, first.file)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a torn record is at its name: %v", err)
	}
	restarted := actionKeysService(t, root, actionKeysSources(t, root, os.Args[0]))
	if _, err := scopedAct(restarted, c, "retry", key, actionKeysWho, true, false); err != nil {
		t.Fatal(err)
	}
	wantSent(t, root, key, 1)
	_, err := scopedAct(restarted, c, "other", key, anotherSubject, true, false)
	wantKeyRefusal(t, "another subject", err, refusalKeyScopeConflict)
	wantSent(t, root, key, 1)
}

// The delegated table, for a reconciling request (SPEC.md §11.8; ADR-0025 L7). The
// actor closes; another sender is compared, finds, and never closes or creates; another
// root actor's reservation is never closed over; a leaf not naming the write plants
// nothing. An undelegated scope and a delegated one are other scopes to each other.
func TestDelegatedReconcile(t *testing.T) {
	h := newDelegationHarness(t, false)
	root := statement(t, nil)
	actor := h.credential(t, root)
	reservation := h.reservationOf(testSub(), rootAgent)
	asToken := func(subject, session, key, extra string) (int, map[string]any) {
		t.Helper()
		return h.post(t, "/act", h.actBody(session, key, extra), map[string]string{"Authorization": "Bearer " + h.token(t, subject)})
	}
	wantAnswer := func(step string, status int, out map[string]any, wantStatus int, want string) {
		t.Helper()
		if status != wantStatus || refusalOf(out) != want {
			t.Fatalf("%s: %d %v, want %d %s", step, status, out, wantStatus, want)
		}
	}
	scopeNamespace := func(key string) string {
		who := &caller{delegated: &delegatedSender{scope: reservationScope{sub: principalRef{"person", testIssuerURL, testSubjectSub}, rootActor: rootAgent, host: "desk"}}}
		return h.g.actionNamespace(who, key)
	}

	// Another sender on a key never seen: refused, and it leaves nothing.
	key := delegationKey(1)
	status, out := asToken(testSubjectSub, "d1", key, reservation+withReconcile)
	wantAnswer("the subject on a key never seen", status, out, http.StatusForbidden, refusalActorOnly)
	journalAbsent(t, h.g, scopeNamespace(key))
	journalAbsent(t, h.g, actionIndexDirectory)

	// The actor closes it, with no session and no admission counted.
	counted := h.host.counted()
	status, out = h.present(t, "/act", h.actBody("d2", key, withReconcile), actor)
	wantAnswer("the actor's close", status, out, http.StatusConflict, refusalKeyNotDispatched)
	if h.host.counted() != counted {
		t.Fatal("a close was counted as a call")
	}
	if _, err := os.Lstat(filepath.Join(h.g.storeRoot, "receipts", "d2")); !os.IsNotExist(err) {
		t.Fatalf("a close left a session: %v", err)
	}
	status, out = h.present(t, "/act", h.actBody("d3", key, ""), actor)
	wantAnswer("the actor's late request", status, out, http.StatusConflict, refusalKeyClosed)
	status, out = h.present(t, "/act", h.actBody("d4", key, withReconcile), actor)
	wantAnswer("the actor's close again", status, out, http.StatusConflict, refusalKeyNotDispatched)
	// A close that died before its first scope: another sender makes none, and answers
	// nothing that rests on one. The actor's next request finishes the close.
	namedBy := func(sender *caller) string {
		return filepath.Join(h.g.storeRoot, "actions", actionIndexDirectory, h.g.actionFirstScope(sender, key, scopeNamespace(key)).file)
	}
	record := namedBy(&caller{delegated: &delegatedSender{scope: reservationScope{sub: principalRef{"person", testIssuerURL, testSubjectSub}, rootActor: rootAgent, host: "desk"}}})
	if err := os.Remove(record); err != nil {
		t.Fatal(err)
	}
	status, out = asToken(testSubjectSub, "d4a", key, reservation+withReconcile)
	wantAnswer("the subject on a close with no first scope", status, out, http.StatusForbidden, refusalActorOnly)
	if _, err := os.Lstat(record); !os.IsNotExist(err) {
		t.Fatalf("a sender other than the actor made a first scope: %v", err)
	}
	status, out = h.present(t, "/act", h.actBody("d4b", key, withReconcile), actor)
	wantAnswer("the actor finishes the close", status, out, http.StatusConflict, refusalKeyNotDispatched)
	if _, err := os.Lstat(record); err != nil {
		t.Fatalf("the close has no first scope: %v", err)
	}
	// Others find it closed, and never a dispatch.
	status, out = asToken(testSubjectSub, "d5", key, reservation+withReconcile)
	wantAnswer("the subject reconciling a closed key", status, out, http.StatusConflict, refusalKeyNotDispatched)
	status, out = asToken(testSubjectSub, "d6", key, reservation)
	wantAnswer("the subject, plain, on a closed key", status, out, http.StatusForbidden, refusalActorOnly)
	// Another root actor, and an undelegated request, are other scopes.
	other := h.credential(t, statement(t, map[string]any{"id": strings.Repeat("66", 16), "act": map[string]any{"agent": otherAgent, "software": testSoftware}}))
	status, out = h.present(t, "/act", h.actBody("d7", key, ""), other)
	wantAnswer("another root actor", status, out, http.StatusForbidden, refusalKeyScopeConflict)
	status, out = asToken("alice", "d8", key, withKeyScope)
	wantAnswer("an undelegated first scope", status, out, http.StatusForbidden, refusalKeyScopeConflict)
	if h.sent(key) != 0 {
		t.Fatalf("sent %d", h.sent(key))
	}

	// A reservation of another root actor is never closed over: the first request
	// went out, and a reconcile under another root actor must not say otherwise.
	sent := delegationKey(2)
	if status, out := h.present(t, "/act", h.actBody("d9", sent, ""), actor); status != http.StatusOK || h.sent(sent) != 1 {
		t.Fatalf("a first dispatch: %d %v", status, out)
	}
	status, out = h.present(t, "/act", h.actBody("d10", sent, withReconcile), other)
	wantAnswer("another root actor reconciling", status, out, http.StatusForbidden, refusalKeyScopeConflict)
	// The actor reconciling it gets the retained answer; the subject too.
	if status, out := h.present(t, "/act", h.actBody("d11", sent, withReconcile), actor); status != http.StatusOK || out["receipt"] == nil {
		t.Fatalf("the actor's retained answer: %d %v", status, out)
	}
	if status, out := asToken(testSubjectSub, "d12", sent, reservation+withReconcile); status != http.StatusOK || out["receipt"] == nil {
		t.Fatalf("the subject's retained answer: %d %v", status, out)
	}
	if h.sent(sent) != 1 {
		t.Fatalf("sent %d", h.sent(sent))
	}

	// A sender other than the actor does not close a reservation with nothing begun:
	// the actor's dispatch still goes, once.
	unsent := delegationKey(3)
	h.host.setAnswer(func(b map[string]any) (int, string) {
		if _, standing := b["standing"]; standing {
			return http.StatusOK, `{"standing":"current"}`
		}
		if c, ok := b["call"].(map[string]any); ok && c["source"] == "tickets/write" {
			return http.StatusOK, `{"admission":"refuse","refusal":"subject-unauthorized"}`
		}
		return http.StatusOK, `{"admission":"admit"}`
	})
	status, out = h.present(t, "/act", h.actBody("d13", unsent, ""), actor)
	wantAnswer("the actor's refused dispatch", status, out, http.StatusForbidden, "subject-unauthorized")
	status, out = asToken(testSubjectSub, "d14", unsent, reservation+withReconcile)
	wantAnswer("the subject on nothing begun", status, out, http.StatusForbidden, refusalActorOnly)
	h.host.setAnswer(nil)
	if status, out := h.present(t, "/act", h.actBody("d15", unsent, ""), actor); status != http.StatusOK || h.sent(unsent) != 1 {
		t.Fatalf("the actor's dispatch after another sender's reconcile: %d %v, sent %d", status, out, h.sent(unsent))
	}

	// A leaf not naming the write closes nothing, and plants nothing.
	narrowKey := delegationKey(4)
	narrow := h.credential(t, root, childOf(t, root, map[string]any{"act": map[string]any{"agent": rootAgent, "software": testSoftware}}))
	status, out = h.present(t, "/act", h.actBody("d16", narrowKey, withReconcile), narrow)
	wantAnswer("a leaf not naming the write", status, out, http.StatusForbidden, refusalKeyUnauthenticated)
	journalAbsent(t, h.g, scopeNamespace(narrowKey))
	entries, err := os.ReadDir(filepath.Join(h.g.storeRoot, "actions"))
	if err != nil {
		t.Fatal(err)
	}
	before := len(entries)
	status, out = h.present(t, "/act", h.actBody("d17", narrowKey, withReconcile), narrow)
	wantAnswer("again", status, out, http.StatusForbidden, refusalKeyUnauthenticated)
	entries, err = os.ReadDir(filepath.Join(h.g.storeRoot, "actions"))
	if err != nil || len(entries) != before {
		t.Fatalf("a refused close planted a record: %v %v", entries, err)
	}

	// An undelegated first scope holds against a delegated request, flagged by
	// neither, and against every sender of that scope.
	held := delegationKey(5)
	if status, out := asToken("alice", "d18", held, withKeyScope); status != http.StatusOK {
		t.Fatalf("an undelegated first send: %d %v", status, out)
	}
	status, out = h.present(t, "/act", h.actBody("d19", held, ""), actor)
	wantAnswer("the actor on another's first scope", status, out, http.StatusForbidden, refusalKeyScopeConflict)
	status, out = h.present(t, "/act", h.actBody("d20", held, withReconcile), actor)
	wantAnswer("the actor reconciling another's first scope", status, out, http.StatusForbidden, refusalKeyScopeConflict)
	status, out = asToken(testSubjectSub, "d21", held, reservation+withReconcile)
	wantAnswer("the subject reconciling another's first scope", status, out, http.StatusForbidden, refusalKeyScopeConflict)
	if h.sent(held) != 1 {
		t.Fatalf("sent %d", h.sent(held))
	}
}

// #352 L4 under a delegation. A retry mints its receipt from the dispatch marker, so a
// marker torn by a crash would refuse the key for good, with no program ever started.
// It appears whole or not at all: with its bytes not durable there is no marker at its
// name, the retry dispatches once, and a close of that attempt cannot be beaten by it.
func TestDelegatedDispatchMarkerAppearsWhole(t *testing.T) {
	h := newDelegationHarness(t, false)
	actor := h.credential(t, statement(t, nil))
	key := delegationKey(8)
	marker := filepath.Join(h.g.storeRoot, "actions", h.g.actionNamespace(&caller{delegated: &delegatedSender{scope: reservationScope{sub: principalRef{"person", testIssuerURL, testSubjectSub}, rootActor: rootAgent, host: "desk"}}}, key), "dispatch-1.json")
	saved := syncActionFile
	defer func() { syncActionFile = saved }()
	seen := false
	syncActionFile = func(f *os.File) error {
		if filepath.Base(f.Name()) == "dispatch-1.json" {
			seen = true
			if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the marker is at its name before its bytes are durable: %v", err)
			}
			return errors.New("injected sync failure")
		}
		return f.Sync()
	}
	status, out := h.present(t, "/act", h.actBody("m1", key, ""), actor)
	syncActionFile = saved
	if !seen || status == http.StatusOK || h.sent(key) != 0 {
		t.Fatalf("a dispatch through a failed marker: %d %v, seen %v, sent %d", status, out, seen, h.sent(key))
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a failed marker is at its name: %v", err)
	}
	status, out = h.present(t, "/act", h.actBody("m2", key, ""), actor)
	if status != http.StatusOK || out["receipt"] == nil || h.sent(key) != 1 {
		t.Fatalf("the retry: %d %v, sent %d", status, out, h.sent(key))
	}
	// A delegated dispatch and a close take the same name, and a close that lost says so.
	raced := delegationKey(9)
	if status, out := h.present(t, "/act", h.actBody("m3", raced, withReconcile), actor); status != http.StatusConflict || refusalOf(out) != refusalKeyNotDispatched {
		t.Fatalf("the close: %d %v", status, out)
	}
	namespace := h.g.actionNamespace(&caller{delegated: &delegatedSender{scope: reservationScope{sub: principalRef{"person", testIssuerURL, testSubjectSub}, rootActor: rootAgent, host: "desk"}}}, raced)
	j, err := openActionJournal(h.g.storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	claim, err := j.holdEntry(namespace, false)
	if err != nil {
		t.Fatal(err)
	}
	defer claim.close()
	if err := claim.claimDispatchUnder(1, newObject(), "sha256:"+strings.Repeat("a", 64)); !errors.Is(err, errActionKeyClosed) {
		t.Fatalf("a delegated dispatch over a close: %v", err)
	}
}

// A dropped delegated write, then a takeover reconciling: the read-back under the
// reconciler #363 built, sending nothing.
func TestDelegatedReconcileReadsBack(t *testing.T) {
	h := newDelegationHarness(t, false)
	actionKeysMode(t, h.root, "write", "drop")
	key := delegationKey(6)
	first := h.credential(t, statement(t, nil))
	if status, out := h.present(t, "/act", h.actBody("r1", key, ""), first); status != http.StatusOK || h.sent(key) != 1 {
		t.Fatalf("first: %d %v", status, out)
	}
	actionKeysMode(t, h.root, "write", "respond")
	reissued := h.credential(t, statement(t, map[string]any{"id": strings.Repeat("55", 16), "issuedAt": "2026-10-30T00:30:00.000Z"}))
	status, out := h.present(t, "/act", h.actBody("r2", key, withReconcile), reissued)
	if status != http.StatusOK || h.sent(key) != 1 {
		t.Fatalf("the takeover: %d %v, sent %d", status, out, h.sent(key))
	}
	if _, rec := reconciledBy(t, out); rec["kind"] != "actor" {
		t.Fatalf("reconciler: %v", rec)
	}
}
