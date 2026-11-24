//go:build unix

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// /act resolving its approval citations (ADR-0063), with the synthetic
// sources of actScopeSetup: the write platform of none ("tickets"), which
// resolves in the gateway's directory, and the one fixed to scope B
// ("tickets-b"), which resolves in its own.

type approvalHarness struct {
	*actScopeHarness
	gateway, scoped string
}

func approvalSetup(t *testing.T) *approvalHarness {
	t.Helper()
	h := &approvalHarness{actScopeHarness: actScopeSetup(t)}
	h.g.dryRunApprovals = true
	h.gateway, h.scoped = filepath.Join(h.root, "approvals"), filepath.Join(h.root, "approvals-b")
	for _, dir := range []string{h.gateway, h.scoped} {
		for _, kind := range []string{approvalSingle, approvalStanding} {
			if err := os.MkdirAll(filepath.Join(dir, kind), 0o700); err != nil {
				t.Fatal(err)
			}
		}
	}
	h.g.approvalRecords = h.gateway
	spec := h.g.sources["tickets-b/write"]
	spec.approvalRecords = h.scoped
	h.g.sources["tickets-b/write"] = spec
	return h
}

// putRecord writes a record and answers its citation.
func putRecord(t *testing.T, dir, kind, id string, data []byte) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, kind, id), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return citationOf(kind, id, digestOf(string(data)))
}

func citationOf(kind, id, digest string) string {
	return `{"digest":"` + digest + `","id":"` + id + `","kind":"` + kind + `"}`
}

// rawAct posts an /act body and answers the status and the body's bytes.
func rawAct(t *testing.T, h *approvalHarness, body, token string) (int, []byte) {
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
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, data
}

func (h *approvalHarness) unscoped(key, approvals string) string {
	return h.dryRunBody("act-u", "tickets", "", key, h.decisionU, h.cite("u-read", h.unscopedSig), `,"approvals":[`+approvals+`]`)
}

func (h *approvalHarness) scopedBody(key, approvals string) string {
	return h.dryRunBody("act-b", "tickets-b", scopeB, key, h.decisionB, h.cite("b-read", h.scopedSig), `,"approvals":[`+approvals+`]`)
}

// unresolvedBody is the one answer of a citation that does not resolve.
var unresolvedBody = func() []byte {
	data, _ := json.Marshal(map[string]any{"error": approvalUnresolved, "refusedAt": "approvals"})
	return data
}()

func receiptAction(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	receipt, _ := out["receipt"].(map[string]any)
	action, _ := receipt["action"].(map[string]any)
	if action == nil {
		t.Fatalf("no action receipt: %s", data)
	}
	return action
}

// One citation resolves, and then eight of both kinds: the receipt marks
// them resolved under the signature, and verify accepts it.
func TestAnApprovalCitationResolves(t *testing.T) {
	h := approvalSetup(t)
	one := putRecord(t, h.gateway, approvalSingle, "change-1", []byte(`{"approved":true}`))
	code, data := rawAct(t, h, h.unscoped(strings.Repeat("1", 64), one), h.tokenA)
	if code != http.StatusOK {
		t.Fatalf("one citation: %d %s", code, data)
	}
	if action := receiptAction(t, data); action["approvalsResolved"] != true {
		t.Fatalf("one citation: the receipt does not mark it resolved: %v", action)
	}
	var eight []string
	for i := 0; i < maxApprovals; i++ {
		kind := approvalSingle
		if i%2 == 1 {
			kind = approvalStanding
		}
		eight = append(eight, putRecord(t, h.gateway, kind, fmt.Sprintf("change-%d", 10+i), []byte(fmt.Sprintf("record %d\n", i))))
	}
	code, data = rawAct(t, h, h.unscoped(strings.Repeat("2", 64), strings.Join(eight, ",")), h.tokenA)
	if code != http.StatusOK {
		t.Fatalf("eight citations: %d %s", code, data)
	}
	action := receiptAction(t, data)
	if action["approvalsResolved"] != true || len(action["approvals"].([]any)) != maxApprovals {
		t.Fatalf("eight citations: %v", action)
	}
	rep, err := h.g.verifyReport()
	if err != nil {
		t.Fatal(err)
	}
	// every receipt passes; the sessions are open, so unregistered
	for _, f := range rep.Findings {
		if _, receipt := f["callIndex"]; receipt && f["status"] != "ok" {
			t.Fatalf("verify: %v", rep.Findings)
		}
	}
}

// Every way a citation fails to resolve is answered with one sentence,
// byte for byte, before anything of the write: no dispatch, no attempt on
// the key and no receipt. One citation that fails among eight that
// resolve refuses the action.
func TestAnUnresolvedApprovalCitationIsOneRefusal(t *testing.T) {
	h := approvalSetup(t)
	good := []byte("approved\n")
	digest := digestOf(string(good))
	elsewhere := t.TempDir()
	if err := os.WriteFile(filepath.Join(elsewhere, "change-9"), good, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		prepare func(t *testing.T)
		cite    string
	}{
		{"missing", func(*testing.T) {}, citationOf(approvalSingle, "change-1", digest)},
		{"a directory", func(t *testing.T) {
			if err := os.Mkdir(filepath.Join(h.gateway, approvalSingle, "change-2"), 0o700); err != nil {
				t.Fatal(err)
			}
		}, citationOf(approvalSingle, "change-2", digest)},
		{"a named pipe", func(t *testing.T) {
			if err := syscall.Mkfifo(filepath.Join(h.gateway, approvalSingle, "change-3"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, citationOf(approvalSingle, "change-3", digest)},
		{"over the bound", func(t *testing.T) {
			putRecord(t, h.gateway, approvalSingle, "change-4", bytes.Repeat([]byte("a"), maxApprovalRecordBytes+1))
		}, citationOf(approvalSingle, "change-4", digestOf(strings.Repeat("a", maxApprovalRecordBytes+1)))},
		{"another digest", func(t *testing.T) {
			putRecord(t, h.gateway, approvalSingle, "change-5", []byte("approved, other bytes\n"))
		}, citationOf(approvalSingle, "change-5", digest)},
		{"of the other kind", func(t *testing.T) {
			putRecord(t, h.gateway, approvalStanding, "change-6", good)
		}, citationOf(approvalSingle, "change-6", digest)},
		{"a symlinked record", func(t *testing.T) {
			if err := os.Symlink(filepath.Join(elsewhere, "change-9"), filepath.Join(h.gateway, approvalSingle, "change-7")); err != nil {
				t.Fatal(err)
			}
		}, citationOf(approvalSingle, "change-7", digest)},
		{"a symlinked kind directory", func(t *testing.T) {
			if err := os.RemoveAll(filepath.Join(h.gateway, approvalStanding)); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(elsewhere, filepath.Join(h.gateway, approvalStanding)); err != nil {
				t.Fatal(err)
			}
		}, citationOf(approvalStanding, "change-9", digest)},
	}
	var resolving []string
	for i := 0; i < maxApprovals-1; i++ {
		resolving = append(resolving, putRecord(t, h.gateway, approvalSingle, fmt.Sprintf("ok-%d", i), []byte(fmt.Sprintf("ok %d", i))))
	}
	who := &caller{issuer: h.g.identity.issuer, subject: subjectA}
	for i, c := range cases {
		c.prepare(t)
		store := treeOf(t, h.g.storeRoot)
		for _, approvals := range []string{c.cite, strings.Join(append(append([]string(nil), resolving...), c.cite), ",")} {
			key := fmt.Sprintf("%064x", i+1)
			code, data := rawAct(t, h, h.unscoped(key, approvals), h.tokenA)
			if code != http.StatusBadRequest || !bytes.Equal(bytes.TrimSpace(data), unresolvedBody) {
				t.Fatalf("%s: %d %s\nwant %s", c.name, code, data, unresolvedBody)
			}
			if n := actionKeysSent(h.root, key); n != 0 {
				t.Fatalf("%s: the target received %d writes", c.name, n)
			}
			journalAbsent(t, h.g, h.g.actionNamespaceIn(who, key, ""))
		}
		sameTree(t, c.name+": the store", treeOf(t, h.g.storeRoot), store)
	}
}

// A record replaced between the look at it and its read, by a file of the
// very same bytes, does not resolve: the file read is held to be the file
// looked at.
func TestTheRecordReplacedBetweenTheLookAndTheReadDoesNotResolve(t *testing.T) {
	h := approvalSetup(t)
	data := []byte("approved\n")
	cite := putRecord(t, h.gateway, approvalSingle, "change-1", data)
	twin := filepath.Join(h.root, "twin")
	if err := os.WriteFile(twin, data, 0o600); err != nil {
		t.Fatal(err)
	}
	swapped := 0
	approvalRecordStatted = func(path string) {
		swapped++
		if err := os.Rename(twin, path); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { approvalRecordStatted = func(string) {} })
	code, body := rawAct(t, h, h.unscoped(strings.Repeat("1", 64), cite), h.tokenA)
	if swapped != 1 || code != http.StatusBadRequest || !bytes.Equal(bytes.TrimSpace(body), unresolvedBody) {
		t.Fatalf("swapped %d: %d %s", swapped, code, body)
	}
	// the same record left in place resolves
	approvalRecordStatted = func(string) {}
	if code, body := rawAct(t, h, h.unscoped(strings.Repeat("2", 64), cite), h.tokenA); code != http.StatusOK {
		t.Fatalf("the record in place: %d %s", code, body)
	}
}

// A citation whose kind or id cannot name one level under the directory is
// refused by the request alone, before any record is looked at.
func TestAnApprovalIDThatIsNoPathSegmentIsRefused(t *testing.T) {
	h := approvalSetup(t)
	putRecord(t, h.gateway, approvalSingle, "change-1", []byte("approved"))
	digest := digestOf("approved")
	for _, id := range []string{".", "..", "../single/change-1", "single/change-1", `single\change-1`, "é", "е"} {
		raw, _ := json.Marshal(id)
		cite := `{"digest":"` + digest + `","id":` + string(raw) + `,"kind":"single"}`
		code, data := rawAct(t, h, h.unscoped(strings.Repeat("1", 64), cite), h.tokenA)
		var out map[string]any
		_ = json.Unmarshal(data, &out)
		if code != http.StatusBadRequest || out["refusedAt"] != "approvals" || !strings.Contains(fmt.Sprint(out["error"]), "cannot name an approval record") {
			t.Fatalf("id %q: %d %s", id, code, data)
		}
	}
}

// A scoped action resolves in its own scope's directory alone, and is
// answered the same, byte for byte, whether or not the gateway's directory
// holds the record; an unscoped action never resolves a scope's record.
func TestAScopedActionResolvesInItsOwnDirectoryAlone(t *testing.T) {
	h := approvalSetup(t)
	data := []byte("approved for scope B\n")
	cite := citationOf(approvalSingle, "change-b", digestOf(string(data)))
	answer := func(name, body, token string) []byte {
		t.Helper()
		code, out := rawAct(t, h, body, token)
		if code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", name, code, out)
		}
		return out
	}
	absent := answer("scope B, the record nowhere", h.scopedBody(strings.Repeat("1", 64), cite), h.tokenB)
	unscopedAbsent := answer("none, the record nowhere", h.unscoped(strings.Repeat("1", 64), cite), h.tokenA)
	putRecord(t, h.gateway, approvalSingle, "change-b", data)
	if got := answer("scope B, the record in the gateway's", h.scopedBody(strings.Repeat("2", 64), cite), h.tokenB); !bytes.Equal(got, absent) {
		t.Fatalf("the gateway's record changed scope B's answer:\n%s\n%s", got, absent)
	}
	if err := os.Remove(filepath.Join(h.gateway, approvalSingle, "change-b")); err != nil {
		t.Fatal(err)
	}
	putRecord(t, h.scoped, approvalSingle, "change-b", data)
	if got := answer("none, the record in scope B's", h.unscoped(strings.Repeat("2", 64), cite), h.tokenA); !bytes.Equal(got, unscopedAbsent) {
		t.Fatalf("scope B's record changed the unscoped answer:\n%s\n%s", got, unscopedAbsent)
	}
	if !bytes.Equal(bytes.TrimSpace(absent), unresolvedBody) {
		t.Fatalf("scope B's answer: %s", absent)
	}
	code, out := rawAct(t, h, h.scopedBody(strings.Repeat("3", 64), cite), h.tokenB)
	if code != http.StatusOK || receiptAction(t, out)["approvalsResolved"] != true {
		t.Fatalf("scope B, its own record: %d %s", code, out)
	}
}

// The bound: a record of exactly maxApprovalRecordBytes resolves, one byte
// more does not.
func TestTheApprovalRecordBound(t *testing.T) {
	h := approvalSetup(t)
	at := putRecord(t, h.gateway, approvalSingle, "at-bound", bytes.Repeat([]byte("b"), maxApprovalRecordBytes))
	if code, data := rawAct(t, h, h.unscoped(strings.Repeat("1", 64), at), h.tokenA); code != http.StatusOK {
		t.Fatalf("at the bound: %d %s", code, data)
	}
	over := putRecord(t, h.gateway, approvalSingle, "over-bound", bytes.Repeat([]byte("b"), maxApprovalRecordBytes+1))
	if code, data := rawAct(t, h, h.unscoped(strings.Repeat("2", 64), over), h.tokenA); code != http.StatusBadRequest || !bytes.Equal(bytes.TrimSpace(data), unresolvedBody) {
		t.Fatalf("one over the bound: %d %s", code, data)
	}
}

// With no directory named, a citation is the requester's claim, as before:
// it is not looked for, and the receipt carries no mark. With one named, an
// action that cites nothing carries no mark either.
func TestAGatewayWithoutTheDirectoryAnswersAsBefore(t *testing.T) {
	h := approvalSetup(t)
	nowhere := citationOf(approvalSingle, "..", digestOf("nothing"))
	h.g.approvalRecords = ""
	code, data := rawAct(t, h, h.unscoped(strings.Repeat("1", 64), nowhere), h.tokenA)
	if code != http.StatusOK {
		t.Fatalf("a claim with no directory: %d %s", code, data)
	}
	if _, marked := receiptAction(t, data)["approvalsResolved"]; marked {
		t.Fatalf("a claim is marked resolved: %s", data)
	}
	h.g.approvalRecords = h.gateway
	body := h.dryRunBody("act-u", "tickets", "", strings.Repeat("2", 64), h.decisionU, h.cite("u-read", h.unscopedSig), "")
	code, data = rawAct(t, h, body, h.tokenA)
	if code != http.StatusOK {
		t.Fatalf("no citation: %d %s", code, data)
	}
	action := receiptAction(t, data)
	if _, marked := action["approvalsResolved"]; marked || action["approvals"] != nil {
		t.Fatalf("an action citing nothing: %v", action)
	}
}

// Resolution is the gateway's fact and not the request's: a key reserved
// with no directory is replayed with one, and the reverse, and each is
// answered from its reservation, never as a conflict.
func TestTheActionKeyAndIdentityDoNotChangeWithResolution(t *testing.T) {
	h := approvalSetup(t)
	cite := putRecord(t, h.gateway, approvalSingle, "change-1", []byte("approved"))
	for i, order := range [][2]string{{"", h.gateway}, {h.gateway, ""}} {
		key := fmt.Sprintf("%064x", 100+i)
		h.g.approvalRecords = order[0]
		code, first := rawAct(t, h, h.unscoped(key, cite), h.tokenA)
		if code != http.StatusOK {
			t.Fatalf("%d: the first request: %d %s", i, code, first)
		}
		h.g.approvalRecords = order[1]
		code, again := rawAct(t, h, h.unscoped(key, cite), h.tokenA)
		if code != http.StatusOK || fmt.Sprint(receiptAction(t, again)) != fmt.Sprint(receiptAction(t, first)) {
			t.Fatalf("%d: the replay: %d %s\nfirst %s", i, code, again, first)
		}
		if n := actionKeysSent(h.root, key); n != 1 {
			t.Fatalf("%d: the target received %d writes", i, n)
		}
	}
	// and the identity is computed over the request's approvals alone
	approvals, err := requestApprovals(json.RawMessage(`[` + cite + `]`))
	if err != nil {
		t.Fatal(err)
	}
	before := canon(approvals)
	if err := resolveApprovals(h.gateway, approvals); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canon(approvals), before) {
		t.Fatal("resolution changed the approvals the key's content is computed over")
	}
}

// A dry-run resolves as the write does: a citation that does not resolve
// refuses it with the same answer, and one that does marks its receipt.
func TestADryRunResolvesItsApprovalCitations(t *testing.T) {
	h := approvalSetup(t)
	cite := putRecord(t, h.gateway, approvalSingle, "change-1", []byte("approved"))
	missing := citationOf(approvalSingle, "change-2", digestOf("approved"))
	dry := func(key, approvals string) (int, []byte) {
		return rawAct(t, h, h.dryRunBody("act-u", "tickets", "", key, h.decisionU, h.cite("u-read", h.unscopedSig), `,"dryRun":true,"approvals":[`+approvals+`]`), h.tokenA)
	}
	if code, data := dry(strings.Repeat("1", 64), missing); code != http.StatusBadRequest || !bytes.Equal(bytes.TrimSpace(data), unresolvedBody) {
		t.Fatalf("a dry-run with a citation that does not resolve: %d %s", code, data)
	}
	code, data := dry(strings.Repeat("2", 64), cite)
	if code != http.StatusOK {
		t.Fatalf("a dry-run that resolves: %d %s", code, data)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out["dryRun"].(map[string]any)["action"].(map[string]any)["approvalsResolved"] != true {
		t.Fatalf("the dry-run receipt is not marked: %s", data)
	}
	raw, _ := json.Marshal(out["dryRun"])
	if rep := verifyDryRun(raw, edKey(h.g.store.publicKey)); !rep.OK {
		t.Fatalf("verify-dry-run: %+v", rep)
	}
}

// The start holds an approval-record directory as it holds a
// decision-record directory, and it is there, a directory and no link.
func TestTheApprovalRecordDirectoryIsHeldAtStart(t *testing.T) {
	host := recordsHost(nil)
	dir := recordsTree(t, map[string]os.FileMode{"approvals": os.ModeDir | 0o700, "open": os.ModeDir | 0o777, "file": 0o600})
	if err := holdApprovalRecords(filepath.Join(dir, "approvals"), host); err != nil {
		t.Fatalf("a private directory: %v", err)
	}
	if err := os.Symlink(filepath.Join(dir, "approvals"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, want string }{
		{"absent", "the operator makes and fills it"},
		{"link", "is a symbolic link"},
		{"file", "is not a directory"},
		{"open", "is writable beyond its owner"},
	} {
		if err := holdApprovalRecords(filepath.Join(dir, c.name), host); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}
