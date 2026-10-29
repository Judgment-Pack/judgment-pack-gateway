package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The actual subprocess target records a committed mutation, then deliberately
// exits without an envelope. Its separate read operation reports that commit.
func TestActionReconciliationTarget(t *testing.T) {
	mode := os.Getenv("ACTION_TARGET_MODE")
	if mode == "" {
		return
	}
	var request struct {
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
		os.Exit(3)
	}
	path := os.Getenv("ACTION_TARGET_STATE")
	if mode == "write" || mode == "write-response" {
		key, _ := request.Arguments["request_id"].(string)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			os.Exit(4)
		}
		if _, err = fmt.Fprintln(f, key); err != nil {
			os.Exit(5)
		}
		if err = f.Sync(); err != nil {
			os.Exit(6)
		}
		f.Close()
		if mode == "write" {
			os.Exit(2)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		os.Exit(7)
	}
	key := ""
	wanted, _ := request.Arguments["key"].(string)
	if mode == "write-response" {
		wanted, _ = request.Arguments["request_id"].(string)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line == wanted {
			key = line
		}
	}
	fmt.Printf(`{"result":{"key":%q,"state":"done"},"acquisition":{"adapter":{"name":"fixture","version":"1","digest":"sha256:%s"},"endpoint":null,"statement":null,"snapshot":null,"peerIdentity":null,"schema":null,"upstreamToken":null,"observedAt":"2026-10-29T00:00:00Z"}}`, key, strings.Repeat("a", 64))
	os.Exit(0)
}

func TestActionReconciliationCommitThenDrop(t *testing.T) {
	if !actionJournalSupported {
		t.Skip("keyed dispatch fails closed on this host")
	}
	t.Setenv(envSourceHelper, "1")
	root := t.TempDir()
	target := filepath.Join(root, "target-state")
	recoveryValue, _ := parseJSON([]byte(recoveryDeclaration))
	binding := binding{write: &operation{tools: []string{"query", "sibling"}}, live: &operation{tools: []string{"query"}, taxonomies: map[string]ToolTaxonomy{"query": {Operation: "read", Effect: "read-external"}}}}
	recovery, err := parseActionRecovery(recoveryValue, binding)
	if err != nil {
		t.Fatal(err)
	}
	makeSource := func(mode string) sourceSpec {
		return sourceSpec{argv: []string{os.Args[0], "-test.run=^TestActionReconciliationTarget$"}, env: []string{"ACTION_TARGET_MODE=" + mode, "ACTION_TARGET_STATE=" + target}, shape: "mcp", tools: []string{"query"}, binding: "tickets@sha256:" + strings.Repeat("b", 64), actionRecovery: recovery}
	}
	sources := map[string]sourceSpec{"screening": {argv: []string{os.Args[0]}, env: helperEnv}, "tickets/write": makeSource("write"), "tickets/live": makeSource("read")}
	makeService := func() *gatewayService {
		g, err := newGatewayService(filepath.Join(root, "store"), testSeed, "gateway:test", filepath.Join(root, "registry.jsonl"), sources)
		if err != nil {
			t.Fatal(err)
		}
		g.decisionRecords = filepath.Join(root, "decisions")
		g.requireActionKey = true
		return g
	}
	g := makeService()
	who := &caller{issuer: "https://issuer.test", subject: "subject", tokenDigest: "sha256:" + strings.Repeat("c", 64)}
	first, err := g.acquire("read", "screening", newObject(), who)
	if err != nil {
		t.Fatal(err)
	}
	receipt := first["receipt"].(map[string]any)
	line := `{"kind":"evaluation","cites":[{"sessionId":"read","callIndex":0,"signature":"` + receipt["signature"].(string) + `"}]}`
	if err = os.Mkdir(g.decisionRecords, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(g.decisionRecords, "decision.json"), []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	decision := json.RawMessage(`{"recordDigest":"` + digestOf(line) + `","packDigest":"sha256:` + strings.Repeat("d", 64) + `"}`)
	cites := json.RawMessage(`[{"sessionId":"read","callIndex":0,"signature":"` + receipt["signature"].(string) + `"}]`)
	key := strings.Repeat("e", 64)
	call := func(g *gatewayService, session string, who *caller, args string) (map[string]any, error) {
		return g.act(json.RawMessage(`"`+session+`"`), json.RawMessage(`"tickets"`), json.RawMessage(`"query"`), json.RawMessage(args), decision, cites, who, json.RawMessage(`"`+key+`"`))
	}
	assertRead := func(out map[string]any, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		action := out["action"].(map[string]any)["receipt"].(map[string]any)
		recon := out["reconciliation"].(map[string]any)["receipt"].(map[string]any)
		member := recon["acquisition"].(map[string]any)["reconciliation"].(map[string]any)
		if member["outcome"] != "committed" || member["key"] != key || member["action"].(map[string]any)["signature"] != action["signature"] {
			t.Fatalf("uncorrelated evidence: %v", member)
		}
		for _, raw := range []map[string]any{action, recon} {
			b, _ := json.Marshal(raw)
			v, err := parseJSON(b)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = receiptFrom(v.(*vObject)); err != nil {
				t.Fatal(err)
			}
		}
	}
	beforeInvalid := g.started.Load()
	for _, raw := range []json.RawMessage{nil, json.RawMessage(`null`), json.RawMessage(`""`), json.RawMessage(`"` + strings.Repeat("a", 65) + `"`)} {
		_, err := g.act(json.RawMessage(`"invalid-key"`), json.RawMessage(`"tickets"`), json.RawMessage(`"query"`), json.RawMessage(`{"ticket":"T-1"}`), decision, cites, who, raw)
		if err == nil || !strings.Contains(err.Error(), "action-key") {
			t.Fatalf("invalid key accepted: %v", err)
		}
	}
	if g.started.Load() != beforeInvalid {
		t.Fatal("invalid action key reached a source")
	}
	assertRead(call(g, "act", who, `{"ticket":"T-1"}`))
	live := sources["tickets/live"]
	moved := live
	moved.endpoint = "https://other.example/read"
	sources["tickets/live"] = moved
	beforeMoved := g.started.Load()
	if _, err := call(g, "act", who, `{"ticket":"T-1"}`); err == nil || !strings.Contains(err.Error(), "action-key-conflict") {
		t.Fatalf("changed recovery source: %v", err)
	}
	if g.started.Load() != beforeMoved {
		t.Fatal("changed recovery source was called")
	}
	sources["tickets/live"] = live

	for _, boundary := range []*sourceSandbox{
		{helper: "helper", policy: "policy", workspace: "workspace", source: "tickets/live"},
		{helper: "other", policy: "policy", workspace: "workspace", source: "tickets/live"},
		{helper: "helper", policy: "other", workspace: "workspace", source: "tickets/live"},
		{helper: "helper", policy: "policy", workspace: "other", source: "tickets/live"},
		{helper: "helper", policy: "policy", workspace: "workspace", source: "other/live"},
	} {
		moved := live
		moved.sandbox = boundary
		sources["tickets/live"] = moved
		if _, err := call(g, "act", who, `{"ticket":"T-1"}`); err == nil || !strings.Contains(err.Error(), "action-key-conflict") {
			t.Fatalf("changed sandbox accepted: %v", err)
		}
		if g.started.Load() != beforeMoved {
			t.Fatal("changed sandbox reached read-back")
		}
	}
	sources["tickets/live"] = live

	renewed := *who
	renewed.tokenDigest = "sha256:" + strings.Repeat("f", 64)
	restarted := makeService()
	assertRead(call(restarted, "after-restart", &renewed, `{"ticket":"T-1"}`))
	if _, err = call(restarted, "conflict", who, `{"ticket":"T-2"}`); err == nil || !strings.Contains(err.Error(), "action-key-conflict") {
		t.Fatalf("changed payload: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			out, err := call(restarted, fmt.Sprintf("repeat-%d", i), who, `{"ticket":"T-1"}`)
			if err != nil || out["reconciliation"] == nil {
				t.Errorf("concurrent repeat: %v", err)
			}
		}(i)
	}
	wg.Wait()
	data, err := os.ReadFile(target)
	if err != nil || string(data) != key+"\n" {
		t.Fatalf("mutation executed more than once: %q %v", data, err)
	}
	for _, session := range []string{"read", "act"} {
		if _, err := g.sealSession(session); err != nil {
			t.Fatal(err)
		}
	}
	for _, session := range []string{"after-restart", "conflict", "repeat-0", "repeat-1", "repeat-2", "repeat-3"} {
		if _, err := restarted.sealSession(session); err != nil {
			t.Fatal(err)
		}
	}
	report, err := verifyWithRegistryAndRecords(g.storeRoot, g.regPath, g.authority, g.decisionRecords, g.publicKey)
	if err != nil || !report.OK {
		t.Fatalf("reconciled store does not verify: %+v %v", report, err)
	}
	testActionCorrelationMutations(t, g, "act", "after-restart")
	// A durable reservation left before dispatch is uncertain after restart;
	// even a negative read-back cannot authorize sending the mutation.
	key = strings.Repeat("2", 64)
	args, _ := parseJSON([]byte(`{"ticket":"T-1","request_id":"` + key + `"}`))
	decisionV, _ := parseJSON(decision)
	citesV, _ := parseJSON(cites)
	pending, err := openActionJournal(g.storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := pending.reserve(g.actionNamespace(who, key), actionFingerprint("tickets", "query", args, decisionV, citesV, sources["tickets/write"], recovery["query"], sources["tickets/live"]))
	if err != nil {
		t.Fatal(err)
	}
	claim.close()
	pending.close()
	afterCrash := makeService()
	unknown, err := call(afterCrash, "after-crash", who, `{"ticket":"T-1"}`)
	if err != nil {
		t.Fatal(err)
	}
	member := unknown["reconciliation"].(map[string]any)["receipt"].(map[string]any)["acquisition"].(map[string]any)["reconciliation"].(map[string]any)
	if member["outcome"] != "unknown" {
		t.Fatal("absent correlated key became committed")
	}
	if data, err := os.ReadFile(target); err != nil || strings.Count(string(data), "\n") != 1 {
		t.Fatal("restart of a reserved action dispatched a second mutation")
	}

	// A complete executor response is replayed without calling either operation.
	key = strings.Repeat("1", 64)
	sources["tickets/write"] = makeSource("write-response")
	completed := makeService()
	firstResponse, err := call(completed, "complete", who, `{"ticket":"T-1"}`)
	if err != nil {
		t.Fatal(err)
	}
	before := completed.started.Load()
	secondResponse, err := call(completed, "complete-again", &renewed, `{"ticket":"T-1"}`)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(firstResponse)
	b, _ := json.Marshal(secondResponse)
	if string(a) != string(b) || completed.started.Load() != before {
		t.Fatal("completed action was not replayed exactly without a target call")
	}
	// No response is valid when its signed receipt has been altered in the journal.
	journal, err := openActionJournal(g.storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.close()
	namespace := g.actionNamespace(who, key)
	path := filepath.Join(g.storeRoot, "actions", namespace, "action.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cached map[string]any
	if err = json.Unmarshal(raw, &cached); err != nil {
		t.Fatal(err)
	}
	cached["receipt"].(map[string]any)["source"] = "altered"
	raw, _ = json.Marshal(cached)
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = call(completed, "tampered-cache", who, `{"ticket":"T-1"}`); err == nil || !strings.Contains(err.Error(), "action-journal-invalid") {
		t.Fatalf("tampered cached receipt: %v", err)
	}
	if completed.started.Load() != before {
		t.Fatal("corrupt cache repeated a target call")
	}
	// An unsupported binding still prevents replay and returns its action evidence.
	key = strings.Repeat("3", 64)
	unsupported := makeSource("write")
	unsupported.actionRecovery = nil
	sources["tickets/write"] = unsupported
	noRecovery := makeService()
	_, err = call(noRecovery, "unsupported", who, `{"ticket":"T-1"}`)
	uncertain, ok := err.(*actionUncertain)
	if !ok || uncertain.reason != "action-reconciliation-unavailable" || uncertain.action["receipt"] == nil {
		t.Fatalf("unsupported recovery: %v", err)
	}
	before = noRecovery.started.Load()
	_, err = call(noRecovery, "unsupported-again", who, `{"ticket":"T-1"}`)
	if _, ok = err.(*actionUncertain); !ok || noRecovery.started.Load() != before {
		t.Fatal("unsupported recovery repeated a mutation")
	}

}

func testActionCorrelationMutations(t *testing.T, g *gatewayService, actionSession, readSession string) {
	t.Helper()
	actionPath := filepath.Join(g.storeRoot, "receipts", actionSession, "0.json")
	readPath := filepath.Join(g.storeRoot, "receipts", readSession, "0.json")
	originalAction, err := os.ReadFile(actionPath)
	if err != nil {
		t.Fatal(err)
	}
	originalRead, err := os.ReadFile(readPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"key", "contract", "signature", "session", "index", "identity", "response", "missing", "tampered"} {
		t.Run("correlation/"+mutation, func(t *testing.T) {
			av, _ := parseJSON(originalAction)
			a := av.(*vObject)
			rv, _ := parseJSON(originalRead)
			r := rv.(*vObject)
			acquisition, _ := r.get("acquisition")
			raw, _ := acquisition.(*vObject).get("reconciliation")
			recon := raw.(*vObject)
			raw, _ = recon.get("action")
			cite := raw.(*vObject)
			resign := func(o *vObject) {
				receipt, err := receiptFrom(o)
				if err != nil {
					t.Fatal(err)
				}
				signature := ed25519.Sign(g.store.private, receipt.signingInput())
				o.set("signature", vString(hex.EncodeToString(signature)))
			}
			switch mutation {
			case "key":
				recon.set("key", vString(strings.Repeat("c", 64)))
			case "contract":
				recon.set("contract", vString("sha256:"+strings.Repeat("c", 64)))
			case "signature":
				cite.set("signature", vString(testSig3))
			case "session":
				cite.set("sessionId", vString("read"))
			case "index":
				cite.set("callIndex", vInt(1))
			case "identity":
				raw, _ := r.get("caller")
				raw.(*vObject).set("subject", vString("other"))
			case "response":
				raw, _ := a.get("action")
				raw, _ = raw.(*vObject).get("delivery")
				raw.(*vObject).set("outcome", vString("response"))
				resign(a)
				signature, _ := a.get("signature")
				cite.set("signature", signature)
			case "tampered":
				a.set("source", vString("tampered"))
			}
			resign(r)
			if err := os.WriteFile(readPath, canon(r), 0600); err != nil {
				t.Fatal(err)
			}
			if mutation == "missing" {
				err = os.Remove(actionPath)
			} else {
				err = os.WriteFile(actionPath, canon(a), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			report, err := verifyWithRegistryAndRecords(g.storeRoot, g.regPath, g.authority, g.decisionRecords, g.publicKey)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, f := range report.Findings {
				if f["sessionId"] == readSession && f["status"] == "action-reconciliation-unresolved" {
					found = true
				}
			}
			if !found {
				t.Fatalf("missing correlation refusal: %+v", report)
			}
			if err = os.WriteFile(actionPath, originalAction, 0600); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(readPath, originalRead, 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
}
