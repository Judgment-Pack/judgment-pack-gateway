package main

// Session labels (ADR-0051): the session a caller names is a label in its
// scope's namespace, mapped to a session id the gateway mints.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// labelRecorder is what a store's labels were looked up under: each
// namespace and label read, in order.
type labelRecorder struct {
	mu     sync.Mutex
	looked []string
}

func (r *labelRecorder) note(scope, label string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.looked = append(r.looked, scope+"|"+label)
}

func (r *labelRecorder) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.looked
	r.looked = nil
	return out
}

// labelledStore is a gateway at labelsVersion over a new store, with a
// source fixed to testScope ("a"), one to otherScope ("b") and one to none
// ("plain"), and the recorder its labels' lookups are told to.
func labelledStore(t *testing.T) (*gatewayService, *httptest.Server, *labelRecorder) {
	t.Helper()
	t.Setenv(envSourceHelper, "1")
	t.Setenv(envSourceEchoStdin, "1")
	root := t.TempDir()
	g, err := newGatewayService(filepath.Join(root, "store"), testSeed, "gateway:test", filepath.Join(root, "registry.jsonl"),
		map[string]sourceSpec{
			"a":     {argv: []string{os.Args[0]}, env: helperEnv, scope: testScope},
			"b":     {argv: []string{os.Args[0]}, env: helperEnv, scope: otherScope},
			"plain": {argv: []string{os.Args[0]}, env: helperEnv},
		})
	if err != nil {
		t.Fatal(err)
	}
	rec := &labelRecorder{}
	g.labels = fsLabels{root: g.storeRoot, looked: rec.note}
	server := httptest.NewServer(g.handler())
	t.Cleanup(server.Close)
	return g, server, rec
}

// labelAcquire acquires under a label from the source of the scope ("" for
// plain), and is the receipt's session id, held to be a minted one.
func labelAcquire(t *testing.T, server *httptest.Server, label, source, scope string) (string, float64) {
	t.Helper()
	body := `{"session":"` + label + `","source":"` + source + `","arguments":{"q":"x"}}`
	if scope != "" {
		body = `{"session":"` + label + `","source":"` + source + `","scope":` + jsonText(t, scope) + `,"arguments":{"q":"x"}}`
	}
	code, out := post(t, server, "/acquire", body)
	if code != http.StatusOK {
		t.Fatalf("acquire %s: %d %v", body, code, out)
	}
	receipt := out["receipt"].(map[string]any)
	id, _ := receipt["sessionId"].(string)
	if !mintedSessionPattern.MatchString(id) {
		t.Fatalf("the receipt's session id is not a minted one: %q", id)
	}
	return id, receipt["callIndex"].(float64)
}

func labelSeal(t *testing.T, server *httptest.Server, label, scope string) (int, []byte) {
	t.Helper()
	body := `{"session":"` + label + `"}`
	if scope != "" {
		body = `{"session":"` + label + `","scope":` + jsonText(t, scope) + `}`
	}
	return postRawWith(t, server, "/seal", body, "")
}

// One label in two scopes and in none is three sessions, each of a minted
// id that is not the label, each sealed in its own namespace, and the store
// verifies; a second call under the label continues its scope's session.
func TestTwoScopesUseOneLabelAndGetTwoSessions(t *testing.T) {
	g, server, _ := labelledStore(t)
	ofA, _ := labelAcquire(t, server, "nightly-1", "a", testScope)
	ofB, _ := labelAcquire(t, server, "nightly-1", "b", otherScope)
	ofNone, _ := labelAcquire(t, server, "nightly-1", "plain", "")
	if ofA == ofB || ofA == ofNone || ofB == ofNone {
		t.Fatalf("one label in three namespaces named one session: %s %s %s", ofA, ofB, ofNone)
	}
	if again, index := labelAcquire(t, server, "nightly-1", "a", testScope); again != ofA || index != 1 {
		t.Fatalf("the label's second call in A: %s at %v, not %s at 1", again, index, ofA)
	}
	for _, tc := range []struct{ scope, id string }{{testScope, ofA}, {otherScope, ofB}, {"", ofNone}} {
		code, raw := labelSeal(t, server, "nightly-1", tc.scope)
		var record map[string]any
		if code != http.StatusOK || json.Unmarshal(raw, &record) != nil || record["sessionId"] != tc.id {
			t.Fatalf("the seal of the label in %q: %d %s, not %s", tc.scope, code, raw, tc.id)
		}
	}
	// a label whose session is sealed is refused as a sealed session is
	if code, out := post(t, server, "/acquire", `{"session":"nightly-1","source":"plain","arguments":{}}`); code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(out["error"]), "sealed") {
		t.Fatalf("an acquisition under a sealed label: %d %v", code, out)
	}
	rep, err := verifyWithRegistry(g.storeRoot, g.regPath, g.authority, g.publicKey)
	if err != nil || !rep.OK {
		t.Fatalf("the store: %v %+v", err, rep)
	}
}

// What a caller of scope B is answered under a label is the same whether
// or not scope A uses it: the same code and the same body for a seal, a
// first receipt for an acquisition, and no lookup outside B's namespace. A
// label not in the namespace is answered no such session with the registry
// not read: one that cannot be read changes nothing of the answer.
func TestScopeBIsAnsweredTheSameWhetherOrNotScopeAUsesALabel(t *testing.T) {
	answers := map[bool][]string{}
	for _, aUses := range []bool{false, true} {
		g, server, rec := labelledStore(t)
		if aUses {
			labelAcquire(t, server, "shared", "a", testScope)
			if code, raw := labelSeal(t, server, "shared", testScope); code != http.StatusOK {
				t.Fatalf("A's seal: %d %s", code, raw)
			}
		}
		rec.take()
		code, raw := labelSeal(t, server, "shared", otherScope)
		noneCode, noneRaw := labelSeal(t, server, "shared", "")
		// the registry made unreadable: a label not in the namespace is
		// answered without it
		if err := os.Rename(g.regPath, g.regPath+".away"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(g.regPath, 0o700); err != nil {
			t.Fatal(err)
		}
		awayCode, awayRaw := labelSeal(t, server, "shared", otherScope)
		os.Remove(g.regPath)
		if err := os.Rename(g.regPath+".away", g.regPath); err != nil {
			t.Fatal(err)
		}
		if awayCode != code || !bytes.Equal(awayRaw, raw) {
			t.Fatalf("with the registry unreadable B's seal changed: %d %s, not %d %s", awayCode, awayRaw, code, raw)
		}
		_, index := labelAcquire(t, server, "shared", "b", otherScope)
		for _, looked := range rec.take() {
			if !strings.HasPrefix(looked, otherScope+"|") && looked != "|shared" {
				t.Fatalf("B's calls read another namespace's label: %s", looked)
			}
		}
		answers[aUses] = []string{fmt.Sprint(code), string(raw), fmt.Sprint(noneCode), string(noneRaw), fmt.Sprint(index)}
	}
	if strings.Join(answers[false], "\n") != strings.Join(answers[true], "\n") {
		t.Fatalf("B's answers depend on A's use of the label:\n%q\n%q", answers[false], answers[true])
	}
	if answers[true][0] != "400" || !strings.Contains(answers[true][1], "no such session: shared") || answers[true][4] != "0" {
		t.Fatalf("B's answers: %q", answers[true])
	}
}

// Two writers racing on one new label each with an id of its own agree on
// one: the one whose file is in the store first.
func TestTwoWritersRacingOnALabelAgreeOnOneID(t *testing.T) {
	root := t.TempDir()
	const writers = 8
	got := make([]string, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id, _ := mintSessionID()
			recorded, err := fsLabels{root: root}.recordLabel(testScope, "race", id)
			if err != nil {
				t.Error(err)
			}
			got[i] = recorded
		}(i)
	}
	wg.Wait()
	for _, id := range got {
		if id != got[0] || id == "" {
			t.Fatalf("the writers recorded %v", got)
		}
	}
	if id, err := (fsLabels{root: root}).labelSession(testScope, "race"); err != nil || id != got[0] {
		t.Fatalf("the label reads %q %v", id, err)
	}
}

// A crash after a label's file is in the store and before its session's
// first receipt leaves a mapping with no receipts: the label's next use
// takes its id up, at callIndex 0.
func TestACrashAfterTheLabelBeforeTheReceiptReusesTheID(t *testing.T) {
	g, server, _ := labelledStore(t)
	id, _ := mintSessionID()
	if _, err := g.labels.recordLabel(testScope, "after-crash", id); err != nil {
		t.Fatal(err)
	}
	if got, index := labelAcquire(t, server, "after-crash", "a", testScope); got != id || index != 0 {
		t.Fatalf("the label after a crash: %s at %v, not %s at 0", got, index, id)
	}
}

// A label file that is not the gateway's form is a refusal, never a label
// taken for unused.
func TestALabelFileOutOfFormIsRefused(t *testing.T) {
	g, server, _ := labelledStore(t)
	id, _ := labelAcquire(t, server, "kept", "a", testScope)
	path := filepath.Join(g.storeRoot, labelsDir, labelFileName(testScope, "kept"))
	if err := os.WriteFile(path, bytes.Replace(labelFileBytes(testScope, "kept", id), []byte(id), []byte(strings.Repeat("0", 32)), 1)[:40], 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := post(t, server, "/acquire", `{"session":"kept","source":"a","scope":`+jsonText(t, testScope)+`,"arguments":{}}`)
	if code == http.StatusOK || !strings.Contains(fmt.Sprint(out["error"]), "its label could not be read") {
		t.Fatalf("a torn label: %d %v", code, out)
	}
}

// After remove-scope a label of the scope is free: its file goes with the
// scope's sessions, and its next use mints a new id; another scope's label
// stays.
func TestAfterRemoveScopeALabelIsFreeAndMintsANewID(t *testing.T) {
	g, seedPath := scopeStore(t)
	g.labels = fsLabels{root: g.storeRoot}
	server := httptest.NewServer(g.handler())
	defer server.Close()
	removed, _ := labelAcquire(t, server, "job", "a", testScope)
	kept, _ := labelAcquire(t, server, "job", "b", otherScope)
	if code, raw := labelSeal(t, server, "job", testScope); code != http.StatusOK {
		t.Fatalf("seal: %d %s", code, raw)
	}
	if code, stdout, stderr := removeScopeOn(t, g, seedPath, "--scope", testScope, "--by", "operator-1"); code != 0 {
		t.Fatalf("remove-scope: %d %q %q", code, stdout, stderr)
	}
	if exists(filepath.Join(g.storeRoot, labelsDir, labelFileName(testScope, "job"))) || !exists(filepath.Join(g.storeRoot, labelsDir, labelFileName(otherScope, "job"))) {
		t.Fatal("remove-scope did not take the scope's label alone")
	}
	if again, index := labelAcquire(t, server, "job", "a", testScope); again == removed || index != 0 {
		t.Fatalf("the label after the removal: %s at %v", again, index)
	}
	if again, _ := labelAcquire(t, server, "job", "b", otherScope); again != kept {
		t.Fatalf("the other scope's label moved: %s, not %s", again, kept)
	}
}

// After retain removes a session its label is free, and mints a new id.
func TestAfterRetainALabelIsFreeAndMintsANewID(t *testing.T) {
	g, config := retainStore(t)
	g.labels = fsLabels{root: g.storeRoot}
	server := httptest.NewServer(g.handler())
	defer server.Close()
	removed, _ := labelAcquire(t, server, "nightly", "a", testScope)
	if code, raw := labelSeal(t, server, "nightly", testScope); code != http.StatusOK {
		t.Fatalf("seal: %d %s", code, raw)
	}
	s := sealOf(t, g.regPath, g.publicKey, removed)
	acks := writeAcks(t, retentionAckLine(retentionAckKey, removed, s.signature, s.finalCount, stampOf(sealTime(t, s).Add(time.Hour))))
	if code, stdout, stderr := runRetain(config, acks, sealTime(t, s).Add(31*24*time.Hour)); code != 0 || !strings.Contains(stdout, removed) {
		t.Fatalf("retain: %d %q %q", code, stdout, stderr)
	}
	if exists(filepath.Join(g.storeRoot, labelsDir, labelFileName(testScope, "nightly"))) {
		t.Fatal("retain left the label of the session it removed")
	}
	if again, index := labelAcquire(t, server, "nightly", "a", testScope); again == removed || index != 0 {
		t.Fatalf("the label after retention: %s at %v", again, index)
	}
}

// From labelsVersion the start refuses while the store holds a session
// open that no label names, naming gateway seal-open --all; a labelled
// session left open does not refuse it.
func TestTheStartRefusesWhileASessionNamedBeforeLabelsIsOpen(t *testing.T) {
	g, server, _ := labelledStore(t)
	labelAcquire(t, server, "left-open", "a", testScope)
	if err := labelsAtStart(g); err != nil {
		t.Fatalf("a labelled session left open refused the start: %v", err)
	}
	keeper := g.labels
	g.labels = nil
	if code, out := post(t, server, "/acquire", `{"session":"named-1","source":"plain","arguments":{}}`); code != http.StatusOK {
		t.Fatalf("an acquisition by name: %d %v", code, out)
	}
	g.labels = keeper
	err := labelsAtStart(g)
	if err == nil || !strings.Contains(err.Error(), "sealed before the upgrade: stop the gateway, run gateway seal-open --all") || !strings.Contains(err.Error(), "(named-1)") {
		t.Fatalf("the start beside a session named before labels: %v", err)
	}
	g.labels = nil
	if err := labelsAtStart(g); err != nil {
		t.Fatalf("a start before labelsVersion: %v", err)
	}
}

// labelsConfig is an engine configuration of the version over the store.
func labelsConfig(t *testing.T, version string, g *gatewayService) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "engine.json")
	body := fmt.Sprintf(`{"engineVersion":%q,"authority":"gateway:test","seed":%q,"store":%q,"registry":%q,"decisionRecords":%q,"listen":"127.0.0.1:8787","catalog":%q,"platforms":{}}`,
		version, filepath.Join(dir, "seed"), g.storeRoot, g.regPath, filepath.Join(dir, "decisions"), filepath.Join(dir, "catalog"))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// At version 38 and below nothing changes: the configuration reads no
// labels, the name a request sends is the session id, no labels/ is made,
// and gateway sessions refuses the configuration.
func TestAtVersion38AndBelowNothingChanges(t *testing.T) {
	g, server, _ := labelledStore(t)
	for version, on := range map[string]bool{"38": false, "1": false, labelsVersion: true} {
		data, _ := os.ReadFile(labelsConfig(t, version, g))
		cfg, err := parseEngineConfig(data)
		if err != nil {
			t.Fatal(err)
		}
		opts := engineServeOptions(cfg, nil, nil)
		g.labels = nil
		applyServeOptions(g, opts)
		if opts.labels != on || (g.labels != nil) != on {
			t.Fatalf("version %s reads labels: %v %v", version, opts.labels, g.labels)
		}
	}
	g.labels = nil
	code, out := post(t, server, "/acquire", `{"session":"by-name","source":"plain","arguments":{}}`)
	if code != http.StatusOK || out["receipt"].(map[string]any)["sessionId"] != "by-name" || exists(filepath.Join(g.storeRoot, labelsDir)) {
		t.Fatalf("an acquisition before labels: %d %v", code, out)
	}
	var stdout, stderr bytes.Buffer
	if code := cmdSessions([]string{"--config", labelsConfig(t, "38", g), "--no-scope"}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "labels are read from engineVersion 39") {
		t.Fatalf("gateway sessions at 38: %d %q", code, stderr.String())
	}
}

// gateway sessions prints a namespace's labels and their session ids, and
// one label's line with --label, reading nothing of the other namespaces.
func TestGatewaySessionsPrintsANamespacesLabels(t *testing.T) {
	g, server, _ := labelledStore(t)
	first, _ := labelAcquire(t, server, "job-a", "a", testScope)
	second, _ := labelAcquire(t, server, "job-b", "a", testScope)
	labelAcquire(t, server, "job-a", "b", otherScope)
	plain, _ := labelAcquire(t, server, "job-a", "plain", "")
	config := labelsConfig(t, labelsVersion, g)
	run := func(args ...string) (int, string) {
		var stdout, stderr bytes.Buffer
		code := cmdSessions(append([]string{"--config", config}, args...), &stdout, &stderr)
		return code, stdout.String() + stderr.String()
	}
	if code, out := run("--scope", testScope); code != 0 || out != "job-a "+first+"\njob-b "+second+"\n" {
		t.Fatalf("the namespace of A: %d %q", code, out)
	}
	if code, out := run("--no-scope", "--label", "job-a"); code != 0 || out != "job-a "+plain+"\n" {
		t.Fatalf("a label of none: %d %q", code, out)
	}
	// --scope none names the scope identifier "none", which holds no label
	if code, out := run("--scope", "none"); code != 0 || out != "" {
		t.Fatalf("the scope identifier none: %d %q", code, out)
	}
	if code, _ := run("--scope", testScope, "--no-scope"); code != 2 {
		t.Fatalf("a scope beside --no-scope: %d", code)
	}
	if code, _ := run("--scope", testScope, "--label", "absent"); code != 1 {
		t.Fatalf("an absent label: %d", code)
	}
	if code, _ := run("--scope", "../x", "--label", "a/b"); code != 2 {
		t.Fatalf("a label out of form: %d", code)
	}
}

// A store holding labels/ verifies as the same store without it: the
// verifiers pass it over (SPEC.md §3a).
func TestAStoreHoldingLabelsVerifiesAsTheSameStoreWithout(t *testing.T) {
	g, server, _ := labelledStore(t)
	labelAcquire(t, server, "v-1", "a", testScope)
	labelAcquire(t, server, "v-1", "plain", "")
	if code, raw := labelSeal(t, server, "v-1", testScope); code != http.StatusOK {
		t.Fatalf("seal: %d %s", code, raw)
	}
	verdict := func() string {
		rep, err := verifyWithRegistry(g.storeRoot, g.regPath, g.authority, g.publicKey)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := json.Marshal(rep)
		return string(out)
	}
	with := verdict()
	if err := os.RemoveAll(filepath.Join(g.storeRoot, labelsDir)); err != nil {
		t.Fatal(err)
	}
	if without := verdict(); without != with {
		t.Fatalf("the store with labels/:\n%s\nwithout:\n%s", with, without)
	}
}

// The caller form's seal tool takes a scope from labelsVersion: a label in
// the namespace it names is sealed, one the token does not reach is refused
// before anything is forwarded, and without the version the member is
// refused as before.
func TestTheCallerFormSealToolTakesAScope(t *testing.T) {
	f := scopedMCPFixture(t, mcpConfig{scopeFromCaller: true})
	f.token = tokenFor(t, f.issuer, subjectEvery, nil)
	sid := f.open(t)
	withScope := `{"session":"front-1","scope":"` + callerScopeA + `"}`
	if raw := f.rawCall(t, sid, toolCall(3, mcpSealTool, withScope, "")); !bytes.Contains(raw, []byte("takes {session} and no other member")) {
		t.Fatalf("a scope before labelsVersion: %s", raw)
	}
	f.server.cfg.version = labelsVersion
	f.service.labels = fsLabels{root: f.service.storeRoot}
	_, _, body := f.call(t, http.MethodPost, sid, toolCall(4, "a.lookup", `{}`, `{"`+mcpSessionMeta+`":"front-1"}`), nil)
	acquired(t, body)
	if raw := f.rawCall(t, sid, toolCall(5, mcpSealTool, `{"session":"front-1"}`, "")); !bytes.Contains(raw, []byte("no such session: front-1")) {
		t.Fatalf("the label sealed in none: %s", raw)
	}
	_, _, body = f.call(t, http.MethodPost, sid, toolCall(6, mcpSealTool, withScope, ""), nil)
	if record := sameBothWays(t, resultOf(t, body)); !mintedSessionPattern.MatchString(fmt.Sprint(record["sessionId"])) || record["finalCount"] != float64(1) {
		t.Fatalf("the label sealed in A: %v", record)
	}
	f.token = tokenFor(t, f.issuer, subjectB, []any{callerScopeB})
	sid = f.open(t)
	if raw := f.rawCall(t, sid, toolCall(7, mcpSealTool, withScope, "")); !bytes.Contains(raw, []byte("a scope identifier this caller's token reaches")) {
		t.Fatalf("a scope the token does not reach: %s", raw)
	}
	// at the signer, the caller of B naming A is answered no such session,
	// and nothing of A's namespace is read
	rec := &labelRecorder{}
	f.service.labels = fsLabels{root: f.service.storeRoot, looked: rec.note}
	code, raw := postRawWith(t, f.signer, "/seal", withScope, f.token)
	if code != http.StatusBadRequest || !bytes.Contains(raw, []byte("no such session: front-1")) || len(rec.take()) != 0 {
		t.Fatalf("a caller of B sealing in A's namespace: %d %s", code, raw)
	}
}

// remove-scope cut off after its records, with a labelled session of the
// scope open, leaves no label naming the session it removes: the label's
// next use mints a new id, before the rerun completes the removal and
// after it, and never names the removed session again.
func TestARemovalCutOffLeavesNoLabelNamingARemovedOpenSession(t *testing.T) {
	g, seedPath := scopeStore(t)
	g.labels = fsLabels{root: g.storeRoot}
	server := httptest.NewServer(g.handler())
	defer server.Close()
	removed, _ := labelAcquire(t, server, "open-job", "a", testScope)
	removalCutOff = func() error { return errors.New("cut off") }
	code, stdout, stderr := removeScopeOn(t, g, seedPath, "--scope", testScope, "--by", "operator-1")
	removalCutOff = nil
	if code == 0 || !strings.Contains(stderr, "cut off; the records stand") {
		t.Fatalf("the run cut off: %d %q %q", code, stdout, stderr)
	}
	if again, index := labelAcquire(t, server, "open-job", "a", testScope); again == removed || index != 0 {
		t.Fatalf("the label after a removal cut off: %s at %v, the removed session %s", again, index, removed)
	}
	if code, stdout, stderr := removeScopeOn(t, g, seedPath, "--scope", testScope, "--by", "operator-1"); code != 0 {
		t.Fatalf("the rerun: %d %q %q", code, stdout, stderr)
	}
	if again, index := labelAcquire(t, server, "open-job", "a", testScope); again == removed || index != 0 {
		t.Fatalf("the label after the rerun: %s at %v, the removed session %s", again, index, removed)
	}
}

// /act reads its session as a label in the namespace of none: the action
// is minted into the session the label names there, after the acquisition
// it cites, and cites[].sessionId is the minted id.
func TestActUnderALabel(t *testing.T) {
	image := "--image=x@sha256:" + strings.Repeat("0", 64)
	service, server := testService(t)
	service.labels = fsLabels{root: service.storeRoot}
	env, _ := goodEnvelope()
	t.Setenv(envSourceEnvelope, envelopeText(t, env))
	service.sources["boards/write"] = sourceSpec{argv: []string{os.Args[0], image, "--tools=update"}, env: helperEnv, tools: []string{"update"}, shape: "mcp", endpoint: "h"}
	service.decisionRecords = t.TempDir()
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	service.identity = &id
	token := issuer.mint(t, "ec-1", nil, goodClaims(time.Now()))
	code, first := authed(t, server, "/acquire", `{"session":"act-label","source":"screening","arguments":{"q":"example"}}`, token)
	if code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, first)
	}
	receipt := first["receipt"].(map[string]any)
	minted, signature := receipt["sessionId"].(string), receipt["signature"].(string)
	if !mintedSessionPattern.MatchString(minted) {
		t.Fatalf("the acquisition's session: %q", minted)
	}
	cite := `{"sessionId":"` + minted + `","callIndex":0,"signature":"` + signature + `"}`
	line := `{"kind":"evaluation","cites":[` + cite + `]}`
	if err := os.WriteFile(filepath.Join(service.decisionRecords, "evaluations.jsonl"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	body := `{"session":"act-label","platform":"boards","tool":"update","arguments":{"id":42},` +
		`"decision":{"recordDigest":"sha256:` + hexOf([]byte(line)) + `","packDigest":"sha256:` + strings.Repeat("b", 64) + `"},"cites":[` + cite + `]}`
	code, acted := authed(t, server, "/act", body, token)
	if code != http.StatusOK {
		t.Fatalf("act: %d %v", code, acted)
	}
	if got := fmt.Sprint(acted["receipt"].(map[string]any)["sessionId"], "/", acted["receipt"].(map[string]any)["callIndex"]); got != minted+"/1" {
		t.Fatalf("the action receipt is at %s, not %s/1", got, minted)
	}
	if exists(filepath.Join(service.storeRoot, "receipts", "act-label")) {
		t.Fatal("the label was taken for a session id")
	}
}

// serve --config's start on the filesystem kind (startOnStore, the start
// cmdServeEngine runs once the platforms' isolation holds) refuses a
// configuration at labelsVersion over a store holding a session open that
// no label names, naming what the operator does, and releases its holds; at
// version 38 the same store starts.
func TestTheStartAtLabelsVersionRefusesASessionLeftFromBefore(t *testing.T) {
	g, server, _ := labelledStore(t)
	g.labels = nil
	if code, out := post(t, server, "/acquire", `{"session":"named-1","source":"plain","arguments":{}}`); code != http.StatusOK {
		t.Fatalf("an acquisition by name: %d %v", code, out)
	}
	server.Close()
	seedPath := writeSeedFile(t, t.TempDir(), testSeed)
	start := func(version string) (*gatewayService, func(), error) {
		data, _ := os.ReadFile(labelsConfig(t, version, g))
		cfg, err := parseEngineConfig(data)
		if err != nil {
			t.Fatal(err)
		}
		cfg.seed = seedPath
		return startOnStore(cfg, testSeed, []string{seedPath}, engineServeOptions(cfg, nil, nil))
	}
	_, _, err := start(labelsVersion)
	if err == nil || !strings.Contains(err.Error(), "engine configuration version 39") || !strings.Contains(err.Error(), "(named-1); such a session is sealed before the upgrade: stop the gateway, run gateway seal-open --all") {
		t.Fatalf("the start at version 39: %v", err)
	}
	// the holds were released: the same store starts at version 38
	service, closeHolds, err := start("38")
	if err != nil || service.labels != nil {
		t.Fatalf("the start at version 38: %v", err)
	}
	closeHolds()
}

// remove-scope takes the labels of a scope that holds labels and no
// session, as a label minted for a source that failed leaves, and leaves
// every other namespace's.
func TestRemoveScopeTakesTheLabelsOfAScopeWithNoSession(t *testing.T) {
	g, seedPath := scopeStore(t)
	keeper := fsLabels{root: g.storeRoot}
	orphan, err := mintSessionID()
	if err != nil {
		t.Fatal(err)
	}
	kept, err := mintSessionID()
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range [][2]string{{"scope-c", orphan}, {otherScope, kept}} {
		if _, err := keeper.recordLabel(l[0], "failed-run", l[1]); err != nil {
			t.Fatal(err)
		}
	}
	code, stdout, stderr := removeScopeOn(t, g, seedPath, "--scope", "scope-c", "--by", "operator-1")
	if code != 0 || !strings.Contains(stdout+stderr, "its 1 session label(s), naming no session, are removed") {
		t.Fatalf("remove-scope: %d %q %q", code, stdout, stderr)
	}
	if id, err := keeper.labelSession("scope-c", "failed-run"); err != nil || id != "" {
		t.Fatalf("the scope's label after the removal: %q %v", id, err)
	}
	if id, err := keeper.labelSession(otherScope, "failed-run"); err != nil || id != kept {
		t.Fatalf("another scope's label after the removal: %q %v", id, err)
	}
}
