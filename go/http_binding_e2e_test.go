package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// buildAdapterInto builds one adapter of the adapters module into bin.
func buildAdapterInto(t *testing.T, bin, name string) string {
	t.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain on PATH")
	}
	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	out := filepath.Join(bin, name+exe)
	build := exec.Command(goTool, "build", "-buildvcs=false", "-o", out, "./cmd/"+name)
	build.Dir = filepath.Join("..", "adapters")
	build.Env = append(os.Environ(), "GOWORK=off")
	if text, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building %s: %v\n%s", name, err, text)
	}
	return out
}

// memberNames is an object's member names, sorted.
func memberNames(obj map[string]any) []string {
	names := make([]string, 0, len(obj))
	for name := range obj {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// From a configuration to a receipt through an HTTP API (gateway #384,
// ADR-0024): the engine derives records/live from a binding of the http
// shape and runs the real adapter-http against a stand-in API served here
// on loopback; the API answers only with the credential the adapter read
// from the platform's file; the receipt is the one the plain form mints for
// the same request, member for member; an action on another platform's
// write cites it; and the store, the registry and the records verify. On
// the way: a caller with no token and a delegated caller, with a
// delegation credential or without, are refused before the adapter runs,
// so is a path the binding does not name, /act
// does not dispatch to the http platform, and the adapter's check of the
// source reads as connect reads it. The platforms' users are stripped
// before the service is built, as in the MCP end-to-end test: the
// switching is proved where it is implemented.
func TestEngineConfigDrivesTheHTTPAdapterEndToEnd(t *testing.T) {
	dir := t.TempDir()
	bin, fake := buildMCPStandIns(t, dir)
	adapter := buildAdapterInto(t, bin, "adapter-http")
	var hits atomic.Int64
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Authorization") != "Bearer api-secret" || r.Header.Get("Accept") != "application/json" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/health":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/search":
			if body, _ := io.ReadAll(r.Body); string(body) != `{"q":"claims"}` {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", `"records-7"`)
			io.WriteString(w, `{"items":[{"id":"r-1","title":"Claim policy"}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer api.Close()
	recordsCredentials := filepath.Join(dir, "records.json")
	if err := os.WriteFile(recordsCredentials, []byte(`{"API_TOKEN":"api-secret","OTHER":"not-sent"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	warehouseCredentials := filepath.Join(dir, "warehouse.json")
	if err := os.WriteFile(warehouseCredentials, []byte(`{"SERVICE_TOKEN":"secret-token"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	records := `{"bindingVersion":"1","platform":"records","operations":{"live":{"shape":"http","endpoint":"` + api.URL + `","paths":["/search","/health"],` +
		`"methods":["GET","POST"],"headers":["Accept=application/json"],"bearer":"API_TOKEN","checkPath":"/health","licence":"Apache-2.0"}}}`
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding, "records": records})
	escape := func(p string) string { return strings.ReplaceAll(p, `\`, `\\`) }
	text := `{"engineVersion":"1","authority":"gateway:test","seed":"` + escape(filepath.Join(dir, "gateway.seed")) + `","store":"` + escape(filepath.Join(dir, "store")) + `",` +
		`"registry":"` + escape(filepath.Join(dir, "registry.jsonl")) + `","decisionRecords":"` + escape(filepath.Join(dir, "decisions")) + `",` +
		`"listen":"127.0.0.1:0","catalog":"` + escape(catalog) + `","runtime":"` + escape(fake) + `","adapters":"` + escape(bin) + `","platforms":{` +
		`"records":{"binding":"records@` + digestOf(records) + `","credentials":{"live":{"file":"` + escape(recordsCredentials) + `"}},"user":"engine-records"},` +
		`"warehouse":{"binding":"postgres@` + digestOf(postgresBinding) + `","credentials":{"history":{"file":"` + escape(warehouseCredentials) + `"},"live":{"file":"` + escape(warehouseCredentials) + `"},"write":{"file":"` + escape(warehouseCredentials) + `"}},"user":"engine-warehouse","endpoint":"warehouse.internal:5432","write":true}}}`
	path := filepath.Join(dir, "engine.json")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, bindings, err := loadEngineConfig(path, stubAccounts(map[string]int{"engine-warehouse": 1001, "engine-records": 1004}))
	if err != nil {
		t.Fatal(err)
	}
	sources := deriveSources(cfg, bindings)
	if sources["records/live"].user != "engine-records" || sources["records/live"].argv[0] != adapter {
		t.Fatalf("records/live is adapter-http as the platform's user: %+v", sources["records/live"])
	}
	if _, write := sources["records/write"]; write {
		t.Fatal("an http platform derives no write source")
	}
	for name, spec := range sources {
		spec.user = ""
		sources[name] = spec
	}
	// The check connect runs, by the real adapter: the check path GET,
	// with the credential, answered.
	report, err := runCheck(context.Background(), sources["records/live"])
	if err != nil {
		t.Fatalf("the check: %v", err)
	}
	if line, err := describeSourceCheck(sources["records/live"], report); err != nil || !strings.HasSuffix(line, ": endpoint "+api.URL+"; GET /health answered 204") {
		t.Fatalf("the check as connect reads it: %q %v", line, err)
	}
	checked := hits.Load()
	service, err := buildService(cfg.store, testSeed, cfg.authority, cfg.registry, engineServeOptions(cfg, sources, nil))
	if err != nil {
		t.Fatal(err)
	}
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	service.identity = &id
	token := issuer.mint(t, "ec-1", nil, goodClaims(time.Now()))
	server := httptest.NewServer(service.handler())
	defer server.Close()
	const search = `{"session":"cfg-1","source":"records/live","arguments":{"path":"/search","method":"POST","body":{"q":"claims"}}}`
	// No token, no acquisition: the route is as authenticated as every
	// other source's.
	if code, body := post(t, server, "/acquire", search); code != http.StatusUnauthorized || hits.Load() != checked {
		t.Fatalf("an unauthenticated acquisition: %d %v, the API asked %d times", code, body, hits.Load()-checked)
	}
	// A delegated acquisition names no tool, and the platform names no
	// grant: refused as grant-unknown before anything runs.
	request, err := parseJSON([]byte(`{"path":"/search","method":"POST","body":{"q":"claims"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.acquireWithReconciliation("cfg-2", "records/live", "", request, &caller{issuer: id.issuer, subject: "user-7", delegated: &delegatedSender{}}, nil); err == nil || !strings.Contains(err.Error(), refusalGrantUnknown) || hits.Load() != checked {
		t.Fatalf("a delegated acquisition: %v, the API asked %d times", err, hits.Load()-checked)
	}
	// A path the binding does not name is refused by the adapter before
	// any request is sent.
	if code, body := authed(t, server, "/acquire", `{"session":"cfg-1","source":"records/live","arguments":{"path":"/admin","method":"GET"}}`, token); code == http.StatusOK || hits.Load() != checked {
		t.Fatalf("a path the binding does not name: %d %v, the API asked %d times", code, body, hits.Load()-checked)
	}
	code, first := authed(t, server, "/acquire", search, token)
	if code != http.StatusOK || hits.Load() != checked+1 {
		t.Fatalf("acquire failed: %d %v", code, first)
	}
	receipt := first["receipt"].(map[string]any)
	acquisition := receipt["acquisition"].(map[string]any)
	adapterOut := acquisition["adapter"].(map[string]any)
	binary, _ := os.ReadFile(adapter)
	sum := sha256.Sum256(binary)
	if receipt["source"] != "records/live" || acquisition["shape"] != "http" || adapterOut["name"] != "adapter-http" || adapterOut["digest"] != "sha256:"+hex.EncodeToString(sum[:]) ||
		acquisition["endpoint"] != api.URL+"/search" || acquisition["snapshot"] != `"records-7"` || acquisition["peerIdentity"] != nil {
		t.Fatalf("the receipt names the derived source, adapter-http by its digest, the URL sent to and the ETag: %v", receipt)
	}
	if encoded, _ := json.Marshal(first); strings.Contains(string(encoded), "api-secret") || strings.Contains(string(encoded), "not-sent") {
		t.Fatal("nothing of the credentials reaches the response")
	}
	// The plain form, the same adapter and the same request: the same
	// receipt kind and members, the same acquisition.
	plainDir := t.TempDir()
	args := []string{filepath.Join(plainDir, "store"), "seed-is-loaded-separately", "gateway:test", filepath.Join(plainDir, "registry.jsonl"),
		"--source", "read=" + adapter + " --endpoint " + api.URL + " --paths /search,/health --methods GET,POST --credentials " + recordsCredentials + " --bearer API_TOKEN --header Accept=application/json",
		"--source-shape", "read=http"}
	opts, msg, ok := parseServeOptions(args)
	if !ok {
		t.Fatal(msg)
	}
	plainService, err := buildService(args[0], testSeed, args[2], args[3], opts)
	if err != nil {
		t.Fatal(err)
	}
	plain := httptest.NewServer(plainService.handler())
	defer plain.Close()
	code, plainOut := post(t, plain, "/acquire", strings.Replace(search, `"records/live"`, `"read"`, 1))
	if code != http.StatusOK {
		t.Fatalf("the plain form: %d %v", code, plainOut)
	}
	plainReceipt := plainOut["receipt"].(map[string]any)
	plainAcquisition := plainReceipt["acquisition"].(map[string]any)
	if !reflect.DeepEqual(memberNames(receipt), memberNames(plainReceipt)) || receipt["kind"] != plainReceipt["kind"] || !reflect.DeepEqual(memberNames(acquisition), memberNames(plainAcquisition)) {
		t.Fatalf("the engine's receipt and the plain form's differ in form:\n%v\n%v", memberNames(receipt), memberNames(plainReceipt))
	}
	for _, member := range []string{"shape", "adapter", "endpoint", "snapshot", "peerIdentity"} {
		if !reflect.DeepEqual(acquisition[member], plainAcquisition[member]) {
			t.Fatalf("acquisition.%s: %v, the plain form's %v", member, acquisition[member], plainAcquisition[member])
		}
	}
	// The result is the API's answer, each time: the same but for the
	// time it was given.
	result, plainResult := first["result"].(map[string]any), plainOut["result"].(map[string]any)
	delete(result["headers"].(map[string]any), "date")
	delete(plainResult["headers"].(map[string]any), "date")
	if !reflect.DeepEqual(result, plainResult) {
		t.Fatalf("the result: %v, the plain form's %v", result, plainResult)
	}
	// /act takes no write for the http platform: it has no write source,
	// and nothing is sent.
	signature := receipt["signature"].(string)
	line := `{"recordVersion":"1","kind":"evaluation","cites":[{"sessionId":"cfg-1","callIndex":0,"signature":"` + signature + `"}]}`
	if err := os.MkdirAll(cfg.decisionRecords, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.decisionRecords, "evaluations.jsonl"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	decision := `"decision":{"recordDigest":"sha256:` + hexOf([]byte(line)) + `","packDigest":"sha256:` + strings.Repeat("b", 64) + `"},` +
		`"cites":[{"sessionId":"cfg-1","callIndex":0,"signature":"` + signature + `"}]}`
	sent := hits.Load()
	if code, body := authed(t, server, "/act", `{"session":"cfg-1","platform":"records","tool":"search","arguments":{"q":"x"},`+decision, token); code == http.StatusOK || body["receipt"] != nil || hits.Load() != sent {
		t.Fatalf("/act dispatched to the http platform: %d %v", code, body)
	}
	// An action on the write platform cites what was read.
	code, acted := authed(t, server, "/act", `{"session":"cfg-1","platform":"warehouse","tool":"execute","arguments":{"sql":"update t set s = 1"},`+decision, token)
	if code != http.StatusOK {
		t.Fatalf("act failed: %d %v", code, acted)
	}
	action := acted["receipt"].(map[string]any)
	cited := action["action"].(map[string]any)["cites"].([]any)[0].(map[string]any)
	if action["kind"] != "action" || action["source"] != "warehouse/write" || cited["signature"] != signature || cited["callIndex"] != float64(0) {
		t.Fatalf("the action cites the http acquisition: %v", action)
	}
	if code, body := authed(t, server, "/seal", `{"session":"cfg-1"}`, token); code != http.StatusOK {
		t.Fatalf("seal failed: %d %v", code, body)
	}
	verified, err := verifyWithRegistryAndRecords(service.storeRoot, service.regPath, "gateway:test", cfg.decisionRecords, service.publicKey)
	if err != nil || !verified.OK {
		t.Fatalf("the store, the registry and the records must verify together: %v %v", err, verified)
	}
	// With a delegation credential presented, a chain bound by an issuing
	// host, the refusal is the same: the platform names no grant, so the
	// call is refused grant-unknown before the scope check, the custody or
	// the issuing host is reached, and the adapter does not run. Last, since
	// the harness sets the environment of the rest of the test.
	if actionJournalSupported {
		h := newDelegationHarness(t, false)
		cred := h.credential(t, statement(t, nil))
		h.d.mu.Lock()
		bound := h.d.credentials[tokenDigestOf(cred)]
		h.d.mu.Unlock()
		leaf := bound.chain.leaf()
		who := &caller{issuer: id.issuer, subject: "user-7", delegated: &delegatedSender{kind: "actor", credential: bound, scope: reservationScope{sub: leaf.sub, rootActor: leaf.agent, host: "desk"}}}
		sent = hits.Load()
		if _, err := service.acquireWithReconciliation("cfg-3", "records/live", "", request, who, nil); err == nil || !strings.Contains(err.Error(), refusalGrantUnknown) || hits.Load() != sent {
			t.Fatalf("a delegated acquisition with a credential: %v, the API asked %d times", err, hits.Load()-sent)
		}
	}
}
