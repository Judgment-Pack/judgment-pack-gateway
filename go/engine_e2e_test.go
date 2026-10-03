package main

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// From a configuration to a receipt: the sources `serve --config` derives
// from a platform's binding run the real adapter-mcp binary against a
// stand-in runtime built here, and the store verifies with a receipt whose
// acquisition names the binding's pinned image. The platform's user is
// stripped before the service is built, since this test does not run as a
// user that can switch; what it proves is that the derivation is right end
// to end, the switching being proved where it is implemented.
func TestEngineConfigDrivesTheMCPAdapterEndToEnd(t *testing.T) {
	dir := t.TempDir()
	bin, fake := buildMCPStandIns(t, dir)
	credentials := filepath.Join(dir, "warehouse.json")
	if err := os.WriteFile(credentials, []byte(`{"SERVICE_TOKEN":"secret-token"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	escape := func(p string) string { return strings.ReplaceAll(p, `\`, `\\`) }
	text := `{"engineVersion":"1","authority":"gateway:test","seed":"` + escape(filepath.Join(dir, "gateway.seed")) + `","store":"` + escape(filepath.Join(dir, "store")) + `",` +
		`"registry":"` + escape(filepath.Join(dir, "registry.jsonl")) + `","decisionRecords":"` + escape(filepath.Join(dir, "decisions")) + `",` +
		`"listen":"127.0.0.1:0","catalog":"` + escape(catalog) + `","runtime":"` + escape(fake) + `","adapters":"` + escape(bin) + `",` +
		`"platforms":{"warehouse":{"binding":"postgres@` + digestOf(postgresBinding) + `","credentials":{"history":{"file":"` + escape(credentials) + `"},"live":{"file":"` + escape(credentials) + `"},"write":{"file":"` + escape(credentials) + `"}},"user":"engine-warehouse","endpoint":"warehouse.internal:5432","write":true}}}`
	path := filepath.Join(dir, "engine.json")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, bindings, err := loadEngineConfig(path, stubAccounts(map[string]int{"engine-warehouse": 1001}))
	if err != nil {
		t.Fatal(err)
	}
	sources := deriveSources(cfg, bindings)
	for name, spec := range sources {
		spec.user = ""
		sources[name] = spec
	}
	service, err := buildService(cfg.store, testSeed, cfg.authority, cfg.registry, engineServeOptions(cfg, sources, nil))
	if err != nil {
		t.Fatal(err)
	}
	// An identity, so that an action has a requester; every request below
	// carries its token.
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	service.identity = &id
	token := issuer.mint(t, "ec-1", nil, goodClaims(time.Now()))
	post := func(t *testing.T, server *httptest.Server, path, body string) (int, map[string]any) {
		t.Helper()
		return authed(t, server, path, body, token)
	}
	server := httptest.NewServer(service.handler())
	defer server.Close()
	code, first := post(t, server, "/acquire", `{"session":"cfg-1","source":"warehouse/live","arguments":{"tool":"query","arguments":{"sql":"select 1"}}}`)
	if code != http.StatusOK {
		t.Fatalf("acquire failed: %d %v", code, first)
	}
	receipt := first["receipt"].(map[string]any)
	acquisition := receipt["acquisition"].(map[string]any)
	adapter := acquisition["adapter"].(map[string]any)
	if receipt["source"] != "warehouse/live" || acquisition["shape"] != "mcp" || adapter["name"] != "ghcr.io/example/mcp-postgres" || adapter["version"] != "2.1" || adapter["digest"] != testImageDigest || acquisition["endpoint"] != "warehouse.internal:5432" {
		t.Fatalf("the receipt names the derived source, the binding's pinned image and the platform's endpoint: %v", receipt)
	}
	result, _ := first["result"].(map[string]any)
	structured, _ := result["structuredContent"].(map[string]any)
	rows, _ := structured["rows"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["id"] != float64(101) {
		t.Fatalf("the tool's result came back through the derived source: %v", first["result"])
	}
	if code, body := post(t, server, "/acquire", `{"session":"cfg-1","source":"warehouse/history","arguments":{"stream":"decisions"}}`); code == http.StatusOK {
		t.Fatalf("the history source runs adapter-airbyte, which is not built here, so it must fail: %v", body)
	}
	// The join, end to end (docs/design/executor.md): a decision record
	// that cites the acquisition, written where the engine looks for one;
	// an action that cites both; the executor is adapter-mcp on the write
	// binding, calling the write tool; and the store, the registry and the
	// records verify together with every receipt ok.
	signature := receipt["signature"].(string)
	line := `{"recordVersion":"1","kind":"evaluation","cites":[{"sessionId":"cfg-1","callIndex":0,"signature":"` + signature + `"}]}`
	if err := os.MkdirAll(cfg.decisionRecords, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.decisionRecords, "evaluations.jsonl"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	act := `{"session":"cfg-1","platform":"warehouse","tool":"execute","arguments":{"sql":"update t set s = 1"},` +
		`"decision":{"recordDigest":"sha256:` + hexOf([]byte(line)) + `","packDigest":"sha256:` + strings.Repeat("b", 64) + `"},` +
		`"cites":[{"sessionId":"cfg-1","callIndex":0,"signature":"` + signature + `"}]}`
	code, acted := post(t, server, "/act", act)
	if code != http.StatusOK {
		t.Fatalf("act failed: %d %v", code, acted)
	}
	action := acted["receipt"].(map[string]any)
	inner := action["action"].(map[string]any)
	tool := inner["tool"].(map[string]any)
	requester := inner["requester"].(map[string]any)
	cited := inner["cites"].([]any)[0].(map[string]any)
	if action["kind"] != "action" || action["source"] != "warehouse/write" || action["callIndex"] != float64(1) || action["prevSignature"] != signature ||
		tool["shape"] != "mcp" || tool["name"] != "execute" || tool["endpoint"] != "warehouse.internal:5432" ||
		requester["subject"] != "user-7" || cited["signature"] != signature || cited["callIndex"] != float64(0) ||
		inner["decision"].(map[string]any)["recordDigest"] != "sha256:"+hexOf([]byte(line)) ||
		inner["adapter"].(map[string]any)["digest"] != testImageDigest || !strings.HasPrefix(fmt.Sprint(inner["request"]), "sha256:") {
		t.Fatalf("the action receipt names the executor, the tool, the requester, the decision and the citation: %v", action)
	}
	// The target received exactly the arguments the requester sent -- the
	// stand-in echoes its call's params -- and both commitments recompute
	// from the returned salts over those same bytes: what was committed to
	// is what was sent.
	echoed := acted["result"].(map[string]any)["structuredContent"].(map[string]any)["params"].(map[string]any)
	if echoed["name"] != "execute" || echoed["arguments"].(map[string]any)["sql"] != "update t set s = 1" {
		t.Fatalf("the target got the tool and the arguments as sent: %v", echoed)
	}
	salts := acted["salts"].(map[string]any)
	argsSalt, err := hex.DecodeString(fmt.Sprint(salts["args"]))
	if err != nil {
		t.Fatal(err)
	}
	requestSalt, err := hex.DecodeString(fmt.Sprint(salts["request"]))
	if err != nil {
		t.Fatal(err)
	}
	argumentsV, _ := parseJSON([]byte(`{"sql":"update t set s = 1"}`))
	requestV, _ := parseJSON([]byte(`{"tool":"execute","arguments":{"sql":"update t set s = 1"}}`))
	if action["argumentsCommitment"] != commitmentOver(argsSalt, "args:", canon(argumentsV)) || inner["request"] != commitmentOver(requestSalt, "request:", canon(requestV)) {
		t.Fatalf("the commitments recompute from the salts over the bytes sent: %v %v", action["argumentsCommitment"], inner["request"])
	}
	// A target that refuses the write answers, and the answer is receipted:
	// the executor is started with --error-results, so the refusal is the
	// call's result, retained as the artifact and named by the receipt,
	// rather than a read that did not happen.
	refused := strings.Replace(act, `"tool":"execute"`, `"tool":"drop"`, 1)
	code, refusal := post(t, server, "/act", refused)
	if code != http.StatusOK {
		t.Fatalf("a target's refusal is a response to receipt: %d %v", code, refusal)
	}
	if refusal["result"].(map[string]any)["isError"] != true || !strings.Contains(fmt.Sprint(refusal["result"]), "not permitted") ||
		refusal["receipt"].(map[string]any)["kind"] != "action" || refusal["receipt"].(map[string]any)["action"].(map[string]any)["tool"].(map[string]any)["name"] != "drop" {
		t.Fatalf("the refusal's bytes are the result and the receipt names the call: %v", refusal)
	}
	if code, body := post(t, server, "/seal", `{"session":"cfg-1"}`); code != http.StatusOK {
		t.Fatalf("seal failed: %d %v", code, body)
	}
	// /verify on the engine reads the configured decision-record directory,
	// as the command does when handed it: every receipt ok, the action's
	// citation and record resolved.
	code, verified := post(t, server, "/verify", ``)
	if code != http.StatusOK || verified["ok"] != true {
		t.Fatalf("/verify with the records: %d %v", code, verified)
	}
	for _, f := range verified["findings"].([]any) {
		if f.(map[string]any)["status"] != "ok" {
			t.Fatalf("every receipt ok over /verify: %v", verified["findings"])
		}
	}
	report, err := verifyWithRegistryAndRecords(service.storeRoot, service.regPath, "gateway:test", cfg.decisionRecords, service.publicKey)
	if err != nil || !report.OK {
		t.Fatalf("the store, the registry and the records must verify together: %v %v", err, report)
	}
}

// The same join with the write held to its decision (ADR-0011): a platform
// whose configuration holds its write tool to a decision policy that
// requires a record signed by a runtime key it trusts (ADR-0012); an
// acquisition; a chained record in the runtime's own form, written where the
// engine looks, citing it; the action refused with nothing run while no
// sidecar signs the record, and, once one does, an action whose claims the
// record does not bear out refused too; the action that meets every check,
// performed by adapter-mcp on the write binding and receipted with the
// policy's digest; and the store, the registry and the records -- the
// sidecar among them -- verifying together, the record compared and
// matching.
func TestEngineHoldsAWriteToItsDecisionEndToEnd(t *testing.T) {
	dir := t.TempDir()
	bin, fake := buildMCPStandIns(t, dir)
	credentials := filepath.Join(dir, "warehouse.json")
	if err := os.WriteFile(credentials, []byte(`{"SERVICE_TOKEN":"secret-token"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	escape := func(p string) string { return strings.ReplaceAll(p, `\`, `\\`) }
	runtimeKey := keyFromSeed(t, vectorSeed1)
	policy := `{"outcomes":["approve"],"packs":["` + packA + `"],"reviewed":true,"bind":[{"argument":"/ticket","fact":"/ticket/id"},{"argument":"/revision","fact":"/ticket/revision"}],` +
		`"requireSignedRecord":["` + runtimeKey.public + `"]}`
	text := `{"engineVersion":"5","authority":"gateway:test","seed":"` + escape(filepath.Join(dir, "gateway.seed")) + `","store":"` + escape(filepath.Join(dir, "store")) + `",` +
		`"registry":"` + escape(filepath.Join(dir, "registry.jsonl")) + `","decisionRecords":"` + escape(filepath.Join(dir, "decisions")) + `",` +
		`"listen":"127.0.0.1:0","catalog":"` + escape(catalog) + `","runtime":"` + escape(fake) + `","adapters":"` + escape(bin) + `",` +
		`"platforms":{"warehouse":{"binding":"postgres@` + digestOf(postgresBinding) + `","credentials":{"history":{"file":"` + escape(credentials) + `"},"live":{"file":"` + escape(credentials) + `"},"write":{"file":"` + escape(credentials) + `"}},` +
		`"user":"engine-warehouse","endpoint":"warehouse.internal:5432","write":true,"decisionPolicy":{"execute":` + policy + `}}}}`
	path := filepath.Join(dir, "engine.json")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, bindings, err := loadEngineConfig(path, stubAccounts(map[string]int{"engine-warehouse": 1001}))
	if err != nil {
		t.Fatal(err)
	}
	sources := deriveSources(cfg, bindings)
	for name, spec := range sources {
		spec.user = ""
		sources[name] = spec
	}
	service, err := buildService(cfg.store, testSeed, cfg.authority, cfg.registry, engineServeOptions(cfg, sources, nil))
	if err != nil {
		t.Fatal(err)
	}
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	service.identity = &id
	token := issuer.mint(t, "ec-1", nil, goodClaims(time.Now()))
	post := func(t *testing.T, server *httptest.Server, path, body string) (int, map[string]any) {
		t.Helper()
		return authed(t, server, path, body, token)
	}
	server := httptest.NewServer(service.handler())
	defer server.Close()
	code, first := post(t, server, "/acquire", `{"session":"held-1","source":"warehouse/live","arguments":{"tool":"query","arguments":{"sql":"select * from tickets where id = 'T-1'"}}}`)
	if code != http.StatusOK {
		t.Fatalf("acquire failed: %d %v", code, first)
	}
	signature := first["receipt"].(map[string]any)["signature"].(string)
	// A line in the form the runtime's audit trail writes one (runtime
	// internal/audit): the pack's digest, the facts as evaluated -- a
	// fraction among them -- the law it was judged under, the receipt it
	// relied on, and the disposition in its canonical form.
	trail := strings.Repeat("8d", 16)
	line := `{"recordVersion":"1","trail":"` + trail + `","sequence":1,"previous":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","run":"9a8b7c6d5e4f3a2b","at":"2026-09-30T10:00:00.5Z","kind":"evaluation","surface":"evaluate","tool":{"name":"jpack","version":"0.23.1"},` +
		`"evaluatorSpecVersion":"1.0","pack":{"id":"ticket-approval","version":"2.0.0","specVersion":"1.0","digest":"` + packA + `"},` +
		`"inputs":{"facts":{"ticket":{"id":"T-1","revision":7,"amount":1250.75}},"evidence":null,"evidenceSupplied":false},"reviewed":true,` +
		`"reviewedSet":{"lockDigest":"sha256:` + strings.Repeat("c3", 32) + `","lockVersion":"1","configDigest":"sha256:` + strings.Repeat("d4", 32) + `"},` +
		`"cites":[{"sessionId":"held-1","callIndex":0,"signature":"` + signature + `"}],` +
		`"disposition":{"handoff":{"state":"none"},"kind":"outcome","outcomeId":"approve","reasons":[]}}`
	if err := os.MkdirAll(cfg.decisionRecords, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.decisionRecords, "evaluations.jsonl"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	act := func(revision string) string {
		return `{"session":"held-1","platform":"warehouse","tool":"execute","arguments":{"sql":"update tickets set status = 'approved' where id = 'T-1'","ticket":"T-1","revision":` + revision + `},` +
			`"decision":{"recordDigest":"sha256:` + hexOf([]byte(line)) + `","packDigest":"` + packA + `"},` +
			`"cites":[{"sessionId":"held-1","callIndex":0,"signature":"` + signature + `"}]}`
	}
	// No sidecar signs the record yet: refused before the executor is
	// started, and nothing is minted.
	started := service.started.Load()
	if code, body := post(t, server, "/act", act("7")); code != http.StatusBadRequest || body["refusedAt"] != "policy-signed" {
		t.Fatalf("a record no trusted key signed: %d %v", code, body)
	}
	// The runtime signs it in the sidecar beside the trail.
	if err := os.WriteFile(filepath.Join(cfg.decisionRecords, sidecarName), []byte(signedLine(runtimeKey, trail, 1, "sha256:"+hexOf([]byte(line)))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Decided on revision 7, written to revision 8: refused before the
	// executor is started, and nothing is minted.
	if code, body := post(t, server, "/act", act("8")); code != http.StatusBadRequest || body["refusedAt"] != "policy-bind" {
		t.Fatalf("a write to another revision than the one decided: %d %v", code, body)
	}
	if service.started.Load() != started {
		t.Fatal("an executor ran for a write its decision does not hold")
	}
	code, acted := post(t, server, "/act", act("7"))
	if code != http.StatusOK {
		t.Fatalf("act failed: %d %v", code, acted)
	}
	action := acted["receipt"].(map[string]any)
	inner := action["action"].(map[string]any)
	if action["kind"] != "action" || action["callIndex"] != float64(1) || inner["tool"].(map[string]any)["name"] != "execute" ||
		inner["policy"] != sources["warehouse/write"].policies["execute"].digest || inner["policy"] != mustPolicy(t, policy).digest {
		t.Fatalf("the action receipt names the policy the write was held to: %v", action)
	}
	echoed := acted["result"].(map[string]any)["structuredContent"].(map[string]any)["params"].(map[string]any)
	if echoed["name"] != "execute" || echoed["arguments"].(map[string]any)["revision"] != float64(7) {
		t.Fatalf("the target got the write as sent: %v", echoed)
	}
	if code, body := post(t, server, "/seal", `{"session":"held-1"}`); code != http.StatusOK {
		t.Fatalf("seal failed: %d %v", code, body)
	}
	// The record is one the verifier understands, so it is compared: the
	// action's pack and citations are the record's, and nothing is said of
	// it but ok.
	code, verified := post(t, server, "/verify", ``)
	if code != http.StatusOK || verified["ok"] != true || verified["observations"] != nil {
		t.Fatalf("/verify with the records: %d %v", code, verified)
	}
	for _, f := range verified["findings"].([]any) {
		if f.(map[string]any)["status"] != "ok" {
			t.Fatalf("every receipt ok over /verify: %v", verified["findings"])
		}
	}
	report, err := verifyWithRegistryAndRecords(service.storeRoot, service.regPath, "gateway:test", cfg.decisionRecords, service.publicKey)
	if err != nil || !report.OK || len(report.Observations) != 0 {
		t.Fatalf("the store, the registry and the records must verify together: %v %+v", err, report)
	}
}

// buildMCPStandIns builds the real adapter-mcp binary into dir/bin and the
// stand-in container runtime below, and returns the adapters' directory and
// the runtime's path; a test with no go toolchain to build them is skipped.
func buildMCPStandIns(t *testing.T, dir string) (string, string) {
	t.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain on PATH")
	}
	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	build := exec.Command(goTool, "build", "-buildvcs=false", "-o", filepath.Join(bin, "adapter-mcp"+exe), "./cmd/adapter-mcp")
	build.Dir = filepath.Join("..", "adapters")
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the adapter: %v\n%s", err, out)
	}
	// The stand-in runtime: `run ... IMAGE` speaks JSON-RPC as the server
	// the image would be, answering only when the env file the adapter
	// mounted carried the credential; kill and inspect as for a container
	// that is gone.
	fakeDir := filepath.Join(dir, "fake")
	if err := os.MkdirAll(fakeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	fakeSource := `package main

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	switch os.Args[1] {
	case "kill":
		os.Exit(0)
	case "inspect":
		os.Stderr.WriteString("Error: No such object: " + os.Args[2] + "\n")
		os.Exit(1)
	}
	envFile := ""
	for i, a := range os.Args {
		if a == "--env-file" && i+1 < len(os.Args) {
			data, _ := os.ReadFile(os.Args[i+1])
			envFile = string(data)
		}
	}
	if !strings.Contains(envFile, "SERVICE_TOKEN=secret-token") {
		os.Stderr.WriteString("no token in the env file\n")
		os.Exit(1)
	}
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		var m struct {
			ID     json.RawMessage ` + "`json:\"id\"`" + `
			Method string          ` + "`json:\"method\"`" + `
			Params json.RawMessage ` + "`json:\"params\"`" + `
		}
		if json.Unmarshal(in.Bytes(), &m) != nil || len(m.ID) == 0 {
			continue
		}
		var result any
		switch m.Method {
		case "initialize":
			result = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "standin", "version": "0.1"}}
		case "tools/list":
			result = map[string]any{"tools": []any{map[string]any{"name": "query", "inputSchema": map[string]any{"type": "object"}}, map[string]any{"name": "execute", "inputSchema": map[string]any{"type": "object"}}, map[string]any{"name": "drop", "inputSchema": map[string]any{"type": "object"}}}}
		case "tools/call":
			if strings.Contains(string(m.Params), ` + "`" + `"name":"drop"` + "`" + `) {
				result = map[string]any{"content": []any{map[string]any{"type": "text", "text": "refused: drop is not permitted for this principal"}}, "isError": true}
				break
			}
			result = map[string]any{"content": []any{map[string]any{"type": "text", "text": "1 row"}}, "structuredContent": map[string]any{"rows": []any{map[string]any{"id": 101}}, "params": json.RawMessage(m.Params)}}
		default:
			continue
		}
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": result})
		os.Stdout.Write(append(b, '\n'))
	}
}
`
	if err := os.WriteFile(filepath.Join(fakeDir, "main.go"), []byte(fakeSource), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeDir, "go.mod"), []byte("module fake\n\ngo 1.26\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(dir, "fake-runtime"+exe)
	build = exec.Command(goTool, "build", "-buildvcs=false", "-o", fake, ".")
	build.Dir = fakeDir
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the stand-in runtime: %v\n%s", err, out)
	}
	return bin, fake
}
