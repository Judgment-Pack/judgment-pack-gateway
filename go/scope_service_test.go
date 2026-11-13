package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testScope is the scope identifier the scoped test source is fixed to: its
// é is the one precomposed code point, so the same letters decomposed are
// another identifier. Every refusal below is held to quote no part of it
// ("quipe").
const testScope = "équipe-a"

// jsonText is s as a JSON string.
func jsonText(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// scopedService is a gateway with a source fixed to testScope and one fixed
// to none, its diagnostics written to the buffer returned.
func scopedService(t *testing.T) (*gatewayService, *httptest.Server, *syncBuffer) {
	t.Helper()
	t.Setenv(envSourceHelper, "1")
	root := t.TempDir()
	service, err := newGatewayService(
		filepath.Join(root, "store"), testSeed, "gateway:test",
		filepath.Join(root, "registry.jsonl"),
		map[string]sourceSpec{
			"scoped": {argv: []string{os.Args[0]}, env: helperEnv, scope: testScope},
			"plain":  {argv: []string{os.Args[0]}, env: helperEnv},
		})
	if err != nil {
		t.Fatal(err)
	}
	said := &syncBuffer{}
	service.reportsOut = said
	server := httptest.NewServer(service.handler())
	t.Cleanup(server.Close)
	return service, server, said
}

// A source fixed to a scope identifier mints receipts that carry it under
// the signature (SPEC.md §1.2a, scope), and they verify; a source of the
// same gateway fixed to none mints receipts without the member. The member
// changed or taken out is a signature mismatch.
func TestAScopedSourcesReceiptCarriesItsScopeAndVerifies(t *testing.T) {
	service, server, _ := scopedService(t)
	code, first := post(t, server, "/acquire", `{"session":"scope-1","source":"scoped","scope":`+jsonText(t, testScope)+`,"arguments":{"q":"a"}}`)
	if code != http.StatusOK {
		t.Fatalf("a scoped acquisition: %d %v", code, first)
	}
	receipt := first["receipt"].(map[string]any)
	if receipt["scope"] != testScope || len(receipt) != 15 {
		t.Fatalf("the receipt of a scoped source carries its scope beside the members it carried before: %v", receipt)
	}
	code, second := post(t, server, "/acquire", `{"session":"scope-1","source":"plain","arguments":{"q":"a"}}`)
	if code != http.StatusOK {
		t.Fatalf("an unscoped acquisition: %d %v", code, second)
	}
	if plain := second["receipt"].(map[string]any); len(plain) != 14 {
		t.Fatalf("the receipt of a source fixed to none carries no scope: %v", plain)
	} else if _, present := plain["scope"]; present {
		t.Fatalf("the receipt of a source fixed to none carries no scope: %v", plain)
	}
	if code, out := post(t, server, "/seal", `{"session":"scope-1"}`); code != http.StatusOK {
		t.Fatalf("seal: %d %v", code, out)
	}
	verdict := func() (bool, string) {
		rep, err := verifyWithRegistry(service.storeRoot, service.regPath, service.authority, service.publicKey)
		if err != nil {
			t.Fatal(err)
		}
		return rep.OK, fmt.Sprint(rep.Findings[0]["status"])
	}
	if ok, status := verdict(); !ok || status != "ok" {
		t.Fatalf("the session as minted: ok %v, %s", ok, status)
	}
	path := filepath.Join(service.storeRoot, "receipts", "scope-1", "0.json")
	minted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	member := `"scope":` + jsonText(t, testScope)
	for _, tc := range []struct{ name, from, to string }{
		{"another scope", member, `"scope":` + jsonText(t, "équipe-b")},
		{"the member taken out", member + ",", ""},
	} {
		if !strings.Contains(string(minted), tc.from) {
			t.Fatalf("%s: the receipt holds no %s: %s", tc.name, tc.from, minted)
		}
		if err := os.WriteFile(path, []byte(strings.Replace(string(minted), tc.from, tc.to, 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		if ok, status := verdict(); ok || status != "signature-mismatch" {
			t.Errorf("%s: ok %v, %s", tc.name, ok, status)
		}
	}
}

// A request whose scope is not its source's -- none for a source fixed to
// one, another, the same letters in another case or another normalization,
// and one for a source fixed to none -- is refused in one sentence that
// quotes neither identifier, before the source starts and before the
// session is admitted; and no diagnostic line names either.
func TestARequestForAnotherScopeIsRefusedBeforeTheSourceStarts(t *testing.T) {
	service, server, said := scopedService(t)
	decomposed := "e" + string(rune(0x0301)) + "quipe-a"
	if decomposed == testScope || len(decomposed) == len(testScope) {
		t.Fatal("the decomposed spelling is the precomposed one")
	}
	started := service.started.Load()
	for _, tc := range []struct{ name, source, scope string }{
		{"no scope, for a scoped source", "scoped", ""},
		{"another scope", "scoped", `"équipe-b"`},
		{"another case", "scoped", `"Équipe-a"`},
		{"another normalization", "scoped", jsonText(t, decomposed)},
		{"the scope and a space", "scoped", `"équipe-a "`},
		{"a prefix of the scope", "scoped", `"équipe"`},
		{"an empty scope", "scoped", `""`},
		{"a scope, for a source fixed to none", "plain", jsonText(t, testScope)},
		{"an empty scope, for a source fixed to none", "plain", `""`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"session":"scope-2","source":"` + tc.source + `","arguments":{"q":"a"}}`
			if tc.scope != "" {
				body = `{"session":"scope-2","source":"` + tc.source + `","scope":` + tc.scope + `,"arguments":{"q":"a"}}`
			}
			code, raw := postRawWith(t, server, "/acquire", body, "")
			if code != http.StatusBadRequest || !bytes.Contains(raw, []byte(scopeRefusal)) {
				t.Fatalf("%d %s", code, raw)
			}
			if bytes.Contains(raw, []byte("quipe")) {
				t.Fatalf("the refusal quotes a scope identifier: %s", raw)
			}
		})
	}
	for _, scope := range []string{`null`, `7`, `true`, `["équipe-a"]`, `{"scope":"équipe-a"}`} {
		code, raw := postRawWith(t, server, "/acquire", `{"session":"scope-2","source":"scoped","scope":`+scope+`,"arguments":{"q":"a"}}`, "")
		if code != http.StatusBadRequest || !bytes.Contains(raw, []byte("scope must be a string")) || bytes.Contains(raw, []byte("quipe")) {
			t.Fatalf("scope %s: %d %s", scope, code, raw)
		}
	}
	if service.started.Load() != started {
		t.Fatal("a source started for a request whose scope is not its own")
	}
	// The session was not admitted: its first receipt is still to come.
	code, out := post(t, server, "/acquire", `{"session":"scope-2","source":"scoped","scope":`+jsonText(t, testScope)+`,"arguments":{"q":"a"}}`)
	if code != http.StatusOK {
		t.Fatalf("the scope as fixed: %d %v", code, out)
	}
	if index := out["receipt"].(map[string]any)["callIndex"]; index != float64(0) {
		t.Fatalf("a refused request was admitted to the session: callIndex %v", index)
	}
	if !service.reports.flush(5 * time.Second) {
		t.Fatal("the diagnostics did not drain")
	}
	if strings.Contains(said.String(), "quipe") {
		t.Fatalf("a diagnostic line names a scope identifier: %s", said.String())
	}
}

// A gateway that fixes no source to a scope identifier reads the request
// member as any member it does not know, as it did before the member
// existed.
func TestAGatewayFixingNoScopeRefusesTheMember(t *testing.T) {
	service, server := testService(t)
	started := service.started.Load()
	code, raw := postRawWith(t, server, "/acquire", `{"session":"scope-3","source":"screening","scope":"équipe-a","arguments":{}}`, "")
	if code != http.StatusBadRequest || !bytes.Contains(raw, []byte("request body carries a member this endpoint does not read: scope")) || bytes.Contains(raw, []byte("quipe")) {
		t.Fatalf("%d %s", code, raw)
	}
	if service.started.Load() != started {
		t.Fatal("a source started")
	}
}

// The guards off /acquire's own path, which the configuration leaves no
// way to reach and which refuse rather than mint a receipt that does not
// name the scope: a version 2 receipt, a read-back (which names none), an
// action on a scoped write source, and a scope out of form handed to the
// service.
func TestTheScopeIsHeldOffTheRequestPath(t *testing.T) {
	service, server, _ := scopedService(t)
	started := service.started.Load()

	service.receiptVersion = receiptVersion
	if code, raw := postRawWith(t, server, "/acquire", `{"session":"scope-4","source":"scoped","scope":`+jsonText(t, testScope)+`,"arguments":{}}`, ""); code == http.StatusOK || !bytes.Contains(raw, []byte("needs receipt version 3")) {
		t.Fatalf("a version 2 receipt for a scoped source: %d %s", code, raw)
	}
	service.receiptVersion = receiptVersion3

	_, err := service.acquireWithReconciliation("scope-4", "scoped", "", newObject(), nil, nil)
	var bad badRequest
	if !errors.As(err, &bad) || err.Error() != scopeRefusal {
		t.Fatalf("a read-back of a scoped source: %v", err)
	}

	service.sources["tickets/write"] = sourceSpec{argv: []string{os.Args[0], "--tools=update_ticket"}, env: helperEnv, shape: "mcp", tools: []string{"update_ticket"}, endpoint: "https://mcp.example/", scope: testScope}
	who := &caller{issuer: "https://login.example", subject: "user-7", tokenDigest: "sha256:" + strings.Repeat("a", 64)}
	_, err = service.actKeyed(json.RawMessage(`"scope-4"`), json.RawMessage(`"tickets"`), json.RawMessage(`"update_ticket"`), json.RawMessage(`{}`), json.RawMessage(`{}`), json.RawMessage(`[]`), who, actionKeyMembers{})
	var refused actRefusal
	if !errors.As(err, &refused) || refused.step != "platform" || !strings.Contains(refused.reason, "is fixed to a scope identifier, and /act takes none") || strings.Contains(refused.reason, "quipe") {
		t.Fatalf("an action on a scoped write source: %v", err)
	}
	if service.started.Load() != started {
		t.Fatal("a source started")
	}

	root := t.TempDir()
	for _, scope := range []string{"a\tb", strings.Repeat("a", 129), "a" + string(rune(0x200b))} {
		_, err := newGatewayService(filepath.Join(root, "store"), testSeed, "gateway:test", filepath.Join(root, "registry.jsonl"),
			map[string]sourceSpec{"scoped": {argv: []string{os.Args[0]}, scope: scope}})
		if err == nil || !strings.Contains(err.Error(), "scope is not a scope identifier") || strings.Contains(err.Error(), scope) {
			t.Fatalf("a scope out of form, %q: %v", scope, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "store")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused service made its store: %v", err)
	}
}

// A platform's scope (engineVersion 20): a scope identifier of its form,
// fixed on the platform's history and live sources, on a platform that
// allows no write, in a configuration with no MCP server; a refusal names
// the platform and quotes nothing of the value.
func TestThePlatformScopeConfiguration(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	ref := "postgres@" + digestOf(postgresBinding)
	at := func(version, extra, platformExtra string, ops ...string) string {
		if len(ops) == 0 {
			ops = []string{"history", "live"}
		}
		return strings.Replace(engineJSON(t, catalog, extra, platformJSONFor(t, "warehouse", ref, "engine-warehouse", platformExtra, ops...)), `"engineVersion":"1"`, `"engineVersion":"`+version+`"`, 1)
	}
	cfg, sources, err := load(t, at("20", ``, `,"scope":`+jsonText(t, testScope)))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.platforms) != 1 || cfg.platforms[0].scope != testScope || len(sources) != 2 ||
		sources["warehouse/history"].scope != testScope || sources["warehouse/live"].scope != testScope {
		t.Fatalf("the scope fixed on both sources: %+v %+v", cfg.platforms, sources)
	}
	// A version-20 file without the member loads, its sources fixed to none.
	if _, sources, err := load(t, at("20", ``, ``)); err != nil || sources["warehouse/history"].scope != "" || sources["warehouse/live"].scope != "" {
		t.Fatalf("version 20 without a scope: %v %+v", err, sources)
	}
	const outOfForm = "platform warehouse: scope must be a scope identifier, 1 to 128 bytes"
	for _, tc := range []struct{ name, text, want, quoted string }{
		{"version 19", at("19", ``, `,"scope":"kappa-a"`), "platform warehouse: scope is a version-20 member; engineVersion 19 has no scope", "kappa-a"},
		{"empty", at("20", ``, `,"scope":""`), outOfForm, ""},
		{"null", at("20", ``, `,"scope":null`), outOfForm, ""},
		{"not a string", at("20", ``, `,"scope":7`), outOfForm, ""},
		{"an array", at("20", ``, `,"scope":["kappa-a"]`), outOfForm, "kappa-a"},
		{"too long", at("20", ``, `,"scope":"`+strings.Repeat("x", 129)+`"`), outOfForm, strings.Repeat("x", 129)},
		{"too long in bytes", at("20", ``, `,"scope":"`+strings.Repeat("x", 127)+`é"`), outOfForm, strings.Repeat("x", 127)},
		{"a control character", at("20", ``, `,"scope":"kappa\u0007a"`), outOfForm, "kappa"},
		{"a tab", at("20", ``, `,"scope":"kappa\ta"`), outOfForm, "kappa"},
		{"a line feed", at("20", ``, `,"scope":"kappa\na"`), outOfForm, "kappa"},
		{"a zero width space", at("20", ``, `,"scope":"kappa\u200ba"`), outOfForm, "kappa"},
		{"a bidi override", at("20", ``, `,"scope":"kappa\u202ea"`), outOfForm, "kappa"},
		{"a private use code point", at("20", ``, `,"scope":"kappa\ue000a"`), outOfForm, "kappa"},
		{"a noncharacter", at("20", ``, `,"scope":"kappa\ufdd0a"`), outOfForm, "kappa"},
		{"a lone surrogate", at("20", ``, `,"scope":"kappa\ud800a"`), "lone surrogate", "kappa"},
		{"beside write", at("20", ``, `,"write":true,"scope":"kappa-a"`, "history", "live", "write"), "platform warehouse: scope fixes the platform's reads to a scope identifier, /act takes none, and the platform sets write: true", "kappa-a"},
		{"beside mcp", at("20", `,"mcp":{"listen":"127.0.0.1:8788"}`, `,"scope":"kappa-a"`), "platform warehouse: scope is refused beside mcp", "kappa-a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := load(t, tc.text)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
			if tc.quoted != "" && strings.Contains(err.Error(), tc.quoted) {
				t.Fatalf("the refusal quotes the value: %v", err)
			}
		})
	}
}

// connect --replace keeps a platform's scope, which connect has no flag
// for: an entry written without it would serve, from the platform's
// sources, requests that name no scope. A replacement that sets --write,
// which a scope refuses, is refused before anything is asked, and the file
// is left as it was.
func TestConnectReplaceKeepsTheScope(t *testing.T) {
	f := newConnectFixture(t, currentPolicyBinding, ``)
	entry := `"warehouse":{"binding":"postgres@` + digestOf(currentPolicyBinding) + `","credentials":{"history":{"file":"` + escapePath(f.credentials) + `"},"live":{"file":"` + escapePath(f.credentials) + `"}},"user":"engine-warehouse","operationDescriptors":{"live":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"scope":` + jsonText(t, testScope) + `}`
	text := strings.Replace(strings.Replace(f.fileText(t), `"engineVersion":"1"`, `"engineVersion":"20"`, 1), `"platforms":{}`, `"platforms":{`+entry+`}`, 1)
	if err := os.WriteFile(f.config, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadEngineConfig(f.config, stubAccounts(stubUsers)); err != nil {
		t.Fatal(err)
	}
	req := f.request()
	req.replace = true
	req.write = true
	req.credentials = map[string]string{"history": f.credentials, "live": f.credentials, "write": f.credentials}
	if _, err := connect(context.Background(), req, f.host, f.check); err == nil || err.Error() != "platform warehouse carries a scope, which --replace keeps, and a platform with a scope allows no write; remove scope from the file first, or replace the entry without --write" {
		t.Fatalf("a replacement with --write: %v", err)
	}
	if len(f.asked) != 0 || f.fileText(t) != text {
		t.Fatal("nothing is asked and nothing is written for a replacement the scope would not fit")
	}
	req.write = false
	req.credentials = map[string]string{"history": f.credentials, "live": f.credentials}
	f.captured = `{"query":{"description":"Run a query","inputSchemaText":"{\"type\":\"object\"}"}}`
	if _, err := connect(context.Background(), req, f.host, f.check); err != nil {
		t.Fatal(err)
	}
	// The sources connect asked of are the platform's as serve derives
	// them from the configuration connect writes: the scope among them.
	if len(f.asked) == 0 {
		t.Fatal("connect asked of no source")
	}
	for _, spec := range f.asked {
		if spec.scope != testScope {
			t.Fatalf("connect asked of a source without the scope it keeps: %+v", spec)
		}
	}
	after, bindings, err := loadEngineConfig(f.config, stubAccounts(stubUsers))
	if err != nil {
		t.Fatal(err)
	}
	if sources := deriveSources(after, bindings); after.version != "20" || after.platforms[0].scope != testScope || sources["warehouse/live"].scope != testScope {
		t.Fatalf("version %s, scope %q: the scope kept as written", after.version, after.platforms[0].scope)
	}
	if written := f.fileText(t); !strings.Contains(written, `"scope": `+jsonText(t, testScope)) {
		t.Fatalf("the file as written: %s", written)
	}
}
