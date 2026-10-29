package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCustomerCommandRegistrationUsesSandbox(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("restricted customer commands refuse on this platform")
	}
	dir := t.TempDir()
	bin, executable := buildMCPStandIns(t, dir)
	workspace := filepath.Join(dir, "workspace")
	if err := os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	env := filepath.Join(dir, "environment")
	if err := os.WriteFile(env, []byte("SERVICE_TOKEN=secret-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	raw := map[string]any{
		"bindingVersion": "2", "customer": true, "platform": "tickets",
		"operations": map[string]any{"live": map[string]any{
			"shape": "mcp", "server": map[string]any{"command": []string{executable, "run", "--env-file", env}, "workspace": workspace},
			"licence": "fixture", "tools": []string{"query"}, "toolTaxonomies": map[string]any{"query": map[string]string{"operation": "read", "effect": "read-external"}},
		}},
	}
	text, _ := json.Marshal(raw)
	f, req, check, adapt := customerFixture(t, bin, string(text), false)
	if _, err := connect(context.Background(), req, f.host, check); err != nil {
		t.Fatal(err)
	}
	cfg, bindings, err := loadEngineConfig(f.config, stubAccounts(stubUsers))
	if err != nil {
		t.Fatal(err)
	}
	source := adapt(deriveSources(cfg, bindings)[req.platform+"/live"])
	service, _ := testService(t)
	if _, _, _, err := service.runSource(req.platform+"/live", source, []byte(`{"tool":"query","arguments":{}}`)); err != nil {
		t.Fatal(err)
	}
}

func TestGenericCustomerBindingRegistersAcquiresAndVerifies(t *testing.T) {
	bin, _ := buildMCPStandIns(t, t.TempDir())
	target := newWriteStandIn(t, customerTools)
	binding := strings.Replace(customerBinding(target.URL, ""), `"bindingVersion":"2"`, `"bindingVersion":"2","customer":true`, 1)
	f, req, check, adapt := customerFixture(t, bin, binding, false)
	if _, err := connect(context.Background(), req, f.host, check); err != nil {
		t.Fatal(err)
	}
	cfg, bindings, err := loadEngineConfig(f.config, stubAccounts(stubUsers))
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.platforms[0]
	raw, err := os.ReadFile(filepath.Join(f.config+".descriptors", strings.TrimPrefix(p.operationDescriptors["live"], "sha256:")+".json"))
	if err != nil {
		t.Fatal(err)
	}
	snap, err := parseSnapshot(raw)
	if err != nil || snap.version != "3" || len(snap.tools) != 2 {
		t.Fatalf("customer snapshot: %v %+v", err, snap)
	}
	frontCfg := cfg
	frontCfg.mcp = &mcpConfig{concurrency: 1}
	front, err := newMCPServer(frontCfg, bindings, nil, f.config)
	if err != nil || len(front.toolList()) != 3 {
		t.Fatalf("declared tools plus seal: %v", err)
	}
	service, server := testService(t)
	name := req.platform + "/live"
	service.sources[name] = adapt(deriveSources(cfg, bindings)[name])
	code, result := post(t, server, "/acquire", `{"session":"customer","source":"`+name+`","arguments":{"tool":"query","arguments":{}}}`)
	if code != http.StatusOK {
		t.Fatalf("customer acquisition: %d %v", code, result)
	}
	if targetCalls(target) != 1 {
		t.Fatal("registration called a tool or acquisition did not call exactly once")
	}
	code, result = post(t, server, "/seal", `{"session":"customer"}`)
	if code != http.StatusOK {
		t.Fatalf("seal: %d %v", code, result)
	}
	report, err := verifyWithRegistry(service.storeRoot, service.regPath, service.authority, service.publicKey)
	if err != nil || !report.OK {
		t.Fatalf("receipt verification: %v %+v", err, report)
	}
}

func TestCustomerCommandBindingRequiresOwnerAndPreservesArguments(t *testing.T) {
	workspace := t.TempDir()
	raw := map[string]any{
		"bindingVersion": "2", "customer": true, "platform": "customer",
		"operations": map[string]any{"live": map[string]any{
			"shape": "mcp", "server": map[string]any{"command": []string{"customer-server", "argument with spaces"}, "workspace": workspace},
			"licence": "fixture", "tools": []string{"lookup"}, "toolTaxonomies": map[string]any{"lookup": map[string]string{"operation": "read", "effect": "read-external"}},
		}},
	}
	encoded, _ := json.Marshal(raw)
	b, err := parseBinding(encoded)
	if err != nil {
		t.Fatal(err)
	}
	cfg := engineConfig{platforms: []platformConfig{{name: "customer", credentials: map[string]string{"live": "credential"}}}}
	spec := deriveSources(cfg, map[string]binding{"customer": b})["customer/live"]
	if spec.shape != "mcp" || !contains(spec.argv, "--customer-binding") || !contains(spec.argv, "--sandbox-source=customer/live") || !contains(spec.argv, "--sandbox-workspace="+workspace) {
		t.Fatalf("customer source: %v", spec.argv)
	}
	last := spec.argv[len(spec.argv)-3:]
	if strings.Join(last, "|") != "--|customer-server|argument with spaces" {
		t.Fatal("server argv was split or reinterpreted")
	}
	delete(raw, "customer")
	encoded, _ = json.Marshal(raw)
	if _, err := parseBinding(encoded); err == nil {
		t.Fatal("command bypassed customer registration")
	}
}
