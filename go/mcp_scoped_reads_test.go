package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// An MCP server that names scope or scopeFrom serves live tools declared
// effect read-external alone (ADR-0044), and so does every platform fixed to
// a scope identifier, whatever the front, none included (ADR-0046): a
// propose or an act tool, or one with no declaration, refuses both starts,
// serve's and gateway mcp's, with a sentence naming the platform and the
// tool and nothing else. A platform of no scope identifier outside the
// caller form is unchanged. Every name here is synthetic.

const (
	readsReadTool = "list_records"
	readsActTool  = "close_record"
)

// readsRefusal is the start's refusal of the act tool of platform records:
// its first clause, as ADR-0044 wrote it.
const readsRefusal = `platform records: tool "` + readsActTool + `" is not declared effect read-external`

// readsSentence is the whole of the start's one sentence for the platform
// and the tool, written out as ADR-0046, decision 2 states it.
func readsSentence(platform, tool string) string {
	return `platform ` + platform + `: tool "` + tool + `" is not declared effect read-external, and a platform fixed to a scope identifier, or one an MCP server that names scopeFrom serves, takes no other live tool, since no decision policy holds a live tool's call (ADR-0044, ADR-0046); declare the tool read-external if it only reads, or move it to a platform of no scope identifier, with no mcp or an mcp that names neither scope nor scopeFrom`
}

var (
	readsRead    = ToolTaxonomy{Operation: "read", Effect: "read-external"}
	readsAct     = ToolTaxonomy{Operation: "act", Effect: "act"}
	readsPropose = ToolTaxonomy{Operation: "propose", Effect: "propose"}
)

// readsFronts are the three ways a server of either form serves platform
// records: fixed to its scope identifier, and taking its callers' with the
// platform fixed to one or to none.
var readsFronts = []struct {
	name  string
	form  mcpConfig
	scope string
}{
	{"fixed to the platform's scope identifier", mcpConfig{scope: callerScopeA}, callerScopeA},
	{"of each caller, the platform fixed to a scope identifier", mcpConfig{scopeFromCaller: true}, callerScopeA},
	{"of each caller, the platform of no scope identifier", mcpConfig{scopeFromCaller: true}, ""},
}

// readsConfig is a configuration of platform records, fixed to scope, and
// the server of the form given.
func readsConfig(form mcpConfig, scope string) engineConfig {
	m := form
	m.listen, m.sessions, m.idleSeconds, m.concurrency, m.callsPerMinute = "127.0.0.1:8788", 1, 60, 1, 1
	return engineConfig{listen: "127.0.0.1:8787", mcp: &m,
		platforms: []platformConfig{{name: "records", scope: scope, binding: "records@sha256:" + strings.Repeat("0", 64), operationDescriptors: map[string]string{"live": "sha256:" + strings.Repeat("0", 64)}}}}
}

// readsLive is platform records' binding: a live operation whose tools are
// the act tool and the read tool, in that order, each with the declaration
// given, and none where owners holds no entry for it; nil owners is a
// binding of no declarations at all.
func readsLive(owners map[string]ToolTaxonomy) map[string]binding {
	op := &operation{name: "live", shape: "mcp", tools: []string{readsActTool, readsReadTool}, taxonomies: owners}
	version := "2"
	if owners == nil {
		version = "1"
	}
	return map[string]binding{"records": {version: version, platform: "records", live: op}}
}

// The refusal is the one sentence, exactly, and names the platform and the
// tool, and nothing else: neither the platform's scope identifier nor
// another tool.
func holdReadsRefusal(t *testing.T, what string, err error) {
	t.Helper()
	if want := readsSentence("records", readsActTool); err == nil || err.Error() != want || !strings.HasPrefix(want, readsRefusal) {
		t.Fatalf("%s: want %q, got %v", what, want, err)
	}
	if strings.Contains(err.Error(), callerScopeA) || strings.Contains(err.Error(), readsReadTool) {
		t.Fatalf("%s: the refusal names more than the platform and the tool: %v", what, err)
	}
}

// A server of either form refuses to start, and so does the signer under
// the same configuration, where a live tool it would serve is declared an
// act or a propose, has no declaration, or declares an effect other than
// read-external: the engine's own read, or read-external under an operation
// that cannot carry it.
func TestAScopedFrontRefusesAtStartALiveToolNotDeclaredReadExternal(t *testing.T) {
	for _, declared := range []struct {
		name   string
		owners map[string]ToolTaxonomy
	}{
		{"an act", map[string]ToolTaxonomy{readsActTool: readsAct, readsReadTool: readsRead}},
		{"a propose", map[string]ToolTaxonomy{readsActTool: readsPropose, readsReadTool: readsRead}},
		{"no declaration of the tool", map[string]ToolTaxonomy{readsReadTool: readsRead}},
		{"no declarations at all", nil},
		{"the engine's own read", map[string]ToolTaxonomy{readsActTool: {Operation: "read", Effect: "read"}, readsReadTool: readsRead}},
		{"read-external under the act operation", map[string]ToolTaxonomy{readsActTool: {Operation: "act", Effect: "read-external"}, readsReadTool: readsRead}},
	} {
		for _, front := range readsFronts {
			t.Run(declared.name+", "+front.name, func(t *testing.T) {
				cfg := readsConfig(front.form, front.scope)
				_, err := newMCPServer(cfg, readsLive(declared.owners), nil, "")
				holdReadsRefusal(t, "gateway mcp", err)
				_, _, err = engineStart(&cfg, readsLive(declared.owners), engineHost{})
				holdReadsRefusal(t, "serve", err)
			})
		}
	}
	// Every live tool declared read-external passes the rule in each form.
	for _, front := range readsFronts {
		if err := scopedLiveReads(readsConfig(front.form, front.scope), readsLive(map[string]ToolTaxonomy{readsActTool: readsRead, readsReadTool: readsRead})); err != nil {
			t.Fatalf("%s: read-external tools refused: %v", front.name, err)
		}
	}
}

// readsBindingText is platform records' binding as the catalog holds it: a
// bindingVersion 2 live operation whose tools are owners' keys.
func readsBindingText(t *testing.T, owners map[string]ToolTaxonomy) string {
	t.Helper()
	tools := make([]string, 0, len(owners))
	for name := range owners {
		tools = append(tools, name)
	}
	sort.Strings(tools)
	text, err := json.Marshal(map[string]any{"bindingVersion": "2", "platform": "records", "operations": map[string]any{
		"live": map[string]any{"shape": "mcp", "server": map[string]any{"image": "ghcr.io/example/mcp-records:1.0@" + testImageDigest}, "tools": tools, "toolTaxonomies": owners, "licence": "MIT"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return string(text)
}

// readsConfigFile is an engine configuration file of version 28: platform
// records with the binding given, fixed to scope (or to none), an identity
// whose keys are the issuer's, and the mcp member given; for mcp "", a file
// of neither identity nor mcp.
func readsConfigFile(t *testing.T, bindingText, mcp, scope string, issuer *testIssuer) string {
	t.Helper()
	catalog := catalogWith(t, map[string]string{"records": bindingText})
	keys := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(keys, issuer.keySet(), 0o600); err != nil {
		t.Fatal(err)
	}
	extra := `,"identity":{"issuer":"https://login.example","audience":"gateway:acme","keys":"` + escapePath(keys) + `"},"mcp":` + mcp
	if mcp == "" {
		extra = ""
	}
	platformExtra := `,"operationDescriptors":{"live":"sha256:` + strings.Repeat("0", 64) + `"}`
	if scope != "" {
		platformExtra += `,"scope":` + jsonText(t, scope)
	}
	text := strings.Replace(engineJSON(t, catalog, extra, platformJSONFor(t, "records", "records@"+digestOf(bindingText), "engine-warehouse", platformExtra, "live")), `"engineVersion":"1"`, `"engineVersion":"28"`, 1)
	path := filepath.Join(t.TempDir(), "engine.json")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// From the configuration file, as each process reads it: gateway mcp's
// start (the file loaded, its identity read, the server built of both, as
// runMCP does once it holds the host's accounts) and serve's start refuse
// the same file, fixed to the platform's scope identifier and taking its
// callers', the platform fixed to one or to none.
func TestBothStartsRefuseAScopedFrontsActToolFromTheFile(t *testing.T) {
	issuer := newIssuer(t)
	for _, owner := range []ToolTaxonomy{readsAct, readsPropose} {
		text := readsBindingText(t, map[string]ToolTaxonomy{readsActTool: owner, readsReadTool: readsRead})
		for _, tc := range []struct{ name, mcp, scope string }{
			{"fixed", `{"listen":"127.0.0.1:8788","scope":` + jsonText(t, callerScopeA) + `}`, callerScopeA},
			{"of each caller", `{"listen":"127.0.0.1:8788","resource":"https://engine.test/mcp","scopeFrom":"caller"}`, callerScopeA},
			{"of each caller, a platform of none", `{"listen":"127.0.0.1:8788","resource":"https://engine.test/mcp","scopeFrom":"caller"}`, ""},
		} {
			t.Run(owner.Effect+", "+tc.name, func(t *testing.T) {
				config := readsConfigFile(t, text, tc.mcp, tc.scope, issuer)
				cfg, bindings, err := loadEngineConfig(config, stubAccounts(stubUsers))
				if err != nil {
					t.Fatal(err)
				}
				identity, err := loadIdentity(cfg.identity)
				if err != nil {
					t.Fatal(err)
				}
				_, err = newMCPServer(cfg, bindings, identity, config)
				holdReadsRefusal(t, "gateway mcp", err)
				_, _, err = engineStart(&cfg, bindings, engineHost{})
				holdReadsRefusal(t, "serve", err)
			})
		}
	}
}

// A server of either form whose live tools are all declared read-external
// starts, lists each caller the tools its token reaches and serves their
// calls, each receipt naming its platform's scope identifier.
func TestAScopedFrontOfReadExternalToolsStartsAndServes(t *testing.T) {
	for _, tc := range []struct {
		name         string
		form         mcpConfig
		subject      string
		claim        any
		listed, tool string
		scope        string
	}{
		{"fixed", mcpConfig{scope: callerScopeA}, subjectA, []any{callerScopeA}, "a.lookup,engine.seal", "a.lookup", callerScopeA},
		{"of each caller", mcpConfig{scopeFromCaller: true}, subjectEvery, nil, "a.lookup,b.lookup,engine.seal,plain.lookup", "b.lookup", callerScopeB},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// scopedMCPFixture declares every live tool read-external and
			// builds the server through newMCPServer
			f := scopedMCPFixture(t, tc.form)
			f.token = tokenFor(t, f.issuer, tc.subject, tc.claim)
			sid := f.open(t)
			if names := f.listed(t, sid); names != tc.listed {
				t.Fatalf("tools/list: %s", names)
			}
			_, _, body := f.call(t, http.MethodPost, sid, toolCall(10, tc.tool, `{"q":"R-101"}`, ""), nil)
			if scope := acquired(t, body)["receipt"].(map[string]any)["scope"]; scope != tc.scope {
				t.Fatalf("the receipt's scope is %v", scope)
			}
		})
	}
}

// A server fixed to one scope identifier serves no platform of another, but
// the platform is fixed to a scope identifier, so its act tool refuses the
// start all the same (ADR-0046, decision 1), naming it and not the server's
// identifier or its own. A platform of no scope identifier beside the fixed
// form, which the server does not serve, is not read.
func TestAFrontFixedToAScopeHoldsThePlatformsOfAnotherScopeToo(t *testing.T) {
	cfg := readsConfig(mcpConfig{scope: callerScopeA}, callerScopeA)
	cfg.platforms = append(cfg.platforms, platformConfig{name: "other", scope: callerScopeB})
	bindings := readsLive(map[string]ToolTaxonomy{readsActTool: readsRead, readsReadTool: readsRead})
	bindings["other"] = binding{version: "2", platform: "other", live: &operation{name: "live", shape: "mcp", tools: []string{readsActTool}, taxonomies: map[string]ToolTaxonomy{readsActTool: readsAct}}}
	err := scopedLiveReads(cfg, bindings)
	if want := readsSentence("other", readsActTool); err == nil || err.Error() != want || strings.Contains(err.Error(), callerScopeA) || strings.Contains(err.Error(), callerScopeB) {
		t.Fatalf("a platform of another scope identifier: want %q, got %v", want, err)
	}
	cfg.platforms[1].scope = ""
	if err := scopedLiveReads(cfg, bindings); err != nil {
		t.Fatalf("a platform of no scope identifier the fixed form does not serve: %v", err)
	}
}

// A server of neither form is unchanged: it starts with an act live tool
// and lists it with the annotations its effect derives. A configuration with
// no mcp member is not read by the rule either.
func TestAnUnscopedFrontStillServesAnActLiveTool(t *testing.T) {
	s, err := servedOwnerServer(t, map[string]binding{"records": ownedLive("records", map[string]ToolTaxonomy{readsActTool: readsAct, readsReadTool: readsRead})}, nil)
	if err != nil {
		t.Fatalf("an unscoped front with an act tool: %v", err)
	}
	found := false
	for _, e := range servedEntries(t, s) {
		if e.Name == "records."+readsActTool {
			found = e.Annotations["destructiveHint"] && !e.Annotations["readOnlyHint"] && e.Meta["effect"] == "act"
		}
	}
	if !found {
		t.Fatalf("the act tool is not listed as an act: %+v", servedEntries(t, s))
	}
	cfg := readsConfig(mcpConfig{}, "")
	if err := scopedLiveReads(cfg, readsLive(map[string]ToolTaxonomy{readsActTool: readsAct, readsReadTool: readsRead})); err != nil {
		t.Fatalf("an mcp of neither form: %v", err)
	}
	cfg.mcp = nil
	if err := scopedLiveReads(cfg, readsLive(map[string]ToolTaxonomy{readsActTool: readsAct, readsReadTool: readsRead})); err != nil {
		t.Fatalf("no mcp member, a platform of no scope identifier: %v", err)
	}
}

// With no mcp member, nothing serves the platform over MCP, but a caller
// that reaches its scope identifier would send /acquire naming the tool to
// the signer itself (ADR-0046). So serve refuses to start, with the same
// one sentence, where a platform fixed to a scope identifier has a live tool
// declared an act or a propose, has no declaration, or declares an effect
// other than read-external; gateway mcp, given the file, refuses it too.
// Read-external tools start as before.
func TestTheSignerRefusesAtStartAScopedPlatformsLiveToolNotDeclaredReadExternal(t *testing.T) {
	for _, declared := range []struct {
		name   string
		owners map[string]ToolTaxonomy
	}{
		{"an act", map[string]ToolTaxonomy{readsActTool: readsAct, readsReadTool: readsRead}},
		{"a propose", map[string]ToolTaxonomy{readsActTool: readsPropose, readsReadTool: readsRead}},
		{"no declaration of the tool", map[string]ToolTaxonomy{readsReadTool: readsRead}},
		{"no declarations at all", nil},
		{"the engine's own read", map[string]ToolTaxonomy{readsActTool: {Operation: "read", Effect: "read"}, readsReadTool: readsRead}},
		{"read-external under the act operation", map[string]ToolTaxonomy{readsActTool: {Operation: "act", Effect: "read-external"}, readsReadTool: readsRead}},
	} {
		t.Run(declared.name, func(t *testing.T) {
			cfg := readsConfig(mcpConfig{}, callerScopeA)
			cfg.mcp = nil
			statements, sources, err := engineStart(&cfg, readsLive(declared.owners), engineHost{})
			holdReadsRefusal(t, "serve", err)
			if statements != nil || sources != nil {
				t.Fatalf("serve derived sources for a configuration it refuses: %v", sources)
			}
		})
	}
	cfg := readsConfig(mcpConfig{}, callerScopeA)
	cfg.mcp = nil
	if err := scopedLiveReads(cfg, readsLive(map[string]ToolTaxonomy{readsActTool: readsRead, readsReadTool: readsRead})); err != nil {
		t.Fatalf("read-external tools of a scoped platform refused: %v", err)
	}
}

// A file a gateway of the release before this one started: a platform fixed
// to a scope identifier, its live operation naming an act or a propose tool,
// and no mcp member, at the version that brought scope and at the version of
// the MCP forms. It still loads, its binding still naming the tool, and
// serve's start refuses it by name: the tool is not left out of a source
// that starts.
func TestAnEarlierScopedFileWithAnActLiveToolIsRefusedByNameNotNarrowed(t *testing.T) {
	issuer := newIssuer(t)
	for _, owner := range []ToolTaxonomy{readsAct, readsPropose} {
		text := readsBindingText(t, map[string]ToolTaxonomy{readsActTool: owner, readsReadTool: readsRead})
		for _, version := range []string{"20", "28"} {
			t.Run(owner.Effect+", version "+version, func(t *testing.T) {
				config := readsConfigFile(t, text, "", callerScopeA, issuer)
				raw, err := os.ReadFile(config)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(config, []byte(strings.Replace(string(raw), `"engineVersion":"28"`, `"engineVersion":"`+version+`"`, 1)), 0o600); err != nil {
					t.Fatal(err)
				}
				cfg, bindings, err := loadEngineConfig(config, stubAccounts(stubUsers))
				if err != nil {
					t.Fatalf("the file no longer loads: %v", err)
				}
				if cfg.mcp != nil || cfg.platforms[0].scope != callerScopeA || !slices.Contains(bindings["records"].live.tools, readsActTool) {
					t.Fatalf("the file loaded narrowed: mcp %v, tools %v", cfg.mcp, bindings["records"].live.tools)
				}
				_, sources, err := engineStart(&cfg, bindings, engineHost{})
				holdReadsRefusal(t, "serve", err)
				if sources != nil {
					t.Fatalf("serve derived sources for a file it refuses: %v", sources)
				}
			})
		}
	}
}

// connect holds the configuration it would write to the rule both starts
// apply: a platform whose live operation has an act tool is not connected
// behind a server that takes its callers' scope identifiers, nothing is
// asked of its adapters and the file is left as it was.
func TestConnectRefusesAnActLiveToolBehindAScopedFront(t *testing.T) {
	f := newConnectFixture(t, currentPolicyBinding, ``)
	text := readsBindingText(t, map[string]ToolTaxonomy{readsActTool: readsAct, readsReadTool: readsRead})
	if err := os.WriteFile(filepath.Join(f.catalog, "records.json"), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	keys := abs(t, t.TempDir(), "keys.json")
	config := strings.Replace(strings.Replace(f.fileText(t), `"engineVersion":"1"`, `"engineVersion":"28"`, 1), `"listen":"127.0.0.1:0"`,
		`"listen":"127.0.0.1:8787","identity":{"issuer":"https://login.example","audience":"gateway:acme","keys":"`+keys+`"},"mcp":{"listen":"127.0.0.1:8788","resource":"https://engine.test/mcp","scopeFrom":"caller"}`, 1)
	if err := os.WriteFile(f.config, []byte(config), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadEngineConfig(f.config, stubAccounts(stubUsers)); err != nil {
		t.Fatal(err)
	}
	req := f.request()
	req.platform, req.binding = "records", "records"
	req.credentials = map[string]string{"live": f.credentials}
	_, err := connect(context.Background(), req, f.host, f.check)
	holdReadsRefusal(t, "connect", err)
	if len(f.asked) != 0 || f.fileText(t) != config {
		t.Fatal("connect asked an adapter or wrote the file for a platform both starts would refuse")
	}
}

// So does connect under the fixed form, and with no mcp member at all
// (ADR-0046): a platform fixed to a scope identifier, replaced with a
// binding whose live tools hold an act (connect --replace keeps the scope),
// is refused before an adapter is asked, and the file is unchanged.
func TestConnectRefusesAnActLiveToolOfAScopedPlatform(t *testing.T) {
	for _, front := range []struct {
		name string
		mcp  map[string]any
	}{
		{"behind a front fixed to the scope", map[string]any{"listen": "127.0.0.1:8788", "resource": "https://engine.test/mcp", "scope": callerScopeA}},
		{"with no mcp member", nil},
	} {
		t.Run(front.name, func(t *testing.T) {
			f := newConnectFixture(t, currentPolicyBinding, ``)
			catalogFile := filepath.Join(f.catalog, "records.json")
			if err := os.WriteFile(catalogFile, []byte(readsBindingText(t, map[string]ToolTaxonomy{readsReadTool: readsRead})), 0o600); err != nil {
				t.Fatal(err)
			}
			req := f.request()
			req.platform, req.binding = "records", "records"
			req.credentials = map[string]string{"live": f.credentials}
			if _, err := connect(context.Background(), req, f.host, f.check); err != nil {
				t.Fatalf("the read-only binding: %v", err)
			}
			// json.Marshal escapes the path itself: abs's doubled backslashes are for text.
			keys := filepath.Join(t.TempDir(), "keys.json")
			var file map[string]any
			if err := json.Unmarshal([]byte(f.fileText(t)), &file); err != nil {
				t.Fatal(err)
			}
			platform, ok := file["platforms"].(map[string]any)["records"].(map[string]any)
			if !ok {
				t.Fatalf("connect wrote no platform records: %v", file)
			}
			platform["scope"] = callerScopeA
			file["engineVersion"], file["listen"] = "28", "127.0.0.1:8787"
			if front.mcp != nil {
				file["identity"] = map[string]any{"issuer": "https://login.example", "audience": "gateway:acme", "keys": keys}
				file["mcp"] = front.mcp
			}
			encoded, err := json.Marshal(file)
			if err != nil {
				t.Fatal(err)
			}
			config := string(encoded)
			if err := os.WriteFile(f.config, []byte(config), 0o640); err != nil {
				t.Fatal(err)
			}
			if _, _, err := loadEngineConfig(f.config, stubAccounts(stubUsers)); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(catalogFile, []byte(readsBindingText(t, map[string]ToolTaxonomy{readsActTool: readsAct, readsReadTool: readsRead})), 0o600); err != nil {
				t.Fatal(err)
			}
			asked := len(f.asked)
			req.replace = true
			_, err = connect(context.Background(), req, f.host, f.check)
			holdReadsRefusal(t, "connect --replace", err)
			if len(f.asked) != asked || f.fileText(t) != config {
				t.Fatal("connect asked an adapter or wrote the file for a platform both starts would refuse")
			}
		})
	}
}
