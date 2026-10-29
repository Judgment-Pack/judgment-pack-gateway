package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

const customerTools = `[{"name":"query","description":"Inspect tickets","inputSchema":{"type":"object"}},{"name":"sibling","description":"Other ticket operation","inputSchema":{"type":"object"}},{"name":"unallowed","inputSchema":{"type":"object"}}]`

func customerBinding(live, write string) string {
	ops := []string{}
	for _, entry := range []struct{ name, url string }{{"live", live}, {"write", write}} {
		if entry.url == "" {
			continue
		}
		family, effect := "read", "read-external"
		if entry.name == "write" {
			family, effect = "act", "act"
		}
		ops = append(ops, fmt.Sprintf(`%q:{"shape":"mcp","server":{"url":%q,"bearer":"token"},"tools":["query","sibling"],"toolTaxonomies":{"query":{"operation":%q,"effect":%q},"sibling":{"operation":%q,"effect":%q}},"licence":"fixture"}`, entry.name, entry.url, family, effect, family, effect))
	}
	return `{"bindingVersion":"2","platform":"tickets","operations":{` + strings.Join(ops, ",") + `}}`
}

func customerFixture(t *testing.T, bin, text string, write bool) (*connectFixture, connectRequest, func(context.Context, sourceSpec) ([]byte, error), func(sourceSpec) sourceSpec) {
	t.Helper()
	f := newConnectFixture(t, restrictedBinding, "")
	if err := os.WriteFile(filepath.Join(f.catalog, "tickets.json"), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	req := f.request()
	req.binding = "tickets"
	req.write = write
	req.credentials = map[string]string{}
	binding, err := parseBinding([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	real := map[string]string{}
	for _, op := range []string{"live", "write"} {
		if (op == "live" && binding.live == nil) || (op == "write" && (!write || binding.write == nil)) {
			continue
		}
		req.credentials[op] = f.credentials
		real[op] = filepath.Join(t.TempDir(), op+".json")
		if err := os.WriteFile(real[op], []byte(`{"token":"fixture-`+op+`-credential"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	adapt := func(spec sourceSpec) sourceSpec {
		op := "live"
		if contains(spec.argv, "--error-results") {
			op = "write"
		}
		spec.user = ""
		spec.argv = append([]string(nil), spec.argv...)
		exe := "adapter-mcp"
		if runtime.GOOS == "windows" {
			exe += ".exe"
		}
		spec.argv[0] = filepath.Join(bin, exe)
		for i, arg := range spec.argv {
			if strings.HasPrefix(arg, "--credentials=") {
				spec.argv[i] = "--credentials=" + real[op]
			}
		}
		return spec
	}
	check := func(ctx context.Context, spec sourceSpec) ([]byte, error) {
		f.asked = append(f.asked, spec)
		return runCheck(ctx, adapt(spec))
	}
	return f, req, check, adapt
}

func targetCalls(s *writeStandIn) int {
	n := 0
	for _, r := range s.requests() {
		if r.method == "tools/call" {
			n++
		}
	}
	return n
}

func TestV2CustomerCatalogConnectAndDispatch(t *testing.T) {
	bin, _ := buildMCPStandIns(t, t.TempDir())
	for _, mode := range []string{"both", "live-only", "write-only", "write-disabled"} {
		t.Run(mode, func(t *testing.T) {
			live, write := newWriteStandIn(t, customerTools), newWriteStandIn(t, customerTools)
			liveURL, writeURL, enabled := live.URL, write.URL, true
			if mode == "live-only" {
				writeURL = ""
				enabled = false
			}
			if mode == "write-only" {
				liveURL = ""
			}
			if mode == "write-disabled" {
				enabled = false
			}
			f, req, check, adapt := customerFixture(t, bin, customerBinding(liveURL, writeURL), enabled)
			if _, err := connect(context.Background(), req, f.host, check); err != nil {
				t.Fatal(err)
			}
			cfg, bindings, err := loadEngineConfig(f.config, stubAccounts(stubUsers))
			if err != nil {
				t.Fatal(err)
			}
			p, b := cfg.platforms[0], bindings[req.platform]
			ops := enabledMCPOperations(p, b)
			if cfg.version != "12" || p.descriptors != "" || len(p.operationDescriptors) != len(ops) || len(f.asked) != len(ops) {
				t.Fatal("incomplete operation pins")
			}
			for op := range ops {
				data, err := os.ReadFile(filepath.Join(f.config+".descriptors", strings.TrimPrefix(p.operationDescriptors[op], "sha256:")+".json"))
				if err != nil {
					t.Fatal(err)
				}
				snapshot, err := parseSnapshot(data)
				if err != nil || snapshot.operation != op || snapshotOwners(snapshot, ops[op]) != nil {
					t.Fatalf("operation snapshot %s: %v", op, err)
				}
				preview, err := previewDescriptors(f.config, cfg, bindings, req.platform, op)
				if err != nil || !strings.Contains(preview, "operation "+op) {
					t.Fatalf("preview: %v %s", err, preview)
				}
			}
			// Exercise the actual current frontend from the persisted customer
			// registration. Only live leaves and seal are offered, never write.
			frontConfig := cfg
			frontConfig.mcp = &mcpConfig{concurrency: 1}
			front, err := newMCPServer(frontConfig, bindings, nil, f.config)
			if err != nil {
				t.Fatal(err)
			}
			listed := front.toolList()
			wantCount := 1
			if b.live != nil {
				wantCount += len(b.live.tools)
			}
			if len(listed) != wantCount {
				t.Fatal("frontend leaked write/unknown tool")
			}
			for _, raw := range listed {
				var tool struct {
					Name        string                             `json:"name"`
					Meta        struct{ Operation, Effect string } `json:"_meta"`
					Annotations map[string]bool                    `json:"annotations"`
				}
				if json.Unmarshal(raw, &tool) != nil {
					t.Fatal("frontend tool shape")
				}
				expected := ToolTaxonomy{Operation: "act", Effect: "act"}
				if tool.Name != mcpSealTool {
					key := strings.TrimPrefix(tool.Name, req.platform+".")
					if b.live == nil {
						t.Fatal("write-only tool offered")
					}
					var ok bool
					expected, ok = b.live.taxonomies[key]
					if !ok {
						t.Fatal("unknown frontend leaf")
					}
				}
				if tool.Meta.Operation != expected.Operation || tool.Meta.Effect != expected.Effect || tool.Annotations["readOnlyHint"] != (expected.Effect != "act") {
					t.Fatal("frontend taxonomy/hints differ from persisted owner")
				}
			}
			if len(ops) == 2 {
				if _, err := previewDescriptors(f.config, cfg, bindings, req.platform); err == nil {
					t.Fatal("ambiguous preview admitted")
				}
			}
			sources := deriveSources(cfg, bindings)
			service, server := connectedTestService(t, cfg)
			for name, spec := range sources {
				source := adapt(spec)
				service.sources[name] = source
				before := targetCalls(live) + targetCalls(write)
				if _, _, _, err := service.runSource(name, source, []byte(`{"tool":"query","arguments":{}}`)); err != nil {
					t.Fatal(err)
				}
				if targetCalls(live)+targetCalls(write) != before+1 {
					t.Fatal("selected operation did not execute once")
				}
			}
			if targetCalls(live) > 0 && mode == "write-only" || targetCalls(write) > 0 && !enabled {
				t.Fatal("disabled operation executed")
			}
			if enabled {
				before := targetCalls(write)
				status, _ := post(t, server, "/act", `{"session":"v2","platform":"warehouse","tool":"query","arguments":{}}`)
				if status == http.StatusOK || targetCalls(write) != before {
					t.Fatal("taxonomy granted /act decision authority")
				}
			}
			if len(ops) == 2 {
				// Same serverInfo and exact names do not make operation pins interchangeable.
				swapped := p
				swapped.operationDescriptors = map[string]string{"live": p.operationDescriptors["write"], "write": p.operationDescriptors["live"]}
				only := cfg
				only.platforms = []platformConfig{swapped}
				if _, err := readServedPlatforms(f.config, only, bindings); err == nil {
					t.Fatal("operation swap accepted")
				}
				for _, pins := range []map[string]string{{"live": p.operationDescriptors["live"]}, {"live": p.operationDescriptors["live"], "write": p.operationDescriptors["write"], "history": p.operationDescriptors["live"]}} {
					changed := p
					changed.operationDescriptors = pins
					if operationPinsMatch(changed, b) == nil {
						t.Fatal("missing/extra operation pin accepted")
					}
				}
			}
			before := f.fileText(t)
			req.replace = true
			_, err = connect(context.Background(), req, f.host, func(ctx context.Context, s sourceSpec) ([]byte, error) {
				if contains(s.argv, "--error-results") {
					return nil, fmt.Errorf("second capture refused")
				}
				return check(ctx, s)
			})
			if enabled && (err == nil || f.fileText(t) != before) {
				t.Fatal("failed second capture replaced old configuration")
			}
		})
	}
}

func TestV2GroupDerivationIsOrderIndependent(t *testing.T) {
	cases := []struct {
		left, right, want ToolTaxonomy
		ops               []string
	}{
		{ToolTaxonomy{Operation: "run", Effect: "read-external"}, ToolTaxonomy{Operation: "run", Effect: "act"}, ToolTaxonomy{Operation: "run", Effect: "act"}, []string{"run"}},
		{ToolTaxonomy{Operation: "read", Effect: "read-external"}, ToolTaxonomy{Operation: "propose", Effect: "propose"}, ToolTaxonomy{Operation: "run", Effect: "propose"}, []string{"read", "propose"}},
		{ToolTaxonomy{Operation: "check", Effect: "read-external", CheckKind: "validate"}, ToolTaxonomy{Operation: "check", Effect: "read-external", CheckKind: "verify"}, ToolTaxonomy{Operation: "run", Effect: "read-external"}, []string{"check"}},
	}
	for _, c := range cases {
		for _, reverse := range []bool{false, true} {
			tools := map[string]ToolTaxonomy{}
			if reverse {
				tools["b"] = c.right
				tools["a"] = c.left
			} else {
				tools["a"] = c.left
				tools["b"] = c.right
			}
			summary, profile, err := SummarizeTaxonomies(tools)
			if err != nil || summary != c.want || profile.Effect != c.want.Effect || !reflect.DeepEqual(profile.Operations, c.ops) {
				t.Fatalf("summary %+v profile %+v err %v", summary, profile, err)
			}
		}
	}
}

func TestV2ShippedDeclarationsAndOwnerOverflow(t *testing.T) {
	for _, name := range []string{"postgres", "azure-devops", "databricks"} {
		text, err := os.ReadFile(filepath.Join("..", "catalog", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		b, err := parseBinding(text)
		if err != nil || b.version != "2" {
			t.Fatalf("catalog %s: %v", name, err)
		}
		for _, op := range []*operation{b.live, b.write} {
			if op == nil {
				continue
			}
			raw, err := ownerFileDeclaration(platformConfig{name: "warehouse", binding: name + "@" + digestOf(string(text))}, op)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%s/%s declaration=%d bytes", name, op.name, len(raw))
		}
		if name == "postgres" && (b.live.taxonomies["execute_sql"].Effect != "act" || b.live.taxonomies["search_objects"].Operation != "discover" || b.live.taxonomy.Effect != "act") {
			t.Fatal("SQL capability understated")
		}
	}
	key := strings.Repeat("x", maxSnapshotBytes)
	op := `{"shape":"mcp","server":{"url":"http://127.0.0.1:1/mcp","bearer":"token"},"tools":[` + fmt.Sprintf("%q", key) + `],"toolTaxonomies":{` + fmt.Sprintf("%q", key) + `:{"operation":"act","effect":"act"}},"licence":"fixture"}`
	text := `{"bindingVersion":"2","platform":"tickets","operations":{"live":` + op + `}}`
	f := newConnectFixture(t, restrictedBinding, "")
	if err := os.WriteFile(filepath.Join(f.catalog, "tickets.json"), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	req := f.request()
	req.binding = "tickets"
	req.credentials = map[string]string{"live": f.credentials}
	before := f.fileText(t)
	if _, err := connect(context.Background(), req, f.host, f.check); err == nil || len(f.asked) != 0 || before != f.fileText(t) {
		t.Fatal("overflow started target or persisted config")
	}
	if _, err := os.Stat(f.config + ".descriptors"); !os.IsNotExist(err) {
		t.Fatal("overflow published metadata")
	}
}

// Test approval preparation for a current shipped write binding. Capture performs
// no tool call; /act below still has to satisfy every original policy/citation gate.
func approveV2WriteFixture(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseEngineConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	cfg.configPath = path
	p := cfg.platforms[0]
	b, err := loadBinding(cfg.catalog, p.binding)
	if err != nil {
		t.Fatal(err)
	}
	b, err = resolveParameters(b, p.parameters, p.binding)
	if err != nil {
		t.Fatal(err)
	}
	file, err := openConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.close()
	declaration, err := ownerFileDeclaration(p, b.write)
	if err != nil {
		t.Fatal(err)
	}
	_, held, err := file.publishSnapshot(declaration)
	if err != nil {
		t.Fatal(err)
	}
	held.Close()
	argv := mcpServerArgv(filepath.Join(cfg.adapters, "adapter-mcp"), *b.write, p.credentials["write"], cfg.runtime, p.endpoint, p.name+"/write", ownerFileArguments(cfg, p, b.write)...)
	spec := sourceSpec{argv: argv, shape: "mcp", check: []string{"--descriptors-platform=" + p.name, "--descriptors-binding=" + p.binding, "--descriptors-operation=write"}}
	report, err := runCheck(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	capture, err := readCapture(report, p.name, p.binding, b.write)
	if err != nil {
		t.Fatal(err)
	}
	pin, held, err := file.publishSnapshot(capture.data)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	value, err := parseJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	top := value.(*vObject)
	platforms, _ := top.get("platforms")
	entry, _ := platforms.(*vObject).get(p.name)
	pins := newObject()
	pins.set("write", vString(pin))
	entry.(*vObject).set("operationDescriptors", pins)
	var out strings.Builder
	formatValue(&out, top, "")
	out.WriteByte('\n')
	file.beforeRename = func() error { return file.stillHeld(held) }
	if err := file.replace(data, []byte(out.String())); err != nil {
		t.Fatal(err)
	}
}

func TestV2CurrentAdmissionRefusesV1ButHistoricalReadersRemain(t *testing.T) {
	f := newConnectFixture(t, historicalRestrictedBinding, "")
	before := f.fileText(t)
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err == nil || !strings.Contains(err.Error(), "recapture V2") || len(f.asked) != 0 || f.fileText(t) != before {
		t.Fatalf("unclassified registration: %v", err)
	}
	legacy, err := parseBinding([]byte(historicalRestrictedBinding))
	if err != nil {
		t.Fatal(err)
	}
	cfg := engineConfig{platforms: []platformConfig{{name: "warehouse"}}, mcp: &mcpConfig{}}
	if _, err := newMCPServer(cfg, map[string]binding{"warehouse": legacy}, nil, ""); err == nil || !strings.Contains(err.Error(), "recapture V2") {
		t.Fatalf("unclassified frontend: %v", err)
	}
	if _, _, err := engineStart(&cfg, map[string]binding{"warehouse": legacy}, engineHost{}); err == nil || !strings.Contains(err.Error(), "recapture V2") {
		t.Fatal("unclassified source startup admitted")
	}
	raw := `{"binding":"tickets@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","capturedAt":"2026-09-15T01:02:03Z","platform":"tickets","policy":1,"tools":{"search":{"description":"Search tickets"}}}`
	if s, err := parseSnapshot([]byte(raw)); err != nil || s.version != "" {
		t.Fatalf("historical V1 decoding changed: %v", err)
	}
}

func TestV2SecondPublicationFailurePreservesOldConfig(t *testing.T) {
	bin, _ := buildMCPStandIns(t, t.TempDir())
	live, write := newWriteStandIn(t, customerTools), newWriteStandIn(t, customerTools)
	f, req, check, _ := customerFixture(t, bin, customerBinding(live.URL, write.URL), true)
	if _, err := connect(context.Background(), req, f.host, check); err != nil {
		t.Fatal(err)
	}
	before := f.fileText(t)
	req.replace = true
	publications := 0
	directorySynced = func(name string) error {
		if strings.HasSuffix(name, ".descriptors") {
			publications++
			if publications == 4 {
				return os.ErrPermission
			}
		}
		return nil
	}
	defer func() { directorySynced = nil }()
	out, err := connect(context.Background(), req, f.host, check)
	if err == nil || publications != 4 || out.written != "" || before != f.fileText(t) {
		t.Fatalf("partial publication committed: %v count%d written%q", err, publications, out.written)
	}
	if targetCalls(live) != 0 || targetCalls(write) != 0 {
		t.Fatal("capture executed target tools")
	}
	entries, err := os.ReadDir(f.config + ".descriptors")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".staged") {
			t.Fatal("product staging entry leaked")
		}
	}
}
