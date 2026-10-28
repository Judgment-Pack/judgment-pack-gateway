package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// The serving path's half of #324: every tool the MCP frontend can serve
// carries its owner's operation and effect, its standard annotations are
// derived from that effect and from nothing else, a server's annotations
// that contradict the owner refuse the start, and a write-back is an act.

// servedOwnerServer builds the MCP frontend, table and listing, for the
// given platforms' live operations, each described from a V2 snapshot that
// holds every allowed tool's owner declaration and, where hints names the
// tool, the annotations its server gave at capture.
func servedOwnerServer(t *testing.T, platforms map[string]binding, hints map[string]map[string]bool) (*mcpServer, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "engine.json")
	if err := os.WriteFile(path, []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(path+".descriptors", 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := engineConfig{listen: "127.0.0.1:8787", configPath: path, mcp: &mcpConfig{listen: "127.0.0.1:8788", sessions: 1, idleSeconds: 60, concurrency: 1, callsPerMinute: 1}}
	names := make([]string, 0, len(platforms))
	for name := range platforms {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		b := platforms[name]
		ref := name + "@sha256:" + strings.Repeat("0", 64)
		tools := newObject()
		for _, tool := range b.live.tools {
			entry := newObject()
			entry.set("taxonomy", taxonomyAsValue(b.live.taxonomies[tool]))
			if given, ok := hints[tool]; ok {
				annotations := newObject()
				for key, v := range given {
					annotations.set(key, vBool(v))
				}
				entry.set("serverAnnotations", annotations)
			}
			tools.set(tool, entry)
		}
		server := newObject()
		server.set("name", vString("fixture"))
		server.set("version", vString("1"))
		snap := newObject()
		snap.set("binding", vString(ref))
		snap.set("capturedAt", vString("2026-10-28T00:00:00Z"))
		snap.set("operation", vString("live"))
		snap.set("platform", vString(name))
		snap.set("policy", vInt(1))
		snap.set("server", server)
		snap.set("snapshotVersion", vString("2"))
		snap.set("tools", tools)
		raw := canon(snap)
		pin := digestOf(string(raw))
		if err := os.WriteFile(filepath.Join(path+".descriptors", strings.TrimPrefix(pin, "sha256:")+".json"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
		cfg.platforms = append(cfg.platforms, platformConfig{name: name, binding: ref, operationDescriptors: map[string]string{"live": pin}})
	}
	return newMCPServer(cfg, platforms, nil, path)
}

// ownedLive is a V2 binding of one live operation whose tools are owners'
// keys, in name order.
func ownedLive(platform string, owners map[string]ToolTaxonomy) binding {
	tools := make([]string, 0, len(owners))
	for name := range owners {
		tools = append(tools, name)
	}
	sort.Strings(tools)
	return binding{version: "2", platform: platform, live: &operation{name: "live", shape: "mcp", tools: tools, taxonomies: owners}}
}

// servedEntry is what a consumer reads of a listed tool to classify it.
type servedEntry struct {
	Name        string          `json:"name"`
	Annotations map[string]bool `json:"annotations"`
	Meta        map[string]any  `json:"_meta"`
}

func servedEntries(t *testing.T, s *mcpServer) []servedEntry {
	t.Helper()
	var out []servedEntry
	for _, raw := range s.toolList() {
		var e servedEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

// The served listing, as a consumer classifies it, is the handwritten
// vector: a discover, a read, an experimental check with its subkind and an
// act, and the seal tool, each with the annotations its effect derives. A
// change to what is served is a change to that file.
func TestServedListingMatchesTheHandwrittenVector(t *testing.T) {
	owners := map[string]ToolTaxonomy{
		"search": {Operation: "discover", Effect: "read-external"},
		"read":   {Operation: "read", Effect: "read-external"},
		"verify": {Operation: "check", Effect: "read-external", CheckKind: "test", Experimental: true},
		"update": {Operation: "act", Effect: "act"},
	}
	// Agreeing server annotations ride along at capture and change nothing
	// served: what is served is derived from the owner's effect.
	hints := map[string]map[string]bool{"search": {"readOnlyHint": true, "openWorldHint": false}, "update": {"readOnlyHint": true}}
	s, err := servedOwnerServer(t, map[string]binding{"tickets": ownedLive("tickets", owners)}, hints)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join("..", "testdata", "tool-taxonomy", "served-listing.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Tools []servedEntry `json:"tools"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	got := servedEntries(t, s)
	if !reflect.DeepEqual(got, vector.Tools) {
		have, _ := json.MarshalIndent(got, "", "  ")
		t.Fatalf("the served listing differs from testdata/tool-taxonomy/served-listing.json:\n%s", have)
	}
}

// A server's annotations that contradict its owner's declaration refuse
// the start of the serving path; a stronger owner than the server's own
// claim does not.
func TestServingRefusesServerAnnotationsThatContradictTheOwner(t *testing.T) {
	read := map[string]ToolTaxonomy{"search": {Operation: "discover", Effect: "read-external"}}
	for _, hints := range []map[string]bool{{"destructiveHint": true}, {"readOnlyHint": false}, {"readOnlyHint": true, "destructiveHint": true}} {
		_, err := servedOwnerServer(t, map[string]binding{"tickets": ownedLive("tickets", read)}, map[string]map[string]bool{"search": hints})
		if err == nil || !strings.Contains(err.Error(), "contradict") {
			t.Fatalf("server annotations %v on a read-external discover tool: %v", hints, err)
		}
	}
	act := map[string]ToolTaxonomy{"update": {Operation: "act", Effect: "act"}}
	s, err := servedOwnerServer(t, map[string]binding{"tickets": ownedLive("tickets", act)}, map[string]map[string]bool{"update": {"readOnlyHint": true, "destructiveHint": false}})
	if err != nil {
		t.Fatalf("a server claiming read-only refused an act owner: %v", err)
	}
	for _, e := range servedEntries(t, s) {
		if e.Name == "tickets.update" && (e.Annotations["readOnlyHint"] || !e.Annotations["destructiveHint"]) {
			t.Fatalf("the server's claim weakened the served annotations: %v", e.Annotations)
		}
	}
}

// A tool without both fields is not served: the one place a listing entry
// is made refuses it, the seal tool's entry and a platform tool's alike.
func TestAToolWithoutOperationAndEffectIsNotServed(t *testing.T) {
	for _, tool := range []mcpTool{
		{name: "tickets.search", platform: "tickets", tool: "search", binding: "tickets@sha256:" + strings.Repeat("0", 64)},
		{name: "tickets.search", platform: "tickets", tool: "search", taxonomy: ToolTaxonomy{Operation: "discover"}},
		{name: "tickets.search", platform: "tickets", tool: "search", taxonomy: ToolTaxonomy{Effect: "read-external"}},
		{name: "tickets.search", platform: "tickets", tool: "search", taxonomy: ToolTaxonomy{Operation: "read", Effect: "pure"}},
		{name: mcpSealTool, seal: true},
	} {
		if entry, err := listingEntry(tool, nil, -1); err == nil || entry != nil || !strings.Contains(err.Error(), "not served") {
			t.Fatalf("%s with %+v was listed: %s %v", tool.name, tool.taxonomy, entry, err)
		}
		count, err := newListingCount(1)
		if err != nil {
			t.Fatal(err)
		}
		if err := count.add(tool); err == nil || len(count.entries) != 0 {
			t.Fatalf("%s with %+v was counted into the listing", tool.name, tool.taxonomy)
		}
	}
}

// A binding's write operation is the executor's write-back through /act:
// each of its tools is declared act/act, and a weaker family refuses the
// binding. A live tool may still be an act (an SQL tool is), and a
// historical binding, which declares nothing, is read as before.
func TestWriteBackOperationsAreAct(t *testing.T) {
	binding := func(liveOwner, writeOwner string) string {
		return `{"bindingVersion":"2","platform":"tickets","operations":{` +
			`"live":{"shape":"mcp","server":{"image":"ghcr.io/example/tickets:1@sha256:` + strings.Repeat("ab", 32) + `"},"tools":["query"],"toolTaxonomies":{"query":` + liveOwner + `},"licence":"MIT"},` +
			`"write":{"shape":"mcp","server":{"image":"ghcr.io/example/tickets:1@sha256:` + strings.Repeat("ab", 32) + `"},"tools":["update"],"toolTaxonomies":{"update":` + writeOwner + `},"licence":"MIT"}}}`
	}
	act := `{"operation":"act","effect":"act"}`
	for _, weaker := range []string{
		`{"operation":"read","effect":"read-external"}`,
		`{"operation":"discover","effect":"read-external"}`,
		`{"operation":"propose","effect":"propose"}`,
		`{"operation":"run","effect":"act"}`,
		`{"operation":"check","effect":"read-external","checkKind":"verify"}`,
	} {
		if _, err := parseBinding([]byte(binding(act, weaker))); err == nil || !strings.Contains(err.Error(), "operation write") {
			t.Fatalf("a write-back declared %s was admitted: %v", weaker, err)
		}
	}
	for _, owners := range [][2]string{{act, act}, {`{"operation":"discover","effect":"read-external"}`, `{"operation":"act","effect":"act","experimental":true}`}} {
		b, err := parseBinding([]byte(binding(owners[0], owners[1])))
		if err != nil || b.write.taxonomies["update"].Effect != "act" {
			t.Fatalf("live %s, write %s: %v", owners[0], owners[1], err)
		}
	}
	historical := `{"bindingVersion":"1","platform":"tickets","operations":{"write":{"shape":"mcp","server":{"image":"ghcr.io/example/tickets:1@sha256:` + strings.Repeat("ab", 32) + `"},"tools":["update"],"licence":"MIT"}}}`
	if _, err := parseBinding([]byte(historical)); err != nil {
		t.Fatalf("a historical write binding no longer reads: %v", err)
	}
}

// Every tool and operation this binary can serve carries both fields, and
// the walk names the first that does not: every operation of every binding
// the distribution ships, history, live and write alike, each write-back an
// act; and every tool of the MCP frontend's table, the seal tool among them,
// served with the operation and effect it carries and the annotations that
// effect derives.
func TestEveryServedToolAndOperationCarriesOperationAndEffect(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "catalog", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no shipped binding: %v", err)
	}
	sort.Strings(files)
	live := map[string]binding{}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		where := "catalog/" + filepath.Base(file)
		b, err := parseBinding(data)
		if err != nil {
			t.Fatalf("%s: %v", where, err)
		}
		for _, entry := range []struct {
			name string
			op   *operation
		}{{"history", b.history}, {"live", b.live}, {"write", b.write}} {
			if entry.op == nil {
				continue
			}
			if entry.op.shape != "mcp" {
				if !entry.op.taxonomy.Valid() || entry.op.taxonomy.Operation == "" || entry.op.taxonomy.Effect == "" {
					t.Fatalf("%s operation %s carries no operation and effect", where, entry.name)
				}
				continue
			}
			for _, tool := range entry.op.tools {
				owner, ok := entry.op.taxonomies[tool]
				if !ok || !owner.Valid() || owner.Operation == "" || owner.Effect == "" {
					t.Fatalf("%s operation %s tool %s carries no operation and effect", where, entry.name, tool)
				}
				if entry.name == "write" && (owner.Operation != "act" || owner.Effect != "act") {
					t.Fatalf("%s operation write tool %s is a write-back declared %s/%s, not act", where, tool, owner.Operation, owner.Effect)
				}
			}
		}
		if b.live != nil {
			live[strings.TrimSuffix(filepath.Base(file), ".json")] = b
		}
	}
	s, err := servedOwnerServer(t, live, nil)
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]servedEntry{}
	for _, e := range servedEntries(t, s) {
		listed[e.Name] = e
	}
	if len(s.order) != len(listed) || len(s.order) < 2 {
		t.Fatalf("the table holds %d tools and the listing %d", len(s.order), len(listed))
	}
	for _, name := range s.order {
		owner := s.tools[name].taxonomy
		if !owner.Valid() || owner.Operation == "" || owner.Effect == "" {
			t.Fatalf("served tool %s carries no operation and effect", name)
		}
		e, ok := listed[name]
		if !ok || e.Meta["operation"] != owner.Operation || e.Meta["effect"] != owner.Effect {
			t.Fatalf("served tool %s is listed without its operation and effect: %+v", name, e)
		}
		if !reflect.DeepEqual(e.Annotations, owner.Annotations()) {
			t.Fatalf("served tool %s is listed with annotations %v, not the %v its effect %s derives", name, e.Annotations, owner.Annotations(), owner.Effect)
		}
	}
}
