package connections

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// The closed set is RFC 0018's, in its order: a name outside it is refused by
// name, and so is a name given twice or out of order. Every ordered subset is
// a declaration, the empty one included.
func TestCapabilitiesAreTheClosedSetInItsOrder(t *testing.T) {
	for _, names := range [][]string{{}, {"answer"}, {"search"}, {"page"}, {"answer", "search"}, {"answer", "page"}, {"search", "page"}, {"answer", "search", "page"}} {
		if err := CheckCapabilities(names); err != nil {
			t.Errorf("%v refused: %v", names, err)
		}
	}
	for _, c := range []struct {
		names []string
		says  string
	}{
		{[]string{"answers"}, `capability "answers" is not one of answer, search and page`},
		{[]string{"search", "crawl"}, `capability "crawl" is not one of answer, search and page`},
		{[]string{"Answer"}, `capability "Answer" is not one of answer, search and page`},
		{[]string{""}, `capability "" is not one of answer, search and page`},
		{[]string{"search", "search"}, `capability "search" is declared twice`},
		{[]string{"answer", "page", "page"}, `capability "page" is declared twice`},
		{[]string{"search", "answer"}, `capability "answer" is out of order: the order is answer, search, page`},
		{[]string{"page", "search"}, `capability "search" is out of order: the order is answer, search, page`},
	} {
		if err := CheckCapabilities(c.names); err == nil || err.Error() != c.says {
			t.Errorf("%q: %v, want %q", c.names, err, c.says)
		}
	}
}

// A research declaration is §5.1's: one to three capabilities, and a model
// exactly when answer is among them, of at most 256 UTF-8 bytes.
func TestAResearchDeclarationHasSection51sForm(t *testing.T) {
	for _, r := range []Research{
		{Capabilities: []string{"answer"}, Model: "gemini-2.5-flash"},
		{Capabilities: []string{"answer", "search", "page"}, Model: strings.Repeat("m", 256)},
		{Capabilities: []string{"search"}},
		{Capabilities: []string{"search", "page"}},
		{Capabilities: []string{"page"}},
	} {
		if err := CheckResearch(r); err != nil {
			t.Errorf("%+v refused: %v", r, err)
		}
	}
	for _, c := range []struct {
		r    Research
		says string
	}{
		{Research{}, "a research declaration names no capability"},
		{Research{Capabilities: []string{}, Model: "gemini-2.5-flash"}, "a research declaration names no capability"},
		{Research{Capabilities: []string{"answer", "pages"}, Model: "gemini-2.5-flash"}, `capability "pages" is not one of answer, search and page`},
		{Research{Capabilities: []string{"answer"}}, "a research declaration with answer names no model"},
		{Research{Capabilities: []string{"answer", "search"}}, "a research declaration with answer names no model"},
		{Research{Capabilities: []string{"search"}, Model: "gemini-2.5-flash"}, "a research declaration without answer names a model"},
		{Research{Capabilities: []string{"answer"}, Model: strings.Repeat("m", 257)}, "a research declaration's model is longer than 256 bytes"},
		{Research{Capabilities: []string{"answer"}, Model: strings.Repeat("é", 129)}, "a research declaration's model is longer than 256 bytes"},
		{Research{Capabilities: []string{"answer"}, Model: "gemini-\xff"}, "a research declaration's model is not UTF-8"},
	} {
		if err := CheckResearch(c.r); err == nil || err.Error() != c.says {
			t.Errorf("%+v: %v, want %q", c.r, err, c.says)
		}
	}
}

// What each adapter of the catalog declares. Every provider and every
// explicit source is named here, so that an adapter added to the catalog
// without a decision about its capabilities fails this test.
var wantCapabilities = struct{ providers, sources map[string][]string }{
	providers: map[string][]string{
		"google-drive": {}, "gmail": {}, "notion": {}, "obsidian": {}, "aws-s3": {},
		"web-search": {"answer", "search"}, "databricks": {}, "azure-devops": {},
	},
	sources: map[string][]string{
		"web": {"page"}, "web-discovery": {}, "web-search": {"answer", "search"},
	},
}

// The program each source's read is written against, as its receipts name it
// in adapter.name. The names are held here, not derived from the code under
// test.
var wantPrograms = map[string]string{
	"drive": "adapter-drive", "gmail": "adapter-gmail", "notion": "adapter-sources",
	"obsidian": "adapter-sources", "aws-s3": "adapter-sources", "web-search": "adapter-sources",
	"databricks": "adapter-sources", "azure-devops": "adapter-sources",
	"web": "adapter-web", "web-discovery": "adapter-web",
}

func TestEachCatalogSourceNamesItsAdapterProgram(t *testing.T) {
	catalog := ConnectionCatalogV4()
	v3 := ConnectionCatalogV3()
	if len(catalog.Providers) != 8 || len(catalog.Sources) != 3 {
		t.Fatalf("%d providers, %d sources", len(catalog.Providers), len(catalog.Sources))
	}
	for i, p := range catalog.Providers {
		if want := wantPrograms[p.Source.ID]; want == "" || p.Source.Adapter != want {
			t.Errorf("provider %s (source %s) names adapter %q, want %q", p.ID, p.Source.ID, p.Source.Adapter, want)
		}
		if p.Source.Record != v3.Providers[i].Source.Record {
			t.Errorf("provider %s: record %q changed from %q", p.ID, p.Source.Record, v3.Providers[i].Source.Record)
		}
	}
	for _, s := range catalog.Sources {
		if want := wantPrograms[s.ID]; want == "" || s.Adapter != want {
			t.Errorf("source %s names adapter %q, want %q", s.ID, s.Adapter, want)
		}
	}
	// The record stays the result contract; the program is its own member.
	for _, p := range catalog.Providers {
		if p.Source.ID == "web-search" && (p.Source.Record != "web-search-v1" || p.Source.Adapter != "adapter-sources") {
			t.Errorf("web-search: record %q, adapter %q", p.Source.Record, p.Source.Adapter)
		}
	}
}

// A source with no program, or a program the gateway mints no receipts for,
// is refused when the catalog is made, naming the source, and no catalog is made.
func TestTheCatalogRefusesAnEmptyOrUnknownProgram(t *testing.T) {
	held := adapterPrograms["web"]
	t.Cleanup(func() { adapterPrograms["web"] = held })
	for _, c := range []struct{ name, says string }{
		{"", `the catalog's adapter for web: no program is named`},
		{"adapter-http", `the catalog's adapter for web: "adapter-http" is not a program the gateway mints receipts for`},
		{"web", `the catalog's adapter for web: "web" is not a program the gateway mints receipts for`},
	} {
		adapterPrograms["web"] = c.name
		func() {
			defer func() {
				if said := recover(); said != c.says {
					t.Errorf("%q: %v, want %q", c.name, said, c.says)
				}
			}()
			ConnectionCatalogV4()
			t.Errorf("%q: a catalog was made", c.name)
		}()
	}
	delete(adapterPrograms, "web")
	defer func() {
		if said := recover(); said != `the catalog's adapter for web: no program is named` {
			t.Errorf("a source with no entry: %v", said)
		}
	}()
	ConnectionCatalogV4()
	t.Error("a catalog was made")
}

func TestEachCatalogAdapterDeclaresItsCapabilities(t *testing.T) {
	catalog := ConnectionCatalogV4()
	if catalog.Version != 4 || len(catalog.Providers) != len(wantCapabilities.providers) || len(catalog.Sources) != len(wantCapabilities.sources) {
		t.Fatalf("version %d, %d providers, %d sources", catalog.Version, len(catalog.Providers), len(catalog.Sources))
	}
	for _, p := range catalog.Providers {
		want, ok := wantCapabilities.providers[p.ID]
		if !ok || p.Source.Capabilities == nil || !reflect.DeepEqual(p.Source.Capabilities, want) || CheckCapabilities(p.Source.Capabilities) != nil {
			t.Errorf("provider %s (source %s) declares %#v, want %#v", p.ID, p.Source.ID, p.Source.Capabilities, want)
		}
	}
	for _, s := range catalog.Sources {
		want, ok := wantCapabilities.sources[s.ID]
		if !ok || s.Capabilities == nil || !reflect.DeepEqual(s.Capabilities, want) || CheckCapabilities(s.Capabilities) != nil {
			t.Errorf("source %s declares %#v, want %#v", s.ID, s.Capabilities, want)
		}
	}
	// An adapter described twice, as a provider's source and as an explicit
	// source, declares the same in both.
	for _, p := range catalog.Providers {
		for _, s := range catalog.Sources {
			if p.Source.ID == s.ID && !reflect.DeepEqual(p.Source.Capabilities, s.Capabilities) {
				t.Errorf("%s declares %v as a provider's source and %v as a source", s.ID, p.Source.Capabilities, s.Capabilities)
			}
		}
	}
	// The member is written even when empty: one spelling.
	raw, err := json.Marshal(catalog)
	if err != nil || strings.Contains(string(raw), `"capabilities":null`) || len(raw) > 128<<10 {
		t.Fatalf("%s %v", raw, err)
	}
}

// Version 4 is version 3 with two members more, and nothing else changed;
// versions 3 and 2 carry no capabilities, so the hosts that hold their
// members closed read them as before.
func TestVersionFourIsVersionThreeWithCapabilities(t *testing.T) {
	generic := func(v any) map[string]any {
		t.Helper()
		raw, err := json.Marshal(v)
		var out map[string]any
		if err != nil || json.Unmarshal(raw, &out) != nil {
			t.Fatal(err)
		}
		return out
	}
	v4, v3 := generic(ConnectionCatalogV4()), generic(ConnectionCatalogV3())
	for _, p := range v4["providers"].([]any) {
		source := p.(map[string]any)["source"].(map[string]any)
		if _, ok := source["capabilities"]; !ok {
			t.Fatalf("a provider's source has no capabilities: %v", source)
		}
		if name, _ := source["adapter"].(string); name == "" {
			t.Fatalf("a provider's source has no adapter: %v", source)
		}
		delete(source, "capabilities")
		delete(source, "adapter")
	}
	for _, s := range v4["sources"].([]any) {
		if _, ok := s.(map[string]any)["capabilities"]; !ok {
			t.Fatalf("a source has no capabilities: %v", s)
		}
		if name, _ := s.(map[string]any)["adapter"].(string); name == "" {
			t.Fatalf("a source has no adapter: %v", s)
		}
		delete(s.(map[string]any), "capabilities")
		delete(s.(map[string]any), "adapter")
	}
	v4["version"] = 3.0
	if !reflect.DeepEqual(v4, v3) {
		t.Fatal("version 4 changes more than the capabilities")
	}
	for _, p := range v3["providers"].([]any) {
		if source := p.(map[string]any)["source"].(map[string]any); len(source) != 3 || source["id"] == nil || source["shape"] == nil || source["record"] == nil {
			t.Fatalf("version 3's source contract is not exactly id, shape and record: %v", source)
		}
	}
	for _, catalog := range []map[string]any{v3, generic(ConnectionCatalog())} {
		for _, s := range catalog["sources"].([]any) {
			if len(s.(map[string]any)) != 4 {
				t.Fatalf("version %v's source is not exactly id, input, mediaTypes and maxBytes: %v", catalog["version"], s)
			}
		}
	}
}

// A declaration outside the closed set is refused when the catalog is made,
// naming the adapter and the capability, and no catalog is made.
func TestTheCatalogRefusesADeclarationOutsideTheSet(t *testing.T) {
	held := adapterCapabilities["web"]
	t.Cleanup(func() { adapterCapabilities["web"] = held })
	for _, c := range []struct {
		names []string
		says  string
	}{
		{[]string{"pages"}, `the catalog's declaration for web: capability "pages" is not one of answer, search and page`},
		{[]string{"page", "page"}, `the catalog's declaration for web: capability "page" is declared twice`},
		{[]string{"page", "search"}, `the catalog's declaration for web: capability "search" is out of order: the order is answer, search, page`},
	} {
		adapterCapabilities["web"] = c.names
		func() {
			defer func() {
				if said := recover(); said != c.says {
					t.Errorf("%v: %v, want %q", c.names, said, c.says)
				}
			}()
			ConnectionCatalogV4()
			t.Errorf("%v: a catalog was made", c.names)
		}()
	}
}

func TestCatalogV4HasNoSharedState(t *testing.T) {
	first := ConnectionCatalogV4()
	for i := range first.Sources {
		if first.Sources[i].ID == "web" {
			first.Sources[i].Capabilities[0] = "answer"
		}
	}
	for i := range first.Providers {
		if first.Providers[i].Source.ID == "web-search" {
			first.Providers[i].Source.Capabilities[0] = "page"
		}
	}
	again := ConnectionCatalogV4()
	for _, s := range again.Sources {
		if s.ID == "web" && !reflect.DeepEqual(s.Capabilities, []string{"page"}) {
			t.Fatal("a source's declaration was changed through an earlier catalog")
		}
	}
	for _, p := range again.Providers {
		if p.Source.ID == "web-search" && !reflect.DeepEqual(p.Source.Capabilities, []string{"answer", "search"}) {
			t.Fatal("a provider's declaration was changed through an earlier catalog")
		}
	}
}
