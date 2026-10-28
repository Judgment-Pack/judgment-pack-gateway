package connections

import (
	"adapters/mcp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// carriesBoth is a declaration with an operation and an effect that go
// together under the taxonomy.
func carriesBoth(t mcp.ToolTaxonomy) bool {
	return t.Operation != "" && t.Effect != "" && t.Valid()
}

// Every capability and operation these programs can serve carries both
// fields, and the walk names the first that does not. It walks what the
// programs execute, not the catalog that describes them, so a case added
// to a dispatcher without a declaration is found here by name rather than
// as a catalog that will not build: each research capability of the closed
// set and each capability an adapter declares; each method the broker
// answers, for every provider it can be opened as; and each dispatch
// selector of every source a catalog names.
func TestEveryServedCapabilityAndOperationCarriesOperationAndEffect(t *testing.T) {
	for _, name := range researchCapabilities {
		owner, ok := capabilityOwner(name)
		if !ok || !carriesBoth(owner) {
			t.Fatalf("capability %s carries no operation and effect", name)
		}
		if owner.Effect != "read-external" {
			t.Fatalf("capability %s is declared %s, not read-external: it is acquired with a signed receipt", name, owner.Effect)
		}
	}
	adapters := make([]string, 0, len(adapterCapabilities))
	for id := range adapterCapabilities {
		adapters = append(adapters, id)
	}
	sort.Strings(adapters)
	for _, id := range adapters {
		for _, name := range adapterCapabilities[id] {
			owner, ok := capabilityOwner(name)
			if !ok || !carriesBoth(owner) {
				t.Fatalf("adapter %s capability %s carries no operation and effect", id, name)
			}
			// A selector that serves a capability under its name is
			// declared as that capability is: one table, not two.
			if selector, served := sourceOwners[id][name]; served && selector != owner {
				t.Fatalf("adapter %s serves capability %s declared %s/%s, and the capability is %s/%s", id, name, selector.Operation, selector.Effect, owner.Operation, owner.Effect)
			}
		}
	}

	// The broker's methods: every provider in the catalog, and the one kind
	// it is opened as that the catalog leaves out, document processing (a
	// local program, configured and never listed for a browser).
	catalog := ConnectionCatalogV3()
	providers := []string{processingDescriptor().ID}
	for _, p := range catalog.Providers {
		providers = append(providers, p.ID)
	}
	universe := append(append(append([]string{}, storageMethods...), StorageConvertMethod), sourceMethods...)
	for _, id := range providers {
		d, ok := LookupProvider(id)
		if !ok {
			t.Fatalf("provider %s is not one the broker opens", id)
		}
		methods := append([]string{}, d.Operations...)
		for _, m := range universe {
			if (storageMethodOf(id, m) || sourceMethodOf(id, m)) && !slices.Contains(methods, m) {
				methods = append(methods, m)
			}
		}
		if len(methods) == 0 {
			t.Fatalf("provider %s answers no method", id)
		}
		for _, method := range methods {
			declaration, ok := controlDeclaration(id, method)
			if !ok || !carriesBoth(declaration.Taxonomy) || !carriesBoth(declaration.Components["operation"]) {
				t.Fatalf("provider %s method %s carries no operation and effect", id, method)
			}
		}
	}

	// The sources' dispatch selectors: each provider's source and each
	// source the catalog lists on its own.
	sources := []string{}
	for _, p := range catalog.Providers {
		sources = append(sources, p.Source.ID)
	}
	for _, s := range catalog.Sources {
		sources = append(sources, s.ID)
	}
	for _, id := range sources {
		selectors := sourceDispatchSelectors(id)
		if len(selectors) == 0 {
			t.Fatalf("source %s names no dispatch selector, so none carries an operation and effect", id)
		}
		for _, selector := range selectors {
			owner, ok := sourceOwner(id, selector)
			if !ok || !carriesBoth(owner) {
				t.Fatalf("source %s selector %s carries no operation and effect", id, selector)
			}
		}
	}
}

// A capability without both fields is not declared: neither the catalog's
// declaration for an adapter nor a connection's research declaration can
// name it, so no research source binds it.
func TestACapabilityWithoutOperationAndEffectIsNotDeclared(t *testing.T) {
	tavily := SearchConnection{ID: "links", Name: "Links", Provider: "tavily", DailyLimit: 10, Credential: "key"}
	if r := searchResearch(tavily); r == nil || !slices.Equal(r.Capabilities, []string{CapabilitySearch}) {
		t.Fatalf("a search-results connection declares %v", r)
	}
	for _, name := range researchCapabilities {
		held := capabilityOwners[name]
		for _, broken := range []*mcp.ToolTaxonomy{nil, {}, {Operation: "read"}, {Effect: "read-external"}, {Operation: "read", Effect: "pure"}} {
			if broken == nil {
				delete(capabilityOwners, name)
			} else {
				capabilityOwners[name] = *broken
			}
			err := CheckCapabilities([]string{name})
			if err == nil || !strings.Contains(err.Error(), "no operation and effect") {
				capabilityOwners[name] = held
				t.Fatalf("capability %s declared %v was admitted: %v", name, broken, err)
			}
			if name == CapabilitySearch && searchResearch(tavily) != nil {
				capabilityOwners[name] = held
				t.Fatalf("a connection declared search while search was declared %v", broken)
			}
		}
		capabilityOwners[name] = held
	}
	if err := CheckCapabilities(researchCapabilities); err != nil {
		t.Fatal(err)
	}
}
