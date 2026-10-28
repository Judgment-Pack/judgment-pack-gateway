package connections

import (
	"adapters/mcp"
	"fmt"
	"slices"
)

// V5 adds owner classifications. Earlier catalog encodings remain frozen.
// No taxonomy is a credential, model-call approval or verified signed receipt.
type SourceContractV5 struct {
	SourceContractV4
	Taxonomy             mcp.ToolTaxonomy            `json:"taxonomy"`
	CapabilityTaxonomies map[string]mcp.ToolTaxonomy `json:"capabilityTaxonomies"`
	DispatchTaxonomies   map[string]mcp.ToolTaxonomy `json:"dispatchTaxonomies"`
	Profile              mcp.CapabilityProfile       `json:"profile"`
}
type OperationDeclarationV5 struct {
	Taxonomy   mcp.ToolTaxonomy            `json:"taxonomy"`
	Profile    mcp.CapabilityProfile       `json:"profile"`
	Components map[string]mcp.ToolTaxonomy `json:"components"`
}
type ProviderDescriptorV5 struct {
	ProviderDescriptorV4
	Source                SourceContractV5                  `json:"source"`
	Taxonomy              mcp.ToolTaxonomy                  `json:"taxonomy"`
	OperationTaxonomies   map[string]mcp.ToolTaxonomy       `json:"operationTaxonomies"`
	OperationDeclarations map[string]OperationDeclarationV5 `json:"operationDeclarations"`
	Profile               mcp.CapabilityProfile             `json:"profile"`
}
type SourceDescriptorV5 struct {
	SourceDescriptorV4
	Taxonomy             mcp.ToolTaxonomy            `json:"taxonomy"`
	CapabilityTaxonomies map[string]mcp.ToolTaxonomy `json:"capabilityTaxonomies"`
	DispatchTaxonomies   map[string]mcp.ToolTaxonomy `json:"dispatchTaxonomies"`
	Profile              mcp.CapabilityProfile       `json:"profile"`
}
type CatalogV5 struct {
	DiscoveryTaxonomy mcp.ToolTaxonomy       `json:"discoveryTaxonomy"`
	Version           int                    `json:"version"`
	Providers         []ProviderDescriptorV5 `json:"providers"`
	Sources           []SourceDescriptorV5   `json:"sources"`
}

func externalOwner(operation string) mcp.ToolTaxonomy {
	return mcp.ToolTaxonomy{Operation: operation, Effect: "read-external"}
}

// capabilityOwners is each research capability's owner declaration: a
// search is a discover, a page a read and an answer an answer, each
// read-external, since each is acquired and answered with a signed receipt.
// It is the one table: CheckCapabilities refuses a capability it does not
// declare, so neither a catalog nor a connection's research declaration
// names one, and the dispatch selectors that serve a capability under its
// name take their declaration from it.
var capabilityOwners = map[string]mcp.ToolTaxonomy{
	CapabilityAnswer: externalOwner("answer"), CapabilitySearch: externalOwner("discover"), CapabilityPage: externalOwner("read"),
}

// capabilityOwner is a capability's declaration, when it has a valid one.
func capabilityOwner(name string) (mcp.ToolTaxonomy, bool) {
	t, ok := capabilityOwners[name]
	return t, ok && t.Valid()
}

// These are owner declarations for the actual closed dispatch selectors, never
// classifications guessed from names or from arbitrary customer MCP descriptors.
// Generic MCP dispatch can act; its container declaration grants no per-tool import.
var sourceOwners = map[string]map[string]mcp.ToolTaxonomy{
	"web":           {CapabilityPage: capabilityOwners[CapabilityPage]},
	"web-discovery": {"discover": externalOwner("discover")},
	"web-search":    {CapabilityAnswer: capabilityOwners[CapabilityAnswer], CapabilitySearch: capabilityOwners[CapabilitySearch]},
	"drive":         {"read": externalOwner("read")}, "gmail": {"read": externalOwner("read")}, "notion": {"read": externalOwner("read")}, "obsidian": {"read": externalOwner("read")}, "aws-s3": {"read": externalOwner("read")},
	"databricks": {"statement": {Operation: "act", Effect: "act"}, "catalog": externalOwner("discover"), "mcp": {Operation: "run", Effect: "act"}},
	"azure-devops": {
		"workitems.query": externalOwner("discover"), "workitems.query-and-get": externalOwner("discover"), "workitems.get": externalOwner("read"),
		"repos.list": externalOwner("discover"), "repos.items": externalOwner("read"), "repos.commits": externalOwner("discover"),
		"pullrequests.list": externalOwner("discover"), "pipelines.list": externalOwner("discover"), "pipelines.runs": externalOwner("discover"), "pipelines.run": externalOwner("read"),
		"mcp": {Operation: "run", Effect: "act"},
	},
}

// Method names here are explicit distribution-owned protocol declarations.
// Broker admission and V5 discovery both require the same complete registry.
var controlMethodOwners = map[string]mcp.ToolTaxonomy{
	"status": {Operation: "read", Effect: "read"}, "configure": {Operation: "act", Effect: "act"},
	"connect": {Operation: "run", Effect: "act"}, "poll": {Operation: "run", Effect: "act"}, "cancel": {Operation: "run", Effect: "act"},
	"disconnect": {Operation: "act", Effect: "act"}, "search": externalOwner("discover"), "select": {Operation: "act", Effect: "act"},
	"test":       {Operation: "check", Effect: "read-external", CheckKind: "test"},
	"files-list": externalOwner("discover"), "files-read": externalOwner("read"), "files-prepare": {Operation: "propose", Effect: "propose"},
	"files-prepare-google-document": {Operation: "propose", Effect: "propose"}, "files-commit": {Operation: "act", Effect: "act"}, "files-status": {Operation: "read", Effect: "read"},
	"source-bind": {Operation: "act", Effect: "act"}, "source-bindings": {Operation: "read", Effect: "read"}, "source-revoke": {Operation: "act", Effect: "act"}, "source-observe": externalOwner("read"),
}
var operatorPolicyOwner = mcp.ToolTaxonomy{Operation: "act", Effect: "act"}

func CheckOperationDeclarationV5(d OperationDeclarationV5) error {
	if len(d.Components) != 2 || d.Components["operator-policy"] != operatorPolicyOwner || !d.Components["operation"].Valid() {
		return fmt.Errorf("missing or invalid actual-entry components")
	}
	summary, profile, err := mcp.SummarizeTaxonomies(d.Components)
	if err != nil || summary != d.Taxonomy || profile.Effect != d.Profile.Effect || !slices.Equal(profile.Operations, d.Profile.Operations) {
		return fmt.Errorf("actual-entry summary or profile contradicts components")
	}
	return nil
}
func controlDeclaration(provider, method string) (OperationDeclarationV5, bool) {
	intrinsic, ok := controlMethodOwners[method]
	if !ok || !intrinsic.Valid() {
		return OperationDeclarationV5{}, false
	}
	components := map[string]mcp.ToolTaxonomy{"operator-policy": operatorPolicyOwner, "operation": intrinsic}
	summary, profile, err := mcp.SummarizeTaxonomies(components)
	if err != nil {
		return OperationDeclarationV5{}, false
	}
	declaration := OperationDeclarationV5{Taxonomy: summary, Profile: profile, Components: components}
	return declaration, CheckOperationDeclarationV5(declaration) == nil
}
func controlOwner(provider, method string) (mcp.ToolTaxonomy, bool) {
	d, ok := controlDeclaration(provider, method)
	return d.Taxonomy, ok
}

// Closed selectors mirror the executable dispatcher cases; a missing declaration
// cannot shrink discovery into a weaker profile or admit an undeclared new case.

func sourceDispatchSelectors(provider string) []string {
	switch provider {
	case "web":
		return []string{"page"}
	case "web-discovery":
		return []string{"discover"}
	case "web-search":
		return []string{"answer", "search"}
	case "drive", "gmail", "notion", "obsidian", "aws-s3":
		return []string{"read"}
	case "databricks":
		return []string{"statement", "catalog", "mcp"}
	case "azure-devops":
		return []string{"workitems.query", "workitems.query-and-get", "workitems.get", "repos.list", "repos.items", "repos.commits", "pullrequests.list", "pipelines.list", "pipelines.runs", "pipelines.run", "mcp"}
	}
	return nil
}
func sourceOwner(provider, selector string) (mcp.ToolTaxonomy, bool) {
	t, ok := sourceOwners[provider][selector]
	return t, ok && t.Valid() && slices.Contains(sourceDispatchSelectors(provider), selector)
}

func copyOwners(tools map[string]mcp.ToolTaxonomy) map[string]mcp.ToolTaxonomy {
	out := map[string]mcp.ToolTaxonomy{}
	for name, t := range tools {
		if !t.Valid() {
			panic("invalid owner taxonomy")
		}
		out[name] = t
	}
	return out
}
func summarizeOwners(tools map[string]mcp.ToolTaxonomy) (mcp.ToolTaxonomy, mcp.CapabilityProfile) {
	t, p, err := mcp.SummarizeTaxonomies(tools)
	if err != nil {
		panic(err)
	}
	return t, p
}
func sourceV5(source SourceContractV4) SourceContractV5 {
	dispatch, known := sourceOwners[source.ID]
	if !known || len(dispatch) == 0 {
		panic(fmt.Sprintf("source %s has no owner dispatch declaration", source.ID))
	}
	selectors := sourceDispatchSelectors(source.ID)
	if len(selectors) != len(dispatch) {
		panic("incomplete source dispatch owner declarations")
	}
	for _, selector := range selectors {
		if _, ok := sourceOwner(source.ID, selector); !ok {
			panic("missing source dispatch owner declaration")
		}
	}
	out := SourceContractV5{SourceContractV4: source, CapabilityTaxonomies: map[string]mcp.ToolTaxonomy{}, DispatchTaxonomies: copyOwners(dispatch)}
	out.Capabilities = append([]string{}, source.Capabilities...)
	for _, name := range source.Capabilities {
		t, ok := capabilityOwners[name]
		if !ok || !t.Valid() {
			panic("missing capability taxonomy")
		}
		out.CapabilityTaxonomies[name] = t
	}
	out.Taxonomy, out.Profile = summarizeOwners(out.DispatchTaxonomies)
	return out
}
func ConnectionCatalogV5() CatalogV5 {
	base := ConnectionCatalogV4()
	out := CatalogV5{DiscoveryTaxonomy: mcp.ToolTaxonomy{Operation: "discover", Effect: "pure"}, Version: 5, Providers: []ProviderDescriptorV5{}, Sources: []SourceDescriptorV5{}}
	for _, provider := range base.Providers {
		p := ProviderDescriptorV5{ProviderDescriptorV4: provider, Source: sourceV5(provider.Source), OperationTaxonomies: map[string]mcp.ToolTaxonomy{}, OperationDeclarations: map[string]OperationDeclarationV5{}}
		constituents := map[string]mcp.ToolTaxonomy{}
		for _, method := range provider.Operations {
			d, ok := controlDeclaration(provider.ID, method)
			if !ok {
				panic(fmt.Sprintf("provider %s method %s has no complete owner declaration", provider.ID, method))
			}
			p.OperationTaxonomies[method] = d.Taxonomy
			p.OperationDeclarations[method] = d
			for role, t := range d.Components {
				constituents[method+"/"+role] = t
			}
		}
		p.Taxonomy, p.Profile = summarizeOwners(constituents)
		out.Providers = append(out.Providers, p)
	}

	for _, source := range base.Sources {
		d := sourceV5(SourceContractV4{ID: source.ID, Adapter: source.Adapter, Capabilities: source.Capabilities})
		out.Sources = append(out.Sources, SourceDescriptorV5{SourceDescriptorV4: source, Taxonomy: d.Taxonomy, CapabilityTaxonomies: d.CapabilityTaxonomies, DispatchTaxonomies: d.DispatchTaxonomies, Profile: d.Profile})
	}
	return out
}
