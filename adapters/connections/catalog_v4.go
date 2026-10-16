package connections

import (
	"fmt"
	"unicode/utf8"
)

// The research capabilities are RFC 0018's closed set, in its order
// (spec/dialect.md §4.3 and §5.1): a research source requests them, an
// installation's input profile declares them, and a Runner binding the source
// compares the two. The gateway declares what each of its adapters can serve;
// it never checks a binding.
const (
	CapabilityAnswer = "answer"
	CapabilitySearch = "search"
	CapabilityPage   = "page"
)

// researchModelBytes is the longest model name RFC 0018 admits, in UTF-8
// bytes (spec/dialect.md §4.3).
const researchModelBytes = 256

func capabilityRank(name string) int {
	switch name {
	case CapabilityAnswer:
		return 0
	case CapabilitySearch:
		return 1
	case CapabilityPage:
		return 2
	}
	return -1
}

// CheckCapabilities holds a declaration to the closed set: each name one of
// answer, search and page, none twice, in that order. An empty declaration
// is an adapter that serves none of them.
func CheckCapabilities(names []string) error {
	last := -1
	for _, name := range names {
		rank := capabilityRank(name)
		if rank < 0 {
			return fmt.Errorf("capability %q is not one of answer, search and page", name)
		}
		if rank == last {
			return fmt.Errorf("capability %q is declared twice", name)
		}
		if rank < last {
			return fmt.Errorf("capability %q is out of order: the order is answer, search, page", name)
		}
		last = rank
	}
	return nil
}

// Research is RFC 0018's research declaration, the form an input profile's
// `research` member has (spec/dialect.md §5.1): one to three capabilities and,
// exactly when they include answer, the model.
type Research struct {
	Capabilities []string `json:"capabilities"`
	Model        string   `json:"model,omitempty"`
}

// CheckResearch holds a declaration to §5.1's form.
func CheckResearch(r Research) error {
	if len(r.Capabilities) == 0 {
		return fmt.Errorf("a research declaration names no capability")
	}
	if err := CheckCapabilities(r.Capabilities); err != nil {
		return err
	}
	answer := r.Capabilities[0] == CapabilityAnswer
	switch {
	case answer && r.Model == "":
		return fmt.Errorf("a research declaration with answer names no model")
	case !answer && r.Model != "":
		return fmt.Errorf("a research declaration without answer names a model")
	case len(r.Model) > researchModelBytes:
		return fmt.Errorf("a research declaration's model is longer than %d bytes", researchModelBytes)
	case !utf8.ValidString(r.Model):
		return fmt.Errorf("a research declaration's model is not UTF-8")
	}
	return nil
}

// adapterCapabilities is each adapter's declaration, by the acquisition id
// the catalog describes it under: the research contracts the gateway declares
// for it. An adapter not named here declares none. That is not to say it
// serves none upstream: a research source cannot bind an adapter that
// declares no capability it needs, whatever the adapter does.
//
// web reads one public page. web-search answers a query with links, and,
// through a connection whose provider is of kind grounded-answer, with the
// answer the connection's model generated: the adapter can serve both, and
// which one a connection serves is that connection's (searchResearch).
//
// A page or file a person selected through a connection (Notion's pages,
// Drive's files, Gmail's messages, Obsidian's notes, S3's objects) is a
// selected read, the dialect's selected-file kind, not the public page read
// that page names: those adapters declare no page. The MCP tools a Databricks
// or Azure DevOps connection enables (a Genie space, a Unity Gateway service
// such as a web search, the organization's remote server) may return a
// model's answer or a search. They are unclassified: the gateway grants them
// no capability, and no research source binds them until a declaration for
// them exists.
var adapterCapabilities = map[string][]string{
	"web":        {CapabilityPage},
	"web-search": {CapabilityAnswer, CapabilitySearch},
}

// declaredCapabilities is a fresh copy of the adapter's declaration, never
// nil, so that the member is written even when empty: [] is no research
// contract declared, not an adapter that serves nothing. A declaration outside
// the closed set is the distribution's own error, and no catalog is made.
func declaredCapabilities(id string) []string {
	names := append([]string{}, adapterCapabilities[id]...)
	if err := CheckCapabilities(names); err != nil {
		panic(fmt.Sprintf("the catalog's declaration for %s: %v", id, err))
	}
	return names
}

// adapterPrograms is the program each source's read is written against, by
// the acquisition id the catalog describes it under, as the program's
// receipts carry it in `adapter.name`: the name each adapter's code sets
// where it mints the receipt. `record` stays the result contract
// (web-search-v1); `adapter` is what a published dialect's `record` names for
// an unbound source (judgment-pack-spec#184), so a desk copies `adapter`,
// never `record`, into that source. adapter-http is not here: no catalog
// source is served by it.
var adapterPrograms = map[string]string{
	"drive":         "adapter-drive",
	"gmail":         "adapter-gmail",
	"notion":        "adapter-sources",
	"obsidian":      "adapter-sources",
	"aws-s3":        "adapter-sources",
	"web-search":    "adapter-sources",
	"databricks":    "adapter-sources",
	"azure-devops":  "adapter-sources",
	"web":           "adapter-web",
	"web-discovery": "adapter-web",
}

// knownPrograms are the programs whose receipts the gateway mints for a
// catalog source.
var knownPrograms = map[string]bool{"adapter-drive": true, "adapter-gmail": true, "adapter-sources": true, "adapter-web": true}

// declaredProgram is the program the source is read by. A source with no
// program, or one the gateway does not mint receipts for, is the
// distribution's own error, and no catalog is made.
func declaredProgram(id string) string {
	name := adapterPrograms[id]
	switch {
	case name == "":
		panic(fmt.Sprintf("the catalog's adapter for %s: no program is named", id))
	case !knownPrograms[name]:
		panic(fmt.Sprintf("the catalog's adapter for %s: %q is not a program the gateway mints receipts for", id, name))
	}
	return name
}

// CatalogV4 is version 3 with each adapter's program and research
// capabilities: the provider's source contract and each explicit source carry
// `adapter` and `capabilities`.
// Version 3 and version 2 remain available, unchanged, for the hosts that
// hold their members closed.
type CatalogV4 struct {
	Version   int                    `json:"version"`
	Providers []ProviderDescriptorV4 `json:"providers"`
	Sources   []SourceDescriptorV4   `json:"sources"`
}
type SourceContractV4 struct {
	ID           string   `json:"id"`
	Shape        string   `json:"shape"`
	Record       string   `json:"record"`
	Adapter      string   `json:"adapter"`
	Capabilities []string `json:"capabilities"`
}

// ProviderDescriptorV4 is a version 3 provider whose source contract is
// version 4's: the outer Source is the one encoded.
type ProviderDescriptorV4 struct {
	ProviderDescriptor
	Source SourceContractV4 `json:"source"`
}
type SourceDescriptorV4 struct {
	SourceDescriptor
	Adapter      string   `json:"adapter"`
	Capabilities []string `json:"capabilities"`
}

func ConnectionCatalogV4() CatalogV4 {
	base := ConnectionCatalogV3()
	out := CatalogV4{Version: 4, Providers: []ProviderDescriptorV4{}, Sources: []SourceDescriptorV4{}}
	for _, provider := range base.Providers {
		source := provider.Source
		out.Providers = append(out.Providers, ProviderDescriptorV4{provider, SourceContractV4{source.ID, source.Shape, source.Record, declaredProgram(source.ID), declaredCapabilities(source.ID)}})
	}
	for _, source := range base.Sources {
		out.Sources = append(out.Sources, SourceDescriptorV4{source, declaredProgram(source.ID), declaredCapabilities(source.ID)})
	}
	return out
}
