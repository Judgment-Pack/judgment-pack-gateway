package connections

import (
	_ "embed"
	"encoding/json"
)

// CatalogV3 describes data and fixed interaction protocols, never host code.
// Version 2 remains available for older hosts. A future provider uses these
// contracts without acquiring a provider-specific implementation in the host.
type CatalogV3 struct {
	Version   int                  `json:"version"`
	Providers []ProviderDescriptor `json:"providers"`
	Sources   []SourceDescriptor   `json:"sources"`
}
type Localized map[string]string
type Presentation struct {
	Icon         string    `json:"icon"`
	Name         string    `json:"name"`
	Description  Localized `json:"description"`
	Instructions Localized `json:"instructions"`
}
type SetupField struct {
	Key      string    `json:"key"`
	Type     string    `json:"type"`
	Label    Localized `json:"label"`
	Required bool      `json:"required"`
}
type SourceContract struct {
	ID     string `json:"id"`
	Shape  string `json:"shape"`
	Record string `json:"record"`
}
type ProviderDescriptor struct {
	Descriptor
	Protocol               string         `json:"protocol"`
	QueryMode              string         `json:"queryMode"`
	Presentation           Presentation   `json:"presentation"`
	Setup                  []SetupField   `json:"setup"`
	AuthorizationEndpoints []string       `json:"authorizationEndpoints"`
	Source                 SourceContract `json:"source"`
}

//go:embed presentation.json
var presentationJSON []byte

func ConnectionCatalogV3() CatalogV3 {
	var presentation map[string]Presentation
	if err := json.Unmarshal(presentationJSON, &presentation); err != nil {
		panic(err)
	}
	base := ConnectionCatalog()
	out := CatalogV3{Version: 3, Sources: base.Sources, Providers: []ProviderDescriptor{}}
	for _, provider := range base.Providers {
		d := ProviderDescriptor{Descriptor: provider, Protocol: "connection-v1", QueryMode: "text", Presentation: presentation[provider.ID], Setup: []SetupField{}, AuthorizationEndpoints: []string{}}
		switch provider.ID {
		case "google-drive":
			d.Source = SourceContract{"drive", "http", "drive-v1"}
			d.AuthorizationEndpoints = []string{"https://accounts.google.com/o/oauth2/v2/auth"}
		case "gmail":
			d.Source = SourceContract{"gmail", "http", "mail-v1"}
			d.AuthorizationEndpoints = []string{"https://accounts.google.com/o/oauth2/v2/auth"}
		case "notion":
			d.Source = SourceContract{"notion", "mcp", "note-v1"}
			d.AuthorizationEndpoints = []string{"https://mcp.notion.com/authorize"}
		case "obsidian":
			d.Source = SourceContract{"obsidian", "command", "note-v1"}
			d.Registration = "form"
			d.Setup = []SetupField{{Key: "path", Type: "text", Label: presentation["vault-folder"].Description, Required: true}}
		}
		out.Providers = append(out.Providers, d)
	}
	out.Providers = append(out.Providers, s3Catalog(presentation), searchCatalog(presentation))
	out.Sources = append(out.Sources, SourceDescriptor{"web-search", "query", []string{"application/vnd.jpack.web-search+json"}, 1 << 20})
	for i := range out.Providers {
		if storageProvider(out.Providers[i].ID) {
			out.Providers[i].Operations = append(out.Providers[i].Operations, storageMethods...)
		}
		if storageMethodOf(out.Providers[i].ID, StorageConvertMethod) {
			out.Providers[i].Operations = append(out.Providers[i].Operations, StorageConvertMethod)
		}
	}
	return out
}

// LocalPlan is installation metadata from the same verified distribution as the
// executables. It is separate from the browser catalog and never user-configurable.
type LocalPlan struct {
	Version int           `json:"version"`
	Sources []LocalSource `json:"sources"`
}
type LocalSource struct {
	ID          string   `json:"id"`
	Executable  string   `json:"executable"`
	Args        []string `json:"args"`
	Shape       string   `json:"shape"`
	Timeout     int      `json:"timeout"`
	Connections bool     `json:"connections"`
}

// ConnectionLocalPlan is the plan with no document processor configured,
// which every desk takes.
func ConnectionLocalPlan() LocalPlan { return ConnectionLocalPlanWith(false) }

// ConnectionLocalPlanWith is the plan, and with processing the sources that
// may read a PDF with the operator's OCR processor (documents, drive, web and
// aws-s3) are launched with --document-processing, hold the connections
// directory where the settings are kept, and have ProcessingSourceSeconds:
// the processing deadline is at most 120 seconds and those adapters then stop
// at 140. Only an adapter launched so resolves the settings, so a read never
// runs OCR inside an envelope that was not given for it. A desk that admits at
// most 60 seconds a source refuses that plan whole, and is given the plan
// without processing as long as no processor is configured.
func ConnectionLocalPlanWith(processing bool) LocalPlan {
	return ConnectionLocalPlanFor(processing, false)
}

// ConnectionLocalPlanFor is ConnectionLocalPlanWith, and with longSearch the
// web-search source is launched with --long-search and SearchSourceSeconds,
// for a search connection whose timeout the ordinary envelope does not carry.
// A desk that admits at most 60 seconds a source refuses that plan whole, and
// is given the ordinary one as long as no such timeout is configured.
func ConnectionLocalPlanFor(processing, longSearch bool) LocalPlan {
	plan := LocalPlan{1, []LocalSource{
		{"documents", "adapter-document", []string{"--max-bytes", "16777216", "--max-output", "8388608", "--timeout", "30s"}, "command", 40, false},
		// The record's bound is the one docs/design/rendering.md gives for a
		// file of the adapter's default bound, 4 MiB. The adapter keeps its
		// default deadline, five seconds under the timeout here. No rendering
		// program is named, so a request for a PDF is refused by name. A desk
		// refuses a plan that names a program its bundle does not carry, so
		// a desk that takes this plan carries adapter-render.
		{"render", "adapter-render", []string{"--max-output", "6291456"}, "command", 30, false},
		{"drive", "adapter-drive", []string{"--principal", "desk-local"}, "http", 60, true},
		{"gmail", "adapter-gmail", []string{"--principal", "desk-local"}, "http", 60, true},
		{"notion", "adapter-sources", []string{"--provider", "notion", "--principal", "desk-local"}, "mcp", 60, true},
		{"obsidian", "adapter-sources", []string{"--provider", "obsidian", "--principal", "desk-local"}, "command", 60, true},
		{"web", "adapter-web", []string{}, "http", 60, false},
		{"web-discovery", "adapter-web", []string{"--discover"}, "http", 60, false},
		{"web-search", "adapter-sources", []string{"--provider", "web-search", "--principal", "desk-local"}, "http", 60, true},
		{"aws-s3", "adapter-sources", []string{"--provider", "aws-s3", "--principal", "desk-local"}, "command", 60, true},
	}}
	if processing {
		for i := range plan.Sources {
			source := &plan.Sources[i]
			if processingSources[source.ID] {
				source.Args = append(append([]string{}, source.Args...), "--document-processing")
				source.Timeout, source.Connections = ProcessingSourceSeconds, true
			}
		}
	}
	if longSearch {
		for i := range plan.Sources {
			if source := &plan.Sources[i]; source.ID == "web-search" {
				source.Args = append(append([]string{}, source.Args...), "--long-search")
				source.Timeout = SearchSourceSeconds
			}
		}
	}
	return plan
}

// processingSources are the sources that may read a PDF with OCR.
var processingSources = map[string]bool{"documents": true, "drive": true, "web": true, "aws-s3": true}
