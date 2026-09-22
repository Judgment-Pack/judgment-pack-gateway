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

func ConnectionLocalPlan() LocalPlan {
	return LocalPlan{1, []LocalSource{
		{"documents", "adapter-document", []string{"--max-bytes", "16777216", "--max-output", "8388608", "--timeout", "30s"}, "command", 40, false},
		{"drive", "adapter-drive", []string{"--principal", "desk-local"}, "http", 60, true},
		{"gmail", "adapter-gmail", []string{"--principal", "desk-local"}, "http", 60, true},
		{"notion", "adapter-sources", []string{"--provider", "notion", "--principal", "desk-local"}, "mcp", 60, true},
		{"obsidian", "adapter-sources", []string{"--provider", "obsidian", "--principal", "desk-local"}, "command", 60, true},
		{"web", "adapter-web", []string{}, "http", 60, false},
	}}
}
