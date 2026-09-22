package connections

// Catalog describes the connection protocols implemented by this binary. It is
// static discovery, not account status, authorization, or a tool grant. Clients
// must still ask status and perform the normal consent/selection operations.
type Catalog struct {
	Sources   []SourceDescriptor `json:"sources"`
	Version   int                `json:"version"`
	Providers []Descriptor       `json:"providers"`
}

type SourceDescriptor struct {
	ID         string   `json:"id"`
	Input      string   `json:"input"`
	MediaTypes []string `json:"mediaTypes"`
	MaxBytes   int      `json:"maxBytes"`
}

type Descriptor struct {
	ID            string   `json:"id"`
	Auth          string   `json:"auth"`
	Registration  string   `json:"registration"`
	Selection     string   `json:"selection"`
	QueryRequired bool     `json:"queryRequired"`
	Operations    []string `json:"operations"`
}

// ConnectionCatalog contains only shipped protocols, without endpoints,
// credentials, executable names, paths, account data, or display copy. Return a
// fresh value so callers cannot alter the broker's operation allowlist.
func ConnectionCatalog() Catalog {
	return Catalog{Version: 2, Sources: []SourceDescriptor{{"web", "url", []string{"text/html", "text/plain", "application/pdf"}, 4 << 20}}, Providers: []Descriptor{
		{"google-drive", "oauth", "google-desktop", "browser-picker", false, []string{"status", "configure", "connect", "pick", "poll", "cancel", "disconnect"}},
		{"gmail", "oauth", "google-desktop", "mail-search", false, []string{"status", "configure", "connect", "poll", "cancel", "disconnect", "search", "select"}},
		{"notion", "oauth", "automatic", "source-search", true, []string{"status", "connect", "poll", "cancel", "disconnect", "search", "select"}},
		{"obsidian", "local-folder", "none", "source-search", false, []string{"status", "configure", "disconnect", "search", "select"}},
	}}
}

func LookupProvider(id string) (Descriptor, bool) {
	if id == "aws-s3" {
		return s3Descriptor(), true
	}
	for _, provider := range ConnectionCatalog().Providers {
		if provider.ID == id {
			return provider, true
		}
	}
	return Descriptor{}, false
}

func (d Descriptor) supports(method string) bool {
	for _, operation := range d.Operations {
		if operation == method {
			return true
		}
	}
	return false
}
