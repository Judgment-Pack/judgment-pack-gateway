package connections

// Web search has its own custody namespace and control protocol. Search results
// discover URLs; they are never represented as documents or applicant evidence.
import (
	"adapters/document"
	"adapters/internal/canon"
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/oauth2"
	googleauth "golang.org/x/oauth2/google"
)

const (
	SearchDefaultTimeoutSeconds = 45
	SearchMinTimeoutSeconds     = 10
	SearchMaxTimeoutSeconds     = 120
	// SearchShortEnvelopeSeconds is the longest connection timeout the
	// plan's ordinary web-search envelope carries: 60 seconds, the adapter
	// stopping at 55. A longer one needs the long envelope: the plan
	// launches the source with --long-search and SearchSourceSeconds, and
	// the adapter stops at SearchAdapterTimeout.
	SearchShortEnvelopeSeconds = 50
	SearchSourceSeconds        = SearchMaxTimeoutSeconds + 10
	SearchAdapterTimeout       = (SearchMaxTimeoutSeconds + 5) * time.Second
)

// SearchNeedsLongEnvelope reports whether a search connection under dir has a
// timeout longer than the ordinary envelope carries, for the local plan. It
// creates, locks and writes nothing; no directory, no namespace, no state, or
// state that cannot be read now, is false: the plan then stays the ordinary
// one, and a search past it ends at the adapter's deadline as search-timeout.
func SearchNeedsLongEnvelope(dir string) bool {
	if dir == "" || !filepath.IsAbs(dir) {
		return false
	}
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || private(st, true) != nil {
		return false
	}
	s, err := peekStore(filepath.Join(dir, "web-search"), "desk-local")
	if err != nil {
		return false
	}
	defer s.Close()
	raw, err := s.read("state.json")
	var v state
	if err != nil || decode(raw, &v) != nil || v.Search == nil {
		return false
	}
	for _, c := range v.Search.Connections {
		// A stored timeout configure would refuse counts as unset: such a
		// connection cannot run, and must not change the plan.
		if searchTimeoutValid(c.TimeoutSeconds) && c.TimeoutSeconds > SearchShortEnvelopeSeconds {
			return true
		}
	}
	return false
}

type SearchConnection struct {
	ID             string `json:"id"`
	Revision       string `json:"revision"`
	Name           string `json:"name"`
	Provider       string `json:"provider"`
	Project        string `json:"project,omitempty"`
	Location       string `json:"location,omitempty"`
	Model          string `json:"model,omitempty"`
	DailyLimit     int    `json:"dailyLimit"`
	TimeoutSeconds int    `json:"timeoutSeconds,omitempty"`
	Credential     string `json:"credential,omitempty"`
	Day            string `json:"day,omitempty"`
	Requests       int    `json:"requests,omitempty"`
}
type searchState struct {
	Connections []SearchConnection `json:"connections"`
}
type SearchRequest struct {
	Connection string `json:"connection"`
	Revision   string `json:"revision"`
	Query      string `json:"query"`
	MaxResults int    `json:"maxResults"`
}
type SearchHit struct {
	Title   string `json:"title"`
	URL     string `json:"url"`
	Snippet string `json:"snippet"`
}
type SearchResult struct {
	Version         int         `json:"version"`
	Connection      string      `json:"connection"`
	Revision        string      `json:"revision"`
	Provider        string      `json:"provider"`
	Query           string      `json:"query"`
	RetrievedAt     string      `json:"retrievedAt"`
	Kind            string      `json:"kind"`
	Hits            []SearchHit `json:"hits"`
	GeneratedAnswer string      `json:"generatedAnswer,omitempty"`
	AttributionHTML string      `json:"attributionHtml,omitempty"`
	Queries         []string    `json:"queries,omitempty"`
}

var searchID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`)
var cloudProject = regexp.MustCompile(`^[a-z][a-z0-9-]{4,61}[a-z0-9]$`)
var cloudLocation = regexp.MustCompile(`^(global|[a-z]+-[a-z]+[0-9]+)$`)
var cloudModel = regexp.MustCompile(`^gemini-[a-z0-9.-]{1,80}$`)

func searchDescriptor() Descriptor {
	return Descriptor{"web-search", "credentials", "form", "web-search", true, []string{"status", "configure", "disconnect", "test"}}
}
func searchCatalog(p map[string]Presentation) ProviderDescriptor {
	return ProviderDescriptor{Descriptor: searchDescriptor(), Protocol: "web-search-v1", QueryMode: "text", Presentation: p["web-search"], Setup: []SetupField{}, AuthorizationEndpoints: []string{}, Source: SourceContract{"web-search", "http", "web-search-v1"}}
}
func OpenSearchStore(dir, principal string) (*Store, error) {
	root, err := OpenStore(dir, principal)
	if err != nil {
		return nil, err
	}
	root.Close()
	return OpenStore(filepath.Join(dir, "web-search"), principal)
}
func NewSearch(s *Store, disabled bool) *Broker {
	p := googleProvider()
	p.search = true
	return &Broker{store: s, provider: p, disabled: disabled}
}

// Alias keeps the existing provider transport (no proxies or redirects) distinct
// from the OAuth library's package name.
func googleProvider() provider {
	p := google()
	// Grounded generation may not send headers until the model has finished.
	// Keep the bounded per-connection context, but do not apply the shorter
	// metadata API header timeout to search. Other Google integrations retain it.
	p.client.Transport.(*http.Transport).ResponseHeaderTimeout = 0
	p.client.Timeout = SearchMaxTimeoutSeconds * time.Second
	return p
}

func searchRequestFailure(err error, fallback Error) error {
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout() {
		return Error("search-timeout")
	}
	return fallback
}
func searchProviders() []map[string]any {
	return []map[string]any{
		{"id": "tavily", "name": "Tavily", "kind": "search-results", "fields": []string{"api-key"}, "docs": "https://docs.tavily.com/documentation/quickstart"},
		{"id": "google-grounding", "name": "Google Cloud · Search grounding", "kind": "grounded-answer", "fields": []string{"project", "location", "model", "service-account-json"}, "docs": "https://cloud.google.com/vertex-ai/generative-ai/docs/grounding/grounding-with-google-search"},
	}
}
func searchTimeout(c SearchConnection) time.Duration {
	seconds := c.TimeoutSeconds
	if seconds == 0 {
		seconds = SearchDefaultTimeoutSeconds
	}
	return time.Duration(seconds) * time.Second
}

// searchTimeoutValid reports whether a stored timeout is one configure
// accepts: zero (the default) or SearchMinTimeoutSeconds to
// SearchMaxTimeoutSeconds.
func searchTimeoutValid(seconds int) bool {
	return seconds == 0 || seconds >= SearchMinTimeoutSeconds && seconds <= SearchMaxTimeoutSeconds
}

// SearchTimeoutInvalid is what status reports for a stored timeout that is
// not one configure accepts (a hand-edited or damaged file): never the value
// itself, and a value outside every advertised bound. Such a connection
// answers setup-required until it is saved with a valid timeout.
const SearchTimeoutInvalid = -1

func searchValid(c SearchConnection) bool {
	if !searchTimeoutValid(c.TimeoutSeconds) {
		return false
	}
	if !searchID.MatchString(c.ID) || !resourceText(c.Name, 80, false) || c.DailyLimit < 1 || c.DailyLimit > 10000 || len(c.Credential) > 8192 {
		return false
	}
	switch c.Provider {
	case "tavily":
		return c.Project == "" && c.Location == "" && c.Model == "" && resourceText(c.Credential, 256, false) && !strings.ContainsAny(c.Credential, " \r\n\t")
	case "google-grounding":
		if !cloudProject.MatchString(c.Project) || !cloudLocation.MatchString(c.Location) || !cloudModel.MatchString(c.Model) {
			return false
		}
		return validateGoogleCredential(c.Credential) == nil
	default:
		return false
	}
}
func validateGoogleCredential(raw string) error {
	var c struct {
		Type     string `json:"type"`
		Email    string `json:"client_email"`
		TokenURI string `json:"token_uri"`
	}
	if json.Unmarshal([]byte(raw), &c) != nil || c.Type != "service_account" || !strings.HasSuffix(c.Email, ".iam.gserviceaccount.com") || c.TokenURI != "https://oauth2.googleapis.com/token" {
		return ErrRequest
	}
	cfg, err := googleauth.JWTConfigFromJSON([]byte(raw), "https://www.googleapis.com/auth/cloud-platform")
	if err != nil || cfg.TokenURL != "https://oauth2.googleapis.com/token" || len(cfg.PrivateKey) == 0 {
		return ErrRequest
	}
	block, _ := pem.Decode(cfg.PrivateKey)
	if block == nil {
		return ErrRequest
	}
	parsed, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		parsed, e = x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if e != nil || !ok || key.N.BitLen() < 2048 {
		return ErrRequest
	}
	return nil
}
func (b *Broker) searchOperation(ctx context.Context, method string, raw []byte) (any, error) {
	switch method {
	case "status":
		var q struct{}
		if decode(raw, &q) != nil {
			return nil, ErrRequest
		}
		rows := []SearchConnection{}
		err := b.store.locked(func(v *state) error {
			if v.Search != nil {
				for _, c := range v.Search.Connections {
					c.Credential = ""
					if !searchTimeoutValid(c.TimeoutSeconds) {
						c.TimeoutSeconds = SearchTimeoutInvalid
					}
					if c.Day != time.Now().UTC().Format("2006-01-02") {
						c.Requests = 0
					}
					rows = append(rows, c)
				}
			}
			return nil
		})
		return map[string]any{"version": 1, "providers": searchProviders(), "connections": rows, "timeout": map[string]int{"defaultSeconds": SearchDefaultTimeoutSeconds, "minSeconds": SearchMinTimeoutSeconds, "maxSeconds": SearchMaxTimeoutSeconds}}, err
	case "configure":
		var q SearchConnection
		if decode(raw, &q) != nil || q.Day != "" || q.Requests != 0 {
			return nil, ErrRequest
		}
		err := b.store.locked(func(v *state) error {
			if v.Search == nil {
				v.Search = &searchState{Connections: []SearchConnection{}}
			}
			index := -1
			for i, c := range v.Search.Connections {
				if c.ID == q.ID {
					index = i
					if c.Revision != q.Revision {
						return ErrChanged
					}
					if q.Credential == "" && c.Provider == q.Provider {
						q.Credential = c.Credential
					}
					q.Day = c.Day
					q.Requests = c.Requests
				}
			}
			if index < 0 && (q.Revision != "" || len(v.Search.Connections) >= 6) {
				return ErrRequest
			}
			if !searchValid(q) {
				return ErrRequest
			}
			q.Revision = randomID()
			if index < 0 {
				v.Search.Connections = append(v.Search.Connections, q)
			} else {
				v.Search.Connections[index] = q
			}
			return b.store.write("state.json", v)
		})
		return map[string]bool{"saved": err == nil}, err
	case "disconnect":
		var q struct {
			ID       string `json:"id"`
			Revision string `json:"revision"`
		}
		if decode(raw, &q) != nil || !searchID.MatchString(q.ID) || !opaque.MatchString(q.Revision) {
			return nil, ErrRequest
		}
		err := b.store.locked(func(v *state) error {
			if v.Search == nil {
				return ErrChanged
			}
			for i, c := range v.Search.Connections {
				if c.ID == q.ID && c.Revision == q.Revision {
					v.Search.Connections = append(v.Search.Connections[:i], v.Search.Connections[i+1:]...)
					return b.store.write("state.json", v)
				}
			}
			return ErrChanged
		})
		return map[string]bool{"disconnected": err == nil}, err
	case "test":
		var q struct {
			ID       string `json:"id"`
			Revision string `json:"revision"`
		}
		if decode(raw, &q) != nil {
			return nil, ErrRequest
		}
		// Explicit UI action, one metered provider request. Never return its content.
		_, err := searchAcquire(ctx, b.store, SearchRequest{q.ID, q.Revision, "public documentation", 1}, b.provider)
		return map[string]bool{"ok": err == nil}, err
	}
	return nil, ErrRequest
}
func searchSnapshot(s *Store, q SearchRequest) (SearchConnection, error) {
	var found SearchConnection
	if !searchID.MatchString(q.Connection) || !opaque.MatchString(q.Revision) || !resourceText(q.Query, 2000, false) || q.MaxResults < 1 || q.MaxResults > 10 {
		return found, ErrRequest
	}
	err := s.locked(func(v *state) error {
		if v.Disabled {
			return ErrPolicy
		}
		if v.Search == nil {
			return ErrConnect
		}
		for i, c := range v.Search.Connections {
			if c.ID == q.Connection {
				if c.Revision != q.Revision {
					return ErrChanged
				}
				if !searchValid(c) {
					return ErrSetup
				}
				day := time.Now().UTC().Format("2006-01-02")
				if c.Day != day {
					c.Day = day
					c.Requests = 0
				}
				if c.Requests >= c.DailyLimit {
					return Error("search-budget-exhausted")
				}
				c.Requests++
				v.Search.Connections[i] = c
				found = c
				return s.write("state.json", v)
			}
		}
		return ErrConnect
	})
	return found, err
}
func searchCurrent(s *Store, c SearchConnection) error {
	return s.locked(func(v *state) error {
		if v.Disabled {
			return ErrPolicy
		}
		if v.Search != nil {
			for _, p := range v.Search.Connections {
				if p.ID == c.ID && p.Revision == c.Revision {
					return nil
				}
			}
		}
		return ErrChanged
	})
}
func ReadSearch(ctx context.Context, s *Store, raw []byte) ([]byte, error) {
	var q SearchRequest
	if decode(raw, &q) != nil {
		return nil, ErrRequest
	}
	return searchAcquire(ctx, s, q, googleProvider())
}
func searchAcquire(ctx context.Context, s *Store, q SearchRequest, p provider) ([]byte, error) {
	c, err := searchSnapshot(s, q)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, searchTimeout(c))
	defer cancel()
	endpoint := "https://api.tavily.com/search"
	token := c.Credential
	body := map[string]any{"query": q.Query, "max_results": q.MaxResults, "search_depth": "basic", "include_answer": false, "include_raw_content": false}
	if c.Provider == "google-grounding" {
		cfg, e := googleauth.JWTConfigFromJSON([]byte(c.Credential), "https://www.googleapis.com/auth/cloud-platform")
		if e != nil {
			return nil, ErrSetup
		}
		authCtx := context.WithValue(ctx, oauth2.HTTPClient, p.client)
		access, e := cfg.TokenSource(authCtx).Token()
		if e != nil {
			return nil, searchRequestFailure(e, Error("credentials-required"))
		}
		token = access.AccessToken
		host := "aiplatform.googleapis.com"
		if c.Location != "global" {
			host = c.Location + "-" + host
		}
		endpoint = "https://" + host + "/v1/projects/" + c.Project + "/locations/" + c.Location + "/publishers/google/models/" + c.Model + ":generateContent"
		body = map[string]any{"contents": []any{map[string]any{"role": "user", "parts": []any{map[string]any{"text": "Use Google Search to find public sources for this query. Give a concise factual answer with sources. Query: " + q.Query}}}}, "tools": []any{map[string]any{"googleSearch": map[string]any{}}}, "generationConfig": map[string]any{"maxOutputTokens": 2048, "temperature": 1}}
	}
	// Tests inject an isolated TLS endpoint through the package-private provider.
	if p.searchEndpoint != "" {
		endpoint = p.searchEndpoint
	}
	encoded, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(encoded))
	if err != nil {
		return nil, ErrRequest
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	response, err := p.client.Do(req)
	if err != nil {
		return nil, searchRequestFailure(err, ErrProvider)
	}
	defer response.Body.Close()
	if response.StatusCode == 401 || response.StatusCode == 403 {
		return nil, Error("credentials-required")
	}
	if response.StatusCode == 429 {
		return nil, Error("rate-limited")
	}
	if response.StatusCode != 200 {
		return nil, ErrProvider
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil {
		return nil, searchRequestFailure(err, ErrProvider)
	}
	if len(data) > 2<<20 || !utf8.Valid(data) || bytes.Contains(data, []byte(token)) {
		return nil, ErrProvider
	}
	result, err := normalizeSearch(data, c, q)
	if err != nil {
		return nil, err
	}
	if err = searchCurrent(s, c); err != nil {
		return nil, err
	}
	identity, err := document.OwnIdentity()
	if err != nil {
		return nil, ErrProvider
	}
	identity.Name = "adapter-sources"
	peer := any(nil)
	if response.TLS != nil && len(response.TLS.PeerCertificates) > 0 {
		sum := sha256.Sum256(response.TLS.PeerCertificates[0].Raw)
		peer = "tls:sha256:" + hex.EncodeToString(sum[:])
	}
	statement, _ := canon.EncodeJSON(map[string]any{"connection": q.Connection, "revision": q.Revision, "provider": c.Provider, "query": q.Query, "maxResults": q.MaxResults, "method": "POST", "endpoint": endpoint})
	return canon.EncodeJSON(map[string]any{"acquisition": map[string]any{"adapter": identity, "endpoint": endpoint, "statement": string(statement), "snapshot": digest(data), "peerIdentity": peer, "schema": nil, "upstreamToken": nil, "observedAt": result.RetrievedAt}, "result": result})
}
func searchURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && (u.Port() == "" || u.Port() == "443") && len(value) <= 4096 && !strings.ContainsAny(value, "\r\n\x00")
}
func normalizeSearch(data []byte, c SearchConnection, q SearchRequest) (SearchResult, error) {
	out := SearchResult{Version: 1, Connection: c.ID, Revision: c.Revision, Provider: c.Provider, Query: q.Query, RetrievedAt: time.Now().UTC().Format(time.RFC3339), Kind: "search-results", Hits: []SearchHit{}}
	seen := map[string]bool{}
	add := func(title, link, snippet string) {
		if len(out.Hits) >= q.MaxResults || !searchURL(link) || seen[link] {
			return
		}
		seen[link] = true
		out.Hits = append(out.Hits, SearchHit{clipSearchText(title, 512), link, clipSearchText(snippet, 2000)})
	}
	if c.Provider == "tavily" {
		var r struct {
			Results *[]struct {
				Title   string `json:"title"`
				URL     string `json:"url"`
				Content string `json:"content"`
			} `json:"results"`
		}
		if json.Unmarshal(data, &r) != nil || r.Results == nil {
			return out, ErrProvider
		}
		for _, h := range *r.Results {
			add(h.Title, h.URL, h.Content)
		}
	} else {
		var r struct {
			Candidates []struct {
				Content struct {
					Parts []struct {
						Text string `json:"text"`
					} `json:"parts"`
				} `json:"content"`
				Metadata struct {
					Chunks []struct {
						Web *struct {
							URI   string `json:"uri"`
							Title string `json:"title"`
						} `json:"web"`
					} `json:"groundingChunks"`
					Entry struct {
						HTML string `json:"renderedContent"`
					} `json:"searchEntryPoint"`
					Queries []string `json:"webSearchQueries"`
				} `json:"groundingMetadata"`
			} `json:"candidates"`
		}
		if json.Unmarshal(data, &r) != nil || len(r.Candidates) == 0 {
			return out, ErrProvider
		}
		first := r.Candidates[0]
		out.Kind = "grounded-answer"
		for _, part := range first.Content.Parts {
			out.GeneratedAnswer += part.Text
		}
		out.GeneratedAnswer = clipSearchText(out.GeneratedAnswer, 12000)
		for _, h := range first.Metadata.Chunks {
			if h.Web != nil {
				add(h.Web.Title, h.Web.URI, "")
			}
		}
		if len(first.Metadata.Entry.HTML) > 32000 {
			return out, ErrProvider
		}
		if len(out.Hits) == 0 || first.Metadata.Entry.HTML == "" {
			return out, Error("search-not-grounded")
		}
		out.AttributionHTML = first.Metadata.Entry.HTML
		if len(first.Metadata.Queries) > 20 {
			return out, ErrProvider
		}
		for _, query := range first.Metadata.Queries {
			out.Queries = append(out.Queries, clipSearchText(query, 2000))
		}
	}
	return out, nil
}
func clipSearchText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
