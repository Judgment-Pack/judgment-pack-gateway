package connections

// Azure DevOps has its own custody namespace and control protocol, as
// Databricks has: up to six named connections, each to one project of one
// organization's REST API, under a personal access token or a Microsoft
// Entra access token the operator pastes with its expiry. A read is one
// bounded request -- or, for workitems.query-and-get, a WIQL query and then
// the work items by the ids it answered -- and its result is the API's answer
// as received. What the credential may read, and whether a call could write,
// is the credential's scopes and its identity's permissions: the connection
// mints nothing, and holds itself to the reads it names, each a GET but the
// query, which the API takes as a POST.
import (
	"adapters/document"
	"adapters/internal/canon"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// AzureDevOpsAPIVersion is the REST API version every request names.
	AzureDevOpsAPIVersion = "7.1"
	// The result bound, as Databricks': room for the envelope under the
	// source's output bound (MaxOutputBytes).
	AzureDevOpsDefaultResultBytes = 8 << 20
	AzureDevOpsMinResultBytes     = 64 << 10
	AzureDevOpsMaxResultBytes     = 15 << 20
	// AzureDevOpsMaxIDs is the most work items one request reads: "Maximum
	// 200 ids allowed", as the API states it.
	AzureDevOpsMaxIDs = 200
	// AzureDevOpsMaxTop bounds a query's $top: query results are truncated
	// at 20,000 items.
	AzureDevOpsMaxTop = 20000
	// AzureDevOpsMaxPage bounds a page of commits, pull requests or
	// pipelines, which the API states no bound for.
	AzureDevOpsMaxPage       = 1000
	azureDevOpsDefaultTop    = 200
	azureDevOpsDefaultPage   = 100
	azureDevOpsQueryChars    = 32000
	azureDevOpsMaxFields     = 64
	azureDevOpsConnections   = 6
	azureDevOpsErrorBytes    = 64 << 10
	azureDevOpsResourceBytes = 256
	// azureDevOpsSeconds bounds each request: the two of a query-and-get fit
	// inside the adapter's 55 seconds.
	azureDevOpsSeconds = 25
	// An access token within this of its expiry is not sent.
	azureDevOpsTokenSlack = time.Minute
)

// AzureDevOpsConnection is what configure takes and custody holds. Its
// member names are the setup fields' keys, and its values are text, as a
// form sends them.
type AzureDevOpsConnection struct {
	ID           string `json:"id"`
	Revision     string `json:"revision"`
	Name         string `json:"name"`
	Organization string `json:"organization-url"`
	Project      string `json:"project"`
	Auth         string `json:"auth"`
	Token        string `json:"token,omitempty"`
	AccessToken  string `json:"access-token,omitempty"`
	ExpiresAt    string `json:"expires-at,omitempty"`
	ResultBytes  string `json:"max-result-bytes,omitempty"`
}
type azureDevOpsState struct {
	Connections []AzureDevOpsConnection `json:"connections"`
}

// azureDevOpsRow is a connection as status reports it: never a secret.
type azureDevOpsRow struct {
	AzureDevOpsConnection
	Ready bool `json:"ready"`
}

// AzureDevOpsRequest is what adapter-sources --provider azure-devops reads.
// Each read takes the members its name says, and no others.
type AzureDevOpsRequest struct {
	Connection  string   `json:"connection"`
	Revision    string   `json:"revision"`
	Read        string   `json:"read"`
	Query       string   `json:"query,omitempty"`
	ID          int64    `json:"id,omitempty"`
	IDs         []int64  `json:"ids,omitempty"`
	Fields      []string `json:"fields,omitempty"`
	Top         int      `json:"top,omitempty"`
	Skip        int      `json:"skip,omitempty"`
	Cursor      string   `json:"cursor,omitempty"`
	Repository  string   `json:"repository,omitempty"`
	Path        string   `json:"path,omitempty"`
	Recursion   string   `json:"recursion,omitempty"`
	Version     string   `json:"version,omitempty"`
	VersionType string   `json:"versionType,omitempty"`
	Status      string   `json:"status,omitempty"`
	Pipeline    int64    `json:"pipeline,omitempty"`
	Run         int64    `json:"run,omitempty"`
}

// An organization's name: letters of the English alphabet, digits and
// hyphens, a letter or a digit first and last, under 50 characters. As a
// host name it is held to lowercase.
var azureDevOpsOrganizationName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,47}[A-Za-z0-9])?$`)
var azureDevOpsOrganizationLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,47}[a-z0-9])?$`)
var azureDevOpsGUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// azureDevOpsField is a work item field's reference name: dotted, as
// System.Title or Microsoft.VSTS.Common.Priority.
var azureDevOpsField = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+)+$`)
var azureDevOpsCommit = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
var azureDevOpsTypeKeyForm = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.]{0,127}$`)

// The characters a project's or a repository's name may not hold.
const (
	azureDevOpsProjectForbidden    = `\/:*?"'<>;#${},+=[]|`
	azureDevOpsRepositoryForbidden = `\/:*?"<>;#${},+=[]|`
)

// AzureDevOpsOrganization holds an organization URL to one of its two forms,
// https://dev.azure.com/{organization} and the older
// https://{organization}.visualstudio.com, and to nothing else: no user
// information, port, path beyond the organization, query, fragment, escape or
// trailing dot. It returns the URL without a trailing slash.
func AzureDevOpsOrganization(raw string) (string, bool) {
	rest, ok := strings.CutPrefix(raw, "https://")
	if !ok || len(raw) > 128 {
		return "", false
	}
	rest = strings.TrimSuffix(rest, "/")
	if rest == "" || strings.ContainsAny(rest, "?#@:[]%\\") {
		return "", false
	}
	for _, r := range rest {
		if r <= ' ' || r >= 0x7f {
			return "", false
		}
	}
	var out, host string
	if found, organization, slashed := strings.Cut(rest, "/"); slashed {
		if found != "dev.azure.com" || !azureDevOpsOrganizationName.MatchString(organization) {
			return "", false
		}
		out, host = "https://dev.azure.com/"+organization, found
	} else {
		label, ok := strings.CutSuffix(rest, ".visualstudio.com")
		// A label with hyphens in its third and fourth places is a
		// punycode or reserved one, never an organization's.
		if !ok || !azureDevOpsOrganizationLabel.MatchString(label) || len(label) >= 4 && label[2:4] == "--" {
			return "", false
		}
		out, host = "https://"+rest, rest
	}
	u, err := url.Parse(out)
	if err != nil || u.Host != host || u.Hostname() != host || u.Port() != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	return out, true
}

// azureDevOpsName holds a project's or a repository's name to the form the
// naming restrictions state: 1 to 64 characters, no control or surrogate
// character, none of the forbidden ones, not an underscore first nor a
// period first or last. An id (a GUID) is taken too.
func azureDevOpsName(s, forbidden string) bool {
	if azureDevOpsGUID.MatchString(s) {
		return true
	}
	if !utf8.ValidString(s) || s == "" || utf8.RuneCountInString(s) > 64 || strings.ContainsAny(s, forbidden) || strings.HasPrefix(s, "_") || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r > 0xffff || unicode.Is(unicode.Cs, r) {
			return false
		}
	}
	return true
}

// azureDevOpsPath is a path in a repository: "/" alone or "/" and segments,
// none empty, "." or "..", with no control character or backslash.
func azureDevOpsPath(s string) bool {
	if s == "/" {
		return true
	}
	if !strings.HasPrefix(s, "/") || len(s) > 1024 || !utf8.ValidString(s) || strings.ContainsAny(s, "\\") {
		return false
	}
	for _, segment := range strings.Split(s[1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// azureDevOpsRef is a branch's or a tag's name, held to git's reference
// rules: no control character, space, ~ ^ : ? * [ or backslash, no "..",
// "@{" or "//", no "/" or "." first or last, no ".lock" last.
func azureDevOpsRef(s string) bool {
	if s == "" || len(s) > 255 || !utf8.ValidString(s) || strings.ContainsAny(s, " ~^:?*[\\") || strings.Contains(s, "..") || strings.Contains(s, "@{") || strings.Contains(s, "//") ||
		strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") || strings.HasSuffix(s, ".lock") {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// azureDevOpsQueryText is a WIQL query: UTF-8, at most 32,000 characters,
// with no control character but a tab or a line's end.
func azureDevOpsQueryText(s string) bool {
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > azureDevOpsQueryChars {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
			return false
		}
	}
	return true
}

// azureDevOpsWithinBound is whether n work items fit the bound of one
// request: AzureDevOpsMaxIDs, or a query-and-get's $top.
func azureDevOpsWithinBound(n, bound int) bool { return n <= bound }

func (c AzureDevOpsConnection) resultBound() int {
	return databricksNumber(c.ResultBytes, AzureDevOpsDefaultResultBytes, AzureDevOpsMinResultBytes, AzureDevOpsMaxResultBytes)
}

// expiry is the access token's expiry as the operator gave it.
func (c AzureDevOpsConnection) expiry() (time.Time, bool) {
	when, err := time.Parse(time.RFC3339, c.ExpiresAt)
	return when, err == nil
}

// expired reports whether the access token would not outlast the minute's
// slack: it is then not sent.
func (c AzureDevOpsConnection) expired() bool {
	if c.Auth != "bearer" {
		return false
	}
	when, ok := c.expiry()
	return !ok || !when.After(time.Now().Add(azureDevOpsTokenSlack))
}

// basic is the personal access token as HTTP basic authentication with an
// empty user name, built when a request is made and kept nowhere.
func (c AzureDevOpsConnection) basic() string {
	return base64.StdEncoding.EncodeToString([]byte(":" + c.Token))
}

// authorization is the Authorization header a request is sent under.
func (c AzureDevOpsConnection) authorization() string {
	if c.Auth == "token" {
		return "Basic " + c.basic()
	}
	return "Bearer " + c.AccessToken
}

// secrets are what is never written into a record, an error, a status or a
// test answer: the personal access token and its basic authentication
// value, or the access token. Longest first, so that a replacement takes
// the whole of each.
func (c AzureDevOpsConnection) secrets() []string {
	out := []string{}
	if c.Token != "" {
		out = append(out, c.Token, c.basic())
	}
	if c.AccessToken != "" {
		out = append(out, c.AccessToken)
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// spells reports whether the connection's own text -- its id, name,
// organization URL, project, expiry or bound -- spells its credential.
func (c AzureDevOpsConnection) spells() bool {
	secrets := c.secrets()
	for _, text := range []string{c.ID, c.Name, c.Organization, c.Project, c.ExpiresAt, c.ResultBytes} {
		if databricksSpells(text, secrets) {
			return true
		}
	}
	return false
}

func (c AzureDevOpsConnection) valid() bool {
	if !searchID.MatchString(c.ID) || !resourceText(c.Name, 80, false) || !azureDevOpsName(c.Project, azureDevOpsProjectForbidden) || c.resultBound() < 0 || c.spells() {
		return false
	}
	if organization, ok := AzureDevOpsOrganization(c.Organization); !ok || organization != c.Organization {
		return false
	}
	switch c.Auth {
	case "token":
		return databricksPrintable(c.Token, 8, 4096) && c.AccessToken == "" && c.ExpiresAt == ""
	case "bearer":
		_, ok := c.expiry()
		return c.Token == "" && databricksPrintable(c.AccessToken, 16, 8192) && ok
	}
	return false
}

func azureDevOpsDescriptor() Descriptor {
	return Descriptor{"azure-devops", "credentials", "form", "none", true, []string{"status", "configure", "disconnect", "test"}}
}

// azureDevOpsSetup is each setup field's key, whether it is a secret, and
// whether a form must fill it.
var azureDevOpsSetup = []struct {
	key      string
	secret   bool
	required bool
}{
	{"organization-url", false, true}, {"project", false, true}, {"auth", false, true},
	{"token", true, false}, {"access-token", true, false}, {"expires-at", false, false}, {"max-result-bytes", false, false},
}

func azureDevOpsCatalog(p map[string]Presentation) ProviderDescriptor {
	d := ProviderDescriptor{Descriptor: azureDevOpsDescriptor(), Protocol: "azure-devops-v1", QueryMode: "text", Presentation: p["azure-devops"], Setup: []SetupField{}, AuthorizationEndpoints: []string{}, Source: SourceContract{"azure-devops", "http", "azure-devops-api-v1"}}
	for _, field := range azureDevOpsSetup {
		kind := "text"
		if field.secret {
			kind = "password"
		}
		d.Setup = append(d.Setup, SetupField{field.key, kind, p["azure-devops-"+field.key].Description, field.required})
	}
	return d
}
func OpenAzureDevOpsStore(dir, principal string) (*Store, error) {
	root, err := OpenStore(dir, principal)
	if err != nil {
		return nil, err
	}
	root.Close()
	return OpenStore(filepath.Join(dir, "azure-devops"), principal)
}
func NewAzureDevOps(s *Store, disabled bool) *Broker {
	return &Broker{store: s, provider: azureDevOpsProvider(), disabled: disabled}
}

// azureDevOpsProvider is the Google transport without its header cutoff: a
// query may answer only when it has run. Each request has a deadline of its
// own; no redirect is followed and no proxy used.
func azureDevOpsProvider() provider {
	p := google()
	p.azureDevOps = true
	p.auth, p.token, p.revoke, p.api = "", "", "", ""
	p.client.Transport.(*http.Transport).ResponseHeaderTimeout = 0
	p.client.Timeout = (azureDevOpsSeconds + 5) * time.Second
	return p
}

// azureDevOpsInConfiguration refuses a connection whose own text carries its
// credential.
const azureDevOpsInConfiguration = Error("credential-in-configuration: the connection's id, name, organization URL, project or expiry carries its credential, which is kept only as the credential; the connection was not saved")

func (b *Broker) azureDevOpsOperation(ctx context.Context, method string, raw []byte) (any, error) {
	switch method {
	case "status":
		var q struct{}
		if decode(raw, &q) != nil {
			return nil, ErrRequest
		}
		rows := []azureDevOpsRow{}
		err := b.store.locked(func(v *state) error {
			if v.AzureDevOps != nil {
				for _, c := range v.AzureDevOps.Connections {
					rows = append(rows, c.row())
				}
			}
			return nil
		})
		limits := map[string]any{
			"apiVersion":         AzureDevOpsAPIVersion,
			"defaultResultBytes": AzureDevOpsDefaultResultBytes, "minResultBytes": AzureDevOpsMinResultBytes, "maxResultBytes": AzureDevOpsMaxResultBytes,
			"maxIds": AzureDevOpsMaxIDs, "maxTop": AzureDevOpsMaxTop, "maxPage": AzureDevOpsMaxPage,
		}
		return map[string]any{"version": 1, "provider": "azure-devops", "connections": rows, "limits": limits}, err
	case "configure":
		var q AzureDevOpsConnection
		if decode(raw, &q) != nil {
			return nil, ErrRequest
		}
		if organization, ok := AzureDevOpsOrganization(q.Organization); ok {
			q.Organization = organization
		}
		err := b.store.locked(func(v *state) error {
			if v.AzureDevOps == nil {
				v.AzureDevOps = &azureDevOpsState{Connections: []AzureDevOpsConnection{}}
			}
			index := -1
			for i, c := range v.AzureDevOps.Connections {
				if c.ID != q.ID {
					continue
				}
				index = i
				if c.Revision != q.Revision {
					return ErrChanged
				}
				// A blank credential keeps the saved one only where it would
				// be sent to the same organization the same way; an access
				// token keeps its expiry with it, and a new expiry is a new
				// token's.
				if q.Auth == c.Auth && q.Organization == c.Organization {
					if q.Auth == "token" && q.Token == "" {
						q.Token = c.Token
					}
					if q.Auth == "bearer" && q.AccessToken == "" && q.ExpiresAt == "" {
						q.AccessToken, q.ExpiresAt = c.AccessToken, c.ExpiresAt
					}
				}
			}
			if index < 0 && (q.Revision != "" || len(v.AzureDevOps.Connections) >= azureDevOpsConnections) {
				return ErrRequest
			}
			if q.spells() {
				return azureDevOpsInConfiguration
			}
			if !q.valid() {
				return ErrRequest
			}
			q.Revision = randomID()
			if index < 0 {
				v.AzureDevOps.Connections = append(v.AzureDevOps.Connections, q)
			} else {
				v.AzureDevOps.Connections[index] = q
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
			if v.AzureDevOps == nil {
				return ErrChanged
			}
			for i, c := range v.AzureDevOps.Connections {
				if c.ID == q.ID && c.Revision == q.Revision {
					v.AzureDevOps.Connections = append(v.AzureDevOps.Connections[:i], v.AzureDevOps.Connections[i+1:]...)
					return b.store.write("state.json", v)
				}
			}
			return ErrChanged
		})
		// Deleting local custody revokes nothing in the organization.
		return map[string]bool{"disconnected": err == nil, "revoked": false}, err
	case "test":
		var q struct {
			ID       string `json:"id"`
			Revision string `json:"revision"`
		}
		if decode(raw, &q) != nil {
			return nil, ErrRequest
		}
		// An explicit action: one query for at most one work item of the
		// project, whose answer is never returned.
		err := azureDevOpsTest(ctx, b.store, q.ID, q.Revision, b.provider)
		return map[string]bool{"ok": err == nil}, err
	}
	return nil, ErrRequest
}

// row is the connection as status reports it: no credential, and a
// connection whose own text would spell its credential -- which configure
// refuses -- reported with that text replaced, and not ready.
func (c AzureDevOpsConnection) row() azureDevOpsRow {
	ready := c.valid() && !c.expired()
	secrets := c.secrets()
	if c.spells() {
		ready = false
		for _, text := range []*string{&c.ID, &c.Name, &c.Organization, &c.Project, &c.ExpiresAt, &c.ResultBytes} {
			if databricksSpells(*text, secrets) {
				*text = "[redacted]"
			}
		}
	}
	c.Token, c.AccessToken = "", ""
	return azureDevOpsRow{c, ready}
}

// azureDevOpsSnapshot is the connection a request names, as it stands.
func azureDevOpsSnapshot(s *Store, id, revision string) (AzureDevOpsConnection, error) {
	var found AzureDevOpsConnection
	if !searchID.MatchString(id) || !opaque.MatchString(revision) {
		return found, ErrRequest
	}
	err := s.locked(func(v *state) error {
		if v.Disabled {
			return ErrPolicy
		}
		if v.AzureDevOps == nil {
			return ErrConnect
		}
		for _, c := range v.AzureDevOps.Connections {
			if c.ID == id {
				if c.Revision != revision {
					return ErrChanged
				}
				if !c.valid() {
					return ErrSetup
				}
				found = c
				return nil
			}
		}
		return ErrConnect
	})
	return found, err
}

// azureDevOpsCurrent refuses an answer to a connection that was changed,
// removed or blocked while it was asked.
func azureDevOpsCurrent(s *Store, c AzureDevOpsConnection) error {
	return s.locked(func(v *state) error {
		if v.Disabled {
			return ErrPolicy
		}
		if v.AzureDevOps != nil {
			for _, p := range v.AzureDevOps.Connections {
				if p.ID == c.ID && p.Revision == c.Revision {
					return nil
				}
			}
		}
		return ErrChanged
	})
}

// azureDevOpsExpired is the refusal of an access token at or within a
// minute of the expiry the operator gave for it.
const azureDevOpsExpired = Error("credentials-expired: the connection's access token has expired, or expires within a minute, by the expiry configured for it; nothing was sent")

// azureDevOpsInRequest is the refusal of a request that carries the
// connection's credential. It names the rule, never the value.
const azureDevOpsInRequest = Error("credential-in-request: a request may not carry the connection's credential, which is sent only as its authorization; the request was not sent")

// azureDevOpsRetry is how long a 429 or a 503 asks to wait, as its
// Retry-After header says it, in seconds or as a date.
func azureDevOpsRetry(header http.Header) string {
	after := header.Get("Retry-After")
	if databricksRetrySeconds.MatchString(after) {
		return after + " seconds"
	}
	if when, err := http.ParseTime(after); err == nil {
		return "until " + when.UTC().Format(http.TimeFormat)
	}
	return ""
}

// azureDevOpsTypeKey is the error type an error body names, read by its
// exact name and held to an identifier's form; nothing where it names none,
// or names it in another case too.
func azureDevOpsTypeKey(raw []byte) string {
	if _, err := canon.Canonicalize(raw, canon.CarryNumbersAsText); err != nil || !canon.IsObject(raw) {
		return ""
	}
	members, ok := databricksMembers(raw, "typeKey")
	var key string
	if present, okKey := databricksField(members, "typeKey", &key); !ok || !present || !okKey || !azureDevOpsTypeKeyForm.MatchString(key) {
		return ""
	}
	return key
}

// azureDevOpsResource is the threshold a rate limit names in its
// X-RateLimit-Resource header, which the service says to show a person:
// printable text, every whole secret replaced, then cut to its bound.
func azureDevOpsResource(header http.Header, secrets []string) string {
	resource := header.Get("X-RateLimit-Resource")
	for i := 0; i < len(resource); i++ {
		if resource[i] < 0x20 || resource[i] > 0x7e {
			return ""
		}
	}
	resource = databricksRedact(resource, secrets)
	if len(resource) > azureDevOpsResourceBytes {
		resource = clipSearchText(resource, azureDevOpsResourceBytes) + "…"
	}
	return resource
}

// azureDevOpsRefusal is what an answer other than 200 is reported as: its
// status, the error type the body names where it names one, and for a 429
// or a 503 the wait it asks for and the threshold it names. The API's
// message is not repeated: it may repeat what was sent. Nothing is retried.
func azureDevOpsRefusal(status int, header http.Header, raw []byte, secrets []string) error {
	named := strconv.Itoa(status)
	if key := azureDevOpsTypeKey(raw); key != "" {
		named += " (" + key + ")"
	}
	var text string
	switch {
	case status >= 300 && status < 400:
		return Error(fmt.Sprintf("provider-unavailable: the organization answered %d, a redirect, which is not followed", status))
	case status == 401:
		text = "credentials-required: the organization answered " + named
	case status == 403:
		text = "permission-denied: the organization answered " + named
	case status == 429:
		text = "rate-limited: the organization answered " + named
	case status >= 500:
		text = "provider-unavailable: the organization answered " + named
	case status >= 400:
		text = "request-refused: the organization answered " + named
	default:
		text = "provider-unavailable: the organization answered " + named + ", which this connection does not read"
	}
	if status == 429 || status == 503 {
		if wait := azureDevOpsRetry(header); wait != "" {
			text += " and asks to wait " + wait + " before another request"
		}
		if resource := azureDevOpsResource(header, secrets); resource != "" {
			text += " (threshold: " + resource + ")"
		}
		text += "; it was not retried"
	}
	return Error(text)
}

// azureDevOpsSend makes one request and returns the JSON body of a 200
// within the bound, read no further than a byte past it, or the refusal.
// The Authorization header is built here, from the connection, and kept
// nowhere else.
func (p provider) azureDevOpsSend(ctx context.Context, c AzureDevOpsConnection, method, target string, body []byte, bound int, secrets []string) (*http.Response, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, azureDevOpsSeconds*time.Second)
	defer cancel()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, nil, ErrRequest
	}
	req.Header.Set("Authorization", c.authorization())
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	timedOut := Error(fmt.Sprintf("provider-unavailable: the organization did not answer within %d seconds", azureDevOpsSeconds))
	response, err := p.client.Do(req)
	if err != nil {
		if databricksTimedOut(err, ctx) {
			return nil, nil, timedOut
		}
		return nil, nil, Error("provider-unavailable: the organization could not be reached")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		raw, _ := io.ReadAll(io.LimitReader(response.Body, azureDevOpsErrorBytes))
		return nil, nil, azureDevOpsRefusal(response.StatusCode, response.Header, raw, secrets)
	}
	tooLarge := Error(fmt.Sprintf("result-too-large: the organization's answer is larger than the connection's bound of %d bytes", bound))
	if response.ContentLength > int64(bound) {
		return nil, nil, tooLarge
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(bound)+1))
	if err != nil {
		if databricksTimedOut(err, ctx) {
			return nil, nil, timedOut
		}
		return nil, nil, Error("provider-unavailable: the organization's answer could not be read")
	}
	if len(raw) > bound {
		return nil, nil, tooLarge
	}
	if !json.Valid(raw) {
		return nil, nil, Error("provider-unavailable: the organization's answer is not JSON")
	}
	return response, raw, nil
}

// azureDevOpsRepeats is an answer that spells the credential, as written or
// in escapes: nothing of it is read or kept.
const azureDevOpsRepeats = Error("provider-unavailable: the organization's answer repeats the credential, and is not kept")

// azureDevOpsOutward is an error the connection reports, held once more
// against the credential as a whole sentence: each whole secret replaced,
// and a sentence that would still spell one, once its escapes are decoded,
// not reported.
func azureDevOpsOutward(err error, secrets []string) error {
	text, ok := databricksScreened(err.Error(), secrets)
	switch {
	case !ok:
		return Error("provider-unavailable: the organization's refusal would repeat the credential, and is not reported")
	case text != err.Error():
		return Error(text)
	}
	return err
}

// check holds a request to its read's form: the members the read takes, each
// of its form, and none of another read's. The ids bound is held here, before
// anything is sent.
func (q AzureDevOpsRequest) check() (AzureDevOpsRequest, error) {
	given := map[string]bool{
		"query": q.Query != "", "id": q.ID != 0, "ids": q.IDs != nil, "fields": q.Fields != nil, "top": q.Top != 0, "skip": q.Skip != 0, "cursor": q.Cursor != "",
		"repository": q.Repository != "", "path": q.Path != "", "recursion": q.Recursion != "", "version": q.Version != "", "versionType": q.VersionType != "",
		"status": q.Status != "", "pipeline": q.Pipeline != 0, "run": q.Run != 0,
	}
	takes := map[string]string{
		"workitems.query":         "query top",
		"workitems.get":           "id ids fields",
		"workitems.query-and-get": "query top fields",
		"repos.list":              "",
		"repos.items":             "repository path recursion version versionType",
		"repos.commits":           "repository top skip path version versionType",
		"pullrequests.list":       "repository top skip status",
		"pipelines.list":          "top cursor",
		"pipelines.runs":          "pipeline",
		"pipelines.run":           "pipeline run",
	}
	members, ok := takes[q.Read]
	if !ok {
		return q, ErrRequest
	}
	allowed := map[string]bool{}
	for _, name := range strings.Fields(members) {
		allowed[name] = true
	}
	for name, present := range given {
		if present && !allowed[name] {
			return q, ErrRequest
		}
	}
	page := func(fallback, most int) bool {
		if q.Top == 0 {
			q.Top = fallback
		}
		return q.Top >= 1 && q.Top <= most && q.Skip >= 0 && q.Skip <= math.MaxInt32
	}
	fields := func() bool {
		if len(q.Fields) > azureDevOpsMaxFields {
			return false
		}
		seen := map[string]bool{}
		for _, field := range q.Fields {
			if len(field) > 256 || !azureDevOpsField.MatchString(field) || seen[strings.ToLower(field)] {
				return false
			}
			seen[strings.ToLower(field)] = true
		}
		return true
	}
	version := func() bool {
		if q.Version == "" {
			return q.VersionType == ""
		}
		if q.VersionType == "" {
			q.VersionType = "branch"
		}
		switch q.VersionType {
		case "branch", "tag":
			return azureDevOpsRef(q.Version)
		case "commit":
			return azureDevOpsCommit.MatchString(q.Version)
		}
		return false
	}
	id := func(n int64) bool { return n >= 1 && n <= math.MaxInt32 }
	ok = true
	switch q.Read {
	case "workitems.query":
		ok = azureDevOpsQueryText(q.Query) && page(azureDevOpsDefaultTop, AzureDevOpsMaxTop)
	case "workitems.query-and-get":
		ok = azureDevOpsQueryText(q.Query) && page(AzureDevOpsMaxIDs, AzureDevOpsMaxIDs) && fields()
	case "workitems.get":
		if (q.ID != 0) == (q.IDs != nil) || q.ID != 0 && !id(q.ID) || !fields() {
			return q, ErrRequest
		}
		if q.IDs != nil && (len(q.IDs) == 0 || !azureDevOpsWithinBound(len(q.IDs), AzureDevOpsMaxIDs)) {
			if len(q.IDs) > 0 {
				return q, Error(fmt.Sprintf("ids-bound-exceeded: a read takes at most %d work items, as one request reads them; nothing was sent", AzureDevOpsMaxIDs))
			}
			return q, ErrRequest
		}
		seen := map[int64]bool{}
		for _, n := range q.IDs {
			if !id(n) || seen[n] {
				return q, ErrRequest
			}
			seen[n] = true
		}
	case "repos.items":
		if q.Path == "" {
			q.Path = "/"
		}
		if q.Recursion == "" {
			q.Recursion = "oneLevel"
		}
		ok = azureDevOpsName(q.Repository, azureDevOpsRepositoryForbidden) && azureDevOpsPath(q.Path) && (q.Recursion == "none" || q.Recursion == "oneLevel" || q.Recursion == "full") && version()
	case "repos.commits":
		ok = azureDevOpsName(q.Repository, azureDevOpsRepositoryForbidden) && page(azureDevOpsDefaultPage, AzureDevOpsMaxPage) && (q.Path == "" || azureDevOpsPath(q.Path)) && version()
	case "pullrequests.list":
		ok = azureDevOpsName(q.Repository, azureDevOpsRepositoryForbidden) && page(azureDevOpsDefaultPage, AzureDevOpsMaxPage) && (q.Status == "" || q.Status == "active" || q.Status == "abandoned" || q.Status == "completed" || q.Status == "all")
	case "pipelines.list":
		ok = page(azureDevOpsDefaultPage, AzureDevOpsMaxPage) && (q.Cursor == "" || databricksPrintable(q.Cursor, 1, 4096))
	case "pipelines.runs":
		ok = id(q.Pipeline)
	case "pipelines.run":
		ok = id(q.Pipeline) && id(q.Run)
	}
	if !ok {
		return q, ErrRequest
	}
	return q, nil
}

// carries reports whether anything the request would send spells a secret:
// its query, a field, the repository, a path, a version, a status or the
// cursor, as written or once its escapes are decoded.
func (q AzureDevOpsRequest) carries(secrets []string) bool {
	texts := append([]string{q.Read, q.Query, q.Cursor, q.Repository, q.Path, q.Recursion, q.Version, q.VersionType, q.Status}, q.Fields...)
	for _, text := range texts {
		if databricksSpells(text, secrets) {
			return true
		}
	}
	return false
}

// azureDevOpsCall is one request of a read: its method, its endpoint (the
// organization URL and the path), its query as sent, and its body.
type azureDevOpsCall struct {
	method, endpoint string
	query            map[string]string
	body             []byte
}

// target is the request's URL: the endpoint and its query, each name as the
// API writes it ($top, searchCriteria.$top) and each value escaped.
func (k azureDevOpsCall) target() string {
	names := make([]string, 0, len(k.query))
	for name := range k.query {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+"="+strings.ReplaceAll(url.QueryEscape(k.query[name]), "%2C", ","))
	}
	return k.endpoint + "?" + strings.Join(parts, "&")
}

// carries reports whether the request as it would be sent -- its body and
// its URL -- carries a secret.
func (k azureDevOpsCall) carries(secrets []string) bool {
	return k.body != nil && databricksCarries(k.body, secrets) || databricksLeaks([]byte(k.target()), secrets)
}

func azureDevOpsJoin(ids []int64) string {
	out := make([]string, len(ids))
	for i, n := range ids {
		out[i] = strconv.FormatInt(n, 10)
	}
	return strings.Join(out, ",")
}

// call is the one request a read makes; for workitems.query-and-get, its
// first, the query.
func (q AzureDevOpsRequest) call(c AzureDevOpsConnection) (azureDevOpsCall, error) {
	base := c.Organization + "/" + url.PathEscape(c.Project) + "/_apis/"
	k := azureDevOpsCall{method: "GET", query: map[string]string{"api-version": AzureDevOpsAPIVersion}}
	repository := url.PathEscape(q.Repository)
	versioned := func(prefix string) {
		if q.Version != "" {
			k.query[prefix+".version"], k.query[prefix+".versionType"] = q.Version, q.VersionType
		}
	}
	switch q.Read {
	case "workitems.query", "workitems.query-and-get":
		body, err := canon.EncodeJSON(map[string]string{"query": q.Query})
		if err != nil {
			return k, ErrRequest
		}
		k.method, k.endpoint, k.body = "POST", base+"wit/wiql", body
		k.query["$top"] = strconv.Itoa(q.Top)
	case "workitems.get":
		k.endpoint = base + "wit/workitems"
		if q.ID != 0 {
			k.endpoint += "/" + strconv.FormatInt(q.ID, 10)
		} else {
			k.query["ids"] = azureDevOpsJoin(q.IDs)
		}
		if len(q.Fields) > 0 {
			k.query["fields"] = strings.Join(q.Fields, ",")
		}
	case "repos.list":
		k.endpoint = base + "git/repositories"
	case "repos.items":
		k.endpoint = base + "git/repositories/" + repository + "/items"
		k.query["scopePath"], k.query["recursionLevel"], k.query["$format"] = q.Path, q.Recursion, "json"
		versioned("versionDescriptor")
	case "repos.commits":
		k.endpoint = base + "git/repositories/" + repository + "/commits"
		k.query["searchCriteria.$top"], k.query["searchCriteria.$skip"] = strconv.Itoa(q.Top), strconv.Itoa(q.Skip)
		if q.Path != "" {
			k.query["searchCriteria.itemPath"] = q.Path
		}
		versioned("searchCriteria.itemVersion")
	case "pullrequests.list":
		k.endpoint = base + "git/repositories/" + repository + "/pullrequests"
		k.query["$top"], k.query["$skip"] = strconv.Itoa(q.Top), strconv.Itoa(q.Skip)
		if q.Status != "" {
			k.query["searchCriteria.status"] = q.Status
		}
	case "pipelines.list":
		k.endpoint = base + "pipelines"
		k.query["$top"] = strconv.Itoa(q.Top)
		if q.Cursor != "" {
			k.query["continuationToken"] = q.Cursor
		}
	case "pipelines.runs":
		k.endpoint = base + "pipelines/" + strconv.FormatInt(q.Pipeline, 10) + "/runs"
	case "pipelines.run":
		k.endpoint = base + "pipelines/" + strconv.FormatInt(q.Pipeline, 10) + "/runs/" + strconv.FormatInt(q.Run, 10)
	default:
		return k, ErrRequest
	}
	return k, nil
}

// azureDevOpsQueryIDs reads a query's answer for the ids of the work items it
// returned, by the exact names of the members it is decided by --
// queryResultType, workItems, workItemRelations and each item's id -- an
// answer that also names one of them in another case, or twice, refused. A
// query of links (a tree or one hop) is refused: its items are not a list of
// ids. The ids are in the order the answer gives them.
func azureDevOpsQueryIDs(raw []byte) ([]int64, error) {
	malformed := Error("provider-unavailable: the organization's query answer is not of the form this connection reads, or names a member it reads in another case or twice")
	if _, err := canon.Canonicalize(raw, canon.CarryNumbersAsText); err != nil || !canon.IsObject(raw) {
		return nil, malformed
	}
	top, ok := databricksMembers(raw, "queryResultType", "workItems", "workItemRelations")
	if !ok {
		return nil, malformed
	}
	var kind string
	var relations, items []json.RawMessage
	hasKind, okKind := databricksField(top, "queryResultType", &kind)
	hasRelations, okRelations := databricksField(top, "workItemRelations", &relations)
	_, okItems := databricksField(top, "workItems", &items)
	if !okKind || !okRelations || !okItems {
		return nil, malformed
	}
	if hasKind && kind != "workItem" || hasRelations {
		return nil, Error("query-not-flat: the query answered links between work items, not a list of them; a query-and-get reads a flat query's items")
	}
	ids := []int64{}
	seen := map[int64]bool{}
	for _, item := range items {
		members, ok := databricksMembers(item, "id")
		var n int64
		present, okID := databricksField(members, "id", &n)
		if !ok || !canon.IsObject(item) || !present || !okID || n < 1 || n > math.MaxInt32 || seen[n] {
			return nil, malformed
		}
		seen[n] = true
		ids = append(ids, n)
	}
	return ids, nil
}

// azureDevOpsItemsAnswer holds the second answer of a query-and-get to the
// ids asked for: its items, read by the exact names value and id, each one
// asked for and none twice.
func azureDevOpsItemsAnswer(raw []byte, asked []int64) error {
	malformed := Error("provider-unavailable: the organization's work items answer is not of the form this connection reads, names a member it reads in another case or twice, or names an item that was not asked for")
	if _, err := canon.Canonicalize(raw, canon.CarryNumbersAsText); err != nil || !canon.IsObject(raw) {
		return malformed
	}
	top, ok := databricksMembers(raw, "value")
	var items []json.RawMessage
	present, okItems := databricksField(top, "value", &items)
	if !ok || !present || !okItems {
		return malformed
	}
	wanted := map[int64]bool{}
	for _, n := range asked {
		wanted[n] = true
	}
	for _, item := range items {
		members, ok := databricksMembers(item, "id")
		var n int64
		present, okID := databricksField(members, "id", &n)
		if !ok || !canon.IsObject(item) || !present || !okID || !wanted[n] {
			return malformed
		}
		delete(wanted, n)
	}
	return nil
}

// azureDevOpsContinuation is the continuation token a pipelines page answers
// with in its x-ms-continuationtoken header: one value, of a cursor's form,
// or none.
func azureDevOpsContinuation(header http.Header) (any, error) {
	values := header.Values("X-Ms-Continuationtoken")
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) > 1 || !databricksPrintable(values[0], 1, 4096) {
		return nil, Error("provider-unavailable: the organization's continuation token is not of the form a cursor takes")
	}
	return values[0], nil
}

func ReadAzureDevOps(ctx context.Context, s *Store, raw []byte) ([]byte, error) {
	var q AzureDevOpsRequest
	if decode(raw, &q) != nil {
		return nil, ErrRequest
	}
	return azureDevOpsAcquire(ctx, s, q, azureDevOpsProvider())
}

// azureDevOpsAcquire is one read. The request is held to its form and
// screened for the credential before anything is sent; every answer is
// screened for it, as written and as decoded, before anything of it is read.
// The envelope's result is the API's answer as received, carried into the
// canon domain (a number outside it as its literal text): for
// pipelines.list with the continuation token the page answered, and for
// workitems.query-and-get the query's answer, whose ids are those read, and
// the items' answer. Its acquisition names the endpoint of the answer the
// snapshot digests, the request as the statement the gateway commits to, and
// the TLS peer the answer came from. Every error is screened once more on its
// way out.
func azureDevOpsAcquire(ctx context.Context, s *Store, q AzureDevOpsRequest, p provider) (out []byte, err error) {
	c, err := azureDevOpsSnapshot(s, q.Connection, q.Revision)
	if err != nil {
		return nil, err
	}
	secrets := c.secrets()
	defer func() {
		if err != nil {
			out, err = nil, azureDevOpsOutward(err, secrets)
		}
	}()
	if q, err = q.check(); err != nil {
		return nil, err
	}
	if c.expired() {
		return nil, azureDevOpsExpired
	}
	first, err := q.call(c)
	if err != nil {
		return nil, err
	}
	if q.carries(secrets) || first.carries(secrets) {
		return nil, azureDevOpsInRequest
	}
	record := map[string]any{"connection": c.ID, "revision": c.Revision, "provider": "azure-devops", "project": c.Project, "read": q.Read, "method": first.method, "endpoint": first.endpoint, "query": first.query}
	if first.body != nil {
		record["body"] = json.RawMessage(first.body)
	}
	bound := c.resultBound()
	response, data, err := p.azureDevOpsSend(ctx, c, first.method, first.target(), first.body, bound, secrets)
	if err != nil {
		return nil, err
	}
	if databricksCarries(data, secrets) {
		return nil, azureDevOpsRepeats
	}
	// A query-and-get's ids are read from the query's answer as received.
	var ids []int64
	if q.Read == "workitems.query-and-get" {
		if ids, err = azureDevOpsQueryIDs(data); err != nil {
			return nil, err
		}
	}
	observed := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	answer, err := canon.Canonicalize(data, canon.CarryNumbersAsText)
	if err != nil {
		return nil, Error("provider-unavailable: the organization's answer is JSON outside the canonical domain")
	}
	endpoint, snapshot, peerIdentity := first.endpoint, digest(data), peer(response)
	result := json.RawMessage(answer)
	switch q.Read {
	case "pipelines.list":
		token, err := azureDevOpsContinuation(response.Header)
		if err != nil {
			return nil, err
		}
		if token != nil && databricksSpells(token.(string), secrets) {
			return nil, azureDevOpsRepeats
		}
		encoded, err := canon.EncodeJSON(map[string]any{"pipelines": json.RawMessage(answer), "continuationToken": token})
		if err != nil {
			return nil, ErrProvider
		}
		result = encoded
	case "workitems.query-and-get":
		if !azureDevOpsWithinBound(len(ids), q.Top) {
			return nil, Error(fmt.Sprintf("ids-bound-exceeded: the query answered %d work items, more than the %d this read takes in one request; the items were not read", len(ids), q.Top))
		}
		then := map[string]any{"method": "GET", "endpoint": c.Organization + "/" + url.PathEscape(c.Project) + "/_apis/wit/workitems", "fields": q.Fields}
		if q.Fields == nil {
			then["fields"] = []string{}
		}
		record["then"] = then
		var items any
		if len(ids) > 0 {
			second := azureDevOpsCall{method: "GET", endpoint: then["endpoint"].(string), query: map[string]string{"api-version": AzureDevOpsAPIVersion, "ids": azureDevOpsJoin(ids)}}
			if len(q.Fields) > 0 {
				second.query["fields"] = strings.Join(q.Fields, ",")
			}
			if second.carries(secrets) {
				return nil, azureDevOpsInRequest
			}
			response, data, err := p.azureDevOpsSend(ctx, c, second.method, second.target(), nil, bound, secrets)
			if err != nil {
				return nil, err
			}
			if databricksCarries(data, secrets) {
				return nil, azureDevOpsRepeats
			}
			if err = azureDevOpsItemsAnswer(data, ids); err != nil {
				return nil, err
			}
			// Both answers came from one organization under one TLS
			// identity, or neither is kept.
			if peer(response) != peerIdentity {
				return nil, Error("provider-unavailable: the organization's two answers came under different TLS identities, and neither is kept")
			}
			kept, err := canon.Canonicalize(data, canon.CarryNumbersAsText)
			if err != nil {
				return nil, Error("provider-unavailable: the organization's answer is JSON outside the canonical domain")
			}
			observed = time.Now().UTC().Format("2006-01-02T15:04:05Z")
			endpoint, snapshot, items = second.endpoint, digest(data), json.RawMessage(kept)
		}
		encoded, err := canon.EncodeJSON(map[string]any{"query": json.RawMessage(answer), "items": items})
		if err != nil {
			return nil, ErrProvider
		}
		result = encoded
	}
	if err = azureDevOpsCurrent(s, c); err != nil {
		return nil, err
	}
	identity, err := document.OwnIdentity()
	if err != nil {
		return nil, ErrProvider
	}
	identity.Name = "adapter-sources"
	encoded, err := canon.EncodeJSON(record)
	if err != nil {
		return nil, ErrRequest
	}
	statement, err := canon.Canonicalize(encoded, canon.RefuseNumbers)
	if err != nil {
		return nil, ErrRequest
	}
	acquisition := map[string]any{"adapter": identity, "endpoint": endpoint, "statement": string(statement), "snapshot": snapshot, "peerIdentity": peerIdentity, "schema": nil, "upstreamToken": nil, "observedAt": observed}
	out, err = canon.EncodeJSON(map[string]any{"acquisition": acquisition, "result": result})
	if err != nil {
		return nil, ErrProvider
	}
	if len(out) > MaxOutputBytes {
		return nil, Error(fmt.Sprintf("result-too-large: the envelope is larger than the source's output bound of %d bytes", MaxOutputBytes))
	}
	if databricksCarries(out, secrets) {
		return nil, Error("provider-unavailable: the record would carry the credential, and is not written")
	}
	return out, nil
}

// azureDevOpsTestQuery is the test's query: the project's work items, of
// which one at most is answered.
const azureDevOpsTestQuery = "SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = @project"

// azureDevOpsTest is a connection test: one query for at most one work item
// of the project, and nothing of its answer kept.
func azureDevOpsTest(ctx context.Context, s *Store, id, revision string, p provider) (err error) {
	c, err := azureDevOpsSnapshot(s, id, revision)
	if err != nil {
		return err
	}
	secrets := c.secrets()
	defer func() {
		if err != nil {
			err = azureDevOpsOutward(err, secrets)
		}
	}()
	if c.expired() {
		return azureDevOpsExpired
	}
	k, err := AzureDevOpsRequest{Read: "workitems.query", Query: azureDevOpsTestQuery, Top: 1}.call(c)
	if err != nil {
		return err
	}
	_, _, err = p.azureDevOpsSend(ctx, c, k.method, k.target(), k.body, 1<<20, secrets)
	return err
}
