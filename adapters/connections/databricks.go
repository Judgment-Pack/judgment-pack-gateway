package connections

// Databricks has its own custody namespace and control protocol, as the
// search connections have: up to six named connections, each to one
// workspace's REST API under a personal access token or a service
// principal. A read is one bounded request, a SQL statement on the
// connection's warehouse or one page of a Unity Catalog listing, and its
// result is the API's answer as received. What the identity may read, and
// whether a statement may change data, is the workspace's grants on that
// identity; nothing here holds a statement to reading.
import (
	"adapters/document"
	"adapters/internal/canon"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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
	DatabricksDefaultWaitSeconds = 30
	DatabricksMinWaitSeconds     = 5
	DatabricksMaxWaitSeconds     = 50
	// DatabricksMaxResultBytes leaves the envelope room under the source's
	// output bound (MaxOutputBytes), and is below the API's own inline
	// bound of 25 MiB, past which the workspace aborts the statement.
	DatabricksDefaultResultBytes = 8 << 20
	DatabricksMinResultBytes     = 64 << 10
	DatabricksMaxResultBytes     = 15 << 20
	databricksStatementBytes     = 32 << 10
	databricksConnections        = 6
	databricksDefaultScope       = "all-apis"
	// A minted token within this of its expiry is not used, and is not kept.
	databricksTokenSlack = time.Minute
	// databricksMintSeconds bounds the token request; databricksListSeconds
	// a catalog page and a connection test; a statement has its wait and
	// databricksMarginSeconds more, for the answer to arrive.
	databricksMintSeconds   = 15
	databricksListSeconds   = 30
	databricksMarginSeconds = 4
	databricksErrorBytes    = 64 << 10
	databricksMessageBytes  = 4096
)

// DatabricksConnection is what configure takes and custody holds. Its
// member names are the setup fields' keys, and its values are text, as a
// form sends them.
type DatabricksConnection struct {
	ID           string `json:"id"`
	Revision     string `json:"revision"`
	Name         string `json:"name"`
	Workspace    string `json:"workspace-url"`
	Warehouse    string `json:"warehouse-id"`
	Auth         string `json:"auth"`
	Token        string `json:"token,omitempty"`
	ClientID     string `json:"client-id,omitempty"`
	ClientSecret string `json:"client-secret,omitempty"`
	Scope        string `json:"scope,omitempty"`
	Catalog      string `json:"catalog,omitempty"`
	Schema       string `json:"schema,omitempty"`
	WaitSeconds  string `json:"wait-seconds,omitempty"`
	ResultBytes  string `json:"max-result-bytes,omitempty"`
}

// databricksToken is an access token minted for a service principal, held
// with its expiry and the revision of the connection it was minted under.
type databricksToken struct {
	Connection string `json:"connection"`
	Revision   string `json:"revision"`
	Access     string `json:"access"`
	Expires    int64  `json:"expires"`
}
type databricksState struct {
	Connections []DatabricksConnection `json:"connections"`
	Tokens      []databricksToken      `json:"tokens,omitempty"`
}

// databricksRow is a connection as status reports it: never a secret.
type databricksRow struct {
	DatabricksConnection
	Ready bool `json:"ready"`
}

// DatabricksRequest is what adapter-sources --provider databricks reads.
type DatabricksRequest struct {
	Connection string                `json:"connection"`
	Revision   string                `json:"revision"`
	Read       string                `json:"read"`
	Statement  string                `json:"statement,omitempty"`
	Parameters []DatabricksParameter `json:"parameters,omitempty"`
	List       string                `json:"list,omitempty"`
	Catalog    string                `json:"catalog,omitempty"`
	Schema     string                `json:"schema,omitempty"`
	PageToken  string                `json:"pageToken,omitempty"`
	MaxResults int                   `json:"maxResults,omitempty"`
}

// DatabricksParameter is a named parameter marker's value, sent as the
// API's parameter form; a value left out is SQL NULL.
type DatabricksParameter struct {
	Name  string  `json:"name"`
	Value *string `json:"value,omitempty"`
	Type  string  `json:"type,omitempty"`
}

var databricksLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
var databricksWarehouse = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)
var databricksClientID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var databricksScopeName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
var databricksParameterName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,254}$`)
var databricksParameterType = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_(), ]{0,63}$`)
var databricksStatementID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var databricksErrorCode = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`)
var databricksRetrySeconds = regexp.MustCompile(`^[0-9]{1,9}$`)
var databricksRetryDelay = regexp.MustCompile(`^[0-9]{1,9}(\.[0-9]{1,9})?s$`)

// databricksDomains are the domains a workspace's own host name is under:
// on AWS, AWS GovCloud and its DoD environment, on Google Cloud, and on
// Azure.
var databricksDomains = []string{".cloud.databricks.com", ".cloud.databricks.us", ".cloud.databricks.mil", ".gcp.databricks.com", ".azuredatabricks.net"}

// databricksLists are the Unity Catalog listings a read may ask for, with
// the most a page may hold, as the API states it.
var databricksLists = map[string]int{"catalogs": 1000, "schemas": 1000, "tables": 50, "functions": 1000}

// DatabricksWorkspace holds a workspace URL to its form: https, a host
// under a workspace domain of one to three labels, none of them the
// account console's, and nothing else -- no user information, no port,
// no path but an empty one, no query, no fragment, no trailing dot, no IP
// literal. It returns the URL without a trailing slash.
func DatabricksWorkspace(raw string) (string, bool) {
	rest, ok := strings.CutPrefix(raw, "https://")
	if !ok || len(raw) > 300 {
		return "", false
	}
	host := strings.TrimSuffix(rest, "/")
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/?#@:[]%\\") {
		return "", false
	}
	name := ""
	for _, domain := range databricksDomains {
		if strings.HasSuffix(host, domain) {
			name = strings.TrimSuffix(host, domain)
			break
		}
	}
	labels := strings.Split(name, ".")
	if name == "" || len(labels) > 3 || labels[0] == "accounts" || labels[0] == "accounts-dod" {
		return "", false
	}
	for _, label := range labels {
		if !databricksLabel.MatchString(label) || strings.HasPrefix(label, "xn--") {
			return "", false
		}
	}
	u, err := url.Parse("https://" + host)
	if err != nil || u.Host != host || u.Hostname() != host || u.Port() != "" || u.User != nil {
		return "", false
	}
	return "https://" + host, true
}

// databricksPrintable is low to high bytes of printable ASCII, no space:
// a secret, a token or a page token.
func databricksPrintable(s string, low, high int) bool {
	if len(s) < low || len(s) > high {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// databricksName is a Unity Catalog name: at most 255 bytes, without a
// period, a space, a slash or a control character.
func databricksName(s string) bool {
	return resourceText(s, 255, false) && !strings.ContainsAny(s, ". /")
}

// databricksText is a statement or a parameter's value: UTF-8, within the
// bound, with no control character but a tab or a line's end.
func databricksText(s string, max int) bool {
	if !utf8.ValidString(s) || len(s) > max {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
			return false
		}
	}
	return true
}

// databricksNumber reads a whole number a form sent as text: empty is the
// default; anything but digits, or a number outside the bounds, is -1.
func databricksNumber(s string, fallback, low, high int) int {
	if s == "" {
		return fallback
	}
	if len(s) > 9 || s[0] == '0' {
		return -1
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < low || n > high {
		return -1
	}
	return n
}
func (c DatabricksConnection) wait() int {
	return databricksNumber(c.WaitSeconds, DatabricksDefaultWaitSeconds, DatabricksMinWaitSeconds, DatabricksMaxWaitSeconds)
}
func (c DatabricksConnection) resultBound() int {
	return databricksNumber(c.ResultBytes, DatabricksDefaultResultBytes, DatabricksMinResultBytes, DatabricksMaxResultBytes)
}
func (c DatabricksConnection) scope() string {
	if c.Scope == "" {
		return databricksDefaultScope
	}
	return c.Scope
}
func databricksScopeValid(scope string) bool {
	if scope == "" {
		return true
	}
	names := strings.Split(scope, " ")
	if len(scope) > 512 || len(names) > 16 {
		return false
	}
	seen := map[string]bool{}
	for _, name := range names {
		if !databricksScopeName.MatchString(name) || seen[name] {
			return false
		}
		seen[name] = true
	}
	return true
}
func (c DatabricksConnection) valid() bool {
	if !searchID.MatchString(c.ID) || !resourceText(c.Name, 80, false) || !databricksWarehouse.MatchString(c.Warehouse) || c.wait() < 0 || c.resultBound() < 0 {
		return false
	}
	if workspace, ok := DatabricksWorkspace(c.Workspace); !ok || workspace != c.Workspace {
		return false
	}
	if c.Catalog != "" && !databricksName(c.Catalog) || c.Schema != "" && !databricksName(c.Schema) || c.Schema != "" && c.Catalog == "" {
		return false
	}
	switch c.Auth {
	case "token":
		return databricksPrintable(c.Token, 8, 4096) && c.ClientID == "" && c.ClientSecret == "" && c.Scope == ""
	case "service-principal":
		return c.Token == "" && databricksClientID.MatchString(c.ClientID) && databricksPrintable(c.ClientSecret, 8, 1024) && databricksScopeValid(c.Scope)
	}
	return false
}

// secrets are what is never written into a record, an error or a status:
// the configured secret and, for a service principal, the token in use.
func (c DatabricksConnection) secrets(bearer string) []string {
	out := []string{}
	for _, s := range []string{c.Token, c.ClientSecret, bearer} {
		if s != "" {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// databricksRedact replaces every whole secret in text, longest first.
func databricksRedact(text string, secrets []string) string {
	for _, s := range secrets {
		if s != "" {
			text = strings.ReplaceAll(text, s, "[redacted]")
		}
	}
	return text
}
func databricksLeaks(raw []byte, secrets []string) bool {
	for _, s := range secrets {
		if s != "" && bytes.Contains(raw, []byte(s)) {
			return true
		}
	}
	return false
}

func databricksDescriptor() Descriptor {
	return Descriptor{"databricks", "client-credentials", "form", "none", true, []string{"status", "configure", "disconnect", "test"}}
}

// databricksSetup is each setup field's key, whether it is a secret, and
// whether a form must fill it.
var databricksSetup = []struct {
	key      string
	secret   bool
	required bool
}{
	{"workspace-url", false, true}, {"warehouse-id", false, true}, {"auth", false, true},
	{"token", true, false}, {"client-id", false, false}, {"client-secret", true, false}, {"scope", false, false},
	{"catalog", false, false}, {"schema", false, false}, {"wait-seconds", false, false}, {"max-result-bytes", false, false},
}

func databricksCatalog(p map[string]Presentation) ProviderDescriptor {
	d := ProviderDescriptor{Descriptor: databricksDescriptor(), Protocol: "databricks-v1", QueryMode: "text", Presentation: p["databricks"], Setup: []SetupField{}, AuthorizationEndpoints: []string{}, Source: SourceContract{"databricks", "http", "databricks-api-v1"}}
	for _, field := range databricksSetup {
		kind := "text"
		if field.secret {
			kind = "password"
		}
		d.Setup = append(d.Setup, SetupField{field.key, kind, p["databricks-"+field.key].Description, field.required})
	}
	return d
}
func OpenDatabricksStore(dir, principal string) (*Store, error) {
	root, err := OpenStore(dir, principal)
	if err != nil {
		return nil, err
	}
	root.Close()
	return OpenStore(filepath.Join(dir, "databricks"), principal)
}
func NewDatabricks(s *Store, disabled bool) *Broker {
	return &Broker{store: s, provider: databricksProvider(), disabled: disabled}
}

// databricksProvider is the Google transport without its header cutoff: a
// statement's answer may come only when its wait has passed. Each request
// has a deadline of its own; no redirect is followed and no proxy used.
func databricksProvider() provider {
	p := google()
	p.databricks = true
	p.auth, p.token, p.revoke, p.api = "", "", "", ""
	p.client.Transport.(*http.Transport).ResponseHeaderTimeout = 0
	p.client.Timeout = (DatabricksMaxWaitSeconds + databricksMarginSeconds + databricksMintSeconds) * time.Second
	return p
}

func (b *Broker) databricksOperation(ctx context.Context, method string, raw []byte) (any, error) {
	switch method {
	case "status":
		var q struct{}
		if decode(raw, &q) != nil {
			return nil, ErrRequest
		}
		rows := []databricksRow{}
		err := b.store.locked(func(v *state) error {
			if v.Databricks != nil {
				for _, c := range v.Databricks.Connections {
					ready := c.valid()
					c.Token, c.ClientSecret = "", ""
					rows = append(rows, databricksRow{c, ready})
				}
			}
			return nil
		})
		limits := map[string]int{
			"defaultWaitSeconds": DatabricksDefaultWaitSeconds, "minWaitSeconds": DatabricksMinWaitSeconds, "maxWaitSeconds": DatabricksMaxWaitSeconds,
			"defaultResultBytes": DatabricksDefaultResultBytes, "minResultBytes": DatabricksMinResultBytes, "maxResultBytes": DatabricksMaxResultBytes,
		}
		return map[string]any{"version": 1, "provider": "databricks", "connections": rows, "limits": limits}, err
	case "configure":
		var q DatabricksConnection
		if decode(raw, &q) != nil {
			return nil, ErrRequest
		}
		if workspace, ok := DatabricksWorkspace(q.Workspace); ok {
			q.Workspace = workspace
		}
		err := b.store.locked(func(v *state) error {
			if v.Databricks == nil {
				v.Databricks = &databricksState{Connections: []DatabricksConnection{}}
			}
			index := -1
			for i, c := range v.Databricks.Connections {
				if c.ID != q.ID {
					continue
				}
				index = i
				if c.Revision != q.Revision {
					return ErrChanged
				}
				// A blank secret keeps the saved one only where it would be
				// sent to the same workspace for the same identity.
				if q.Auth == c.Auth && q.Workspace == c.Workspace && q.ClientID == c.ClientID {
					if q.Auth == "token" && q.Token == "" {
						q.Token = c.Token
					}
					if q.Auth == "service-principal" && q.ClientSecret == "" {
						q.ClientSecret = c.ClientSecret
					}
				}
			}
			if index < 0 && (q.Revision != "" || len(v.Databricks.Connections) >= databricksConnections) {
				return ErrRequest
			}
			if !q.valid() {
				return ErrRequest
			}
			q.Revision = randomID()
			if index < 0 {
				v.Databricks.Connections = append(v.Databricks.Connections, q)
			} else {
				v.Databricks.Connections[index] = q
			}
			v.Databricks.Tokens = databricksWithout(v.Databricks.Tokens, q.ID)
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
			if v.Databricks == nil {
				return ErrChanged
			}
			for i, c := range v.Databricks.Connections {
				if c.ID == q.ID && c.Revision == q.Revision {
					v.Databricks.Connections = append(v.Databricks.Connections[:i], v.Databricks.Connections[i+1:]...)
					v.Databricks.Tokens = databricksWithout(v.Databricks.Tokens, q.ID)
					return b.store.write("state.json", v)
				}
			}
			return ErrChanged
		})
		// Deleting local custody revokes nothing at the workspace.
		return map[string]bool{"disconnected": err == nil, "revoked": false}, err
	case "test":
		var q struct {
			ID       string `json:"id"`
			Revision string `json:"revision"`
		}
		if decode(raw, &q) != nil {
			return nil, ErrRequest
		}
		// An explicit action: one request, the first catalog of the
		// listing, whose content is never returned. It starts no warehouse.
		err := databricksTest(ctx, b.store, q.ID, q.Revision, b.provider)
		return map[string]bool{"ok": err == nil}, err
	}
	return nil, ErrRequest
}
func databricksWithout(tokens []databricksToken, id string) []databricksToken {
	out := []databricksToken{}
	for _, t := range tokens {
		if t.Connection != id {
			out = append(out, t)
		}
	}
	return out
}

// databricksSnapshot is the connection a request names, as it stands.
func databricksSnapshot(s *Store, id, revision string) (DatabricksConnection, error) {
	var found DatabricksConnection
	if !searchID.MatchString(id) || !opaque.MatchString(revision) {
		return found, ErrRequest
	}
	err := s.locked(func(v *state) error {
		if v.Disabled {
			return ErrPolicy
		}
		if v.Databricks == nil {
			return ErrConnect
		}
		for _, c := range v.Databricks.Connections {
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
func databricksIsCurrent(v *state, c DatabricksConnection) bool {
	if v.Databricks == nil {
		return false
	}
	for _, p := range v.Databricks.Connections {
		if p.ID == c.ID && p.Revision == c.Revision {
			return true
		}
	}
	return false
}

// databricksCurrent refuses an answer to a connection that was changed,
// removed or blocked while it was asked.
func databricksCurrent(s *Store, c DatabricksConnection) error {
	return s.locked(func(v *state) error {
		if v.Disabled {
			return ErrPolicy
		}
		if !databricksIsCurrent(v, c) {
			return ErrChanged
		}
		return nil
	})
}

// databricksBearer is the token a request is sent under: the personal
// access token as configured, or the service principal's access token in
// custody while it is more than a minute from its expiry, and otherwise
// one minted now. A held token that is not so is removed before another is
// asked for, so custody never holds a token past its expiry record.
func (p provider) databricksBearer(ctx context.Context, s *Store, c DatabricksConnection) (string, error) {
	if c.Auth == "token" {
		return c.Token, nil
	}
	var held string
	err := s.locked(func(v *state) error {
		if v.Disabled {
			return ErrPolicy
		}
		if !databricksIsCurrent(v, c) {
			return ErrChanged
		}
		for _, t := range v.Databricks.Tokens {
			if t.Connection != c.ID {
				continue
			}
			if t.Revision == c.Revision && t.Expires > time.Now().Add(databricksTokenSlack).Unix() {
				held = t.Access
				return nil
			}
			v.Databricks.Tokens = databricksWithout(v.Databricks.Tokens, c.ID)
			return s.write("state.json", v)
		}
		return nil
	})
	if err != nil || held != "" {
		return held, err
	}
	access, expires, err := p.databricksMint(ctx, c)
	if err != nil {
		return "", err
	}
	err = s.locked(func(v *state) error {
		if v.Disabled {
			return ErrPolicy
		}
		if !databricksIsCurrent(v, c) {
			return ErrChanged
		}
		v.Databricks.Tokens = append(databricksWithout(v.Databricks.Tokens, c.ID), databricksToken{c.ID, c.Revision, access, expires})
		return s.write("state.json", v)
	})
	if err != nil {
		return "", err
	}
	return access, nil
}

// databricksMint asks the workspace's token endpoint for an access token by
// the client-credentials grant, the client's id and secret as basic
// authentication. A failure names the status and the server's error code
// where it gives one, and nothing it said besides.
func (p provider) databricksMint(ctx context.Context, c DatabricksConnection) (string, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, databricksMintSeconds*time.Second)
	defer cancel()
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {c.scope()}}
	req, err := http.NewRequestWithContext(ctx, "POST", c.Workspace+"/oidc/v1/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, ErrRequest
	}
	req.SetBasicAuth(c.ClientID, c.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	sent := time.Now()
	response, err := p.client.Do(req)
	if err != nil {
		if databricksTimedOut(err, ctx) {
			return "", 0, Error(fmt.Sprintf("token-failed: the workspace's token endpoint did not answer within %d seconds", databricksMintSeconds))
		}
		return "", 0, Error("token-failed: the workspace's token endpoint could not be reached")
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, databricksErrorBytes+1))
	secrets := c.secrets("")
	if response.StatusCode != 200 {
		text := fmt.Sprintf("token-failed: the workspace's token endpoint answered %d", response.StatusCode)
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			text += ", a redirect, which is not followed"
		} else if code := databricksCode(raw, "error", "error_code"); code != "" {
			text += " (" + code + ")"
		}
		return "", 0, Error(databricksRedact(text, secrets))
	}
	var t struct {
		Access  string `json:"access_token"`
		Type    string `json:"token_type"`
		Expires int64  `json:"expires_in"`
	}
	if readErr != nil || len(raw) > databricksErrorBytes || json.Unmarshal(raw, &t) != nil {
		return "", 0, Error("token-failed: the workspace's token endpoint answered 200 with a body that is not a token")
	}
	if !strings.EqualFold(t.Type, "Bearer") || t.Expires <= 0 || t.Expires > 86400 || !databricksPrintable(t.Access, 8, 4096) || databricksLeaks([]byte(t.Access), secrets) {
		return "", 0, Error("token-failed: the workspace's token endpoint answered 200 with a token not of the form asked for")
	}
	return t.Access, sent.Add(time.Duration(t.Expires) * time.Second).Unix(), nil
}

// databricksCode is the first of the named members of a JSON error body
// that holds an error code of the form one has.
func databricksCode(raw []byte, names ...string) string {
	var body map[string]json.RawMessage
	if json.Unmarshal(raw, &body) != nil {
		return ""
	}
	for _, name := range names {
		var code string
		if json.Unmarshal(body[name], &code) == nil && databricksErrorCode.MatchString(code) {
			return code
		}
	}
	return ""
}
func databricksTimedOut(err error, ctx context.Context) bool {
	var timeout net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout() || errors.Is(ctx.Err(), context.DeadlineExceeded)
}

// databricksRetry is how long a 429 asks to wait, as the API says it: the
// Retry-After header, or a RetryInfo detail's retry_delay.
func databricksRetry(header http.Header, raw []byte) string {
	if after := header.Get("Retry-After"); after != "" {
		if databricksRetrySeconds.MatchString(after) {
			return after + " seconds"
		}
		if when, err := http.ParseTime(after); err == nil {
			return "until " + when.UTC().Format(http.TimeFormat)
		}
	}
	var body struct {
		Details []struct {
			Type  string `json:"@type"`
			Delay string `json:"retry_delay"`
		} `json:"details"`
	}
	if json.Unmarshal(raw, &body) == nil {
		for _, d := range body.Details {
			if strings.HasSuffix(d.Type, "RetryInfo") && databricksRetryDelay.MatchString(d.Delay) {
				return strings.TrimSuffix(d.Delay, "s") + " seconds"
			}
		}
	}
	return ""
}

// databricksRefusal is what an answer other than 200 is reported as: its
// status, the API's error code where it gives one, and for a 429 the wait
// it asks for. The API's message is not repeated: it may repeat what was
// sent. Nothing is retried.
func databricksRefusal(status int, header http.Header, raw []byte, secrets []string) error {
	code := databricksCode(raw, "error_code", "error")
	named := fmt.Sprintf("%d", status)
	if code != "" {
		named += " (" + code + ")"
	}
	var text string
	switch {
	case status >= 300 && status < 400:
		text = fmt.Sprintf("provider-unavailable: the workspace answered %d, a redirect, which is not followed", status)
	case status == 401:
		text = "credentials-required: the workspace answered " + named
	case status == 403:
		text = "permission-denied: the workspace answered " + named
	case status == 429:
		text = "rate-limited: the workspace answered " + named
		if wait := databricksRetry(header, raw); wait != "" {
			text += " and asks to wait " + wait + " before another request"
		}
		text += "; it was not retried"
	case status >= 500:
		text = "provider-unavailable: the workspace answered " + named
	default:
		text = "request-refused: the workspace answered " + named
	}
	return Error(databricksRedact(text, secrets))
}

// databricksSend makes the one request of a read and returns the JSON body
// of a 200 within the bound, or the refusal.
func (p provider) databricksSend(ctx context.Context, method, target string, body []byte, bearer string, bound int, secrets []string, seconds int) (*http.Response, []byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, nil, ErrRequest
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := p.client.Do(req)
	if err != nil {
		if databricksTimedOut(err, ctx) {
			return nil, nil, Error(fmt.Sprintf("provider-unavailable: the workspace did not answer within %d seconds", seconds))
		}
		return nil, nil, Error("provider-unavailable: the workspace could not be reached")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		raw, _ := io.ReadAll(io.LimitReader(response.Body, databricksErrorBytes))
		return nil, nil, databricksRefusal(response.StatusCode, response.Header, raw, secrets)
	}
	tooLarge := Error(fmt.Sprintf("result-too-large: the workspace's answer is larger than the connection's bound of %d bytes", bound))
	if response.ContentLength > int64(bound) {
		return nil, nil, tooLarge
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(bound)+1))
	if err != nil {
		if databricksTimedOut(err, ctx) {
			return nil, nil, Error(fmt.Sprintf("provider-unavailable: the workspace did not answer within %d seconds", seconds))
		}
		return nil, nil, Error("provider-unavailable: the workspace's answer could not be read")
	}
	if len(raw) > bound {
		return nil, nil, tooLarge
	}
	if !json.Valid(raw) {
		return nil, nil, Error("provider-unavailable: the workspace's answer is not JSON")
	}
	return response, raw, nil
}

// databricksStatement reads the state of a statement's answer: the
// statement_id of one that succeeded whole, or the refusal.
func databricksStatement(raw []byte, wait int, elapsed time.Duration, secrets []string) (string, error) {
	var a struct {
		ID     string `json:"statement_id"`
		Status struct {
			State string `json:"state"`
			Error *struct {
				Code    string `json:"error_code"`
				Message string `json:"message"`
			} `json:"error"`
		} `json:"status"`
		Manifest *struct {
			Truncated  bool `json:"truncated"`
			ChunkCount *int `json:"total_chunk_count"`
		} `json:"manifest"`
		Result *struct {
			NextIndex *int    `json:"next_chunk_index"`
			NextLink  *string `json:"next_chunk_internal_link"`
		} `json:"result"`
	}
	if json.Unmarshal(raw, &a) != nil || !databricksStatementID.MatchString(a.ID) {
		return "", Error("provider-unavailable: the workspace's answer names no statement")
	}
	message := ""
	if a.Status.Error != nil {
		message = a.Status.Error.Message
		if len(message) > databricksMessageBytes {
			message = clipSearchText(message, databricksMessageBytes) + "…"
		}
		message = databricksRedact(message, secrets)
	}
	switch a.Status.State {
	case "SUCCEEDED":
		if a.Manifest != nil && (a.Manifest.Truncated || a.Manifest.ChunkCount != nil && *a.Manifest.ChunkCount > 1) || a.Result != nil && (a.Result.NextIndex != nil || a.Result.NextLink != nil) {
			return "", Error("result-incomplete: the workspace answered part of the result, in chunks or truncated; the rest is not fetched")
		}
		return a.ID, nil
	case "FAILED":
		if message == "" {
			return "", Error("statement-failed: the statement failed, and the workspace gave no message")
		}
		return "", Error("statement-failed: " + message)
	case "CANCELED":
		if message != "" {
			return "", Error("statement-canceled: " + message)
		}
		if elapsed < time.Duration(wait)*time.Second {
			return "", Error(fmt.Sprintf("statement-canceled: the statement was cancelled in the workspace before %d seconds had passed", wait))
		}
		return "", Error(fmt.Sprintf("statement-timeout: the statement did not finish within %d seconds and was cancelled", wait))
	case "PENDING", "RUNNING":
		return "", Error(fmt.Sprintf("statement-timeout: the statement did not finish within %d seconds; the workspace answered %s, and it is not polled", wait, a.Status.State))
	}
	return "", Error("provider-unavailable: the workspace answered a statement in no state this connection reads")
}

func (q DatabricksRequest) check(c DatabricksConnection) (DatabricksRequest, error) {
	if q.Catalog == "" && q.Schema == "" {
		q.Catalog, q.Schema = c.Catalog, c.Schema
	}
	if q.Catalog != "" && !databricksName(q.Catalog) || q.Schema != "" && !databricksName(q.Schema) || q.Schema != "" && q.Catalog == "" {
		return q, ErrRequest
	}
	switch q.Read {
	case "statement":
		if q.List != "" || q.PageToken != "" || q.MaxResults != 0 || q.Statement == "" || !databricksText(q.Statement, databricksStatementBytes) || len(q.Parameters) > 256 {
			return q, ErrRequest
		}
		seen := map[string]bool{}
		for _, parameter := range q.Parameters {
			if !databricksParameterName.MatchString(parameter.Name) || seen[strings.ToLower(parameter.Name)] || parameter.Type != "" && !databricksParameterType.MatchString(parameter.Type) || parameter.Value != nil && !databricksText(*parameter.Value, databricksStatementBytes) {
				return q, ErrRequest
			}
			seen[strings.ToLower(parameter.Name)] = true
		}
		return q, nil
	case "catalog":
		most, ok := databricksLists[q.List]
		if !ok || q.Statement != "" || q.Parameters != nil || q.MaxResults < 0 || q.MaxResults > most || q.PageToken != "" && !databricksPrintable(q.PageToken, 1, 4096) {
			return q, ErrRequest
		}
		switch q.List {
		case "catalogs":
			q.Catalog, q.Schema = "", ""
		case "schemas":
			if q.Catalog == "" {
				return q, ErrRequest
			}
			q.Schema = ""
		default:
			if q.Catalog == "" || q.Schema == "" {
				return q, ErrRequest
			}
		}
		return q, nil
	}
	return q, ErrRequest
}

func ReadDatabricks(ctx context.Context, s *Store, raw []byte) ([]byte, error) {
	var q DatabricksRequest
	if decode(raw, &q) != nil {
		return nil, ErrRequest
	}
	return databricksAcquire(ctx, s, q, databricksProvider())
}

// databricksAcquire is one read: one request to the workspace, after a
// token request where a service principal holds no token it may use. The
// envelope's result is the API's answer as received, carried into the
// canon domain (a number outside it as its literal text); its
// acquisition names the workspace's endpoint, the request as the
// statement the gateway commits to, the statement_id the API returned (a
// listing names none, and has the digest of the answer as received), and
// the TLS peer the answer came from.
func databricksAcquire(ctx context.Context, s *Store, q DatabricksRequest, p provider) ([]byte, error) {
	c, err := databricksSnapshot(s, q.Connection, q.Revision)
	if err != nil {
		return nil, err
	}
	if q, err = q.check(c); err != nil {
		return nil, err
	}
	bearer, err := p.databricksBearer(ctx, s, c)
	if err != nil {
		return nil, err
	}
	secrets := c.secrets(bearer)
	wait := c.wait()
	seconds := databricksListSeconds
	record := map[string]any{"connection": c.ID, "revision": c.Revision, "provider": "databricks", "read": q.Read}
	var method, endpoint, target string
	var body []byte
	if q.Read == "statement" {
		send := map[string]any{"warehouse_id": c.Warehouse, "statement": q.Statement, "wait_timeout": fmt.Sprintf("%ds", wait), "on_wait_timeout": "CANCEL", "disposition": "INLINE", "format": "JSON_ARRAY"}
		if q.Catalog != "" {
			send["catalog"] = q.Catalog
		}
		if q.Schema != "" {
			send["schema"] = q.Schema
		}
		if len(q.Parameters) > 0 {
			send["parameters"] = q.Parameters
		}
		if body, err = canon.EncodeJSON(send); err != nil {
			return nil, ErrRequest
		}
		method, endpoint = "POST", c.Workspace+"/api/2.0/sql/statements"
		target = endpoint
		seconds = wait + databricksMarginSeconds
		record["body"] = json.RawMessage(body)
	} else {
		query := url.Values{"max_results": {strconv.Itoa(q.MaxResults)}}
		if q.Catalog != "" {
			query.Set("catalog_name", q.Catalog)
		}
		if q.Schema != "" {
			query.Set("schema_name", q.Schema)
		}
		if q.PageToken != "" {
			query.Set("page_token", q.PageToken)
		}
		method, endpoint = "GET", c.Workspace+"/api/2.1/unity-catalog/"+q.List
		target = endpoint + "?" + query.Encode()
		record["query"] = queryValues(query)
	}
	record["method"], record["endpoint"] = method, endpoint
	rctx, cancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	defer cancel()
	started := time.Now()
	response, data, err := p.databricksSend(rctx, method, target, body, bearer, c.resultBound(), secrets, seconds)
	if err != nil {
		return nil, err
	}
	observed := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	snapshot := digest(data)
	if q.Read == "statement" {
		if snapshot, err = databricksStatement(data, wait, time.Since(started), secrets); err != nil {
			return nil, err
		}
	}
	// A failed statement's message is reported with the credential
	// replaced; an answer that would be kept is not kept at all.
	if databricksLeaks(data, secrets) {
		return nil, Error("provider-unavailable: the workspace's answer repeats the credential, and is not kept")
	}
	result, err := canon.Canonicalize(data, canon.CarryNumbersAsText)
	if err != nil {
		return nil, Error("provider-unavailable: the workspace's answer is JSON outside the canonical domain")
	}
	if err = databricksCurrent(s, c); err != nil {
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
	acquisition := map[string]any{"adapter": identity, "endpoint": endpoint, "statement": string(statement), "snapshot": snapshot, "peerIdentity": peer(response), "schema": nil, "upstreamToken": nil, "observedAt": observed}
	out, err := canon.EncodeJSON(map[string]any{"acquisition": acquisition, "result": json.RawMessage(result)})
	if err != nil {
		return nil, ErrProvider
	}
	if len(out) > MaxOutputBytes {
		return nil, Error(fmt.Sprintf("result-too-large: the envelope is larger than the source's output bound of %d bytes", MaxOutputBytes))
	}
	return out, nil
}

// databricksTest is a connection test: the first catalog of the listing,
// one request after any token request, and nothing of its content kept.
func databricksTest(ctx context.Context, s *Store, id, revision string, p provider) error {
	c, err := databricksSnapshot(s, id, revision)
	if err != nil {
		return err
	}
	bearer, err := p.databricksBearer(ctx, s, c)
	if err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, databricksListSeconds*time.Second)
	defer cancel()
	_, _, err = p.databricksSend(rctx, "GET", c.Workspace+"/api/2.1/unity-catalog/catalogs?max_results=1", nil, bearer, 1<<20, c.secrets(bearer), databricksListSeconds)
	return err
}
