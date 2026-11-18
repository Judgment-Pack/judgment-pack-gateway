package gcpasset

// A stand-in for the platform, served in-process: the token endpoint (the
// jwt-bearer grant, its assertion verified against a key generated here),
// the token-information endpoint, the metadata server, projects.
// testIamPermissions, assets.list, and a directory answering groups.lookup
// and groups.memberships.list. Every answer is hand-written or a
// fixture of testdata/; no recorder, no live call, no real project,
// principal or credential. Each token minted is a fresh random value, and
// the stand-in remembers the scope it was minted for, so a test can show
// each token went to its one use.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const (
	testProject  = "projects/example-project-1"
	otherProject = "projects/example-project-2"
	testEmail    = "drift-reader@example-project-1.iam.gserviceaccount.com"
)

var (
	keyOnce sync.Once
	testKey *rsa.PrivateKey
)

func generatedKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	keyOnce.Do(func() {
		var err error
		if testKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			t.Fatal(err)
		}
	})
	return testKey
}

type call struct {
	method, path, query, token, body string
}

// fake is the stand-in platform and what it was asked.
type fake struct {
	t        *testing.T
	mu       sync.Mutex
	api      *httptest.Server
	metadata *httptest.Server
	key      *rsa.PrivateKey

	// scopeMember is the token answer's scope member for a requested scope:
	// nil, the scope requested; omitScope, no member.
	scopeMember func(requested string) any
	// tokenInfo answers the token-information endpoint for a token's scope:
	// nil answers {"scope": scope}.
	tokenInfo func(scope string) (int, string)
	// granted are the permissions testIamPermissions grants, by project;
	// permissionsAnswer, when set, answers every call instead.
	granted           map[string][]string
	permissionsAnswer func(asked []string) (int, string)
	// beforePermissions, when set, runs before each testIamPermissions
	// call is answered: a test's delay, or a wait for the caller to leave.
	beforePermissions func(r *http.Request)
	// permissionsType, when set, is the content type permissionsAnswer is
	// served with. A 3xx answer redirects to /redirected, which answers
	// 200 {} as JSON, so only the refusal of redirects refuses it.
	permissionsType string
	// page answers assets.list.
	page func(r *http.Request) (int, string)
	// metadataFlavor is the header the metadata server answers with;
	// listType, when set, the list call's content type.
	metadataFlavor, listType string
	// refuseScope are scopes the token endpoint and the metadata server
	// refuse to mint.
	refuseScope map[string]bool
	// groups is the directory: each group's email, lower-cased, and its
	// memberships, each a JSON object as the platform answers one, paged
	// by the size each call asks for, or by groupPage where it is set.
	groups    map[string][]string
	groupPage int
	// lastEmpty answers the last memberships page with an explicit empty
	// nextPageToken instead of leaving the member out.
	lastEmpty bool
	// identity, when set, answers a call to the directory first; handled
	// false leaves it to the directory.
	identity func(r *http.Request) (status int, body string, handled bool)

	minted map[string]string // token → the scope it was minted for
	scopes []string          // the scopes requested, in order
	calls  []call
}

// omitScope is a token answer with no scope member.
var omitScope = &struct{}{}

func newFake(t *testing.T) *fake {
	t.Helper()
	f := &fake{t: t, key: generatedKey(t), granted: map[string][]string{}, minted: map[string]string{}, metadataFlavor: "Google",
		refuseScope: map[string]bool{}, groups: map[string][]string{}}
	f.page = func(*http.Request) (int, string) { return 200, fixture(t, "resources-page.json") }
	f.api = httptest.NewTLSServer(http.HandlerFunc(f.serveAPI))
	f.metadata = httptest.NewServer(http.HandlerFunc(f.serveMetadata))
	saved, savedRoots := endpoints, testRoots
	endpoints.Asset = f.api.URL + "/asset"
	endpoints.ResourceManager = f.api.URL + "/rm"
	endpoints.Identity = f.api.URL + "/identity"
	endpoints.OAuthToken = f.api.URL + "/token"
	endpoints.TokenInfo = f.api.URL + "/tokeninfo"
	endpoints.Metadata = f.metadata.URL
	pool := x509.NewCertPool()
	pool.AddCert(f.api.Certificate())
	testRoots = pool
	t.Cleanup(func() {
		f.api.Close()
		f.metadata.Close()
		endpoints, testRoots = saved, savedRoots
	})
	return f
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func (f *fake) mint(scope string) map[string]any {
	raw := make([]byte, 24)
	rand.Read(raw)
	token := "ya29.test-" + hex.EncodeToString(raw)
	f.minted[token] = scope
	f.scopes = append(f.scopes, scope)
	answer := map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 3599}
	var member any = scope
	if f.scopeMember != nil {
		member = f.scopeMember(scope)
	}
	if member != omitScope {
		answer["scope"] = member
	}
	return answer
}

// tokens are every token minted.
func (f *fake) tokens() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []string{}
	for token := range f.minted {
		out = append(out, token)
	}
	return out
}

func (f *fake) callsTo(prefix string) []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []call
	for _, c := range f.calls {
		if strings.HasPrefix(c.path, prefix) {
			out = append(out, c)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	io.WriteString(w, body)
}

func mustJSON(v any) string {
	out, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(out)
}

func (f *fake) serveAPI(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.calls = append(f.calls, call{method: r.Method, path: r.URL.Path, query: r.URL.RawQuery, token: token, body: string(body)})
	scope, known := f.minted[token]
	f.mu.Unlock()
	switch {
	case r.URL.Path == "/redirected":
		writeJSON(w, 200, `{}`)
	case r.URL.Path == "/token":
		form, _ := url.ParseQuery(string(body))
		claims, ok := f.verifyAssertion(form.Get("assertion"))
		if form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || !ok || f.refuseScope[claims.Scope] {
			writeJSON(w, 400, `{"error":"invalid_grant"}`)
			return
		}
		f.mu.Lock()
		answer := f.mint(claims.Scope)
		f.mu.Unlock()
		writeJSON(w, 200, mustJSON(answer))
	case r.URL.Path == "/tokeninfo":
		form, _ := url.ParseQuery(string(body))
		f.mu.Lock()
		scope, known := f.minted[form.Get("access_token")]
		f.mu.Unlock()
		if !known {
			writeJSON(w, 400, `{"error":"invalid_token"}`)
			return
		}
		if f.tokenInfo != nil {
			status, answer := f.tokenInfo(scope)
			writeJSON(w, status, answer)
			return
		}
		writeJSON(w, 200, mustJSON(map[string]any{"scope": scope, "expires_in": 3500}))
	case strings.HasPrefix(r.URL.Path, "/rm/v3/") && strings.HasSuffix(r.URL.Path, ":testIamPermissions"):
		if !known || scope != CheckScope {
			writeJSON(w, 403, `{"error":{"code":403,"status":"PERMISSION_DENIED"}}`)
			return
		}
		if f.beforePermissions != nil {
			f.beforePermissions(r)
		}
		var asked struct {
			Permissions []string `json:"permissions"`
		}
		json.Unmarshal(body, &asked)
		if f.permissionsAnswer != nil {
			status, answer := f.permissionsAnswer(asked.Permissions)
			switch {
			case status >= 300 && status < 400:
				w.Header().Set("Location", "/redirected")
				w.WriteHeader(status)
			case f.permissionsType != "":
				w.Header().Set("Content-Type", f.permissionsType)
				w.WriteHeader(status)
				io.WriteString(w, answer)
			default:
				writeJSON(w, status, answer)
			}
			return
		}
		project := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/rm/v3/"), ":testIamPermissions")
		// Answered in the reverse of the list's order, so that a refusal
		// naming the first in the list's order is the adapter's ordering.
		var held []string
		for i := len(asked.Permissions) - 1; i >= 0; i-- {
			for _, g := range f.granted[project] {
				if g == asked.Permissions[i] {
					held = append(held, g)
				}
			}
		}
		if len(held) == 0 {
			writeJSON(w, 200, `{}`)
			return
		}
		writeJSON(w, 200, mustJSON(map[string]any{"permissions": held}))
	case strings.HasPrefix(r.URL.Path, "/asset/v1/") && strings.HasSuffix(r.URL.Path, "/assets"):
		if !known || scope != AssetScope {
			writeJSON(w, 403, `{"error":{"code":403,"status":"PERMISSION_DENIED"}}`)
			return
		}
		status, answer := f.page(r)
		if f.listType != "" {
			w.Header().Set("Content-Type", f.listType)
			w.WriteHeader(status)
			io.WriteString(w, answer)
			return
		}
		writeJSON(w, status, answer)
	case strings.HasPrefix(r.URL.Path, "/identity/v1/"):
		if !known || scope != GroupsScope {
			writeJSON(w, 403, `{"error":{"code":403,"status":"PERMISSION_DENIED"}}`)
			return
		}
		if f.identity != nil {
			if status, answer, handled := f.identity(r); handled {
				writeJSON(w, status, answer)
				return
			}
		}
		f.serveDirectory(w, r)
	default:
		writeJSON(w, 404, `{}`)
	}
}

// groupID is a group's resource name in the stand-in directory.
func groupID(email string) string {
	sum := sha256.Sum256([]byte(email))
	return "groups/" + hex.EncodeToString(sum[:8])
}

// serveDirectory answers groups.lookup by a group's email, 404 for one
// it does not hold, and groups.memberships.list of a group's resource
// name, a page at a time, the page token the offset of the next.
func (f *fake) serveDirectory(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/identity/v1/groups:lookup" {
		key := r.URL.Query().Get("groupKey.id")
		if _, ok := f.groups[key]; !ok {
			writeJSON(w, 404, `{"error":{"code":404,"message":"Group `+key+` not found","status":"NOT_FOUND"}}`)
			return
		}
		writeJSON(w, 200, mustJSON(map[string]string{"name": groupID(key)}))
		return
	}
	name, ok := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/identity/v1/"), "/memberships")
	if !ok {
		writeJSON(w, 404, `{}`)
		return
	}
	for email, members := range f.groups {
		if groupID(email) != name {
			continue
		}
		size, _ := strconv.Atoi(r.URL.Query().Get("pageSize"))
		if f.groupPage > 0 {
			size = f.groupPage
		}
		offset, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Query().Get("pageToken"), "o"))
		end := min(offset+max(size, 1), len(members))
		answer := `{"memberships":[` + strings.Join(members[offset:end], ",") + `]`
		if end < len(members) {
			answer += `,"nextPageToken":"o` + strconv.Itoa(end) + `"`
		} else if f.lastEmpty {
			answer += `,"nextPageToken":""`
		}
		writeJSON(w, 200, answer+`}`)
		return
	}
	writeJSON(w, 404, `{"error":{"code":404,"status":"NOT_FOUND"}}`)
}

// membership is one membership as the FULL view answers it: the member's
// key and type, "" for none.
func membership(kind, id string) string {
	m := map[string]any{"name": "groups/x/memberships/" + hex.EncodeToString([]byte(id))[:8], "preferredMemberKey": map[string]string{"id": id},
		"roles": []map[string]string{{"name": "MEMBER"}}}
	if kind != "" {
		m["type"] = kind
	}
	return mustJSON(m)
}

func (f *fake) serveMetadata(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls = append(f.calls, call{method: r.Method, path: "/metadata" + r.URL.Path, query: r.URL.RawQuery})
	flavor := f.metadataFlavor
	f.mu.Unlock()
	if r.Header.Get("Metadata-Flavor") != "Google" {
		w.WriteHeader(403)
		return
	}
	w.Header().Set("Metadata-Flavor", flavor)
	switch r.URL.Path {
	case "/computeMetadata/v1/instance/service-accounts/default/email":
		w.Header().Set("Content-Type", "application/text")
		io.WriteString(w, testEmail)
	case "/computeMetadata/v1/instance/service-accounts/default/token":
		if f.refuseScope[r.URL.Query().Get("scopes")] {
			w.WriteHeader(403)
			return
		}
		f.mu.Lock()
		answer := f.mint(r.URL.Query().Get("scopes"))
		f.mu.Unlock()
		// The metadata server answers no scope member of its own; the
		// adapter reads it from the token-information endpoint.
		if f.scopeMember == nil {
			delete(answer, "scope")
		}
		writeJSON(w, 200, mustJSON(answer))
	default:
		w.WriteHeader(404)
	}
}

type assertionClaims struct {
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Scope string `json:"scope"`
	Aud   string `json:"aud"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
}

// verifyAssertion holds the jwt-bearer assertion to the key generated
// here: RS256, iss the service account, aud the token endpoint, and no
// subject, which would be a user's by domain-wide delegation.
func (f *fake) verifyAssertion(assertion string) (assertionClaims, bool) {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return assertionClaims{}, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return assertionClaims{}, false
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&f.key.PublicKey, crypto.SHA256, digest[:], sig) != nil {
		return assertionClaims{}, false
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims assertionClaims
	if json.Unmarshal(raw, &claims) != nil || claims.Iss != testEmail || claims.Sub != "" || claims.Aud != endpoints.OAuthToken || claims.Exp <= claims.Iat {
		return assertionClaims{}, false
	}
	return claims, true
}

// keyFile writes a service account key of the key generated here.
func keyFile(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	path := filepath.Join(t.TempDir(), "key.json")
	data := mustJSON(map[string]string{"type": "service_account", "client_email": testEmail, "private_key": pemText, "private_key_id": "test-key-1", "project_id": "example-project-1"})
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// sealKeyFile writes a metadata platform's credentials file.
func sealKeyFile(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	rand.Read(raw)
	path := filepath.Join(t.TempDir(), "seal.json")
	if err := os.WriteFile(path, []byte(`{"sealKey":"`+hex.EncodeToString(raw)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// config is a configuration of every asset type served, both content
// types, on the test project, by the key.
func (f *fake) config(t *testing.T) Config {
	return Config{
		Parents: []string{testProject}, AssetTypes: ServedAssetTypes(), ContentTypes: []string{ContentResource, ContentIAMPolicy},
		TokenSource: TokenSourceKey, Credentials: keyFile(t, f.key), MaxOutput: 1 << 24, MaxAnswer: DefaultMaxAnswer,
	}
}

func resourceRequest() Request {
	return Request{Parent: testProject, ContentType: ContentResource, AssetTypes: ServedAssetTypes()}
}
