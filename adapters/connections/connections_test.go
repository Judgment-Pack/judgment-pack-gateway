//go:build linux || darwin

package connections

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testStore(t *testing.T, principal string) *Store {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	s, e := OpenStore(dir, principal)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCatalogDispatchPreservesDisabledPolicyForUnsupportedRequests(t *testing.T) {
	s := testStore(t, "catalog-policy")
	b := New(s, true)
	defer b.Close()
	_, err := b.Handle(context.Background(), "send", []byte(`{}`))
	if err != ErrPolicy {
		t.Fatalf("unsupported method bypassed operator policy: %v", err)
	}
	if err := s.locked(func(v *state) error {
		if !v.Disabled {
			t.Fatal("unsupported request left other processes able to use the connection")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
func testBroker(t *testing.T) (*Broker, *atomic.Int32, *string) {
	t.Helper()
	s := testStore(t, "alice")
	b := New(s, false)
	t.Cleanup(b.Close)
	c := Client{"test.apps.googleusercontent.com", "client-secret-test"}
	if _, e := b.Handle(context.Background(), "configure", mustJSON(c)); e != nil {
		t.Fatal(e)
	}
	count := &atomic.Int32{}
	accountID := new(string)
	*accountID = "account-A"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			r.ParseForm()
			if r.Form.Get("client_id") != c.ID || r.Form.Get("client_secret") != c.Secret {
				t.Error("client mismatch")
			}
			if r.Form.Get("grant_type") == "authorization_code" {
				if r.Form.Get("code") != "one-use-code" || r.Form.Get("code_verifier") == "" {
					t.Error("missing code/PKCE")
				}
			}
			io.WriteString(w, `{"access_token":"google-access-private","refresh_token":"google-refresh-private","expires_in":3600,"token_type":"Bearer","scope":"https://www.googleapis.com/auth/drive"}`)
		case "/about":
			if r.Header.Get("Authorization") != "Bearer google-access-private" {
				t.Error("token not sent correctly")
			}
			json.NewEncoder(w).Encode(map[string]any{"user": map[string]string{"permissionId": *accountID, "emailAddress": "person@example.test", "displayName": "Person"}})
		case "/files/file-A":
			count.Add(1)
			if r.Header.Get("Authorization") != "Bearer google-access-private" {
				t.Error("token not sent")
			}
			if r.URL.Query().Get("alt") == "media" {
				io.WriteString(w, "A test policy document.")
				return
			}
			io.WriteString(w, `{"id":"file-A","name":"policy.txt","mimeType":"text/plain","version":"7","size":"23","capabilities":{"canDownload":true}}`)
		case "/revoke":
			io.WriteString(w, "{}")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	b.provider = provider{auth: server.URL + "/auth", token: server.URL + "/token", revoke: server.URL + "/revoke", api: server.URL, client: server.Client(), gmail: false}
	b.provider.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return b, count, accountID
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
func start(t *testing.T, b *Broker, method string) FlowResult {
	t.Helper()
	v, e := b.Handle(context.Background(), method, []byte(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	return v.(FlowResult)
}
func finish(t *testing.T, b *Broker, f FlowResult, extra url.Values) FlowResult {
	t.Helper()
	u, _ := url.Parse(f.URL)
	q := u.Query()
	callback := q.Get("redirect_uri")
	if q.Get("scope") != driveScope || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") != challenge(b.active.verifier) {
		t.Fatal("scope or PKCE")
	}
	values := url.Values{"state": {q.Get("state")}, "code": {"one-use-code"}}
	for k, v := range extra {
		values[k] = v
	}
	r, e := http.Get(callback + "?" + values.Encode())
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	v, e := b.Handle(context.Background(), "poll", mustJSON(map[string]string{"id": f.ID}))
	if e != nil {
		t.Fatal(e)
	}
	return v.(FlowResult)
}

// chosen is what a connection and a selection of files give: the flow's
// result, and a grant for each file.
type chosen struct {
	FlowResult
	Selections []Selection
}

// choose connects, as a person who consents does, and selects the files by
// their IDs under the connection's own context. It asks for no search: a
// test that is of the search asks for one itself.
func choose(t *testing.T, b *Broker, ids ...string) chosen {
	t.Helper()
	out := chosen{FlowResult: finish(t, b, start(t, b, "connect"), nil)}
	if out.State != "complete" {
		return out
	}
	var epoch string
	if e := b.store.locked(func(v *state) error { epoch = v.Epoch; return nil }); e != nil {
		t.Fatal(e)
	}
	v, e := b.Handle(context.Background(), "select", mustJSON(map[string]any{"resourceIds": ids, "selectionContext": epoch}))
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range v.([]SourceSelection) {
		out.Selections = append(out.Selections, Selection{s.ResourceID, s.Grant})
	}
	return out
}
func TestSelectionRetrievesChosenFileAndRetainsOriginal(t *testing.T) {
	b, count, _ := testBroker(t)
	result := choose(t, b, "file-A")
	if result.State != "complete" || len(result.Selections) != 1 {
		t.Fatalf("%+v", result)
	}
	raw := mustJSON(ReadRequest{result.Selections[0].Grant, "file-A"})
	out, e := b.provider.read(context.Background(), b.store, raw)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(out), "google-access-private") || strings.Contains(string(out), "google-refresh-private") {
		t.Fatal("credential in record")
	}
	var envelope struct {
		Result struct {
			Original   struct{ Bytes string }
			Document   struct{ ID string }
			Provenance struct {
				Source struct {
					Kind   string
					FileID string `json:"fileId"`
				}
			}
		}
	}
	if json.Unmarshal(out, &envelope) != nil {
		t.Fatal("invalid record")
	}
	original, _ := base64.StdEncoding.DecodeString(envelope.Result.Original.Bytes)
	if string(original) != "A test policy document." || envelope.Result.Document.ID != digest(original) || envelope.Result.Provenance.Source.Kind != "google-drive" || envelope.Result.Provenance.Source.FileID != "file-A" {
		t.Fatal("wrong original/provenance")
	}
	if count.Load() != 3 {
		t.Fatalf("metadata/content/version-check count %d", count.Load())
	}
	if _, e = b.provider.read(context.Background(), b.store, raw); e != ErrGrant {
		t.Fatalf("replay accepted: %v", e)
	}
}
func TestPrincipalAndFileCannotBeSubstituted(t *testing.T) {
	b, count, _ := testBroker(t)
	r := choose(t, b, "file-A")
	g := r.Selections[0].Grant
	if _, e := b.provider.read(context.Background(), b.store, mustJSON(ReadRequest{g, "file-B"})); e != ErrGrant {
		t.Fatalf("file substitution reached provider: %v", e)
	}
	for _, req := range []string{string(mustJSON(ReadRequest{g, "file-B"})), `{"grant":"` + g + `","fileId":"file-A","principal":"alice"}`, `{"grant":"` + g + `","fileId":"../state.json"}`} {
		if _, e := b.provider.read(context.Background(), b.store, []byte(req)); e == nil {
			t.Fatal("substitution accepted")
		}
	}
	other, err := OpenStore(filepath.Dir(b.store.root.Name()), "bob")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, e := b.provider.read(context.Background(), other, mustJSON(ReadRequest{g, "file-A"})); e != ErrGrant {
		t.Fatal(e)
	}
	if count.Load() != 0 {
		t.Fatal("unauthorized network call")
	}
}
func TestStateMismatchDoesNotConsumeAuthorization(t *testing.T) {
	b, _, _ := testBroker(t)
	f := start(t, b, "connect")
	u, _ := url.Parse(f.URL)
	r, e := http.Get(u.Query().Get("redirect_uri") + "?state=wrong&code=one-use-code")
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 400 {
		t.Fatal("wrong state accepted")
	}
	if result := finish(t, b, f, nil); result.State != "complete" {
		t.Fatalf("%+v", result)
	}
}
func TestCancelAndWrongAccountCannotReplaceConnection(t *testing.T) {
	b, _, accountID := testBroker(t)
	f := start(t, b, "connect")
	if r := finish(t, b, f, nil); r.State != "complete" {
		t.Fatal(r)
	}
	*accountID = "account-B"
	r := choose(t, b, "file-A")
	if r.Error != "wrong-account" || len(r.Selections) != 0 {
		t.Fatal(r)
	}
	f = start(t, b, "connect")
	if _, e := b.Handle(context.Background(), "cancel", mustJSON(map[string]string{"id": f.ID})); e != nil {
		t.Fatal(e)
	}
	if b.active.State != "canceled" {
		t.Fatal("not canceled")
	}
	status, e := b.Handle(context.Background(), "status", nil)
	if e != nil || status.(Status).Account.ID != "account-A" {
		t.Fatal(status, e)
	}
}
func TestDisconnectInvalidatesOutstandingSelection(t *testing.T) {
	b, count, _ := testBroker(t)
	r := choose(t, b, "file-A")
	v, e := b.Handle(context.Background(), "disconnect", nil)
	if e != nil || !v.(map[string]bool)["revoked"] {
		t.Fatal(v, e)
	}
	if _, e = b.provider.read(context.Background(), b.store, mustJSON(ReadRequest{r.Selections[0].Grant, "file-A"})); e != ErrGrant {
		t.Fatal(e)
	}
	if count.Load() != 0 {
		t.Fatal("network after disconnect")
	}
}
func TestPolicyAndMalformedRequests(t *testing.T) {
	b, _, _ := testBroker(t)
	b.disabled = true
	for _, method := range []string{"configure", "connect", "search", "select", "disconnect"} {
		if _, e := b.Handle(context.Background(), method, []byte(`{}`)); e != ErrPolicy {
			t.Fatal(e)
		}
	}
	b.disabled = false
	for _, raw := range []string{`{"principal":"admin"}`, `{"clientId":"a","clientId":"b"}`, `{"clientId":"https://evil.example"}`} {
		if _, e := b.Handle(context.Background(), "configure", []byte(raw)); e != ErrRequest {
			t.Fatal(e)
		}
	}
}
func TestStorageRefusesSymlinksAndPublicPermissions(t *testing.T) {
	s := testStore(t, "alice")
	target := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(target, []byte(`{}`), 0600)
	if e := s.root.Symlink(target, "state.json"); e != nil {
		t.Fatal(e)
	}
	if e := s.locked(func(*state) error { return nil }); e != ErrStorage {
		t.Fatal("followed symlink", e)
	}
	s.root.Remove("state.json")
	if e := s.write("state.json", state{}); e != nil {
		t.Fatal(e)
	}
	s.root.Chmod("state.json", 0644)
	if e := s.locked(func(*state) error { return nil }); e != ErrStorage {
		t.Fatal("public credentials accepted", e)
	}
}
func TestExpiredGrantRefusedBeforeNetwork(t *testing.T) {
	b, count, _ := testBroker(t)
	r := choose(t, b, "file-A")
	var id string
	b.store.locked(func(v *state) error { id = v.Connection.ID; return nil })
	b.store.write("grant-"+r.Selections[0].Grant, grant{Connection: id, File: "file-A", Expires: time.Now().Add(-time.Second).Unix()})
	if _, e := b.provider.read(context.Background(), b.store, mustJSON(ReadRequest{r.Selections[0].Grant, "file-A"})); e != ErrGrant {
		t.Fatal(e)
	}
	if count.Load() != 0 {
		t.Fatal("expired grant used")
	}
}

func TestDownloadRefusalsNeverBecomeDocuments(t *testing.T) {
	for _, scenario := range []string{"changed", "oversize", "redirect", "echo", "revoked", "unsupported"} {
		t.Run(scenario, func(t *testing.T) {
			b, _, _ := testBroker(t)
			r := choose(t, b, "file-A")
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.URL.Query().Get("alt") == "media" {
					switch scenario {
					case "oversize":
						w.Header().Set("Content-Length", "4194305")
					case "redirect":
						http.Redirect(w, req, "https://untrusted.example", 302)
					case "echo":
						io.WriteString(w, "google-access-private")
					case "revoked":
						w.WriteHeader(401)
					default:
						io.WriteString(w, "A test policy document.")
					}
					return
				}
				calls++
				version, media := "7", "text/plain"
				if scenario == "changed" && calls > 1 {
					version = "8"
				}
				if scenario == "unsupported" {
					media = "image/png"
				}
				json.NewEncoder(w).Encode(map[string]any{"id": "file-A", "name": "policy.txt", "mimeType": media, "version": version, "size": "23", "capabilities": map[string]bool{"canDownload": true}})
			}))
			defer server.Close()
			b.provider.api = server.URL
			b.provider.client = server.Client()
			b.provider.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			if data, err := b.provider.read(context.Background(), b.store, mustJSON(ReadRequest{r.Selections[0].Grant, "file-A"})); err == nil || len(data) != 0 || scenario == "oversize" && err != ErrLimit {
				t.Fatal("refused response became a document")
			}
		})
	}
}
func TestPublicStatusDoesNotExposeTokensOrClientSecret(t *testing.T) {
	b, _, _ := testBroker(t)
	finish(t, b, start(t, b, "connect"), nil)
	v, e := b.Handle(context.Background(), "status", nil)
	if e != nil {
		t.Fatal(e)
	}
	raw := string(mustJSON(v))
	for _, secret := range []string{"google-access-private", "google-refresh-private", "client-secret-test"} {
		if strings.Contains(raw, secret) {
			t.Fatal("credential in public status")
		}
	}
}
func TestRestartUsesStoredConnectionAndRefreshesExpiredToken(t *testing.T) {
	b, _, _ := testBroker(t)
	r := choose(t, b, "file-A")
	if e := b.store.locked(func(v *state) error { v.Connection.Expires = 1; return b.store.write("state.json", v) }); e != nil {
		t.Fatal(e)
	}
	b.Close()
	if _, e := b.provider.read(context.Background(), b.store, mustJSON(ReadRequest{r.Selections[0].Grant, "file-A"})); e != nil {
		t.Fatal(e)
	}
}

func TestDisabledConnectionAndGenerationInvalidateGrants(t *testing.T) {
	for _, scenario := range []string{"disabled", "generation"} {
		t.Run(scenario, func(t *testing.T) {
			b, count, _ := testBroker(t)
			r := choose(t, b, "file-A")
			if scenario == "disabled" {
				b.disabled = true
				b.Handle(context.Background(), "status", nil)
			} else {
				b.store.locked(func(v *state) error { v.Connection.ID = randomID(); return b.store.write("state.json", v) })
			}
			if _, e := b.provider.read(context.Background(), b.store, mustJSON(ReadRequest{r.Selections[0].Grant, "file-A"})); e == nil {
				t.Fatal("invalidated grant accepted")
			}
			if count.Load() != 0 {
				t.Fatal("request sent")
			}
		})
	}
}

// A token is taken for the scope that was asked for and for no other: not
// for less, which is what a connection made before ADR-0010 has, and not for
// more.
func TestTokenOfAnotherScopeIsRefused(t *testing.T) {
	for scope, want := range map[string]error{
		"https://www.googleapis.com/auth/drive":                                                nil,
		"https://www.googleapis.com/auth/drive.file":                                           ErrProvider,
		"https://www.googleapis.com/auth/drive.readonly":                                       ErrProvider,
		"https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/gmail.readonly": ErrProvider,
		"https://www.googleapis.com/auth/drive.file https://www.googleapis.com/auth/drive":     ErrProvider,
	} {
		b, _, _ := testBroker(t)
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{"access_token": "private", "refresh_token": "private-refresh", "expires_in": 3600, "token_type": "Bearer", "scope": scope})
		}))
		b.provider.token = server.URL
		b.provider.client = server.Client()
		if _, e := b.provider.exchange(context.Background(), Client{"id", "secret"}, url.Values{}); e != want {
			t.Errorf("a token of the scope %q: %v, and not %v", scope, e, want)
		}
		server.Close()
	}
}

// A connection made under the narrower scope is asked to connect again when
// its token is next renewed, and is not used as if it were of the whole Drive.
func TestConnectionOfTheNarrowerScopeIsAskedToConnectAgain(t *testing.T) {
	b, count, _ := testBroker(t)
	r := choose(t, b, "file-A")
	if err := b.store.locked(func(v *state) error { v.Connection.Expires = 1; return b.store.write("state.json", v) }); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"access_token":"narrow","expires_in":3600,"token_type":"Bearer","scope":"https://www.googleapis.com/auth/drive.file"}`)
	}))
	defer server.Close()
	p := b.provider
	p.token = server.URL
	p.client = server.Client()
	if _, e := p.read(context.Background(), b.store, mustJSON(ReadRequest{r.Selections[0].Grant, "file-A"})); e != ErrRevoked {
		t.Fatalf("a read under a token of the narrower scope: %v", e)
	}
	if count.Load() != 0 {
		t.Fatal("the file was asked for under the narrower token")
	}
	if e := b.store.locked(func(v *state) error {
		if v.Connection.Access == "narrow" {
			t.Error("the narrower token was kept")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
