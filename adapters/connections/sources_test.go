//go:build linux || darwin

package connections

import (
	"adapters/attachment"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type notionTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (t notionTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host != "mcp.notion.com" {
		return nil, ErrProvider
	}
	clone := r.Clone(r.Context())
	u := *r.URL
	u.Host = t.target.Host
	u.Scheme = t.target.Scheme
	clone.URL = &u
	clone.Host = t.target.Host
	return t.base.RoundTrip(clone)
}

const testPage = "11111111-2222-3333-4444-555555555555"

func notionFixture(t *testing.T) (*Broker, *atomic.Int32) {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	s, err := OpenNotionStore(dir, "test-person")
	if err != nil {
		t.Fatal(err)
	}
	b := NewNotion(s, false)
	count := &atomic.Int32{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/oauth-protected-resource":
			io.WriteString(w, `{"resource":"https://mcp.notion.com","authorization_servers":["https://mcp.notion.com"]}`)
		case "/.well-known/oauth-authorization-server":
			io.WriteString(w, `{"issuer":"https://mcp.notion.com","authorization_endpoint":"https://mcp.notion.com/authorize","token_endpoint":"https://mcp.notion.com/token","registration_endpoint":"https://mcp.notion.com/register","code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["none"]}`)
		case "/register":
			var v map[string]any
			json.NewDecoder(r.Body).Decode(&v)
			if v["token_endpoint_auth_method"] != "none" {
				t.Error("not public PKCE client")
			}
			json.NewEncoder(w).Encode(map[string]any{"client_id": "notion-client", "token_endpoint_auth_method": "none", "redirect_uris": v["redirect_uris"]})
		case "/token":
			r.ParseForm()
			if r.Form.Get("resource") != notionResource || r.Form.Get("client_id") != "notion-client" {
				t.Error("wrong token audience/client")
			}
			if r.Form.Get("grant_type") == "authorization_code" && (r.Form.Get("code") != "fixture-code" || r.Form.Get("code_verifier") == "") {
				t.Error("code/PKCE missing")
			}
			if r.Form.Get("grant_type") == "refresh_token" {
				count.Add(1)
				time.Sleep(20 * time.Millisecond)
			}
			io.WriteString(w, `{"access_token":"notion-private-access","refresh_token":"notion-private-refresh","expires_in":3600,"token_type":"Bearer","scope":"default","workspace_id":"workspace-1","user_id":"person-1"}`)
		case "/mcp":
			if r.Header.Get("Authorization") != "Bearer notion-private-access" {
				t.Error("wrong bearer")
			}
			if r.Method == "DELETE" {
				w.WriteHeader(204)
				return
			}
			var v struct {
				ID     int    `json:"id"`
				Method string `json:"method"`
				Params struct {
					Name string         `json:"name"`
					Args map[string]any `json:"arguments"`
				} `json:"params"`
			}
			json.NewDecoder(r.Body).Decode(&v)
			if v.ID == 0 {
				w.WriteHeader(202)
				return
			}
			var result any
			text := func(s string) any {
				return map[string]any{"content": []any{map[string]string{"type": "text", "text": s}}}
			}
			switch v.Method {
			case "initialize":
				result = map[string]string{"protocolVersion": "2025-11-25"}
			case "tools/list":
				result = map[string]any{"tools": []any{map[string]any{"name": "notion-search", "inputSchema": map[string]any{}}, map[string]any{"name": "notion-get-tool-access", "inputSchema": map[string]any{}}}}
			case "tools/call":
				switch v.Params.Name {
				case "notion-get-tool-access":
					result = text(`{"current_tool_access":{"search":{"status":"available"}}}`)
				case "notion-search":
					result = text(`{"results":[{"id":"` + testPage + `","title":"Policy","url":"https://www.notion.so/11111111222233334444555555555555"},{"id":"` + testPage + `","title":"External secret","url":"https://evil.invalid/11111111222233334444555555555555"}]}`)
				case "notion-fetch":
					if v.Params.Args["id"] != testPage {
						t.Error("wrong page")
					}
					result = text(`{"title":"Policy","url":"https://www.notion.so/11111111222233334444555555555555","text":"Review budgets over 100."}`)
				default:
					t.Errorf("unexpected tool %s", v.Params.Name)
					w.WriteHeader(500)
					return
				}
			default:
				t.Error("unexpected MCP operation")
			}
			json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": v.ID, "result": result})
		default:
			http.NotFound(w, r)
		}
	}))
	target, _ := url.Parse(server.URL)
	h := server.Client()
	h.Transport = notionTransport{target, h.Transport}
	b.provider.client = h
	t.Cleanup(func() { b.Close(); s.Close(); server.Close() })
	return b, count
}
func connectNotion(t *testing.T, b *Broker) {
	t.Helper()
	value, err := b.Handle(context.Background(), "connect", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	flow := value.(FlowResult)
	u, _ := url.Parse(flow.URL)
	q := u.Query()
	if u.Host != "mcp.notion.com" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") != challenge(b.active.verifier) {
		t.Fatal("bad auth URL")
	}
	target := q.Get("redirect_uri") + "?" + url.Values{"state": {q.Get("state")}, "code": {"fixture-code"}}.Encode()
	response, err := http.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	result, err := b.Handle(context.Background(), "poll", mustJSON(map[string]string{"id": flow.ID}))
	if err != nil || result.(FlowResult).State != "complete" {
		t.Fatalf("authorization: %v %v", result, err)
	}
}
func TestNotionOAuthSearchSelectedSnapshot(t *testing.T) {
	b, _ := notionFixture(t)
	connectNotion(t, b)
	v, err := b.Handle(context.Background(), "search", []byte(`{"query":"policy"}`))
	if err != nil {
		t.Fatal(err)
	}
	matches := v.(SourceSearch)
	if len(matches.Items) != 1 || matches.Items[0].Title != "Policy" {
		t.Fatal("untrusted external result admitted")
	}
	v, err = b.Handle(context.Background(), "select", mustJSON(map[string]any{"resourceIds": []string{testPage}, "selectionContext": matches.SelectionContext}))
	if err != nil {
		t.Fatal(err)
	}
	selected := v.([]SourceSelection)[0]
	raw, err := b.provider.readNotion(context.Background(), b.store, mustJSON(selected))
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Result json.RawMessage `json:"result"`
	}
	json.Unmarshal(raw, &env)
	if err = attachment.Check(env.Result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "Review budgets") || strings.Contains(string(raw), "notion-private") {
		t.Fatal("missing source or credential escaped")
	}
	if _, err = b.provider.readNotion(context.Background(), b.store, mustJSON(selected)); err != ErrGrant {
		t.Fatal("selection replay accepted")
	}
	if path := os.Getenv("JPACK_TEST_NOTION_RECORD"); path != "" {
		if err = os.WriteFile(path, env.Result, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
func TestNotionRefreshSerializedAcrossWorkers(t *testing.T) {
	b, count := notionFixture(t)
	connectNotion(t, b)
	b.store.locked(func(v *state) error { v.Connection.Expires = 1; return b.store.write("state.json", v) })
	client, c, epoch, err := b.connectedSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := b.provider.access(context.Background(), b.store, client, c, epoch); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if count.Load() != 1 {
		t.Fatalf("refresh token used %d times", count.Load())
	}
}
func TestObsidianFailedReadsStillConsumeSearchBudget(t *testing.T) {
	vault := t.TempDir()
	if err := os.Mkdir(filepath.Join(vault, ".obsidian"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vault, "invalid.md"), []byte{0xff, 0xff, 0xff}, 0600); err != nil {
		t.Fatal(err)
	}
	root, err := openVault(vault)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	data, consumed, err := vaultReadBounded(root, "invalid.md", 3)
	if data != nil || consumed != 3 || err != ErrUnsupported {
		t.Fatalf("unaccounted failed read: %d %v", consumed, err)
	}
	_, consumed, err = vaultReadBounded(root, "invalid.md", 2)
	if consumed != 0 || err != ErrLimit {
		t.Fatal("read exceeded remaining search budget")
	}
}
func TestObsidianSelectedSnapshotAndBoundary(t *testing.T) {
	vault := t.TempDir()
	os.Mkdir(filepath.Join(vault, ".obsidian"), 0700)
	os.Mkdir(filepath.Join(vault, "notes"), 0700)
	os.WriteFile(filepath.Join(vault, "notes", "Policy.md"), []byte("Review budgets over 100.\n"), 0600)
	os.WriteFile(filepath.Join(vault, ".obsidian", "private.md"), []byte("must not read"), 0600)
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret.md"), []byte("must not read"), 0600)
	if err := os.Symlink(outside, filepath.Join(vault, "escape")); err != nil && os.PathSeparator != '\\' {
		t.Fatal(err)
	}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	s, err := OpenObsidianStore(dir, "test-person")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	b := NewObsidian(s, false)
	defer b.Close()
	if _, err = b.Handle(context.Background(), "configure", mustJSON(map[string]string{"path": vault})); err != nil {
		t.Fatal(err)
	}
	result, err := b.Handle(context.Background(), "search", []byte(`{"query":""}`))
	if err != nil {
		t.Fatal(err)
	}
	found := result.(SourceSearch)
	if len(found.Items) != 1 || found.Items[0].ID != "notes/Policy.md" {
		t.Fatalf("vault boundaries: %v", found.Items)
	}
	for _, id := range []string{"../secret.md", ".obsidian/private.md", "/secret.md", "notes/../secret.md", "notes\\secret.md"} {
		if _, err = b.Handle(context.Background(), "select", mustJSON(map[string]any{"resourceIds": []string{id}, "selectionContext": found.SelectionContext})); err == nil {
			t.Fatalf("accepted %s", id)
		}
	}
	value, err := b.Handle(context.Background(), "select", mustJSON(map[string]any{"resourceIds": []string{"notes/Policy.md"}, "selectionContext": found.SelectionContext}))
	if err != nil {
		t.Fatal(err)
	}
	selection := value.([]SourceSelection)[0]
	raw, err := ReadObsidian(context.Background(), s, mustJSON(selection))
	if err != nil {
		t.Fatal(err)
	}
	if err = attachment.Check(raw); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(vault, "notes", "Policy.md"), []byte("Changed later"), 0600)
	if !strings.Contains(string(raw), "Review budgets") || strings.Contains(string(raw), vault) {
		t.Fatal("snapshot changed or absolute vault path escaped")
	}
	if _, err = ReadObsidian(context.Background(), s, mustJSON(selection)); err != ErrGrant {
		t.Fatal("replayed selection")
	}
	if _, err = b.Handle(context.Background(), "disconnect", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err = b.Handle(context.Background(), "select", mustJSON(map[string]any{"resourceIds": []string{"notes/Policy.md"}, "selectionContext": found.SelectionContext})); err != ErrConnect {
		t.Fatal("disconnected vault accessible")
	}
	if name := os.Getenv("JPACK_TEST_OBSIDIAN_RECORD"); name != "" {
		os.WriteFile(name, raw, 0600)
	}
}

type testTransportFunc func(*http.Request) (*http.Response, error)

func (f testTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func testReply(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}
func TestNotionRefusesForeignDiscoveryWithoutContactingIt(t *testing.T) {
	b, _ := notionFixture(t)
	calls := 0
	b.provider.client.Transport = testTransportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return testReply(200, `{"resource":"https://mcp.notion.com","authorization_servers":["http://127.0.0.1/private"]}`), nil
	})
	if _, err := b.Handle(context.Background(), "connect", []byte(`{}`)); err != ErrProvider {
		t.Fatalf("foreign issuer: %v", err)
	}
	if calls != 1 {
		t.Fatal("followed foreign issuer")
	}
}
func TestNotionInvalidGrantClearsTokensAndNeverRetries(t *testing.T) {
	b, _ := notionFixture(t)
	connectNotion(t, b)
	b.store.locked(func(v *state) error { v.Connection.Expires = 1; return b.store.write("state.json", v) })
	client, c, epoch, _ := b.connectedSnapshot()
	count := 0
	b.provider.client.Transport = testTransportFunc(func(r *http.Request) (*http.Response, error) {
		count++
		return testReply(400, `{"error":"invalid_grant","error_description":"notion-private-refresh"}`), nil
	})
	if _, err := b.provider.access(context.Background(), b.store, client, c, epoch); err != ErrRevoked {
		t.Fatalf("terminal grant: %v", err)
	}
	if _, err := b.provider.access(context.Background(), b.store, client, c, epoch); err != ErrCanceled {
		t.Fatalf("retried dead connection: %v", err)
	}
	if count != 1 {
		t.Fatal("retried invalid_grant")
	}
	b.store.locked(func(v *state) error {
		if v.Connection != nil {
			t.Error("tokens retained")
		}
		return nil
	})
}
func TestNotionDisconnectDuringRefreshCannotRestoreTokens(t *testing.T) {
	b, _ := notionFixture(t)
	connectNotion(t, b)
	b.store.locked(func(v *state) error { v.Connection.Expires = 1; return b.store.write("state.json", v) })
	client, c, epoch, _ := b.connectedSnapshot()
	entered, release := make(chan struct{}), make(chan struct{})
	base := b.provider.client.Transport
	b.provider.client.Transport = testTransportFunc(func(r *http.Request) (*http.Response, error) { close(entered); <-release; return base.RoundTrip(r) })
	done := make(chan error, 1)
	go func() { _, err := b.provider.access(context.Background(), b.store, client, c, epoch); done <- err }()
	<-entered
	if _, err := b.Handle(context.Background(), "disconnect", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != ErrCanceled {
		t.Fatalf("stale refresh: %v", err)
	}
	b.store.locked(func(v *state) error {
		if v.Connection != nil {
			t.Error("restored disconnected tokens")
		}
		return nil
	})
}
