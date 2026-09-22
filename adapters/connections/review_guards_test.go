//go:build linux || darwin

// Regression cases adapted from the independent Claude review of 5346eb6.
package connections

import (
	"adapters/attachment"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// mcpOverride answers chosen MCP tool calls and passes everything else through.
func mcpOverride(base http.RoundTripper, tool string, reply func() string, before func()) http.RoundTripper {
	return testTransportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/mcp" || r.Method != "POST" {
			return base.RoundTrip(r)
		}
		raw, _ := io.ReadAll(r.Body)
		var v struct {
			ID     int `json:"id"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		json.Unmarshal(raw, &v)
		if v.Params.Name != tool {
			r.Body = io.NopCloser(strings.NewReader(string(raw)))
			return base.RoundTrip(r)
		}
		if before != nil {
			before()
		}
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": v.ID, "result": map[string]any{"content": []any{map[string]string{"type": "text", "text": reply()}}}})
		return testReply(200, string(body)), nil
	})
}

func TestReviewStaleSelectionContextAfterReconnect(t *testing.T) {
	b, _ := notionFixture(t)
	connectNotion(t, b)
	v, _ := b.Handle(context.Background(), "search", []byte(`{"query":"policy"}`))
	old := v.(SourceSearch).SelectionContext
	b.Handle(context.Background(), "disconnect", []byte(`{}`))
	connectNotion(t, b)
	_, err := b.Handle(context.Background(), "select", mustJSON(map[string]any{"resourceIds": []string{testPage}, "selectionContext": old}))
	t.Logf("select with the previous account's context: %v", err)
	if err == nil {
		t.Error("STALE CONTEXT ACCEPTED")
	}
}

func TestReviewDisconnectDuringRetrievalDiscardsResult(t *testing.T) {
	b, _ := notionFixture(t)
	connectNotion(t, b)
	v, _ := b.Handle(context.Background(), "search", []byte(`{"query":"policy"}`))
	got, err := b.Handle(context.Background(), "select", mustJSON(map[string]any{"resourceIds": []string{testPage}, "selectionContext": v.(SourceSearch).SelectionContext}))
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	b.provider.client.Transport = mcpOverride(b.provider.client.Transport, "notion-fetch", func() string { return `{"title":"Policy","text":"late text"}` }, func() {
		once.Do(func() {
			// A second broker on the same store stands in for the companion process.
			other := NewNotion(b.store, false)
			if _, err := other.Handle(context.Background(), "disconnect", []byte(`{}`)); err != nil {
				t.Error(err)
			}
		})
	})
	raw, err := b.provider.readNotion(context.Background(), b.store, mustJSON(got.([]SourceSelection)[0]))
	t.Logf("retrieval that straddled a disconnect: %d bytes, err=%v", len(raw), err)
	if err == nil {
		t.Error("RESULT SURVIVED A DISCONNECT")
	}
}

func TestReviewForeignSearchResultWithItsOwnID(t *testing.T) {
	b, _ := notionFixture(t)
	connectNotion(t, b)
	other := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	flat := strings.ReplaceAll(other, "-", "")
	b.provider.client.Transport = mcpOverride(b.provider.client.Transport, "notion-search", func() string {
		return `{"results":[` +
			`{"id":"` + other + `","title":"evil host","url":"https://evil.invalid/` + flat + `"},` +
			`{"id":"` + other + `","title":"lookalike","url":"https://www.notion.so.evil.invalid/` + flat + `"},` +
			`{"id":"` + other + `","title":"userinfo","url":"https://www.notion.so@evil.invalid/` + flat + `"},` +
			`{"id":"` + other + `","title":"port","url":"https://www.notion.so:8443/` + flat + `"},` +
			`{"id":"` + other + `","title":"http","url":"http://www.notion.so/` + flat + `"},` +
			`{"id":"` + other + `","title":"id mismatch","url":"https://www.notion.so/11111111222233334444555555555555"},` +
			`{"id":"https://docs.google.com/x","title":"connected app","url":"https://docs.google.com/x"}]}`
	}, nil)
	v, err := b.Handle(context.Background(), "search", []byte(`{"query":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range v.(SourceSearch).Items {
		t.Errorf("ADMITTED %q %s", item.Title, item.URL)
	}
	t.Logf("admitted %d of 7 foreign results", len(v.(SourceSearch).Items))
}

func TestReviewDiscoveryAndRegistrationPinning(t *testing.T) {
	good := `{"resource":"https://mcp.notion.com","authorization_servers":["https://mcp.notion.com"]}`
	meta := func(issuer, auth, token, reg string) string {
		return fmt.Sprintf(`{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"registration_endpoint":%q,"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["none"]}`, issuer, auth, token, reg)
	}
	n := "https://mcp.notion.com"
	cases := map[string]string{
		"foreign token endpoint":         meta(n, n+"/authorize", "https://evil.invalid/token", n+"/register"),
		"foreign registration endpoint":  meta(n, n+"/authorize", n+"/token", "https://evil.invalid/register"),
		"foreign authorization endpoint": meta(n, "https://evil.invalid/auth", n+"/token", n+"/register"),
		"foreign issuer":                 meta("https://evil.invalid", n+"/authorize", n+"/token", n+"/register"),
		"plain PKCE only":                strings.Replace(meta(n, n+"/authorize", n+"/token", n+"/register"), `["S256"]`, `["plain"]`, 1),
		"confidential clients only":      strings.Replace(meta(n, n+"/authorize", n+"/token", n+"/register"), `["none"]`, `["client_secret_basic"]`, 1),
	}
	for name, body := range cases {
		b, _ := notionFixture(t)
		var hosts []string
		b.provider.client.Transport = testTransportFunc(func(r *http.Request) (*http.Response, error) {
			hosts = append(hosts, r.URL.Host+r.URL.Path)
			if strings.HasSuffix(r.URL.Path, "oauth-protected-resource") {
				return testReply(200, good), nil
			}
			return testReply(200, body), nil
		})
		err := b.provider.notionDiscovery(context.Background())
		t.Logf("%-30s -> %v; contacted %v", name, err, hosts)
		if err == nil {
			t.Errorf("%s ACCEPTED", name)
		}
		for _, h := range hosts {
			if !strings.HasPrefix(h, "mcp.notion.com/") {
				t.Errorf("%s contacted %s", name, h)
			}
		}
	}
	// A registration reply that swaps the redirect, or upgrades the client.
	for name, reply := range map[string]string{
		"redirect swapped":     `{"client_id":"c","token_endpoint_auth_method":"none","redirect_uris":["http://127.0.0.1:1/oauth/callback"]}`,
		"extra redirect":       `{"client_id":"c","token_endpoint_auth_method":"none","redirect_uris":["REDIRECT","https://evil.invalid/cb"]}`,
		"confidential upgrade": `{"client_id":"c","client_secret":"s","token_endpoint_auth_method":"client_secret_post","redirect_uris":["REDIRECT"]}`,
	} {
		b, _ := notionFixture(t)
		base := b.provider.client.Transport
		b.provider.client.Transport = testTransportFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path != "/register" {
				return base.RoundTrip(r)
			}
			raw, _ := io.ReadAll(r.Body)
			var v struct {
				R []string `json:"redirect_uris"`
			}
			json.Unmarshal(raw, &v)
			return testReply(201, strings.ReplaceAll(reply, "REDIRECT", v.R[0])), nil
		})
		_, err := b.provider.registerNotion(context.Background(), "http://127.0.0.1:54321/oauth/callback")
		t.Logf("registration %-22s -> %v", name, err)
		if err == nil {
			t.Errorf("registration %s ACCEPTED", name)
		}
	}
}

func TestReviewCallbackHostReplayAndWrongState(t *testing.T) {
	b, _ := notionFixture(t)
	v, err := b.Handle(context.Background(), "connect", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(v.(FlowResult).URL)
	q := u.Query()
	redirect, _ := url.Parse(q.Get("redirect_uri"))
	t.Logf("listener %s (IPv4 loopback only)", redirect.Host)
	get := func(host, state string) int {
		req, _ := http.NewRequest("GET", q.Get("redirect_uri")+"?"+url.Values{"state": {state}, "code": {"fixture-code"}}.Encode(), nil)
		if host != "" {
			req.Host = host
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return -1
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if status := get("evil.invalid:"+redirect.Port(), q.Get("state")); status != 400 {
		t.Fatalf("invalid callback returned %d", status)
	}
	if status := get("localhost:"+redirect.Port(), q.Get("state")); status != 400 {
		t.Fatalf("invalid callback returned %d", status)
	}
	if status := get("", strings.Repeat("0", 64)); status != 400 {
		t.Fatalf("invalid callback returned %d", status)
	}
	first := get("", q.Get("state"))
	replay := get("", q.Get("state"))
	t.Logf("correct callback: %d, replay: %d", first, replay)
	ok, _ := connected(b)
	if first != 200 || !ok {
		t.Error("the refused attempts consumed the flow")
	}
	if replay == 200 {
		t.Error("REPLAY ACCEPTED")
	}
}

func TestReviewObsidianEntryAndDepthCaps(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	vault, b, _ := probeVault(t)
	deep := vault
	for i := 0; i < 30; i++ {
		deep = filepath.Join(deep, "d")
		os.Mkdir(deep, 0700)
	}
	os.WriteFile(filepath.Join(deep, "deepnote.md"), []byte("x"), 0600)
	b.Handle(context.Background(), "configure", mustJSON(map[string]string{"path": vault}))
	v, err := b.Handle(context.Background(), "search", []byte(`{"query":"deepnote"}`))
	if err != nil {
		t.Fatal(err)
	}
	r := v.(SourceSearch)
	t.Logf("note at depth 30: items=%d more=%v", len(r.Items), r.More)
	if len(r.Items) != 0 || !r.More {
		t.Error("depth cap")
	}
	vault2, b2, _ := probeVault(t)
	for i := 0; i < 10050; i++ {
		os.WriteFile(filepath.Join(vault2, fmt.Sprintf("f%05d.txt", i)), nil, 0600)
	}
	b2.Handle(context.Background(), "configure", mustJSON(map[string]string{"path": vault2}))
	v, err = b2.Handle(context.Background(), "search", []byte(`{"query":"nothing"}`))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("10,050 entries: more=%v", v.(SourceSearch).More)
	if !v.(SourceSearch).More {
		t.Error("entry cap")
	}
}

func TestReviewAttachmentCheckIsolatesIdentity(t *testing.T) {
	vault, b, s := probeVault(t)
	os.WriteFile(filepath.Join(vault, "n.md"), []byte("body"), 0600)
	b.Handle(context.Background(), "configure", mustJSON(map[string]string{"path": vault}))
	sel, err := grantFor(t, b, "n.md")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ReadObsidian(context.Background(), s, mustJSON(sel))
	if err != nil {
		t.Fatal(err)
	}
	if attachment.Check(raw) != nil {
		t.Fatal("honest record refused")
	}
	mutate := func(name string, f func(rec, src map[string]any)) {
		var rec map[string]any
		d := json.NewDecoder(strings.NewReader(string(raw)))
		d.UseNumber()
		d.Decode(&rec)
		f(rec, rec["provenance"].(map[string]any)["source"].(map[string]any))
		out, _ := json.Marshal(rec)
		err := attachment.Check(out)
		t.Logf("%-44s -> refused=%v", name, err != nil)
		if err == nil {
			t.Errorf("%s ACCEPTED", name)
		}
	}
	id := "11111111222233334444555555555555"
	mutate("notion identity on a foreign host", func(_, s map[string]any) {
		s["provider"], s["resourceId"], s["url"] = "notion", id, "https://evil.invalid/"+id
	})
	mutate("notion lookalike host", func(_, s map[string]any) {
		s["provider"], s["resourceId"], s["url"] = "notion", id, "https://www.notion.so.evil.invalid/"+id
	})
	mutate("obsidian url for a different note", func(_, s map[string]any) { s["url"] = "obsidian://open?file=other&vault=v" })
	mutate("obsidian https url", func(_, s map[string]any) { s["url"] = "https://evil.invalid/?vault=v&file=n" })
	mutate("hidden resource id", func(_, s map[string]any) {
		s["resourceId"], s["url"] = ".obsidian/n.md", "obsidian://open?file=.obsidian%2Fn&vault=v"
	})
	mutate("version is another digest", func(r, s map[string]any) {
		s["version"] = "sha256:" + strings.Repeat("0", 64)
		r["document"].(map[string]any)["version"] = s["version"]
	})
	mutate("extra Drive member on a connected source", func(_, s map[string]any) { s["fileId"] = "abc" })
	mutate("credential member", func(_, s map[string]any) { s["accessToken"] = "x" })
	mutate("original not retained", func(r, _ map[string]any) {
		r["original"] = map[string]any{"retention": "caller", "encoding": nil, "bytes": nil}
	})
	mutate("retained original is other bytes", func(r, _ map[string]any) { r["original"].(map[string]any)["bytes"] = "b3RoZXI=" })
}
