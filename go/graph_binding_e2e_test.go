package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// graphAPI is an invented directory on loopback that pages the way the
// directory service's documentation says it does (catalog/README.md): a
// collection names its next page by @odata.nextLink, an absolute URL with
// $skiptoken; the last page of a delta round names @odata.deltaLink, with
// $deltatoken; an expired delta token is answered 410; a throttled read
// 429 with Retry-After. It takes only the token last issued.
type graphAPI struct {
	mu       sync.Mutex
	token    string
	received []string
}

func (g *graphAPI) handler(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	g.received = append(g.received, r.RequestURI)
	token := g.token
	g.mu.Unlock()
	if token == "" || r.Header.Get("Authorization") != "Bearer "+token {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	origin := "http://" + r.Host
	w.Header().Set("Content-Type", "application/json")
	switch r.RequestURI {
	case "/v1.0/organization":
		io.WriteString(w, `{"value":[{"id":"9a8b7c6d-0000-4000-8000-000000000001","displayName":"Example Directory"}]}`)
	case "/v1.0/users?$top=2":
		fmt.Fprintf(w, `{"value":[{"id":"u-1"},{"id":"u-2"}],"@odata.nextLink":"%s/v1.0/users?$top=2&$skiptoken=RFNwdAIAAQ%%3d%%3d"}`, origin)
	case "/v1.0/users?$top=2&$skiptoken=RFNwdAIAAQ%3d%3d":
		io.WriteString(w, `{"value":[{"id":"u-3"}]}`)
	case "/v1.0/groups/delta":
		fmt.Fprintf(w, `{"value":[{"id":"g-1"}],"@odata.nextLink":"%s/v1.0/groups/delta?$skiptoken=gd-2"}`, origin)
	case "/v1.0/groups/delta?$skiptoken=gd-2":
		fmt.Fprintf(w, `{"value":[{"id":"g-2"}],"@odata.deltaLink":"%s/v1.0/groups/delta?$deltatoken=dt-1"}`, origin)
	case "/v1.0/groups/delta?$deltatoken=dt-expired":
		w.Header().Set("Location", origin+"/v1.0/groups/delta?$deltatoken=")
		w.WriteHeader(http.StatusGone)
		io.WriteString(w, `{"error":{"code":"resyncRequired"}}`)
	case "/v1.0/groups/1b4e28ba-2fa1-41d2-883f-0016d3cca427/members":
		io.WriteString(w, `{"value":[{"id":"u-1"}]}`)
	case "/v1.0/auditLogs/signIns":
		w.Header().Set("Retry-After", "9")
		w.WriteHeader(http.StatusTooManyRequests)
		io.WriteString(w, `{"error":{"code":"TooManyRequests"}}`)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// From the shipped binding to receipts, by the real adapter-http, with a
// token step of a federated identity against a stand-in token endpoint of
// the directory's form and a stand-in directory on loopback: a collection
// is paged by the next links its pages name and a delta round by its next
// and delta links, each followed as written, and each page's statement
// commits to the path and the query sent; a template's path is read with
// a GUID; an expired delta token is answered source_reference_expired, a
// throttled read 429 with its wait; and a link to another host is refused
// before any token is obtained for it. One token serves every page.
func TestAGraphSourceIsPagedByTheLinksItsPagesName(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	buildAdapterInto(t, bin, "adapter-http")
	const tenant = "5d2c1b0a-3e4f-4a5b-9c6d-7e8f9a0b1c2d"
	const federatedText = "federated-identity-token-graph-4e1a"
	var mu sync.Mutex
	tokenRequests := 0
	api := &graphAPI{}
	tokens := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		form := r.PostForm
		mu.Lock()
		defer mu.Unlock()
		tokenRequests++
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/"+tenant+"/oauth2/v2.0/token" || form.Get("grant_type") != "client_credentials" || form.Get("client_id") != "directory-reader" ||
			form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" || form.Get("client_assertion") != federatedText ||
			form.Get("scope") != "https://graph.microsoft.com/.default" {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"error":"invalid_request"}`)
			return
		}
		token := fmt.Sprintf("graph-access-%d", tokenRequests)
		api.mu.Lock()
		api.token = token
		api.mu.Unlock()
		io.WriteString(w, `{"access_token":"`+token+`","token_type":"Bearer","expires_in":3599}`)
	}))
	defer tokens.Close()
	graph := httptest.NewServer(http.HandlerFunc(api.handler))
	defer graph.Close()

	shipped, err := os.ReadFile(filepath.Join("..", "catalog", "microsoft-graph.json"))
	if err != nil {
		t.Fatal(err)
	}
	binding := strings.Replace(string(shipped), `"https://graph.microsoft.com"`, `"`+graph.URL+`"`, 1)
	catalog := catalogWith(t, map[string]string{"microsoft-graph": binding})
	credentials := filepath.Join(dir, "directory-live.json")
	if err := os.WriteFile(credentials, []byte(`{"token":"member-never-sent"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	federated := filepath.Join(dir, "federated.jwt")
	if err := os.WriteFile(federated, []byte(federatedText+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	escape := func(p string) string { return strings.ReplaceAll(p, `\`, `\\`) }
	config := func(version string) string {
		return `{"engineVersion":"` + version + `","authority":"gateway:test","seed":"` + escape(filepath.Join(dir, "gateway.seed")) + `","store":"` + escape(filepath.Join(dir, "store")) + `",` +
			`"registry":"` + escape(filepath.Join(dir, "registry.jsonl")) + `","decisionRecords":"` + escape(filepath.Join(dir, "decisions")) + `",` +
			`"listen":"127.0.0.1:0","catalog":"` + escape(catalog) + `","adapters":"` + escape(bin) + `","platforms":{` +
			`"directory":{"binding":"microsoft-graph@` + digestOf(binding) + `","credentials":{"live":{"file":"` + escape(credentials) + `",` +
			`"tokenStep":{"endpoint":"` + tokens.URL + `/` + tenant + `/oauth2/v2.0/token","clientId":"directory-reader","federatedTokenFile":"` + escape(federated) + `",` +
			`"requestScope":"https://graph.microsoft.com/.default"}}},"user":"engine-directory"}}}`
	}
	path := filepath.Join(dir, "engine.json")
	accounts := stubAccounts(map[string]int{"engine-directory": 1006})
	if err := os.WriteFile(path, []byte(config("30")), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadEngineConfig(path, accounts); err == nil || !strings.Contains(err.Error(), "a version-31 member; engineVersion 30 has none") {
		t.Fatalf("the shipped binding under version 30: %v", err)
	}
	if err := os.WriteFile(path, []byte(config("31")), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, bindings, err := loadEngineConfig(path, accounts)
	if err != nil {
		t.Fatal(err)
	}
	sources := deriveSources(cfg, bindings)
	for name, spec := range sources {
		spec.user, spec.sandbox = "", nil
		sources[name] = spec
	}
	live := sources["directory/live"]
	if !live.tokenStep || live.requestEndpoint != graph.URL {
		t.Fatalf("the source holds requests to its endpoint before a token: %+v", live)
	}
	report, err := runCheck(context.Background(), live)
	if err != nil {
		t.Fatalf("the check: %v", err)
	}
	if line, err := describeSourceCheck(live, report); err != nil || !strings.HasSuffix(line, "; GET /v1.0/organization answered 200") {
		t.Fatalf("the check as connect reads it: %q %v", line, err)
	}
	mu.Lock()
	checkTokens := tokenRequests
	mu.Unlock()

	service, err := buildService(cfg.store, testSeed, cfg.authority, cfg.registry, engineServeOptions(cfg, sources, nil))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(service.handler())
	defer server.Close()
	api.mu.Lock()
	api.received = nil
	api.mu.Unlock()

	// A link to another host, before any token is held: refused, nothing
	// requested of either endpoint.
	code, body := post(t, server, "/acquire", `{"session":"dir-x","source":"directory/live","arguments":{"link":"http://other.example/v1.0/users?$skiptoken=zq7","method":"GET"}}`)
	mu.Lock()
	requested := tokenRequests
	mu.Unlock()
	if code == http.StatusOK || !strings.Contains(fmt.Sprint(body), fmt.Sprintf(errTokenRequestNotAdmitted, "directory/live")) || strings.Contains(fmt.Sprint(body), "zq7") ||
		requested != checkTokens || len(api.received) != 0 {
		t.Fatalf("a link to another host: %d %v; %d token requests", code, body, requested-checkTokens)
	}

	committed := func(out map[string]any, statement string) bool {
		salt, err := hex.DecodeString(out["salts"].(map[string]any)["statement"].(string))
		if err != nil {
			return false
		}
		return out["receipt"].(map[string]any)["acquisition"].(map[string]any)["statement"] == commitmentOver(salt, "statement:", canon(vString(statement)))
	}
	acquire := func(session, arguments string) map[string]any {
		t.Helper()
		code, out := post(t, server, "/acquire", `{"session":"`+session+`","source":"directory/live","arguments":`+arguments+`}`)
		if code != http.StatusOK {
			t.Fatalf("%s: %d %v", arguments, code, out)
		}
		return out
	}
	link := func(out map[string]any, member string) string {
		s, _ := out["result"].(map[string]any)["body"].(map[string]any)[member].(string)
		return s
	}
	first := acquire("dir-users", `{"path":"/v1.0/users","method":"GET","query":{"$top":"2"}}`)
	if !committed(first, `{"method":"GET","path":"/v1.0/users","query":{"$top":"2"}}`) {
		t.Fatalf("a path request's statement: %v", first["receipt"])
	}
	next := link(first, "@odata.nextLink")
	second := acquire("dir-users", fmt.Sprintf(`{"link":%q,"method":"GET"}`, next))
	acquisition := second["receipt"].(map[string]any)["acquisition"].(map[string]any)
	if !committed(second, `{"method":"GET","path":"/v1.0/users","rawQuery":"$top=2&$skiptoken=RFNwdAIAAQ%3d%3d"}`) || acquisition["endpoint"] != graph.URL+"/v1.0/users" ||
		second["receipt"].(map[string]any)["callIndex"] != float64(1) {
		t.Fatalf("a link request's statement, endpoint and place in the session: %v", second["receipt"])
	}
	if link(second, "@odata.nextLink") != "" {
		t.Fatal("the last page names no next")
	}
	page := acquire("dir-groups", `{"path":"/v1.0/groups/delta","method":"GET"}`)
	page = acquire("dir-groups", fmt.Sprintf(`{"link":%q,"method":"GET"}`, link(page, "@odata.nextLink")))
	if delta := link(page, "@odata.deltaLink"); delta != graph.URL+"/v1.0/groups/delta?$deltatoken=dt-1" {
		t.Fatalf("the round ends with its delta link: %q", delta)
	}
	acquire("dir-members", `{"path":"/v1.0/groups/1b4e28ba-2fa1-41d2-883f-0016d3cca427/members","method":"GET"}`)

	expired := postRaw(t, server.URL, "/acquire", fmt.Sprintf(`{"session":"dir-delta","source":"directory/live","arguments":{"link":%q,"method":"GET"}}`, graph.URL+"/v1.0/groups/delta?$deltatoken=dt-expired"))
	if expired.code != http.StatusGone || !strings.Contains(expired.body, `"code":"source_reference_expired"`) || strings.Contains(expired.body, "dt-expired") {
		t.Fatalf("an expired delta token: %d %s", expired.code, expired.body)
	}
	throttled := postRaw(t, server.URL, "/acquire", `{"session":"dir-signins","source":"directory/live","arguments":{"path":"/v1.0/auditLogs/signIns","method":"GET"}}`)
	if throttled.code != http.StatusTooManyRequests || throttled.header.Get("Retry-After") != "9" {
		t.Fatalf("a throttled read: %d %v %s", throttled.code, throttled.header, throttled.body)
	}

	mu.Lock()
	requested = tokenRequests
	mu.Unlock()
	if requested != checkTokens+1 {
		t.Fatalf("one token serves every page: %d token requests", requested-checkTokens)
	}
	want := []string{
		"/v1.0/users?$top=2",
		"/v1.0/users?$top=2&$skiptoken=RFNwdAIAAQ%3d%3d",
		"/v1.0/groups/delta",
		"/v1.0/groups/delta?$skiptoken=gd-2",
		"/v1.0/groups/1b4e28ba-2fa1-41d2-883f-0016d3cca427/members",
		"/v1.0/groups/delta?$deltatoken=dt-expired",
		"/v1.0/auditLogs/signIns",
	}
	api.mu.Lock()
	received := append([]string(nil), api.received...)
	api.mu.Unlock()
	if !reflect.DeepEqual(received, want) {
		t.Fatalf("the requests as the directory received them:\n%s\nwant\n%s", strings.Join(received, "\n"), strings.Join(want, "\n"))
	}
}
