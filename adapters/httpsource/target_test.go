package httpsource

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// requestCase is one request of the table adapter-http and the engine
// answer to (testdata/http-requests/cases.json).
type requestCase struct {
	Rule      string          `json:"rule"`
	Request   json.RawMessage `json:"request"`
	Endpoint  string          `json:"endpoint"`
	Paths     []string        `json:"paths"`
	Methods   []string        `json:"methods"`
	PadLinkTo int             `json:"padLinkTo"`
	Path      *string         `json:"path"`
	RawQuery  *string         `json:"rawQuery"`
}

type requestTable struct {
	About     []string      `json:"about"`
	Endpoint  string        `json:"endpoint"`
	Paths     []string      `json:"paths"`
	Methods   []string      `json:"methods"`
	Rules     []string      `json:"rules"`
	Accepted  []requestCase `json:"accepted"`
	Refused   []requestCase `json:"refused"`
	Templates struct {
		Accepted []string `json:"accepted"`
		Refused  []struct {
			Rule string `json:"rule"`
			Path string `json:"path"`
		} `json:"refused"`
	} `json:"templates"`
}

// readRequestTable reads the table, held to its own rule: every case names
// a rule the table lists, every rule has a case on each side, and an
// accepted case says what is sent.
func readRequestTable(t *testing.T) requestTable {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "http-requests", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var table requestTable
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&table); err != nil {
		t.Fatal(err)
	}
	for _, rule := range table.Rules {
		var sides [2]int
		for side, cases := range [][]requestCase{table.Accepted, table.Refused} {
			for _, c := range cases {
				if c.Rule == rule {
					sides[side]++
				}
			}
		}
		if sides[0] == 0 || sides[1] == 0 {
			t.Fatalf("rule %s has %d accepted and %d refused cases; every rule has a case on each side", rule, sides[0], sides[1])
		}
	}
	for _, c := range append(append([]requestCase(nil), table.Accepted...), table.Refused...) {
		if !contains(table.Rules, c.Rule) {
			t.Fatalf("a case names rule %q, which the table does not list", c.Rule)
		}
	}
	for _, c := range table.Accepted {
		if c.Path == nil || c.RawQuery == nil {
			t.Fatalf("accepted case of rule %s says no path or no query sent", c.Rule)
		}
	}
	return table
}

// under is the case read under the table's endpoint, paths and methods
// unless it gives its own; its request, its link extended to padLinkTo;
// and, accepted, the query sent extended by the same.
func (c requestCase) under(t *testing.T, table requestTable) (cfg Config, request []byte, rawQuery string) {
	t.Helper()
	cfg = Config{Endpoint: table.Endpoint, Paths: table.Paths, Methods: table.Methods, MaxOutput: 1 << 20}
	if c.Endpoint != "" {
		cfg.Endpoint = c.Endpoint
	}
	if c.Paths != nil {
		cfg.Paths = c.Paths
	}
	if c.Methods != nil {
		cfg.Methods = c.Methods
	}
	request = c.Request
	if c.RawQuery != nil {
		rawQuery = *c.RawQuery
	}
	if c.PadLinkTo > 0 {
		var members map[string]any
		if err := json.Unmarshal(c.Request, &members); err != nil {
			t.Fatal(err)
		}
		link := members["link"].(string)
		pad := strings.Repeat("a", c.PadLinkTo-len(link))
		members["link"] = link + pad
		rawQuery += pad
		var err error
		if request, err = json.Marshal(members); err != nil {
			t.Fatal(err)
		}
	}
	return cfg, request, rawQuery
}

// The table's requests, as adapter-http reads and admits them: an accepted
// one forms a request whose path and query are the ones the case says,
// byte for byte, and a refused one is refused by ParseRequest or by
// admits, before anything is sent. The table's templates are held to the
// rule of a configured path.
func TestRequestsAreAdmittedAsTheTableSays(t *testing.T) {
	table := readRequestTable(t)
	for i, c := range table.Accepted {
		cfg, request, rawQuery := c.under(t, table)
		base, err := endpointOf(cfg.Endpoint)
		if err != nil {
			t.Fatalf("accepted %d (%s): endpoint: %v", i, c.Rule, err)
		}
		req, err := ParseRequest(bytes.NewReader(request))
		if err != nil {
			t.Errorf("accepted %d (%s): %s: %v", i, c.Rule, request, err)
			continue
		}
		p := &prepared{base: base, headers: http.Header{}}
		target, err := p.admits(cfg, req)
		if err != nil {
			t.Errorf("accepted %d (%s): %s: %v", i, c.Rule, request, err)
			continue
		}
		if target.path != *c.Path || target.rawQuery != rawQuery {
			t.Errorf("accepted %d (%s): target %q ? %q, want %q ? %q", i, c.Rule, target.path, target.rawQuery, *c.Path, rawQuery)
		}
		out, err := p.build(context.Background(), cfg, req)
		if err != nil {
			t.Fatalf("accepted %d (%s): build: %v", i, c.Rule, err)
		}
		want := strings.TrimSuffix(base.EscapedPath(), "/") + *c.Path
		if rawQuery != "" {
			want += "?" + rawQuery
		}
		if out.URL.RequestURI() != want || out.URL.Host != base.Host || out.URL.Scheme != base.Scheme {
			t.Errorf("accepted %d (%s): sent %s://%s%s, want %s://%s%s", i, c.Rule, out.URL.Scheme, out.URL.Host, out.URL.RequestURI(), base.Scheme, base.Host, want)
		}
	}
	for i, c := range table.Refused {
		cfg, request, _ := c.under(t, table)
		base, err := endpointOf(cfg.Endpoint)
		if err != nil {
			t.Fatalf("refused %d (%s): endpoint: %v", i, c.Rule, err)
		}
		req, err := ParseRequest(bytes.NewReader(request))
		if err != nil {
			continue
		}
		p := &prepared{base: base, headers: http.Header{}}
		if target, err := p.admits(cfg, req); err == nil {
			t.Errorf("refused %d (%s): %s admitted as %q ? %q", i, c.Rule, request, target.path, target.rawQuery)
		}
	}
	for _, path := range table.Templates.Accepted {
		if err := configuredPathProblem(path); err != nil {
			t.Errorf("template %s: %v", path, err)
		}
	}
	for _, c := range table.Templates.Refused {
		if err := configuredPathProblem(c.Path); err == nil {
			t.Errorf("template %s (%s) accepted", c.Path, c.Rule)
		}
	}
}

func TestIsGUIDIsTheFormAndNothingElse(t *testing.T) {
	for s, want := range map[string]bool{
		"6a1f0c2e-4b7d-4e9a-8c3f-2d5e7b9a1c40":   true,
		"6A1F0C2E-4B7D-4E9A-8C3F-2D5E7B9A1C40":   true,
		"00000000-0000-0000-0000-000000000000":   true,
		"6a1f0c2e-4b7d-4e9a-8c3f-2d5e7b9a1c4":    false,
		"6a1f0c2e-4b7d-4e9a-8c3f-2d5e7b9a1c400":  false,
		"6a1f0c2e-4b7d-4e9a-8c3f-2d5e7b9a1c4g":   false,
		"6a1f0c2e4b7d-4e9a-8c3f-2d5e7b9a1c40-":   false,
		"{6a1f0c2e-4b7d-4e9a-8c3f-2d5e7b9a1c40}": false,
		"6a1f0c2e-4b7d-4e9a-8c3f-2d5e7b9a1c4%":   false,
		"6a1f0c2e-4b7d-4e9a-8c3f-2d5e7b9a1c4/":   false,
		"6a1f0c2e-4b7d-4e9a-8c3f-2d5e7b9a1c.0":   false,
		"":                                       false,
	} {
		if isGUID(s) != want {
			t.Errorf("isGUID(%q) = %v", s, !want)
		}
	}
}

// A template is configured by the rule of a path, and a request reaches it
// only with a GUID in its one placeholder: anything else is refused before
// a connection is made, by its own sentence.
func TestATemplateAdmitsAGUIDAndNothingElse(t *testing.T) {
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"value":[]}`)
	})
	cfg := e.config(t)
	cfg.Methods = []string{http.MethodGet}
	for _, paths := range [][]string{{"/groups/{id}/members/{id}"}, {"/groups/x{id}"}, {"/groups/{name}"}} {
		bad := cfg
		bad.Paths = paths
		if _, err := Acquire(context.Background(), bad, Request{Path: "/groups", Method: http.MethodGet}); err == nil || !strings.Contains(err.Error(), "--paths") {
			t.Fatalf("%v: %v", paths, err)
		}
	}
	cfg.Paths = []string{"/groups/{id}/members"}
	for _, path := range []string{
		"/groups/6a1f0c2e-4b7d-4e9a-8c3f-2d5e7b9a1c40x/members",
		"/groups/6a1f0c2e-4b7d-4e9a-8c3f-2d5e7b9a1c4/members",
		"/groups/6a1f0c2e-4b7d-4e9a-8c3f-2d5e7b9a1c40/members/x",
		"/groups/members",
	} {
		req := parseRequest(t, `{"path":"`+path+`","method":"GET"}`)
		if _, err := Acquire(context.Background(), cfg, req); err == nil || !strings.Contains(err.Error(), "is not one this source may request") {
			t.Fatalf("%s: %v", path, err)
		}
	}
	if len(e.received()) != 0 {
		t.Fatal("a refused request never reaches the endpoint")
	}
	out, err := Acquire(context.Background(), cfg, parseRequest(t, `{"path":"/groups/6A1F0C2E-4B7D-4E9A-8C3F-2D5E7B9A1C40/members","method":"GET"}`))
	if err != nil {
		t.Fatal(err)
	}
	acq, _ := decodeEnvelope(t, out)
	if acq["statement"] != `{"method":"GET","path":"/groups/6A1F0C2E-4B7D-4E9A-8C3F-2D5E7B9A1C40/members"}` ||
		acq["endpoint"] != e.server.URL+"/groups/6A1F0C2E-4B7D-4E9A-8C3F-2D5E7B9A1C40/members" {
		t.Fatalf("the statement and the endpoint name the path sent, its {id} filled: %v", acq)
	}
}

// Each refusal of a link is its own fixed sentence, which names nothing of
// the link, and nothing is sent.
func TestLinkRefusalsNameNothingOfTheLink(t *testing.T) {
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"value":[]}`)
	})
	cfg := e.config(t)
	cfg.Paths = []string{"/v1.0/users", "/v1.0/groups/{id}/members"}
	cfg.Methods = []string{http.MethodGet}
	origin := e.server.URL // https://127.0.0.1:PORT
	_, port, _ := strings.Cut(strings.TrimPrefix(origin, "https://"), ":")
	const marker = "zq7marker"
	for link, want := range map[string]error{
		"https://other.example:" + port + "/v1.0/users?$skiptoken=" + marker:              errLinkHost,
		"https://localhost:" + port + "/v1.0/users?$skiptoken=" + marker:                  errLinkHost,
		"https://127.0.0.1:1/v1.0/users?$skiptoken=" + marker:                             errLinkPort,
		"https://127.0.0.1/v1.0/users?$skiptoken=" + marker:                               errLinkPort,
		"http://127.0.0.1:" + port + "/v1.0/users?$skiptoken=" + marker:                   errLinkScheme,
		"https://" + marker + "@127.0.0.1:" + port + "/v1.0/users":                        errLinkUser,
		origin + "/v1.0/users?$skiptoken=a#" + marker:                                     errLinkFragment,
		origin + "/v1.0/%75sers?$skiptoken=" + marker:                                     errLinkPercent,
		origin + "/v1.0/groups/../users?$skiptoken=" + marker:                             errLinkPathForm,
		origin + "/v1.0/./users?$skiptoken=" + marker:                                     errLinkPathForm,
		origin + "//v1.0/users?$skiptoken=" + marker:                                      errLinkPathForm,
		origin + "/v1.0//users?$skiptoken=" + marker:                                      errLinkPathForm,
		origin + "/v1.0/groups?$skiptoken=" + marker:                                      errLinkPath,
		origin + "/v1.0/groups/6a1f0c2e-4b7d-4e9a-8c3f-2d5e7b9a1c40x/members?m=" + marker: errLinkPath,
		origin + "/v1.0/users?$skiptoken=" + marker + "%zz":                               errLinkQuery,
		origin + "/v1.0/users?$filter=" + marker + "<1":                                   errLinkQuery,
	} {
		req, err := ParseRequest(strings.NewReader(fmt.Sprintf(`{"link":%q,"method":"GET"}`, link)))
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		_, err = Acquire(context.Background(), cfg, req)
		if !errors.Is(err, want) && (err == nil || err.Error() != want.Error()) {
			t.Errorf("%s: %v, want %v", link, err, want)
		}
		if err != nil && (strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), port)) {
			t.Errorf("%s: the refusal names something of the link: %v", link, err)
		}
	}
	for text, want := range map[string]string{
		`{"link":"` + origin + `/v1.0/users","path":"/v1.0/users"}`: `"path" and "link" each name what is requested; give one`,
		`{"link":"` + origin + `/v1.0/users","query":{"$top":"1"}}`: `a "link" carries its own query`,
		`{"link":1}`: `"link" must be a string`,
		`{"link":"` + origin + `/v1.0/users?$search=` + marker + ` x"}`:                             errLinkForm.Error(),
		`{"link":"` + origin + `/v1.0/users?$search=` + marker + `\u00e9"}`:                         errLinkForm.Error(),
		`{"link":"` + origin + `/v1.0/users?$skiptoken=` + strings.Repeat("a", maxLinkBytes) + `"}`: errLinkForm.Error(),
	} {
		_, err := ParseRequest(strings.NewReader(text))
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), marker) {
			t.Errorf("%.120s: %v, want %q", text, err, want)
		}
	}
	if len(e.received()) != 0 {
		t.Fatal("a refused link never reaches the endpoint")
	}
}

// graphStandIn is an invented directory over TLS that pages the way the
// directory service's documentation says it does: a page of a collection
// names the next one by @odata.nextLink, an absolute URL carrying
// $skiptoken; the last page of a delta round names @odata.deltaLink,
// carrying $deltatoken; a delta token no longer held is answered 410; and
// a throttled read is answered 429 with Retry-After. Every name in it is
// invented.
func graphStandIn(t *testing.T) *endpoint {
	var e *endpoint
	e = newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		origin := "https://" + r.Host
		if r.Header.Get("Authorization") != "Bearer secret-token-value" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json; odata.metadata=minimal")
		switch r.URL.Path + "?" + r.URL.RawQuery {
		case "/v1.0/users?$select=displayName,id&$top=2", "/v1.0/users?$select=displayName%2Cid&$top=2":
			fmt.Fprintf(w, `{"value":[{"id":"u-1","displayName":"Reader One"},{"id":"u-2","displayName":"Reader Two"}],"@odata.nextLink":"%s/v1.0/users?$select=displayName,id&$top=2&$skiptoken=RFNwdAIAAQAAAA%%3d%%3d"}`, origin)
		case "/v1.0/users?$select=displayName,id&$top=2&$skiptoken=RFNwdAIAAQAAAA%3d%3d":
			io.WriteString(w, `{"value":[{"id":"u-3","displayName":"Reader Three"}]}`)
		case "/v1.0/groups/delta?":
			fmt.Fprintf(w, `{"value":[{"id":"g-1","displayName":"Readers"}],"@odata.nextLink":"%s/v1.0/groups/delta?$skiptoken=gd-2"}`, origin)
		case "/v1.0/groups/delta?$skiptoken=gd-2":
			fmt.Fprintf(w, `{"value":[{"id":"g-2","displayName":"Approvers"}],"@odata.deltaLink":"%s/v1.0/groups/delta?$deltatoken=dt-1"}`, origin)
		case "/v1.0/groups/delta?$deltatoken=dt-1":
			fmt.Fprintf(w, `{"value":[],"@odata.deltaLink":"%s/v1.0/groups/delta?$deltatoken=dt-2"}`, origin)
		case "/v1.0/groups/delta?$deltatoken=dt-expired":
			w.Header().Set("Location", origin+"/v1.0/groups/delta?$deltatoken=")
			w.WriteHeader(http.StatusGone)
			io.WriteString(w, `{"error":{"code":"resyncRequired","message":"the token dt-expired is no longer held"}}`)
		case "/v1.0/groups/7c9e6679-7425-40de-944b-e07fc1f90ae7/members?":
			io.WriteString(w, `{"value":[{"@odata.type":"#microsoft.graph.user","id":"u-1"}]}`)
		case "/v1.0/auditLogs/signIns?$top=1":
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			io.WriteString(w, `{"error":{"code":"TooManyRequests"}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"error":{"code":"notFound","path":%q}}`, r.URL.RequestURI())
		}
	})
	return e
}

func graphConfig(t *testing.T, e *endpoint) Config {
	cfg := e.config(t)
	cfg.Paths = []string{"/v1.0/users", "/v1.0/groups/delta", "/v1.0/groups/{id}/members", "/v1.0/auditLogs/signIns"}
	cfg.Methods = []string{http.MethodGet}
	return cfg
}

// nextLink is the link a page names under the member, or "".
func nextLink(t *testing.T, out []byte, member string) string {
	t.Helper()
	_, result := decodeEnvelope(t, out)
	body, _ := result["body"].(map[string]any)
	link, _ := body[member].(string)
	return link
}

// A collection is paged by its next links and a delta round by its next
// and delta links, each followed as the endpoint wrote it: the request
// sent is the link's path and query, byte for byte, and the statement
// commits to that path and that query. A path request's $ options are
// sent as written too.
func TestGraphPagesAreFollowedByTheLinksTheyName(t *testing.T) {
	e := graphStandIn(t)
	cfg := graphConfig(t, e)
	acquire := func(request string) []byte {
		t.Helper()
		out, err := Acquire(context.Background(), cfg, parseRequest(t, request))
		if err != nil {
			t.Fatalf("%s: %v", request, err)
		}
		return out
	}
	first := acquire(`{"path":"/v1.0/users","method":"GET","query":{"$top":"2","$select":"displayName,id"}}`)
	acq, _ := decodeEnvelope(t, first)
	if acq["statement"] != `{"method":"GET","path":"/v1.0/users","query":{"$select":"displayName,id","$top":"2"}}` {
		t.Fatalf("a path request's statement: %v", acq["statement"])
	}
	next := nextLink(t, first, "@odata.nextLink")
	if !strings.HasPrefix(next, e.server.URL+"/v1.0/users?") {
		t.Fatalf("the first page names its next: %q", next)
	}
	second := acquire(fmt.Sprintf(`{"link":%q,"method":"GET"}`, next))
	acq, _ = decodeEnvelope(t, second)
	if acq["statement"] != `{"method":"GET","path":"/v1.0/users","rawQuery":"$select=displayName,id&$top=2&$skiptoken=RFNwdAIAAQAAAA%3d%3d"}` ||
		acq["endpoint"] != e.server.URL+"/v1.0/users" {
		t.Fatalf("a link request's statement and endpoint: %v %v", acq["statement"], acq["endpoint"])
	}
	if nextLink(t, second, "@odata.nextLink") != "" {
		t.Fatal("the last page names no next")
	}

	page := acquire(`{"path":"/v1.0/groups/delta","method":"GET"}`)
	var delta string
	for i := 0; i < 4 && delta == ""; i++ {
		if next := nextLink(t, page, "@odata.nextLink"); next != "" {
			page = acquire(fmt.Sprintf(`{"link":%q,"method":"GET"}`, next))
			continue
		}
		delta = nextLink(t, page, "@odata.deltaLink")
	}
	if delta != e.server.URL+"/v1.0/groups/delta?$deltatoken=dt-1" {
		t.Fatalf("the round ends with its delta link: %q", delta)
	}
	if again := nextLink(t, acquire(fmt.Sprintf(`{"link":%q,"method":"GET"}`, delta)), "@odata.deltaLink"); !strings.HasSuffix(again, "dt-2") {
		t.Fatalf("a delta link read later names the next one: %q", again)
	}
	members := acquire(`{"path":"/v1.0/groups/7c9e6679-7425-40de-944b-e07fc1f90ae7/members","method":"GET"}`)
	if _, result := decodeEnvelope(t, members); result["status"] != float64(200) {
		t.Fatalf("a template's path is read: %v", result)
	}

	var sent []string
	for _, r := range e.received() {
		sent = append(sent, r.RequestURI)
	}
	want := []string{
		"/v1.0/users?$select=displayName%2Cid&$top=2",
		"/v1.0/users?$select=displayName,id&$top=2&$skiptoken=RFNwdAIAAQAAAA%3d%3d",
		"/v1.0/groups/delta",
		"/v1.0/groups/delta?$skiptoken=gd-2",
		"/v1.0/groups/delta?$deltatoken=dt-1",
		"/v1.0/groups/7c9e6679-7425-40de-944b-e07fc1f90ae7/members",
	}
	if strings.Join(sent, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the requests as the endpoint received them:\n%s\nwant\n%s", strings.Join(sent, "\n"), strings.Join(want, "\n"))
	}
}

// An expired delta token is answered 410 and reported as an expired
// reference, by its class, with nothing of the link; a throttled read is
// reported with the wait the endpoint asked for.
func TestGraphExpiredTokenAndThrottleAreReportedByTheirClass(t *testing.T) {
	e := graphStandIn(t)
	cfg := graphConfig(t, e)
	_, err := Acquire(context.Background(), cfg, parseRequest(t, fmt.Sprintf(`{"link":%q,"method":"GET"}`, e.server.URL+"/v1.0/groups/delta?$deltatoken=dt-expired")))
	var expired *ReferenceExpired
	if !errors.As(err, &expired) || !strings.Contains(err.Error(), "410") {
		t.Fatalf("an expired delta token is an expired reference: %v", err)
	}
	if !bytes.Equal(expired.Report(), []byte(`{"referenceExpired":{"status":410}}`)) {
		t.Fatalf("its report: %s", expired.Report())
	}
	_, err = Acquire(context.Background(), cfg, parseRequest(t, `{"path":"/v1.0/auditLogs/signIns","method":"GET","query":{"$top":"1"}}`))
	var throttled *Throttled
	if !errors.As(err, &throttled) || throttled.Status != http.StatusTooManyRequests || throttled.RetryAfter == nil || *throttled.RetryAfter != 7 {
		t.Fatalf("a throttled read carries its wait: %v", err)
	}
}
