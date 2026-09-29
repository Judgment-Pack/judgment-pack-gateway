//go:build linux || darwin

package connections

// Each test here holds one refusal or one bound of the search connections.
// Each was checked by taking the condition out of web_search.go and seeing
// the test fail.
//
// Four conditions cannot be told apart from their absence by any test,
// because another condition refuses the same input first:
//
//   - a saved credential is kept on an update only for the same provider: a
//     credential of the other provider is refused by that provider's form;
//   - the credential's type is a service account: the library that reads the
//     credential refuses any other;
//   - the token endpoint the library derives is Google's: the member it is
//     derived from is held to the same value first;
//   - the credential has a key: no key is a key that does not parse.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// searchAnswering is a provider whose search endpoint is a local TLS server
// giving one status and one body to every request.
func searchAnswering(t *testing.T, status int, body []byte) provider {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write(body)
	}))
	t.Cleanup(server.Close)
	p := google()
	p.search = true
	p.client = server.Client()
	p.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	p.searchEndpoint = server.URL
	return p
}

func configureSearch(b *Broker, fields map[string]any) error {
	raw, _ := json.Marshal(fields)
	_, err := b.Handle(context.Background(), "configure", raw)
	return err
}

func searchRows(t *testing.T, b *Broker) []SearchConnection {
	t.Helper()
	out, err := b.Handle(context.Background(), "status", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	return out.(map[string]any)["connections"].([]SearchConnection)
}

var searchKeys struct {
	once         sync.Once
	strong, weak []byte
}

// serviceAccount is a service account credential as Google writes one, with
// the members a case changes or, given an empty value, leaves out.
func serviceAccount(t *testing.T, weak bool, change map[string]string) string {
	t.Helper()
	searchKeys.once.Do(func() {
		for _, bits := range []int{2048, 1024} {
			key, err := rsa.GenerateKey(rand.Reader, bits)
			if err != nil {
				t.Fatal(err)
			}
			der, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
			if bits == 2048 {
				searchKeys.strong = encoded
			} else {
				searchKeys.weak = encoded
			}
		}
	})
	key := searchKeys.strong
	if weak {
		key = searchKeys.weak
	}
	members := map[string]string{"type": "service_account", "client_email": "reader@demo-project.iam.gserviceaccount.com", "private_key": string(key), "token_uri": "https://oauth2.googleapis.com/token"}
	for name, value := range change {
		if value == "" {
			delete(members, name)
		} else {
			members[name] = value
		}
	}
	raw, _ := json.Marshal(members)
	return string(raw)
}

func TestSearchConfigureTakesNoCounterFromTheCaller(t *testing.T) {
	_, b, _ := searchFixture(t)
	for _, extra := range []map[string]any{{"requests": 3}, {"day": "2026-09-29"}} {
		fields := map[string]any{"id": "second", "name": "Second", "provider": "tavily", "dailyLimit": 5, "credential": "tvly-second"}
		for name, value := range extra {
			fields[name] = value
		}
		if err := configureSearch(b, fields); err != ErrRequest {
			t.Fatalf("a counter from the caller was taken: %v, %v", extra, err)
		}
	}
	if rows := searchRows(t, b); len(rows) != 1 {
		t.Fatalf("a refused connection was saved: %d", len(rows))
	}
}

func TestSearchHoldsAtMostSixConnections(t *testing.T) {
	_, b, _ := searchFixture(t)
	for _, id := range []string{"two", "three", "four", "five", "six"} {
		if err := configureSearch(b, map[string]any{"id": id, "name": id, "provider": "tavily", "dailyLimit": 5, "credential": "tvly-" + id}); err != nil {
			t.Fatal(id, err)
		}
	}
	if err := configureSearch(b, map[string]any{"id": "seven", "name": "seven", "provider": "tavily", "dailyLimit": 5, "credential": "tvly-seven"}); err != ErrRequest {
		t.Fatal("a seventh connection was saved", err)
	}
	if rows := searchRows(t, b); len(rows) != 6 {
		t.Fatalf("connections held: %d", len(rows))
	}
}

func TestSearchNewConnectionCarriesNoRevision(t *testing.T) {
	_, b, _ := searchFixture(t)
	if err := configureSearch(b, map[string]any{"id": "second", "revision": strings.Repeat("a", 64), "name": "Second", "provider": "tavily", "dailyLimit": 5, "credential": "tvly-second"}); err != ErrRequest {
		t.Fatal("a connection that never existed was updated", err)
	}
}

func TestSearchDisconnectNeedsTheCurrentRevision(t *testing.T) {
	_, b, c := searchFixture(t)
	stale, _ := json.Marshal(map[string]string{"id": c.ID, "revision": strings.Repeat("0", 64)})
	if _, err := b.Handle(context.Background(), "disconnect", stale); err != ErrChanged {
		t.Fatal("a stale revision disconnected", err)
	}
	if rows := searchRows(t, b); len(rows) != 1 {
		t.Fatal("the connection is gone after a refused disconnect")
	}
	current, _ := json.Marshal(map[string]string{"id": c.ID, "revision": c.Revision})
	if _, err := b.Handle(context.Background(), "disconnect", current); err != nil {
		t.Fatal(err)
	}
	if rows := searchRows(t, b); len(rows) != 0 {
		t.Fatal("the connection remains after its disconnect")
	}
}

func TestSearchIsRefusedUnderABlockAndSpendsNothing(t *testing.T) {
	s, _, c := searchFixture(t)
	s.locked(func(v *state) error { v.Disabled = true; return s.write("state.json", v) })
	if _, err := searchSnapshot(s, SearchRequest{c.ID, c.Revision, "query", 1}); err != ErrPolicy {
		t.Fatal("a blocked connection was read", err)
	}
	s.locked(func(v *state) error {
		if v.Search.Connections[0].Requests != 0 {
			t.Error("a refused request was counted")
		}
		return nil
	})
}

func TestSearchRefusesAnAnswerThatArrivesUnderABlock(t *testing.T) {
	s, _, c := searchFixture(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.locked(func(v *state) error { v.Disabled = true; return s.write("state.json", v) })
		w.Write([]byte(`{"results":[{"url":"https://example.org"}]}`))
	}))
	defer server.Close()
	p := google()
	p.client = server.Client()
	p.searchEndpoint = server.URL
	if _, err := searchAcquire(context.Background(), s, SearchRequest{c.ID, c.Revision, "query", 1}, p); err != ErrPolicy {
		t.Fatal("an answer was kept though the connection was blocked meanwhile", err)
	}
}

func TestSearchRefusesAnAnswerThatRepeatsTheCredential(t *testing.T) {
	s, _, c := searchFixture(t)
	body, _ := json.Marshal(map[string]any{"results": []map[string]string{{"title": "Echo", "url": "https://example.org/echo", "content": "sent with " + c.Credential}}})
	raw, err := searchAcquire(context.Background(), s, SearchRequest{c.ID, c.Revision, "query", 1}, searchAnswering(t, 200, body))
	if err != ErrProvider || len(raw) != 0 {
		t.Fatal("an answer carrying the credential was kept", err)
	}
}

func TestSearchRefusesAnAnswerOverItsBound(t *testing.T) {
	s, _, c := searchFixture(t)
	// A whole answer followed by spaces: cut at any length it still parses,
	// so only the bound refuses it.
	answer := []byte(`{"results":[{"title":"Policy","url":"https://example.org/policy","content":"A snippet"}]}`)
	within := append(append([]byte{}, answer...), bytes.Repeat([]byte(" "), 2<<20-len(answer))...)
	if _, err := searchAcquire(context.Background(), s, SearchRequest{c.ID, c.Revision, "query", 1}, searchAnswering(t, 200, within)); err != nil {
		t.Fatal("an answer of exactly the bound was refused", err)
	}
	if _, err := searchAcquire(context.Background(), s, SearchRequest{c.ID, c.Revision, "query", 1}, searchAnswering(t, 200, append(within, ' '))); err != ErrProvider {
		t.Fatal("an answer over the bound was kept", err)
	}
}

func TestSearchRefusesAnAnswerThatIsNotUTF8(t *testing.T) {
	s, _, c := searchFixture(t)
	body := []byte("{\"results\":[{\"title\":\"\xff\",\"url\":\"https://example.org/policy\",\"content\":\"\"}]}")
	if _, err := searchAcquire(context.Background(), s, SearchRequest{c.ID, c.Revision, "query", 1}, searchAnswering(t, 200, body)); err != ErrProvider {
		t.Fatal("an answer that is not UTF-8 was kept", err)
	}
}

func TestSearchNamesWhyTheProviderRefused(t *testing.T) {
	// The body is a whole answer, so a status that is let through yields a
	// result and not an error of another name.
	body := []byte(`{"results":[{"title":"Policy","url":"https://example.org/policy","content":"A snippet"}]}`)
	for status, want := range map[int]Error{401: "credentials-required", 403: "credentials-required", 429: "rate-limited", 500: ErrProvider, 204: ErrProvider, 302: ErrProvider} {
		s, _, c := searchFixture(t)
		raw, err := searchAcquire(context.Background(), s, SearchRequest{c.ID, c.Revision, "query", 1}, searchAnswering(t, status, body))
		if err != want || len(raw) != 0 {
			t.Fatalf("status %d: %v, %d bytes", status, err, len(raw))
		}
	}
}

func TestSearchHitsAreLinksOverHTTPSAlone(t *testing.T) {
	c := SearchConnection{ID: "demo", Provider: "tavily", Revision: strings.Repeat("a", 64)}
	for _, refused := range []string{"http://example.org/plain", "https://reader@example.org/named", "https://example.org:8443/port", "https:///nowhere"} {
		body, _ := json.Marshal(map[string]any{"results": []map[string]string{{"title": "Refused", "url": refused}, {"title": "Kept", "url": "https://example.org:443/kept"}}})
		r, err := normalizeSearch(body, c, SearchRequest{c.ID, c.Revision, "query", 5})
		if err != nil || len(r.Hits) != 1 || r.Hits[0].URL != "https://example.org:443/kept" {
			t.Fatalf("%s: %v, %v", refused, r.Hits, err)
		}
	}
}

func TestSearchGivesNoMoreHitsThanAsked(t *testing.T) {
	c := SearchConnection{ID: "demo", Provider: "tavily", Revision: strings.Repeat("a", 64)}
	body := []byte(`{"results":[{"url":"https://example.org/1"},{"url":"https://example.org/2"},{"url":"https://example.org/3"}]}`)
	r, err := normalizeSearch(body, c, SearchRequest{c.ID, c.Revision, "query", 2})
	if err != nil || len(r.Hits) != 2 || r.Hits[1].URL != "https://example.org/2" {
		t.Fatal(r.Hits, err)
	}
}

func TestSearchHitIsHeldToItsLength(t *testing.T) {
	c := SearchConnection{ID: "demo", Provider: "tavily", Revision: strings.Repeat("a", 64)}
	atBound := "https://example.org/" + strings.Repeat("a", 4096-len("https://example.org/"))
	body, _ := json.Marshal(map[string]any{"results": []map[string]string{
		{"title": strings.Repeat("t", 511) + "é", "url": atBound + "a", "content": "over the bound by one"},
		{"title": strings.Repeat("t", 511) + "é", "url": atBound, "content": strings.Repeat("s", 1999) + "é"},
	}})
	r, err := normalizeSearch(body, c, SearchRequest{c.ID, c.Revision, "query", 5})
	if err != nil || len(r.Hits) != 1 || r.Hits[0].URL != atBound {
		t.Fatal("a link over its bound was kept, or one at its bound refused", len(r.Hits), err)
	}
	// The last character of each is two bytes and crosses the bound, so it
	// goes whole: what is kept is one byte short and still UTF-8.
	if r.Hits[0].Title != strings.Repeat("t", 511) || r.Hits[0].Snippet != strings.Repeat("s", 1999) {
		t.Fatalf("title of %d bytes, snippet of %d", len(r.Hits[0].Title), len(r.Hits[0].Snippet))
	}
}

func TestGoogleAnswerIsCutAtItsBound(t *testing.T) {
	c := SearchConnection{ID: "google", Provider: "google-grounding", Revision: strings.Repeat("a", 64)}
	body, _ := json.Marshal(map[string]any{"candidates": []any{map[string]any{
		"content": map[string]any{"parts": []map[string]string{{"text": strings.Repeat("a", 11999)}, {"text": "é and more"}}},
		"groundingMetadata": map[string]any{
			"groundingChunks":  []any{map[string]any{"web": map[string]string{"uri": "https://example.org", "title": "Source"}}},
			"searchEntryPoint": map[string]string{"renderedContent": "<div>Google Search</div>"},
			"webSearchQueries": []string{strings.Repeat("q", 1999) + "é"},
		},
	}}})
	r, err := normalizeSearch(body, c, SearchRequest{c.ID, c.Revision, "query", 5})
	if err != nil || r.GeneratedAnswer != strings.Repeat("a", 11999) || len(r.Queries) != 1 || r.Queries[0] != strings.Repeat("q", 1999) {
		t.Fatalf("answer of %d bytes, %d queries: %v", len(r.GeneratedAnswer), len(r.Queries), err)
	}
}

func TestSearchBudgetIsOfTheDay(t *testing.T) {
	s, b, c := searchFixture(t)
	s.locked(func(v *state) error {
		v.Search.Connections[0].Day = "2000-01-01"
		v.Search.Connections[0].Requests = c.DailyLimit
		return s.write("state.json", v)
	})
	if rows := searchRows(t, b); len(rows) != 1 || rows[0].Requests != 0 {
		t.Fatalf("the status counts another day's requests: %+v", rows)
	}
	if _, err := searchSnapshot(s, SearchRequest{c.ID, c.Revision, "query", 1}); err != nil {
		t.Fatal("another day's requests were held against this one", err)
	}
	s.locked(func(v *state) error {
		if got := v.Search.Connections[0]; got.Requests != 1 || got.Day == "2000-01-01" {
			t.Errorf("after one request of a new day: %d on %s", got.Requests, got.Day)
		}
		return nil
	})
}

func TestGoogleAnswerIsRefusedWithoutItsGrounding(t *testing.T) {
	c := SearchConnection{ID: "google", Provider: "google-grounding", Revision: strings.Repeat("a", 64)}
	q := SearchRequest{c.ID, c.Revision, "query", 5}
	answer := func(chunks, entry, queries string) []byte {
		return []byte(`{"candidates":[{"content":{"parts":[{"text":"Generated"}]},"groundingMetadata":{"groundingChunks":` + chunks + `,"searchEntryPoint":` + entry + `,"webSearchQueries":` + queries + `}}]}`)
	}
	chunk := `[{"web":{"uri":"https://example.org","title":"Source"}}]`
	entry := `{"renderedContent":"<div>Google Search</div>"}`
	long, _ := json.Marshal(map[string]string{"renderedContent": strings.Repeat("a", 32001)})
	atBound, _ := json.Marshal(map[string]string{"renderedContent": strings.Repeat("a", 32000)})
	many, _ := json.Marshal(make([]string, 21))
	twenty, _ := json.Marshal(make([]string, 20))
	for name, test := range map[string]struct {
		body []byte
		want error
	}{
		"as it should be":               {answer(chunk, entry, `["query"]`), nil},
		"no sources":                    {answer(`[]`, entry, `["query"]`), Error("search-not-grounded")},
		"sources that are not links":    {answer(`[{"web":{"uri":"http://example.org","title":"Source"}}]`, entry, `["query"]`), Error("search-not-grounded")},
		"no attribution":                {answer(chunk, `{}`, `["query"]`), Error("search-not-grounded")},
		"attribution at its bound":      {answer(chunk, string(atBound), `["query"]`), nil},
		"attribution over its bound":    {answer(chunk, string(long), `["query"]`), ErrProvider},
		"as many queries as are kept":   {answer(chunk, entry, string(twenty)), nil},
		"more queries than are kept":    {answer(chunk, entry, string(many)), ErrProvider},
		"an answer that is not a value": {[]byte(`{"candidates":`), ErrProvider},
		"no candidate":                  {[]byte(`{"candidates":[]}`), ErrProvider},
	} {
		if _, err := normalizeSearch(test.body, c, q); err != test.want {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestGoogleCredentialIsHeldToItsForm(t *testing.T) {
	if err := validateGoogleCredential(serviceAccount(t, false, nil)); err != nil {
		t.Fatal("a credential as Google writes one was refused", err)
	}
	for name, credential := range map[string]string{
		"no token endpoint":      serviceAccount(t, false, map[string]string{"token_uri": ""}),
		"another token endpoint": serviceAccount(t, false, map[string]string{"token_uri": "https://evil.example/token"}),
		"not a service account":  serviceAccount(t, false, map[string]string{"client_email": "reader@example.org"}),
		"a key of 1024 bits":     serviceAccount(t, true, nil),
		"no key":                 serviceAccount(t, false, map[string]string{"private_key": ""}),
		"a key that is no key":   serviceAccount(t, false, map[string]string{"private_key": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"}),
		// Refused by the library that reads the credential as well as by the
		// check of the type here, so this case holds the two together.
		"a user's credential": serviceAccount(t, false, map[string]string{"type": "authorized_user"}),
		"not a value":         "{",
	} {
		if validateGoogleCredential(credential) != ErrRequest {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestSearchConnectionIsHeldToItsBounds(t *testing.T) {
	tavily := SearchConnection{ID: "demo", Name: "Demo", Provider: "tavily", DailyLimit: 10, Credential: "tvly-key"}
	grounding := SearchConnection{ID: "demo", Name: "Demo", Provider: "google-grounding", DailyLimit: 10, Credential: serviceAccount(t, false, nil), Project: "demo-project", Location: "us-central1", Model: "gemini-2.5-flash"}
	if !searchValid(tavily) || !searchValid(grounding) {
		t.Fatal("the cases start from a connection that is refused")
	}
	for name, change := range map[string]func(*SearchConnection){
		"identifier":              func(c *SearchConnection) { c.ID = "Demo" },
		"no name":                 func(c *SearchConnection) { c.Name = "" },
		"no requests a day":       func(c *SearchConnection) { c.DailyLimit = 0 },
		"over the daily bound":    func(c *SearchConnection) { c.DailyLimit = 10001 },
		"a key with a space":      func(c *SearchConnection) { c.Credential = "tvly key" },
		"a key with a line end":   func(c *SearchConnection) { c.Credential = "tvly-key\n" },
		"no key":                  func(c *SearchConnection) { c.Credential = "" },
		"a project for Tavily":    func(c *SearchConnection) { c.Project = "demo-project" },
		"a location for Tavily":   func(c *SearchConnection) { c.Location = "global" },
		"a model for Tavily":      func(c *SearchConnection) { c.Model = "gemini-2.5-flash" },
		"a provider of no name":   func(c *SearchConnection) { c.Provider = "" },
		"a provider not known":    func(c *SearchConnection) { c.Provider = "other" },
		"a credential over 8192":  func(c *SearchConnection) { c.Credential = strings.Repeat("a", 8193) },
		"a name over eighty":      func(c *SearchConnection) { c.Name = strings.Repeat("a", 81) },
		"an identifier over 48":   func(c *SearchConnection) { c.ID = strings.Repeat("a", 49) },
		"an identifier of a path": func(c *SearchConnection) { c.ID = "a/b" },
	} {
		c := tavily
		change(&c)
		if searchValid(c) {
			t.Fatalf("Tavily, %s: accepted", name)
		}
	}
	for name, change := range map[string]func(*SearchConnection){
		"a project that is a path":   func(c *SearchConnection) { c.Project = "demo/../other" },
		"a project in capitals":      func(c *SearchConnection) { c.Project = "Demo-Project" },
		"a location that is a host":  func(c *SearchConnection) { c.Location = "evil.example" },
		"a location with a path":     func(c *SearchConnection) { c.Location = "us-central1/x" },
		"a model that is not Gemini": func(c *SearchConnection) { c.Model = "other-model" },
		"a model with a path":        func(c *SearchConnection) { c.Model = "gemini-2.5-flash/../x" },
		"a model with a verb":        func(c *SearchConnection) { c.Model = "gemini-2.5-flash:predict" },
		"no project":                 func(c *SearchConnection) { c.Project = "" },
		"no location":                func(c *SearchConnection) { c.Location = "" },
		"no model":                   func(c *SearchConnection) { c.Model = "" },
		"a key of 1024 bits":         func(c *SearchConnection) { c.Credential = serviceAccount(t, true, nil) },
		// A credential of the right form, and too long only by a member
		// that nothing reads.
		"a credential over 8192": func(c *SearchConnection) {
			c.Credential = serviceAccount(t, false, map[string]string{"note": strings.Repeat("a", 8192)})
		},
	} {
		c := grounding
		change(&c)
		if searchValid(c) {
			t.Fatalf("Google, %s: accepted", name)
		}
	}
}

func TestSearchRecordNamesWhatWasAskedAndWhatWasAnswered(t *testing.T) {
	s, _, c := searchFixture(t)
	body := []byte(`{"results":[{"title":"Policy","url":"https://example.org/policy","content":"A snippet"}]}`)
	p := searchAnswering(t, 200, body)
	raw, err := searchAcquire(context.Background(), s, SearchRequest{c.ID, c.Revision, "find policies", 3}, p)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Acquisition struct {
			Endpoint, Statement, Snapshot string
			Adapter                       struct{ Name string }
		}
	}
	if err = json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	var statement map[string]any
	if err = json.Unmarshal([]byte(envelope.Acquisition.Statement), &statement); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"connection": c.ID, "revision": c.Revision, "provider": "tavily", "query": "find policies", "maxResults": float64(3), "method": "POST", "endpoint": p.searchEndpoint}
	if len(statement) != len(want) {
		t.Fatalf("statement: %v", statement)
	}
	for name, value := range want {
		if statement[name] != value {
			t.Fatalf("statement %s: %v", name, statement[name])
		}
	}
	if envelope.Acquisition.Snapshot != digest(body) {
		t.Fatal("the snapshot is not the digest of the answer as the provider sent it")
	}
	if envelope.Acquisition.Endpoint != p.searchEndpoint || envelope.Acquisition.Adapter.Name != "adapter-sources" {
		t.Fatalf("acquisition: %+v", envelope.Acquisition)
	}
	if bytes.Contains(raw, []byte(c.Credential)) {
		t.Fatal("the record carries the credential")
	}
}

func TestSearchTestSaysOnlyWhetherItWorkedAndIsCounted(t *testing.T) {
	_, b, c := searchFixture(t)
	b.provider = searchAnswering(t, 200, []byte(`{"results":[{"title":"Policy","url":"https://example.org/policy","content":"A snippet"}]}`))
	request, _ := json.Marshal(map[string]string{"id": c.ID, "revision": c.Revision})
	out, err := b.Handle(context.Background(), "test", request)
	if err != nil {
		t.Fatal(err)
	}
	if said, _ := json.Marshal(out); string(said) != `{"ok":true}` {
		t.Fatalf("the test said %s", said)
	}
	if rows := searchRows(t, b); len(rows) != 1 || rows[0].Requests != 1 {
		t.Fatalf("the test was not counted: %+v", rows)
	}
}

func TestTavilyIsAskedForResultsAndNothingWritten(t *testing.T) {
	s, _, c := searchFixture(t)
	var asked map[string]any
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent, _ := io.ReadAll(r.Body)
		if r.Method != "POST" || json.Unmarshal(sent, &asked) != nil {
			t.Error("the request is not a JSON value sent by POST")
		}
		w.Write([]byte(`{"results":[{"url":"https://example.org"}]}`))
	}))
	defer server.Close()
	p := google()
	p.client = server.Client()
	p.searchEndpoint = server.URL
	if _, err := searchAcquire(context.Background(), s, SearchRequest{c.ID, c.Revision, "find policies", 4}, p); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"query": "find policies", "max_results": float64(4), "search_depth": "basic", "include_answer": false, "include_raw_content": false}
	if len(asked) != len(want) {
		t.Fatalf("asked: %v", asked)
	}
	for name, value := range want {
		if asked[name] != value {
			t.Fatalf("asked %s: %v", name, asked[name])
		}
	}
}
