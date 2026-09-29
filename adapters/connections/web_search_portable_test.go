package connections

// Tests of the search connections that need neither the custody store nor a
// listener, so they run on every platform the package builds for. The tests
// that need either are in web_search_safeguards_test.go, and what is said
// there of how these were checked holds here.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"sync"
	"testing"
)

func TestGoogleGroundingRetainsGeneratedContentAndAttributionSeparately(t *testing.T) {
	c := SearchConnection{ID: "google", Provider: "google-grounding", Revision: strings.Repeat("a", 64)}
	q := SearchRequest{c.ID, c.Revision, "query", 5}
	raw := []byte(`{"candidates":[{"content":{"parts":[{"text":"Generated claim"}]},"groundingMetadata":{"groundingChunks":[{"web":{"uri":"https://example.org","title":"Source"}}],"searchEntryPoint":{"renderedContent":"<div>Google Search</div>"},"webSearchQueries":["query"]}}]}`)
	r, err := normalizeSearch(raw, c, q)
	if err != nil || r.Kind != "grounded-answer" || r.GeneratedAnswer != "Generated claim" || r.Hits[0].Snippet != "" || r.AttributionHTML == "" {
		t.Fatal("grounding merged with evidence", err)
	}
}

var searchKeys struct {
	once                       sync.Once
	strong, weak, older, curve []byte
}

// serviceAccount is a service account credential as Google writes one, with
// the members a case changes or, given an empty value, leaves out.
func serviceAccount(t *testing.T, weak bool, change map[string]string) string {
	t.Helper()
	searchKeys.once.Do(func() {
		for _, bits := range []int{2048, 1024} {
			key, err := rsa.GenerateKey(rand.Reader, bits)
			if err != nil && bits == 1024 {
				// Where a key this short may not be made, the cases that
				// need one are not run, and say so.
				continue
			}
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
				// The same key in the older form, which names RSA itself.
				searchKeys.older = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
			} else {
				searchKeys.weak = encoded
			}
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		searchKeys.curve = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	})
	key := searchKeys.strong
	if weak {
		key = searchKeys.weak
	}
	if key == nil {
		return ""
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

func TestSearchHitsAreLinksOverHTTPSAlone(t *testing.T) {
	c := SearchConnection{ID: "demo", Provider: "tavily", Revision: strings.Repeat("a", 64)}
	// The last three parse: a control character after the # is read as part
	// of the fragment, so only the check for one refuses them.
	for _, refused := range []string{"http://example.org/plain", "https://reader@example.org/named", "https://example.org:8443/port", "https:///nowhere", "https://example.org/#\n", "https://example.org/#\r", "https://example.org/#\x00"} {
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
	if err := validateGoogleCredential(serviceAccount(t, false, map[string]string{"private_key": string(searchKeys.older)})); err != nil {
		t.Fatal("a key in the older form was refused", err)
	}
	// A member of the wrong kind that only the library reads.
	numbered := strings.Replace(serviceAccount(t, false, map[string]string{"private_key": "KEY"}), `"KEY"`, `5`, 1)
	for name, credential := range map[string]string{
		"no token endpoint":      serviceAccount(t, false, map[string]string{"token_uri": ""}),
		"another token endpoint": serviceAccount(t, false, map[string]string{"token_uri": "https://evil.example/token"}),
		"not a service account":  serviceAccount(t, false, map[string]string{"client_email": "reader@example.org"}),
		"no key":                 serviceAccount(t, false, map[string]string{"private_key": ""}),
		"a key that is no key":   serviceAccount(t, false, map[string]string{"private_key": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"}),
		"a key that is not PEM":  serviceAccount(t, false, map[string]string{"private_key": "not PEM"}),
		"a key that is not RSA":  serviceAccount(t, false, map[string]string{"private_key": string(searchKeys.curve)}),
		"a key that is a number": numbered,
		// Refused by the library that reads the credential as well as by the
		// check of the type here, so this case holds the two together.
		"a user's credential": serviceAccount(t, false, map[string]string{"type": "authorized_user"}),
		"not a value":         "{",
	} {
		if validateGoogleCredential(credential) != ErrRequest {
			t.Fatalf("%s: accepted", name)
		}
	}
	if short := serviceAccount(t, true, nil); short == "" {
		t.Log("no key of 1024 bits can be made here; that such a key is refused is not tested")
	} else if validateGoogleCredential(short) != ErrRequest {
		t.Fatal("a key of 1024 bits: accepted")
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
	if short := serviceAccount(t, true, nil); short != "" {
		c := grounding
		c.Credential = short
		if searchValid(c) {
			t.Fatal("Google, a key of 1024 bits: accepted")
		}
	}
}

func TestTavilyAnswerIsHeldToItsForm(t *testing.T) {
	c := SearchConnection{ID: "demo", Provider: "tavily", Revision: strings.Repeat("a", 64)}
	q := SearchRequest{c.ID, c.Revision, "query", 5}
	for name, body := range map[string]string{
		"no results named":         `{}`,
		"results that are nothing": `{"results":null}`,
		"results that are a text":  `{"results":"none"}`,
		"a title that is a number": `{"results":[{"url":"https://example.org/","title":1}]}`,
		"not a value":              `{"results":[`,
	} {
		if r, err := normalizeSearch([]byte(body), c, q); err != ErrProvider {
			t.Fatalf("%s: %v, %v", name, r.Hits, err)
		}
	}
	// No result at all is an answer, and it has no hits.
	if r, err := normalizeSearch([]byte(`{"results":[]}`), c, q); err != nil || len(r.Hits) != 0 || r.Kind != "search-results" {
		t.Fatal(r, err)
	}
}

func TestGoogleAnswerIsHeldToItsForm(t *testing.T) {
	c := SearchConnection{ID: "google", Provider: "google-grounding", Revision: strings.Repeat("a", 64)}
	q := SearchRequest{c.ID, c.Revision, "query", 5}
	grounding := `"groundingMetadata":{"groundingChunks":[{"web":{"uri":"https://example.org","title":"Source"}}],"searchEntryPoint":{"renderedContent":"<div>Google Search</div>"}}`
	if _, err := normalizeSearch([]byte(`{"candidates":[{"content":{"parts":[{"text":"Generated"}]},`+grounding+`}]}`), c, q); err != nil {
		t.Fatal("the cases start from an answer that is refused", err)
	}
	if r, err := normalizeSearch([]byte(`{"candidates":[{"content":{"parts":[{"text":5}]},`+grounding+`}]}`), c, q); err != ErrProvider {
		t.Fatal("a text that is a number was kept", r.Hits, err)
	}
}

func TestSearchLinkThatDoesNotParseIsNoHit(t *testing.T) {
	c := SearchConnection{ID: "demo", Provider: "tavily", Revision: strings.Repeat("a", 64)}
	body, _ := json.Marshal(map[string]any{"results": []map[string]string{{"url": "https://example.org/%zz"}, {"url": "https://example.org/kept"}}})
	r, err := normalizeSearch(body, c, SearchRequest{c.ID, c.Revision, "query", 5})
	if err != nil || len(r.Hits) != 1 || r.Hits[0].URL != "https://example.org/kept" {
		t.Fatal(r.Hits, err)
	}
}
