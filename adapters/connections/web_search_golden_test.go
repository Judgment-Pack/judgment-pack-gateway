//go:build linux || darwin

package connections

// The golden comparison: an acquisition that passes none of the arguments
// ADR-0019 added asks each provider for the same bytes, and answers with the
// same record, as the adapter did before them. testdata/search-golden.jsonl
// was written by this test run against the code before the change (gateway
// main at 8f7c619, with goldenRead decoding the request and calling
// searchAcquire, as ReadSearch did there); with
// JPACK_TEST_SEARCH_GOLDEN_WRITE naming a file, it writes that file again
// instead of comparing. testdata/describe-golden-v1.jsonl is what
// --describe-research wrote then, version 1, for the same two connections.
//
// What a run cannot reproduce is taken out, and only that: the instant the
// answer was read (observedAt, retrievedAt) and the digest of the program
// that read it, which is this test's own binary. Everything else is compared
// byte for byte: each request's method, address and body (but the body of
// Google's token request, a signed assertion of the moment), the statement,
// the endpoint, the snapshot, the peer and the result. A receipt the gateway
// mints from the same arguments and the same record differs from another
// only by its salts, its session and its stamps.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"

	"adapters/document"
)

type searchGolden struct {
	Case     string          `json:"case"`
	Requests []goldenRequest `json:"requests"`
	Output   string          `json:"output"`
}

type goldenRequest struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Body   string `json:"body"`
}

// goldenRead is what ReadSearch does, with the provider given.
var goldenRead = readSearch

var goldenInstant = regexp.MustCompile(`"(observedAt|retrievedAt)":"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"`)

const (
	goldenTavilyRevision = "5b1f5b1f5b1f5b1f5b1f5b1f5b1f5b1f5b1f5b1f5b1f5b1f5b1f5b1f5b1f5b1f"
	goldenGoogleRevision = "6c2a6c2a6c2a6c2a6c2a6c2a6c2a6c2a6c2a6c2a6c2a6c2a6c2a6c2a6c2a6c2a"
)

// goldenStore is a store holding a Tavily connection, demo, and a Google
// connection, grounded, at location, each at a revision fixed for the test.
func goldenStore(t *testing.T, location string) (*Store, *Broker) {
	t.Helper()
	s, b, _ := searchFixture(t)
	if err := configureSearch(b, map[string]any{"id": "grounded", "name": "Grounded", "provider": "google-grounding", "dailyLimit": 10, "credential": serviceAccount(t, false, nil), "project": "demo-project", "location": location, "model": "gemini-2.5-flash"}); err != nil {
		t.Fatal(err)
	}
	if err := s.locked(func(v *state) error {
		v.Search.Connections[0].Revision = goldenTavilyRevision
		v.Search.Connections[1].Revision = goldenGoogleRevision
		return s.write("state.json", v)
	}); err != nil {
		t.Fatal(err)
	}
	return s, b
}

func goldenTavilyAnswer(n int) string {
	results := []map[string]any{
		{"title": "Guidance on public policy", "url": "https://example.org/guidance", "content": "An excerpt.", "score": 0.98},
		{"title": "Duplicate", "url": "https://example.org/guidance", "content": "Again."},
		{"title": "Left out: not HTTPS", "url": "http://example.org/plain", "content": ""},
		{"title": "政策の手引き", "url": "HTTPS://example.org/ja/%E6%89%8B%E5%BC%95", "content": strings.Repeat("é", 1200)},
	}
	for i := 0; i < n; i++ {
		results = append(results, map[string]any{"title": "Result", "url": "https://example.net/" + strings.Repeat("r", i+1), "content": "More."})
	}
	raw, _ := json.Marshal(map[string]any{"query": "as asked", "response_time": 1.25, "results": results})
	return string(raw)
}

const goldenGrounded = `{"candidates":[{"content":{"role":"model","parts":[{"text":"A generated answer. "},{"text":"Its second part."}]},"groundingMetadata":{"groundingChunks":[{"web":{"uri":"https://example.org/guidance","title":"example.org"}},{"web":{"uri":"https://example.net/second","title":"example.net"}},{"retrievedContext":{"uri":"https://example.org/not-web"}},{"web":{"uri":"https://example.com/third","title":"example.com"}}],"searchEntryPoint":{"renderedContent":"<div>Search suggestions</div>"},"webSearchQueries":["public policy guidance","policy guidance official"]}}]}`

// goldenProvider answers every request from the test and records it.
func goldenProvider(t *testing.T, tavily string, recorded *[]goldenRequest) provider {
	return searchThrough(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Host == "oauth2.googleapis.com" {
			*recorded = append(*recorded, goldenRequest{r.Method, r.URL.String(), "(a signed assertion)"})
			return searchReply(200, strings.NewReader(`{"access_token":"isolated-token","token_type":"Bearer","expires_in":3600}`)), nil
		}
		*recorded = append(*recorded, goldenRequest{r.Method, r.URL.String(), string(body)})
		if strings.HasSuffix(r.URL.Path, ":generateContent") {
			return searchReply(200, strings.NewReader(goldenGrounded)), nil
		}
		return searchReply(200, strings.NewReader(tavily)), nil
	})
}

func goldenNormalize(t *testing.T, out []byte) string {
	t.Helper()
	identity, err := document.OwnIdentity()
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(out), identity.Digest, "sha256:(this test's own program)")
	return goldenInstant.ReplaceAllString(text, `"$1":"(the instant it was read)"`)
}

func TestSearchWithoutTheNewArgumentsIsAsBefore(t *testing.T) {
	long := strings.Repeat("q", 2000)
	cases := []struct {
		name, location, request, tavily string
	}{
		{"tavily, five", "global", `{"connection":"demo","maxResults":5,"query":"public policy guidance","revision":"` + goldenTavilyRevision + `"}`, goldenTavilyAnswer(3)},
		{"tavily, one, members in another order", "global", `{"query":"政策 guidance — 2026","revision":"` + goldenTavilyRevision + `","maxResults":1,"connection":"demo"}`, goldenTavilyAnswer(0)},
		{"tavily, ten, the longest query", "global", `{"connection":"demo","maxResults":10,"query":"` + long + `","revision":"` + goldenTavilyRevision + `"}`, goldenTavilyAnswer(12)},
		{"google, global, five", "global", `{"connection":"grounded","maxResults":5,"query":"public policy guidance","revision":"` + goldenGoogleRevision + `"}`, ""},
		{"google, regional, two", "us-central1", `{"connection":"grounded","maxResults":2,"query":"policy guidance official","revision":"` + goldenGoogleRevision + `"}`, ""},
	}
	var got []searchGolden
	for _, c := range cases {
		s, _ := goldenStore(t, c.location)
		var recorded []goldenRequest
		out, err := goldenRead(context.Background(), s, []byte(c.request), goldenProvider(t, c.tavily, &recorded))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got = append(got, searchGolden{c.name, recorded, goldenNormalize(t, out)})
	}
	// The connection test, which asks with its own fixed query.
	_, b := goldenStore(t, "global")
	var recorded []goldenRequest
	b.provider = goldenProvider(t, goldenTavilyAnswer(1), &recorded)
	out, err := b.Handle(context.Background(), "test", []byte(`{"id":"demo","revision":"`+goldenTavilyRevision+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	said, _ := json.Marshal(out)
	got = append(got, searchGolden{"tavily, the connection test", recorded, string(said)})

	if path := os.Getenv("JPACK_TEST_SEARCH_GOLDEN_WRITE"); path != "" {
		var buf bytes.Buffer
		for _, g := range got {
			line, _ := json.Marshal(g)
			buf.Write(line)
			buf.WriteByte('\n')
		}
		if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	file, err := os.Open("testdata/search-golden.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	lines := bufio.NewScanner(file)
	lines.Buffer(nil, 1<<20)
	i := 0
	for ; lines.Scan(); i++ {
		var want searchGolden
		if err := json.Unmarshal(lines.Bytes(), &want); err != nil {
			t.Fatal(err)
		}
		if i >= len(got) {
			t.Fatalf("the golden file holds a case this test does not make: %s", want.Case)
		}
		g := got[i]
		if g.Case != want.Case {
			t.Fatalf("case %d: %q, the golden file has %q", i, g.Case, want.Case)
		}
		if len(g.Requests) != len(want.Requests) {
			t.Fatalf("%s: %d requests, before %d", g.Case, len(g.Requests), len(want.Requests))
		}
		for j := range want.Requests {
			if g.Requests[j] != want.Requests[j] {
				t.Errorf("%s: request %d\n got  %+v\n want %+v", g.Case, j, g.Requests[j], want.Requests[j])
			}
		}
		if g.Output != want.Output {
			t.Errorf("%s: the record differs\n got  %s\n want %s", g.Case, g.Output, want.Output)
		}
	}
	if err := lines.Err(); err != nil {
		t.Fatal(err)
	}
	if i != len(got) {
		t.Fatalf("the golden file holds %d cases, this test makes %d", i, len(got))
	}
}

// The description of version 2 keeps every member of version 1 as version 1
// wrote it, and the request schema of version 1 is the schema of version 2
// with the arguments ADR-0019 added taken out: a Google connection's, which
// takes none of them, is the same bytes.
func TestTheDescriptionKeepsWhatVersionOneSaid(t *testing.T) {
	file, err := os.ReadFile("testdata/describe-golden-v1.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	s, _ := goldenStore(t, "us-central1")
	lines := bytes.Split(bytes.TrimSuffix(file, []byte("\n")), []byte("\n"))
	requests := []string{`{"connection":"demo","revision":"` + goldenTavilyRevision + `"}`, `{"connection":"grounded","revision":"` + goldenGoogleRevision + `"}`}
	if len(lines) != len(requests) {
		t.Fatalf("the golden file holds %d descriptions", len(lines))
	}
	for i, request := range requests {
		raw, err := DescribeSearchBinding(s, []byte(request))
		if err != nil {
			t.Fatal(err)
		}
		var now, then map[string]json.RawMessage
		if json.Unmarshal([]byte(goldenNormalize(t, raw)), &now) != nil || json.Unmarshal(lines[i], &then) != nil {
			t.Fatal("a description is not an object")
		}
		if string(then["version"]) != "1" || string(now["version"]) != "2" {
			t.Fatalf("versions: then %s, now %s", then["version"], now["version"])
		}
		for name, value := range then {
			if name == "version" || name == "requestSchema" {
				continue
			}
			if !bytes.Equal(now[name], value) {
				t.Errorf("%s: %s, version 1 wrote %s", name, now[name], value)
			}
		}
		var schemaNow, schemaThen map[string]json.RawMessage
		var propertiesNow, propertiesThen map[string]json.RawMessage
		if json.Unmarshal(now["requestSchema"], &schemaNow) != nil || json.Unmarshal(then["requestSchema"], &schemaThen) != nil || json.Unmarshal(schemaNow["properties"], &propertiesNow) != nil || json.Unmarshal(schemaThen["properties"], &propertiesThen) != nil {
			t.Fatal("a request schema is not an object")
		}
		for name, value := range schemaThen {
			if name != "properties" && !bytes.Equal(schemaNow[name], value) {
				t.Errorf("requestSchema %s: %s, version 1 wrote %s", name, schemaNow[name], value)
			}
		}
		for name, value := range propertiesThen {
			if !bytes.Equal(propertiesNow[name], value) {
				t.Errorf("requestSchema property %s: %s, version 1 wrote %s", name, propertiesNow[name], value)
			}
		}
		provider := []string{"tavily", "google-grounding"}[i]
		for name := range propertiesNow {
			if _, before := propertiesThen[name]; before {
				continue
			}
			a, known := searchArgumentNamed(name)
			if !known || a.required || !a.takes(provider) {
				t.Errorf("%s: the request schema gained %s, which is not an optional argument the provider takes", provider, name)
			}
		}
		if provider == "google-grounding" && !bytes.Equal(now["requestSchema"], then["requestSchema"]) {
			t.Errorf("a Google connection's request schema changed:\n%s\n%s", now["requestSchema"], then["requestSchema"])
		}
	}
}
