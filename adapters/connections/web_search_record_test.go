//go:build linux || darwin

package connections

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

// TestSearchResultsForPublishedSchema makes a search of each kind and, where
// the environment names a file for it, writes the result there, for
// testdata/search/check_schema.py to hold to the published schema. The
// answers are this test's own, made to use what the form allows: a link that
// is left out, a title of another script, an excerpt and an answer past
// their bounds, members of the provider's the adapter does not read.
func TestSearchResultsForPublishedSchema(t *testing.T) {
	write := func(variable string, raw []byte) {
		t.Helper()
		var envelope struct{ Result json.RawMessage }
		if err := json.Unmarshal(raw, &envelope); err != nil || len(envelope.Result) == 0 {
			t.Fatal("no result in what the source answered", err)
		}
		if path := os.Getenv(variable); path != "" {
			if err := os.WriteFile(path, envelope.Result, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}

	results, _ := json.Marshal(map[string]any{
		"query":         "public policy guidance",
		"response_time": 1.25,
		"results": []map[string]any{
			{"title": "Guidance on public policy", "url": "https://example.org/guidance", "content": "An excerpt.", "score": 0.98, "raw_content": nil},
			{"title": "政策の手引き", "url": "HTTPS://example.org/ja/%E6%89%8B%E5%BC%95", "content": strings.Repeat("é", 1200)},
			{"title": "Left out: not HTTPS", "url": "http://example.org/plain", "content": ""},
			{"url": "https://example.org/untitled"},
		},
	})
	s, _, c := searchFixture(t)
	raw, err := searchAcquire(context.Background(), s, SearchRequest{c.ID, c.Revision, "public policy guidance", 5}, searchThrough(func(*http.Request) (*http.Response, error) {
		return searchReply(200, strings.NewReader(string(results))), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	write("JPACK_TEST_SEARCH_RESULT", raw)

	grounded, _ := json.Marshal(map[string]any{
		"candidates": []any{map[string]any{
			"content":      map[string]any{"role": "model", "parts": []map[string]string{{"text": strings.Repeat("An answer. ", 1200)}}},
			"finishReason": "STOP",
			"groundingMetadata": map[string]any{
				"groundingChunks": []any{
					map[string]any{"web": map[string]string{"uri": "https://example.org/guidance", "title": "example.org"}},
					map[string]any{"web": map[string]string{"uri": "https://example.net/second", "title": "example.net"}},
					map[string]any{"retrievedContext": map[string]string{"uri": "https://example.org/not-web"}},
				},
				"groundingSupports": []any{map[string]any{"groundingChunkIndices": []int{0}}},
				"searchEntryPoint":  map[string]string{"renderedContent": "<style>.c{color:#000}</style><div class=\"c\">Search suggestions</div>"},
				"webSearchQueries":  []string{"public policy guidance", "policy guidance official"},
			},
		}},
		"usageMetadata": map[string]int{"totalTokenCount": 1234},
	})
	gs, gc := groundingFixture(t, "global")
	raw, err = searchAcquire(context.Background(), gs, SearchRequest{gc.ID, gc.Revision, "public policy guidance", 5}, searchThrough(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "oauth2.googleapis.com" {
			return searchReply(200, strings.NewReader(`{"access_token":"isolated-token","token_type":"Bearer","expires_in":3600}`)), nil
		}
		return searchReply(200, strings.NewReader(string(grounded))), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	write("JPACK_TEST_GROUNDED_RESULT", raw)
}
