//go:build gateway_acquisition_fixture && (linux || darwin)

package connections

import (
	"adapters/attachment"
	"adapters/document"
	"adapters/internal/acquisitionfixture"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestAcquisitionFixtureSearchKeepsIdentityValidationAndBudget(t *testing.T) {
	store, broker, connection := searchFixture(t)
	connection.Credential = acquisitionfixture.Credential
	connection.DailyLimit = 1
	raw, _ := json.Marshal(connection)
	if _, err := broker.Handle(t.Context(), "configure", raw); err != nil {
		t.Fatal(err)
	}
	store.locked(func(state *state) error { connection = state.Search.Connections[0]; return nil })
	request := SearchRequest{Connection: connection.ID, Revision: connection.Revision, Query: "synthetic fixture sources", MaxResults: 3}
	encoded, _ := json.Marshal(request)
	for _, bad := range []string{`null`, `{"connection":"demo","revision":"bad","query":"fixture","maxResults":1}`, string(encoded[:len(encoded)-1]) + `,"query":"duplicate"}`} {
		if _, err := ReadSearchAcquisitionFixture(t.Context(), store, []byte(bad)); err == nil {
			t.Fatal("malformed request admitted", bad)
		}
	}
	stale := request
	stale.Revision = strings.Repeat("0", 64)
	bad, _ := json.Marshal(stale)
	if _, err := ReadSearchAcquisitionFixture(t.Context(), store, bad); err != ErrChanged {
		t.Fatal("stale revision admitted", err)
	}
	raw, err := ReadSearchAcquisitionFixture(t.Context(), store, encoded)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Acquisition struct {
			Adapter                attachment.Identity
			Endpoint, PeerIdentity string
		}
		Result SearchResult
	}
	identity, err := document.OwnIdentity()
	identity.Name = "adapter-sources"
	if err != nil || json.Unmarshal(raw, &envelope) != nil || envelope.Acquisition.Adapter != identity || envelope.Acquisition.Endpoint != acquisitionfixture.SearchEndpoint || !strings.HasPrefix(envelope.Acquisition.PeerIdentity, "tls:sha256:") || envelope.Result.Query != request.Query || len(envelope.Result.Hits) != 3 || envelope.Result.Hits[0].URL != acquisitionfixture.CompanySearchURL || strings.Contains(string(raw), acquisitionfixture.Credential) {
		t.Fatal("search normalization/identity/credential boundary changed", string(raw))
	}
	if envelope.Result.Hits[0].Snippet != acquisitionfixture.CompanySearchSnippet || !strings.Contains(acquisitionfixture.CompanyHTML, "Location: Fixture City") || strings.Contains(envelope.Result.Hits[0].Snippet, "Fixture City") {
		t.Fatal("distinct source observations collapsed", string(raw))
	}
	description, _ := json.Marshal(map[string]string{"connection": connection.ID, "revision": connection.Revision})
	described, err := DescribeSearchBinding(store, description)
	var descriptor ResearchBindingDescriptor
	if err != nil || json.Unmarshal(described, &descriptor) != nil || descriptor.Adapter != identity || descriptor.Endpoint != envelope.Acquisition.Endpoint {
		t.Fatal("descriptor and actual fixture acquisition differ", err)
	}
	if _, err := ReadSearchAcquisitionFixture(t.Context(), store, encoded); err != Error("search-budget-exhausted") {
		t.Fatal("production durable daily cap bypassed", err)
	}
}

type bodyKeeper struct {
	http.RoundTripper
	bodies *[]string
}

func (k bodyKeeper) RoundTrip(r *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	*k.bodies = append(*k.bodies, string(body))
	return k.RoundTripper.RoundTrip(r)
}

// The fixture reads a request by production's path: for the same request it
// sends the same body, commits the same statement and refuses by the same
// code as production's readSearch.
func TestAcquisitionFixtureSearchTakesProductionsArgumentTable(t *testing.T) {
	store, broker, connection := searchFixture(t)
	connection.Credential = acquisitionfixture.Credential
	connection.DailyLimit = 1000
	configured, _ := json.Marshal(connection)
	if _, err := broker.Handle(t.Context(), "configure", configured); err != nil {
		t.Fatal(err)
	}
	store.locked(func(state *state) error { connection = state.Search.Connections[0]; return nil })
	in, p := newStandIn(t)
	statementOf := func(out []byte) string {
		var envelope struct{ Acquisition struct{ Statement string } }
		if json.Unmarshal(out, &envelope) != nil || envelope.Acquisition.Statement == "" {
			t.Fatal("no statement", string(out))
		}
		return envelope.Acquisition.Statement
	}
	admitted := map[string]map[string]any{
		"includeDomains":   {"includeDomains": []string{"example.gov"}},
		"excludeDomains":   {"excludeDomains": []string{"example.com"}},
		"timeRange":        {"timeRange": "week"},
		"all three":        {"includeDomains": []string{"example.gov"}, "excludeDomains": []string{"example.com"}, "timeRange": "year"},
		"maxResults lower": {"maxResults": 1},
		"maxResults upper": {"maxResults": 10},
		"the four alone":   {},
		"twenty domains":   {"includeDomains": domains(20)},
	}
	for label, change := range admitted {
		raw := request(connection, change)
		want, err := readSearch(t.Context(), store, raw, p)
		if err != nil {
			t.Fatalf("%s: production refused: %v", label, err)
		}
		var bodies []string
		got, err := readSearchAcquisitionFixture(t.Context(), store, raw, func(rt http.RoundTripper) http.RoundTripper { return bodyKeeper{rt, &bodies} })
		if err != nil {
			t.Fatalf("%s: the fixture refused what production admits: %v", label, err)
		}
		if len(bodies) != 1 || bodies[0] != in.last().Body {
			t.Errorf("%s: the fixture sent %q, production %q", label, bodies, in.last().Body)
		}
		if statementOf(got) != statementOf(want) {
			t.Errorf("%s: statements differ:\n%s\n%s", label, statementOf(got), statementOf(want))
		}
	}
	invalid, unsupported := "search-argument-invalid", "search-argument-unsupported"
	refused := map[string]struct {
		change map[string]any
		code   string
	}{
		"maxResults zero":         {map[string]any{"maxResults": 0}, invalid},
		"maxResults eleven":       {map[string]any{"maxResults": 11}, invalid},
		"includeDomains empty":    {map[string]any{"includeDomains": []string{}}, invalid},
		"includeDomains scheme":   {map[string]any{"includeDomains": []string{"https://example.org"}}, invalid},
		"timeRange decade":        {map[string]any{"timeRange": "decade"}, invalid},
		"unsupported searchDepth": {map[string]any{"searchDepth": "advanced"}, unsupported},
		"unsupported mode":        {map[string]any{"include_domains_mode": "prefer"}, unsupported},
	}
	for label, c := range refused {
		raw := request(connection, c.change)
		sent := in.count()
		_, want := readSearch(t.Context(), store, raw, p)
		var bodies []string
		out, got := readSearchAcquisitionFixture(t.Context(), store, raw, func(rt http.RoundTripper) http.RoundTripper { return bodyKeeper{rt, &bodies} })
		if want == nil || got == nil || got.Error() != want.Error() || len(out) != 0 || len(bodies) != 0 || in.count() != sent {
			t.Errorf("%s: fixture %v, production %v, %d fixture requests", label, got, want, len(bodies))
			continue
		}
		if code := strings.SplitN(got.Error(), ":", 2)[0]; code != c.code {
			t.Errorf("%s: code %q, want %q", label, code, c.code)
		}
	}
}
