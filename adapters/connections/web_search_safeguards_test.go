//go:build linux || darwin

package connections

// Tests of the search connections that need the custody store, a listener or
// the stand-in transport. Those that need none are in
// web_search_portable_test.go.
//
// Each test holds a refusal or a bound of web_search.go, and each was checked
// by taking the condition out and seeing a test fail. The conditions taken
// out, and what failed for each, are in the review record of the pull request
// that added these files.
//
// Six conditions no test here tells from their absence:
//
//   - a saved credential is kept on an update only for the same provider: a
//     row saved through configure holds a credential of its provider's form,
//     and the other provider's form refuses it;
//   - the credential is a JSON value: the library that reads it after
//     refuses one that is not;
//   - the credential's type is a service account: the same library refuses
//     any other;
//   - the token endpoint the library derives is Google's: the member it is
//     derived from is held to the same value first;
//   - the credential has a key: no key is a key that is not PEM;
//   - a saved credential is read again before a request: the row was held to
//     its form a moment before, under the same lock that read it.
//
// No test here reaches a network, whatever the program under test does: a
// client either answers from a function or connects to the test's own server
// and to nothing else, whichever address it is asked for.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	p.client = searchClient(server)
	p.searchEndpoint = server.URL
	return p
}

// searchClient is a client that trusts the server's certificate and connects
// to that server whatever address a request names, so that a program that
// chose another endpoint would fail here and reach nothing.
func searchClient(server *httptest.Server) *http.Client {
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
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
	p.client = searchClient(server)
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
	// Read from the store: the status counts a request of the day before as
	// none, and a day may end between the request and the reading.
	b.store.locked(func(v *state) error {
		if v.Search.Connections[0].Requests != 1 {
			t.Errorf("the test was not counted: %+v", v.Search.Connections[0])
		}
		return nil
	})
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
	p.client = searchClient(server)
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

// searchThrough is a provider whose every request goes to a function, so
// that nothing reaches a network whatever the program under test does.
func searchThrough(answer func(*http.Request) (*http.Response, error)) provider {
	p := google()
	p.search = true
	p.client = &http.Client{Transport: testTransportFunc(answer)}
	return p
}

func searchReply(status int, body io.Reader) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(body)}
}

// groundingFixture is a store holding one Google connection.
func groundingFixture(t *testing.T, location string) (*Store, SearchConnection) {
	t.Helper()
	s, b, _ := searchFixture(t)
	err := configureSearch(b, map[string]any{"id": "grounded", "name": "Grounded", "provider": "google-grounding", "dailyLimit": 10, "credential": serviceAccount(t, false, nil), "project": "demo-project", "location": location, "model": "gemini-2.5-flash"})
	if err != nil {
		t.Fatal(err)
	}
	var c SearchConnection
	s.locked(func(v *state) error { c = v.Search.Connections[1]; return nil })
	return s, c
}

func searchSpent(t *testing.T, s *Store, id string) int {
	t.Helper()
	spent := -1
	s.locked(func(v *state) error {
		for _, c := range v.Search.Connections {
			if c.ID == id {
				spent = c.Requests
			}
		}
		return nil
	})
	return spent
}

type failingAfter struct{ whole io.Reader }

func (f *failingAfter) Read(p []byte) (int, error) {
	n, err := f.whole.Read(p)
	if err == io.EOF {
		return n, errors.New("the connection was cut")
	}
	return n, err
}

func TestSearchStoreNeedsARootItCanHold(t *testing.T) {
	if s, err := OpenSearchStore("relative", "test"); err != ErrRequest || s != nil {
		t.Fatal("a store was opened under a path that is not absolute", err)
	}
}

func TestSearchStatusTakesNoMember(t *testing.T) {
	_, b, _ := searchFixture(t)
	if _, err := b.Handle(context.Background(), "status", []byte(`{"extra":1}`)); err != ErrRequest {
		t.Fatal("a status request with a member was answered", err)
	}
}

func TestSearchCredentialIsReplacedOnlyByAnother(t *testing.T) {
	s, b, c := searchFixture(t)
	var sent string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent = r.Header.Get("Authorization")
		w.Write([]byte(`{"results":[{"url":"https://example.org"}]}`))
	}))
	defer server.Close()
	p := google()
	p.client = searchClient(server)
	p.searchEndpoint = server.URL
	for _, step := range []struct{ given, want string }{{"", c.Credential}, {"tvly-replacement", "tvly-replacement"}} {
		if err := configureSearch(b, map[string]any{"id": c.ID, "revision": c.Revision, "name": c.Name, "provider": c.Provider, "dailyLimit": c.DailyLimit, "credential": step.given}); err != nil {
			t.Fatal(err)
		}
		s.locked(func(v *state) error { c = v.Search.Connections[0]; return nil })
		if _, err := searchAcquire(context.Background(), s, SearchRequest{c.ID, c.Revision, "query", 1}, p); err != nil {
			t.Fatal(err)
		}
		if sent != "Bearer "+step.want {
			t.Fatalf("given %q, the provider was sent %q", step.given, sent)
		}
	}
}

func TestSearchDisconnectIsHeldToItsForm(t *testing.T) {
	_, b, c := searchFixture(t)
	for name, test := range map[string]struct {
		request string
		want    error
	}{
		"a member too many":           {`{"id":"` + c.ID + `","revision":"` + c.Revision + `","extra":1}`, ErrRequest},
		"an identifier in capitals":   {`{"id":"Demo","revision":"` + c.Revision + `"}`, ErrRequest},
		"a revision that is not one":  {`{"id":"` + c.ID + `","revision":"bad"}`, ErrRequest},
		"another connection's name":   {`{"id":"other","revision":"` + c.Revision + `"}`, ErrChanged},
		"a revision that is not this": {`{"id":"` + c.ID + `","revision":"` + strings.Repeat("0", 64) + `"}`, ErrChanged},
	} {
		if _, err := b.Handle(context.Background(), "disconnect", []byte(test.request)); err != test.want {
			t.Fatalf("%s: %v", name, err)
		}
		if rows := searchRows(t, b); len(rows) != 1 {
			t.Fatalf("%s: the connection is gone", name)
		}
	}
}

func TestSearchWithNoConnectionSaved(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	s, err := OpenSearchStore(dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	b := NewSearch(s, false)
	defer b.Close()
	request := `{"id":"demo","revision":"` + strings.Repeat("a", 64) + `"}`
	if _, err = b.Handle(context.Background(), "disconnect", []byte(request)); err != ErrChanged {
		t.Fatal("disconnect:", err)
	}
	if _, err = searchSnapshot(s, SearchRequest{"demo", strings.Repeat("a", 64), "query", 1}); err != ErrConnect {
		t.Fatal("request:", err)
	}
	if err = searchCurrent(s, SearchConnection{ID: "demo", Revision: strings.Repeat("a", 64)}); err != ErrChanged {
		t.Fatal("after the answer:", err)
	}
}

func TestSearchTestIsHeldToItsForm(t *testing.T) {
	s, b, c := searchFixture(t)
	b.provider = searchAnswering(t, 200, []byte(`{"results":[{"url":"https://example.org"}]}`))
	if _, err := b.Handle(context.Background(), "test", []byte(`{"id":"`+c.ID+`","revision":"`+c.Revision+`","extra":1}`)); err != ErrRequest {
		t.Fatal("a test with a member too many was run", err)
	}
	if spent := searchSpent(t, s, c.ID); spent != 0 {
		t.Fatalf("a refused test was counted: %d", spent)
	}
}

func TestSearchRequestIsHeldToItsForm(t *testing.T) {
	s, _, c := searchFixture(t)
	for name, q := range map[string]SearchRequest{
		"a connection in capitals":   {"Demo", c.Revision, "query", 1},
		"a revision that is not one": {c.ID, "bad", "query", 1},
		"no query":                   {c.ID, c.Revision, "", 1},
		"a query with a line end":    {c.ID, c.Revision, "one\ntwo", 1},
		"a query over its bound":     {c.ID, c.Revision, strings.Repeat("q", 2001), 1},
		"no results asked":           {c.ID, c.Revision, "query", 0},
		"fewer than none":            {c.ID, c.Revision, "query", -1},
		"more than ten":              {c.ID, c.Revision, "query", 11},
	} {
		if _, err := searchSnapshot(s, q); err != ErrRequest {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := searchSnapshot(s, SearchRequest{"absent", c.Revision, "query", 1}); err != ErrConnect {
		t.Fatal("a connection that is not saved:", err)
	}
	if spent := searchSpent(t, s, c.ID); spent != 0 {
		t.Fatalf("a refused request was counted: %d", spent)
	}
	// As the program reads one: a member too many, naming no saved
	// connection, so that nothing is asked of a provider however it is read.
	raw := `{"connection":"absent","revision":"` + c.Revision + `","query":"query","maxResults":1,"extra":1}`
	if out, err := ReadSearch(context.Background(), s, []byte(raw)); err != ErrRequest || len(out) != 0 {
		t.Fatal("a request with a member too many was read", err)
	}
}

func TestSearchRefusesASavedConnectionThatIsNotInItsForm(t *testing.T) {
	s, _, c := searchFixture(t)
	s.locked(func(v *state) error { v.Search.Connections[0].Name = ""; return s.write("state.json", v) })
	if _, err := searchSnapshot(s, SearchRequest{c.ID, c.Revision, "query", 1}); err != ErrSetup {
		t.Fatal("a saved connection with no name was used", err)
	}
	if spent := searchSpent(t, s, c.ID); spent != 0 {
		t.Fatalf("a refused request was counted: %d", spent)
	}
}

func TestSearchRefusesAnAnswerWhenAnotherConnectionHasItsRevision(t *testing.T) {
	s, _, c := searchFixture(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.locked(func(v *state) error {
			v.Search.Connections[0].ID = "other"
			return s.write("state.json", v)
		})
		w.Write([]byte(`{"results":[{"url":"https://example.org"}]}`))
	}))
	defer server.Close()
	p := google()
	p.client = searchClient(server)
	p.searchEndpoint = server.URL
	if _, err := searchAcquire(context.Background(), s, SearchRequest{c.ID, c.Revision, "query", 1}, p); err != ErrChanged {
		t.Fatal("an answer was kept for a connection that is gone", err)
	}
}

func TestSearchAnswerWithoutResultsIsNoRecord(t *testing.T) {
	s, _, c := searchFixture(t)
	raw, err := searchAcquire(context.Background(), s, SearchRequest{c.ID, c.Revision, "query", 1}, searchAnswering(t, 200, []byte(`{}`)))
	if err != ErrProvider || len(raw) != 0 {
		t.Fatal("an answer that names no results made a record", err)
	}
}

func TestSearchFailsAsTheProviderWhenNothingIsAnswered(t *testing.T) {
	answer := `{"results":[{"url":"https://example.org"}]}`
	for name, reply := range map[string]func(*http.Request) (*http.Response, error){
		"no connection": func(*http.Request) (*http.Response, error) { return nil, errors.New("no route") },
		"an answer cut short": func(*http.Request) (*http.Response, error) {
			return searchReply(200, &failingAfter{strings.NewReader(answer)}), nil
		},
	} {
		s, _, c := searchFixture(t)
		raw, err := searchAcquire(context.Background(), s, SearchRequest{c.ID, c.Revision, "query", 1}, searchThrough(reply))
		if err != ErrProvider || len(raw) != 0 {
			t.Fatalf("%s: %v", name, err)
		}
		if spent := searchSpent(t, s, c.ID); spent != 1 {
			t.Fatalf("%s: a failed request was not counted: %d", name, spent)
		}
	}
}

func TestSearchEndpointThatIsNoAddressAsksNothing(t *testing.T) {
	s, _, c := searchFixture(t)
	p := searchThrough(func(r *http.Request) (*http.Response, error) {
		t.Error("a request was sent")
		return nil, errors.New("not reached")
	})
	p.searchEndpoint = "://nowhere"
	if _, err := searchAcquire(context.Background(), s, SearchRequest{c.ID, c.Revision, "query", 1}, p); err != ErrRequest {
		t.Fatal(err)
	}
}

func TestSearchRecordsNoPeerWhereNoneWasSeen(t *testing.T) {
	answer := `{"results":[{"url":"https://example.org"}]}`
	for name, state := range map[string]*tls.ConnectionState{"no TLS reported": nil, "TLS with no certificate": {}} {
		s, _, c := searchFixture(t)
		raw, err := searchAcquire(context.Background(), s, SearchRequest{c.ID, c.Revision, "query", 1}, searchThrough(func(*http.Request) (*http.Response, error) {
			reply := searchReply(200, strings.NewReader(answer))
			reply.TLS = state
			return reply, nil
		}))
		if err != nil || !bytes.Contains(raw, []byte(`"peerIdentity":null`)) {
			t.Fatalf("%s: %v, %s", name, err, raw)
		}
	}
}

func TestGoogleIsAskedAtTheRegionOfTheConnection(t *testing.T) {
	grounded := `{"candidates":[{"content":{"parts":[{"text":"Generated"}]},"groundingMetadata":{"groundingChunks":[{"web":{"uri":"https://example.org","title":"Example"}}],"searchEntryPoint":{"renderedContent":"<div>Google</div>"}}}]}`
	for location, host := range map[string]string{"global": "aiplatform.googleapis.com", "us-central1": "us-central1-aiplatform.googleapis.com"} {
		s, c := groundingFixture(t, location)
		var asked []string
		var sent map[string]any
		raw, err := searchAcquire(context.Background(), s, SearchRequest{c.ID, c.Revision, "public sources", 5}, searchThrough(func(r *http.Request) (*http.Response, error) {
			asked = append(asked, r.URL.String())
			if r.URL.Host == "oauth2.googleapis.com" {
				return searchReply(200, strings.NewReader(`{"access_token":"isolated-token","token_type":"Bearer","expires_in":3600}`)), nil
			}
			body, _ := io.ReadAll(r.Body)
			json.Unmarshal(body, &sent)
			return searchReply(200, strings.NewReader(grounded)), nil
		}))
		want := "https://" + host + "/v1/projects/demo-project/locations/" + location + "/publishers/google/models/gemini-2.5-flash:generateContent"
		if err != nil || len(asked) != 2 || asked[0] != "https://oauth2.googleapis.com/token" || asked[1] != want {
			t.Fatalf("%s: %v, asked %v", location, err, asked)
		}
		if !bytes.Contains(raw, []byte(`"endpoint":"`+want+`"`)) {
			t.Fatalf("%s: the record names another endpoint: %s", location, raw)
		}
		// What is sent holds the query, after the instruction that is the
		// adapter's own, and asks for the search tool and nothing else.
		text := sent["contents"].([]any)[0].(map[string]any)["parts"].([]any)[0].(map[string]any)["text"].(string)
		tools, _ := json.Marshal(sent["tools"])
		if !strings.HasSuffix(text, " Query: public sources") || string(tools) != `[{"googleSearch":{}}]` {
			t.Fatalf("%s: sent %q with tools %s", location, text, tools)
		}
	}
}

func TestGoogleTokenRefusedIsACredentialToGiveAgain(t *testing.T) {
	s, c := groundingFixture(t, "global")
	asked := 0
	raw, err := searchAcquire(context.Background(), s, SearchRequest{c.ID, c.Revision, "public sources", 5}, searchThrough(func(r *http.Request) (*http.Response, error) {
		asked++
		if r.URL.Host != "oauth2.googleapis.com" {
			t.Errorf("asked %s without a token", r.URL)
		}
		return searchReply(400, strings.NewReader(`{"error":"invalid_grant"}`)), nil
	}))
	if err != Error("credentials-required") || len(raw) != 0 || asked != 1 {
		t.Fatalf("%v after %d requests", err, asked)
	}
	if spent := searchSpent(t, s, c.ID); spent != 1 {
		t.Fatalf("a failed request was not counted: %d", spent)
	}
}

func TestSearchClientReachesItsOwnServerAlone(t *testing.T) {
	reached := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached++ }))
	defer server.Close()
	// A name that is not the server's: the connection is made to the server
	// all the same, and fails there, since its certificate is for other names.
	if response, err := searchClient(server).Get("https://api.tavily.com/search"); err == nil {
		response.Body.Close()
		t.Fatal("a request for another host was answered")
	}
	if reached != 0 {
		t.Fatal("a request for another host was served")
	}
	response, err := searchClient(server).Get(server.URL)
	if err != nil || reached != 1 {
		t.Fatal("the server's own address was not reached", err)
	}
	response.Body.Close()
}

func TestSearchMakesNoRecordWhenItsOwnProgramCannotBeRead(t *testing.T) {
	program, err := os.Executable()
	if err == nil {
		program, err = filepath.EvalSymlinks(program)
	}
	if err != nil {
		t.Skip("the test's own program cannot be located here")
	}
	before, err := os.Stat(program)
	if err != nil || os.Chmod(program, 0111) != nil {
		t.Skip("the mode of the test's own program cannot be changed here")
	}
	defer os.Chmod(program, before.Mode().Perm())
	if file, err := os.Open(program); err == nil {
		file.Close()
		t.Skip("this account reads a file whatever its mode")
	}
	s, _, c := searchFixture(t)
	raw, err := searchAcquire(context.Background(), s, SearchRequest{c.ID, c.Revision, "query", 1}, searchThrough(func(*http.Request) (*http.Response, error) {
		return searchReply(200, strings.NewReader(`{"results":[{"url":"https://example.org"}]}`)), nil
	}))
	if err != ErrProvider || len(raw) != 0 {
		t.Fatal("a record was made that cannot name the program that made it", err)
	}
}
