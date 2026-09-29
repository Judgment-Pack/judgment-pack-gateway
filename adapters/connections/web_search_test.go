//go:build linux || darwin

package connections

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
	"os"
	"strings"
	"sync"
	"testing"
)

func searchFixture(t *testing.T) (*Store, *Broker, SearchConnection) {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	s, err := OpenSearchStore(dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	b := NewSearch(s, false)
	t.Cleanup(b.Close)
	c := SearchConnection{ID: "demo", Name: "Demo", Provider: "tavily", DailyLimit: 10, Credential: "tvly-test-private-key"}
	raw, _ := json.Marshal(c)
	if _, err = b.Handle(context.Background(), "configure", raw); err != nil {
		t.Fatal(err)
	}
	s.locked(func(v *state) error { c = v.Search.Connections[0]; return nil })
	return s, b, c
}
func TestSearchStatusNeverReturnsCredentialsAndUpdatesUseRevision(t *testing.T) {
	_, b, c := searchFixture(t)
	out, err := b.Handle(context.Background(), "status", []byte(`{}`))
	raw, _ := json.Marshal(out)
	if err != nil || strings.Contains(string(raw), c.Credential) || strings.Contains(string(raw), `"credential"`) {
		t.Fatal("credentials exposed", err)
	}
	stale := c
	stale.Revision = ""
	encoded, _ := json.Marshal(stale)
	if _, err = b.Handle(context.Background(), "configure", encoded); err != ErrChanged {
		t.Fatal("stale overwrite accepted", err)
	}
	c.Name = "Renamed"
	c.Credential = ""
	encoded, _ = json.Marshal(c)
	if _, err = b.Handle(context.Background(), "configure", encoded); err != nil {
		t.Fatal(err)
	}
}
func TestSearchAcquisitionIsBoundedAttestedAndPinned(t *testing.T) {
	s, _, c := searchFixture(t)
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") != "Bearer "+c.Credential {
			t.Error("credential not sent to provider")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"results":[{"title":"Policy","url":"https://example.org/policy","content":"A snippet"},{"title":"Duplicate","url":"https://example.org/policy"},{"url":"javascript:alert(1)"}]}`))
	}))
	defer server.Close()
	p := google()
	p.client = searchClient(server)
	p.searchEndpoint = server.URL
	q := SearchRequest{c.ID, c.Revision, "find policies", 5}
	raw, err := searchAcquire(context.Background(), s, q, p)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Result      SearchResult
		Acquisition struct{ Endpoint, Snapshot, PeerIdentity string }
	}
	if json.Unmarshal(raw, &envelope) != nil || len(envelope.Result.Hits) != 1 || envelope.Result.Query != q.Query || envelope.Result.Connection != c.ID || envelope.Result.Kind != "search-results" || envelope.Acquisition.Endpoint != server.URL || !strings.HasPrefix(envelope.Acquisition.PeerIdentity, "tls:sha256:") || strings.Contains(string(raw), c.Credential) {
		t.Fatal("invalid search result")
	}
	q.Revision = strings.Repeat("0", 64)
	if _, err = searchAcquire(context.Background(), s, q, p); err != ErrChanged || requests != 1 {
		t.Fatal("stale connection acquired", err)
	}
}
func TestSearchBudgetIsSharedAndDurable(t *testing.T) {
	s, _, c := searchFixture(t)
	s.locked(func(v *state) error { v.Search.Connections[0].DailyLimit = 2; return s.write("state.json", v) })
	var wg sync.WaitGroup
	success := make(chan bool, 10)
	for range 10 {
		wg.Go(func() {
			_, err := searchSnapshot(s, SearchRequest{c.ID, c.Revision, "query", 1})
			success <- err == nil
		})
	}
	wg.Wait()
	close(success)
	count := 0
	for ok := range success {
		if ok {
			count++
		}
	}
	if count != 2 {
		t.Fatal("budget exceeded", count)
	}
}
func TestSearchRefusesLateResultsAfterCredentialsChange(t *testing.T) {
	s, b, c := searchFixture(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Name = "Changed"
		raw, _ := json.Marshal(c)
		if _, err := b.Handle(context.Background(), "configure", raw); err != nil {
			t.Error(err)
		}
		w.Write([]byte(`{"results":[{"url":"https://example.org"}]}`))
	}))
	defer server.Close()
	p := google()
	p.client = searchClient(server)
	p.searchEndpoint = server.URL
	if _, err := searchAcquire(context.Background(), s, SearchRequest{c.ID, c.Revision, "query", 1}, p); err != ErrChanged {
		t.Fatal("late result accepted", err)
	}
}
func TestSearchErrorsNeverEchoProviderContent(t *testing.T) {
	for _, status := range []int{401, 403, 429, 500, 302} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			s, _, c := searchFixture(t)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "https://example.org/leak")
				w.WriteHeader(status)
				w.Write([]byte(c.Credential))
			}))
			defer server.Close()
			p := google()
			p.client = searchClient(server)
			p.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			p.searchEndpoint = server.URL
			raw, err := searchAcquire(context.Background(), s, SearchRequest{c.ID, c.Revision, "query", 1}, p)
			if err == nil || len(raw) > 0 || strings.Contains(err.Error(), c.Credential) {
				t.Fatal("unsafe failure")
			}
		})
	}
}
func TestSearchConfigurationRejectsUntrustedEndpointsAndProviders(t *testing.T) {
	_, b, c := searchFixture(t)
	for _, raw := range []string{`{"id":"bad","provider":"other","name":"Bad","dailyLimit":1,"credential":"secret"}`, `{"id":"bad","provider":"tavily","name":"Bad","dailyLimit":1,"credential":"secret","endpoint":"https://attacker.invalid"}`} {
		if _, err := b.Handle(context.Background(), "configure", []byte(raw)); err == nil {
			t.Fatal("unsupported config accepted")
		}
	}
	for _, q := range []SearchRequest{{c.ID, c.Revision, "", 1}, {c.ID, c.Revision, "query", 11}, {c.ID, "bad", "query", 1}} {
		if _, err := searchSnapshot(b.store, q); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
}

func TestGoogleSearchAcquiresTokenAndGroundingThroughFixedEndpoints(t *testing.T) {
	s, b, c := searchFixture(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "test@demo-project.iam.gserviceaccount.com", "private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), "token_uri": "https://oauth2.googleapis.com/token"})
	c.Provider = "google-grounding"
	c.Credential = string(credential)
	c.Project = "demo-project"
	c.Location = "global"
	c.Model = "gemini-2.5-flash"
	raw, _ := json.Marshal(c)
	if _, err = b.Handle(context.Background(), "configure", raw); err != nil {
		t.Fatal(err)
	}
	s.locked(func(v *state) error { c = v.Search.Connections[0]; return nil })
	var paths []string
	p := google()
	p.client = &http.Client{Transport: testTransportFunc(func(r *http.Request) (*http.Response, error) {
		paths = append(paths, r.URL.String())
		var result string
		switch r.URL.String() {
		case "https://oauth2.googleapis.com/token":
			if err := r.ParseForm(); err != nil || r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || r.Form.Get("assertion") == "" {
				t.Error("missing signed OAuth assertion")
			}
			result = `{"access_token":"isolated-token","token_type":"Bearer","expires_in":3600}`
		case "https://aiplatform.googleapis.com/v1/projects/demo-project/locations/global/publishers/google/models/gemini-2.5-flash:generateContent":
			if r.Header.Get("Authorization") != "Bearer isolated-token" {
				t.Error("missing OAuth token")
			}
			body, _ := io.ReadAll(r.Body)
			if !bytes.Contains(body, []byte(`"googleSearch":{}`)) {
				t.Error("grounding not requested")
			}
			result = `{"candidates":[{"content":{"parts":[{"text":"Generated"}]},"groundingMetadata":{"groundingChunks":[{"web":{"uri":"https://example.org","title":"Example"}}],"searchEntryPoint":{"renderedContent":"<div>Google</div>"}}}]}`
		default:
			t.Errorf("untrusted endpoint %s", r.URL)
			result = `{}`
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(result))}, nil
	})}
	result, err := searchAcquire(context.Background(), s, SearchRequest{c.ID, c.Revision, "public sources", 5}, p)
	if err != nil || len(paths) != 2 || bytes.Contains(result, []byte("isolated-token")) || bytes.Contains(result, []byte("PRIVATE KEY")) {
		t.Fatal("Google flow failed", err)
	}
	var v map[string]any
	if json.Unmarshal(result, &v) != nil {
		t.Fatal("bad envelope")
	}
	got := v["result"].(map[string]any)
	if got["attributionHtml"] == nil || got["kind"] != "grounded-answer" {
		t.Fatal("missing grounding attribution")
	}
	bad := strings.Replace(c.Credential, "https://oauth2.googleapis.com/token", "https://evil.example/token", 1)
	if validateGoogleCredential(bad) == nil {
		t.Fatal("untrusted credential token endpoint accepted")
	}
}
