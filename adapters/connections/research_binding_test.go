//go:build linux || darwin

package connections

import (
	"adapters/attachment"
	"adapters/document"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestResearchBindingDiscoveryRetainsNoCredentialsAndDoesNotCharge(t *testing.T) {
	s, _, c := searchFixture(t)
	before, err := s.read("state.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := DescribeSearchBinding(s, []byte(`{"connection":"`+c.ID+`","revision":"`+c.Revision+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	var d ResearchBindingDescriptor
	if json.Unmarshal(raw, &d) != nil {
		t.Fatal("invalid descriptor")
	}
	actual, err := document.OwnIdentity()
	if err != nil {
		t.Fatal(err)
	}
	actual.Name = "adapter-sources"
	if d.Version != 1 || d.Shape != "http" || d.Adapter != actual || d.Endpoint != "https://api.tavily.com/search" || d.ResultRecord != "web-search-v1" || strings.Join(d.Research.Capabilities, ",") != "search" || d.FixedArguments["connection"] != c.ID || d.FixedArguments["revision"] != c.Revision {
		t.Fatal("descriptor does not name exact acquisition", d)
	}
	if bytes.Contains(raw, []byte(c.Credential)) || bytes.Contains(raw, []byte(`"credential"`)) {
		t.Fatal("credential exposed")
	}
	after, _ := s.read("state.json")
	if !bytes.Equal(before, after) {
		t.Fatal("discovery changed custody or allowance")
	}
	// A descriptor is still available when compute is exhausted. It is no grant:
	// acquisition continues to enforce the durable allowance.
	if err := s.locked(func(v *state) error {
		v.Search.Connections[0].Requests = c.DailyLimit
		v.Search.Connections[0].Day = time.Now().UTC().Format("2006-01-02")
		return s.write("state.json", v)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = DescribeSearchBinding(s, []byte(`{"connection":"`+c.ID+`","revision":"`+c.Revision+`"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err = searchSnapshot(s, SearchRequest{c.ID, c.Revision, "query", 1}); err != Error("search-budget-exhausted") {
		t.Fatal("descriptor bypassed allowance", err)
	}
}

func TestResearchBindingDiscoveryRefusesStaleAndUnsupportedRequests(t *testing.T) {
	s, b, c := searchFixture(t)
	valid := `{"connection":"` + c.ID + `","revision":"` + c.Revision + `"}`
	for _, raw := range []string{`{}`, `null`, strings.Replace(valid, `"connection"`, `"Connection"`, 1), strings.Replace(valid, `"revision"`, `"connection":"other","revision"`, 1), strings.TrimSuffix(valid, "}") + `,"endpoint":"https://example.org"}`, strings.TrimSuffix(valid, "}") + `,"query":"compute"}`, strings.TrimSuffix(valid, "}") + `,"capabilities":["page"]}`, strings.TrimSuffix(valid, "}") + `,"domain":"example.org"}`} {
		if out, err := DescribeSearchBinding(s, []byte(raw)); err != ErrRequest || len(out) != 0 {
			t.Errorf("accepted unsupported descriptor request: %s (%v)", raw, err)
		}
	}
	if out, err := DescribeSearchBinding(s, []byte(strings.Replace(valid, c.Revision, strings.Repeat("a", 64), 1))); err != ErrChanged || len(out) != 0 {
		t.Fatal("stale binding described", err)
	}
	c.Name = "Renamed"
	c.Credential = ""
	encoded, _ := json.Marshal(c)
	if _, err := b.Handle(context.Background(), "configure", encoded); err != nil {
		t.Fatal(err)
	}
	if _, err := DescribeSearchBinding(s, []byte(valid)); err != ErrChanged {
		t.Fatal("old revision retained", err)
	}
	if err := s.locked(func(v *state) error { v.Disabled = true; return s.write("state.json", v) }); err != nil {
		t.Fatal(err)
	}
	if _, err := DescribeSearchBinding(s, []byte(valid)); err != ErrPolicy {
		t.Fatal("disabled connection described", err)
	}
}

func TestResearchBindingEndpointUsesActualProviderConstruction(t *testing.T) {
	for _, tc := range []struct {
		c    SearchConnection
		want string
	}{
		{SearchConnection{Provider: "tavily"}, "https://api.tavily.com/search"},
		{SearchConnection{Provider: "google-grounding", Project: "example-project", Location: "global", Model: "gemini-2.5-flash"}, "https://aiplatform.googleapis.com/v1/projects/example-project/locations/global/publishers/google/models/gemini-2.5-flash:generateContent"},
		{SearchConnection{Provider: "google-grounding", Project: "example-project", Location: "us-central1", Model: "gemini-2.5-pro"}, "https://us-central1-aiplatform.googleapis.com/v1/projects/example-project/locations/us-central1/publishers/google/models/gemini-2.5-pro:generateContent"},
	} {
		if got := searchEndpoint(tc.c); got != tc.want {
			t.Fatalf("%s != %s", got, tc.want)
		}
	}
}

// Keep the executable identity check explicit: a consumer must not substitute
// a release label, its own binary, or a guessed adapter version.
func TestResearchBindingAdapterIdentityIsThisExecutable(t *testing.T) {
	s, _, c := searchFixture(t)
	req, _ := json.Marshal(map[string]string{"connection": c.ID, "revision": c.Revision})
	raw, err := DescribeSearchBinding(s, req)
	if err != nil {
		t.Fatal(err)
	}
	var d struct{ Adapter attachment.Identity }
	if json.Unmarshal(raw, &d) != nil {
		t.Fatal("invalid identity")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if d.Adapter.Digest != digest(data) || d.Adapter.Version != document.Version {
		t.Fatal("identity is not executable's own")
	}
}
