//go:build gateway_acquisition_fixture

package main

import (
	"adapters/attachment"
	"adapters/connections"
	"adapters/document"
	"adapters/internal/acquisitionfixture"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

// markedBuild makes the test run as the builder stamps the fixture; a test of
// the refusal of an unmarked build sets the version itself.
func markedBuild(t *testing.T) {
	t.Helper()
	was := document.Version
	document.Version = "fixture.test"
	t.Cleanup(func() { document.Version = was })
}

type unread struct{ t *testing.T }

func (r unread) Read([]byte) (int, error) {
	r.t.Error("closed protocol read stdin")
	return 0, io.EOF
}

func TestAcquisitionFixtureProtocolIsClosedBeforeReadingInput(t *testing.T) {
	for _, test := range []struct {
		role string
		args []string
	}{
		{"fixture", nil},
		{"adapter-web", []string{"--discover"}},
		{"adapter-web", []string{"--document-processing"}},
		{"adapter-web", []string{"--describe-research", "--describe-research"}},
		{"adapter-web", []string{"--endpoint=https://attacker.example"}},
		{"adapter-sources", []string{"--provider", "notion", "--principal", "desk-local"}},
		{"adapter-sources", []string{"--provider", "web-search", "--provider", "web-search", "--principal", "desk-local"}},
		{"adapter-sources", []string{"--provider=web-search"}},
		{"adapter-sources", []string{"--provider", "web-search", "--principal", "desk-local", "--endpoint", "https://attacker.example"}},
		{"adapter-sources", []string{"--provider", "web-search", "--principal", "desk-local", "--describe-research", "--long-search"}},
	} {
		var out, stderr bytes.Buffer
		if code := run(test.role, test.args, unread{t}, &out, &stderr); code != 2 || out.Len() != 0 || stderr.Len() != 0 {
			t.Fatal("invalid protocol accepted", test, code, out.String(), stderr.String())
		}
	}
}

func TestAcquisitionFixturePageDescriptionReadsNoInput(t *testing.T) {
	markedBuild(t)
	t.Setenv("JPACK_CONNECTIONS_DIR", "/must-not-be-opened")
	var out, stderr bytes.Buffer
	if code := run("adapter-web", []string{"--describe-research"}, unread{t}, &out, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatal("page descriptor unavailable", code, stderr.String())
	}
	var descriptor struct {
		Adapter  attachment.Identity
		Endpoint *string
	}
	identity, err := document.OwnIdentity()
	identity.Name = "adapter-web"
	if err != nil || json.Unmarshal(out.Bytes(), &descriptor) != nil || descriptor.Adapter != identity || descriptor.Endpoint != nil {
		t.Fatal("descriptor did not identify actual test executable")
	}
}

func TestAcquisitionFixtureProtocolBoundsInputAndDoesNotEchoIt(t *testing.T) {
	markedBuild(t)
	for _, input := range []string{strings.Repeat("sensitive-fixture", 1000), `{"url":"https://example.com/fixtures/company","endpoint":"secret"}`, `{"url":"https://user:private@example.com/fixtures/company"}`} {
		var out, stderr bytes.Buffer
		if code := run("adapter-web", nil, strings.NewReader(input), &out, &stderr); code != 1 || out.Len() != 0 || strings.Contains(stderr.String(), "private") || strings.Contains(stderr.String(), "secret") || strings.Contains(stderr.String(), "https:") || stderr.Len() > 200 {
			t.Fatal("unsafe protocol refusal", code, out.String(), stderr.String())
		}
	}
}

func TestAcquisitionFixtureSourceProtocolUsesPrivateStoreAndRealBodies(t *testing.T) {
	markedBuild(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := connections.OpenSearchStore(dir, "desk-local")
	if err != nil {
		t.Fatal(err)
	}
	broker := connections.NewSearch(store, false)
	encoded, _ := json.Marshal(connections.SearchConnection{ID: "fixture", Name: "Fixture", Provider: "tavily", Credential: acquisitionfixture.Credential, DailyLimit: 1})
	if _, err := broker.Handle(t.Context(), "configure", encoded); err != nil {
		t.Fatal(err)
	}
	status, err := broker.Handle(t.Context(), "status", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ = json.Marshal(status)
	var connection struct {
		Connections []connections.SearchConnection
	}
	if json.Unmarshal(encoded, &connection) != nil || len(connection.Connections) != 1 {
		t.Fatal("fixture setup unavailable")
	}
	broker.Close()
	store.Close()
	choice := map[string]string{"connection": "fixture", "revision": connection.Connections[0].Revision}
	encoded, _ = json.Marshal(choice)
	args := []string{"--state-dir", dir, "--principal", "desk-local", "--provider", "web-search"}
	var out, stderr bytes.Buffer
	if code := run("adapter-sources", append(args, "--describe-research"), bytes.NewReader(encoded), &out, &stderr); code != 0 || stderr.Len() != 0 || !strings.Contains(out.String(), acquisitionfixture.SearchEndpoint) {
		t.Fatal("source descriptor failed", code, stderr.String())
	}
	out.Reset()
	request, _ := json.Marshal(connections.SearchRequest{Connection: "fixture", Revision: connection.Connections[0].Revision, Query: "synthetic sources", MaxResults: 3})
	// The real local plan carries state through this existing environment
	// variable; the harness accepts no network configuration from it.
	t.Setenv("JPACK_CONNECTIONS_DIR", dir)
	if code := run("adapter-sources", args[2:], bytes.NewReader(request), &out, &stderr); code != 0 || !strings.Contains(out.String(), `"kind":"search-results"`) {
		t.Fatal("real source body failed", code, stderr.String())
	}
	out.Reset()
	stderr.Reset()
	if code := run("adapter-sources", args, bytes.NewReader(request), &out, &stderr); code != 1 || out.Len() != 0 || strings.TrimSpace(stderr.String()) != "search-budget-exhausted" {
		t.Fatal("source protocol bypassed daily budget", code, stderr.String())
	}
}

func TestAcquisitionFixtureRefusesAnUnmarkedBuildInEveryRole(t *testing.T) {
	was := document.Version
	document.Version = "0"
	t.Cleanup(func() { document.Version = was })
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	source := []string{"--state-dir", dir, "--principal", "desk-local", "--provider", "web-search"}
	for _, test := range []struct {
		role  string
		args  []string
		input string
	}{
		{"adapter-web", []string{"--describe-research"}, ""},
		{"adapter-web", nil, `{"url":"https://example.com/fixtures/company"}`},
		{"adapter-sources", append([]string{"--describe-research"}, source...), `{"connection":"demo","revision":"abc"}`},
		{"adapter-sources", source, `{"connection":"demo","revision":"abc","query":"fixture","maxResults":1}`},
	} {
		var out, stderr bytes.Buffer
		if code := run(test.role, test.args, strings.NewReader(test.input), &out, &stderr); code != 1 || out.Len() != 0 || strings.TrimSpace(stderr.String()) != "fixture-build-required" {
			t.Fatal("unmarked build served", test.role, code, out.String(), stderr.String())
		}
	}
}

// Each of these stops at the principal alone: the state directory is absolute,
// the provider is right, and no input may be read.
func TestAcquisitionFixtureSourceRefusesAnyPrincipalButTheLocalDesk(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{
		{"--state-dir", dir, "--provider", "web-search"},
		{"--state-dir", dir, "--provider", "web-search", "--principal", "someone-else"},
		{"--state-dir", dir, "--provider", "web-search", "--principal", "desk-local ", "--describe-research"},
	} {
		var out, stderr bytes.Buffer
		if code := run("adapter-sources", args, unread{t}, &out, &stderr); code != 2 || out.Len() != 0 || stderr.Len() != 0 {
			t.Fatal("principal check bypassed", args, code, out.String(), stderr.String())
		}
	}
}
