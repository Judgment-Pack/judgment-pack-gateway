//go:build linux || darwin

package connections

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// researchStatus is status's rows by connection id, as JSON decodes them.
func researchStatus(t *testing.T, b *Broker) map[string]map[string]any {
	t.Helper()
	out, err := b.Handle(context.Background(), "status", []byte(`{}`))
	raw, _ := json.Marshal(out)
	var decoded struct{ Connections []map[string]any }
	if err != nil || json.Unmarshal(raw, &decoded) != nil {
		t.Fatal(err)
	}
	rows := map[string]map[string]any{}
	for _, row := range decoded.Connections {
		if _, ok := row["credential"]; ok {
			t.Fatal("a credential in status")
		}
		rows[row["id"].(string)] = row
	}
	return rows
}

// researchFixture holds a Tavily connection, demo, and a Google grounding
// one, grounded.
func researchFixture(t *testing.T) (*Store, *Broker) {
	t.Helper()
	s, b, _ := searchFixture(t)
	if err := configureSearch(b, map[string]any{"id": "grounded", "name": "Grounded", "provider": "google-grounding", "dailyLimit": 10, "credential": serviceAccount(t, false, nil), "project": "demo-project", "location": "us-central1", "model": "gemini-2.5-flash"}); err != nil {
		t.Fatal(err)
	}
	return s, b
}

var wantResearch = map[string]map[string]any{
	"demo":     {"capabilities": []any{"search"}},
	"grounded": {"capabilities": []any{"answer", "search"}, "model": "gemini-2.5-flash"},
}

// Status names, beside each connection, the research declaration a profile
// pinning that connection's endpoint carries, in §5.1's form: a Tavily
// connection serves search; a Google grounding connection serves answer and
// search, from the model it names. The adapter's declaration in the catalog
// is what its connections can serve together.
func TestSearchStatusDeclaresWhatEachConnectionServes(t *testing.T) {
	_, b := researchFixture(t)
	rows := researchStatus(t, b)
	union := map[string]bool{}
	for id, want := range wantResearch {
		if !reflect.DeepEqual(rows[id]["research"], want) {
			t.Errorf("%s declares %v, want %v", id, rows[id]["research"], want)
		}
		for _, name := range want["capabilities"].([]any) {
			union[name.(string)] = true
		}
	}
	declared := map[string]bool{}
	for _, name := range declaredCapabilities("web-search") {
		declared[name] = true
	}
	if !reflect.DeepEqual(union, declared) {
		t.Fatalf("the providers serve %v, the catalog declares %v", union, declared)
	}
	// A provider acquisition does not know declares nothing.
	if r := searchResearch(SearchConnection{ID: "other", Name: "Other", Provider: "another-provider", DailyLimit: 10, Credential: "key", Model: "gemini-2.5-flash"}); r != nil {
		t.Errorf("an unknown provider declares %v", r)
	}
}

// Only a connection acquisition admits declares anything. A stored state
// acquisition refuses as setup-required (a Tavily connection with a model, a
// Google one whose model is not well-formed, a stored timeout configure would
// refuse) declares nothing, and its model is never declared; the other
// connection declares as before.
func TestASearchConnectionAcquisitionRefusesDeclaresNothing(t *testing.T) {
	for _, c := range []struct {
		name, id, from, to string
	}{
		{"a Tavily connection with a stored model", "demo", `"provider":"tavily"`, `"provider":"tavily","model":"gemini-2.5-flash"`},
		{"a Google connection with a model that is not gemini's", "grounded", `"model":"gemini-2.5-flash"`, `"model":"another-model"`},
		{"a Google connection with an empty model", "grounded", `"model":"gemini-2.5-flash"`, `"model":""`},
		{"a Tavily connection with a stored timeout configure refuses", "demo", `"provider":"tavily"`, `"provider":"tavily","timeoutSeconds":121`},
	} {
		s, b := researchFixture(t)
		revision := researchStatus(t, b)[c.id]["revision"].(string)
		held, err := s.read("state.json")
		if err != nil || strings.Count(string(held), c.from) != 1 {
			t.Fatalf("%s: nothing to tamper with: %v", c.name, err)
		}
		if err = s.write("state.json", json.RawMessage(strings.Replace(string(held), c.from, c.to, 1))); err != nil {
			t.Fatal(err)
		}
		if _, err := searchSnapshot(s, SearchRequest{Connection: c.id, Revision: revision, Query: "query", MaxResults: 5}); err != ErrSetup {
			t.Errorf("%s: acquisition answered %v, not setup-required", c.name, err)
		}
		rows := researchStatus(t, b)
		if research, ok := rows[c.id]["research"]; ok {
			t.Errorf("%s declares %v", c.name, research)
		}
		for id, want := range wantResearch {
			if id != c.id && !reflect.DeepEqual(rows[id]["research"], want) {
				t.Errorf("%s: %s declares %v, want %v", c.name, id, rows[id]["research"], want)
			}
		}
	}
}

// The declaration is the gateway's, from the provider: configure never takes
// one from a caller, and the stored connection never holds one.
func TestSearchConfigureTakesNoDeclarationFromTheCaller(t *testing.T) {
	s, b, _ := searchFixture(t)
	for _, research := range []any{map[string]any{"capabilities": []string{"answer", "search"}, "model": "gemini-2.5-flash"}, map[string]any{}, nil} {
		err := configureSearch(b, map[string]any{"id": "second", "name": "Second", "provider": "tavily", "dailyLimit": 5, "credential": "tvly-second", "research": research})
		if err != ErrRequest {
			t.Errorf("a declaration %v from the caller: %v", research, err)
		}
	}
	held, err := s.read("state.json")
	if err != nil || strings.Contains(string(held), "research") || strings.Contains(string(held), "capabilities") {
		t.Fatalf("the stored state holds a declaration: %s %v", held, err)
	}
}
