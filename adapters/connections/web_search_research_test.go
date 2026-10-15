//go:build linux || darwin

package connections

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// Status names, beside each connection, the research declaration a profile
// pinning that connection's endpoint carries, in §5.1's form: a Tavily
// connection serves search; a Google grounding connection serves answer and
// search, from the model it names. The adapter's declaration in the catalog
// is what its connections can serve together.
func TestSearchStatusDeclaresWhatEachConnectionServes(t *testing.T) {
	s, b, _ := searchFixture(t)
	if err := configureSearch(b, map[string]any{"id": "grounded", "name": "Grounded", "provider": "google-grounding", "dailyLimit": 10, "credential": serviceAccount(t, false, nil), "project": "demo-project", "location": "us-central1", "model": "gemini-2.5-flash"}); err != nil {
		t.Fatal(err)
	}
	status := func() map[string]map[string]any {
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
	rows := status()
	for id, want := range map[string]map[string]any{
		"demo":     {"capabilities": []any{"search"}},
		"grounded": {"capabilities": []any{"answer", "search"}, "model": "gemini-2.5-flash"},
	} {
		if !reflect.DeepEqual(rows[id]["research"], want) {
			t.Errorf("%s declares %v, want %v", id, rows[id]["research"], want)
		}
	}
	union := map[string]bool{}
	for _, c := range []SearchConnection{{Provider: "tavily"}, {Provider: "google-grounding", Model: "gemini-2.5-flash"}} {
		r := searchResearch(c)
		if r == nil || CheckResearch(*r) != nil {
			t.Fatalf("%s: %v", c.Provider, r)
		}
		for _, name := range r.Capabilities {
			union[name] = true
		}
	}
	declared := map[string]bool{}
	for _, name := range declaredCapabilities("web-search") {
		declared[name] = true
	}
	if !reflect.DeepEqual(union, declared) {
		t.Fatalf("the providers serve %v, the catalog declares %v", union, declared)
	}

	// A stored model configure would refuse declares nothing, and is never
	// declared as a model; the other connection is as before.
	held, err := s.read("state.json")
	if err != nil || !strings.Contains(string(held), `"model":"gemini-2.5-flash"`) {
		t.Fatal("no stored model to tamper with", err)
	}
	if err = s.write("state.json", json.RawMessage(strings.Replace(string(held), `"model":"gemini-2.5-flash"`, `"model":"another-model"`, 1))); err != nil {
		t.Fatal(err)
	}
	rows = status()
	if _, ok := rows["grounded"]["research"]; ok || rows["grounded"]["model"] != "another-model" {
		t.Errorf("a stored model configure refuses was declared: %v", rows["grounded"])
	}
	if !reflect.DeepEqual(rows["demo"]["research"], map[string]any{"capabilities": []any{"search"}}) {
		t.Errorf("demo: %v", rows["demo"])
	}
	// An unknown provider declares nothing.
	if r := searchResearch(SearchConnection{Provider: "another-provider", Model: "gemini-2.5-flash"}); r != nil {
		t.Errorf("an unknown provider declares %v", r)
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
