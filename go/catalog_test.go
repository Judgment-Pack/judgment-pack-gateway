package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The bindings the engine ships parse under the rules serve applies, each
// naming its own file's platform, every image pinned by digest and every
// licence stated; the Postgres binding's live server runs restricted.
func TestShippedCatalogHoldsItsShape(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "catalog"))
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		seen++
		name := strings.TrimSuffix(e.Name(), ".json")
		data, err := os.ReadFile(filepath.Join("..", "catalog", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		b, err := parseBinding(data)
		if err != nil {
			t.Fatalf("catalog/%s: %v", e.Name(), err)
		}
		if b.platform != name {
			t.Fatalf("catalog/%s names platform %q", e.Name(), b.platform)
		}
		for _, op := range []*operation{b.history, b.live} {
			if op != nil && (!isPinnedImage(op.image) || op.licence == "" || !strings.Contains(op.image, ":")) {
				t.Fatalf("catalog/%s: %+v is not a versioned, pinned, licensed image", e.Name(), op)
			}
		}
		if name == "postgres" {
			if b.history == nil || b.live == nil || strings.Join(b.live.args, " ") != "--access-mode=restricted" || b.live.probe != "list_schemas" || b.live.probeFailure != "Error:" || !strings.HasPrefix(b.history.image, "airbyte/source-postgres:") || !strings.HasPrefix(b.live.image, "crystaldba/postgres-mcp:") {
				t.Fatalf("catalog/postgres.json: history through the Airbyte connector, live through the restricted MCP server: %+v %+v", b.history, b.live)
			}
			for _, tool := range b.live.tools {
				if strings.HasPrefix(tool, "analyze_") || tool == "get_top_queries" {
					t.Fatalf("catalog/postgres.json: %s is an operator's tool, not a decision's", tool)
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("the catalog ships no binding")
	}
}
