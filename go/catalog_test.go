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
			// Live through DBHub, which connects as it starts (so no probe) and answers SQL as JSON text; the
			// operator's read-only role, not the server, holds the live operation to reading (catalog/README.md).
			if b.history == nil || b.live == nil || strings.Join(b.live.args, " ") != "--transport stdio" || b.live.probe != "" || b.live.probeFailure != "" || !strings.HasPrefix(b.history.image, "airbyte/source-postgres:") || !strings.HasPrefix(b.live.image, "bytebase/dbhub:") || strings.Join(b.live.tools, ",") != "execute_sql,search_objects" {
				t.Fatalf("catalog/postgres.json: history through the Airbyte connector, live through DBHub over stdio: %+v %+v", b.history, b.live)
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
