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
		// No remote write is sent under the read-only header a server
		// honours: a write needs it absent, and a binding that sent it would
		// ask the server to refuse every write it is pointed at.
		if b.write != nil {
			for _, h := range b.write.headers {
				if header, _, _ := strings.Cut(h, "="); strings.EqualFold(header, "X-MCP-Readonly") {
					t.Fatalf("catalog/%s: the write operation sends %s", e.Name(), h)
				}
			}
		}
		for _, op := range []*operation{b.live, b.write} {
			if op != nil && op.url != "" && (op.licence == "" || op.bearer == "") {
				t.Fatalf("catalog/%s: a remote operation states its licence and the credentials member it sends: %+v", e.Name(), op)
			}
		}
		switch name {
		case "azure-devops":
			// The organization's remote MCP server, for writes alone: the
			// three work-item write tools the server lists (catalog/README.md),
			// no read tool, no read-only header; reads are the connection's.
			if b.history != nil || b.live != nil || b.write == nil || b.write.url != "https://mcp.dev.azure.com/{organization}" || b.write.bearer != "token" || len(b.write.headers) != 0 ||
				strings.Join(b.write.tools, ",") != "wit_work_item_write,wit_work_item_comment_write,wit_work_item_link_write" {
				t.Fatalf("catalog/azure-devops.json: the remote server's work-item write tools: %+v", b.write)
			}
		case "databricks":
			// A Unity Catalog function's managed MCP server, for writes alone:
			// its one tool, named for the function; no SQL server, since a
			// decision could then authorize an arbitrary statement.
			if b.history != nil || b.live != nil || b.write == nil || b.write.url != "https://{workspace}/api/2.0/mcp/functions/{catalog}/{schema}/{function}" || b.write.bearer != "token" || len(b.write.headers) != 0 ||
				strings.Join(b.write.tools, ",") != "{catalog}__{schema}__{function}" {
				t.Fatalf("catalog/databricks.json: one Unity Catalog function's tool: %+v", b.write)
			}
		}
		for _, op := range []*operation{b.live, b.write} {
			if op == nil || op.url == "" {
				continue
			}
			for _, tool := range op.tools {
				if strings.Contains(strings.ToLower(tool), "sql") || strings.Contains(strings.ToLower(op.url), "/mcp/sql") {
					t.Fatalf("catalog/%s: %s names raw SQL, which no decision policy can bind argument by argument", e.Name(), tool)
				}
			}
		}
		// No write operation names a tool that takes a statement (#260, #257):
		// a decision policy binds a statement's text only as a whole.
		if b.write != nil {
			if reason := statementWriteTool(b.write.tools); reason != "" {
				t.Fatalf("catalog/%s: the write operation %s", e.Name(), reason)
			}
		}
		if name == "postgres" {
			// Live through DBHub, which connects as it starts (so no probe) and answers SQL as JSON text; the
			// operator's read-only role, not the server, holds the live operation to reading (catalog/README.md).
			if b.write != nil {
				t.Fatalf("catalog/postgres.json: no write operation, since raw SQL is no write tool (#260): %+v", b.write)
			}
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

// The write-back bindings, pinned by the digests of their files as they
// ship and filled with example parameters, derive the executor a
// configuration would run: the resolved URL, the bearer member, the write
// tools and --error-results, and no template; a template with a placeholder
// of another form is refused.
func TestTheWriteBackBindingsResolveAsShipped(t *testing.T) {
	catalog := filepath.Join("..", "catalog")
	for _, tc := range []struct {
		name, parameters, url, tools string
	}{
		{"azure-devops", `{"organization":"example-org"}`, "https://mcp.dev.azure.com/example-org", "wit_work_item_write,wit_work_item_comment_write,wit_work_item_link_write"},
		{"databricks", `{"workspace":"dbc-example.cloud.databricks.com","catalog":"main","schema":"decisions","function":"record_approval"}`, "https://dbc-example.cloud.databricks.com/api/2.0/mcp/functions/main/decisions/record_approval", "main__decisions__record_approval"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(catalog, tc.name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			ref := tc.name + "@" + digestOf(string(data))
			b, err := loadBinding(catalog, ref)
			if err != nil {
				t.Fatalf("the shipped file loads under its digest %s: %v", ref, err)
			}
			v, err := parseJSON([]byte(tc.parameters))
			if err != nil {
				t.Fatal(err)
			}
			parameters, err := parsePlatformParameters(v)
			if err != nil {
				t.Fatal(err)
			}
			if b, err = resolveParameters(b, parameters, ref); err != nil {
				t.Fatal(err)
			}
			cfg := engineConfig{runtime: "docker", platforms: []platformConfig{{name: "p", credentials: map[string]string{"write": "/run/secrets/p-write"}, user: "engine-p", home: "/home/engine-p", write: true}}}
			write := deriveSources(cfg, map[string]binding{"p": b})["p/write"]
			want := "adapter-mcp --url=" + tc.url + " --credentials=/run/secrets/p-write --bearer=token --tools=" + tc.tools + " --error-results"
			if strings.Join(write.argv, " ") != want || write.endpoint != tc.url || strings.Join(write.tools, ",") != tc.tools {
				t.Fatalf("%s: derived %q (endpoint %q), want %q", ref, write.argv, write.endpoint, want)
			}
			t.Logf("%s resolves to %s", ref, write.endpoint)
			// A placeholder of another form in the shipped template is refused.
			bad := strings.Replace(string(data), "/{", "/{X", 1)
			if _, err := parseBinding([]byte(bad)); err == nil || !strings.Contains(err.Error(), "which is not a parameter's name") {
				t.Fatalf("a disallowed placeholder: %v", err)
			}
		})
	}
}

// statementWriteTool says why a write operation's tools name one that takes a
// statement, or "" when none does. The catalog states tool names, not their
// arguments, so the names that carry a statement are held out: execute_sql and
// anything naming sql, a query or a statement.
func statementWriteTool(tools []string) string {
	for _, tool := range tools {
		lower := strings.ToLower(tool)
		for _, word := range []string{"sql", "query", "statement"} {
			if strings.Contains(lower, word) {
				return "names " + tool + ", which takes a statement; no decision policy can bind a statement argument by argument"
			}
		}
	}
	return ""
}

// The refusal holds: the operation the binding used to carry, put back, is
// caught by the shape test's rule, and the shipped write tools are not.
func TestStatementWriteToolIsRefused(t *testing.T) {
	for _, tools := range [][]string{{"execute_sql"}, {"run_query"}, {"EXECUTE_STATEMENT"}, {"wit_work_item_write", "execute_sql"}} {
		if statementWriteTool(tools) == "" {
			t.Fatalf("%v is a write tool that takes a statement and was not refused", tools)
		}
	}
	for _, tools := range [][]string{{"wit_work_item_write", "wit_work_item_comment_write"}, {"{catalog}__{schema}__{function}"}, {"record_approval"}} {
		if reason := statementWriteTool(tools); reason != "" {
			t.Fatalf("%v refused: %s", tools, reason)
		}
	}
	data, err := os.ReadFile(filepath.Join("..", "catalog", "postgres.json"))
	if err != nil {
		t.Fatal(err)
	}
	mutant := strings.Replace(string(data), `    }
  }
}`, `    },
    "write": {"shape": "mcp", "server": {"image": "bytebase/dbhub:1.2.3@sha256:8fbdf3f579b7eb2701c32d895447e35f61b24e6c2505b0fcfd34e314bdf9f5db", "args": ["--transport", "stdio"]}, "tools": ["execute_sql"], "licence": "MIT"}
  }
}`, 1)
	if mutant == string(data) {
		t.Fatal("the mutant did not apply")
	}
	b, err := parseBinding([]byte(mutant))
	if err != nil {
		t.Fatal(err)
	}
	if b.write == nil || statementWriteTool(b.write.tools) == "" {
		t.Fatalf("postgres with its write operation put back is not caught: %+v", b.write)
	}
}
