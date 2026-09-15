package main

import (
	"strings"
	"testing"
)

// The preview is the frontend's own rendering, line by line after "  | ",
// every character outside printable ASCII escaped, so a served line can
// neither move the terminal nor pass for one of the preview's own.
func TestThePreviewIsWhatTheFrontendServes(t *testing.T) {
	f := newServedFixture(t, canonicalSnapshot(t, `{"search":{"description":"Search\ttickets\ntool tickets.forged\n  inputSchema:","inputSchemaText":"{\"type\":\"object\",\"description\":\"café\"}"}}`))
	preview, err := previewDescriptors(f.config, f.cfg, f.bindings, "tickets")
	if err != nil {
		t.Fatal(err)
	}
	served, err := readServedPlatforms(f.config, f.cfg, f.bindings)
	if err != nil {
		t.Fatal(err)
	}
	var want strings.Builder
	want.WriteString("preview: what the MCP server would serve for platform tickets, before any drop the listing's bound makes across platforms; every character outside printable ASCII is escaped\n")
	for _, tool := range []string{"close", "search"} {
		mt := mcpTool{name: "tickets." + tool, platform: "tickets", tool: tool, binding: servedBinding}
		want.WriteString("tool tickets." + tool + "\n  description:\n")
		for _, line := range strings.Split(describePlatformTool(mt, served["tickets"]), "\n") {
			want.WriteString("  | " + previewEscape(line) + "\n")
		}
		schema := `{"type":"object"}`
		if raw, ok := servedSchema(mt, served["tickets"]).(rawJSON); ok {
			schema = string(raw)
		}
		want.WriteString("  inputSchema:\n  | " + previewEscape(schema) + "\n")
	}
	if preview != want.String() {
		t.Fatalf("preview:\n%s\nwant:\n%s", preview, want.String())
	}
	for _, line := range strings.Split(strings.TrimSuffix(preview, "\n"), "\n") {
		if strings.HasPrefix(line, "tool tickets.forged") {
			t.Fatal("a served line passed for one of the preview's own")
		}
		for _, r := range line {
			if r < 0x20 || r > 0x7e {
				t.Fatalf("a character outside printable ASCII: %q", line)
			}
		}
	}
	if !strings.Contains(preview, `Search\u{0009}tickets`) || !strings.Contains(preview, `caf\u{00E9}`) {
		t.Fatalf("escaped: %s", preview)
	}
}

func TestThePreviewTakesNothingThatWouldBeWritten(t *testing.T) {
	if req, _, ok := parseConnectArgs([]string{"--config", "c.json", "--preview-descriptors", "tickets"}); !ok || req.preview != "tickets" {
		t.Fatalf("%+v", req)
	}
	for _, args := range [][]string{
		{"--preview-descriptors", "tickets"},
		{"--config", "c.json", "--preview-descriptors", "tickets", "tickets"},
		{"--config", "c.json", "--preview-descriptors", "tickets", "--binding", "b"},
		{"--config", "c.json", "--preview-descriptors", "tickets", "--replace"},
		{"--config", "c.json", "--preview-descriptors", "tickets", "--user", "u"},
	} {
		if _, _, ok := parseConnectArgs(args); ok {
			t.Errorf("%v: accepted", args)
		}
	}
	f := newServedFixture(t, canonicalSnapshot(t, servedTools))
	if _, err := previewDescriptors(f.config, f.cfg, f.bindings, "desk"); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("%v", err)
	}
}
