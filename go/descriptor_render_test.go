package main

import (
	"strings"
	"testing"
)

func TestTheFourTemplates(t *testing.T) {
	desc := "Search tickets.\nMatches the title and the body."
	schema, err := decodeWritten([]byte(`{"type":"object","description":"The search","properties":{"q":{"type":"string","description":"Words to find","title":"Query"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	tool := mcpTool{name: "tickets.search", platform: "tickets", tool: "search", binding: "tickets@sha256:" + strings.Repeat("0", 64)}
	head := "Tool `search` of platform `tickets` (binding `tickets@sha256:" + strings.Repeat("0", 64) + "`), called by the engine's own adapter under the engine's key."
	provenance := " When `connect` ran at `2026-09-15T01:02:03Z`, the platform's server described it as follows, in its own words, which are not the engine's and which no receipt covers:\n\n"
	server := &snapshotServer{name: "tickets-mcp", version: "2.4.1"}
	for _, tc := range []struct {
		name   string
		served *servedPlatform
		want   string
		schema string
	}{
		{"both captured", &servedPlatform{capturedAt: "2026-09-15T01:02:03Z", server: server, tools: map[string]servedTool{"search": {description: &desc, schema: schema}}},
			head + " Its arguments are declared by the platform's server's schema, as captured. " + answerCarries + provenance +
				"```\nserver: tickets-mcp 2.4.1\nSearch tickets.\n  Matches the title and the body.\n(root): The search\n/properties/q: Words to find\n```",
			`{"properties":{"q":{"type":"string"}},"type":"object"}`},
		{"the schema alone", &servedPlatform{capturedAt: "2026-09-15T01:02:03Z", server: server, tools: map[string]servedTool{"search": {schema: schema}}},
			head + " Its arguments are declared by the platform's server's schema, as captured. " + answerCarries + provenance +
				"```\nserver: tickets-mcp 2.4.1\n(root): The search\n/properties/q: Words to find\n```",
			`{"properties":{"q":{"type":"string"}},"type":"object"}`},
		{"the description alone", &servedPlatform{capturedAt: "2026-09-15T01:02:03Z", tools: map[string]servedTool{"search": {description: &desc}}},
			head + " Its arguments are what the platform's server defines. " + answerCarries + provenance +
				"```\nSearch tickets.\n  Matches the title and the body.\n```",
			`{"type":"object"}`},
		{"nothing captured", nil,
			head + " Its arguments are what the platform's server defines; the engine does not read that server's schema. " + answerCarries,
			`{"type":"object"}`},
	} {
		if got := describePlatformTool(tool, tc.served); got != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
		got := servedSchema(tool, tc.served)
		var text string
		if raw, ok := got.(rawJSON); ok {
			text = string(raw)
		} else {
			text = `{"type":"object"}`
		}
		if text != tc.schema {
			t.Errorf("%s: schema %s, want %s", tc.name, text, tc.schema)
		}
	}
}

func TestAFenceIsLongerThanAnyRunInside(t *testing.T) {
	for _, tc := range []struct {
		items []string
		fence string
	}{
		{[]string{"plain"}, "```"},
		{[]string{"a ``` b"}, "````"},
		{[]string{"a ````` b\n```"}, "``````"},
		// A run is within a line: not across items, nor lines.
		{[]string{"a```", "```b"}, "````"},
		{[]string{"```\n```"}, "````"},
		{[]string{"`a`a`a`"}, "```"},
	} {
		block := fencedBlock(tc.items)
		if !strings.HasPrefix(block, tc.fence+"\n") || !strings.HasSuffix(block, "\n"+tc.fence) || strings.HasPrefix(block, tc.fence+"`") {
			t.Errorf("%q: %q", tc.items, block)
		}
	}
	for _, tc := range []struct {
		items []string
		block string
	}{
		{nil, "```\n```"},
		{[]string{""}, "```\n```"},
		{[]string{"", ""}, "```\n\n\n```"},
		{[]string{"a\nb", "", "c\n"}, "```\na\n  b\n\nc\n  \n```"},
	} {
		if block := fencedBlock(tc.items); block != tc.block {
			t.Errorf("%q: %q, not %q", tc.items, block, tc.block)
		}
	}
}

// A description is built to its limit exactly: at its own length it is
// whole, and a byte short it is none.
func TestADescriptionIsBuiltToItsLimit(t *testing.T) {
	words := "one\ntwo ``` three\n"
	root, err := decodeWritten([]byte(`{"type":"object","description":"top","properties":{"a/b~":{"description":"x\ny"},"c":{"description":""}}}`))
	if err != nil {
		t.Fatal(err)
	}
	tool := mcpTool{name: "tickets.search", platform: "tickets", tool: "search", binding: "tickets@sha256:" + strings.Repeat("0", 64)}
	for _, p := range []*servedPlatform{
		{capturedAt: "2026-09-15T00:00:00Z", server: &snapshotServer{name: "s\nt", version: "1"}, tools: map[string]servedTool{"search": {description: &words, schema: root}}},
		{capturedAt: "2026-09-15T00:00:00Z", tools: map[string]servedTool{"search": {schema: root}}},
		nil,
	} {
		whole := describePlatformTool(tool, p)
		if d, ok := describePlatformToolWithin(tool, p, len(whole)); !ok || d != whole {
			t.Fatalf("at its own length, the description is whole: %q", d)
		}
		if p == nil {
			continue
		}
		if d, ok := describePlatformToolWithin(tool, p, len(whole)-1); ok {
			t.Fatalf("a byte short, the description is none: %q", d)
		}
	}
}

func TestAnIdentifierIsACodeSpanItCannotLeave(t *testing.T) {
	for in, want := range map[string]string{
		"search":             "`search`",
		"a`b":                "``a`b``",
		"`edge":              "`` `edge ``",
		"line\nbreak":        "`line\\u{000A}break`",
		"<script>x</script>": "`<script>x</script>`",
		"rtl\u202eover":      "`rtl\\u{202E}over`",
		" padded ":           "`  padded  `",
	} {
		if got := codeSpan(in); got != want {
			t.Errorf("codeSpan(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLabelsArePointersToSchemaLocations(t *testing.T) {
	root, err := decodeWritten([]byte(`{"type":"object","properties":{"a/b":{"description":"slash"},"c~d":{"description":"tilde"},"description":{"type":"string","description":"a property named description"},"list":{"type":"array","items":{"description":"each"}},"either":{"anyOf":[{"description":"first"},{"not":{"description":"never"}}]}},"description":"last, as written","additionalProperties":{"description":"any other"}}`))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, d := range schemaDescriptions(root) {
		got = append(got, d.label+"="+d.text)
	}
	want := []string{"/properties/a~1b=slash", "/properties/c~0d=tilde", "/properties/description=a property named description", "/properties/list/items=each",
		"/properties/either/anyOf/0=first", "/properties/either/anyOf/1/not=never", "(root)=last, as written", "/additionalProperties=any other"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("labels in the order written:\n got %q\nwant %q", got, want)
	}
}

func TestTheProjectionRemovesAnnotationsAtSchemaLocationsOnly(t *testing.T) {
	root, err := decodeWritten([]byte(`{"type":"object","title":"T","$comment":"c","properties":{"title":{"type":"string","default":"x","examples":["y"],"deprecated":true,"readOnly":false,"writeOnly":true},"default":{"enum":[{"description":"data"}],"const":1.50},"n":{"minimum":1e2,"multipleOf":0.10}},"additionalProperties":{"description":"d","type":"integer"},"anyOf":[{"description":"a"}],"required":["title"]}`))
	if err != nil {
		t.Fatal(err)
	}
	got := string(projectSchema(root))
	want := `{"additionalProperties":{"type":"integer"},"anyOf":[{}],"properties":{"default":{"const":1.50,"enum":[{"description":"data"}]},"n":{"minimum":1e2,"multipleOf":0.10},"title":{"type":"string"}},"required":["title"],"type":"object"}`
	if got != want {
		t.Fatalf("projection:\n got %s\nwant %s", got, want)
	}
}
