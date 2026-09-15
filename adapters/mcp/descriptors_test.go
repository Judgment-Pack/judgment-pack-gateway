package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"adapters/internal/canon"
	"adapters/internal/fakemcp"
)

const testBinding = "tickets@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// captureReport is a check report read in full.
type captureReport struct {
	Status             string            `json:"status"`
	Server             map[string]string `json:"server"`
	Tools              []string          `json:"tools"`
	ToolsUnlisted      int               `json:"toolsUnlisted"`
	Descriptors        json.RawMessage   `json:"descriptors"`
	Fallbacks          []fallback        `json:"fallbacks"`
	FallbacksUnlisted  int               `json:"fallbacksUnlisted"`
	DescriptorsDropped string            `json:"descriptorsDropped"`
}

func readReport(t *testing.T, out []byte) captureReport {
	t.Helper()
	var top struct {
		Check captureReport `json:"check"`
	}
	if err := json.Unmarshal(out, &top); err != nil {
		t.Fatalf("report: %v\n%s", err, out)
	}
	return top.Check
}

// capturing is a check configuration that captures for testBinding, with
// the clock fixed.
func capturing(t *testing.T, tools ...string) Config {
	t.Helper()
	cfg := fake(t)
	cfg.Tools = tools
	cfg.Descriptors = &DescriptorTarget{Platform: "tickets", Binding: testBinding}
	saved := now
	now = func() time.Time { return time.Date(2026, 9, 15, 1, 2, 3, 400, time.UTC) }
	t.Cleanup(func() { now = saved })
	return cfg
}

// listLine has tools/list answer with this result, written as it is.
func listLine(t *testing.T, result string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "list")
	if err := os.WriteFile(path, []byte(`{"jsonrpc":"2.0","id":{id},"result":`+result+"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(fakemcp.EnvListLine, path)
}

// toolsFile has tools/list answer with this tools array.
func toolsFile(t *testing.T, tools any) {
	t.Helper()
	data, err := json.Marshal(tools)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "tools.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(fakemcp.EnvTools, path)
}

func TestCheckCapturesTheAllowedToolsAsTheServerWroteThem(t *testing.T) {
	cfg := capturing(t, "search", "close")
	// The schema as the server wrote it -- spaced, tabbed, a name
	// escaped, since a message on stdio holds no line break -- and a tool
	// the operation does not allow, whose descriptor is not captured.
	listLine(t, `{"tools":[`+
		`{"name":"drop","description":"Drop everything","inputSchema":{"type":"object"}},`+
		`{"name":"search","description":"Search tickets","inputSchema":{ "type": "object",`+"\t"+`  "properties": {"q\u00e9": {"type": "string"}}, "required": ["q\u00e9"] }},`+
		`{"name":"close","inputSchema":{"type":"object"}}]}`)
	out, err := Check(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	report := readReport(t, out)
	want := `{"binding":"` + testBinding + `","capturedAt":"2026-09-15T01:02:03Z","platform":"tickets","policy":1,` +
		`"server":{"name":"fake-mcp","version":"1.0"},"tools":{"close":{"inputSchemaText":"{\"type\":\"object\"}"},` +
		`"search":{"description":"Search tickets","inputSchemaText":"{ \"type\": \"object\",\t  \"properties\": {\"q\\u00e9\": {\"type\": \"string\"}}, \"required\": [\"q\\u00e9\"] }"}}}`
	if string(report.Descriptors) != want {
		t.Fatalf("the snapshot, canonical, with each schema's original text:\n got %s\nwant %s", report.Descriptors, want)
	}
	if canonical, err := canon.Canonicalize(report.Descriptors, canon.RefuseNumbers); err != nil || !bytes.Equal(canonical, report.Descriptors) {
		t.Fatalf("the snapshot is in canonical form: %v", err)
	}
	if len(report.Fallbacks) != 0 || report.DescriptorsDropped != "" {
		t.Fatalf("an absent description is absent, not fallen back: %s", out)
	}
	if strings.Join(report.Tools, ",") != "drop,search,close" {
		t.Fatalf("every offered tool is still listed: %v", report.Tools)
	}
}

func TestOnlyACheckAskedToCaptureDoes(t *testing.T) {
	cfg := fake(t)
	cfg.Tools = []string{"query"}
	out, err := Check(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), `"descriptors"`) || strings.Contains(string(out), `"fallbacks"`) {
		t.Fatalf("a check not asked to capture reports as it did: %s", out)
	}
	for _, bad := range []DescriptorTarget{{Platform: "", Binding: testBinding}, {Platform: "tickets", Binding: "tickets"},
		{Platform: "tickets", Binding: "@sha256:" + strings.Repeat("0", 64)}, {Platform: "tickets", Binding: "tickets@sha256:ABC"}} {
		cfg.Descriptors = &bad
		if _, err := Check(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "pinned binding") {
			t.Errorf("%+v: %v", bad, err)
		}
	}
}

func TestAPinnedListingFailsOnARepeatedNameOrCursor(t *testing.T) {
	page := func(tools, next string) string {
		result := `{"tools":[` + tools + `]`
		if next != "" {
			result += `,"nextCursor":"` + next + `"`
		}
		return `{"jsonrpc":"2.0","id":{id},"result":` + result + "}}"
	}
	a := `{"name":"a","inputSchema":{"type":"object"}}`
	b := `{"name":"b","inputSchema":{"type":"object"}}`
	for _, tc := range []struct {
		name  string
		pages []string
		want  string
	}{
		{"a name twice on one page", []string{page(a+","+a, "")}, "offers one tool name twice"},
		{"a name on two pages", []string{page(a, "1"), page(a, "")}, "offers one tool name twice"},
		{"a cursor twice", []string{page(a, "1"), page(b, "1")}, "gave a cursor it had given before"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pages")
			if err := os.WriteFile(path, []byte(strings.Join(tc.pages, "\n")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := capturing(t, "a")
			t.Setenv(fakemcp.EnvListPages, path)
			if out, err := Check(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q: %v %s", tc.want, err, out)
			}
			// A listing that is not pinned is not held to it.
			if tc.name != "a cursor twice" {
				cfg.Descriptors = nil
				if out, err := Check(context.Background(), cfg); err != nil {
					t.Fatalf("a check that captures nothing lists as it did: %v %s", err, out)
				}
			}
		})
	}
	// The pages themselves are read: a listing across two pages is whole.
	path := filepath.Join(t.TempDir(), "pages")
	if err := os.WriteFile(path, []byte(page(a, "1")+"\n"+page(b, "")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := capturing(t, "a", "b")
	t.Setenv(fakemcp.EnvListPages, path)
	out, err := Check(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if report := readReport(t, out); !strings.Contains(string(report.Descriptors), `"a":{`) || !strings.Contains(string(report.Descriptors), `"b":{`) {
		t.Fatalf("both pages' tools are captured: %s", out)
	}
}

func TestACredentialValueIsRefusedAndNotDisclosed(t *testing.T) {
	cfg := capturing(t, "ask", "lookup", "query_hunter2", "plain", "named")
	// The fixture's credentials hold hunter2, app and require.
	t.Setenv(fakemcp.EnvServerInfo, `{"name":"srv","version":"1.0+hunter2"}`)
	toolsFile(t, []map[string]any{
		{"name": "ask", "description": "Ask with hunter2 in hand", "inputSchema": map[string]any{"type": "object"}},
		{"name": "lookup", "description": "Look up", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"hunter2_id": map[string]any{"type": "string"}}}},
		{"name": "query_hunter2", "description": "Query", "inputSchema": map[string]any{"type": "object"}},
		// required is the grammar's word and passes beside the credential
		// "require"; a name that holds it does not.
		{"name": "plain", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"id": map[string]any{"type": "string"}}, "required": []string{"id"}}},
		{"name": "named", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"required_by": map[string]any{"type": "string"}}}},
	})
	out, err := Check(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "hunter2") {
		t.Fatalf("the report discloses a credential value: %s", out)
	}
	report := readReport(t, out)
	var snap struct {
		Server *serverIdentity         `json:"server"`
		Tools  map[string]capturedTool `json:"tools"`
	}
	if err := json.Unmarshal(report.Descriptors, &snap); err != nil {
		t.Fatal(err)
	}
	if snap.Server != nil {
		t.Fatalf("a refused identity is omitted: %s", report.Descriptors)
	}
	if len(snap.Tools) != 3 || snap.Tools["lookup"].Description == nil || snap.Tools["lookup"].InputSchemaText != nil ||
		snap.Tools["plain"].InputSchemaText == nil || snap.Tools["ask"].Description != nil {
		t.Fatalf("each candidate is judged on its own: %s", report.Descriptors)
	}
	want := []fallback{
		{Part: partServer, Reason: "the server's version holds a value of the credentials"},
		{Tool: "ask", Part: partDescription, Reason: "the description holds a value of the credentials"},
		{Tool: "lookup", Part: partInputSchema, Reason: "a string in it holds a value of the credentials"},
		{Tool: "query_[redacted]", Part: partTool, Reason: "its name holds a value of the credentials"},
		{Tool: "named", Part: partInputSchema, Reason: "a string in it holds a value of the credentials"},
	}
	if fmt.Sprint(report.Fallbacks) != fmt.Sprint(want) {
		t.Fatalf("fallbacks, in order, saying only that a credential value was held:\n got %v\nwant %v", report.Fallbacks, want)
	}
}

func TestCandidatesFallBackOneByOne(t *testing.T) {
	cfg := capturing(t, "a", "b", "c", "d")
	toolsFile(t, []map[string]any{
		{"name": "a", "description": "Right-to-left \u202e", "inputSchema": map[string]any{"type": "object"}},
		{"name": "b", "description": 5, "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"e": map[string]any{"type": "string", "format": "email"}}}},
		{"name": "c", "description": "No schema"},
		{"name": "d", "description": nil, "inputSchema": map[string]any{"$ref": "#/x", "type": "object"}},
	})
	out, err := Check(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	report := readReport(t, out)
	want := []fallback{
		{Tool: "a", Part: partDescription, Reason: "the description holds U+202E, which display policy 1 refuses"},
		{Tool: "b", Part: partDescription, Reason: "the description is not a string"},
		{Tool: "b", Part: partInputSchema, Reason: "/properties/e/format: not a keyword of schema grammar 1"},
		{Tool: "c", Part: partInputSchema, Reason: "the tool declares no inputSchema"},
		{Tool: "d", Part: partDescription, Reason: "the description is not a string"},
		{Tool: "d", Part: partInputSchema, Reason: "/$ref: not a keyword of schema grammar 1"},
	}
	if fmt.Sprint(report.Fallbacks) != fmt.Sprint(want) {
		t.Fatalf("fallbacks:\n got %v\nwant %v", report.Fallbacks, want)
	}
	if !strings.Contains(string(report.Descriptors), `"tools":{"a":{"inputSchemaText":"{\"type\":\"object\"}"},"c":{"description":"No schema"}}`) {
		t.Fatalf("a tool with neither candidate is not listed: %s", report.Descriptors)
	}
}

func TestAnOversizedIdentityFallsBackAndIsCappedInTheReport(t *testing.T) {
	cfg := capturing(t, "query")
	long := strings.Repeat("n", 600)
	t.Setenv(fakemcp.EnvServerInfo, `{"name":"`+long+`","version":"1"}`)
	out, err := Check(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	report := readReport(t, out)
	if name := report.Server["name"]; len(name) != maxReportField || !strings.HasSuffix(name, "…") {
		t.Fatalf("the report's server name is cut to %d bytes, the marker included: %d %q", maxReportField, len(name), name)
	}
	if strings.Contains(string(report.Descriptors), `"server"`) || len(report.Fallbacks) != 1 ||
		report.Fallbacks[0].Reason != "the server's name is 600 bytes, over 256" {
		t.Fatalf("an identity over its bound is omitted and said so: %s", out)
	}
}

// quoted is a descriptor list of n tools whose descriptions are 4096
// quotation marks, each written as two bytes in the snapshot.
func quoted(n int) ([]map[string]any, []string) {
	var tools []map[string]any
	var names []string
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("t%03d", i)
		names = append(names, name)
		tools = append(tools, map[string]any{"name": name, "description": strings.Repeat(`"`, maxDescription)})
	}
	return tools, names
}

func TestTheSnapshotAdmitsToolsInOrderWhileItFits(t *testing.T) {
	for _, tc := range []struct {
		name  string
		tools func() ([]map[string]any, []string)
		bound string
	}{
		// Descriptions of quotation marks fill the snapshot, at two bytes
		// each, before their text fills its own bound.
		{"the snapshot's bound", func() ([]map[string]any, []string) { return quoted(60) }, "snapshot"},
		// Schemas of fifteen 1000-byte descriptions, few quotation marks
		// among them, fill the candidates' text before the snapshot.
		{"the candidates' bound", func() ([]map[string]any, []string) {
			var tools []map[string]any
			var names []string
			for i := 0; i < 20; i++ {
				name := fmt.Sprintf("s%03d", i)
				names = append(names, name)
				props := map[string]any{}
				for p := 0; p < 15; p++ {
					props[fmt.Sprintf("p%02d", p)] = map[string]any{"description": strings.Repeat("d", 1000)}
				}
				tools = append(tools, map[string]any{"name": name, "inputSchema": map[string]any{"type": "object", "properties": props}})
			}
			return tools, names
		}, "text"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tools, names := tc.tools()
			// A small tool last, which would fit on its own: every tool
			// after the first that does not fit falls back all the same.
			tools = append(tools, map[string]any{"name": "zzz", "inputSchema": map[string]any{"type": "object"}})
			names = append(names, "zzz")
			cfg := capturing(t, names...)
			toolsFile(t, tools)
			out, err := Check(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			report := readReport(t, out)
			var snap struct {
				Tools map[string]capturedTool `json:"tools"`
			}
			if err := json.Unmarshal(report.Descriptors, &snap); err != nil {
				t.Fatal(err)
			}
			admitted := len(snap.Tools)
			for _, name := range names[:admitted] {
				if _, ok := snap.Tools[name]; !ok {
					t.Fatalf("the snapshot is not a prefix of the server's order: %s missing", name)
				}
			}
			if len(report.Descriptors) > maxSnapshot || admitted == 0 || admitted == len(names) {
				t.Fatalf("%d of %d admitted in %d bytes", admitted, len(names), len(report.Descriptors))
			}
			text := 0
			for _, tool := range snap.Tools {
				text += len(deref(tool.Description)) + len(deref(tool.InputSchemaText))
			}
			if text > maxCandidateText {
				t.Fatalf("the candidates' text is %d bytes", text)
			}
			// The first tool left out would have passed the bound named.
			next := tools[admitted]
			var grow, parts int
			if d, ok := next["description"].(string); ok {
				grow = len(fmt.Sprintf(`,"%s":{"description":""}`, next["name"])) + 2*len(d)
				parts = len(d)
			} else {
				schema, _ := json.Marshal(next["inputSchema"])
				grow = len(fmt.Sprintf(`,"%s":{"inputSchemaText":""}`, next["name"])) + len(schema) + strings.Count(string(schema), `"`)
				parts = len(schema)
			}
			switch tc.bound {
			case "snapshot":
				if len(report.Descriptors)+grow <= maxSnapshot {
					t.Fatalf("the next tool, %d bytes more, fitted the snapshot of %d", grow, len(report.Descriptors))
				}
			case "text":
				if text+parts <= maxCandidateText {
					t.Fatalf("the next tool, %d bytes of text more, fitted the %d", parts, text)
				}
			}
			var over []string
			for _, f := range report.Fallbacks {
				if f.Part == partTool && strings.HasPrefix(f.Reason, "over the platform's budget") {
					over = append(over, f.Tool)
				}
			}
			if strings.Join(over, ",") != strings.Join(names[admitted:], ",") {
				t.Fatalf("every tool after the first left out falls back over the budget: %v", over)
			}
		})
	}
}

func TestTheReportsListsAreCappedAndCounted(t *testing.T) {
	// 2500 offered tools of 40-byte names pass the list's 64 KiB.
	cfg := fake(t)
	var tools []map[string]any
	for i := 0; i < 2500; i++ {
		tools = append(tools, map[string]any{"name": fmt.Sprintf("tool_%035d", i), "inputSchema": map[string]any{"type": "object"}})
	}
	tools = append(tools[:1], append([]map[string]any{{"name": strings.Repeat("x", 700), "inputSchema": map[string]any{"type": "object"}}}, tools[1:]...)...)
	toolsFile(t, tools)
	out, err := Check(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	report := readReport(t, out)
	listed, _ := json.Marshal(report.Tools)
	if len(listed) > maxReportList || report.ToolsUnlisted == 0 || len(report.Tools)+report.ToolsUnlisted != len(tools) {
		t.Fatalf("the tool list is %d bytes with %d listed and %d counted", len(listed), len(report.Tools), report.ToolsUnlisted)
	}
	if long := report.Tools[1]; len(long) != maxReportField || !strings.HasSuffix(long, "…") {
		t.Fatalf("a name is cut to %d bytes, the marker included: %d", maxReportField, len(long))
	}
	// 1000 allowed tools, each schema refused, pass the fallbacks' 64 KiB.
	var names []string
	tools = nil
	for i := 0; i < 1000; i++ {
		name := fmt.Sprintf("f%04d", i)
		names = append(names, name)
		tools = append(tools, map[string]any{"name": name, "inputSchema": map[string]any{"type": "object", "format": "uri"}})
	}
	cfg = capturing(t, names...)
	toolsFile(t, tools)
	if out, err = Check(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	report = readReport(t, out)
	encoded, _ := json.Marshal(report.Fallbacks)
	if len(encoded) > maxReportList || report.FallbacksUnlisted == 0 || len(report.Fallbacks)+report.FallbacksUnlisted != 1000 {
		t.Fatalf("the fallbacks are %d bytes with %d listed and %d counted", len(encoded), len(report.Fallbacks), report.FallbacksUnlisted)
	}
}

func TestAReportPastItsBoundDropsTheSnapshot(t *testing.T) {
	cfg := capturing(t, "query")
	out, err := Check(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	report := readReport(t, out)
	saved := reportBound
	t.Cleanup(func() { reportBound = saved })
	// A bound the report fits only without its snapshot.
	reportBound = len(out) - len(report.Descriptors) + 100
	out, err = Check(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if report := readReport(t, out); report.Descriptors != nil || !strings.Contains(report.DescriptorsDropped, "no tool's descriptors are captured") || len(out) > reportBound {
		t.Fatalf("the snapshot is dropped and the report says so: %s", out)
	}
	// A bound it fits not at all: the check fails rather than write past
	// what connect reads.
	reportBound = 100
	if out, err := Check(context.Background(), cfg); err == nil || out != nil || !strings.Contains(err.Error(), "would pass 100 bytes") {
		t.Fatalf("%v %s", err, out)
	}
}

func TestReportFieldsAreCutExactly(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int
	}{
		{strings.Repeat("a", 512), 512},
		{strings.Repeat("a", 513), 512},
		{strings.Repeat("é", 300), 511},
	} {
		got := capField(tc.in)
		if len(got) != tc.want || !utf8.ValidString(got) || (len(tc.in) > maxReportField && !strings.HasSuffix(got, "…")) {
			t.Errorf("%d bytes in: %d out, valid %v", len(tc.in), len(got), utf8.ValidString(got))
		}
	}
	if got := reportField("token hunter2 and "+strings.Repeat("x", 600), []string{"hunter2"}); strings.Contains(got, "hunter2") || len(got) > maxReportField {
		t.Fatalf("a field is redacted, then cut: %q", got)
	}
}

// Each tool is judged as its page is read: the listing hands every tool on
// a page over before it asks for the next, so no descriptor outlives the
// page it came on, whatever a server puts in one.
func TestEachPageIsJudgedBeforeTheNextIsAsked(t *testing.T) {
	cfg := fake(t)
	page := func(name, next string) string {
		result := `{"tools":[{"name":"` + name + `","junk":"` + strings.Repeat("x", 1<<16) + `","inputSchema":{"type":"object"}}]`
		if next != "" {
			result += `,"nextCursor":"` + next + `"`
		}
		return `{"jsonrpc":"2.0","id":{id},"result":` + result + "}}"
	}
	path := filepath.Join(t.TempDir(), "pages")
	if err := os.WriteFile(path, []byte(page("a", "1")+"\n"+page("b", "2")+"\n"+page("c", "")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(fakemcp.EnvListPages, path)
	ctx := context.Background()
	srv, err := startServer(ctx, cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.stop()
	rpc := newClient(srv.stdin, srv.stdout)
	if _, err := rpc.call(ctx, "initialize", map[string]any{"protocolVersion": protocolVersion, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "t", "version": "0"}}); err != nil {
		t.Fatal(err)
	}
	var askedWhenSeen []int
	names, err := listTools(ctx, rpc, true, func(tool listedTool) error {
		askedWhenSeen = append(askedWhenSeen, strings.Count(strings.Join(methods(trace(t)), " "), "tools/list"))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(names, ",") != "a,b,c" || fmt.Sprint(askedWhenSeen) != "[1 2 3]" {
		t.Fatalf("each page's tools are handed over before the next page is asked for: %v %v", names, askedWhenSeen)
	}
}

func TestASnapshotWhoseBaseIsOverItsBoundIsDropped(t *testing.T) {
	cfg := capturing(t, "query")
	cfg.Descriptors.Platform = strings.Repeat("p", maxSnapshot)
	out, err := Check(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	report := readReport(t, out)
	if report.Descriptors != nil || !strings.Contains(report.DescriptorsDropped, "platform and binding alone pass 327680 bytes") ||
		strings.Contains(string(out), strings.Repeat("p", 600)) {
		t.Fatalf("no snapshot, said why, the platform not echoed: %.600s", out)
	}
	if len(report.Fallbacks) != 1 || report.Fallbacks[0].Tool != "query" || report.Fallbacks[0].Reason != overBudget {
		t.Fatalf("the tool falls back over the budget: %v", report.Fallbacks)
	}
}

// Screening follows each string's role: the grammar's own words in their
// own places pass beside a credential that spells them, and every string
// a server chose is screened, a grammar word or not.
func TestScreeningFollowsEachStringsRole(t *testing.T) {
	secrets := []string{"string", "object", "require", "json-schema.org"}
	for _, tc := range []struct {
		name, text string
		refused    bool
	}{
		{"keywords, type names and the root's dialect", `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"x":{"type":["string","null"]}},"required":["x"]}`, false},
		{"a constant", `{"type":"object","properties":{"password":{"type":"string","const":"string"}}}`, true},
		{"an enum member", `{"type":"object","properties":{"x":{"enum":["object"]}}}`, true},
		{"a default", `{"type":"object","properties":{"x":{"default":"object"}}}`, true},
		{"an example", `{"type":"object","properties":{"x":{"examples":["string"]}}}`, true},
		{"a member name in data", `{"type":"object","properties":{"x":{"default":{"string":1}}}}`, true},
		{"a property name that is a type name", `{"type":"object","properties":{"string":{}}}`, true},
		{"a property name that is a keyword", `{"type":"object","properties":{"required":{}}}`, true},
		{"a required name", `{"type":"object","required":["string"]}`, true},
		{"a description", `{"type":"object","description":"required"}`, true},
		{"a title", `{"type":"object","title":"object"}`, true},
		{"a keyword the grammar does not name", `{"type":"object","x-string":1}`, true},
		{"what an unnamed keyword holds", `{"type":"object","x":"object"}`, true},
		{"a type that is no type name", `{"type":"object","properties":{"x":{"type":"requirement"}}}`, true},
		{"a $schema below the root", `{"type":"object","properties":{"x":{"$schema":"https://json-schema.org/draft/2020-12/schema"}}}`, true},
		{"a $schema that is no dialect", `{"$schema":"https://json-schema.org/other","type":"object"}`, true},
	} {
		r := checkSchema([]byte(tc.text), secrets)
		switch refused := r != nil && r.code == codeSecret; {
		case refused != tc.refused:
			t.Errorf("%s: refused as holding a credential %v, want %v (%v)", tc.name, refused, tc.refused, r)
		case refused && !r.whole:
			t.Errorf("%s: a credential's refusal names a location: %q", tc.name, r.pointer)
		}
	}
}

// A description written in more than six times its bound is refused for
// its size before it is decoded: a text that would not decode says so
// only when it was decoded.
func TestADescriptionWrittenPastSixTimesItsBoundIsNotDecoded(t *testing.T) {
	raw := []byte(`"` + strings.Repeat("a", 6*maxDescription+1) + `\x"`)
	if _, r := checkDescription(raw, nil); r == nil || r.code != codeStringSize {
		t.Fatalf("refused unread for its size: %v", r)
	}
	if _, r := checkDescription([]byte(`"abc\x"`), nil); r == nil || r.code != codeValue {
		t.Fatalf("a short one is read, and refused as no string: %v", r)
	}
}

// What a capture keeps of a fallback is what the report carries: each
// field redacted and cut, the list within its bound, the rest counted --
// while the listing runs, not after it.
func TestFallbacksAreCutAsTheyAreRecorded(t *testing.T) {
	c, err := newCapturer(DescriptorTarget{Platform: "tickets", Binding: testBinding}, initializeResult{name: "srv", version: "1"}, []string{"hunter2"}, "2026-09-15T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	// Every other tool's schema holds a keyword of 16000 bytes, which its
	// reason's pointer names; the rest are named with a credential.
	keyword := strings.Repeat("k", 16000)
	for i := 0; i < 2000; i++ {
		name := fmt.Sprintf("tool_%04d", i)
		if i%2 == 1 {
			name = fmt.Sprintf("tool_hunter2_%04d", i)
		}
		schema := json.RawMessage(`{"type":"object","` + keyword + `":1}`)
		descriptor, _ := json.Marshal(map[string]any{"name": name, "inputSchema": schema})
		if err := c.add(listedTool{name: name, descriptor: descriptor}); err != nil {
			t.Fatal(err)
		}
	}
	encoded, _ := json.Marshal(c.fallbacks)
	if len(encoded) > maxReportList || c.unlisted == 0 || len(c.fallbacks)+c.unlisted != 2000 {
		t.Fatalf("kept %d bytes in %d fallbacks, %d counted", len(encoded), len(c.fallbacks), c.unlisted)
	}
	// What is kept is the list's front, whole: no fallback after the first
	// that did not fit, however small.
	for i, f := range c.fallbacks {
		want := fmt.Sprintf("tool_%04d", i)
		if i%2 == 1 {
			want = fmt.Sprintf("tool_[redacted]_%04d", i)
		}
		if f.Tool != want {
			t.Fatalf("fallback %d is %q, not %q: the kept list is not the front of the whole", i, f.Tool, want)
		}
	}
	cut := 0
	for _, f := range c.fallbacks {
		if len(f.Reason) > maxReportField || len(f.Tool) > maxReportField || strings.Contains(f.Tool, "hunter2") {
			t.Fatalf("a fallback kept as it was written: %d %q", len(f.Reason), f.Tool)
		}
		if len(f.Reason) == maxReportField {
			cut++
		}
	}
	if cut == 0 {
		t.Fatal("no long reason was recorded, so none was cut")
	}
	// Once the list is over its bound, a fallback small enough to fit is
	// counted all the same, as the whole list would be cut.
	kept := len(c.fallbacks)
	if err := c.add(listedTool{name: "t", descriptor: json.RawMessage(`{"name":"t"}`)}); err != nil {
		t.Fatal(err)
	}
	if len(c.fallbacks) != kept || c.unlisted != 2001-kept {
		t.Fatalf("a later fallback is kept past the bound: %d kept, %d counted", len(c.fallbacks), c.unlisted)
	}
}
