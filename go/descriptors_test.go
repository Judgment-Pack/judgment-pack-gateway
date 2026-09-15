package main

import (
	"strings"
	"testing"
)

const testSnapshotBinding = "tickets@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// goodSnapshot is a snapshot as the adapter captures it: canonical, every
// member of its type.
const goodSnapshot = `{"binding":"` + testSnapshotBinding + `","capturedAt":"2026-09-15T01:02:03Z","platform":"tickets","policy":1,` +
	`"server":{"name":"tickets-mcp","version":"2.4.1"},"tools":{"close":{"inputSchemaText":"{\"type\":\"object\"}"},` +
	`"search":{"description":"Search tickets","inputSchemaText":"{ \"type\": \"object\" }"}}}`

func TestParseSnapshotReadsWhatTheAdapterCaptures(t *testing.T) {
	s, err := parseSnapshot([]byte(goodSnapshot))
	if err != nil {
		t.Fatal(err)
	}
	if s.platform != "tickets" || s.binding != testSnapshotBinding || s.capturedAt != "2026-09-15T01:02:03Z" ||
		s.server == nil || s.server.name != "tickets-mcp" || s.server.version != "2.4.1" || strings.Join(s.names, ",") != "close,search" {
		t.Fatalf("%+v", s)
	}
	if search := s.tools["search"]; search.description == nil || *search.description != "Search tickets" ||
		search.inputSchemaText == nil || *search.inputSchemaText != `{ "type": "object" }` || s.tools["close"].description != nil {
		t.Fatalf("each tool's candidates, the schema's text as written: %+v", s.tools)
	}
	noServer := strings.Replace(goodSnapshot, `"server":{"name":"tickets-mcp","version":"2.4.1"},`, "", 1)
	if s, err := parseSnapshot([]byte(noServer)); err != nil || s.server != nil {
		t.Fatalf("the server is optional: %v", err)
	}
}

func TestParseSnapshotRefusesAnythingElse(t *testing.T) {
	swap := func(old, new string) string {
		if !strings.Contains(goodSnapshot, old) {
			t.Fatalf("fixture lacks %q", old)
		}
		return strings.Replace(goodSnapshot, old, new, 1)
	}
	for _, tc := range []struct{ name, text, want string }{
		{"not canonical: whitespace", strings.Replace(goodSnapshot, `"policy":1`, `"policy": 1`, 1), "not in canonical form"},
		{"not canonical: order", swap(`"binding":"`+testSnapshotBinding+`","capturedAt":"2026-09-15T01:02:03Z",`, `"capturedAt":"2026-09-15T01:02:03Z","binding":"`+testSnapshotBinding+`",`), "not in canonical form"},
		{"a member twice", swap(`"policy":1,`, `"policy":1,"policy":1,`), "duplicate member"},
		{"a member twice, deep", swap(`{"description":"Search tickets",`, `{"description":"Search tickets","description":"x",`), "duplicate member"},
		{"trailing content", goodSnapshot + " {}", "trailing content"},
		{"a lone surrogate", swap(`"Search tickets"`, `"Search \ud800"`), "lone surrogate"},
		{"an unknown member", swap(`"platform":"tickets",`, `"extra":1,"platform":"tickets",`), "unknown member"},
		{"no tools", swap(`"tools":{"close"`, `"toolz":{"close"`), "unknown member"},
		{"another policy", swap(`"policy":1`, `"policy":2`), "display policy is not 1"},
		{"a policy as a string", swap(`"policy":1`, `"policy":"1"`), "display policy is not 1"},
		{"a binding not pinned", swap(testSnapshotBinding, "tickets"), "binding is not"},
		{"a local time", swap("2026-09-15T01:02:03Z", "2026-09-15T01:02:03+01:00"), "capturedAt"},
		{"a fraction of a second", swap("2026-09-15T01:02:03Z", "2026-09-15T01:02:03.5Z"), "capturedAt"},
		{"no such day", swap("2026-09-15T01:02:03Z", "2026-02-30T01:02:03Z"), "capturedAt"},
		{"a platform that is no name", swap(`"platform":"tickets"`, `"platform":"a/b"`), "platform"},
		{"a server without a version", swap(`{"name":"tickets-mcp","version":"2.4.1"}`, `{"name":"tickets-mcp"}`), "missing member"},
		{"a server version that is a number", swap(`"version":"2.4.1"`, `"version":2`), "server"},
		{"a tool with nothing", swap(`"close":{"inputSchemaText":"{\"type\":\"object\"}"}`, `"close":{}`), "a tool is not an object"},
		{"a tool's schema as an object", swap(`"close":{"inputSchemaText":"{\"type\":\"object\"}"}`, `"close":{"inputSchemaText":{"type":"object"}}`), "not a string"},
		{"a tool's unknown member", swap(`"close":{"inputSchemaText":"{\"type\":\"object\"}"}`, `"close":{"inputSchemaText":"{\"type\":\"object\"}","title":"x"}`), "unknown member"},
		{"over the bound", strings.Replace(goodSnapshot, `"Search tickets"`, `"`+strings.Repeat("a", maxSnapshotBytes)+`"`, 1), "over"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseSnapshot([]byte(tc.text)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q: %v", tc.want, err)
			}
		})
	}
}
