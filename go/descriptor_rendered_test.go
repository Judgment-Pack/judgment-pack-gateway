package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// renderedCase is a description as the frontend serves it, recorded for
// the CommonMark check (testdata/tool-descriptors/commonmark), which renders
// each with a CommonMark renderer the gateway does not link.
type renderedCase struct {
	Name     string `json:"name"`
	Captured bool   `json:"captured"`
	Markdown string `json:"markdown"`
}

// hostileWords is a description holding what a renderer would act on
// outside a code block: a link, an image, HTML, a heading, fences of both
// kinds, an indented block, a quote, a list, a rule and a comment.
const hostileWords = "Click [here](http://evil.example) ![x](http://evil.example/i.png) <script>alert(1)</script> <b>bold</b>\n# Heading\n```\nfenced\n```\n~~~\ntilde\n~~~\n    indented\n> quote\n- item\n***\n<!-- comment -->"

func renderedCases(t *testing.T) []renderedCase {
	t.Helper()
	schema, err := decodeWritten([]byte(`{"type":"object","description":"` + "``<i>x</i>``" + `","properties":{"q":{"type":"string","description":"[link](http://evil.example) ` + "`````" + `"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	words := hostileWords
	tool := mcpTool{name: "tick<b>ets.x", platform: "tick<b>ets", tool: "se`arch\n# <h1>x</h1>", binding: "tick<b>ets@sha256:" + strings.Repeat("0", 64)}
	server := &snapshotServer{name: "srv <b>", version: "1\n# v"}
	served := func(t servedTool) *servedPlatform {
		return &servedPlatform{capturedAt: "2026-09-15T01:02:03Z", server: server, tools: map[string]servedTool{tool.tool: t}}
	}
	return []renderedCase{
		{"both captured", true, describePlatformTool(tool, served(servedTool{description: &words, schema: schema}))},
		{"the schema alone", true, describePlatformTool(tool, served(servedTool{schema: schema}))},
		{"the description alone", true, describePlatformTool(tool, served(servedTool{description: &words}))},
		{"nothing captured", false, describePlatformTool(tool, nil)},
	}
}

// The record the CommonMark check renders is what the frontend renders
// now; GATEWAY_WRITE_RENDERED=1 rewrites it.
func TestTheRenderedRecordIsTheFrontendsRendering(t *testing.T) {
	path := "../testdata/tool-descriptors/rendered.json"
	got, err := json.MarshalIndent(renderedCases(t), "", " ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if os.Getenv("GATEWAY_WRITE_RENDERED") == "1" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s is not the frontend's rendering; GATEWAY_WRITE_RENDERED=1 rewrites it", path)
	}
}
