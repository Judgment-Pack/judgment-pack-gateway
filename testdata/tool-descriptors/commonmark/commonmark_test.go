// Package commonmark renders every description the frontend serves, as
// ../rendered.json records it, with a CommonMark renderer the gateway does
// not link (docs/design/tool-descriptors.md, "Literal text"): what the
// server wrote stays inside one fenced code block, and nothing else in the
// description -- the engine's words and the identifiers, a tool name
// holding a line break and markup among them -- becomes an element but a
// paragraph and its code spans. It is a module of its own, so neither of
// the gateway's modules takes the dependency.
package commonmark

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"
)

type rendered struct {
	Name     string `json:"name"`
	Captured bool   `json:"captured"`
	Markdown string `json:"markdown"`
}

func TestNothingTheServerWroteRendersAsMarkup(t *testing.T) {
	data, err := os.ReadFile("../rendered.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []rendered
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) != 4 {
		t.Fatalf("the four templates: %d", len(cases))
	}
	md := goldmark.New() // CommonMark, no extensions
	for _, c := range cases {
		source := []byte(c.Markdown)
		doc := md.Parser().Parse(text.NewReader(source))
		blocks := 0
		err := ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
			if !entering {
				return ast.WalkContinue, nil
			}
			switch n.Kind() {
			case ast.KindDocument, ast.KindParagraph, ast.KindText, ast.KindCodeSpan, ast.KindString:
			case ast.KindFencedCodeBlock:
				blocks++
				// Inside the block nothing is parsed further.
				return ast.WalkSkipChildren, nil
			default:
				t.Errorf("%s: a %s element", c.Name, n.Kind())
			}
			return ast.WalkContinue, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		want := 0
		if c.Captured {
			want = 1
		}
		if blocks != want {
			t.Errorf("%s: %d fenced blocks, want %d", c.Name, blocks, want)
		}
		var html bytes.Buffer
		if err := md.Convert(source, &html); err != nil {
			t.Fatal(err)
		}
		out := html.String()
		for _, tag := range []string{"<script", "<a ", "<img", "<h1", "<b>", "<i>", "<blockquote", "<ul", "<hr", "<!--"} {
			if strings.Contains(out, tag) {
				t.Errorf("%s: the HTML holds %s:\n%s", c.Name, tag, out)
			}
		}
		// The server's words are there, as text.
		if c.Captured && !strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt;") && !strings.Contains(out, "&lt;i&gt;x&lt;/i&gt;") {
			t.Errorf("%s: the server's words are not in the HTML as text:\n%s", c.Name, out)
		}
	}
}

// The check has teeth: the same words outside a fence render as markup.
func TestTheSameWordsUnfencedRenderAsMarkup(t *testing.T) {
	var html bytes.Buffer
	if err := goldmark.New().Convert([]byte("Click [here](http://evil.example)\n\n# Heading"), &html); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html.String(), "<a href=") || !strings.Contains(html.String(), "<h1>") {
		t.Fatalf("%s", html.String())
	}
}
