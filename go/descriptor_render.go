package main

import (
	"fmt"
	"strings"
)

// What the frontend serves for a platform's tool (docs/design/
// tool-descriptors.md, "What the frontend serves"): one of four
// templates, the server's own words inside a fenced code block, and the
// schema's serving projection.

// servedTool is what a snapshot holds of one tool, verified at start: the
// description when captured, and the schema's parsed text when captured.
type servedTool struct {
	description *string
	schema      *jsonNode
}

// servedPlatform is a platform's verified snapshot.
type servedPlatform struct {
	capturedAt string
	server     *snapshotServer
	tools      map[string]servedTool
}

const answerCarries = "The answer carries {session, result, receipt, salts}."

// describePlatformTool is the description served for a platform's tool:
// today's template when nothing of it was captured, and otherwise the one
// that says which of its parts the server's words are, when they were
// captured, and whose they are, with those words in a fenced block.
func describePlatformTool(t mcpTool, p *servedPlatform) string {
	description, _ := describePlatformToolWithin(t, p, -1)
	return description
}

// describePlatformToolWithin is the description, unless it would pass
// limit bytes (a negative limit is none): building it stops there, so a
// description far past what a listing could carry costs no more than the
// limit.
func describePlatformToolWithin(t mcpTool, p *servedPlatform, limit int) (string, bool) {
	head := fmt.Sprintf("Tool %s of platform %s (binding %s), called by the engine's own adapter under the engine's key.", codeSpan(t.tool), codeSpan(t.platform), codeSpan(t.binding))
	var captured servedTool
	if p != nil {
		captured = p.tools[t.tool]
	}
	if captured.description == nil && captured.schema == nil {
		description := head + " Its arguments are what the platform's server defines; the engine does not read that server's schema. " + answerCarries
		if limit >= 0 && len(description) > limit {
			return "", false
		}
		return description, true
	}
	arguments := "what the platform's server defines"
	if captured.schema != nil {
		arguments = "declared by the platform's server's schema, as captured"
	}
	prose := head + " Its arguments are " + arguments + ". " + answerCarries +
		" When " + codeSpan("connect") + " ran at " + codeSpan(p.capturedAt) + ", the platform's server described it as follows, in its own words, which are not the engine's and which no receipt covers:\n\n"
	return fenced(prose, func(w *blockWriter) {
		if p.server != nil {
			w.item()
			blockPart(w, "server: ")
			blockPart(w, p.server.name)
			blockPart(w, " ")
			blockPart(w, p.server.version)
		}
		if captured.description != nil && !w.over() {
			w.item()
			blockPart(w, *captured.description)
		}
		if captured.schema != nil && !w.over() {
			walkSchemaDescriptions(captured.schema, func(label []byte, text string) bool {
				w.item()
				blockPart(w, label)
				blockPart(w, ": ")
				blockPart(w, text)
				return !w.over()
			})
		}
	}, limit)
}

// servedSchema is the inputSchema served: the projection of a captured
// schema, or the open schema.
func servedSchema(t mcpTool, p *servedPlatform) any {
	if p != nil {
		if captured := p.tools[t.tool]; captured.schema != nil {
			return rawJSON(projectSchema(captured.schema))
		}
	}
	return map[string]any{"type": "object"}
}

// rawJSON is JSON text written into a listing as it is.
type rawJSON []byte

func (r rawJSON) MarshalJSON() ([]byte, error) { return r, nil }

// fencedBlock is a fenced code block holding the items, one after another:
// a text that spans lines keeps them, each after its first indented by two
// spaces. Its fence is a run of backticks one longer than the longest run
// inside, and at least three, so nothing inside can close it; inside it
// nothing renders -- no link, image, heading or HTML.
func fencedBlock(items []string) string {
	block, _ := fenced("", func(w *blockWriter) {
		for _, item := range items {
			w.item()
			blockPart(w, item)
		}
	}, -1)
	return block
}

// fenced is prose followed by a fenced code block, as fencedBlock writes
// one, holding the items feed hands a blockWriter -- unless it would pass
// limit bytes (a negative limit is none). The block is gathered twice:
// counted first, feed stopping once the count passes limit, and written
// only when it fits, in one allocation of its exact size.
func fenced(prose string, feed func(w *blockWriter), limit int) (string, bool) {
	counted := &blockWriter{limit: limit - len(prose), bounded: limit >= 0}
	feed(counted)
	if counted.over() {
		return "", false
	}
	fence := max(3, counted.longest+1)
	size := len(prose) + fence + 1 + counted.size + fence
	if counted.size > 0 {
		size++
	}
	if limit >= 0 && size > limit {
		return "", false
	}
	var out strings.Builder
	out.Grow(size)
	out.WriteString(prose)
	writeFence := func() {
		for i := 0; i < fence; i++ {
			out.WriteByte('`')
		}
	}
	writeFence()
	out.WriteByte('\n')
	feed(&blockWriter{out: &out})
	if counted.size > 0 {
		out.WriteByte('\n')
	}
	writeFence()
	return out.String(), true
}

// blockWriter is a fenced block's body: its items one after another, each
// on its own line and each of an item's lines after its first indented by
// two spaces. Counting (out nil), it takes the body's size and the longest
// run of backticks in it; writing, it writes the body to out.
type blockWriter struct {
	out     *strings.Builder
	limit   int
	bounded bool
	items   int
	size    int
	run     int
	longest int
}

// item starts an item: after the first, on a line of its own.
func (w *blockWriter) item() {
	if w.items++; w.items == 1 {
		return
	}
	if w.out != nil {
		w.out.WriteByte('\n')
		return
	}
	w.size++
	w.run = 0
}

// over is whether the count has passed the limit.
func (w *blockWriter) over() bool {
	return w.out == nil && w.bounded && w.size > w.limit
}

// blockPart is the next part of the item begun: text, or a label the
// schema walk holds only while it is handed over.
func blockPart[T string | []byte](w *blockWriter, s T) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if w.out != nil {
			w.out.WriteByte(c)
			if c == '\n' {
				w.out.WriteString("  ")
			}
			continue
		}
		w.size++
		switch c {
		case '`':
			w.run++
			w.longest = max(w.longest, w.run)
		case '\n':
			w.size += 2
			w.run = 0
		default:
			w.run = 0
		}
	}
}

// longestRun is the length of the longest run of c in s.
func longestRun(s string, c byte) int {
	longest, run := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	return longest
}

// codeSpan writes an identifier in prose as a Markdown code span, whose
// backtick run is longer than any inside it -- escaped first, so no
// identifier leaves its line, opens an HTML block, or reaches the fence --
// with a space inside each end where an end is a backtick, or both ends
// spaces a renderer would strip.
func codeSpan(s string) string {
	content := escapeIdentifier(s)
	run := strings.Repeat("`", longestRun(content, '`')+1)
	if strings.HasPrefix(content, "`") || strings.HasSuffix(content, "`") ||
		(strings.HasPrefix(content, " ") && strings.HasSuffix(content, " ") && strings.Trim(content, " ") != "") {
		content = " " + content + " "
	}
	return run + content + run
}

// escapeIdentifier writes every control character, line feed included, and
// every character of display policy 1's classes as a visible escape,
// \u{XXXX}; everything else as it is.
func escapeIdentifier(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || policyRefuses(r) {
			fmt.Fprintf(&b, `\u{%04X}`, r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
