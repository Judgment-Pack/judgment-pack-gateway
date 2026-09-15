package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"adapters/internal/canon"
	"adapters/internal/redact"
)

// Descriptor capture (docs/design/tool-descriptors.md): the live
// operation's check captures, for each tool the operation allows, its
// description and its input schema as the server wrote them, with the
// server's own name and version, into the snapshot connect keeps for the
// platform. A candidate is captured whole or refused whole, never
// stripped, redacted or normalized; nothing captured becomes an engine
// claim, and no receipt covers it.

const (
	// maxSnapshot bounds the snapshot, the whole file; maxCandidateText
	// bounds its descriptions and schema texts together.
	maxSnapshot      = 320 << 10
	maxCandidateText = 256 << 10
	// maxReportField bounds every string of the report outside the
	// snapshot, the marker of a cut included; maxReportList bounds the
	// list of offered tools and the list of fallbacks, each as JSON.
	maxReportField = 512
	maxReportList  = 64 << 10
)

// reportBound is the size of report connect reads (its checkMaxOutput).
var reportBound = 1 << 20

// now is the clock a snapshot's capture time is read from.
var now = time.Now

// DescriptorTarget names the snapshot a check captures descriptors for:
// the platform as the engine's configuration names it, and the binding it
// pins, name@sha256:<64 hex>.
type DescriptorTarget struct {
	Platform string
	Binding  string
}

func (t DescriptorTarget) refusal() error {
	at := strings.LastIndex(t.Binding, "@")
	if t.Platform == "" || at < 1 || !canon.IsDigestString(t.Binding[at+1:]) {
		return errors.New("descriptors are captured for a platform and its pinned binding, name@sha256:<64 hex>")
	}
	return nil
}

// snapshot is what connect keeps: the platform, the binding it pins, when
// the check ran, the display policy the candidates passed, the server's
// identity when it passed, and the tools with a candidate that passed.
type snapshot struct {
	Binding    string                  `json:"binding"`
	CapturedAt string                  `json:"capturedAt"`
	Platform   string                  `json:"platform"`
	Policy     int                     `json:"policy"`
	Server     *serverIdentity         `json:"server,omitempty"`
	Tools      map[string]capturedTool `json:"tools"`
}

// capturedTool is a tool's candidates that passed: its description, and
// its input schema's original text, as a string, so no encoder along the
// way compacts, reorders or respells it.
type capturedTool struct {
	Description     *string `json:"description,omitempty"`
	InputSchemaText *string `json:"inputSchemaText,omitempty"`
}

// fallback is a candidate that was not captured, and why: the server's
// identity, a tool's description or input schema, or a whole tool.
type fallback struct {
	Tool   string `json:"tool,omitempty"`
	Part   string `json:"part"`
	Reason string `json:"reason"`
}

const (
	partServer      = "server"
	partTool        = "tool"
	partDescription = "description"
	partInputSchema = "inputSchema"
)

// capturer judges each allowed tool as the listing reaches it and admits
// it, in the server's order, while the snapshot and its candidates' text
// both stay within their bounds with the tool added; every later tool
// falls back. It keeps only what it admits and why the rest fell back, so
// a descriptor's bytes last no longer than the page they came on.
type capturer struct {
	secrets   []string
	snap      snapshot
	size      int // the snapshot's canonical size with what is admitted
	text      int // the admitted descriptions' and schemas' bytes
	over      bool
	dropped   string // why the report carries no snapshot, when it carries none
	fallbacks []fallback
}

const overBudget = "over the platform's budget: a snapshot of at most 327680 bytes, its descriptions and schemas at most 262144 together"

// newCapturer starts a snapshot for the target, with the server's identity
// as its initialize answer gave it when that passes, and the snapshot as
// it stands before any tool is added. When that alone passes the
// snapshot's bound -- a platform or binding so long -- no tool is
// admitted, and the report carries no snapshot and says why.
func newCapturer(target DescriptorTarget, info initializeResult, secrets []string, capturedAt string) (*capturer, error) {
	c := &capturer{secrets: secrets, snap: snapshot{Binding: target.Binding, CapturedAt: capturedAt, Platform: target.Platform, Policy: displayPolicy, Tools: map[string]capturedTool{}}}
	if r := checkIdentity(info.name, info.version, secrets); r != nil {
		// A refused identity is omitted, and nothing names the server.
		c.fallbacks = append(c.fallbacks, fallback{Part: partServer, Reason: r.reason()})
	} else {
		c.snap.Server = &serverIdentity{Name: info.name, Version: info.version}
	}
	empty, err := canonicalJSON(c.snap)
	if err != nil {
		return nil, err
	}
	c.size = len(empty)
	if c.size > maxSnapshot {
		c.over = true
		c.dropped = fmt.Sprintf("the snapshot's platform and binding alone pass %d bytes, so no tool's descriptors are captured", maxSnapshot)
	}
	return c, nil
}

// add judges one allowed tool and admits it or records why it fell back.
// The canonical form sorts members by name and writes no whitespace, so
// what a tool adds does not depend on where it sorts: its name, a colon,
// its candidates, and a comma beside any other tool.
func (c *capturer) add(tool listedTool) error {
	entry, refused := candidates(tool, c.secrets)
	c.fallbacks = append(c.fallbacks, refused...)
	if entry.Description == nil && entry.InputSchemaText == nil {
		return nil
	}
	if !c.over {
		name, err := canonicalJSON(tool.name)
		if err != nil {
			return err
		}
		value, err := canonicalJSON(entry)
		if err != nil {
			return err
		}
		grow := len(name) + 1 + len(value)
		if len(c.snap.Tools) > 0 {
			grow++
		}
		parts := len(deref(entry.Description)) + len(deref(entry.InputSchemaText))
		if c.size+grow <= maxSnapshot && c.text+parts <= maxCandidateText {
			c.snap.Tools[tool.name] = entry
			c.size, c.text = c.size+grow, c.text+parts
			return nil
		}
		c.over = true
	}
	c.fallbacks = append(c.fallbacks, fallback{Tool: tool.name, Part: partTool, Reason: overBudget})
	return nil
}

// finish is the snapshot in canonical form -- the bytes connect writes and
// pins -- or, when there is none, why; and every fallback, in order.
func (c *capturer) finish() ([]byte, []fallback, string, error) {
	if c.dropped != "" {
		return nil, c.fallbacks, c.dropped, nil
	}
	out, err := canonicalJSON(c.snap)
	if err != nil {
		return nil, nil, "", err
	}
	if len(out) != c.size || len(out) > maxSnapshot {
		return nil, nil, "", fmt.Errorf("the snapshot is %d bytes where %d were counted, of at most %d", len(out), c.size, maxSnapshot)
	}
	return out, c.fallbacks, "", nil
}

// candidates judges one tool's description and input schema, each on its
// own: either may be captured while the other falls back. A tool whose
// name holds a value of the credentials is captured not at all, since the
// snapshot names every tool it holds.
func candidates(tool listedTool, secrets []string) (capturedTool, []fallback) {
	var entry capturedTool
	if holdsSecret(tool.name, secrets) {
		return entry, []fallback{{Tool: tool.name, Part: partTool, Reason: "its name holds a value of the credentials"}}
	}
	var refused []fallback
	members, err := exactMembers(tool.descriptor)
	if err != nil {
		return entry, []fallback{{Tool: tool.name, Part: partTool, Reason: "its descriptor is not an object"}}
	}
	if raw, ok := members["description"]; ok {
		if s, r := checkDescription(raw, secrets); r != nil {
			refused = append(refused, fallback{Tool: tool.name, Part: partDescription, Reason: r.reason()})
		} else {
			entry.Description = &s
		}
	}
	// The member's bytes as the server wrote them, cut from its message.
	if raw, ok := members["inputSchema"]; !ok {
		refused = append(refused, fallback{Tool: tool.name, Part: partInputSchema, Reason: "the tool declares no inputSchema"})
	} else if r := checkSchema(raw, secrets); r != nil {
		refused = append(refused, fallback{Tool: tool.name, Part: partInputSchema, Reason: r.reason()})
	} else {
		s := string(raw)
		entry.InputSchemaText = &s
	}
	return entry, refused
}

// checkDescription judges a description as the server wrote it: a string
// holding no value of the credentials, within its bound, and passing
// display policy 1.
func checkDescription(raw json.RawMessage, secrets []string) (string, *refusal) {
	// No escape is written in more than six bytes, so a string written in
	// more than six times the bound holds more than the bound, and is
	// refused without being decoded.
	if len(raw) > 6*maxDescription+2 {
		return "", &refusal{code: codeStringSize, whole: true, detail: fmt.Sprintf("the description is over %d bytes", maxDescription)}
	}
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", &refusal{code: codeValue, whole: true, detail: "the description is not a string"}
	}
	if holdsSecret(s, secrets) {
		return "", &refusal{code: codeSecret, whole: true, detail: "the description holds a value of the credentials"}
	}
	if len(s) > maxDescription {
		return "", &refusal{code: codeStringSize, whole: true, detail: fmt.Sprintf("the description is over %d bytes", maxDescription)}
	}
	if r, refused := displayRefusal(s); refused {
		return "", &refusal{code: codePolicy, whole: true, detail: fmt.Sprintf("the description holds U+%04X, which display policy 1 refuses", r)}
	}
	return s, nil
}

// checkIdentity judges the server's name and version as its initialize
// answer gave them, not as a report redacts them: neither holding a value
// of the credentials, each within its bound, each passing display policy
// 1. Either refused refuses both.
func checkIdentity(name, version string, secrets []string) *refusal {
	fields := []struct{ what, s string }{{"name", name}, {"version", version}}
	for _, f := range fields {
		if holdsSecret(f.s, secrets) {
			return &refusal{code: codeSecret, whole: true, detail: fmt.Sprintf("the server's %s holds a value of the credentials", f.what)}
		}
	}
	for _, f := range fields {
		if len(f.s) > maxIdentity {
			return &refusal{code: codeStringSize, whole: true, detail: fmt.Sprintf("the server's %s is %d bytes, over %d", f.what, len(f.s), maxIdentity)}
		}
		if r, refused := displayRefusal(f.s); refused {
			return &refusal{code: codePolicy, whole: true, detail: fmt.Sprintf("the server's %s holds U+%04X, which display policy 1 refuses", f.what, r)}
		}
	}
	return nil
}

// canonicalJSON is v in the canonical form of SPEC.md §1.1, the form the
// snapshot is written and digested in.
func canonicalJSON(v any) ([]byte, error) {
	encoded, err := canon.EncodeJSON(v)
	if err != nil {
		return nil, err
	}
	return canon.Canonicalize(encoded, canon.RefuseNumbers)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// reportField is a string the report carries: redacted, then at most
// maxReportField bytes, the marker of a cut included, cut on a character
// boundary. Cutting a redacted text leaves no start of a credential that
// the whole text did not show.
func reportField(s string, secrets []string) string {
	return capField(redact.Redact(s, secrets))
}

// capField cuts s to maxReportField bytes, the marker included.
func capField(s string) string {
	const marker = "…"
	if len(s) <= maxReportField {
		return s
	}
	cut := maxReportField - len(marker)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + marker
}

// capList keeps items from the front of list while the list, as JSON,
// stays within limit bytes, and counts the rest.
func capList[T any](list []T, limit int) ([]T, int) {
	size := len("[]")
	for i, item := range list {
		encoded, err := canon.EncodeJSON(item)
		if err != nil {
			return list[:i], len(list) - i
		}
		grow := len(encoded)
		if i > 0 {
			grow++
		}
		if size+grow > limit {
			return list[:i], len(list) - i
		}
		size += grow
	}
	return list, 0
}
