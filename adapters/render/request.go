package render

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"adapters/attachment"
	"adapters/internal/canon"
)

// The bounds of the structure that are the contract's and not the
// operator's: what one block, one list and one table may hold, and how long
// a link's target may be.
const (
	maxHeadingLevel = 6
	maxRuns         = 512
	maxListItems    = 1000
	maxTableColumns = 64
	maxTableRows    = 1000
	maxTargetBytes  = 2048
	maxLanguageSize = 35

	// maxNesting is how deep the arguments nest at their deepest, which is
	// a run in a cell of a table: the arguments, the document, its blocks,
	// a block, its rows, a row, a cell, its runs, a run.
	maxNesting = 9

	// maxInteger is the largest integer of the canonical domain.
	maxInteger = 1<<53 - 1
)

// The block types of the contract. The set is closed.
const (
	BlockHeading   = "heading"
	BlockParagraph = "paragraph"
	BlockList      = "list"
	BlockTable     = "table"
)

// Run is a run of literal text. Link is its target, or empty.
type Run struct {
	Text   string
	Bold   bool
	Italic bool
	Code   bool
	Link   string
}

// Cell is one cell of a table, or one item of a list: runs of text.
type Cell []Run

// Block is one block of a document. Which members mean anything depends on
// Type: Level and Runs for a heading, Runs for a paragraph, Ordered and Items
// for a list, Header and Rows for a table.
type Block struct {
	Type    string
	Level   int
	Runs    []Run
	Ordered bool
	Items   []Cell
	// Header is the table's header row, or nil for a table without one.
	Header []Cell
	Rows   [][]Cell
}

// Document is the content of a request.
type Document struct {
	Title string
	// Language is a language tag, or empty.
	Language string
	Blocks   []Block
}

// Request is one admitted request.
type Request struct {
	Format   string
	Document Document
	// ContentDigest is the SHA-256 of the canonical form of the request's
	// document member.
	ContentDigest string
	// Decision is the digest of the decision record the caller says the
	// document reports, or empty. It is the caller's assertion.
	Decision string
	// TextBytes is the bytes of UTF-8 in every run's text.
	TextBytes int64
	// ReceivedAt is when the request had been read in full.
	ReceivedAt time.Time
}

var languageForm = regexp.MustCompile(`^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$`)

// content is a violation of the structure's rules; bound is one of its
// bounds.
func content(format string, args ...any) *Refusal {
	return refuse(CodeContentInvalid, format, args...)
}

func bound(format string, args ...any) *Refusal {
	return refuse(CodeContentOverBound, format, args...)
}

// parseArguments reads the arguments. Every object in them is closed: a
// member the contract does not name refuses the request. Arguments outside
// the canonical domain -- a member named twice in any object among them --
// are refused before anything else is read, as the gateway refuses them
// before the adapter runs.
func parseArguments(raw []byte, cfg Config) (Request, error) {
	invalid := func(format string, args ...any) (Request, error) {
		return Request{}, refuse(CodeArgumentsInvalid, format, args...)
	}
	// The structure does not nest, so its depth is fixed, and arguments that
	// nest deeper are none the contract admits. They are refused here, by one
	// pass over their bytes, since putting deeply nested JSON in canonical
	// form costs far more than its length.
	if !nestedWithin(raw, maxNesting) {
		return invalid("the arguments nest deeper than the structure does")
	}
	// The canonical domain is held next, over the whole of the arguments:
	// what is read after it is JSON in which no object names a member twice.
	if _, err := canon.Canonicalize(raw, canon.RefuseNumbers); err != nil {
		return invalid("the arguments are not JSON of the canonical domain")
	}
	top, err := exactMembers(raw, map[string]bool{"format": true, "document": true, "cites": false})
	if err != nil {
		return invalid("arguments: %v", err)
	}
	var req Request
	if !stringInto(top["format"], &req.Format) || (req.Format != FormatDocx && req.Format != FormatPDF) {
		return invalid("format must be %q or %q", FormatDocx, FormatPDF)
	}
	if cites, ok := top["cites"]; ok {
		members, err := exactMembers(cites, map[string]bool{"decision": true})
		if err != nil {
			return invalid("cites: %v", err)
		}
		if !stringInto(members["decision"], &req.Decision) || !attachment.ValidDigest(req.Decision) {
			return invalid("cites.decision must be \"sha256:\" and 64 lowercase hex characters")
		}
	}
	doc, err := exactMembers(top["document"], map[string]bool{"title": true, "language": false, "blocks": true})
	if err != nil {
		return invalid("document: %v", err)
	}
	if !stringInto(doc["title"], &req.Document.Title) || !validTitle(req.Document.Title) {
		return invalid("document.title must be 1 to 255 bytes of UTF-8 with no control character")
	}
	if language, ok := doc["language"]; ok {
		if !stringInto(language, &req.Document.Language) || len(req.Document.Language) > maxLanguageSize || !languageForm.MatchString(req.Document.Language) {
			return invalid("document.language must be a language tag of letters, digits and hyphens, at most %d bytes", maxLanguageSize)
		}
	}
	blocks, ok := arrayOf(doc["blocks"])
	if !ok {
		return invalid("document.blocks must be an array")
	}
	if len(blocks) == 0 {
		return Request{}, content("document.blocks holds no block")
	}
	if len(blocks) > cfg.MaxBlocks {
		return Request{}, bound("the document holds %d blocks, past --max-blocks %d", len(blocks), cfg.MaxBlocks)
	}
	for i, raw := range blocks {
		block, err := parseBlock(raw, &req.TextBytes)
		if err != nil {
			var refusal *Refusal
			if errors.As(err, &refusal) {
				return Request{}, &Refusal{Code: refusal.Code, Reason: fmt.Sprintf("block %d: %s", i+1, refusal.Reason)}
			}
			return Request{}, content("block %d: %v", i+1, err)
		}
		req.Document.Blocks = append(req.Document.Blocks, block)
	}
	// The digest is of the document member in canonical form, so that two
	// requests that spell the same content differently have one digest. The
	// member is inside the canonical domain, since the arguments are.
	canonical, err := canon.Canonicalize(top["document"], canon.RefuseNumbers)
	if err != nil {
		return Request{}, refuse(CodeAdapterFailed, "the content could not be put in canonical form")
	}
	req.ContentDigest = digestOf(canonical)
	return req, nil
}

func parseBlock(raw json.RawMessage, textBytes *int64) (Block, error) {
	kind, err := typeOf(raw)
	if err != nil {
		return Block{}, err
	}
	block := Block{Type: kind}
	switch kind {
	case BlockHeading:
		members, err := exactMembers(raw, map[string]bool{"type": true, "level": true, "runs": true})
		if err != nil {
			return Block{}, err
		}
		level, ok := integerOf(members["level"])
		if !ok || level < 1 || level > maxHeadingLevel {
			return Block{}, fmt.Errorf("a heading's level is an integer from 1 to %d", maxHeadingLevel)
		}
		block.Level = int(level)
		if block.Runs, err = parseRuns(members["runs"], textBytes); err != nil {
			return Block{}, err
		}
	case BlockParagraph:
		members, err := exactMembers(raw, map[string]bool{"type": true, "runs": true})
		if err != nil {
			return Block{}, err
		}
		if block.Runs, err = parseRuns(members["runs"], textBytes); err != nil {
			return Block{}, err
		}
	case BlockList:
		members, err := exactMembers(raw, map[string]bool{"type": true, "ordered": true, "items": true})
		if err != nil {
			return Block{}, err
		}
		if !boolInto(members["ordered"], &block.Ordered) {
			return Block{}, errors.New("a list's ordered is true or false")
		}
		if block.Items, err = parseCells(members["items"], "items", maxListItems, textBytes); err != nil {
			return Block{}, err
		}
	case BlockTable:
		members, err := exactMembers(raw, map[string]bool{"type": true, "header": false, "rows": true})
		if err != nil {
			return Block{}, err
		}
		columns := 0
		if header, ok := members["header"]; ok {
			if block.Header, err = parseCells(header, "header", maxTableColumns, textBytes); err != nil {
				return Block{}, err
			}
			columns = len(block.Header)
		}
		rows, ok := arrayOf(members["rows"])
		if !ok {
			return Block{}, errors.New("a table's rows is an array")
		}
		if len(rows) == 0 {
			return Block{}, errors.New("a table holds no row")
		}
		if len(rows) > maxTableRows {
			return Block{}, bound("a table holds %d rows, past %d", len(rows), maxTableRows)
		}
		for _, raw := range rows {
			cells, err := parseCells(raw, "row", maxTableColumns, textBytes)
			if err != nil {
				return Block{}, err
			}
			if columns == 0 {
				columns = len(cells)
			}
			if len(cells) != columns {
				return Block{}, fmt.Errorf("a table's rows do not all hold %d cells", columns)
			}
			block.Rows = append(block.Rows, cells)
		}
	}
	return block, nil
}

// typeOf reads a block's type before its members are held to it, since which
// members a block may have depends on its type.
func typeOf(raw json.RawMessage) (string, error) {
	members, _ := membersOf(raw)
	value, ok := members["type"]
	if !ok {
		return "", errors.New("a block is an object with a type")
	}
	var kind string
	if !stringInto(value, &kind) {
		return "", errors.New("a block's type is a string")
	}
	switch kind {
	case BlockHeading, BlockParagraph, BlockList, BlockTable:
		return kind, nil
	}
	return "", errors.New("a type the contract does not define")
}

// parseCells reads an array of cells, each an object whose one member is its
// runs: the items of a list, or the cells of one row of a table.
func parseCells(raw json.RawMessage, what string, most int, textBytes *int64) ([]Cell, error) {
	values, ok := arrayOf(raw)
	if !ok {
		return nil, fmt.Errorf("%s is an array", what)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("%s holds nothing", what)
	}
	if len(values) > most {
		return nil, bound("%s holds %d entries, past %d", what, len(values), most)
	}
	cells := make([]Cell, 0, len(values))
	for _, value := range values {
		members, err := exactMembers(value, map[string]bool{"runs": true})
		if err != nil {
			return nil, err
		}
		runs, err := parseRuns(members["runs"], textBytes)
		if err != nil {
			return nil, err
		}
		cells = append(cells, runs)
	}
	return cells, nil
}

func parseRuns(raw json.RawMessage, textBytes *int64) ([]Run, error) {
	values, ok := arrayOf(raw)
	if !ok {
		return nil, errors.New("runs is an array")
	}
	if len(values) > maxRuns {
		return nil, bound("runs holds %d entries, past %d", len(values), maxRuns)
	}
	runs := make([]Run, 0, len(values))
	for _, value := range values {
		members, err := exactMembers(value, map[string]bool{"text": true, "bold": false, "italic": false, "code": false, "link": false})
		if err != nil {
			return nil, err
		}
		var run Run
		if !stringInto(members["text"], &run.Text) {
			return nil, errors.New("a run's text is a string")
		}
		if err := literalText(run.Text); err != nil {
			return nil, err
		}
		for _, flag := range []struct {
			name string
			into *bool
		}{{"bold", &run.Bold}, {"italic", &run.Italic}, {"code", &run.Code}} {
			if value, ok := members[flag.name]; ok && !boolInto(value, flag.into) {
				return nil, fmt.Errorf("a run's %s is true or false", flag.name)
			}
		}
		if target, ok := members["link"]; ok {
			if !stringInto(target, &run.Link) {
				return nil, errors.New("a run's link is a string")
			}
			if err := linkTarget(run.Link); err != nil {
				return nil, err
			}
		}
		*textBytes += int64(len(run.Text))
		runs = append(runs, run)
	}
	return runs, nil
}

// validTitle holds a title to the form of a document's name, 1 to 255 bytes
// of UTF-8 with no control character, and to what a Word file can carry.
func validTitle(title string) bool {
	if !attachment.ValidName(title) {
		return false
	}
	for _, r := range title {
		if r == 0xfffe || r == 0xffff {
			return false
		}
	}
	return true
}

// literalText holds a run's text to what a Word file can carry as text. A
// line feed is a line break and a tab is a tab. Every other control
// character is refused, and so are the two code points XML does not admit;
// nothing is removed or replaced, since the text is literal.
func literalText(text string) error {
	for _, r := range text {
		switch {
		case r == '\n' || r == '\t':
		case r < 0x20 || r == 0x7f:
			return errors.New("a run's text holds a control character other than a line feed or a tab")
		case r == 0xfffe || r == 0xffff:
			return errors.New("a run's text holds a code point a Word file cannot carry")
		case r == utf8.RuneError:
			// The arguments are valid UTF-8 by now, so this is the
			// replacement character itself, which is text.
		}
	}
	return nil
}

// linkTarget holds a link's target to the schemes the contract names, and to
// what a Word file can carry unchanged. The adapter writes the target into
// the file and never follows it.
func linkTarget(target string) error {
	if target == "" || len(target) > maxTargetBytes {
		return fmt.Errorf("a link's target is 1 to %d bytes", maxTargetBytes)
	}
	for _, r := range target {
		switch {
		case r <= 0x20 || r == 0x7f:
			return errors.New("a link's target holds a space or a control character")
		case r == 0xfffe || r == 0xffff:
			return errors.New("a link's target holds a code point a Word file cannot carry")
		}
	}
	u, err := url.Parse(target)
	if err != nil {
		return errors.New("a link's target is not a URL")
	}
	// Parse gives the scheme in lowercase, however the target spelt it.
	switch u.Scheme {
	case "https", "http":
		// The host is what stands before any port: a target that names a
		// port and no host names no host.
		if u.Hostname() == "" {
			return errors.New("a link's target names no host")
		}
	case "mailto":
		if !mailbox(u.Opaque) {
			return errors.New("a link's target names no address")
		}
	default:
		return errors.New("a link's target has a scheme other than https, http and mailto")
	}
	return nil
}

// mailbox reports whether what follows "mailto:" and stands before any
// question mark, which Parse has taken off it, is one address in its plainest
// form: something, an at sign, and something, with no second at sign and none
// of the characters that begin a path, a scheme or a list. It is a test of
// form. Whether the address exists is nobody's to say here.
func mailbox(address string) bool {
	local, domain, found := strings.Cut(address, "@")
	if !found || local == "" || domain == "" {
		return false
	}
	return !strings.ContainsAny(address[len(local)+1:], "@") && !strings.ContainsAny(address, `/\:,;<>"`)
}

// nestedWithin reports whether the objects and arrays of a JSON text nest no
// deeper than most. It counts the brackets that stand outside strings, in one
// pass, and judges nothing else: whether the text is JSON at all is for the
// canonicalizer to say, which reads what this has let through.
func nestedWithin(raw []byte, most int) bool {
	depth, inString := 0, false
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case inString && c == '\\':
			// What follows a backslash is part of the string, a quotation
			// mark included.
			i++
		case inString:
			inString = c != '"'
		case c == '"':
			inString = true
		case c == '{' || c == '[':
			if depth++; depth > most {
				return false
			}
		case (c == '}' || c == ']') && depth > 0:
			depth--
		}
	}
	return true
}

// membersOf decodes a JSON object, and only an object, into its members by
// name. The names are the members' own: one that differs in case is another
// member. What is given here is inside the canonical domain, so no name is
// given twice.
func membersOf(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var members map[string]json.RawMessage
	if !canon.IsObject(raw) || json.Unmarshal(raw, &members) != nil {
		return nil, false
	}
	return members, true
}

// arrayOf decodes a JSON array, and only an array, into its elements.
func arrayOf(raw json.RawMessage) ([]json.RawMessage, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, false
	}
	var out []json.RawMessage
	if json.Unmarshal(trimmed, &out) != nil {
		return nil, false
	}
	return out, true
}

// integerOf decodes a JSON integer that is not negative and is written as
// one: digits, with no sign, no fraction, no exponent and no leading zero, at
// most 2^53 - 1.
func integerOf(raw json.RawMessage) (int64, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || len(trimmed) > 16 {
		return 0, false
	}
	var n int64
	for i, c := range trimmed {
		if c < '0' || c > '9' || (c == '0' && i == 0 && len(trimmed) > 1) {
			return 0, false
		}
		n = n*10 + int64(c-'0')
	}
	return n, n <= maxInteger
}

// boolInto decodes a JSON true or false, and nothing else, into out.
func boolInto(raw json.RawMessage, out *bool) bool {
	switch string(bytes.TrimSpace(raw)) {
	case "true":
		*out = true
	case "false":
		*out = false
	default:
		return false
	}
	return true
}

// stringInto decodes a JSON string, and only a string, into out.
func stringInto(raw json.RawMessage, out *string) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return false
	}
	return json.Unmarshal(trimmed, out) == nil
}

// exactMembers decodes one JSON object whose members are exactly those
// named (true for required). Its errors name no member the caller wrote that
// the contract does not name.
func exactMembers(raw json.RawMessage, members map[string]bool) (map[string]json.RawMessage, error) {
	out, ok := membersOf(raw)
	if !ok {
		return nil, errors.New("not a JSON object")
	}
	for key := range out {
		if _, known := members[key]; !known {
			return nil, errors.New("a member the contract does not define")
		}
	}
	// The names are gone through in order, so that a request missing two
	// members is refused for the same one every time.
	names := make([]string, 0, len(members))
	for name := range members {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, ok := out[name]; members[name] && !ok {
			return nil, fmt.Errorf("member %s is missing", name)
		}
	}
	return out, nil
}
