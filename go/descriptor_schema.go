package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Grammar 1's limits and refusal codes, as the design note and the shared
// vectors state them.
const (
	schemaTextBound     = 16384
	schemaNestingBound  = 32
	schemaLocationBound = 2048
	propertyNameBound   = 128
	schemaStringBound   = 1024
	schemaListBound     = 256
	schemaBranchBound   = 16
	numberTextBound     = 32
	exponentBound       = 308
	descriptionBound    = 4096
	identityBound       = 256
	schemaDecodeNesting = 10000
	dialect202012       = "https://json-schema.org/draft/2020-12/schema"
	dialectDraft07      = "http://json-schema.org/draft-07/schema#"
	refusedTextSize     = "text-size"
	refusedJSON         = "json"
	refusedNotObject    = "not-object"
	refusedKeyword      = "keyword"
	refusedValue        = "value"
	refusedNumber       = "number"
	refusedNesting      = "nesting"
	refusedLocations    = "locations"
	refusedNameSize     = "name-size"
	refusedStringSize   = "string-size"
	refusedPolicy       = "policy"
)

// jsonNode is a JSON value as written: an object's members in the order
// written, a number as its literal.
type jsonNode struct {
	kind   byte // 'o' object, 'a' array, 's' string, 'n' number, 'b' boolean, 'z' null
	text   string
	truth  bool
	names  []string    // an object's member names, in order
	values []*jsonNode // an object's member values, or an array's items
}

func (n *jsonNode) member(name string) (*jsonNode, bool) {
	for i, m := range n.names {
		if m == name {
			return n.values[i], true
		}
	}
	return nil, false
}

// decodeWritten reads one JSON value strictly -- valid UTF-8, no lone
// surrogate escape, no member twice in an object, nothing after it,
// nesting no deeper than a decoder reads -- keeping what was written, with
// a stack of its own, so depth and size cost what the bytes do.
func decodeWritten(text []byte) (*jsonNode, error) {
	if !utf8.Valid(text) {
		return nil, errors.New("not valid UTF-8")
	}
	if err := refuseLoneSurrogates(text); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(text))
	dec.UseNumber()
	// Each open container, with, for an object, the names it holds and
	// the member name read and not yet given its value -- kept apart from
	// whether one is pending, since "" is a name like any other.
	type open struct {
		node    *jsonNode
		seen    map[string]bool
		name    string
		pending bool
	}
	var stack []*open
	var root *jsonNode
	attach := func(v *jsonNode) {
		if len(stack) == 0 {
			root = v
			return
		}
		top := stack[len(stack)-1]
		if top.node.kind == 'o' {
			top.node.names = append(top.node.names, top.name)
			top.name, top.pending = "", false
		}
		top.node.values = append(top.node.values, v)
	}
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		if len(stack) > 0 && stack[len(stack)-1].node.kind == 'o' && !stack[len(stack)-1].pending {
			top := stack[len(stack)-1]
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:len(stack)-1]
				attach(top.node)
			} else {
				name, ok := tok.(string)
				if !ok {
					return nil, errors.New("a member name that is not a string")
				}
				if top.seen[name] {
					return nil, errors.New("a member name twice")
				}
				top.seen[name] = true
				top.name, top.pending = name, true
				continue
			}
		} else {
			switch v := tok.(type) {
			case json.Delim:
				switch v {
				case '{', '[':
					if len(stack) >= schemaDecodeNesting {
						return nil, errors.New("nested too deep")
					}
					kind := byte('a')
					if v == '{' {
						kind = 'o'
					}
					stack = append(stack, &open{node: &jsonNode{kind: kind}, seen: map[string]bool{}})
					continue
				case ']':
					top := stack[len(stack)-1]
					stack = stack[:len(stack)-1]
					attach(top.node)
				}
			case string:
				attach(&jsonNode{kind: 's', text: v})
			case json.Number:
				attach(&jsonNode{kind: 'n', text: string(v)})
			case bool:
				attach(&jsonNode{kind: 'b', truth: v})
			case nil:
				attach(&jsonNode{kind: 'z'})
			}
		}
		if len(stack) == 0 && root != nil {
			break
		}
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing content")
	}
	return root, nil
}

// refuseLoneSurrogates refuses a \u escape of a surrogate outside a
// properly ordered pair.
func refuseLoneSurrogates(text []byte) error {
	inString := false
	for i := 0; i < len(text); i++ {
		c := text[i]
		if !inString {
			inString = c == '"'
			continue
		}
		if c == '"' {
			inString = false
			continue
		}
		if c != '\\' {
			continue
		}
		if i+1 >= len(text) {
			return errors.New("an unterminated escape")
		}
		if text[i+1] != 'u' {
			i++
			continue
		}
		unit := func(at int) (int, bool) {
			if at+4 > len(text) {
				return 0, false
			}
			n, err := strconv.ParseUint(string(text[at:at+4]), 16, 32)
			return int(n), err == nil
		}
		high, ok := unit(i + 2)
		if !ok {
			return errors.New("a malformed escape")
		}
		if high >= 0xDC00 && high <= 0xDFFF {
			return errors.New("a lone surrogate escape")
		}
		if high >= 0xD800 && high <= 0xDBFF {
			low, ok := unit(i + 8)
			if !ok || text[i+6] != '\\' || text[i+7] != 'u' || low < 0xDC00 || low > 0xDFFF {
				return errors.New("a lone surrogate escape")
			}
			i += 11
			continue
		}
		i += 5
	}
	return nil
}

// descriptorRefusal is why a candidate is refused: the shared vectors'
// code, and where, a JSON Pointer, unless the candidate is refused whole.
type descriptorRefusal struct {
	code    string
	pointer string
	whole   bool
	detail  string
}

func (r *descriptorRefusal) Error() string {
	if r.whole {
		return r.detail
	}
	where := r.pointer
	if where == "" {
		where = "(root)"
	}
	return escapeIdentifier(where) + ": " + r.detail
}

var grammarTypeNames = map[string]bool{"null": true, "boolean": true, "object": true, "array": true, "number": true, "string": true, "integer": true}

// judgeSchemaText judges an input schema's original text to grammar 1, its
// limits and display policy 1, walking members in the order written.
func judgeSchemaText(text string) *descriptorRefusal {
	if len(text) > schemaTextBound {
		return &descriptorRefusal{code: refusedTextSize, whole: true, detail: fmt.Sprintf("its text is %d bytes, over %d", len(text), schemaTextBound)}
	}
	root, err := decodeWritten([]byte(text))
	if err != nil {
		return &descriptorRefusal{code: refusedJSON, whole: true, detail: "it is not one strict JSON value"}
	}
	w := &grammarWalk{}
	w.schema(root, 1)
	return w.refused
}

type grammarWalk struct {
	path      []string
	locations int
	refused   *descriptorRefusal
}

func (w *grammarWalk) here() string {
	if len(w.path) == 0 {
		return ""
	}
	return "/" + strings.Join(w.path, "/")
}

func (w *grammarWalk) refuse(code, detail string) {
	if w.refused == nil {
		w.refused = &descriptorRefusal{code: code, pointer: w.here(), detail: detail}
	}
}

func (w *grammarWalk) in(token string, f func()) {
	w.path = append(w.path, token)
	f()
	w.path = w.path[:len(w.path)-1]
}

func escapeToken(name string) string {
	return strings.ReplaceAll(strings.ReplaceAll(name, "~", "~0"), "/", "~1")
}

// schema judges the schema location the walk stands at, at depth (the
// root is 1).
func (w *grammarWalk) schema(n *jsonNode, depth int) {
	if w.refused != nil {
		return
	}
	if w.locations++; w.locations > schemaLocationBound {
		w.refused = &descriptorRefusal{code: refusedLocations, whole: true, detail: fmt.Sprintf("more than %d schema locations", schemaLocationBound)}
		return
	}
	if depth > schemaNestingBound {
		w.refuse(refusedNesting, fmt.Sprintf("schema locations nested deeper than %d", schemaNestingBound))
		return
	}
	if n.kind != 'o' {
		w.refuse(refusedNotObject, "a schema here is an object")
		return
	}
	for i, name := range n.names {
		v := n.values[i]
		w.in(escapeToken(name), func() { w.keyword(name, v, depth) })
		if w.refused != nil {
			return
		}
	}
	if _, ok := n.member("type"); depth == 1 && !ok {
		w.in("type", func() { w.refuse(refusedValue, `the root's type is exactly "object"`) })
	}
}

func (w *grammarWalk) keyword(name string, v *jsonNode, depth int) {
	switch name {
	case "type":
		switch {
		case depth == 1:
			if v.kind != 's' || v.text != "object" {
				w.refuse(refusedValue, `the root's type is exactly "object"`)
			}
		case v.kind == 's':
			if !grammarTypeNames[v.text] {
				w.refuse(refusedValue, "type names a type")
			}
		case v.kind == 'a' && len(v.values) > 0:
			seen := map[string]bool{}
			for i, item := range v.values {
				if item.kind != 's' || !grammarTypeNames[item.text] || seen[item.text] {
					w.in(strconv.Itoa(i), func() { w.refuse(refusedValue, "type holds distinct type names") })
					return
				}
				seen[item.text] = true
			}
		default:
			w.refuse(refusedValue, "type is a type name or a non-empty array of distinct ones")
		}
	case "properties":
		if v.kind != 'o' || len(v.names) > schemaListBound {
			w.refuse(refusedValue, "properties is an object of at most 256 schemas")
			return
		}
		for i, prop := range v.names {
			sub := v.values[i]
			w.in(escapeToken(prop), func() {
				w.str(prop, propertyNameBound, refusedNameSize)
				w.schema(sub, depth+1)
			})
			if w.refused != nil {
				return
			}
		}
	case "required":
		if v.kind != 'a' || len(v.values) > schemaListBound {
			w.refuse(refusedValue, "required is an array of at most 256 distinct strings")
			return
		}
		seen := map[string]bool{}
		for i, item := range v.values {
			w.in(strconv.Itoa(i), func() {
				switch {
				case item.kind != 's':
					w.refuse(refusedValue, "required holds strings")
				default:
					if w.str(item.text, schemaStringBound, refusedStringSize); w.refused == nil && seen[item.text] {
						w.refuse(refusedValue, "required names a property twice")
					}
					seen[item.text] = true
				}
			})
			if w.refused != nil {
				return
			}
		}
	case "additionalProperties":
		if v.kind != 'b' {
			w.schema(v, depth+1)
		}
	case "items":
		if v.kind == 'a' {
			w.refuse(refusedValue, "the array form of items is refused")
			return
		}
		w.schema(v, depth+1)
	case "enum":
		if v.kind != 'a' || len(v.values) == 0 || len(v.values) > schemaListBound {
			w.refuse(refusedValue, "enum is a non-empty array of at most 256 distinct scalars")
			return
		}
		seen := map[string]bool{}
		for i, item := range v.values {
			w.in(strconv.Itoa(i), func() {
				key, ok := w.scalar(item)
				switch {
				case w.refused != nil:
				case !ok:
					w.refuse(refusedValue, "enum holds scalars")
				case seen[key]:
					w.refuse(refusedValue, "enum holds a value twice")
				}
				seen[key] = true
			})
			if w.refused != nil {
				return
			}
		}
	case "const":
		if _, ok := w.scalar(v); !ok && w.refused == nil {
			w.refuse(refusedValue, "const is a scalar")
		}
	case "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum":
		if v.kind != 'n' {
			w.refuse(refusedValue, name+" is a number")
			return
		}
		w.number(v.text)
	case "multipleOf":
		if v.kind != 'n' {
			w.refuse(refusedValue, "multipleOf is a number greater than zero")
			return
		}
		if w.number(v.text); w.refused == nil {
			if r, ok := new(big.Rat).SetString(v.text); !ok || r.Sign() <= 0 {
				w.refuse(refusedValue, "multipleOf is a number greater than zero")
			}
		}
	case "minLength", "maxLength", "minItems", "maxItems", "minProperties", "maxProperties":
		if v.kind != 'n' || !lengthSpelling(v.text) {
			w.refuse(refusedValue, name+" is a non-negative integer, written without fraction or exponent, at most 2^53-1")
		}
	case "anyOf", "oneOf", "allOf":
		if v.kind != 'a' || len(v.values) == 0 || len(v.values) > schemaBranchBound {
			w.refuse(refusedValue, name+" is a non-empty array of at most 16 schemas")
			return
		}
		for i, sub := range v.values {
			w.in(strconv.Itoa(i), func() { w.schema(sub, depth+1) })
			if w.refused != nil {
				return
			}
		}
	case "not":
		w.schema(v, depth+1)
	case "description", "title", "$comment":
		if v.kind != 's' {
			w.refuse(refusedValue, name+" is a string")
			return
		}
		w.str(v.text, schemaStringBound, refusedStringSize)
	case "examples":
		if v.kind != 'a' {
			w.refuse(refusedValue, "examples is an array")
			return
		}
		w.data(v)
	case "default":
		w.data(v)
	case "deprecated", "readOnly", "writeOnly":
		if v.kind != 'b' {
			w.refuse(refusedValue, name+" is a boolean")
		}
	case "$schema":
		if depth != 1 {
			w.refuse(refusedKeyword, "$schema is for the root only")
			return
		}
		if v.kind != 's' || (v.text != dialect202012 && v.text != dialectDraft07) {
			w.refuse(refusedValue, "$schema names 2020-12 or draft-07")
		}
	default:
		w.refuse(refusedKeyword, "not a keyword of schema grammar 1")
	}
}

// scalar judges a scalar to its bounds and names its value; false for what
// is not a scalar.
func (w *grammarWalk) scalar(n *jsonNode) (string, bool) {
	switch n.kind {
	case 's':
		w.str(n.text, schemaStringBound, refusedStringSize)
		return "s" + n.text, true
	case 'n':
		if w.number(n.text); w.refused != nil {
			return "", true
		}
		r, ok := new(big.Rat).SetString(n.text)
		if !ok {
			return "", false
		}
		return "n" + r.RatString(), true
	case 'b':
		return "b" + strconv.FormatBool(n.truth), true
	case 'z':
		return "z", true
	}
	return "", false
}

// data judges data -- a default, an example -- to the bounds every string
// and number meets; a member name inside data is a string like any other.
// The decoder bounds its nesting.
func (w *grammarWalk) data(n *jsonNode) {
	if w.refused != nil {
		return
	}
	switch n.kind {
	case 's':
		w.str(n.text, schemaStringBound, refusedStringSize)
	case 'n':
		w.number(n.text)
	case 'a':
		for i, item := range n.values {
			w.in(strconv.Itoa(i), func() { w.data(item) })
		}
	case 'o':
		for i, name := range n.names {
			item := n.values[i]
			w.in(escapeToken(name), func() {
				w.str(name, schemaStringBound, refusedStringSize)
				w.data(item)
			})
		}
	}
}

func (w *grammarWalk) str(s string, bound int, code string) {
	if w.refused != nil {
		return
	}
	if len(s) > bound {
		w.refuse(code, fmt.Sprintf("a string of %d bytes, over %d", len(s), bound))
		return
	}
	if r, bad := firstRefused(s); bad {
		w.refuse(refusedPolicy, fmt.Sprintf("holds U+%04X, which display policy 1 refuses", r))
	}
}

// number judges a number as written: at most 32 characters, an exponent
// within ±308.
func (w *grammarWalk) number(literal string) {
	if w.refused != nil {
		return
	}
	if len(literal) > numberTextBound {
		w.refuse(refusedNumber, "a number written in more than 32 characters")
		return
	}
	if at := strings.IndexAny(literal, "eE"); at >= 0 {
		exponent := strings.TrimLeft(literal[at+1:], "+-")
		exponent = strings.TrimLeft(exponent, "0")
		if n, err := strconv.Atoi(exponent); len(exponent) > 3 || (err == nil && n > exponentBound) {
			w.refuse(refusedNumber, "a number whose exponent is beyond ±308")
		}
	}
}

// lengthSpelling is a non-negative integer with neither fraction nor
// exponent, at most 2^53-1.
func lengthSpelling(literal string) bool {
	if literal == "" || (literal[0] == '0' && len(literal) > 1) {
		return false
	}
	for _, c := range literal {
		if c < '0' || c > '9' {
			return false
		}
	}
	n, err := strconv.ParseUint(literal, 10, 64)
	return err == nil && n <= 1<<53-1
}

// annotationKeywords are the members the serving projection removes at
// schema locations: nothing that bears on validation.
var annotationKeywords = map[string]bool{"description": true, "title": true, "examples": true, "default": true, "$comment": true, "deprecated": true, "readOnly": true, "writeOnly": true}

// labelledText is a description at a schema location, labelled by the
// location's JSON Pointer, the root's as (root).
type labelledText struct{ label, text string }

// schemaDescriptions are the descriptions at schema locations, in the order
// the server wrote them; a property named description is a name, not one.
func schemaDescriptions(root *jsonNode) []labelledText {
	var out []labelledText
	walkSchemaDescriptions(root, func(label []byte, text string) bool {
		out = append(out, labelledText{label: string(label), text: text})
		return true
	})
	return out
}

// walkSchemaDescriptions hands each description at a schema location to
// visit, in the order written, with its label, until visit says stop. The
// label is the walk's own pointer, held only while visit runs: a schema's
// labels together can run far past the schema, and are never built.
func walkSchemaDescriptions(root *jsonNode, visit func(label []byte, text string) bool) {
	var pointer []byte
	var walk func(n *jsonNode) bool
	walk = func(n *jsonNode) bool {
		if n.kind != 'o' {
			return true
		}
		at := len(pointer)
		for i, name := range n.names {
			v := n.values[i]
			pointer = appendToken(append(pointer[:at], '/'), name)
			here := len(pointer)
			switch name {
			case "description":
				if v.kind == 's' {
					label := pointer[:at]
					if at == 0 {
						label = []byte("(root)")
					}
					if !visit(label, v.text) {
						return false
					}
				}
			case "properties":
				if v.kind == 'o' {
					for j, prop := range v.names {
						pointer = appendToken(append(pointer[:here], '/'), prop)
						if !walk(v.values[j]) {
							return false
						}
					}
				}
			case "items", "additionalProperties", "not":
				if !walk(v) {
					return false
				}
			case "anyOf", "oneOf", "allOf":
				if v.kind == 'a' {
					for j, sub := range v.values {
						pointer = strconv.AppendInt(append(pointer[:here], '/'), int64(j), 10)
						if !walk(sub) {
							return false
						}
					}
				}
			}
		}
		return true
	}
	walk(root)
}

// appendToken appends name to a JSON Pointer as a reference token, ~ and /
// escaped.
func appendToken(pointer []byte, name string) []byte {
	for i := 0; i < len(name); i++ {
		switch name[i] {
		case '~':
			pointer = append(pointer, '~', '0')
		case '/':
			pointer = append(pointer, '~', '1')
		default:
			pointer = append(pointer, name[i])
		}
	}
	return pointer
}

// projectSchema is a schema as served: its original text parsed, the
// annotations removed at schema locations, and written compactly, members
// sorted, each number as it was spelled.
func projectSchema(root *jsonNode) []byte {
	var sb strings.Builder
	var write func(n *jsonNode, location bool)
	write = func(n *jsonNode, location bool) {
		switch n.kind {
		case 'o':
			type member struct {
				name  string
				value *jsonNode
			}
			var members []member
			for i, name := range n.names {
				if location && annotationKeywords[name] {
					continue
				}
				members = append(members, member{name, n.values[i]})
			}
			sort.Slice(members, func(i, j int) bool { return members[i].name < members[j].name })
			sb.WriteByte('{')
			for i, m := range members {
				if i > 0 {
					sb.WriteByte(',')
				}
				writeCanonicalString(&sb, m.name)
				sb.WriteByte(':')
				switch {
				case !location:
					write(m.value, false)
				case m.name == "properties" && m.value.kind == 'o':
					writeSchemaMap(&sb, m.value, write)
				case m.name == "items" || m.name == "additionalProperties" || m.name == "not":
					write(m.value, m.value.kind == 'o')
				case (m.name == "anyOf" || m.name == "oneOf" || m.name == "allOf") && m.value.kind == 'a':
					sb.WriteByte('[')
					for j, sub := range m.value.values {
						if j > 0 {
							sb.WriteByte(',')
						}
						write(sub, true)
					}
					sb.WriteByte(']')
				default:
					write(m.value, false)
				}
			}
			sb.WriteByte('}')
		case 'a':
			sb.WriteByte('[')
			for i, item := range n.values {
				if i > 0 {
					sb.WriteByte(',')
				}
				write(item, false)
			}
			sb.WriteByte(']')
		case 's':
			writeCanonicalString(&sb, n.text)
		case 'n':
			sb.WriteString(n.text)
		case 'b':
			sb.WriteString(strconv.FormatBool(n.truth))
		case 'z':
			sb.WriteString("null")
		}
	}
	write(root, true)
	return []byte(sb.String())
}

// writeSchemaMap writes properties: each member's value a schema location.
func writeSchemaMap(sb *strings.Builder, props *jsonNode, write func(*jsonNode, bool)) {
	order := make([]int, len(props.names))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(a, b int) bool { return props.names[order[a]] < props.names[order[b]] })
	sb.WriteByte('{')
	for i, at := range order {
		if i > 0 {
			sb.WriteByte(',')
		}
		writeCanonicalString(sb, props.names[at])
		sb.WriteByte(':')
		write(props.values[at], true)
	}
	sb.WriteByte('}')
}

// judgeText judges a description or an identity string to its bound and
// display policy 1.
func judgeText(s string, bound int, what string) *descriptorRefusal {
	if len(s) > bound {
		return &descriptorRefusal{code: refusedStringSize, whole: true, detail: fmt.Sprintf("%s is over %d bytes", what, bound)}
	}
	if r, bad := firstRefused(s); bad {
		return &descriptorRefusal{code: refusedPolicy, whole: true, detail: fmt.Sprintf("%s holds U+%04X, which display policy 1 refuses", what, r)}
	}
	return nil
}
