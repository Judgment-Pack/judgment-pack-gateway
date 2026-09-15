package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Schema grammar 1 (docs/design/tool-descriptors.md) is the
// reference-free subset of JSON Schema a captured inputSchema is written
// in, with its limits. Nothing is removed to bring a schema inside it: one
// keyword outside it costs the tool its schema, which falls back whole.
const (
	maxSchemaText      = 16384
	maxSchemaNesting   = 32
	maxSchemaLocations = 2048
	maxPropertyName    = 128
	maxSchemaString    = 1024
	maxListed          = 256 // members of properties, required and enum
	maxBranches        = 16  // anyOf, oneOf and allOf
	maxNumberText      = 32
	maxExponent        = 308
	maxDescription     = 4096
	maxIdentity        = 256

	dialect2020 = "https://json-schema.org/draft/2020-12/schema"
	dialect07   = "http://json-schema.org/draft-07/schema#"
)

// The codes a refusal carries, which the shared vectors
// (testdata/tool-descriptors) name: the frontend judges again with an
// implementation of its own, and the two answer to the same vectors.
const (
	codeTextSize   = "text-size"   // a schema's text, over its bound
	codeJSON       = "json"        // not one strict JSON value
	codeNotObject  = "not-object"  // a schema location that is not an object
	codeKeyword    = "keyword"     // a keyword outside the grammar, or $schema below the root
	codeValue      = "value"       // a keyword's value not of its form
	codeNumber     = "number"      // a number past the written bounds
	codeNesting    = "nesting"     // schema locations nested past the bound
	codeLocations  = "locations"   // more schema locations than the bound
	codeNameSize   = "name-size"   // a property name over its bound
	codeStringSize = "string-size" // any other string over its bound
	codePolicy     = "policy"      // a code point display policy 1 refuses
	codeSecret     = "secret"      // a string holding a value of the credentials
	codeAbsent     = "absent"      // no candidate where one is required
)

// refusal is why a candidate is refused: its code, the JSON Pointer of
// what is refused when a location is meant (whole for the candidate as a
// whole), and the words an operator reads.
type refusal struct {
	code    string
	pointer string
	whole   bool
	detail  string
}

// reason is the refusal as an operator reads it: the location, the root's
// labelled (root), then what is wrong. A location is written visibly, so
// no name a server wrote moves the terminal.
func (r *refusal) reason() string {
	if r.whole {
		return r.detail
	}
	label := r.pointer
	if label == "" {
		label = "(root)"
	}
	return visible(label) + ": " + r.detail
}

var schemaTypes = map[string]bool{"null": true, "boolean": true, "object": true, "array": true, "number": true, "string": true, "integer": true}

// grammarKeywords are the keywords the grammar names.
var grammarKeywords = map[string]bool{
	"type": true, "properties": true, "required": true, "additionalProperties": true, "items": true,
	"enum": true, "const": true, "minimum": true, "maximum": true, "exclusiveMinimum": true,
	"exclusiveMaximum": true, "multipleOf": true, "minLength": true, "maxLength": true, "minItems": true,
	"maxItems": true, "minProperties": true, "maxProperties": true, "anyOf": true, "oneOf": true,
	"allOf": true, "not": true, "description": true, "title": true, "$comment": true, "examples": true,
	"default": true, "deprecated": true, "readOnly": true, "writeOnly": true, "$schema": true,
}

// lengthLiteral is a non-negative integer written without sign, fraction
// or exponent.
var lengthLiteral = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// checkSchema judges a schema candidate by its original text: its size;
// then that it is one strict JSON value; then that no string in it that a
// server chose holds a value of the credentials, which is refused without
// a location since a location would point at it; then the grammar, its
// limits and the display policy. It returns the first refusal, or nil.
// Every step is linear in the text: a value nested thousands deep costs
// what its bytes do.
func checkSchema(text []byte, secrets []string) *refusal {
	if len(text) > maxSchemaText {
		return &refusal{code: codeTextSize, whole: true, detail: fmt.Sprintf("its text is %d bytes, over %d", len(text), maxSchemaText)}
	}
	// The whole message was held to these already; the candidate is held
	// to them again on its own, so the check stands without the message.
	tree, err := decodeStrict(text)
	if err != nil {
		return &refusal{code: codeJSON, whole: true, detail: "it is not one strict JSON value"}
	}
	if schemaHoldsSecret(tree, secrets, true) {
		return &refusal{code: codeSecret, whole: true, detail: "a string in it holds a value of the credentials"}
	}
	c := &schemaCheck{}
	c.location(tree, 1)
	return c.fail
}

// decodeStrict decodes one JSON value -- valid UTF-8, no lone surrogate
// escape, no member name twice in an object, nothing after it, nesting no
// deeper than a decoder reads -- into maps, slices and json.Number, with an
// explicit stack, so neither the depth nor the size of a value costs more
// than its bytes.
func decodeStrict(text []byte) (any, error) {
	if !utf8.Valid(text) {
		return nil, errors.New("not valid UTF-8")
	}
	if err := loneSurrogate(text); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(text))
	dec.UseNumber()
	type frame struct {
		object map[string]any
		array  []any
		key    string
		keyed  bool // an object's next token is its value
	}
	var stack []*frame
	var root any
	done := false
	// put places a finished value where it belongs: as the root, in the
	// array being read, or under the key just read.
	put := func(v any) error {
		if len(stack) == 0 {
			root, done = v, true
			return nil
		}
		top := stack[len(stack)-1]
		if top.object != nil {
			if _, twice := top.object[top.key]; twice {
				return errors.New("a member name twice")
			}
			top.object[top.key] = v
			top.keyed = false
			return nil
		}
		top.array = append(top.array, v)
		return nil
	}
	for !done {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		if len(stack) > 0 {
			if top := stack[len(stack)-1]; top.object != nil && !top.keyed {
				if delim, ok := tok.(json.Delim); ok && delim == '}' {
					stack = stack[:len(stack)-1]
					if err := put(top.object); err != nil {
						return nil, err
					}
					continue
				}
				name, ok := tok.(string)
				if !ok {
					return nil, errors.New("a member name that is not a string")
				}
				top.key, top.keyed = name, true
				continue
			}
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				if len(stack) >= maxDecodeNesting {
					return nil, errors.New("nested too deep")
				}
				f := &frame{}
				if v == '{' {
					f.object = map[string]any{}
				} else {
					f.array = []any{}
				}
				stack = append(stack, f)
			case ']':
				top := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if err := put(top.array); err != nil {
					return nil, err
				}
			}
		default:
			if err := put(v); err != nil {
				return nil, err
			}
		}
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing content")
	}
	return root, nil
}

// maxDecodeNesting is the nesting a decoder reads: what encoding/json and
// the canonical form refuse past.
const maxDecodeNesting = 10000

// loneSurrogate refuses a \u escape of a surrogate that is not one half of a
// properly ordered pair, which a decoder would turn into U+FFFD unsaid.
func loneSurrogate(text []byte) error {
	in := false
	for i := 0; i < len(text); i++ {
		switch c := text[i]; {
		case !in:
			in = c == '"'
		case c == '"':
			in = false
		case c == '\\':
			if i+1 >= len(text) {
				return errors.New("an unterminated escape")
			}
			if text[i+1] != 'u' {
				i++
				continue
			}
			high, ok := hex4(text, i+2)
			if !ok {
				return errors.New("a malformed \\u escape")
			}
			switch {
			case high >= 0xD800 && high <= 0xDBFF:
				low, ok := hex4(text, i+8)
				if !ok || text[i+6] != '\\' || text[i+7] != 'u' || low < 0xDC00 || low > 0xDFFF {
					return errors.New("a lone surrogate escape")
				}
				i += 11
			case high >= 0xDC00 && high <= 0xDFFF:
				return errors.New("a lone surrogate escape")
			default:
				i += 5
			}
		}
	}
	return nil
}

func hex4(text []byte, at int) (rune, bool) {
	if at+4 > len(text) {
		return 0, false
	}
	n, err := strconv.ParseUint(string(text[at:at+4]), 16, 32)
	return rune(n), err == nil
}

// schemaCheck walks a schema's locations, counting them, and keeps the
// first refusal; members are taken in sorted order, so which refusal is
// first does not depend on how a decoder ordered them. Where it stands is
// a stack of pointer tokens, joined into a pointer only when something is
// refused, so a value nested thousands deep costs no pointer per level.
type schemaCheck struct {
	locations int
	path      []string
	fail      *refusal
}

func (c *schemaCheck) push(token string) { c.path = append(c.path, token) }
func (c *schemaCheck) pop()              { c.path = c.path[:len(c.path)-1] }

// pointer is where the walk stands, as a JSON Pointer.
func (c *schemaCheck) pointer() string {
	if len(c.path) == 0 {
		return ""
	}
	return "/" + strings.Join(c.path, "/")
}

// refuse records the first refusal, where the walk stands.
func (c *schemaCheck) refuse(code, format string, args ...any) {
	if c.fail == nil {
		c.fail = &refusal{code: code, pointer: c.pointer(), detail: fmt.Sprintf(format, args...)}
	}
}

// at refuses at a position below where the walk stands.
func (c *schemaCheck) at(token, code, format string, args ...any) {
	c.push(token)
	c.refuse(code, format, args...)
	c.pop()
}

// location judges the schema location where the walk stands, at nesting
// depth, the root at 1.
func (c *schemaCheck) location(v any, depth int) {
	if c.fail != nil {
		return
	}
	c.locations++
	if c.locations > maxSchemaLocations {
		// Whole, not located: which location is the one too many depends
		// on the order a walk takes, and the two implementations need
		// not share one.
		c.fail = &refusal{code: codeLocations, whole: true, detail: fmt.Sprintf("more than %d schema locations", maxSchemaLocations)}
		return
	}
	if depth > maxSchemaNesting {
		c.refuse(codeNesting, "schema locations nested deeper than %d", maxSchemaNesting)
		return
	}
	obj, ok := v.(map[string]any)
	if !ok {
		// A boolean schema is refused everywhere but as the value of
		// additionalProperties, which is judged before it gets here.
		c.refuse(codeNotObject, "a schema here is an object")
		return
	}
	for _, key := range sortedKeys(obj) {
		c.push(pointerToken(key))
		c.keyword(key, obj[key], depth)
		c.pop()
		if c.fail != nil {
			return
		}
	}
	if _, ok := obj["type"]; depth == 1 && !ok {
		c.at("type", codeValue, `the root's type is exactly "object"`)
	}
}

// keyword judges one member of a schema location against the table; the
// walk stands at the member.
func (c *schemaCheck) keyword(key string, v any, depth int) {
	switch key {
	case "type":
		c.typeValue(v, depth == 1)
	case "properties":
		props, ok := v.(map[string]any)
		if !ok || len(props) > maxListed {
			c.refuse(codeValue, "properties is an object of at most %d schemas", maxListed)
			return
		}
		for _, name := range sortedKeys(props) {
			c.push(pointerToken(name))
			c.text(name, maxPropertyName, codeNameSize)
			c.location(props[name], depth+1)
			c.pop()
		}
	case "required":
		list, ok := v.([]any)
		if !ok || len(list) > maxListed {
			c.refuse(codeValue, "required is an array of at most %d distinct strings", maxListed)
			return
		}
		seen := map[string]bool{}
		for i, item := range list {
			c.push(strconv.Itoa(i))
			s, ok := item.(string)
			if !ok {
				c.refuse(codeValue, "required holds strings")
			} else if c.text(s, maxSchemaString, codeStringSize); c.fail == nil && seen[s] {
				c.refuse(codeValue, "required names a property twice")
			}
			seen[s] = true
			c.pop()
			if c.fail != nil {
				return
			}
		}
	case "additionalProperties":
		if _, ok := v.(bool); ok {
			return
		}
		c.location(v, depth+1)
	case "items":
		if _, ok := v.([]any); ok {
			c.refuse(codeValue, "the array form of items is refused")
			return
		}
		c.location(v, depth+1)
	case "enum":
		list, ok := v.([]any)
		if !ok || len(list) == 0 || len(list) > maxListed {
			c.refuse(codeValue, "enum is a non-empty array of at most %d distinct scalars", maxListed)
			return
		}
		c.distinctScalars(list)
	case "const":
		if !isScalar(v) {
			c.refuse(codeValue, "const is a scalar")
			return
		}
		c.data(v)
	case "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum":
		// The boolean exclusive forms of draft-04 are refused with every
		// other value that is not a number.
		n, ok := v.(json.Number)
		if !ok {
			c.refuse(codeValue, "%s is a number", key)
			return
		}
		c.number(n)
	case "multipleOf":
		n, ok := v.(json.Number)
		if !ok {
			c.refuse(codeValue, "multipleOf is a number greater than zero")
			return
		}
		if c.number(n); c.fail == nil && !positive(string(n)) {
			c.refuse(codeValue, "multipleOf is a number greater than zero")
		}
	case "minLength", "maxLength", "minItems", "maxItems", "minProperties", "maxProperties":
		n, ok := v.(json.Number)
		if !ok || !isLength(string(n)) {
			c.refuse(codeValue, "%s is a non-negative integer, written without fraction or exponent, at most 2^53-1", key)
		}
	case "anyOf", "oneOf", "allOf":
		list, ok := v.([]any)
		if !ok || len(list) == 0 || len(list) > maxBranches {
			c.refuse(codeValue, "%s is a non-empty array of at most %d schemas", key, maxBranches)
			return
		}
		for i, item := range list {
			c.push(strconv.Itoa(i))
			c.location(item, depth+1)
			c.pop()
		}
	case "not":
		c.location(v, depth+1)
	case "description", "title", "$comment":
		s, ok := v.(string)
		if !ok {
			c.refuse(codeValue, "%s is a string", key)
			return
		}
		c.text(s, maxSchemaString, codeStringSize)
	case "examples":
		if _, ok := v.([]any); !ok {
			c.refuse(codeValue, "examples is an array")
			return
		}
		c.data(v)
	case "default":
		c.data(v)
	case "deprecated", "readOnly", "writeOnly":
		if _, ok := v.(bool); !ok {
			c.refuse(codeValue, "%s is a boolean", key)
		}
	case "$schema":
		if depth != 1 {
			c.refuse(codeKeyword, "$schema is for the root only")
			return
		}
		if s, ok := v.(string); !ok || (s != dialect2020 && s != dialect07) {
			c.refuse(codeValue, "$schema is %s or %s", dialect2020, dialect07)
		}
	default:
		// format, pattern, every reference and identifier keyword, and
		// every keyword this grammar does not name.
		c.refuse(codeKeyword, "not a keyword of schema grammar 1")
	}
}

// typeValue judges type: at the root exactly "object", elsewhere one type
// name or a non-empty array of distinct ones.
func (c *schemaCheck) typeValue(v any, root bool) {
	if root {
		if s, ok := v.(string); !ok || s != "object" {
			c.refuse(codeValue, `the root's type is exactly "object"`)
		}
		return
	}
	switch x := v.(type) {
	case string:
		if !schemaTypes[x] {
			c.refuse(codeValue, "type names one of null, boolean, object, array, number, string and integer")
		}
	case []any:
		if len(x) == 0 {
			c.refuse(codeValue, "type is a type name or a non-empty array of distinct ones")
			return
		}
		seen := map[string]bool{}
		for i, item := range x {
			s, ok := item.(string)
			if !ok || !schemaTypes[s] || seen[s] {
				c.at(strconv.Itoa(i), codeValue, "type is a type name or a non-empty array of distinct ones")
				return
			}
			seen[s] = true
		}
	default:
		c.refuse(codeValue, "type is a type name or a non-empty array of distinct ones")
	}
}

// distinctScalars judges enum's members: each a scalar, no two equal as
// JSON values are -- numbers by their exact value, so 1 and 1.0 are one
// value -- each within the bounds of what it is.
func (c *schemaCheck) distinctScalars(list []any) {
	seen := map[string]bool{}
	for i, item := range list {
		c.push(strconv.Itoa(i))
		key, ok := c.scalarKey(item)
		switch {
		case c.fail != nil:
		case !ok:
			c.refuse(codeValue, "enum holds scalars")
		case seen[key]:
			c.refuse(codeValue, "enum holds a value twice")
		}
		seen[key] = true
		c.pop()
		if c.fail != nil {
			return
		}
	}
}

// scalarKey is a scalar's identity as a JSON value, judging it to its
// bounds first; false for what is not a scalar.
func (c *schemaCheck) scalarKey(item any) (string, bool) {
	switch x := item.(type) {
	case string:
		c.text(x, maxSchemaString, codeStringSize)
		return "s" + x, true
	case json.Number:
		// Judged as written first, so the value is only ever computed
		// for a number within the written bounds.
		if c.number(x); c.fail != nil {
			return "", true
		}
		r, ok := new(big.Rat).SetString(string(x))
		if !ok {
			return "", false
		}
		return "n" + r.RatString(), true
	case bool:
		return fmt.Sprint("b", x), true
	case nil:
		return "z", true
	}
	return "", false
}

// data judges a value that is data, not schema -- a default, an example,
// a constant -- to the bounds every string and number in a schema meets.
// A member name inside data is a string like any other.
func (c *schemaCheck) data(v any) {
	if c.fail != nil {
		return
	}
	switch x := v.(type) {
	case string:
		c.text(x, maxSchemaString, codeStringSize)
	case json.Number:
		c.number(x)
	case []any:
		for i, item := range x {
			c.push(strconv.Itoa(i))
			c.data(item)
			c.pop()
		}
	case map[string]any:
		for _, k := range sortedKeys(x) {
			c.push(pointerToken(k))
			c.text(k, maxSchemaString, codeStringSize)
			c.data(x[k])
			c.pop()
		}
	}
}

// text judges a string to its bound, in bytes, and to display policy 1.
func (c *schemaCheck) text(s string, limit int, code string) {
	if c.fail != nil {
		return
	}
	if len(s) > limit {
		c.refuse(code, "a string of %d bytes, over %d", len(s), limit)
		return
	}
	if r, refused := displayRefusal(s); refused {
		c.refuse(codePolicy, "holds U+%04X, which display policy 1 refuses", r)
	}
}

// number judges a number as written: at most 32 characters, an exponent,
// if any, within ±308.
func (c *schemaCheck) number(n json.Number) {
	if c.fail != nil {
		return
	}
	if detail := numberRefusal(string(n)); detail != "" {
		c.refuse(codeNumber, "%s", detail)
	}
}

func numberRefusal(literal string) string {
	if len(literal) > maxNumberText {
		return fmt.Sprintf("a number written in %d characters, over %d", len(literal), maxNumberText)
	}
	if i := strings.IndexAny(literal, "eE"); i >= 0 {
		digits := strings.TrimLeft(strings.TrimLeft(literal[i+1:], "+-"), "0")
		if len(digits) > 3 || len(digits) == 3 && digits > fmt.Sprint(maxExponent) {
			return fmt.Sprintf("a number whose exponent is beyond ±%d", maxExponent)
		}
	}
	return ""
}

// positive reports whether a JSON number literal is greater than zero: no
// sign, and a digit other than zero before any exponent.
func positive(literal string) bool {
	if strings.HasPrefix(literal, "-") {
		return false
	}
	mantissa, _, _ := strings.Cut(strings.ToLower(literal), "e")
	return strings.ContainsAny(mantissa, "123456789")
}

// isLength reports whether a literal is a length: a non-negative integer
// written without fraction or exponent, at most 2^53-1.
func isLength(literal string) bool {
	const max = "9007199254740991"
	return lengthLiteral.MatchString(literal) && (len(literal) < len(max) || len(literal) == len(max) && literal <= max)
}

func isScalar(v any) bool {
	switch v.(type) {
	case string, json.Number, bool, nil:
		return true
	}
	return false
}

// schemaHoldsSecret reports whether a string a server chose holds a value
// of the credentials, walking the schema by the role each string has. Three
// are the grammar's own words in their own places, the same whatever the
// credentials hold, and are not screened: a keyword the grammar names, as a
// member of a schema location; a type name, as the value of type; and a
// dialect's URI, as the root's $schema. A credential "require"
// (PostgreSQL's sslmode) would otherwise refuse every schema that uses
// required. Every other string is screened wherever it is: a property
// name, a string of data, a description, title or comment, a name required
// lists, a keyword the grammar does not name and all it holds.
func schemaHoldsSecret(v any, secrets []string, root bool) bool {
	obj, ok := v.(map[string]any)
	if !ok {
		return treeHoldsSecret(v, secrets)
	}
	for key, value := range obj {
		if !grammarKeywords[key] {
			if holdsSecret(key, secrets) || treeHoldsSecret(value, secrets) {
				return true
			}
			continue
		}
		switch key {
		case "properties":
			props, ok := value.(map[string]any)
			if !ok {
				if treeHoldsSecret(value, secrets) {
					return true
				}
				continue
			}
			for name, sub := range props {
				if holdsSecret(name, secrets) || schemaHoldsSecret(sub, secrets, false) {
					return true
				}
			}
		case "items", "additionalProperties", "not":
			if schemaHoldsSecret(value, secrets, false) {
				return true
			}
		case "anyOf", "oneOf", "allOf":
			list, ok := value.([]any)
			if !ok {
				if treeHoldsSecret(value, secrets) {
					return true
				}
				continue
			}
			for _, sub := range list {
				if schemaHoldsSecret(sub, secrets, false) {
					return true
				}
			}
		case "type":
			names := []any{value}
			if list, ok := value.([]any); ok {
				names = list
			}
			for _, name := range names {
				if s, ok := name.(string); ok && schemaTypes[s] {
					continue
				}
				if treeHoldsSecret(name, secrets) {
					return true
				}
			}
		case "$schema":
			if s, ok := value.(string); ok && root && (s == dialect2020 || s == dialect07) {
				continue
			}
			if treeHoldsSecret(value, secrets) {
				return true
			}
		default:
			if treeHoldsSecret(value, secrets) {
				return true
			}
		}
	}
	return false
}

// treeHoldsSecret reports whether any string of a decoded JSON value, a
// member name or a value, holds a value of the credentials.
func treeHoldsSecret(v any, secrets []string) bool {
	switch x := v.(type) {
	case string:
		return holdsSecret(x, secrets)
	case []any:
		for _, item := range x {
			if treeHoldsSecret(item, secrets) {
				return true
			}
		}
	case map[string]any:
		for k, item := range x {
			if holdsSecret(k, secrets) || treeHoldsSecret(item, secrets) {
				return true
			}
		}
	}
	return false
}

// holdsSecret reports whether s contains any value the credentials'
// secret collection found.
func holdsSecret(s string, secrets []string) bool {
	for _, secret := range secrets {
		if secret != "" && strings.Contains(s, secret) {
			return true
		}
	}
	return false
}

// pointerToken is a member name as a JSON Pointer token: ~ as ~0, / as ~1.
func pointerToken(name string) string {
	return strings.ReplaceAll(strings.ReplaceAll(name, "~", "~0"), "/", "~1")
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
