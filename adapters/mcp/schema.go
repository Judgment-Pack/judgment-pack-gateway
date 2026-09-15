package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strings"

	"adapters/internal/canon"
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
// then that it is one strict JSON value; then that no string in it, a name
// or a value, holds a value of the credentials, which is refused without a
// location since a location would point at it; then the grammar, its
// limits and the display policy. It returns the first refusal, or nil.
func checkSchema(text []byte, secrets []string) *refusal {
	if len(text) > maxSchemaText {
		return &refusal{code: codeTextSize, whole: true, detail: fmt.Sprintf("its text is %d bytes, over %d", len(text), maxSchemaText)}
	}
	// The whole message was held to these already; the candidate is held
	// to them again on its own, so the check stands without the message.
	if _, err := canon.Canonicalize(text, canon.CarryNumbersAsText); err != nil {
		return &refusal{code: codeJSON, whole: true, detail: "it is not one strict JSON value"}
	}
	dec := json.NewDecoder(bytes.NewReader(text))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return &refusal{code: codeJSON, whole: true, detail: "it is not one strict JSON value"}
	}
	if schemaHoldsSecret(tree, secrets, true) {
		return &refusal{code: codeSecret, whole: true, detail: "a string in it holds a value of the credentials"}
	}
	c := &schemaCheck{}
	c.location(tree, "", 1)
	return c.fail
}

// schemaCheck walks a schema's locations, counting them, and keeps the
// first refusal; members are taken in sorted order, so which refusal is
// first does not depend on how a decoder ordered them.
type schemaCheck struct {
	locations int
	fail      *refusal
}

func (c *schemaCheck) refuse(code, pointer, format string, args ...any) {
	if c.fail == nil {
		c.fail = &refusal{code: code, pointer: pointer, detail: fmt.Sprintf(format, args...)}
	}
}

// location judges one schema location at nesting depth, the root at 1.
func (c *schemaCheck) location(v any, at string, depth int) {
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
		c.refuse(codeNesting, at, "schema locations nested deeper than %d", maxSchemaNesting)
		return
	}
	obj, ok := v.(map[string]any)
	if !ok {
		// A boolean schema is refused everywhere but as the value of
		// additionalProperties, which is judged before it gets here.
		c.refuse(codeNotObject, at, "a schema here is an object")
		return
	}
	for _, key := range sortedKeys(obj) {
		c.keyword(key, obj[key], at, depth)
		if c.fail != nil {
			return
		}
	}
	if _, ok := obj["type"]; depth == 1 && !ok {
		c.refuse(codeValue, at+"/type", `the root's type is exactly "object"`)
	}
}

// keyword judges one member of a schema location against the table.
func (c *schemaCheck) keyword(key string, v any, at string, depth int) {
	here := at + "/" + pointerToken(key)
	switch key {
	case "type":
		c.typeValue(v, here, depth == 1)
	case "properties":
		props, ok := v.(map[string]any)
		if !ok || len(props) > maxListed {
			c.refuse(codeValue, here, "properties is an object of at most %d schemas", maxListed)
			return
		}
		for _, name := range sortedKeys(props) {
			member := here + "/" + pointerToken(name)
			c.text(name, member, maxPropertyName, codeNameSize)
			c.location(props[name], member, depth+1)
		}
	case "required":
		list, ok := v.([]any)
		if !ok || len(list) > maxListed {
			c.refuse(codeValue, here, "required is an array of at most %d distinct strings", maxListed)
			return
		}
		seen := map[string]bool{}
		for i, item := range list {
			s, ok := item.(string)
			if !ok {
				c.refuse(codeValue, index(here, i), "required holds strings")
				return
			}
			if c.text(s, index(here, i), maxSchemaString, codeStringSize); c.fail != nil {
				return
			}
			if seen[s] {
				c.refuse(codeValue, index(here, i), "required names a property twice")
				return
			}
			seen[s] = true
		}
	case "additionalProperties":
		if _, ok := v.(bool); ok {
			return
		}
		c.location(v, here, depth+1)
	case "items":
		if _, ok := v.([]any); ok {
			c.refuse(codeValue, here, "the array form of items is refused")
			return
		}
		c.location(v, here, depth+1)
	case "enum":
		list, ok := v.([]any)
		if !ok || len(list) == 0 || len(list) > maxListed {
			c.refuse(codeValue, here, "enum is a non-empty array of at most %d distinct scalars", maxListed)
			return
		}
		c.distinctScalars(list, here)
	case "const":
		if !isScalar(v) {
			c.refuse(codeValue, here, "const is a scalar")
			return
		}
		c.data(v, here)
	case "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum":
		// The boolean exclusive forms of draft-04 are refused with every
		// other value that is not a number.
		n, ok := v.(json.Number)
		if !ok {
			c.refuse(codeValue, here, "%s is a number", key)
			return
		}
		c.number(n, here)
	case "multipleOf":
		n, ok := v.(json.Number)
		if !ok {
			c.refuse(codeValue, here, "multipleOf is a number greater than zero")
			return
		}
		if c.number(n, here); c.fail == nil && !positive(string(n)) {
			c.refuse(codeValue, here, "multipleOf is a number greater than zero")
		}
	case "minLength", "maxLength", "minItems", "maxItems", "minProperties", "maxProperties":
		n, ok := v.(json.Number)
		if !ok || !isLength(string(n)) {
			c.refuse(codeValue, here, "%s is a non-negative integer, written without fraction or exponent, at most 2^53-1", key)
		}
	case "anyOf", "oneOf", "allOf":
		list, ok := v.([]any)
		if !ok || len(list) == 0 || len(list) > maxBranches {
			c.refuse(codeValue, here, "%s is a non-empty array of at most %d schemas", key, maxBranches)
			return
		}
		for i, item := range list {
			c.location(item, index(here, i), depth+1)
		}
	case "not":
		c.location(v, here, depth+1)
	case "description", "title", "$comment":
		s, ok := v.(string)
		if !ok {
			c.refuse(codeValue, here, "%s is a string", key)
			return
		}
		c.text(s, here, maxSchemaString, codeStringSize)
	case "examples":
		if _, ok := v.([]any); !ok {
			c.refuse(codeValue, here, "examples is an array")
			return
		}
		c.data(v, here)
	case "default":
		c.data(v, here)
	case "deprecated", "readOnly", "writeOnly":
		if _, ok := v.(bool); !ok {
			c.refuse(codeValue, here, "%s is a boolean", key)
		}
	case "$schema":
		if depth != 1 {
			c.refuse(codeKeyword, here, "$schema is for the root only")
			return
		}
		if s, ok := v.(string); !ok || (s != dialect2020 && s != dialect07) {
			c.refuse(codeValue, here, "$schema is %s or %s", dialect2020, dialect07)
		}
	default:
		// format, pattern, every reference and identifier keyword, and
		// every keyword this grammar does not name.
		c.refuse(codeKeyword, here, "not a keyword of schema grammar 1")
	}
}

// typeValue judges type: at the root exactly "object", elsewhere one type
// name or a non-empty array of distinct ones.
func (c *schemaCheck) typeValue(v any, at string, root bool) {
	if root {
		if s, ok := v.(string); !ok || s != "object" {
			c.refuse(codeValue, at, `the root's type is exactly "object"`)
		}
		return
	}
	switch x := v.(type) {
	case string:
		if !schemaTypes[x] {
			c.refuse(codeValue, at, "type names one of null, boolean, object, array, number, string and integer")
		}
	case []any:
		if len(x) == 0 {
			c.refuse(codeValue, at, "type is a type name or a non-empty array of distinct ones")
			return
		}
		seen := map[string]bool{}
		for i, item := range x {
			s, ok := item.(string)
			if !ok || !schemaTypes[s] || seen[s] {
				c.refuse(codeValue, index(at, i), "type is a type name or a non-empty array of distinct ones")
				return
			}
			seen[s] = true
		}
	default:
		c.refuse(codeValue, at, "type is a type name or a non-empty array of distinct ones")
	}
}

// distinctScalars judges enum's members: each a scalar, no two equal as
// JSON values are -- numbers by their exact value, so 1 and 1.0 are one
// value -- each within the bounds of what it is.
func (c *schemaCheck) distinctScalars(list []any, at string) {
	seen := map[string]bool{}
	for i, item := range list {
		here := index(at, i)
		var key string
		switch x := item.(type) {
		case string:
			c.text(x, here, maxSchemaString, codeStringSize)
			key = "s" + x
		case json.Number:
			// Judged as written first, so the value is only ever
			// computed for a number within the written bounds.
			if c.number(x, here); c.fail != nil {
				return
			}
			r, ok := new(big.Rat).SetString(string(x))
			if !ok {
				c.refuse(codeValue, here, "enum holds scalars")
				return
			}
			key = "n" + r.RatString()
		case bool:
			key = fmt.Sprint("b", x)
		case nil:
			key = "z"
		default:
			c.refuse(codeValue, here, "enum holds scalars")
			return
		}
		if c.fail != nil {
			return
		}
		if seen[key] {
			c.refuse(codeValue, here, "enum holds a value twice")
			return
		}
		seen[key] = true
	}
}

// data judges a value that is data, not schema -- a default, an example,
// a constant -- to the bounds every string and number in a schema meets.
// A member name inside data is a string like any other.
func (c *schemaCheck) data(v any, at string) {
	if c.fail != nil {
		return
	}
	switch x := v.(type) {
	case string:
		c.text(x, at, maxSchemaString, codeStringSize)
	case json.Number:
		c.number(x, at)
	case []any:
		for i, item := range x {
			c.data(item, index(at, i))
		}
	case map[string]any:
		for _, k := range sortedKeys(x) {
			member := at + "/" + pointerToken(k)
			c.text(k, member, maxSchemaString, codeStringSize)
			c.data(x[k], member)
		}
	}
}

// text judges a string to its bound, in bytes, and to display policy 1.
func (c *schemaCheck) text(s, at string, limit int, code string) {
	if c.fail != nil {
		return
	}
	if len(s) > limit {
		c.refuse(code, at, "a string of %d bytes, over %d", len(s), limit)
		return
	}
	if r, refused := displayRefusal(s); refused {
		c.refuse(codePolicy, at, "holds U+%04X, which display policy 1 refuses", r)
	}
}

// number judges a number as written: at most 32 characters, an exponent,
// if any, within ±308.
func (c *schemaCheck) number(n json.Number, at string) {
	if c.fail != nil {
		return
	}
	if detail := numberRefusal(string(n)); detail != "" {
		c.refuse(codeNumber, at, "%s", detail)
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

func index(at string, i int) string { return fmt.Sprintf("%s/%d", at, i) }

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
