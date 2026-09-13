// Package canon renders JSON in the form SPEC.md §1.1 states and carries a
// connector's records into that domain, answering to corpus/canon.json
// without importing the core module.
package canon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// NumberPolicy says what Canonicalize does with a number the canon domain of
// SPEC.md §1.1 does not admit -- one with a fraction or an exponent, or an
// integer past ±(2^53-1).
type NumberPolicy int

const (
	// RefuseNumbers refuses such a number, as the gateway's own parser does.
	RefuseNumbers NumberPolicy = iota
	// CarryNumbersAsText carries it as a JSON string holding its literal
	// exactly as the connector wrote it: lossless, deterministic, and
	// visibly a string to whoever derives from the record.
	CarryNumbersAsText
)

var integerLiteral = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

const maxInteger = 1<<53 - 1

// Canonicalize renders one JSON document in the form SPEC.md §1.1 states --
// member names sorted by code point, no insignificant whitespace, strings
// with the short escapes, lowercase \u00xx for the other control characters
// and everything else raw, integers as written -- refusing duplicate member
// names, invalid UTF-8 and unpaired surrogate escapes. It is what makes a
// schema digest reproducible by an implementation that never linked this
// code, and what carries a connector's records into the domain the gateway
// attests. The core module has its own canonicalizer; this one answers to
// the same frozen vectors (corpus/canon.json) without importing it.
func Canonicalize(raw []byte, numbers NumberPolicy) ([]byte, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("not valid UTF-8")
	}
	if err := checkSurrogateEscapes(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out bytes.Buffer
	if err := writeCanonical(dec, &out, numbers); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing content after the document")
	}
	return out.Bytes(), nil
}

func writeCanonical(dec *json.Decoder, out *bytes.Buffer, numbers NumberPolicy) error {
	tok, err := dec.Token()
	if err != nil {
		if err == io.EOF {
			return errors.New("unexpected end of input")
		}
		return err
	}
	switch v := tok.(type) {
	case json.Delim:
		switch v {
		case '{':
			type member struct {
				name  string
				value []byte
			}
			var members []member
			seen := map[string]bool{}
			for dec.More() {
				nameTok, err := dec.Token()
				if err != nil {
					return err
				}
				name, ok := nameTok.(string)
				if !ok {
					return errors.New("member name is not a string")
				}
				if seen[name] {
					return fmt.Errorf("duplicate member name %q", name)
				}
				seen[name] = true
				var value bytes.Buffer
				if err := writeCanonical(dec, &value, numbers); err != nil {
					return err
				}
				members = append(members, member{name, value.Bytes()})
			}
			if _, err := dec.Token(); err != nil { // the closing brace
				return err
			}
			sort.Slice(members, func(i, j int) bool { return members[i].name < members[j].name })
			out.WriteByte('{')
			for i, m := range members {
				if i > 0 {
					out.WriteByte(',')
				}
				writeString(out, m.name)
				out.WriteByte(':')
				out.Write(m.value)
			}
			out.WriteByte('}')
		case '[':
			out.WriteByte('[')
			first := true
			for dec.More() {
				if !first {
					out.WriteByte(',')
				}
				first = false
				if err := writeCanonical(dec, out, numbers); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil { // the closing bracket
				return err
			}
			out.WriteByte(']')
		default:
			return fmt.Errorf("unexpected delimiter %q", v)
		}
	case string:
		writeString(out, v)
	case json.Number:
		literal := v.String()
		var n int64
		inDomain := integerLiteral.MatchString(literal)
		if inDomain {
			var err error
			n, err = strconv.ParseInt(literal, 10, 64)
			inDomain = err == nil && n <= maxInteger && n >= -maxInteger
		}
		switch {
		case inDomain:
			// Emitted from the parsed value, so -0 is 0 (§1.1).
			out.WriteString(strconv.FormatInt(n, 10))
		case numbers == CarryNumbersAsText:
			writeString(out, literal)
		default:
			return fmt.Errorf("number %s is outside the canon domain", literal)
		}
	case bool:
		if v {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case nil:
		out.WriteString("null")
	default:
		return fmt.Errorf("unexpected token %v", tok)
	}
	return nil
}

// writeString escapes per SPEC.md §1.1: the quote, the backslash, the short
// escapes for backspace, formfeed, newline, carriage return and tab,
// \u00xx in lowercase for every other control character, and everything
// else -- including the solidus, DEL, U+2028 and U+2029 and every non-ASCII
// code point -- raw.
func writeString(out *bytes.Buffer, s string) {
	out.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(out, `\u%04x`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
}

// checkSurrogateEscapes refuses a \u escape of a surrogate that is not one
// half of a properly ordered pair, which encoding/json would otherwise turn
// into U+FFFD without a word.
func checkSurrogateEscapes(raw []byte) error {
	inString := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if !inString {
			if c == '"' {
				inString = true
			}
			continue
		}
		switch c {
		case '"':
			inString = false
		case '\\':
			if i+1 >= len(raw) {
				return errors.New("unterminated escape")
			}
			if raw[i+1] != 'u' {
				i++
				continue
			}
			high, ok := hexRune(raw, i+2)
			if !ok {
				return errors.New("malformed \\u escape")
			}
			switch {
			case high >= 0xD800 && high <= 0xDBFF:
				low, ok := hexRune(raw, i+8)
				if !ok || i+6 >= len(raw) || raw[i+6] != '\\' || raw[i+7] != 'u' || low < 0xDC00 || low > 0xDFFF {
					return errors.New("unpaired high surrogate escape")
				}
				i += 11
			case high >= 0xDC00 && high <= 0xDFFF:
				return errors.New("unpaired low surrogate escape")
			default:
				i += 5
			}
		}
	}
	return nil
}

func hexRune(raw []byte, at int) (rune, bool) {
	if at+4 > len(raw) {
		return 0, false
	}
	n, err := strconv.ParseUint(string(raw[at:at+4]), 16, 32)
	if err != nil {
		return 0, false
	}
	return rune(n), true
}

// Compact removes insignificant whitespace and nothing else: the form a
// state bookmark is carried in, exactly as the connector emitted it, so it
// can be handed back.
func Compact(raw []byte) ([]byte, error) {
	var out bytes.Buffer
	if err := json.Compact(&out, raw); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// IsDigestString reports whether s is "sha256:" and 64 lowercase hex.
func IsDigestString(s string) bool {
	h, ok := strings.CutPrefix(s, "sha256:")
	if !ok || len(h) != 64 {
		return false
	}
	for _, c := range h {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ObjectMembers reports whether raw is a JSON object, and how many members
// it has: structurally, so {} and { } are the same empty object.
func ObjectMembers(raw json.RawMessage) (int, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return 0, false
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(trimmed, &members) != nil {
		return 0, false
	}
	return len(members), true
}

// IsObject reports whether raw is a JSON object, empty or not.
func IsObject(raw json.RawMessage) bool {
	_, ok := ObjectMembers(raw)
	return ok
}

// EncodeJSON marshals without HTML escaping and without a trailing newline:
// ordinary JSON for an envelope or a statement, which the gateway
// canonicalizes itself.
func EncodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
