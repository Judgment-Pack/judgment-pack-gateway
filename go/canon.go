package main

// Canonicalization for receipt version 2.
//
// The canonical form is derived from SPEC.md and corpus/canon.json:
//
//   - object members are emitted in ascending order of their member name's
//     Unicode CODE POINT sequence (not UTF-16 code unit order);
//   - array order is preserved;
//   - strings are emitted as raw UTF-8 (no \u escaping of non-ASCII, no HTML
//     escaping of < > &, no escaping of /), with the standard short escapes
//     and \u00xx for the remaining C0 controls;
//   - numbers are integers only, restricted to the IEEE-754 "safe integer"
//     range; any float literal (including 1.0 and 1e2) is refused;
//   - a value carrying a lone surrogate is refused, since it cannot be encoded
//     as UTF-8.
//
// Because the domain checks have to see the *literal* (integer 1 vs float 1.0)
// and have to notice a lone surrogate before it is silently replaced with
// U+FFFD, this file parses JSON text itself rather than going through
// encoding/json.

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// The safe-integer bounds, inclusive. corpus/canon.json pins both ends.
const (
	maxSafeInteger = int64(9007199254740991)
	minSafeInteger = int64(-9007199254740991)
)

type value interface{ canonWrite(*strings.Builder) }

type vObject struct {
	names  []string // insertion order, kept only for diagnostics
	byName map[string]value
}

type vArray []value

type vString string

type vInt int64

type vBool bool

type vNull struct{}

func newObject() *vObject {
	return &vObject{byName: map[string]value{}}
}

func (o *vObject) set(name string, v value) {
	if _, seen := o.byName[name]; !seen {
		o.names = append(o.names, name)
	}
	o.byName[name] = v
}

func (o *vObject) get(name string) (value, bool) {
	v, ok := o.byName[name]
	return v, ok
}

// canonWrite emits the canonical bytes of each kind of value.

func (o *vObject) canonWrite(sb *strings.Builder) {
	names := make([]string, 0, len(o.byName))
	for n := range o.byName {
		names = append(names, n)
	}
	// Go strings hold UTF-8 and sort.Strings compares bytes, so this is
	// ascending code point order -- which is what this format wants, and what
	// a UTF-16-ordered canonicalizer (RFC 8785) would get wrong outside the BMP.
	sort.Strings(names)
	sb.WriteByte('{')
	for i, n := range names {
		if i > 0 {
			sb.WriteByte(',')
		}
		writeCanonicalString(sb, n)
		sb.WriteByte(':')
		o.byName[n].canonWrite(sb)
	}
	sb.WriteByte('}')
}

func (a vArray) canonWrite(sb *strings.Builder) {
	sb.WriteByte('[')
	for i, item := range a {
		if i > 0 {
			sb.WriteByte(',')
		}
		item.canonWrite(sb)
	}
	sb.WriteByte(']')
}

func (s vString) canonWrite(sb *strings.Builder) { writeCanonicalString(sb, string(s)) }

func (n vInt) canonWrite(sb *strings.Builder) { sb.WriteString(strconv.FormatInt(int64(n), 10)) }

func (b vBool) canonWrite(sb *strings.Builder) {
	if b {
		sb.WriteString("true")
	} else {
		sb.WriteString("false")
	}
}

func (vNull) canonWrite(sb *strings.Builder) { sb.WriteString("null") }

func writeCanonicalString(sb *strings.Builder, s string) {
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\b':
			sb.WriteString(`\b`)
		case '\f':
			sb.WriteString(`\f`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(sb, `\u%04x`, r)
			} else {
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
}

// canon returns the canonical bytes of an already-parsed value.
func canon(v value) []byte {
	var sb strings.Builder
	v.canonWrite(&sb)
	return []byte(sb.String())
}

// canonText parses JSON text and returns its canonical bytes, refusing
// anything outside the canonical domain.
func canonText(text []byte) ([]byte, error) {
	v, err := parseJSON(text)
	if err != nil {
		return nil, err
	}
	return canon(v), nil
}

// --- parser ---------------------------------------------------------------

type parser struct {
	data []byte
	pos  int
}

func parseJSON(data []byte) (value, error) {
	p := &parser{data: data}
	p.skipWhitespace()
	v, err := p.parseValue()
	if err != nil {
		return nil, err
	}
	p.skipWhitespace()
	if p.pos != len(p.data) {
		return nil, fmt.Errorf("trailing content at byte %d", p.pos)
	}
	return v, nil
}

func (p *parser) skipWhitespace() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) parseValue() (value, error) {
	if p.pos >= len(p.data) {
		return nil, errors.New("unexpected end of input")
	}
	switch c := p.data[p.pos]; {
	case c == '{':
		return p.parseObject()
	case c == '[':
		return p.parseArray()
	case c == '"':
		s, err := p.parseString()
		if err != nil {
			return nil, err
		}
		return vString(s), nil
	case c == 't':
		return vBool(true), p.expectLiteral("true")
	case c == 'f':
		return vBool(false), p.expectLiteral("false")
	case c == 'n':
		return vNull{}, p.expectLiteral("null")
	case c == '-' || (c >= '0' && c <= '9'):
		return p.parseNumber()
	default:
		return nil, fmt.Errorf("unexpected byte %q at %d", c, p.pos)
	}
}

func (p *parser) expectLiteral(lit string) error {
	if p.pos+len(lit) > len(p.data) || string(p.data[p.pos:p.pos+len(lit)]) != lit {
		return fmt.Errorf("expected %q at %d", lit, p.pos)
	}
	p.pos += len(lit)
	return nil
}

func (p *parser) parseObject() (value, error) {
	p.pos++ // '{'
	obj := newObject()
	p.skipWhitespace()
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		return obj, nil
	}
	for {
		p.skipWhitespace()
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return nil, fmt.Errorf("expected member name at %d", p.pos)
		}
		name, err := p.parseString()
		if err != nil {
			return nil, err
		}
		if _, dup := obj.get(name); dup {
			// SPEC.md does not say; see AMBIGUITIES.md. A signed format cannot
			// afford two readers disagreeing about which value is meant.
			return nil, fmt.Errorf("duplicate member name %q", name)
		}
		p.skipWhitespace()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return nil, fmt.Errorf("expected ':' at %d", p.pos)
		}
		p.pos++
		p.skipWhitespace()
		v, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		obj.set(name, v)
		p.skipWhitespace()
		if p.pos >= len(p.data) {
			return nil, errors.New("unterminated object")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return obj, nil
		default:
			return nil, fmt.Errorf("expected ',' or '}' at %d", p.pos)
		}
	}
}

func (p *parser) parseArray() (value, error) {
	p.pos++ // '['
	arr := vArray{}
	p.skipWhitespace()
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		return arr, nil
	}
	for {
		p.skipWhitespace()
		v, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		arr = append(arr, v)
		p.skipWhitespace()
		if p.pos >= len(p.data) {
			return nil, errors.New("unterminated array")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return arr, nil
		default:
			return nil, fmt.Errorf("expected ',' or ']' at %d", p.pos)
		}
	}
}

func (p *parser) parseString() (string, error) {
	p.pos++ // '"'
	var sb strings.Builder
	for {
		if p.pos >= len(p.data) {
			return "", errors.New("unterminated string")
		}
		c := p.data[p.pos]
		switch {
		case c == '"':
			p.pos++
			return sb.String(), nil
		case c == '\\':
			p.pos++
			if p.pos >= len(p.data) {
				return "", errors.New("unterminated escape")
			}
			e := p.data[p.pos]
			p.pos++
			switch e {
			case '"':
				sb.WriteByte('"')
			case '\\':
				sb.WriteByte('\\')
			case '/':
				sb.WriteByte('/')
			case 'b':
				sb.WriteByte('\b')
			case 'f':
				sb.WriteByte('\f')
			case 'n':
				sb.WriteByte('\n')
			case 'r':
				sb.WriteByte('\r')
			case 't':
				sb.WriteByte('\t')
			case 'u':
				r, err := p.parseUnicodeEscape()
				if err != nil {
					return "", err
				}
				sb.WriteRune(r)
			default:
				return "", fmt.Errorf("invalid escape \\%c", e)
			}
		case c < 0x20:
			return "", fmt.Errorf("unescaped control character %#02x in string", c)
		case c < 0x80:
			sb.WriteByte(c)
			p.pos++
		default:
			r, size := utf8.DecodeRune(p.data[p.pos:])
			if r == utf8.RuneError && size <= 1 {
				return "", errors.New("invalid UTF-8 in string")
			}
			sb.Write(p.data[p.pos : p.pos+size])
			p.pos += size
		}
	}
}

// parseUnicodeEscape consumes the four hex digits of a \u escape (the "\u"
// itself is already consumed) and, if it is a high surrogate, the \uXXXX low
// surrogate that must follow. A surrogate that is not part of a valid pair is
// refused: it has no UTF-8 encoding, so it cannot appear in canonical bytes.
func (p *parser) parseUnicodeEscape() (rune, error) {
	u1, err := p.readHex4()
	if err != nil {
		return 0, err
	}
	if !utf16.IsSurrogate(rune(u1)) {
		return rune(u1), nil
	}
	if p.pos+1 < len(p.data) && p.data[p.pos] == '\\' && p.data[p.pos+1] == 'u' {
		save := p.pos
		p.pos += 2
		u2, err := p.readHex4()
		if err != nil {
			return 0, err
		}
		if r := utf16.DecodeRune(rune(u1), rune(u2)); r != utf8.RuneError {
			return r, nil
		}
		p.pos = save
	}
	return 0, fmt.Errorf("lone surrogate \\u%04x is not encodable", u1)
}

func (p *parser) readHex4() (uint16, error) {
	if p.pos+4 > len(p.data) {
		return 0, errors.New("truncated \\u escape")
	}
	var n uint16
	for i := 0; i < 4; i++ {
		c := p.data[p.pos+i]
		var d uint16
		switch {
		case c >= '0' && c <= '9':
			d = uint16(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint16(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint16(c-'A') + 10
		default:
			return 0, fmt.Errorf("invalid hex digit %q in \\u escape", c)
		}
		n = n<<4 | d
	}
	p.pos += 4
	return n, nil
}

func (p *parser) parseNumber() (value, error) {
	start := p.pos
	if p.pos < len(p.data) && p.data[p.pos] == '-' {
		p.pos++
	}
	digitsStart := p.pos
	for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
		p.pos++
	}
	if p.pos == digitsStart {
		return nil, fmt.Errorf("expected digits at %d", digitsStart)
	}
	// JSON forbids leading zeros.
	if p.data[digitsStart] == '0' && p.pos-digitsStart > 1 {
		return nil, fmt.Errorf("leading zero in number at %d", digitsStart)
	}
	// A fraction or an exponent makes this a float literal, which is outside
	// the canonical domain even when its value happens to be integral.
	if p.pos < len(p.data) {
		switch p.data[p.pos] {
		case '.':
			return nil, errors.New("non-integer number is outside the canonical domain")
		case 'e', 'E':
			return nil, errors.New("exponent notation is outside the canonical domain")
		}
	}
	lit := string(p.data[start:p.pos])
	n, err := strconv.ParseInt(lit, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("integer %s is outside the canonical domain", lit)
	}
	if n > maxSafeInteger || n < minSafeInteger {
		return nil, fmt.Errorf("integer %s is outside the safe-integer range", lit)
	}
	return vInt(n), nil
}
