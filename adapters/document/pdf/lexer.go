// Package pdf reads the text of a PDF document with the standard library
// and nothing else, under bounds the caller states: the cross-reference
// table or stream, object streams, the Flate, LZW, ASCII and run-length
// filters, the standard security handler opened with an empty user
// password, simple and composite fonts mapped to Unicode through their
// encodings and ToUnicode maps, and the text operators of each page's
// content, in stream order. It renders nothing, decodes no image, and
// stops at the first bound it meets, saying which.
//
// It is written for hostile input: every loop is bounded by a count or by
// the bytes of the file, recursion by a depth, inflation by a budget, and
// a document that departs from the structure it expects is refused with a
// reason rather than read as something it is not.
package pdf

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
)

// The object model. A PDF value is one of: nil (the null object), bool,
// int64, float64, Name, String, Array, Dict, *stream, or ref. Numbers past
// int64 are refused where they are read.
type (
	// Name is a name object, without its leading slash and with #xx
	// escapes resolved.
	Name string
	// String is a string object's bytes, escapes resolved and hex decoded;
	// decrypted when the document is encrypted.
	String []byte
	// Array is an array object.
	Array []object
	// Dict is a dictionary object.
	Dict map[Name]object
	// ref is an indirect reference.
	ref struct{ num, gen int }
	// object is any of the above.
	object any
)

// stream is a stream object: its dictionary and its raw bytes as they lie
// in the file, before any filter and before decryption.
type stream struct {
	dict Dict
	raw  []byte
	// num and gen identify the object the stream was read as, for the
	// per-object key of the standard security handler.
	num, gen int
}

const (
	// maxNameBytes bounds a name token; the specification's limit is 127.
	maxNameBytes = 1 << 12
	// maxStringBytes bounds a string token: a literal or hex string past it
	// is not one this reader carries.
	maxStringBytes = 1 << 24
	// maxNumberBytes bounds a numeric token.
	maxNumberBytes = 64
	// maxNesting bounds arrays and dictionaries nested in one another.
	maxNesting = 256
	// maxContainerItems bounds one array's elements and one dictionary's
	// members.
	maxContainerItems = 1 << 20
)

// tokenKind says what a lexer token is.
type tokenKind int

const (
	tokEOF tokenKind = iota
	tokInteger
	tokReal
	tokName
	tokString
	tokArrayOpen
	tokArrayClose
	tokDictOpen
	tokDictClose
	tokBraceOpen
	tokBraceClose
	tokKeyword
)

type token struct {
	kind tokenKind
	// pos is the offset of the token's first byte; end is one past its last.
	pos, end int
	i        int64
	f        float64
	name     Name
	str      []byte
	keyword  string
}

// lexer tokenizes a byte slice. It never allocates beyond the token it
// returns, and every scan is bounded by the slice.
type lexer struct {
	data []byte
	pos  int
	// allow is what the parse this lexer serves may spend, where it serves
	// one: the bytes it advances over are charged to it, so that a file whose
	// objects each read the rest of it -- a comment with no line end after
	// every object is one -- spends the allowance instead of being read once
	// for every object. It is nil for a lexer with none, where the slice it
	// reads bounds what it can advance over.
	allow *allowance
	// charged is how far the bytes advanced over have been charged. It only
	// rises, so a parser that goes back over what it has read does not pay for
	// it twice, and each byte of the slice costs this lexer one charge.
	charged int
	// reserved is what the token being built has been charged for the room it
	// holds, so that growing it charges what the growth costs and no more.
	reserved int64
	// spent is set when a charge did not fit. Every token after it is an
	// error, so a parse whose reading has run out of allowance ends where it
	// is rather than reading on and counting: a lookahead that threw its
	// error away would otherwise go on reading at no cost.
	spent bool
}

func newLexer(data []byte, pos int) *lexer { return &lexer{data: data, pos: pos, charged: pos} }

// within gives the lexer the allowance the parse spends, and returns it.
func (l *lexer) within(a *allowance) *lexer {
	l.allow = a
	return l
}

// advanced charges the bytes read since the last charge. What a value costs
// to hold is charged apart from this, by the parser that builds it: the two
// are different costs of the same object -- the file it was read from and the
// memory it takes -- and a file that is read without being held, as a comment
// or a candidate given up on is, is charged only here.
//
// It is called where a token begins, where a comment ends and where a string
// ends, rather than on the way out of every call: a short token is bounded
// by the bound on its kind, so charging it at the next token costs nothing
// that matters, while a comment runs to the end of a line that may be the
// end of the file, and a string with no end runs to the end of the data, and
// each is charged where it ends. A string is charged there rather than at
// the next token because the parser reads one ahead and steps back: an
// unterminated string read as the token after a value would otherwise be
// stepped back over before any call saw how far it went, and the rest of
// the data would be read once for every value in it and charged for none.
func (l *lexer) advanced() {
	if l.pos > l.charged {
		if !l.allow.take(int64(l.pos - l.charged)) {
			l.spent = true
		}
		l.charged = l.pos
	}
}

// reserve charges the room a token being built has grown to, and reports
// whether the allowance had it. The bytes are charged as the room is taken,
// so a token past what is left is never allocated whole and then refused.
func (l *lexer) reserve(capacity int) bool {
	want := goSizeClass(int64(capacity))
	if want <= l.reserved {
		return true
	}
	if !l.allow.take(want - l.reserved) {
		l.spent = true
		l.reserved = 0
		return false
	}
	l.reserved = want
	return true
}

// errRead is the error every token is once the allowance for reading is
// spent.
func (l *lexer) errRead() error { return l.allow.exhausted() }

// stringToken is a string token read from start to the lexer's position,
// its bytes charged where it ends.
func (l *lexer) stringToken(start int, out []byte) token {
	l.advanced()
	l.reserved = 0
	return token{kind: tokString, pos: start, end: l.pos, str: out}
}

func isWhitespace(c byte) bool {
	return c == 0 || c == '\t' || c == '\n' || c == '\f' || c == '\r' || c == ' '
}

func isDelimiter(c byte) bool {
	switch c {
	case '(', ')', '<', '>', '[', ']', '{', '}', '/', '%':
		return true
	}
	return false
}

func isRegular(c byte) bool { return !isWhitespace(c) && !isDelimiter(c) }

// skipSpace skips whitespace and comments. A comment runs to the end of its
// line, which may be the end of the data: what it passes over is charged, as
// every other advance is.
func (l *lexer) skipSpace() {
	l.advanced()
	for l.pos < len(l.data) {
		c := l.data[l.pos]
		if isWhitespace(c) {
			l.pos++
			continue
		}
		if c == '%' {
			for l.pos < len(l.data) && l.data[l.pos] != '\n' && l.data[l.pos] != '\r' {
				l.pos++
			}
			l.advanced()
			continue
		}
		break
	}
	// What was skipped is charged here and not at the next reading of a
	// token: whitespace at the end of the data may be all that is left, and
	// nothing after it would charge it.
	l.advanced()
}

// errStructureBound is the class of every error that says the document has a
// structure past a bound the reader holds -- a token, a nesting, a container,
// a cross-reference chain, an object count -- rather than a structure it could
// not make sense of. Damage may be read past; a bound is not.
var errStructureBound = errors.New("a structure past a bound the reader holds")

// structureBound is a structure past a bound, in the words given.
func structureBound(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errStructureBound, fmt.Sprintf(format, args...))
}

// errLexer is the class of every error the lexer returns: a token past the
// bound on its kind, and so a structure bound. The end of the data is not an
// error; it is a tokEOF token.
var errLexer = fmt.Errorf("%w: lexical error", errStructureBound)

// next reads one token. A byte that begins no token -- a ')' outside a
// string, a '>' that is not half of ">>" -- is an error in the syntax, and
// is skipped so a damaged file still yields its objects. Skipping is this
// loop, never a call per byte skipped, so a run of such bytes takes no more
// stack than one does.
//
// Every token reader is reached through here, and the charge on the way out
// covers every way out of them: this call's error exits and the readers'
// own -- a string past the bound on its kind is read before it is refused,
// and a reader that refused one without charging would let a file be read
// again for every object that asks. A token read once the allowance is spent
// is an error rather than a token, so a parse that has run out of it ends
// where it stands, a lookahead that would throw the error away included.
func (l *lexer) next() (token, error) {
	defer l.advanced()
	if l.spent {
		return token{}, l.errRead()
	}
	for {
		l.skipSpace()
		if l.pos >= len(l.data) {
			return token{kind: tokEOF, pos: l.pos, end: l.pos}, nil
		}
		start := l.pos
		c := l.data[l.pos]
		switch {
		case c == '[':
			l.pos++
			return token{kind: tokArrayOpen, pos: start, end: l.pos}, nil
		case c == ']':
			l.pos++
			return token{kind: tokArrayClose, pos: start, end: l.pos}, nil
		case c == '{':
			l.pos++
			return token{kind: tokBraceOpen, pos: start, end: l.pos}, nil
		case c == '}':
			l.pos++
			return token{kind: tokBraceClose, pos: start, end: l.pos}, nil
		case c == '<':
			if l.pos+1 < len(l.data) && l.data[l.pos+1] == '<' {
				l.pos += 2
				return token{kind: tokDictOpen, pos: start, end: l.pos}, nil
			}
			return l.hexString()
		case c == '>':
			if l.pos+1 < len(l.data) && l.data[l.pos+1] == '>' {
				l.pos += 2
				return token{kind: tokDictClose, pos: start, end: l.pos}, nil
			}
			l.pos++
			continue
		case c == ')':
			l.pos++
			continue
		case c == '(':
			return l.literalString()
		case c == '/':
			return l.name()
		case c == '+' || c == '-' || c == '.' || (c >= '0' && c <= '9'):
			return l.number()
		}
		// A keyword: regular characters up to a delimiter or whitespace.
		end := l.pos
		for end < len(l.data) && isRegular(l.data[end]) && end-start < maxNameBytes {
			end++
		}
		if end == start {
			// A delimiter this switch does not name cannot happen; a regular
			// character always advances. Guard against a stall anyway.
			l.pos++
			continue
		}
		l.pos = end
		return token{kind: tokKeyword, pos: start, end: end, keyword: string(l.data[start:end])}, nil
	}
}

func (l *lexer) number() (token, error) {
	start := l.pos
	end := start
	for end < len(l.data) && (l.data[end] >= '0' && l.data[end] <= '9' || l.data[end] == '+' || l.data[end] == '-' || l.data[end] == '.' || l.data[end] == 'e' || l.data[end] == 'E') {
		end++
		if end-start > maxNumberBytes {
			return token{}, fmt.Errorf("%w: number token past %d bytes", errLexer, maxNumberBytes)
		}
	}
	l.pos = end
	text := l.data[start:end]
	// PDF numbers carry no exponent; a token with one is read as a real
	// where strconv admits it and refused otherwise, since such files
	// exist and a width or a matrix entry is all it will ever be.
	if bytes.IndexAny(text, ".eE") < 0 {
		// An integer is an optional sign and digits, and an integer token is
		// only such a literal within the int64 range: one past the range is
		// a real of its magnitude.
		if integerLiteral(text) {
			if i, err := strconv.ParseInt(string(text), 10, 64); err == nil {
				return token{kind: tokInteger, pos: start, end: end, i: i}, nil
			}
			f, _ := strconv.ParseFloat(string(text), 64)
			return token{kind: tokReal, pos: start, end: end, f: f}, nil
		}
		// "--5" and the like appear in damaged files. They are reals of the
		// value they have always been read as -- 0 where the signs do not
		// reduce to one -- and never an integer the document did not write.
		i, err := strconv.ParseInt(trimPlus(string(text)), 10, 64)
		if err != nil {
			i = 0
		}
		return token{kind: tokReal, pos: start, end: end, f: float64(i)}, nil
	}
	f, err := strconv.ParseFloat(normalizeReal(string(text)), 64)
	if err != nil {
		f = 0
	}
	return token{kind: tokReal, pos: start, end: end, f: f}, nil
}

// integerLiteral reports whether text is an optional sign and one or more
// decimal digits.
func integerLiteral(text []byte) bool {
	if len(text) > 0 && (text[0] == '+' || text[0] == '-') {
		text = text[1:]
	}
	if len(text) == 0 {
		return false
	}
	for _, c := range text {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func trimPlus(s string) string {
	for len(s) > 0 && s[0] == '+' {
		s = s[1:]
	}
	return s
}

// normalizeReal makes the forms PDF writers produce ("-.5", "4.", "--3.2")
// acceptable to strconv.
func normalizeReal(s string) string {
	neg := false
	for len(s) > 0 && (s[0] == '-' || s[0] == '+') {
		if s[0] == '-' {
			neg = !neg
		}
		s = s[1:]
	}
	if s == "" || s == "." {
		s = "0"
	}
	if s[0] == '.' {
		s = "0" + s
	}
	if s[len(s)-1] == '.' {
		s += "0"
	}
	if neg {
		s = "-" + s
	}
	return s
}

func (l *lexer) name() (token, error) {
	start := l.pos
	l.pos++ // the slash
	var out []byte
	for l.pos < len(l.data) && isRegular(l.data[l.pos]) {
		c := l.data[l.pos]
		if c == '#' && l.pos+2 < len(l.data) {
			if v, ok := hexPair(l.data[l.pos+1], l.data[l.pos+2]); ok {
				c = v
				l.pos += 2
			}
		}
		out = append(out, c)
		l.pos++
		if len(out) > maxNameBytes {
			return token{}, fmt.Errorf("%w: name past %d bytes", errLexer, maxNameBytes)
		}
	}
	return token{kind: tokName, pos: start, end: l.pos, name: Name(out)}, nil
}

func hexPair(a, b byte) (byte, bool) {
	x, okx := hexValue(a)
	y, oky := hexValue(b)
	if !okx || !oky {
		return 0, false
	}
	return x<<4 | y, true
}

func hexValue(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func (l *lexer) hexString() (token, error) {
	start := l.pos
	l.pos++ // '<'
	var out []byte
	var pending byte
	half := false
	for l.pos < len(l.data) {
		c := l.data[l.pos]
		l.pos++
		if c == '>' {
			if half {
				out = append(out, pending<<4)
			}
			return l.stringToken(start, out), nil
		}
		if isWhitespace(c) {
			continue
		}
		v, ok := hexValue(c)
		if !ok {
			// A stray character in a hex string is skipped, as viewers do.
			continue
		}
		if half {
			out = append(out, pending<<4|v)
			half = false
		} else {
			pending, half = v, true
		}
		if !l.reserve(cap(out)) {
			return token{}, l.errRead()
		}
		if len(out) > maxStringBytes {
			return token{}, fmt.Errorf("%w: string past %d bytes", errLexer, maxStringBytes)
		}
	}
	// Unterminated: what was read is the string.
	if half {
		out = append(out, pending<<4)
	}
	return l.stringToken(start, out), nil
}

func (l *lexer) literalString() (token, error) {
	start := l.pos
	l.pos++ // '('
	depth := 1
	var out []byte
	for l.pos < len(l.data) {
		c := l.data[l.pos]
		l.pos++
		switch c {
		case '\\':
			if l.pos >= len(l.data) {
				break
			}
			e := l.data[l.pos]
			l.pos++
			switch e {
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case '(', ')', '\\':
				out = append(out, e)
			case '\r':
				// Line continuation: \ followed by CR or CRLF.
				if l.pos < len(l.data) && l.data[l.pos] == '\n' {
					l.pos++
				}
			case '\n':
			default:
				if e >= '0' && e <= '7' {
					v := int(e - '0')
					for i := 0; i < 2 && l.pos < len(l.data) && l.data[l.pos] >= '0' && l.data[l.pos] <= '7'; i++ {
						v = v*8 + int(l.data[l.pos]-'0')
						l.pos++
					}
					out = append(out, byte(v))
				} else {
					out = append(out, e)
				}
			}
		case '(':
			depth++
			out = append(out, c)
		case ')':
			depth--
			if depth == 0 {
				return l.stringToken(start, out), nil
			}
			out = append(out, c)
		case '\r':
			// An end-of-line in a literal is one LF, whatever form it took.
			if l.pos < len(l.data) && l.data[l.pos] == '\n' {
				l.pos++
			}
			out = append(out, '\n')
		default:
			out = append(out, c)
		}
		if !l.reserve(cap(out)) {
			return token{}, l.errRead()
		}
		if len(out) > maxStringBytes {
			return token{}, fmt.Errorf("%w: string past %d bytes", errLexer, maxStringBytes)
		}
	}
	return l.stringToken(start, out), nil
}

// peekKeyword reports whether the next token is the keyword given,
// without consuming anything.
func (l *lexer) peekKeyword(kw string) bool {
	save := l.pos
	t, err := l.next()
	l.pos = save
	return err == nil && t.kind == tokKeyword && t.keyword == kw
}

// parser turns tokens into objects.
type parser struct {
	lex *lexer
	// contentMode is set for content streams, where "R" is not a reference
	// and operators are keywords the caller reads.
	contentMode bool
	// allow is what the values this parser builds may cost to hold. It is
	// spent as they are built, element by element and member by member, so
	// that a value past what the reader may hold ends the parse where it
	// stands rather than being built whole and refused after: the memory a
	// refused value would have taken is never taken. It is nil for a parse
	// with no allowance -- the header of an object stream, a test's own --
	// where the value's size is bounded by what it is parsed from.
	allow *allowance
}

// hold charges what a value the parser has just built costs to hold, and
// reports the error to end the parse with when the document may not hold it.
func (p *parser) hold(n int64) error {
	if p.allow.take(n) {
		return nil
	}
	return p.allow.exhausted()
}

// errKeyword carries a keyword the parser met where an object was
// expected: "endobj", "stream", "obj", or, in content mode, an operator.
type errKeyword struct {
	keyword string
	pos     int
}

func (e errKeyword) Error() string { return "keyword " + e.keyword }

var errUnexpectedEOF = errors.New("unexpected end of data")

// parseObject reads one object. In content mode a keyword is returned as
// errKeyword for the interpreter; otherwise "R" after two integers makes
// a reference, and other keywords are errors the caller inspects.
func (p *parser) parseObject(depth int) (object, error) {
	if depth > maxNesting {
		return nil, fmt.Errorf("%w: objects nested past %d", errStructureBound, maxNesting)
	}
	t, err := p.lex.next()
	// Closing delimiters and braces where an object should begin are stray,
	// and skipped in this loop: they do not deepen the nesting.
	for err == nil && (t.kind == tokArrayClose || t.kind == tokDictClose || t.kind == tokBraceOpen || t.kind == tokBraceClose) {
		t, err = p.lex.next()
	}
	if err != nil {
		return nil, err
	}
	switch t.kind {
	case tokEOF:
		return nil, errUnexpectedEOF
	case tokInteger:
		if err := p.hold(parsedValueBytes); err != nil {
			return nil, err
		}
		if !p.contentMode {
			// Two integers followed by R are a reference.
			save := p.lex.pos
			t2, err2 := p.lex.next()
			if err2 == nil && t2.kind == tokInteger {
				t3, err3 := p.lex.next()
				if err3 == nil && t3.kind == tokKeyword && t3.keyword == "R" {
					if t.i < 0 || t.i > 1<<31 || t2.i < 0 || t2.i > 1<<16 {
						return nil, fmt.Errorf("reference %d %d R out of range", t.i, t2.i)
					}
					return ref{int(t.i), int(t2.i)}, nil
				}
			}
			p.lex.pos = save
		}
		return t.i, nil
	case tokReal:
		if err := p.hold(parsedValueBytes); err != nil {
			return nil, err
		}
		return t.f, nil
	case tokName:
		if err := p.hold(parsedStringBytes + goSizeClass(int64(len(t.name)))); err != nil {
			return nil, err
		}
		return t.name, nil
	case tokString:
		if err := p.hold(parsedStringBytes + goSizeClass(int64(len(t.str)))); err != nil {
			return nil, err
		}
		return String(t.str), nil
	case tokArrayOpen:
		if err := p.hold(parsedArrayBytes); err != nil {
			return nil, err
		}
		arr := Array{}
		for {
			save := p.lex.pos
			tt, err := p.lex.next()
			if err != nil {
				return nil, err
			}
			if tt.kind == tokArrayClose {
				return arr, nil
			}
			if tt.kind == tokEOF {
				return arr, nil // unterminated: what was read
			}
			if tt.kind == tokDictClose {
				continue // stray
			}
			p.lex.pos = save
			item, err := p.parseObject(depth + 1)
			if err != nil {
				var kw errKeyword
				if errors.As(err, &kw) {
					if p.contentMode {
						// An operator inside an array in a content
						// stream: malformed; end the array here.
						p.lex.pos = kw.pos
						return arr, nil
					}
					if kw.keyword == "endobj" || kw.keyword == "stream" || kw.keyword == "endstream" {
						p.lex.pos = kw.pos
						return arr, nil
					}
					// An unknown keyword inside an array (e.g. a bare
					// "null" is handled below); skip it.
					continue
				}
				return nil, err
			}
			if err := p.hold(parsedSlotBytes); err != nil {
				return nil, err
			}
			arr = append(arr, item)
			if len(arr) > maxContainerItems {
				return nil, fmt.Errorf("%w: array past %d items", errStructureBound, maxContainerItems)
			}
		}
	case tokDictOpen:
		if err := p.hold(parsedDictBytes); err != nil {
			return nil, err
		}
		dict := Dict{}
		for {
			tt, err := p.lex.next()
			if err != nil {
				return nil, err
			}
			if tt.kind == tokDictClose {
				return dict, nil
			}
			if tt.kind == tokEOF {
				return dict, nil
			}
			if tt.kind != tokName {
				// A value where a key should be: skip to resynchronise.
				if tt.kind == tokKeyword && (tt.keyword == "endobj" || tt.keyword == "stream" || tt.keyword == "endstream") {
					p.lex.pos = tt.pos
					return dict, nil
				}
				if tt.kind == tokArrayOpen || tt.kind == tokDictOpen {
					p.lex.pos = tt.pos
					if _, err := p.parseObject(depth + 1); err != nil {
						return nil, err
					}
				}
				continue
			}
			key := tt.name
			save := p.lex.pos
			vt, err := p.lex.next()
			if err != nil {
				return nil, err
			}
			if vt.kind == tokDictClose {
				if err := p.hold(parsedMemberBytes + goSizeClass(int64(len(key)))); err != nil {
					return nil, err
				}
				dict[key] = nil
				return dict, nil
			}
			p.lex.pos = save
			val, err := p.parseObject(depth + 1)
			if err != nil {
				var kw errKeyword
				if errors.As(err, &kw) {
					if kw.keyword == "endobj" || kw.keyword == "stream" || kw.keyword == "endstream" {
						p.lex.pos = kw.pos
						return dict, nil
					}
					continue
				}
				return nil, err
			}
			if _, taken := dict[key]; !taken {
				if err := p.hold(parsedMemberBytes + goSizeClass(int64(len(key)))); err != nil {
					return nil, err
				}
			}
			dict[key] = val
			if len(dict) > maxContainerItems {
				return nil, fmt.Errorf("%w: dictionary past %d members", errStructureBound, maxContainerItems)
			}
		}
	case tokKeyword:
		switch t.keyword {
		case "true", "false":
			if err := p.hold(parsedValueBytes); err != nil {
				return nil, err
			}
			return t.keyword == "true", nil
		case "null":
			// The null object is charged as any other value is: what holds it
			// holds a slot and an interface, whatever the interface says.
			if err := p.hold(parsedValueBytes); err != nil {
				return nil, err
			}
			return nil, nil
		}
		return nil, errKeyword{keyword: t.keyword, pos: t.pos}
	}
	return nil, errors.New("unexpected token")
}
