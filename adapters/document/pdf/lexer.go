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
	"math"
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
	// lexBytesPerCheck is how many bytes a lexer that reads a document
	// advances over between two readings of the deadline: the bytes of its
	// tokens, the whitespace and comments it skips, and the bytes it reads
	// again where a parser steps back over a token. One object's parse may run
	// through a large part of the file within every bound the reader holds --
	// a trailer of a million members, a run of whitespace or a comment as long
	// as the file -- and the deadline is read as it runs and not only after
	// it. A token the lexer reads with no reading inside it, a keyword or a
	// number, is read whole, so no more than this and the bytes of a keyword,
	// maxNameBytes, lie between two readings. A trailer of a million members
	// is parsed at about seventy nanoseconds a byte, so at this size a reading
	// falls due every millisecond or so of that parse, and the readings cost
	// nothing measurable beside it: a larger size lets the longest wait
	// between two readings grow with it, and a smaller one shortens the wait
	// no further than the work a single token's growth does in one step.
	lexBytesPerCheck = 16 << 10
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
	// ident is what the probe build knows the lexer by, and every copy of
	// it with it, and every lexer made again over the same data where it
	// stands, so that what a copy or a lexer made in its place reads again
	// is counted as the lexer's own: see lexIdentity. In every other build
	// it is empty and takes no room.
	ident lexIdentity
	data  []byte
	pos   int
	// work is what the bytes this lexer advances over are charged to: a file
	// whose objects each read the rest of it -- a comment with no line end
	// after every object is one -- spends the allowance instead of being read
	// once for every object. It is nil for a lexer whose reading is not
	// charged: a page's content is read once from end to end, and what that
	// costs is the page's own work allowance, charged where the stream is
	// decoded.
	work *allowance
	// room is what the memory of the token being built is charged to, as the
	// builder grows into it. Every lexer has one where its parser has one,
	// content and CMaps included: what a token takes is memory wherever it is
	// read, while what it advanced over is the reading of a file.
	room *allowance
	// charged is how far the bytes advanced over have been charged. It only
	// rises, so a parser that goes back over what it has read does not pay for
	// it twice, and each byte of the slice costs this lexer one charge.
	charged int
	// reserved is what the token being built has been charged for the room it
	// holds, so that growing it charges what the growth costs and no more.
	reserved int64
	// due is where the lexer stands when the next reading of the deadline
	// falls due: lexBytesPerCheck bytes past where it stood at the last one.
	// Every byte advanced over counts toward it, however often it is advanced
	// over: a parser that steps back over a token has the lexer read the
	// token again, and back moves the reading that much earlier in the data,
	// so that it still falls due after the same number of bytes read. A lexer
	// that reads no deadline has it at the end of every slice there is, and
	// the checks of it cost a comparison that never holds.
	due int
	// strict is set while an inline image's dictionary is read. A byte that
	// begins no token is skipped everywhere else, so that a damaged file
	// still yields its objects; there it is not, since what stands after it
	// may be the image's data rather than the dictionary, and a dictionary
	// read past a byte it does not admit establishes nothing.
	strict bool
	// spent is set when a charge did not fit. Every token after it is an
	// error, so a parse whose reading has run out of allowance ends where it
	// is rather than reading on and counting: a lookahead that threw its
	// error away would otherwise go on reading at no cost.
	spent bool
	// halted is set once a reading of the deadline found it passed. Every
	// token after it is the deadline's error, as every token after a spent
	// allowance is the allowance's: a parse the deadline ended ends where it
	// stands, a lookahead that would throw the error away included. The
	// deadline read is that of the document whose allowance the lexer's
	// reading spends, and a lexer whose reading spends none reads no
	// deadline: a page's content and a CMap are read under the page's work
	// allowance and the page's own readings of the deadline. The error is
	// the document's, and a document stopped once stays stopped: see
	// Document.stopped.
	//
	// The flags stand together at the end, and the lexer is as large as it
	// was before it read a deadline: one is allocated for every object read,
	// and a larger one costs a larger allocation every time.
	halted bool
}

func newLexer(data []byte, pos int) *lexer {
	return &lexer{ident: newLexIdentity(data, pos), data: data, pos: pos, charged: pos, due: math.MaxInt}
}

// within gives the lexer the allowance a document's reading spends: both what
// its tokens take and what its reading of the file costs. An allowance on a
// document gives it that document's deadline as well, read every
// lexBytesPerCheck bytes the lexer advances over: a lexer charged to a
// document reads that document's bytes, the file's own or those of a stream
// of objects it holds.
func (l *lexer) within(a *allowance) *lexer {
	l.work, l.room = a, a
	if a != nil && a.doc != nil {
		l.due = l.pos + lexBytesPerCheck
		if a.doc.expired != nil {
			// A lexer made for a document the deadline has stopped reads the
			// deadline before its first byte, and so reads none.
			l.due = l.pos
		}
		if lexTrace != nil {
			lexTrace(a, lexBegan, l.pos)
		}
	}
	return l
}

// pace reads the deadline, where the lexer has one and has reached the
// position the reading falls due at, and reports whether it has passed. The
// next reading falls due lexBytesPerCheck bytes on. A lexer that has spent its
// allowance reads no deadline: the allowance was met first, and every token
// after it is that error.
func (l *lexer) pace() bool {
	if l.halted {
		return true
	}
	if l.work == nil || l.work.doc == nil || l.spent {
		l.due = math.MaxInt
		return false
	}
	if l.pos < l.due {
		return false
	}
	if lexTrace != nil {
		lexTrace(l.work, lexReadAt, l.pos)
	}
	if l.work.doc.deadlineNow() {
		// Every check of the position against due is met from here on, and
		// each finds the lexer stopped.
		l.halted = true
		l.due = l.pos
		return true
	}
	l.due = l.pos + lexBytesPerCheck
	return false
}

// end is where a run the lexer reads byte by byte may be read to before the
// deadline is read: where the reading falls due, or the end of the data.
func (l *lexer) end() int {
	return min(len(l.data), l.due)
}

// back steps the lexer back to an earlier position, where a parser gives up
// what it read ahead. Every step back is made here and nowhere else, so that
// what is read again is counted again: the reading of the deadline falls due
// as much earlier in the data as the step back is long.
func (l *lexer) back(to int) {
	if lexTrace != nil {
		lexTrace(l.work, lexSteppedBack, l.pos-to)
	}
	l.due -= l.pos - to
	l.pos = to
}

// stopped is the deadline's error once a reading of it found it passed, and
// nil before. The error is the document's: see Document.stopped.
func (l *lexer) stopped() error {
	if !l.halted {
		return nil
	}
	return l.work.doc.deadline()
}

// at is the byte of the data at i. Every byte the lexer inspects one at a
// time it reads here -- a keyword's and a number's bytes are inspected here
// to find their end, and then taken whole as a slice -- so that a build made
// for the tests (see lexProbed) can see how far each lexer has loaded, where
// it loads it; in every other build this is the byte and nothing else, and
// costs what indexing the data costs.
func (l *lexer) at(i int) byte {
	if lexProbed {
		lexLoaded(l, i)
	}
	return l.data[i]
}

// lexLoaded, in the build made for the tests, is told of every byte a lexer
// loads through at; lexEntered is told when a reading of tokens or a skip
// begins and returns what to call when it ends. See lexProbed.
var (
	lexLoaded  func(l *lexer, i int)
	lexEntered func(l *lexer) func()
)

// failed is the error every token is once a reading of the deadline has found
// it passed or the allowance is spent, whichever came first: a lexer that has
// spent its allowance reads no deadline after it, and one that has stopped
// reads no token.
func (l *lexer) failed() error {
	if l.halted {
		return l.stopped()
	}
	return l.errRead()
}

// eof is the token at the end of the data, or the deadline's error where the
// skipping before it ended at a reading that found it passed.
func (l *lexer) eof() (token, error) {
	if l.halted {
		return token{}, l.stopped()
	}
	return token{kind: tokEOF, pos: l.pos, end: l.pos}, nil
}

// lexTrace, where it is set, is told where a lexer that reads a document
// begins, where it stands at every reading of the deadline it makes, and how
// far it steps back each time it does, as each happens. From those the tests
// count what a lexer has advanced over between two readings -- where it
// stands less where it began, and every step back again -- apart from due,
// which decides when a reading falls due, so that the count does not take
// due's word for it. It is told nothing at a token or a byte, and a lexer
// that reads no deadline is told of nothing but its steps back. A lexer is
// known to it by its work allowance, which no other lexer spends: a lexer
// handed to it would escape to the heap wherever one is made, and a lexer is
// made for every object read, where it otherwise lives on the stack. The
// reader never sets it.
var lexTrace func(work *allowance, event lexEvent, n int)

// lexEvent is what lexTrace is told of.
type lexEvent int

const (
	lexBegan lexEvent = iota
	lexReadAt
	lexSteppedBack
)

// reserving gives the lexer the allowance its tokens' memory is charged to,
// and leaves its reading uncharged: a content stream and a CMap are each read
// once from end to end, so what they cost to read is bounded where they are
// decoded, while what their tokens hold is memory like any other.
func (l *lexer) reserving(a *allowance) *lexer {
	l.room = a
	return l
}

// advanced charges the bytes read since the last charge. What a value costs
// to hold is charged apart from this, by the parser that builds it: the two
// are different costs of the same object -- the file it was read from and the
// memory it takes -- and a file that is read without being held, as a comment
// or a candidate given up on is, is charged only here.
//
// It is called on the way out of every reading of a token, and again where a
// comment ends, where a string ends and where skipping whitespace ends: the
// way out covers every reader and every error of one, and the others charge
// before a parser can step back over what was read -- an unterminated string
// read as the token after a value is stepped back over, and the rest of the
// data would otherwise be read for every value in it and charged for none.
// A byte is charged once however often it is offered, so the calls that
// overlap cost nothing: a call with nothing new to charge is a comparison,
// made where it is called, and only one with something to charge is a call.
func (l *lexer) advanced() {
	if l.pos > l.charged {
		l.charge()
	}
}

// charge charges the bytes advanced over since the last charge: see advanced.
// It is kept out of line, so that advanced, which is called several times for
// every token, is the comparison alone where it is called.
//
//go:noinline
func (l *lexer) charge() {
	if !l.work.take(int64(l.pos - l.charged)) {
		l.spent = true
	}
	l.charged = l.pos
}

// reserve charges the room a token being built has grown to, and reports
// whether the allowance had it. The bytes are charged as the room is taken,
// so a token past what is left is never allocated whole and then refused.
func (l *lexer) reserve(capacity int) bool {
	want := goSizeClass(int64(capacity))
	if want <= l.reserved {
		return true
	}
	if !l.room.take(want - l.reserved) {
		l.spent = true
		l.reserved = 0
		return false
	}
	l.reserved = want
	return true
}

// errRead is the error every token is once an allowance this lexer spends is
// spent: the memory its tokens take, or the reading of the file itself.
func (l *lexer) errRead() error {
	if l.room != nil {
		return l.room.exhausted()
	}
	return l.work.exhausted()
}

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
// every other advance is. A run of whitespace or a comment may be as long as
// the data, and is one stretch between two tokens however long it is, so the
// deadline is read within each of them and not only where they end; skipping
// ends where a reading finds it passed, with the lexer halted.
//
// The skipping runs to end: where the reading of the deadline falls due, or
// the end of the data, whichever comes first. Each byte costs what it did
// before the lexer read a deadline, and a lexer that reads none skips to the
// end of the data as it always has. Where end is where the reading falls due,
// the deadline is read there, and the skipping goes on to the next end,
// within a comment as well as between comments. Every token is read after a
// skip, so a skip that begins where the reading has already fallen due -- a
// token read whole has taken the lexer past it -- reads the deadline before
// it skips anything: that is where the reading at the end of a token is made.
func (l *lexer) skipSpace() {
	if lexProbed {
		defer lexEntered(l)()
	}
	l.advanced()
	end := l.end()
skipping:
	for {
		for l.pos < end {
			c := l.at(l.pos)
			if isWhitespace(c) {
				l.pos++
				continue
			}
			if c != '%' {
				break skipping
			}
			for {
				for l.pos < end && l.at(l.pos) != '\n' && l.at(l.pos) != '\r' {
					l.pos++
				}
				if l.pos < end || l.pos >= len(l.data) || l.pace() {
					break
				}
				end = l.end()
			}
			l.advanced()
			if l.halted {
				break skipping
			}
		}
		if l.pos >= len(l.data) || l.pace() {
			break
		}
		end = l.end()
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
// is skipped so a damaged file still yields its objects, unless the lexer is
// strict: see the strict field. Skipping is this loop, never a call per byte
// skipped, so a run of such bytes takes no more stack than one does.
//
// Every token reader is reached through here, and the charge on the way out
// covers every way out of them: this call's error exits and the readers'
// own -- a string past the bound on its kind is read before it is refused,
// and a reader that refused one without charging would let a file be read
// again for every object that asks. A token read once the allowance is spent,
// or once a reading of the deadline has found it passed, is an error rather
// than a token, so a parse that has run out of either ends where it stands, a
// lookahead that would throw the error away included: a stopped lexer's skip
// reads the deadline before it skips anything, finds it passed, and the token
// is its error. Those errors, and the end of the data, leave by one return
// each: Go makes the deferred charge a plain call only in a function of few
// returns, and a charge made through the runtime's defer on every token costs
// a measurable part of reading an ordinary file.
func (l *lexer) next() (token, error) {
	if lexProbed {
		defer lexEntered(l)()
	}
	defer l.advanced()
	if l.spent {
		return token{}, l.failed()
	}
	for {
		l.skipSpace()
		if l.pos >= len(l.data) || l.halted {
			return l.eof()
		}
		start := l.pos
		c := l.at(l.pos)
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
			if l.pos+1 < len(l.data) && l.at(l.pos+1) == '<' {
				l.pos += 2
				return token{kind: tokDictOpen, pos: start, end: l.pos}, nil
			}
			return l.hexString()
		case c == '>':
			if l.pos+1 < len(l.data) && l.at(l.pos+1) == '>' {
				l.pos += 2
				return token{kind: tokDictClose, pos: start, end: l.pos}, nil
			}
			if l.strict {
				return token{}, errInlineImageUnended
			}
			l.pos++
			continue
		case c == ')':
			if l.strict {
				return token{}, errInlineImageUnended
			}
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
		for end < len(l.data) && isRegular(l.at(end)) && end-start < maxNameBytes {
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
	for end < len(l.data) && (l.at(end) >= '0' && l.at(end) <= '9' || l.at(end) == '+' || l.at(end) == '-' || l.at(end) == '.' || l.at(end) == 'e' || l.at(end) == 'E') {
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
	// A name's bytes are built into a buffer of their own where an escape
	// makes them differ from the file's, and it is charged as it grows, as a
	// string's is.
	start := l.pos
	l.pos++ // the slash
	var out []byte
	for l.pos < len(l.data) && isRegular(l.at(l.pos)) {
		// A name with every byte escaped is three times its bound in the
		// file, so the deadline is read within it as within a string.
		if l.pos >= l.due && l.pace() {
			return token{}, l.stopped()
		}
		c := l.at(l.pos)
		if c == '#' && l.pos+2 < len(l.data) {
			if v, ok := hexPair(l.at(l.pos+1), l.at(l.pos+2)); ok {
				c = v
				l.pos += 2
			}
		}
		out = append(out, c)
		l.pos++
		if !l.reserve(cap(out)) {
			return token{}, l.errRead()
		}
		if len(out) > maxNameBytes {
			return token{}, fmt.Errorf("%w: name past %d bytes", errLexer, maxNameBytes)
		}
	}
	l.reserved = 0
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
		// A string may run to the bound on its kind, or to the end of the
		// data where it is not closed: the deadline is read within it.
		if l.pos >= l.due && l.pace() {
			return token{}, l.stopped()
		}
		c := l.at(l.pos)
		l.pos++
		if c == '>' {
			if half {
				var err error
				if out, err = l.padHex(out, pending); err != nil {
					return token{}, err
				}
			}
			return l.stringToken(start, out), nil
		}
		if isWhitespace(c) {
			continue
		}
		v, ok := hexValue(c)
		if !ok {
			if l.strict {
				// In an inline image's dictionary a byte that is neither a
				// hexadecimal digit nor white space begins no token of the
				// string: skipping it would read the bytes after it -- the
				// image's data among them, where the '>' that would end the
				// string lies past the dictionary -- as the value's own.
				return token{}, errInlineImageUnended
			}
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
	// Unterminated: what was read is the string, and its last nibble is padded
	// as it would be at a '>'.
	if half {
		var err error
		if out, err = l.padHex(out, pending); err != nil {
			return token{}, err
		}
	}
	return l.stringToken(start, out), nil
}

// padHex appends the byte an odd last nibble is padded into. That byte is a
// byte of the string like every other: it is reserved like every other -- a
// token that grew into a larger buffer to hold it is a token that holds it,
// and one the allowance cannot pay for is not returned -- and it counts
// against the bound on a string like every other, so a string of the bound
// exactly and one nibble more is a string past the bound, wherever it ended.
func (l *lexer) padHex(out []byte, pending byte) ([]byte, error) {
	out = append(out, pending<<4)
	if !l.reserve(cap(out)) {
		return nil, l.errRead()
	}
	if len(out) > maxStringBytes {
		return nil, fmt.Errorf("%w: string past %d bytes", errLexer, maxStringBytes)
	}
	return out, nil
}

func (l *lexer) literalString() (token, error) {
	start := l.pos
	l.pos++ // '('
	depth := 1
	var out []byte
	for l.pos < len(l.data) {
		// A string may run to the bound on its kind, or to the end of the
		// data where it is not closed: the deadline is read within it.
		if l.pos >= l.due && l.pace() {
			return token{}, l.stopped()
		}
		c := l.at(l.pos)
		l.pos++
		switch c {
		case '\\':
			if l.pos >= len(l.data) {
				break
			}
			e := l.at(l.pos)
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
				if l.pos < len(l.data) && l.at(l.pos) == '\n' {
					l.pos++
				}
			case '\n':
			default:
				if e >= '0' && e <= '7' {
					v := int(e - '0')
					for i := 0; i < 2 && l.pos < len(l.data) && l.at(l.pos) >= '0' && l.at(l.pos) <= '7'; i++ {
						v = v*8 + int(l.at(l.pos)-'0')
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
			if l.pos < len(l.data) && l.at(l.pos) == '\n' {
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
	l.back(save)
	return err == nil && t.kind == tokKeyword && t.keyword == kw
}

// parser turns tokens into objects.
type parser struct {
	lex *lexer
	// contentMode is set for content streams, where "R" is not a reference
	// and operators are keywords the caller reads.
	contentMode bool
	// inlineImage is set while an inline image's dictionary is read. There
	// the pairs are read strictly, at every depth: a keyword, a value where a
	// key stands, a stray delimiter or a container that does not close is the
	// dictionary failing to reach the data it describes, since what follows
	// may be the image's data rather than the dictionary. Nothing is skipped
	// and nothing is repaired -- either the dictionary reads as pairs to an
	// ID of its own, or where the image's data begins is not established.
	inlineImage bool
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

// appended puts item in arr, holding the room the array grows by before the
// allocation that takes it. What the reader holds is the whole backing array
// and not the elements in it: append grows that array by Go's own policy,
// which leaves room past the length, and an array charged element by element
// would be charged less than it holds. An element that fits the room the
// array already has is held by a slot already charged and costs nothing more.
//
// A growth holds two backing arrays at once, since append copies the old into
// the new before the old is let go, so what is reserved here covers both: the
// array as it stands, charged a second time, and the doubling Go gives a small
// slice over it. The array's own slots are charged already, so the reserve is
// twice its room -- and one slot where it has none -- and the two of them
// together cover what is held while the copy is made: a small slice grows to
// twice its room and the allocator's rounding over that, a large one to a
// quarter more and that rounding, which is well within the same reserve. The
// rounding is the one thing the reader holds before it is charged, and it is
// charged the moment the growth is known.
//
// Once the copy is made the old array is the collector's, so what was reserved
// for it goes back: the reserve less the room the growth actually left, which
// is never less than nothing at any capacity Go grows through. What the array
// has cost when this returns is the room it now has, however it got there.
// The cost of reserving for both is that an array whose old room and doubled
// new room do not fit together is refused at that growth rather than at the
// next one, which is the reader declining to make a copy it could not hold.
func (p *parser) appended(arr Array, item object) (Array, error) {
	if len(arr) < cap(arr) {
		return append(arr, item), nil
	}
	reserve := int64(max(2*cap(arr), 1))
	if err := p.hold(reserve * parsedSlotBytes); err != nil {
		return nil, err
	}
	before := int64(cap(arr))
	arr = append(arr, item)
	switch grew := int64(cap(arr)) - before; {
	case grew > reserve:
		if err := p.hold((grew - reserve) * parsedSlotBytes); err != nil {
			return nil, err
		}
	case grew < reserve:
		p.allow.give((reserve - grew) * parsedSlotBytes)
	}
	return arr, nil
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
	// and skipped in this loop: they do not deepen the nesting. Inside an
	// inline image's dictionary nothing is skipped: see the parser's
	// inlineImage field.
	for err == nil && (t.kind == tokArrayClose || t.kind == tokDictClose || t.kind == tokBraceOpen || t.kind == tokBraceClose) {
		if p.inlineImage {
			p.lex.back(t.pos)
			return nil, errInlineImageUnended
		}
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
			if p.lex.halted {
				// The deadline was read as passed while the lexer looked
				// past the integer for a reference: the integer is not known
				// to stand alone, and the parse ends at the deadline.
				return nil, p.lex.stopped()
			}
			if err2 == nil && t2.kind == tokInteger {
				t3, err3 := p.lex.next()
				if p.lex.halted {
					return nil, p.lex.stopped()
				}
				if err3 == nil && t3.kind == tokKeyword && t3.keyword == "R" {
					if t.i < 0 || t.i > 1<<31 || t2.i < 0 || t2.i > 1<<16 {
						return nil, fmt.Errorf("reference %d %d R out of range", t.i, t2.i)
					}
					return ref{int(t.i), int(t2.i)}, nil
				}
			}
			p.lex.back(save)
		}
		return t.i, nil
	case tokReal:
		if err := p.hold(parsedValueBytes); err != nil {
			return nil, err
		}
		return t.f, nil
	case tokName:
		if err := p.hold(parsedStringBytes + grownBytes(int64(len(t.name)))); err != nil {
			return nil, err
		}
		return t.name, nil
	case tokString:
		if err := p.hold(parsedStringBytes + grownBytes(int64(len(t.str)))); err != nil {
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
				if p.inlineImage {
					return nil, errInlineImageUnended
				}
				return arr, nil // unterminated: what was read
			}
			if tt.kind == tokDictClose {
				if p.inlineImage {
					p.lex.back(tt.pos)
					return nil, errInlineImageUnended
				}
				continue // stray
			}
			p.lex.back(save)
			item, err := p.parseObject(depth + 1)
			if err != nil {
				var kw errKeyword
				if errors.As(err, &kw) {
					if p.inlineImage {
						// A keyword inside an array of an inline image's
						// dictionary: the array is unfinished, and an
						// unfinished value is no value. Ending the array
						// here would let a keyword inside one stand for the
						// end of the dictionary, which the page does not say.
						p.lex.back(kw.pos)
						return nil, errInlineImageUnended
					}
					if p.contentMode {
						// An operator inside an array in a content
						// stream: malformed; end the array here.
						p.lex.back(kw.pos)
						return arr, nil
					}
					if kw.keyword == "endobj" || kw.keyword == "stream" || kw.keyword == "endstream" {
						p.lex.back(kw.pos)
						return arr, nil
					}
					// An unknown keyword inside an array (e.g. a bare
					// "null" is handled below); skip it.
					continue
				}
				return nil, err
			}
			arr, err = p.appended(arr, item)
			if err != nil {
				return nil, err
			}
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
				if p.inlineImage {
					return nil, errInlineImageUnended
				}
				return dict, nil
			}
			if tt.kind != tokName {
				// A value where a key should be: skip to resynchronise --
				// except inside an inline image's dictionary, where the
				// pairs are read strictly at every depth.
				if p.inlineImage {
					p.lex.back(tt.pos)
					return nil, errInlineImageUnended
				}
				if tt.kind == tokKeyword && (tt.keyword == "endobj" || tt.keyword == "stream" || tt.keyword == "endstream") {
					p.lex.back(tt.pos)
					return dict, nil
				}
				if tt.kind == tokArrayOpen || tt.kind == tokDictOpen {
					p.lex.back(tt.pos)
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
				if p.inlineImage {
					// A key with no value: what the dictionary says of that
					// key is not in the file.
					p.lex.back(vt.pos)
					return nil, errInlineImageUnended
				}
				if err := p.hold(parsedMemberBytes + grownBytes(int64(len(key)))); err != nil {
					return nil, err
				}
				dict[key] = nil
				return dict, nil
			}
			p.lex.back(save)
			val, err := p.parseObject(depth + 1)
			if err != nil {
				var kw errKeyword
				if errors.As(err, &kw) {
					if p.inlineImage {
						p.lex.back(kw.pos)
						return nil, errInlineImageUnended
					}
					if kw.keyword == "endobj" || kw.keyword == "stream" || kw.keyword == "endstream" {
						p.lex.back(kw.pos)
						return dict, nil
					}
					continue
				}
				return nil, err
			}
			if _, taken := dict[key]; !taken {
				if err := p.hold(parsedMemberBytes + grownBytes(int64(len(key)))); err != nil {
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
