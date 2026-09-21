package pdf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"unicode/utf8"
)

// A bound below met in a page's content fails the page as pdf-page-failed,
// since the content past it is not interpreted and the text before it is not
// the page's text.
const (
	// maxFormDepth bounds form XObjects drawn from within form XObjects.
	maxFormDepth = 12
	// maxOperators bounds the operators interpreted for one page, forms
	// included.
	maxOperators = 4_000_000
	// maxCharacters bounds the characters the glyphs shown on one page map
	// to, forms included, an unmapped glyph's U+FFFD counted as one, and so
	// the glyphs a page shows -- one operator can show millions -- whether
	// or not their text is kept.
	maxCharacters = 4_000_000
	// maxContentBytes bounds a page's concatenated content streams.
	maxContentBytes = 64 << 20
	// maxOperands bounds the operand stack, and twice it the keys and values
	// of an inline image's dictionary.
	maxOperands = 64
	// maxOperandItems bounds what the operand stacks of a page hold at one
	// time, the forms it draws included, counting the elements of nested
	// arrays and the members of nested dictionaries. The stack is bounded by
	// what it holds and not by the count of operands alone: one operand may
	// be an array of a million names, which a content stream spells in two
	// bytes each and the reader holds at about twenty times that. It admits
	// one array of maxContainerItems elements, which is the most any one
	// operand can hold.
	maxOperandItems = 1 << 20
	// maxGraphicsStates bounds the graphics states saved and not restored.
	maxGraphicsStates = 256
	// maxInlineImageBytes bounds one inline image's data.
	maxInlineImageBytes = 16 << 20
	// operatorsPerCheck is how often the deadline is consulted: once per this
	// many operators, and, within one operator that shows a string, once per
	// this many glyphs.
	operatorsPerCheck = 4096
)

// matrix is a PDF transformation [a b c d e f].
type matrix [6]float64

var identity = matrix{1, 0, 0, 1, 0, 0}

func (m matrix) mul(n matrix) matrix {
	return matrix{
		m[0]*n[0] + m[1]*n[2], m[0]*n[1] + m[1]*n[3],
		m[2]*n[0] + m[3]*n[2], m[2]*n[1] + m[3]*n[3],
		m[4]*n[0] + m[5]*n[2] + n[4], m[4]*n[1] + m[5]*n[3] + n[5],
	}
}

func (m matrix) apply(x, y float64) (float64, float64) {
	return m[0]*x + m[2]*y + m[4], m[1]*x + m[3]*y + m[5]
}

// gstate is the part of the graphics state text extraction needs.
type gstate struct {
	ctm        matrix
	font       *font
	size       float64
	charSpace  float64
	wordSpace  float64
	hscale     float64
	leading    float64
	rise       float64
	renderMode int64
}

// textBuilder turns positioned glyphs into a page's text: a newline when
// the pen moves down (or up, for a new paragraph), a space when it jumps
// right further than a glyph would, and the glyphs in stream order. What it
// writes passes through the record's normalisation as it is written, so the
// text budget is decided on the normalised text and the builder holds no
// more than the budget.
type textBuilder struct {
	norm     streamNormalizer
	unmapped int
	// last glyph's end position in device space and the font size there.
	lastX, lastY, lastSize float64
	lineStart              bool
	started                bool
}

// writeRune writes one rune and reports whether the normalised text is
// still within the budget.
func (b *textBuilder) writeRune(r rune) bool {
	// A guard for a rune no text can carry: it is dropped, and counted in
	// neither chars nor unmapped. A glyph should not reach here with one --
	// the CMap lookups in cmap.go hold a destination to validScalar and
	// leave the code unmapped instead, so the glyph is U+FFFD and counted.
	if utf8.RuneLen(r) < 0 {
		return true
	}
	b.norm.write(r)
	return !b.norm.over
}

// cut reports that the normalised text is past the budget.
func (b *textBuilder) cut() bool { return b.norm.over }

// place positions the next glyph: x, y in device space, size the font
// size in device units. It writes the separator the move implies.
func (b *textBuilder) place(x, y, size float64) {
	if !b.started {
		b.started = true
		b.lastX, b.lastY, b.lastSize = x, y, size
		return
	}
	ref := b.lastSize
	if ref <= 0 {
		ref = size
	}
	if ref <= 0 {
		ref = 1
	}
	dy := y - b.lastY
	dx := x - b.lastX
	switch {
	case math.Abs(dy) > 0.5*ref:
		// A new line. A large upward move is a new block; either way, a
		// line break, and blank lines for a big gap.
		if !b.lineStart {
			b.writeRune('\n')
			if math.Abs(dy) > 2.2*ref {
				b.writeRune('\n')
			}
		}
		b.lineStart = true
	case dx > 0.16*ref && !b.lineStart:
		b.writeRune(' ')
	case dx < -0.5*ref && !b.lineStart:
		// Moved back on the same line: a column, or a tab.
		b.writeRune(' ')
	}
}

// add writes a glyph's characters. Every character the font maps it to is
// written as it is, a control, a tab or a line feed included: what of them
// stays is the normalisation's to decide, in the order the text holds them.
func (b *textBuilder) add(g glyph, endX, endY, size float64) {
	if g.unmapped {
		b.unmapped++
		b.writeRune(0xFFFD)
	} else {
		for _, r := range g.runes {
			if !b.writeRune(r) {
				break
			}
		}
	}
	b.lineStart = false
	b.lastX, b.lastY, b.lastSize = endX, endY, size
}

// interp interprets one page's content.
type interp struct {
	d        *Document
	ctx      context.Context
	tb       *textBuilder
	ops      int
	fonts    map[string]*font
	fontRefs map[ref]*font
	images   int
	textOps  int
	// operandItems counts what the operand stacks hold at this moment: the
	// stream being interpreted and, while it draws a form, the streams it was
	// drawn from, since those hold their operands until the form returns.
	operandItems int
	// chars counts the characters the page's glyphs map to, and glyphs the
	// glyphs shown, which paces the deadline within one operator.
	chars  int
	glyphs int
	err    error
}

// pageResult is what interpreting a page yields: its normalised text,
// whether it drew an image, the glyphs it could not map, whether its text
// went past the budget, and the error that stopped it -- the context's when
// the deadline did. Text past the budget ends what is kept of the text, not
// the interpretation: err says whether the content could be interpreted
// whether or not the text was cut.
type pageResult struct {
	text     string
	hasImage bool
	unmapped int
	cut      bool
	err      error
}

// errTooManyOperators is a page past the operators the reader interprets.
var errTooManyOperators = fmt.Errorf("%w: the page has more operators than the reader interprets", errStructureBound)

// errTooManyCharacters is a page whose glyphs map to more characters than
// the reader interprets.
var errTooManyCharacters = fmt.Errorf("%w: the page's glyphs map to more than %d characters", errStructureBound, maxCharacters)

func (d *Document) interpretPage(ctx context.Context, content []byte, resources Dict, textLimit int, fontRefs map[ref]*font) (result pageResult) {
	tb := &textBuilder{norm: streamNormalizer{limit: textLimit}}
	it := &interp{d: d, ctx: ctx, tb: tb, fonts: map[string]*font{}, fontRefs: fontRefs}
	defer func() {
		// A defect the interpreter did not anticipate fails this page, not
		// the document.
		if r := recover(); r != nil {
			result = pageResult{err: errPageDefect}
		}
	}()
	it.run(content, resources, gstate{ctm: identity, hscale: 1}, 0)
	return pageResult{text: tb.norm.text(), hasImage: it.images > 0, unmapped: tb.unmapped, cut: tb.cut(), err: it.err}
}

// errPageDefect is a page the interpreter could not continue through.
var errPageDefect = errors.New("the page's content could not be interpreted")

// unknownFont is the font of a resource name the page's /Resources does not
// name: it holds no mapping, so a glyph it yields is unmapped, and it measures
// a glyph as half an em. One value serves such a name whatever the name is,
// since what the reader makes of an unknown one does not depend on it: the
// fonts a document declares are built by loadFont, which writes to the font it
// allocates, and this one is not built from a dictionary.
var unknownFont = func() *font {
	f := &font{noWidths: true}
	for c := range f.simpleWidths {
		f.simpleWidths[c] = 500
	}
	return f
}()

// fontFor finds a font resource by name, cached by reference so the same
// font across pages is loaded once, and by name while one content stream is
// read. Both caches are bounded by maxFontCacheEntries: past it a name's font
// is found again rather than held, so what a page holds does not grow with
// the names its content shows.
func (it *interp) fontFor(resources Dict, name Name) *font {
	if f, ok := it.fonts[string(name)]; ok {
		return f
	}
	fonts := it.d.dictOf(resources["Font"])
	var f *font
	if fonts != nil {
		if r, ok := fonts[name].(ref); ok {
			if cached, ok := it.fontRefs[r]; ok {
				f = cached
			} else if dict := it.d.dictOf(r); dict != nil {
				f = it.d.loadFont(dict)
				if len(it.fontRefs) < maxFontCacheEntries {
					it.fontRefs[r] = f
				}
			}
		} else if dict := it.d.dictOf(fonts[name]); dict != nil {
			f = it.d.loadFont(dict)
		}
	}
	if f == nil {
		// An unknown font: glyphs are unmapped one byte at a time.
		f = unknownFont
	}
	if len(it.fonts) < maxFontCacheEntries {
		it.fonts[string(name)] = f
	}
	return f
}

func num(o object) float64 {
	switch x := o.(type) {
	case int64:
		return float64(x)
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return 0
		}
		return x
	}
	return 0
}

// run interprets one content stream under resources, with the initial
// graphics state given, at a form nesting depth. A form receives a copy of
// its caller's state, including the selected font and text parameters.
func (it *interp) run(content []byte, resources Dict, gs gstate, depth int) {
	if depth > maxFormDepth {
		it.noteStreamError(structureBound("forms drawn within forms past %d", maxFormDepth))
		return
	}
	lex := newLexer(content, 0)
	p := &parser{lex: lex, contentMode: true}
	var stack []gstate
	var operands []object
	// held is what this stream's operands hold, charged to the page's count
	// while they are held and given back when this stream is done with them:
	// the operands of a stream that drew a form are still held while the form
	// is interpreted, and are counted there too.
	held := 0
	defer func() { it.operandItems -= held }()
	var tm, tlm matrix
	inText := false
	for {
		// A page whose content has failed is failed, whatever follows; text
		// past the budget does not stop interpretation.
		if it.err != nil {
			return
		}
		if it.ops%operatorsPerCheck == 0 && it.deadlinePassed() {
			return
		}
		if it.ops > maxOperators {
			it.noteStreamError(errTooManyOperators)
			return
		}
		obj, err := p.parseObject(0)
		if err == nil {
			if len(operands) == maxOperands {
				it.noteStreamError(structureBound("operands past %d", maxOperands))
				return
			}
			items := operandItems(obj)
			if items > maxOperandItems-it.operandItems {
				it.noteStreamError(structureBound("the operands held past %d items", maxOperandItems))
				return
			}
			held += items
			it.operandItems += items
			operands = append(operands, obj)
			continue
		}
		kw, ok := err.(errKeyword)
		if !ok {
			if !errors.Is(err, errUnexpectedEOF) {
				// A lexical error or a structure bound: the content past it
				// cannot be read, so what was read before it is not the page.
				it.noteStreamError(err)
			}
			return
		}
		it.ops++
		op := kw.keyword
		n := len(operands)
		arg := func(i int) float64 {
			if i < 0 || i >= n {
				return 0
			}
			return num(operands[i])
		}
		switch op {
		case "q":
			if len(stack) == maxGraphicsStates {
				it.noteStreamError(structureBound("graphics states saved past %d", maxGraphicsStates))
				return
			}
			stack = append(stack, gs)
		case "Q":
			if len(stack) > 0 {
				gs = stack[len(stack)-1]
				stack = stack[:len(stack)-1]
			}
		case "cm":
			if n >= 6 {
				gs.ctm = matrix{arg(n - 6), arg(n - 5), arg(n - 4), arg(n - 3), arg(n - 2), arg(n - 1)}.mul(gs.ctm)
			}
		case "BT":
			inText = true
			tm, tlm = identity, identity
		case "ET":
			inText = false
		case "Tf":
			if n >= 2 {
				if name, ok := operands[n-2].(Name); ok {
					gs.font = it.fontFor(resources, name)
				}
				gs.size = arg(n - 1)
			}
		case "Td":
			tlm = matrix{1, 0, 0, 1, arg(n - 2), arg(n - 1)}.mul(tlm)
			tm = tlm
		case "TD":
			gs.leading = -arg(n - 1)
			tlm = matrix{1, 0, 0, 1, arg(n - 2), arg(n - 1)}.mul(tlm)
			tm = tlm
		case "Tm":
			if n >= 6 {
				tlm = matrix{arg(n - 6), arg(n - 5), arg(n - 4), arg(n - 3), arg(n - 2), arg(n - 1)}
				tm = tlm
			}
		case "T*":
			tlm = matrix{1, 0, 0, 1, 0, -gs.leading}.mul(tlm)
			tm = tlm
		case "TL":
			gs.leading = arg(n - 1)
		case "Tc":
			gs.charSpace = arg(n - 1)
		case "Tw":
			gs.wordSpace = arg(n - 1)
		case "Tz":
			gs.hscale = arg(n-1) / 100
		case "Ts":
			gs.rise = arg(n - 1)
		case "Tr":
			gs.renderMode = int64(arg(n - 1))
		case "Tj":
			if n >= 1 {
				if s, ok := operands[n-1].(String); ok {
					it.show(&gs, &tm, s, inText)
				}
			}
		case "'":
			tlm = matrix{1, 0, 0, 1, 0, -gs.leading}.mul(tlm)
			tm = tlm
			if n >= 1 {
				if s, ok := operands[n-1].(String); ok {
					it.show(&gs, &tm, s, inText)
				}
			}
		case "\"":
			if n >= 3 {
				gs.wordSpace = arg(n - 3)
				gs.charSpace = arg(n - 2)
				tlm = matrix{1, 0, 0, 1, 0, -gs.leading}.mul(tlm)
				tm = tlm
				if s, ok := operands[n-1].(String); ok {
					it.show(&gs, &tm, s, inText)
				}
			}
		case "TJ":
			if n >= 1 {
				if arr, ok := operands[n-1].(Array); ok {
					for _, item := range arr {
						switch x := item.(type) {
						case String:
							it.show(&gs, &tm, x, inText)
						case int64, float64:
							// A negative adjustment moves right: a gap.
							tx := -num(x) / 1000 * gs.size * gs.hscale
							if gs.font != nil && gs.font.vertical {
								tm = matrix{1, 0, 0, 1, 0, -num(x) / 1000 * gs.size}.mul(tm)
							} else {
								tm = matrix{1, 0, 0, 1, tx, 0}.mul(tm)
							}
						}
					}
				}
			}
		case "Do":
			if n >= 1 {
				if name, ok := operands[n-1].(Name); ok {
					it.do(resources, name, gs, depth)
				}
			}
		case "BI":
			// Inline image: skip to EI. The lexer position is after BI;
			// the dictionary tokens follow, then ID, one whitespace, data.
			it.images++
			if err := it.skipInlineImage(lex); err != nil {
				it.noteStreamError(err)
				return
			}
		case "d0", "d1":
			// Type3 glyph metrics; nothing for text.
		}
		operands = operands[:0]
		it.operandItems -= held
		held = 0
	}
}

// operandItems is what an operand holds: itself, and what its elements or
// members hold in turn, since an array or a dictionary is held whole while
// it is an operand. A value holds no value twice and none holds itself, so
// this walk ends within the nesting the parser admits.
func operandItems(o object) int {
	switch x := o.(type) {
	case Array:
		n := 1
		for _, item := range x {
			n += operandItems(item)
		}
		return n
	case Dict:
		n := 1
		for _, v := range x {
			n += 1 + operandItems(v)
		}
		return n
	}
	return 1
}

// show renders a string's glyphs into the text builder, advancing tm. Every
// glyph's characters are counted against maxCharacters, those past the text
// budget too, so that whether the page is past the bound does not depend on
// the budget.
func (it *interp) show(gs *gstate, tm *matrix, s String, inText bool) {
	f := gs.font
	if f == nil {
		f = it.fontFor(Dict{}, "")
		gs.font = f
	}
	if gs.renderMode == 3 || gs.renderMode == 7 {
		// Invisible text: an OCR layer over a scanned page is exactly
		// this, and it is text the document carries; keep it.
	}
	trm := matrix{gs.size * gs.hscale, 0, 0, gs.size, 0, gs.rise}.mul(*tm).mul(gs.ctm)
	// Device font size: the length of the (0,1) vector under trm.
	sx, sy := trm[2], trm[3]
	devSize := math.Sqrt(sx*sx + sy*sy)
	for g := range f.glyphs(s) {
		// One operator can show millions of glyphs: the deadline is read
		// within it on the cadence the operator loop uses.
		it.glyphs++
		if it.glyphs%operatorsPerCheck == 0 && it.deadlinePassed() {
			return
		}
		it.chars += max(len(g.runes), 1)
		if it.chars > maxCharacters {
			it.noteStreamError(errTooManyCharacters)
			return
		}
		if it.tb.cut() {
			// Text past the budget is not kept.
			continue
		}
		x0, y0 := trm.apply(0, 0)
		it.tb.place(x0, y0, devSize)
		it.textOps++
		var adv float64
		if f.vertical {
			adv = g.width
		} else {
			adv = g.width*gs.size + gs.charSpace
			if g.isSpace {
				adv += gs.wordSpace
			}
			adv *= gs.hscale
		}
		if f.type3 {
			adv = (g.width*gs.size + gs.charSpace) * gs.hscale
			if g.isSpace {
				adv += gs.wordSpace * gs.hscale
			}
		}
		if f.vertical {
			*tm = matrix{1, 0, 0, 1, 0, -(g.width*gs.size + gs.charSpace)}.mul(*tm)
		} else {
			*tm = matrix{1, 0, 0, 1, adv, 0}.mul(*tm)
		}
		trm = matrix{gs.size * gs.hscale, 0, 0, gs.size, 0, gs.rise}.mul(*tm).mul(gs.ctm)
		x1, y1 := trm.apply(0, 0)
		it.tb.add(g, x1, y1, devSize)
	}
}

// do draws an XObject: a form is interpreted with its own resources and
// matrix; an image is counted.
func (it *interp) do(resources Dict, name Name, gs gstate, depth int) {
	xobjects := it.d.dictOf(resources["XObject"])
	if xobjects == nil {
		return
	}
	s, ok := it.d.resolve(xobjects[name]).(*stream)
	if !ok {
		return
	}
	switch s.dict["Subtype"] {
	case Name("Image"):
		it.images++
	case Name("Form"):
		if depth >= maxFormDepth {
			it.noteStreamError(structureBound("forms drawn within forms past %d", maxFormDepth))
			return
		}
		// A form is decoded and read each time it is drawn, before its first
		// operator: the deadline is checked before that, so that a large form
		// drawn many times is not read many times between two checks.
		if it.deadlinePassed() {
			return
		}
		data, err := it.d.decodeStream(s, false)
		if err != nil {
			it.noteStreamError(err)
			return
		}
		ctm := gs.ctm
		if m := it.d.arrayOf(s.dict["Matrix"]); len(m) == 6 {
			var fm matrix
			for i := range m {
				fm[i] = num(it.d.resolve(m[i]))
			}
			ctm = fm.mul(ctm)
		}
		res := it.d.dictOf(s.dict["Resources"])
		if res == nil {
			res = resources
		}
		saved := it.fonts
		it.fonts = map[string]*font{}
		gs.ctm = ctm
		it.run(data, res, gs, depth+1)
		it.fonts = saved
	}
}

// deadlinePassed checks the deadline, and records the context's error as
// what stopped the page when it has passed.
func (it *interp) deadlinePassed() bool {
	select {
	case <-it.ctx.Done():
		it.noteStreamError(it.ctx.Err())
		return true
	default:
		return false
	}
}

// noteStreamError records the first stream problem met on a page.
func (it *interp) noteStreamError(err error) {
	if it.err == nil {
		it.err = err
	}
}

// skipInlineImage advances the lexer past an inline image's data: after
// "ID" and one whitespace byte, the data runs to "EI" delimited by
// whitespace on both sides (or the end of the stream). An image whose
// dictionary or data is past its bound, or whose dictionary cannot be read,
// is an error: the content after it cannot be found.
func (it *interp) skipInlineImage(lex *lexer) error {
	data := lex.data
	// Find "ID" as a token.
	p := &parser{lex: lex, contentMode: true}
	for objects := 0; ; objects++ {
		if objects > 2*maxOperands {
			return structureBound("an inline image's dictionary past %d objects", 2*maxOperands)
		}
		_, err := p.parseObject(0)
		if err == nil {
			continue
		}
		kw, ok := err.(errKeyword)
		if !ok {
			if errors.Is(err, errUnexpectedEOF) {
				return nil
			}
			return err
		}
		if kw.keyword == "ID" {
			break
		}
		if kw.keyword == "EI" {
			return nil
		}
	}
	start := lex.pos
	if start < len(data) && isWhitespace(data[start]) {
		start++
	}
	// The data, at most maxInlineImageBytes, then a whitespace byte and EI.
	limit := start + maxInlineImageBytes + 3
	if limit > len(data) {
		limit = len(data)
	}
	for end := start; end < limit; {
		i := bytes.Index(data[end:limit], []byte("EI"))
		if i < 0 {
			break
		}
		at := end + i
		before := at == 0 || isWhitespace(data[at-1])
		after := at+2 >= len(data) || isWhitespace(data[at+2]) || isDelimiter(data[at+2])
		if before && after {
			lex.pos = at + 2
			return nil
		}
		end = at + 2
	}
	if limit < len(data) {
		return structureBound("an inline image's data past %d bytes", maxInlineImageBytes)
	}
	lex.pos = len(data)
	return nil
}
