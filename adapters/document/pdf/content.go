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
	// maxOperandBytes bounds what the operand stacks of a page hold at one
	// time, the forms it draws included, in the bytes the reader charges for
	// holding a value. The stack is bounded by what it holds and not by the
	// count of operands alone: one operand may be an array of a million
	// names, which a content stream spells in two bytes each and the reader
	// holds at about forty. The allowance is handed to the parser, which
	// spends it element by element, so an operand past it ends the page where
	// it is met rather than being built whole first. It admits an array of
	// maxContainerItems numbers, the most elements any one operand may hold,
	// at the forty bytes each of them is charged.
	maxOperandBytes = 64 << 20
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
	d       *Document
	ctx     context.Context
	tb      *textBuilder
	ops     int
	fonts   map[string]*font
	images  int
	textOps int
	// operandBytes counts what the operand stacks hold at this moment: the
	// stream being interpreted and, while it draws a form, the streams it was
	// drawn from, since those hold their operands until the form returns.
	operandBytes int64
	// chars counts the characters the page's glyphs map to, and glyphs the
	// glyphs shown, which paces the deadline within one operator.
	chars  int
	glyphs int
	// generation is the cross-reference this page is being read under. A
	// rebuild while it is read ends the page: what was read before the
	// rebuild and what is read after it are two documents' pages, and the
	// caller reads the page again under the cross-reference the rebuild
	// produced.
	generation int
	err        error
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

func (d *Document) interpretPage(ctx context.Context, content []byte, resources Dict, textLimit int) (result pageResult) {
	tb := &textBuilder{norm: streamNormalizer{limit: textLimit}}
	it := &interp{d: d, ctx: ctx, tb: tb, fonts: map[string]*font{}, generation: d.generation}
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

// errOperandBudget is a page whose operands hold more than one page's
// operands may hold.
func errOperandBudget() error {
	return structureBound("the operands held past %d bytes", maxOperandBytes)
}

// errPageDefect is a page the interpreter could not continue through.
var errPageDefect = errors.New("the page's content could not be interpreted")

// errCrossReferenceRebuilt is a page whose reading straddled a rebuilt
// cross-reference. It ends the page where it stands, and the reading of the
// document begins again: the record never carries it.
var errCrossReferenceRebuilt = errors.New("the cross-reference was rebuilt while the page was read")

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

// fontFor finds a font resource by name, cached on the document by reference
// so the same font across pages is loaded once -- and dropped with the
// document's objects, since a rebuilt cross-reference gives a number other
// bytes -- and by name while one content stream is read. Both caches are
// bounded by maxFontCacheEntries: past it a name's font is found again rather
// than held, so what a page holds does not grow with the names its content
// shows.
func (it *interp) fontFor(resources Dict, name Name) *font {
	if f, ok := it.fonts[string(name)]; ok {
		return f
	}
	// Finding a font is one read: the resources, the font dictionary they
	// name and everything the font is built from are read under one
	// cross-reference. See beginRead.
	defer it.d.beginRead()()
	// The cross-reference this lookup stands on, read before the resources or
	// the font are resolved: resolving either may rebuild it, and a font
	// built from the objects the old one named is held by neither the old
	// document nor the new.
	generation := it.d.generation
	fonts := it.d.dictOf(resources["Font"])
	var f *font
	if fonts != nil {
		if r, ok := fonts[name].(ref); ok {
			if cached, ok := it.d.fontRefs[r]; ok {
				f = cached
			} else if dict := it.d.dictOf(r); dict != nil {
				f = it.d.loadFont(dict)
				if it.d.generation == generation && it.d.stopped() == nil && len(it.d.fontRefs) < maxFontCacheEntries {
					if it.d.fontRefs == nil {
						it.d.fontRefs = map[ref]*font{}
					}
					it.d.fontRefs[r] = f
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
	if f.deadline != nil {
		// The deadline passed while this font's own resources were read. The
		// page is ended here rather than at the interpreter's next check of
		// the deadline, which the rest of the page's operators may not reach:
		// what it would show under a font read in part is not its text.
		it.noteStreamError(f.deadline)
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
	held := int64(0)
	defer func() { it.operandBytes -= held }()
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
		if it.d.generation != it.generation {
			it.noteStreamError(errCrossReferenceRebuilt)
			return
		}
		if it.ops > maxOperators {
			it.noteStreamError(errTooManyOperators)
			return
		}
		// The operand about to be parsed may hold what is left of the page's
		// operand allowance and no more: the parser is handed the allowance
		// and stops within it, so the memory an operand past the bound would
		// take is never taken. What the parse spent is held until an operator
		// consumes the operands, whether the parse ended in a value, in an
		// operator or at the bound.
		// The allowance bounds what the operands hold. The bytes of the content
		// stream itself are not charged to it: this lexer reads the stream once
		// from end to end, where the bytes a document's lexers read are charged
		// because each object starts one of its own, and what reading a page
		// costs is bounded by the page's work allowance instead.
		room := &allowance{left: maxOperandBytes - it.operandBytes, past: errOperandBudget}
		p.allow = room
		lex.reserving(room)
		before := room.left
		obj, err := p.parseObject(0)
		spent := before - room.left
		held += spent
		it.operandBytes += spent
		if err == nil {
			if len(operands) == maxOperands {
				it.noteStreamError(structureBound("operands past %d", maxOperands))
				return
			}
			if !room.take(parsedSlotBytes) {
				it.noteStreamError(errOperandBudget())
				return
			}
			held += parsedSlotBytes
			it.operandBytes += parsedSlotBytes
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
			// The page's resources go with it, since a colour space the image
			// names may be one of them.
			it.images++
			if err := it.skipInlineImage(lex, resources); err != nil {
				it.noteStreamError(err)
				return
			}
		case "d0", "d1":
			// Type3 glyph metrics; nothing for text.
		}
		// The slots the operands leave behind still refer to them: they are
		// cleared before the charge goes back, so that what is no longer
		// charged is no longer held either.
		for i := range operands {
			operands[i] = nil
		}
		operands = operands[:0]
		it.operandBytes -= held
		held = 0
	}
}

// show renders a string's glyphs into the text builder, advancing tm. Every
// glyph's characters are counted against maxCharacters, those past the text
// budget too, so that whether the page is past the bound does not depend on
// the budget.
func (it *interp) show(gs *gstate, tm *matrix, s String, inText bool) {
	f := gs.font
	if f == nil {
		// A string shown before any Tf selected a font: its glyphs are
		// unmapped, and nothing is cached under the empty name, which is a
		// name a page's /Font may carry and a later Tf may select.
		f = unknownFont
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
	// Drawing an XObject is one read: the resources, the stream they name
	// and the stream's own matrix and resources are read under one
	// cross-reference. See beginRead.
	defer it.d.beginRead()()
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
		// drawn many times is not read many times between two checks, and the
		// bytes it holds are charged to the page for each drawing, so that a
		// form drawn a thousand times costs the page a thousand readings of
		// it whether or not a deadline is there to stop them.
		if it.deadlinePassed() {
			return
		}
		if err := it.d.chargeWork(int64(len(s.raw))); err != nil {
			it.noteStreamError(err)
			return
		}
		data, err := it.d.decodeStream(s, false, heldByPage)
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
// what stopped the page when it has passed. The context is asked first,
// since a caller may end the work by cancelling it; the clock is read after,
// so a deadline the clock has reached stops the page whether or not the
// timer that cancels the context has run.
func (it *interp) deadlinePassed() bool {
	select {
	case <-it.ctx.Done():
		// The document is stopped by what the context says, as by any
		// other reading of it.
		it.d.deadlineFor(it.ctx)
		it.noteStreamError(it.ctx.Err())
		return true
	default:
	}
	if err := it.d.deadlineFor(it.ctx); err != nil {
		it.noteStreamError(err)
		return true
	}
	return false
}

// noteStreamError records the first stream problem met on a page.
func (it *interp) noteStreamError(err error) {
	if it.err == nil {
		it.err = err
	}
}

// Where an inline image's data ends is established from the way the image is
// encoded, and from nothing else: the boundary the reader takes is the one
// every conforming viewer stops reading the image at.
//
//  1. The dictionary between BI and ID, whose keys 8.9.7 abbreviates, is read
//     first. A key bearing on the end, given twice in either spelling with
//     values that disagree once the spellings are set aside, says two things
//     about the image, and the page fails rather than the reader preferring
//     one of them; so does a dictionary that never reaches ID.
//  2. An image no filter encodes is measured: every viewer consumes the bytes
//     its width, height, bits per component and colour components take, and
//     "EI" stands there or the page fails.
//  3. An image a filter encodes is framed by that filter: every decoder of it
//     stops where its encoding ends, and "EI" stands there or the page fails.
//
// The length /L states is no boundary: viewers disagree over it -- one honours
// it where an "EI" follows, another decodes the filter and never reads it --
// so a record that took it would carry one viewer's reading rather than the
// page. Nor is a delimited "EI" in the data: those two bytes are as common in
// an image's samples as any other two, and a comment, a string or a later
// image after a whole image holds them as readily, so neither their presence
// nor their number establishes anything. An image the reader can neither
// measure nor frame therefore fails the page, and says so.
func (it *interp) skipInlineImage(lex *lexer, resources Dict) error {
	img, err := it.readInlineImage(lex)
	if err != nil {
		return err
	}
	data := lex.data
	start := lex.pos
	// One white-space byte stands between ID and the data, and a carriage
	// return and a line feed are one end-of-line marker (7.2.3), not one
	// separator and a sample.
	if start < len(data) && isWhitespace(data[start]) {
		if data[start] == '\r' && start+1 < len(data) && data[start+1] == '\n' {
			start++
		}
		start++
	}
	// Framing an encoded image decodes it, which is a stream's work: the
	// deadline is read before it, as it is before the reading of a form.
	if it.deadlinePassed() {
		return it.d.deadlineFor(it.ctx)
	}
	// What the reader may read of one image bounds the work of finding its
	// end as well as the data it admits.
	window := min(start+maxInlineImageBytes, len(data))
	end, err := it.inlineDataEnds(img, resources, data[start:window])
	if errors.Is(err, errFilterUnended) && window < len(data) {
		// The encoding did not end within the bytes the reader may read of
		// one image: the bound is what it met, and the record says so.
		return structureBound("an inline image's data past %d bytes", maxInlineImageBytes)
	}
	if err != nil {
		return err
	}
	if at, ok := inlineImageEnds(data, start+end); ok {
		lex.pos = at
		return nil
	}
	return errInlineImageEnd
}

// An inline image whose end the reader cannot place. Each fails the page it
// lies on: the operators after the image cannot be found, so what the page
// shows after it is not known.
var (
	errInlineImageUnended   = errors.New("an inline image's dictionary does not reach the data it describes")
	errInlineImageEnd       = errors.New("an inline image's data does not end where the image says it does")
	errInlineImageUnframed  = errors.New("an inline image is encoded by a filter whose data the reader cannot measure or frame")
	errInlineImageDisagrees = errors.New("an inline image's dictionary declares a key twice with values that disagree")
)

// readInlineImage reads the dictionary between BI and ID, leaving the lexer
// on the byte after "ID", and returns what it says about where the data ends.
// Nothing of a value the reader has no use for is held: one image's
// dictionary is bounded in objects and in the memory its values cost.
func (it *interp) readInlineImage(lex *lexer) (inlineImage, error) {
	// Dictionary values are built within the space the page's operands
	// leave. Retained declarations and temporary values spend one allowance;
	// no value past the bound is built before it is refused.
	room := &allowance{left: maxOperandBytes - it.operandBytes, past: errOperandBudget}
	previousRoom := lex.room
	lex.reserving(room)
	defer func() { lex.room = previousRoom }()
	p := &parser{lex: lex, contentMode: true, inlineImage: true, allow: room}
	// The bytes of the dictionary are read strictly, a byte that begins no
	// token included; the content after the image is read as content again.
	lex.strict = true
	defer func() { lex.strict = false }()
	img := inlineImage{declared: -1}
	declared := map[Name]object{}
	var key Name
	var haveKey bool
	for objects := 0; ; objects++ {
		if objects > 2*maxOperands {
			return img, structureBound("an inline image's dictionary past %d objects", 2*maxOperands)
		}
		obj, err := p.parseObject(0)
		if err == nil {
			if !haveKey {
				name, ok := obj.(Name)
				if !ok {
					// A value where a key stands: what the pairs after it
					// are is not something this dictionary says.
					return img, errInlineImageUnended
				}
				key, haveKey = name, true
				continue
			}
			haveKey = false
			if obj == nil {
				// A value written null is an entry the dictionary does not
				// have (7.3.9). It says nothing of its key -- so nothing of
				// where the data ends -- and nothing another writing of the
				// same key says can disagree with it.
				continue
			}
			name, bearsOnEnd := inlineImageKey(key)
			if bearsOnEnd {
				if before, again := declared[name]; again {
					if !sameDeclaration(name, before, obj) {
						return img, errInlineImageDisagrees
					}
					obj = inlineUsable(before, obj)
				}
				declared[name] = obj
			}
			img.set(name, obj)
			continue
		}
		kw, ok := err.(errKeyword)
		if !ok {
			if errors.Is(err, errUnexpectedEOF) {
				// The content ends inside the dictionary: the data never
				// begins, and the operators the page holds after the image
				// are not there to be read.
				return img, errInlineImageUnended
			}
			return img, err
		}
		switch kw.keyword {
		case "ID":
			if haveKey {
				// A key with no value: what the image says of that key is
				// not in the file, and the pair before ID is not one.
				return img, errInlineImageUnended
			}
			return img, nil
		default:
			// Any other keyword: an image that ended or began again before
			// its data began, or an operator where a key or a value stands.
			// Where ID is missing the bytes between are not the image's data,
			// and what the reader has read of them as a dictionary is not the
			// page's content either.
			return img, errInlineImageUnended
		}
	}
}

// inlineUsable is the writing of one value the reader can use, given two
// writings of it that say the same thing: the integer where either is one,
// since a dimension or a depth written as a real is no dimension or depth --
// and which of the two a dictionary wrote first says nothing about the image.
func inlineUsable(before, again object) object {
	if _, ok := again.(int64); ok {
		return again
	}
	if _, ok := before.(int64); ok {
		return before
	}
	return again
}

// inlineImageKey is the one name the reader keeps for a key of an inline
// image's dictionary, and whether that key bears on where the data ends.
// 8.9.7 abbreviates these keys, and a writer may use either spelling of each:
// they are one key, so an image that gives both says one thing or fails.
func inlineImageKey(key Name) (Name, bool) {
	switch key {
	case "W", "Width":
		return "W", true
	case "H", "Height":
		return "H", true
	case "BPC", "BitsPerComponent":
		return "BPC", true
	case "CS", "ColorSpace":
		return "CS", true
	case "F", "Filter":
		return "F", true
	case "DP", "DecodeParms":
		return "DP", true
	case "L", "Length":
		return "L", true
	case "IM", "ImageMask":
		return "IM", true
	case "D", "Decode":
		return "D", false
	case "I", "Interpolate":
		return "I", false
	}
	return key, false
}

// inlineColourNames and inlineFilterNames are the abbreviations 8.9.7 allows
// an inline image, each under the name it stands for. A value written one way
// and then the other is one value written twice, not two values.
var inlineColourNames = map[Name]Name{
	"G": "DeviceGray", "RGB": "DeviceRGB", "CMYK": "DeviceCMYK", "I": "Indexed",
}

// inlineDeviceColourNames are the three of those a colour space may be
// written as on its own. /I is not among them: Indexed is a family written as
// an array, so a bare /I or a bare /Indexed is the name of one of the
// resources in force, and a resource's name is the name it was given.
var inlineDeviceColourNames = map[Name]Name{
	"G": "DeviceGray", "RGB": "DeviceRGB", "CMYK": "DeviceCMYK",
}

var inlineFilterNames = map[Name]Name{
	"AHx": "ASCIIHexDecode", "A85": "ASCII85Decode", "LZW": "LZWDecode",
	"Fl": "FlateDecode", "RL": "RunLengthDecode", "CCF": "CCITTFaxDecode",
	"DCT": "DCTDecode",
}

// sameDeclaration reports whether two values an inline image's dictionary
// declared for one key say the same thing. What a key means is compared and
// not how it was written: the abbreviations of a colour space or a filter
// stand for the names they abbreviate, one filter is one filter whether it is
// written alone or in an array of one, and the parameters of one filter are
// its parameters written either way.
func sameDeclaration(key Name, a, b object) bool {
	return sameValue(inlineDeclared(key, a), inlineDeclared(key, b))
}

// inlineDeclared is one of an inline image's values under the one form the
// reader compares it in.
func inlineDeclared(key Name, v object) object {
	switch key {
	case "CS":
		return inlineColourValue(v)
	case "F":
		v = inlineNamesOf(v, inlineFilterNames)
		if name, ok := v.(Name); ok {
			return Array{name}
		}
	case "DP":
		if dict, ok := v.(Dict); ok {
			return Array{dict}
		}
	}
	return v
}

// inlineColourValue is a colour space under the one form the reader compares
// it in. A name is normalised by where it stands, as the measurement reads
// it: at the head of an array it names a family, and 8.9.7 abbreviates four
// of those; standing alone it is a device space under either spelling, or
// else the name of a resource, which abbreviates nothing. Two images naming
// two resources name two colour spaces however alike the names look.
//
// A colour space stands at the name written alone, at the family at the head
// of an array, and at the positions such an array gives a colour space of its
// own -- the base of an Indexed space and the alternate of a Separation or a
// DeviceN one -- and those are the only ones rewritten here. An array of one
// element is that device space written another way where the element the
// image wrote is a device family's name -- a device space takes no parameters
// (8.6.4) -- and is not unwrapped otherwise: an array whose element is itself
// an array has no name at its family position at all, and is no writing of
// the space that array would be; a family that does take parameters, written
// alone, is a space missing what it needs; and a resource's name is not a
// family. Everything else an array holds after its family is that family's
// parameters and is compared as the image wrote it: a colourant's name, a
// tint transformation, a hival, a lookup table, and a name at a nested
// family's position that is no family of one.
//
// Nothing bounds the recursion here but the nesting the parser admits,
// maxNesting, as in sameValue: a value the parser read is a value this can
// rewrite.
func inlineColourValue(v object) object {
	switch x := v.(type) {
	case Name:
		if full, ok := inlineDeviceColourNames[x]; ok {
			return full
		}
	case Array:
		if len(x) == 1 {
			if name, ok := x[0].(Name); ok {
				if _, device := inlineDeviceComponents[name]; device {
					if full, ok := inlineDeviceColourNames[name]; ok {
						return full
					}
					return name
				}
			}
		}
		out := make(Array, len(x))
		copy(out, x)
		if len(out) > 0 {
			if name, ok := x[0].(Name); ok {
				if full, ok := inlineColourNames[name]; ok {
					name = full
				}
				out[0] = name
				if at, nested := inlineNestedColourSpaces[name]; nested && at < len(out) {
					out[at] = inlineColourValue(out[at])
				}
			}
		}
		return out
	}
	return v
}

// inlineNestedColourSpaces are the families that hold a colour space among
// their parameters, and the position it stands at: the base space of an
// Indexed space (8.6.6.3), and the alternate space of a Separation (8.6.6.4)
// or a DeviceN one (8.6.6.5). A space standing there is a colour space in its
// own right and is read as one, under the same rule as at the top. The other
// positions of those arrays are not colour spaces and are left as written.
var inlineNestedColourSpaces = map[Name]int{
	"Indexed": 1, "Separation": 2, "DeviceN": 2,
}

// inlineNamesOf is v with every name it holds written as the table writes it.
func inlineNamesOf(v object, table map[Name]Name) object {
	switch x := v.(type) {
	case Name:
		if full, ok := table[x]; ok {
			return full
		}
	case Array:
		out := make(Array, len(x))
		for i, item := range x {
			out[i] = inlineNamesOf(item, table)
		}
		return out
	}
	return v
}

// sameValue reports whether two values are the same value, to the bottom of
// whatever they hold. Nothing bounds the recursion here but the nesting the
// parser admits, maxNesting, which is what an inline image's dictionary can
// carry at all: two values the parser read are two values this can compare,
// and identical values are equal however deep they go.
func sameValue(a, b object) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case int64:
		// A number is a number: 1 and 1.0 are one value written two ways.
		switch y := b.(type) {
		case int64:
			return x == y
		case float64:
			return sameIntegerAndReal(x, y)
		}
		return false
	case float64:
		switch y := b.(type) {
		case int64:
			return sameIntegerAndReal(y, x)
		case float64:
			return x == y
		}
		return false
	case Name:
		y, ok := b.(Name)
		return ok && x == y
	case String:
		y, ok := b.(String)
		return ok && bytes.Equal(x, y)
	case Array:
		y, ok := b.(Array)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !sameValue(x[i], y[i]) {
				return false
			}
		}
		return true
	case Dict:
		y, ok := b.(Dict)
		if !ok {
			return false
		}
		// An entry written null is an entry the dictionary does not have
		// (7.3.9), at whatever depth it stands: two dictionaries that differ
		// by one of them are the same dictionary, so the members are
		// compared by name and a name only one of them has must be null
		// there. The lengths are not compared, since they count what is
		// written and not what is said.
		for k, v := range x {
			if !sameValue(v, y[k]) {
				return false
			}
		}
		for k, w := range y {
			if _, has := x[k]; !has && !sameValue(nil, w) {
				return false
			}
		}
		return true
	}
	return false
}

// sameIntegerAndReal reports whether an integer and a real are one value. A
// real is that integer where it is a whole number within the integers and
// stands at it: the two are compared as integers and not as float64, since a
// float64 holds whole numbers only to 2^53 and reading the integer as one
// would make 9,007,199,254,740,993 the same value as 9,007,199,254,740,992.0
// -- two declarations the dictionary really did write differently. A real
// past the integers, or with a fraction, or no number at all, is no writing
// of any integer.
func sameIntegerAndReal(i int64, f float64) bool {
	if f != math.Trunc(f) || f < math.MinInt64 || f >= -math.MinInt64 {
		return false
	}
	return int64(f) == i
}

// inlineImage is what an inline image's dictionary says about how long its
// data is, under the one name the reader keeps for each key.
type inlineImage struct {
	// declared is /L. It is no boundary -- nothing below reads it to find the
	// end -- but an image that states two different lengths states two things
	// about itself, which readInlineImage refuses.
	declared      int64
	width, height int64
	bpc           int64
	// colorSpace is /CS as the image wrote it: a name of a colour space, a
	// colour space in place, or the name of one of the resources in force.
	colorSpace object
	// parms is /DP, which says how the first filter was applied.
	parms object
	// filter is the name of the first filter, and filtered says whether the
	// image declares one at all: a filter the reader cannot name is still a
	// filter, and its samples are not the length of the data.
	filter   Name
	filtered bool
	mask     bool
	// bpcGiven says the dictionary declared a depth, whatever it declared:
	// an image mask may leave the depth out, and one that writes 0 has
	// written a depth no sample has rather than left it out.
	bpcGiven bool
}

// set records what one member of an inline image's dictionary says, under the
// name the reader keeps for its key.
func (img *inlineImage) set(key Name, v object) {
	switch key {
	case "L":
		if n, ok := v.(int64); ok {
			img.declared = n
		}
	case "W":
		if n, ok := v.(int64); ok {
			img.width = n
		}
	case "H":
		if n, ok := v.(int64); ok {
			img.height = n
		}
	case "BPC":
		// A depth the image gives as anything but an integer is no depth:
		// -1 stands for one the reader cannot use. Whether the image gave a
		// depth at all is kept apart from what it gave, since 0 is a depth a
		// dictionary can write and no depth a sample has.
		img.bpc, img.bpcGiven = -1, true
		if n, ok := v.(int64); ok {
			img.bpc = n
		}
	case "IM":
		if b, ok := v.(bool); ok {
			img.mask = b
		}
	case "DP":
		img.parms = v
	case "F":
		switch f := v.(type) {
		case Name:
			img.filtered, img.filter = true, f
		case Array:
			img.filtered = len(f) > 0
			if len(f) > 0 {
				if name, ok := f[0].(Name); ok {
					img.filter = name
				}
			}
		}
	case "CS":
		img.colorSpace = v
	}
}

// inlineDataEnds is where the image's own encoding puts the end of its data:
// the offsets from the start of the data at which "EI" may stand. An image no
// filter encodes is measured from its samples, and an encoded one is framed
// by its first filter. An image that is neither, and one whose framing met a
// bound or found no end of its own, is an error: the reader cannot say where
// it ends, and a page whose image ends nowhere is a page it cannot read.
func (it *interp) inlineDataEnds(img inlineImage, resources Dict, data []byte) (int, error) {
	if !img.filtered {
		n := img.sampleBytes(it.d.inlineColorComponents(img.colorSpace, resources, 0))
		switch {
		case n < 0:
			return 0, errInlineImageUnframed
		case n > maxInlineImageBytes:
			return 0, structureBound("an inline image's data past %d bytes", maxInlineImageBytes)
		}
		return int(n), nil
	}
	end, err := it.d.filterFraming(img.filter, img.parms, data)
	switch {
	case errors.Is(err, errFilterNotFramed):
		return 0, errInlineImageUnframed
	case err != nil:
		// The encoding's own defect, a bound met framing it, or data that
		// ends nowhere: the page's problem, and no reason to read the
		// image's end some other way. The caller tells a bound on what it
		// handed over from data that simply ends.
		return 0, err
	}
	return end, nil
}

// inlineDeviceComponents is how many colour components one sample has in the
// colour spaces an inline image may name on its own, abbreviated as 8.9.7
// abbreviates them. Every other colour space is written as an array -- its
// family and what the family needs -- or is the name of one of the resources
// in force: a bare /CalGray is the name of a resource, and what that resource
// holds is what says how many components its samples have.
var inlineDeviceComponents = map[Name]int64{
	"G": 1, "DeviceGray": 1,
	"RGB": 3, "DeviceRGB": 3,
	"CMYK": 4, "DeviceCMYK": 4,
}

// maxColorSpaceDepth bounds how far the reader follows a colour space through
// the resources that name it, and maxColorComponents the components one
// sample may have: 8.6.6.5 gives a DeviceN space up to 32 colourants, and no
// other space of the specification has more.
const (
	maxColorSpaceDepth = 4
	maxColorComponents = 32
)

// inlineColorComponents is how many colour components one sample of the image
// has, or 0 where the document does not say. A name is a colour space in its
// own right, or one the /ColorSpace dictionary of the resources in force --
// the page's, or the form's where the image is drawn in one -- declares; a
// colour space written in place is read from its family, ICCBased from the /N
// of its stream and DeviceN from the names it separates.
func (d *Document) inlineColorComponents(cs object, resources Dict, depth int) int64 {
	// Sizing a colour space is one read: the space, the resources that name
	// it and the stream or array it stands for are read under one
	// cross-reference. See beginRead.
	defer d.beginRead()()
	if cs == nil || depth > maxColorSpaceDepth {
		return 0
	}
	switch v := d.resolve(cs).(type) {
	case Name:
		if n, ok := inlineDeviceComponents[v]; ok {
			return n
		}
		spaces := d.dictOf(resources["ColorSpace"])
		if spaces == nil {
			return 0
		}
		named, ok := spaces[v]
		if !ok {
			return 0
		}
		return d.inlineColorComponents(named, resources, depth+1)
	case Array:
		if len(v) == 0 {
			return 0
		}
		family, ok := d.nameOf(v[0])
		if !ok {
			return 0
		}
		switch family {
		case "CalGray":
			return 1
		case "CalRGB", "Lab":
			return 3
		case "I", "Indexed", "Separation":
			return 1
		case "ICCBased":
			if len(v) < 2 {
				return 0
			}
			s, ok := d.resolve(v[1]).(*stream)
			if !ok {
				return 0
			}
			// 8.6.5.5 gives /N three values and no others: 1, 3 or 4, the
			// components of the space the profile is of. A stream declaring
			// any other count -- 2, 5, 32, no number, or a real such as 3.0,
			// since a count of components is written as an integer -- has
			// declared a packing no ICCBased space has, and how long the
			// samples of an image in it are is not something the file says.
			// Such an image is not measured, and the page fails rather than
			// the record carrying a reading recovered from a count the
			// specification does not give.
			if n, ok := d.resolve(s.dict["N"]).(int64); ok && (n == 1 || n == 3 || n == 4) {
				return n
			}
		case "DeviceN":
			if len(v) < 2 {
				return 0
			}
			if names := d.arrayOf(v[1]); len(names) >= 1 && len(names) <= maxColorComponents {
				return int64(len(names))
			}
		default:
			if n, ok := inlineDeviceComponents[family]; ok && len(v) == 1 {
				return n
			}
		}
	}
	return 0
}

// sampleBytes is how many bytes the image's samples take, given how many
// colour components one of them has, or -1 where the dictionary does not say:
// no width, no height, no colour space the reader could size, or a bit depth
// that is none of the depths a sample has. A row is whole bytes, as 8.9.7 has
// it, and an image mask is one component of one bit.
func (img inlineImage) sampleBytes(components int64) int64 {
	if img.width <= 0 || img.height <= 0 {
		return -1
	}
	bits := img.bpc
	if img.mask {
		// A mask's samples are one bit of one component (Table 89). A mask
		// that says its depth says one, or says nothing.
		if img.bpcGiven && bits != 1 {
			return -1
		}
		components, bits = 1, 1
	}
	// Every other image says its depth, and says one of the depths 8.9.5
	// gives: nothing here is assumed of an image that does not.
	if components < 1 || components > maxColorComponents || (bits != 1 && bits != 2 && bits != 4 && bits != 8 && bits != 16) {
		return -1
	}
	// The bound is on the bytes the image's samples take, which is what the
	// packing above gives: a row of samples one bit wide is an eighth of the
	// bytes a row of the same width eight bits wide is, and an image is past
	// the bound when its bytes are and not when its pixels are. Each step is
	// bounded before it is taken, the components and the depth being bounded
	// above, so nothing here approaches where an int64 ends.
	if img.width > maxInlineImageBytes*8/(components*bits) {
		return maxInlineImageBytes + 1
	}
	row := (img.width*components*bits + 7) / 8
	if row < 1 || img.height > maxInlineImageBytes/row {
		return maxInlineImageBytes + 1
	}
	return row * img.height
}

// inlineImageEnds reports whether an inline image's data ends at the offset
// given -- white space or a comment, which 7.2.3 counts as white space, then
// "EI" as a token of its own -- and where the content after it resumes.
func inlineImageEnds(data []byte, at int) (int, bool) {
	if at < 0 || at > len(data) {
		return 0, false
	}
	lex := newLexer(data, at)
	lex.skipSpace()
	at = lex.pos
	if at+2 > len(data) || data[at] != 'E' || data[at+1] != 'I' {
		return 0, false
	}
	if at+2 < len(data) && !isWhitespace(data[at+2]) && !isDelimiter(data[at+2]) {
		return 0, false
	}
	return at + 2, true
}
