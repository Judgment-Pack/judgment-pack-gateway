package pdf

import (
	"unicode/utf16"
)

// A CMap maps byte codes to CIDs (an embedded encoding CMap) or to
// Unicode (a ToUnicode CMap). Both are the same PostScript-like syntax:
// codespace ranges say how many bytes a code has, and cidchar/cidrange or
// bfchar/bfrange say what a code means.

const (
	// maxCMapEntries bounds the mappings one CMap may hold: a CMap that
	// holds more is not used.
	maxCMapEntries = 1 << 20
	// maxCMapRange bounds one bfrange or cidrange's span.
	maxCMapRange = 1 << 16
	// maxCMapDestinationBytes bounds a bfchar or bfrange destination string,
	// as the specification does: a longer one maps nothing.
	maxCMapDestinationBytes = 512
	// maxCodespaces bounds the codespace ranges one CMap declares: a CMap
	// that declares more is not used.
	maxCodespaces = 256
	// cmapRangeEntries is what one bfrange or cidrange is charged against the
	// two bounds above. A range is held as its endpoints, its destination and
	// an index of the endpoints -- about seventy bytes, whatever its span --
	// rather than as a mapping for each code it spans, and a line of a stream
	// declares one. Charged a single entry, the ranges of one document would
	// come to close to three hundred megabytes held, which is the sort of
	// thing these bounds are for; charged four, to about seventy.
	cmapRangeEntries = 4
	// cmapEntryBytes is what one entry of the font budget stands for in the
	// values a CMap is read through: about what a mapping costs to hold, so
	// that the values built while it is read are bounded by the same budget
	// the mappings themselves are.
	cmapEntryBytes = 96
	// cmapRunsPerEntry is how many characters of a mapping's destination one
	// further entry covers. A destination is held as the characters it
	// decoded to, up to the two hundred and fifty-six a destination string may
	// carry, so a mapping is not one size: charging its characters as well
	// keeps what a document's fonts may hold within the same figure whatever
	// shape its mappings take.
	cmapRunsPerEntry = 8
)

// destinationEntries is what a mapping's destination is charged beyond the
// mapping itself: its characters, by the measure above.
func destinationEntries(runes []rune) int { return len(runes) / cmapRunsPerEntry }

type codespace struct {
	nbytes  int
	low, hi uint32
}

// cmap is a parsed CMap. Codes are up to four bytes.
type cmap struct {
	codespaces []codespace
	// single maps a code to a CID (cid maps) or to a string of runes
	// (unicode maps).
	cid     map[uint32]uint32
	unicode map[uint32][]rune
	// ranges map [lo, hi] to a starting CID or rune.
	cidRanges []cmapRange
	uniRanges []cmapRange
	vertical  bool
	// entries counts the mappings held, each charged to budget as it is
	// added; unusable is set when one would take either past its bound.
	entries  int
	budget   *fontBudget
	unusable bool
	// stop reports whether the deadline has passed, on the cadence the
	// document reads it; it is nil for a CMap read with no deadline.
	stop func() bool
	// The indexes, built once the CMap is read, find the first codespace of
	// each code length (1 to 4), cid range and unicode range that holds a
	// code; shortest is the shortest code length declared, or 4.
	codespaceIndex     [5]firstSpans
	cidIndex, uniIndex firstSpans
	shortest           int
}

type cmapRange struct {
	nbytes int
	lo, hi uint32
	dst    uint32
	// runes is a destination of more than one character, held once for the
	// whole range: code lo maps to it, and each later code to it with its
	// last character advanced by the code's distance from lo.
	runes []rune
}

// identityCMap is Identity-H: two-byte codes, CID = code.
func identityCMap() *cmap {
	c := &cmap{codespaces: []codespace{{nbytes: 2, low: 0, hi: 0xFFFF}}, cid: map[uint32]uint32{}, unicode: map[uint32][]rune{}, cidRanges: []cmapRange{{nbytes: 2, lo: 0, hi: 0xFFFF, dst: 0}}}
	return c.finish()
}

// parseCMap reads a CMap from its bytes, charging each mapping it holds to
// the document's font budget. Errors in the syntax end the parse with what
// was read so far. A CMap that would hold more mappings than one CMap may,
// or than the budget has left, or that declares more codespace ranges than
// one CMap may, is not used: parseCMap returns nil. So is one the deadline
// passed while reading, which stop reports: a CMap read in part maps some of
// a font's codes and not others, and a reader that used it would carry text
// the deadline decided rather than text the page shows.
func parseCMap(data []byte, budget *fontBudget, stop func() bool) *cmap {
	c := &cmap{cid: map[uint32]uint32{}, unicode: map[uint32][]rune{}, budget: budget, stop: stop}
	lex := newLexer(data, 0)
	// The values a CMap is read through -- an operand, a destination, an
	// array of them -- are built within what one CMap's mappings may hold,
	// counted in the bytes a mapping costs: a destination array of hundreds
	// of thousands of dictionaries is not built and then ignored.
	// What one CMap's mappings may hold, and never more than what the
	// document's fonts may still hold: the values a CMap is read through are
	// bounded by both.
	entries := maxCMapEntries
	if left := maxFontEntries - budget.used; left < entries {
		entries = left
	}
	room := &allowance{left: int64(entries) * cmapEntryBytes, past: errCMapBudget}
	lex.reserving(room)
	p := &parser{lex: lex, contentMode: true, allow: room}
	var stack []object
	// A value this CMap is read through that is past what it may hold ends
	// the reading of it where that ran out, and the CMap is abandoned rather
	// than kept with the mappings read so far: what it would map then is what
	// the bound decided, and a font is better without it than with half of
	// it. Every way out of this parse asks.
	abandoned := func() bool { return room.left == 0 }
	for !c.unusable {
		// Each step of this loop reads one object, and the sections it enters
		// read the deadline as they charge what they hold.
		if c.stopped() || abandoned() {
			return nil
		}
		obj, err := p.parseObject(0)
		if err != nil {
			var kw errKeyword
			if !asKeyword(err, &kw) {
				break
			}
			switch kw.keyword {
			case "begincodespacerange":
				c.readCodespaces(p)
			case "begincidrange":
				c.readRanges(p, false)
			case "beginbfrange":
				c.readRanges(p, true)
			case "begincidchar":
				c.readChars(p, false)
			case "beginbfchar":
				c.readChars(p, true)
			case "usecmap":
				// A predefined parent this reader does not carry; an
				// embedded one would need the resource. Nothing to do.
			case "endcmap":
				if abandoned() {
					return nil
				}
				return c.finish()
			case "def":
				if len(stack) >= 2 {
					if name, ok := stack[len(stack)-2].(Name); ok && name == "WMode" {
						if v, ok := stack[len(stack)-1].(int64); ok && v == 1 {
							c.vertical = true
						}
					}
				}
				stack = stack[:0]
			}
			if kw.keyword != "def" {
				stack = stack[:0]
			}
			continue
		}
		stack = append(stack, obj)
		if len(stack) > 32 {
			stack = stack[1:]
		}
	}
	if c.unusable || abandoned() {
		return nil
	}
	if len(c.codespaces) == 0 {
		// Infer the code length from the mappings: most embedded
		// ToUnicode maps declare <0000> <FFFF>; a map with none is read
		// with the widest source seen, and two bytes by default.
		n := 2
		for _, r := range c.uniRanges {
			if r.nbytes > 0 {
				n = r.nbytes
				break
			}
		}
		for _, r := range c.cidRanges {
			if r.nbytes > 0 {
				n = r.nbytes
				break
			}
		}
		if n == 1 {
			c.codespaces = []codespace{{nbytes: 1, low: 0, hi: 0xFF}}
		} else {
			c.codespaces = []codespace{{nbytes: n, low: 0, hi: 1<<(8*uint(n)) - 1}}
		}
	}
	return c.finish()
}

// finish indexes what the CMap holds, and returns it; or nil when it met a
// bound.
func (c *cmap) finish() *cmap {
	if c.unusable {
		return nil
	}
	c.shortest = 4
	var byLength [5][]span
	for i, cs := range c.codespaces {
		byLength[cs.nbytes] = append(byLength[cs.nbytes], span{lo: cs.low, hi: cs.hi, order: int32(i)})
		c.shortest = min(c.shortest, cs.nbytes)
	}
	for n := range byLength {
		c.codespaceIndex[n] = indexSpans(byLength[n])
	}
	c.cidIndex = indexRanges(c.cidRanges)
	c.uniIndex = indexRanges(c.uniRanges)
	return c
}

// indexRanges indexes cid or unicode ranges in the order they were read.
func indexRanges(ranges []cmapRange) firstSpans {
	spans := make([]span, len(ranges))
	for i, r := range ranges {
		spans[i] = span{lo: r.lo, hi: r.hi, order: int32(i)}
	}
	return indexSpans(spans)
}

// take charges one mapping, and reports whether the CMap may hold it.
func (c *cmap) take() bool { return c.takeN(1) }

// takeN charges n entries for one mapping, and reports whether the CMap may
// hold it. It is where the deadline is read while a CMap is parsed: a section
// of a million ranges never returns to the loop that reads each object, and
// every mapping it holds is charged here.
func (c *cmap) takeN(n int) bool {
	c.entries += n
	if c.entries > maxCMapEntries || !c.budget.take(n) || c.stopped() {
		c.unusable = true
	}
	return !c.unusable
}

// stopped reports whether the deadline has passed, and never that it has for
// a CMap read with none.
func (c *cmap) stopped() bool { return c.stop != nil && c.stop() }

// errCMapBudget is a CMap whose values are past what a document's fonts may
// hold. The CMap is not used, as one past any other of its bounds is not.
func errCMapBudget() error {
	return structureBound("a CMap's values past what a document's fonts may hold")
}

func asKeyword(err error, kw *errKeyword) bool {
	k, ok := err.(errKeyword)
	if ok {
		*kw = k
	}
	return ok
}

func bytesToCode(b []byte) (uint32, int) {
	if len(b) > 4 {
		b = b[:4]
	}
	var v uint32
	for _, x := range b {
		v = v<<8 | uint32(x)
	}
	return v, len(b)
}

func (c *cmap) readCodespaces(p *parser) {
	for {
		lo, err := p.parseObject(0)
		if err != nil {
			return
		}
		hi, err := p.parseObject(0)
		if err != nil {
			return
		}
		ls, ok1 := lo.(String)
		hs, ok2 := hi.(String)
		if !ok1 || !ok2 || len(ls) == 0 || len(ls) > 4 {
			return
		}
		if len(c.codespaces) == maxCodespaces {
			c.unusable = true
			return
		}
		l, n := bytesToCode(ls)
		h, _ := bytesToCode(hs)
		c.codespaces = append(c.codespaces, codespace{nbytes: n, low: l, hi: h})
	}
}

func (c *cmap) readRanges(p *parser, unicode bool) {
	for !c.unusable {
		// The deadline is read on the cadence of the entries examined, and
		// not of the entries kept: a section of a million entries the CMap
		// keeps none of is a section it read.
		if c.stopped() {
			c.unusable = true
			return
		}
		lo, err := p.parseObject(0)
		if err != nil {
			return
		}
		hi, err := p.parseObject(0)
		if err != nil {
			return
		}
		dst, err := p.parseObject(0)
		if err != nil {
			return
		}
		ls, ok1 := lo.(String)
		hs, ok2 := hi.(String)
		if !ok1 || !ok2 || len(ls) == 0 || len(ls) > 4 {
			return
		}
		l, n := bytesToCode(ls)
		h, _ := bytesToCode(hs)
		if h < l {
			continue
		}
		// A longer range is cut to the codes one range may span, lo
		// included: lo + maxCMapRange - 1 is the highest code it maps.
		if h-l >= maxCMapRange {
			h = l + maxCMapRange - 1
		}
		switch d := dst.(type) {
		case int64:
			if d < 0 || d > 1<<31 || !c.takeN(cmapRangeEntries) {
				continue
			}
			if unicode {
				c.uniRanges = append(c.uniRanges, cmapRange{nbytes: n, lo: l, hi: h, dst: uint32(d)})
			} else {
				c.cidRanges = append(c.cidRanges, cmapRange{nbytes: n, lo: l, hi: h, dst: uint32(d)})
			}
		case String:
			if !unicode || len(d) > maxCMapDestinationBytes {
				continue
			}
			runes := utf16Runes(d)
			if len(runes) == 0 || !c.takeN(cmapRangeEntries+destinationEntries(runes)) {
				continue
			}
			r := cmapRange{nbytes: n, lo: l, hi: h, dst: uint32(runes[0])}
			if len(runes) > 1 {
				r.runes = runes
			}
			c.uniRanges = append(c.uniRanges, r)
		case Array:
			if !unicode {
				continue
			}
			for i, item := range d {
				if int64(i) > int64(h-l) {
					break
				}
				s, ok := item.(String)
				if !ok || len(s) > maxCMapDestinationBytes {
					continue
				}
				runes := utf16Runes(s)
				if !c.takeN(1 + destinationEntries(runes)) {
					break
				}
				c.unicode[l+uint32(i)] = runes
			}
		default:
			return
		}
	}
}

func (c *cmap) readChars(p *parser, unicode bool) {
	for !c.unusable {
		if c.stopped() {
			c.unusable = true
			return
		}
		src, err := p.parseObject(0)
		if err != nil {
			return
		}
		dst, err := p.parseObject(0)
		if err != nil {
			return
		}
		ss, ok := src.(String)
		if !ok || len(ss) == 0 || len(ss) > 4 {
			return
		}
		code, _ := bytesToCode(ss)
		switch d := dst.(type) {
		case int64:
			if d < 0 || d > 1<<31 {
				continue
			}
			// A destination that is not a scalar value is no character a
			// text can carry: the code is left unmapped, so that the glyph
			// is U+FFFD and counted in unmapped, as a range whose advance
			// leaves the scalar values leaves it.
			if unicode && !validScalar(rune(d)) {
				continue
			}
			if !c.take() {
				continue
			}
			if unicode {
				c.unicode[code] = []rune{rune(d)}
			} else {
				c.cid[code] = uint32(d)
			}
		case String:
			if unicode && len(d) <= maxCMapDestinationBytes {
				runes := utf16Runes(d)
				if c.takeN(1 + destinationEntries(runes)) {
					c.unicode[code] = runes
				}
			}
		case Name:
			if unicode {
				if r, ok := glyphToRune(string(d)); ok && c.take() {
					c.unicode[code] = []rune{r}
				}
			}
		}
	}
}

// utf16Runes decodes a ToUnicode destination: UTF-16BE, with a lone byte
// read as a single code unit's low half.
func utf16Runes(b []byte) []rune {
	if len(b) == 1 {
		return []rune{rune(b[0])}
	}
	if len(b)%2 != 0 {
		return nil
	}
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		units = append(units, uint16(b[i])<<8|uint16(b[i+1]))
	}
	// Decode replaces unpaired surrogates with U+FFFD. Reject those mappings
	// first so the glyph is counted as unmapped, while a declared U+FFFD
	// remains a mapped character.
	for i := 0; i < len(units); i++ {
		u := units[i]
		if u >= 0xD800 && u <= 0xDBFF {
			if i+1 == len(units) || units[i+1] < 0xDC00 || units[i+1] > 0xDFFF {
				return nil
			}
			i++
		} else if u >= 0xDC00 && u <= 0xDFFF {
			return nil
		}
	}
	// Decode hands back a slice with room for sixty-four runes, which a
	// destination of one or two would hold for as long as the mapping is
	// held: a document's fonts may hold millions of mappings, so each keeps
	// a slice of exactly what it decoded and not the room Decode left.
	decoded := utf16.Decode(units)
	return append(make([]rune, 0, len(decoded)), decoded...)
}

// nextCode reads one code from the head of s by the codespace ranges,
// returning the code, its byte length, and whether it fell in a range. A
// byte sequence in no range consumes the shortest codespace length (one
// byte when none is declared), as the specification prescribes.
func (c *cmap) nextCode(s []byte) (code uint32, n int, ok bool) {
	// The first codespace declared that holds the head of s, of any length.
	first := -1
	for length := 1; length <= 4 && length <= len(s); length++ {
		v, _ := bytesToCode(s[:length])
		if i, found := c.codespaceIndex[length].find(v); found && (first < 0 || i < first) {
			first, code, n = i, v, length
		}
	}
	if first >= 0 {
		return code, n, true
	}
	// Partial match on the first byte decides the length, per 9.7.6.3;
	// this reader takes the shortest declared length.
	shortest := c.shortest
	if shortest > len(s) {
		shortest = len(s)
	}
	if shortest == 0 {
		shortest = 1
	}
	v, _ := bytesToCode(s[:shortest])
	return v, shortest, false
}

// toCID maps a code to a CID through the cid mappings.
func (c *cmap) toCID(code uint32) (uint32, bool) {
	if v, ok := c.cid[code]; ok {
		return v, true
	}
	if i, ok := c.cidIndex.find(code); ok {
		r := c.cidRanges[i]
		return r.dst + (code - r.lo), true
	}
	return 0, false
}

// toUnicode maps a code to runes through the unicode mappings.
func (c *cmap) toUnicode(code uint32) ([]rune, bool) {
	if v, ok := c.unicode[code]; ok {
		return v, len(v) > 0
	}
	if i, ok := c.uniIndex.find(code); ok {
		r := c.uniRanges[i]
		if r.runes != nil {
			// The last character advanced by the code's distance from lo,
			// as the specification says. Past the scalar values it is no
			// character a text can carry, and the code maps nothing.
			last := r.runes[len(r.runes)-1] + rune(code-r.lo)
			if !validScalar(last) {
				return nil, false
			}
			// Made for this lookup: the range holds its destination once.
			rs := append([]rune(nil), r.runes...)
			rs[len(rs)-1] = last
			return rs, true
		}
		ru := rune(r.dst + (code - r.lo))
		if !validScalar(ru) {
			return nil, false
		}
		return []rune{ru}, true
	}
	return nil, false
}
