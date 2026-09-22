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
)

// codespace is one codespace range: the low and the high byte of each of the
// positions a code of nbytes bytes has. A code falls in the range when each
// of its bytes falls between the two bytes of its own position, which is what
// 9.7.6.2 says a codespace range is -- not when the code read as one number
// falls between the two endpoints, which would take <8130> for a code of
// <8140> <9FFC> and read the bytes after it as codes the page never shows.
type codespace struct {
	nbytes int
	lo, hi [4]byte
}

// codespaceOf is the range from lo to hi, whose length is the length of both,
// which the caller has checked is from one to four bytes.
func codespaceOf(lo, hi []byte) codespace {
	cs := codespace{nbytes: len(lo)}
	copy(cs.lo[:], lo)
	copy(cs.hi[:], hi)
	return cs
}

// fullCodespace is the range of every code of n bytes.
func fullCodespace(n int) codespace {
	cs := codespace{nbytes: n}
	for i := 0; i < n && i < len(cs.hi); i++ {
		cs.hi[i] = 0xFF
	}
	return cs
}

// prefix is how many of the range's leading bytes hold the head of s at their
// own positions: the range's own length when a whole code of it stands at the
// head of s, and fewer when a byte does not hold or s is shorter than the
// range is, which 9.7.6.3 calls a partial match.
func (cs codespace) prefix(s []byte) int {
	n := min(cs.nbytes, len(s))
	for i := 0; i < n; i++ {
		if s[i] < cs.lo[i] || s[i] > cs.hi[i] {
			return i
		}
	}
	return n
}

// code is one code of a CMap: its bytes, as a number, and how many bytes it
// has. 9.7.6.2 gives a mapping for codes of one length, so <41> and <0041>
// are two codes and not one, and the length is part of what names a mapping.
type code struct {
	value  uint32
	nbytes int
}

// cmap is a parsed CMap. Codes are up to four bytes.
type cmap struct {
	codespaces []codespace
	// single maps a code to a CID (cid maps) or to a string of runes
	// (unicode maps).
	cid     map[code]uint32
	unicode map[code][]rune
	// ranges map [lo, hi] to a starting CID or rune.
	cidRanges []cmapRange
	uniRanges []cmapRange
	vertical  bool
	// entries counts the mappings held, each charged to budget as it is
	// added; unusable is set when one would take either past its bound.
	entries  int
	budget   *fontBudget
	unusable bool
	// The indexes, built once the CMap is read, find the first cid range and
	// the first unicode range of a code's own length that holds it; shortest
	// is the shortest code length declared, or 4. The codespace ranges are
	// matched in the order they were declared, at most maxCodespaces of them,
	// since a range is a range of each byte and not of the code as one
	// number.
	cidIndex, uniIndex [5]firstSpans
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
	c := &cmap{codespaces: []codespace{fullCodespace(2)}, cid: map[code]uint32{}, unicode: map[code][]rune{}, cidRanges: []cmapRange{{nbytes: 2, lo: 0, hi: 0xFFFF, dst: 0}}}
	return c.finish()
}

// parseCMap reads a CMap from its bytes, charging each mapping it holds to
// the document's font budget. Errors in the syntax end the parse with what
// was read so far. A CMap that would hold more mappings than one CMap may,
// or than the budget has left, or that declares more codespace ranges than
// one CMap may, is not used: parseCMap returns nil.
func parseCMap(data []byte, budget *fontBudget) *cmap {
	c := &cmap{cid: map[code]uint32{}, unicode: map[code][]rune{}, budget: budget}
	lex := newLexer(data, 0)
	p := &parser{lex: lex, contentMode: true}
	var stack []object
	for !c.unusable {
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
	if c.unusable {
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
		c.codespaces = []codespace{fullCodespace(n)}
	}
	return c.finish()
}

// finish indexes what the CMap holds, and returns it; or nil when it met a
// bound.
func (c *cmap) finish() *cmap {
	if c.unusable {
		return nil
	}
	if ambiguousCodespaces(c.codespaces) {
		// Two ranges of different lengths whose leading bytes hold the same
		// codes: what length a code beginning there has is not something this
		// CMap says, and the reader would be choosing by declaration order.
		// The CMap is not used, as one past a bound is not: the glyphs it
		// would have mapped are unmapped, and the record counts them.
		return nil
	}
	c.shortest = 4
	for _, cs := range c.codespaces {
		c.shortest = min(c.shortest, cs.nbytes)
	}
	for n := 1; n <= 4; n++ {
		c.cidIndex[n] = indexRanges(c.cidRanges, n)
		c.uniIndex[n] = indexRanges(c.uniRanges, n)
	}
	return c
}

// ambiguousCodespaces reports whether two ranges of different code lengths
// hold the same leading bytes, which 9.7.6.2 does not admit: a code beginning
// with those bytes would be as long as one range says and as long as the
// other says. Ranges of one length may overlap without ambiguity -- a code in
// both is the same code either way -- and a range declared twice says one
// thing twice.
func ambiguousCodespaces(spaces []codespace) bool {
	for i, a := range spaces {
		for _, b := range spaces[i+1:] {
			if a.nbytes == b.nbytes || a.nbytes == 0 || b.nbytes == 0 {
				continue
			}
			shared := min(a.nbytes, b.nbytes)
			overlap := true
			for k := 0; k < shared && overlap; k++ {
				overlap = a.lo[k] <= b.hi[k] && b.lo[k] <= a.hi[k]
			}
			if overlap {
				return true
			}
		}
	}
	return false
}

// codespacesOnly is a CMap that splits a string into codes the way c does
// and maps none of them: what one CMap declares of the lengths its codes
// have, for a font whose own encoding CMap the reader does not carry.
func (c *cmap) codespacesOnly() *cmap {
	return codespacesCMap(c.codespaces)
}

// twoByteCodespaces splits a string into codes of two bytes and maps none of
// them: what is left of an encoding CMap the reader does not carry when the
// font declares no codespace range anywhere either. It maps none, where
// Identity-H maps a code to the CID of the same number, because a code of a
// CMap the reader does not carry stands for a CID only that CMap knows: a
// width taken at the code's own number would be some other glyph's.
func twoByteCodespaces() *cmap {
	return codespacesCMap([]codespace{fullCodespace(2)})
}

// codespacesCMap is a CMap of the codespace ranges given and no mappings.
func codespacesCMap(spaces []codespace) *cmap {
	out := &cmap{codespaces: spaces, cid: map[code]uint32{}, unicode: map[code][]rune{}}
	return out.finish()
}

// indexRanges indexes the cid or unicode ranges whose codes have n bytes, in
// the order they were read. A range of another length holds none of these
// codes: a code is the bytes it has, and a mapping is for codes of one length.
func indexRanges(ranges []cmapRange, n int) firstSpans {
	var spans []span
	for i, r := range ranges {
		if r.nbytes == n {
			spans = append(spans, span{lo: r.lo, hi: r.hi, order: int32(i)})
		}
	}
	return indexSpans(spans)
}

// take charges one mapping, and reports whether the CMap may hold it.
func (c *cmap) take() bool {
	c.entries++
	if c.entries > maxCMapEntries || !c.budget.take(1) {
		c.unusable = true
	}
	return !c.unusable
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
		if len(hs) != len(ls) {
			// The two ends of a range have the same number of bytes, which is
			// how many bytes the codes in it have. A pair whose ends differ
			// declares no range: read as one it would hold codes of a length
			// neither end gives. The pairs after it are still read, since the
			// two objects of this one were read whole.
			continue
		}
		if len(c.codespaces) == maxCodespaces {
			c.unusable = true
			return
		}
		c.codespaces = append(c.codespaces, codespaceOf(ls, hs))
	}
}

func (c *cmap) readRanges(p *parser, unicode bool) {
	for !c.unusable {
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
			if d < 0 || d > 1<<31 || !c.take() {
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
			if len(runes) == 0 || !c.take() {
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
				if !c.take() {
					break
				}
				c.unicode[code{l + uint32(i), n}] = utf16Runes(s)
			}
		default:
			return
		}
	}
}

func (c *cmap) readChars(p *parser, unicode bool) {
	for !c.unusable {
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
		v, n := bytesToCode(ss)
		key := code{v, n}
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
				c.unicode[key] = []rune{rune(d)}
			} else {
				c.cid[key] = uint32(d)
			}
		case String:
			if unicode && len(d) <= maxCMapDestinationBytes && c.take() {
				c.unicode[key] = utf16Runes(d)
			}
		case Name:
			if unicode {
				if r, ok := glyphToRune(string(d)); ok && c.take() {
					c.unicode[key] = []rune{r}
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
	return utf16.Decode(units)
}

// nextCode reads one code from the head of s by the codespace ranges,
// returning the code, its byte length, and whether it fell in a range. The
// ranges are matched byte by byte in the order they were declared, the first
// that holds the head winning; a CMap declares at most maxCodespaces of them,
// so the scan is bounded whatever the CMap holds.
//
// A head in no range is a code the CMap does not declare, and how many bytes
// of it to consume is the partial match of 9.7.6.3: the range that holds the
// longest run of leading bytes decides, and among ranges that hold the same
// run the shortest code length does. Where no range holds even the first
// byte, the shortest length declared is taken, one byte when none is. Those
// bytes are consumed as one code and not read again as codes of their own,
// and the code is reported as holding in no range: what its number would mean
// in a mapping is not what the page shows.
func (c *cmap) nextCode(s []byte) (code uint32, n int, ok bool) {
	if len(s) == 0 {
		return 0, 0, false
	}
	longest, partial := -1, 0
	for i, cs := range c.codespaces {
		if cs.nbytes == 0 {
			continue
		}
		p := cs.prefix(s)
		if p == cs.nbytes {
			// A whole code of this range stands at the head of s. The first
			// range declared that holds it wins, whatever the ranges after it
			// hold.
			v, _ := bytesToCode(s[:cs.nbytes])
			return v, cs.nbytes, true
		}
		if p > partial || (p == partial && longest >= 0 && cs.nbytes < c.codespaces[longest].nbytes) {
			longest, partial = i, p
		}
	}
	n = c.shortest
	if partial > 0 {
		n = c.codespaces[longest].nbytes
	}
	if n > len(s) {
		n = len(s)
	}
	if n < 1 {
		n = 1
	}
	v, _ := bytesToCode(s[:n])
	return v, n, false
}

// toCID maps a code of n bytes to a CID through the cid mappings of that
// length.
func (c *cmap) toCID(v uint32, n int) (uint32, bool) {
	if cid, ok := c.cid[code{v, n}]; ok {
		return cid, true
	}
	if n < 1 || n > 4 {
		return 0, false
	}
	if i, ok := c.cidIndex[n].find(v); ok {
		r := c.cidRanges[i]
		return r.dst + (v - r.lo), true
	}
	return 0, false
}

// toUnicode maps a code of n bytes to runes through the unicode mappings of
// that length.
func (c *cmap) toUnicode(v uint32, n int) ([]rune, bool) {
	if rs, ok := c.unicode[code{v, n}]; ok {
		return rs, len(rs) > 0
	}
	if n < 1 || n > 4 {
		return nil, false
	}
	if i, ok := c.uniIndex[n].find(v); ok {
		r := c.uniRanges[i]
		if r.runes != nil {
			// The last character advanced by the code's distance from lo,
			// as the specification says. Past the scalar values it is no
			// character a text can carry, and the code maps nothing.
			last := r.runes[len(r.runes)-1] + rune(v-r.lo)
			if !validScalar(last) {
				return nil, false
			}
			// Made for this lookup: the range holds its destination once.
			rs := append([]rune(nil), r.runes...)
			rs[len(rs)-1] = last
			return rs, true
		}
		ru := rune(r.dst + (v - r.lo))
		if !validScalar(ru) {
			return nil, false
		}
		return []rune{ru}, true
	}
	return nil, false
}
