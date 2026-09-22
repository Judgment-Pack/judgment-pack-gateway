package pdf

import (
	"sort"
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
	// stop reports whether the deadline has passed, on the cadence the
	// document reads it; it is nil for a CMap read with no deadline.
	stop func() bool
	// The indexes, built once the CMap is read, find the first cid range and
	// the first unicode range of a code's own length that holds it; shortest
	// is the shortest code length declared, or 4. The codespace ranges are
	// matched in the order they were declared, at most maxCodespaces of them,
	// since a range is a range of each byte and not of the code as one
	// number.
	cidIndex, uniIndex [5]firstSpans
	shortest           int
	// declaredCodespaces says the CMap declared codespace ranges of its own,
	// as against the one this reader infers for a map that declares none: an
	// inferred range is the reader's reading of what the map holds, and a
	// font borrowing ranges borrows only what was declared.
	declaredCodespaces bool
	// established says the parse found an encoding at all: a codespace range
	// or a mapping. A CMap that found neither -- no bytes, bytes that hold no
	// operator of the syntax, or a begincmap and an endcmap with nothing
	// between them -- says nothing about how a string splits into codes or
	// what its codes stand for, and a font whose own encoding it is has an
	// encoding the reader cannot use.
	established bool
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
// one CMap may, is not used: parseCMap returns nil. So is one the deadline
// passed while reading, which stop reports: a CMap read in part maps some of
// a font's codes and not others, and a reader that used it would carry text
// the deadline decided rather than text the page shows.
func parseCMap(data []byte, budget *fontBudget, stop func() bool) *cmap {
	c := &cmap{cid: map[code]uint32{}, unicode: map[code][]rune{}, budget: budget, stop: stop}
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
				// A CMap the parser could not read to the end of is read as
				// far as it goes, and that is what it says -- except at a
				// bound, which is not damage to read past: a CMap past a
				// bound is not used at all, and the glyphs it would have
				// mapped are unmapped and counted. What was charged for it
				// stays charged.
				c.boundIf(err)
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
				return c.parsed()
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
	return c.parsed()
}

// parsed is the CMap a parse yielded: what it declared, with a codespace
// range inferred where it declared none, and whether it established an
// encoding at all. A parse that ended at endcmap and one whose bytes ran out
// end the same way -- a CMap declaring no codespace range says nothing about
// how long its codes are, and four bytes is no reading of it.
func (c *cmap) parsed() *cmap {
	// What the CMap established is what it holds that a code can be looked up
	// in -- a codespace range it declared, a range of codes it maps, a single
	// code it maps -- and not what it was given to read: an entry the parser
	// read and the reader could not use maps nothing, and a map of nothing
	// establishes no encoding, however many entries were charged for.
	established := c.declaredCodespaces || len(c.cidRanges) > 0 || len(c.uniRanges) > 0 || len(c.cid) > 0 || len(c.unicode) > 0
	if len(c.codespaces) == 0 {
		c.codespaces = inferredCodespaces(c)
	}
	out := c.finish()
	if out != nil {
		out.established = established
	}
	return out
}

// inferredCodespaces is how a CMap that declares no codespace range of its
// own splits a string into codes: by the sources it maps, every one of them --
// the ranges and the single codes alike, since a code is its bytes and how
// many of them it has and a mapping is for codes of one length.
//
// A map whose sources are all of one length is read at that length whatever
// the bytes are, which is the reading the specification's own embedded maps
// make of themselves, and a map holding no mapping at all is read at two
// bytes, which is what those maps declare where they declare anything. Where
// the sources are of several lengths, no one length is the map's reading of a
// string: each length is given the codes it actually maps, so that the
// lengths stand beside one another where the bytes let them -- and where they
// do not, the ranges are ambiguous and finish does not use the map, since
// which length a code beginning with those bytes has is then not something
// the map says.
func inferredCodespaces(c *cmap) []codespace {
	var mapped [5][]codeRun
	lengths := 0
	add := func(nbytes int, lo, hi uint32) {
		if nbytes < 1 || nbytes > 4 || hi < lo {
			return
		}
		if len(mapped[nbytes]) == 0 {
			lengths++
		}
		mapped[nbytes] = append(mapped[nbytes], codeRun{lo, hi})
	}
	for _, ranges := range [][]cmapRange{c.uniRanges, c.cidRanges} {
		for _, r := range ranges {
			add(r.nbytes, r.lo, r.hi)
		}
	}
	for key := range c.cid {
		add(key.nbytes, key.value, key.value)
	}
	for key := range c.unicode {
		add(key.nbytes, key.value, key.value)
	}
	switch lengths {
	case 0:
		return []codespace{fullCodespace(2)}
	case 1:
		for n := 1; n <= 4; n++ {
			if len(mapped[n]) > 0 {
				return []codespace{fullCodespace(n)}
			}
		}
	}
	var out []codespace
	for n := 1; n <= 4; n++ {
		out = append(out, codespacesCovering(n, mapped[n])...)
	}
	return out
}

// codeRun is a run of codes of one length, read as numbers: what one mapping
// of the CMap covers.
type codeRun struct{ lo, hi uint32 }

// maxInferredCodespaces bounds the ranges inferred for one code length, so
// that the four lengths together declare no more than one CMap may.
const maxInferredCodespaces = maxCodespaces / 4

// codespacesCovering is the codespace ranges of nbytes bytes that hold the
// codes given: the runs are put in order and joined where they meet, and each
// run is split where a byte carries, since a codespace range is a range of
// each byte and not of the code read as one number -- the codes from 00FF to
// 0100 are two ranges, where the one range 00 to 01 of a first byte beside FF
// to 00 of a second holds neither of them. The ranges hold what the map maps
// and no more, so that a length stands beside another without taking in the
// leading bytes the other's codes begin with.
//
// Where the runs of one length need more ranges than the reader holds for it,
// they are taken together, from the lowest code to the highest: the ranges
// then hold codes the map does not map, which is the one widening a reader
// that cannot hold them all can make.
func codespacesCovering(nbytes int, runs []codeRun) []codespace {
	if len(runs) == 0 {
		return nil
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].lo < runs[j].lo })
	joined := runs[:1]
	for _, r := range runs[1:] {
		last := &joined[len(joined)-1]
		if uint64(r.lo) <= uint64(last.hi)+1 {
			last.hi = max(last.hi, r.hi)
			continue
		}
		joined = append(joined, r)
	}
	var out []codespace
	for _, r := range joined {
		// Count the actual fragments: a run may cross several byte carries,
		// while a singleton still needs only one range. With at most four
		// bytes, this temporary split contains at most fifteen ranges.
		parts := appendCarrySplit(nil, codeBytes(r.lo, nbytes), codeBytes(r.hi, nbytes), 0)
		if len(out)+len(parts) > maxInferredCodespaces {
			low, high := joined[0].lo, joined[len(joined)-1].hi
			return appendCarrySplit(nil, codeBytes(low, nbytes), codeBytes(high, nbytes), 0)
		}
		out = append(out, parts...)
	}
	return out
}

// appendCarrySplit adds to out the codespace ranges holding every code from
// lo to hi and no other, the bytes of the two before at being equal, which
// the caller has made so. A byte position where the two differ is split into
// the low end's own run to the top of its byte, the bytes between the two
// taken whole, and the high end's run from the bottom of its byte: each of
// those is a range of each byte, which a run across a carry is not.
func appendCarrySplit(out []codespace, lo, hi []byte, at int) []codespace {
	n := len(lo)
	if at >= n-1 || lo[at] == hi[at] {
		if at < n-1 {
			return appendCarrySplit(out, lo, hi, at+1)
		}
		return append(out, codespaceOf(lo, hi))
	}
	ends := func(b []byte, from int, fill byte) []byte {
		out := append([]byte{}, b...)
		for i := from; i < n; i++ {
			out[i] = fill
		}
		return out
	}
	out = appendCarrySplit(out, lo, ends(lo, at+1, 0xFF), at+1)
	if hi[at]-lo[at] > 1 {
		between := ends(lo, at+1, 0x00)
		between[at] = lo[at] + 1
		top := ends(hi, at+1, 0xFF)
		top[at] = hi[at] - 1
		out = append(out, codespaceOf(between, top))
	}
	return appendCarrySplit(out, ends(hi, at+1, 0x00), hi, at+1)
}

// rangeMapsScalar reports whether a range of codes standing at the scalar
// values from dst upwards stands at any value a text can carry: the values a
// surrogate half has and those past the last of Unicode are no characters,
// and a range lying wholly among them maps nothing at all.
func rangeMapsScalar(dst, span uint32) bool {
	first, last := uint64(dst), uint64(dst)+uint64(span)
	if last > 0x10FFFF {
		last = 0x10FFFF
	}
	if first > last {
		return false
	}
	return first < 0xD800 || last > 0xDFFF
}

// codeBytes is a code of nbytes bytes written as its bytes, most significant
// first.
func codeBytes(v uint32, nbytes int) []byte {
	out := make([]byte, nbytes)
	for i := nbytes - 1; i >= 0; i-- {
		out[i] = byte(v)
		v >>= 8
	}
	return out
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
	out := codespacesCMap(c.codespaces)
	if out != nil {
		out.declaredCodespaces = c.declaredCodespaces
	}
	return out
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

// boundIf marks the CMap unusable where the error given is a bound of the
// parser: a CMap read no further than a bound is not used, wherever the
// bound was met -- in a section of it or at the outer parse -- as a CMap
// whose codespaces are ambiguous is not used. What it charged the font
// budget for is not given back: the reader did the reading.
func (c *cmap) boundIf(err error) bool {
	if err != nil && isBound(err) {
		c.unusable = true
		return true
	}
	return false
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
			c.boundIf(err)
			return
		}
		hi, err := p.parseObject(0)
		if err != nil {
			c.boundIf(err)
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
		c.declaredCodespaces = true
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
			c.boundIf(err)
			return
		}
		hi, err := p.parseObject(0)
		if err != nil {
			c.boundIf(err)
			return
		}
		dst, err := p.parseObject(0)
		if err != nil {
			c.boundIf(err)
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
				// A range whose destinations are no text a page can carry --
				// every code in it standing at a surrogate half or past the
				// last scalar value -- maps nothing, as a destination that is
				// no character maps nothing: it is not held, so its codes are
				// U+FFFD and counted, and a map holding only such ranges
				// establishes no encoding. What reading it cost is charged.
				if !rangeMapsScalar(uint32(d), h-l) {
					continue
				}
				c.uniRanges = append(c.uniRanges, cmapRange{nbytes: n, lo: l, hi: h, dst: uint32(d)})
			} else {
				c.cidRanges = append(c.cidRanges, cmapRange{nbytes: n, lo: l, hi: h, dst: uint32(d)})
			}
		case String:
			if !unicode || len(d) > maxCMapDestinationBytes {
				continue
			}
			// The entry is charged before its destination is read, as a
			// single mapping's is: the reader did the reading whether what it
			// read is text or not.
			if !c.takeN(cmapRangeEntries) {
				continue
			}
			runes := utf16Runes(d)
			if len(runes) == 0 || !c.takeN(destinationEntries(runes)) {
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
				if len(runes) > 0 {
					c.unicode[code{l + uint32(i), n}] = runes
				}
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
			c.boundIf(err)
			return
		}
		dst, err := p.parseObject(0)
		if err != nil {
			c.boundIf(err)
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
			// A destination of no characters -- an empty string, an odd
			// number of bytes, an unpaired surrogate -- is no text the code
			// stands for: the mapping is not held, so the glyph is U+FFFD and
			// counted, and a map holding no mapping establishes nothing. The
			// entry is charged for all the same.
			if unicode && len(d) <= maxCMapDestinationBytes {
				runes := utf16Runes(d)
				if c.takeN(1+destinationEntries(runes)) && len(runes) > 0 {
					c.unicode[key] = runes
				}
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

// utf16Runes decodes a ToUnicode destination, which 9.10.3 writes as
// UTF-16BE: an odd number of bytes is half a code unit, and half a code unit
// is no character, whether the odd byte stands alone or after whole ones.
func utf16Runes(b []byte) []rune {
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
