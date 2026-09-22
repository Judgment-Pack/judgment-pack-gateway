package pdf

import (
	"iter"
	"math"
	"strings"
)

// font is what the interpreter needs of a font: how to split a string
// into codes, what each code means in Unicode, and how wide it is.
type font struct {
	composite bool
	// encoding maps codes to CIDs for a composite font; nil for Identity.
	encoding *cmap
	// toUnicode is the font's ToUnicode map, when it has one.
	toUnicode *cmap
	// simple maps a one-byte code to a rune for a simple font, with
	// mapped saying whether the code has a mapping at all.
	simple [256]rune
	mapped [256]bool
	// widths in text space units (1/1000 em) by code for a simple font.
	simpleWidths [256]float64
	// cidWidths by CID for a composite font, with defaultWidth for the rest.
	cidWidths    map[uint32]float64
	defaultWidth float64
	// type3 fonts have widths in glyph space, scaled by their matrix.
	type3        bool
	fontMatrix   [6]float64
	missingWidth float64
	vertical     bool
	// symbolic and noWidths help the space heuristic: a font that
	// declares no widths is measured as if every glyph were half an em.
	noWidths bool
	// encodingUnusable is a composite font whose own encoding CMap the reader
	// cannot use. Its bytes are split into two-byte codes so that the glyphs
	// can be counted, and every one of them is unmapped: which codes the page
	// shows is not something the file says.
	encodingUnusable bool
}

// glyph is one shown glyph: its runes (empty when unmapped), its code,
// its width in text space (already divided by 1000 for non-Type3), and
// whether it is a single-byte code 32 (the word-space code).
type glyph struct {
	runes    []rune
	width    float64
	isSpace  bool
	unmapped bool
}

const (
	maxFontCacheEntries = 4096
	// maxFontEntries bounds the width entries and CMap mappings all of a
	// document's fonts hold together. Each is charged as it is read; a /W or
	// a CMap that a charge would take past the bound is not used, and what
	// it charged before stays charged.
	maxFontEntries = 1 << 22
	// maxCIDWidths bounds the width entries one font's /W declares: a /W
	// that declares more is not used, and every glyph takes the default
	// width.
	maxCIDWidths = 1 << 18
	// maxWidthCID bounds the CIDs a /W entry names.
	maxWidthCID = 1 << 20
	// maxWidthRange bounds the CIDs one /W range spans.
	maxWidthRange = 1 << 16
)

// fontBudget counts the width entries and CMap mappings a document's fonts
// hold, up to maxFontEntries.
type fontBudget struct{ used int }

// take charges n entries, and reports whether they fit what is left; when
// they do not, nothing is charged.
func (b *fontBudget) take(n int) bool {
	if n < 0 || n > maxFontEntries-b.used {
		return false
	}
	b.used += n
	return true
}

// cmapOf reads a CMap stream once for the document: the fonts that share
// the stream share what was read of it, and its mappings are charged once.
// It is nil when the stream cannot be decoded or the CMap is not used.
func (d *Document) cmapOf(s *stream) *cmap {
	if c, ok := d.cmaps[s]; ok {
		return c
	}
	// The cross-reference the read that resolved this stream began on, not
	// the one it ends on: a CMap read from a stream a replaced
	// cross-reference named is not held, since the number that named it names
	// other bytes now.
	defer d.beginRead()()
	generation := d.readingGeneration()
	var c *cmap
	if data, err := d.decodeStream(s, false); err == nil {
		c = parseCMap(data, &d.fontBudget)
	}
	if d.generation != generation {
		return c
	}
	if d.cmaps == nil {
		d.cmaps = map[*stream]*cmap{}
	}
	d.cmaps[s] = c
	return c
}

// loadFont builds a font from its dictionary. Nothing here fails: a font
// this reader cannot interpret still yields glyphs, unmapped.
func (d *Document) loadFont(dict Dict) *font {
	// Building a font reads the objects it names, and one of them may rebuild
	// the cross-reference: everything the load reads after that belongs to a
	// document this one no longer is, and publishes nothing -- not a cached
	// object, not a bound met resolving a chain the old font named.
	defer d.beginRead()()
	f := &font{defaultWidth: 1000, fontMatrix: [6]float64{0.001, 0, 0, 0.001, 0, 0}}
	subtype, _ := d.nameOf(dict["Subtype"])
	if tu, ok := d.resolve(dict["ToUnicode"]).(*stream); ok {
		f.toUnicode = d.cmapOf(tu)
	}
	if subtype == "Type0" {
		f.composite = true
		d.loadType0(f, dict)
		return f
	}
	if subtype == "Type3" {
		f.type3 = true
		if m := d.arrayOf(dict["FontMatrix"]); len(m) == 6 {
			for i := range m {
				if v, ok := d.numOf(m[i]); ok {
					f.fontMatrix[i] = v
				}
			}
		}
	}
	d.loadSimple(f, dict, subtype)
	return f
}

// unusableEncoding is a composite font whose encoding the reader cannot use:
// its bytes are split into two-byte codes so that the glyphs can be counted,
// and every one of them is unmapped, at the width the font gives a CID it has
// no width for. Identity would be a reading of the page, and the page does
// not say it.
func (d *Document) unusableEncoding(f *font) {
	f.encoding = twoByteCodespaces()
	f.encodingUnusable = true
}

func (d *Document) loadType0(f *font, dict Dict) {
	switch enc := d.resolve(dict["Encoding"]).(type) {
	case Name:
		if enc == "Identity-H" || enc == "Identity-V" {
			f.encoding = identityCMap()
			f.vertical = enc == "Identity-V"
		} else {
			// A predefined CMap this reader does not carry: codes are mapped
			// through ToUnicode alone, and where the font has a ToUnicode map
			// its codespace ranges say how many bytes a code has. Reading
			// every code as two bytes loses the text of an encoding whose
			// codes are one byte or two, which the predefined CMaps of the CJK
			// registries are; two bytes is what is left when the font declares
			// no codespace range anywhere. Neither carries a CID: this font's
			// codes stand for the CIDs of a CMap the reader does not have.
			f.encoding = twoByteCodespaces()
			if f.toUnicode != nil && f.toUnicode.declaredCodespaces {
				// Only ranges the map declares: a range the reader inferred
				// from what a map holds is the reader's reading of it, and a
				// font whose map declares none takes the two-byte fallback
				// however that map's parsing ended.
				f.encoding = f.toUnicode.codespacesOnly()
			}
			f.vertical = strings.HasSuffix(string(enc), "-V")
		}
	case *stream:
		// A CMap stream whose parse established no encoding -- no bytes, bytes
		// that hold no operator of the syntax, a begincmap and an endcmap with
		// nothing between them, a stream naming a parent CMap this reader does
		// not look up -- is a stream the reader cannot use: it declares no
		// codespace range and maps no code, so nothing in it says how this
		// font's bytes split into codes or what they stand for.
		if c := d.cmapOf(enc); c != nil && c.established {
			f.encoding = c
			f.vertical = c.vertical
		} else {
			d.unusableEncoding(f)
		}
	default:
		// An /Encoding that is neither a name nor a CMap stream: absent,
		// null, a number, a dictionary, or a reference to an object the
		// reader could not read. None of them says how this font's bytes
		// split into codes or what they stand for.
		d.unusableEncoding(f)
	}
	descendants := d.arrayOf(dict["DescendantFonts"])
	if len(descendants) == 0 {
		return
	}
	cid := d.dictOf(descendants[0])
	if cid == nil {
		return
	}
	if dw, ok := d.numOf(cid["DW"]); ok {
		f.defaultWidth = dw
	}
	// /W: [c [w1 w2 ...] | cfirst clast w]... Every entry an array or a
	// range declares is counted against maxCIDWidths and charged to the
	// document's font budget before it is read; past either, the font keeps
	// no widths. A code that is not an integer from 0 below maxWidthCID
	// leaves its entry out, as does a range longer than maxWidthRange.
	w := d.arrayOf(cid["W"])
	widths := map[uint32]float64{}
	declared := 0
	declare := func(n int) bool {
		declared += n
		return declared <= maxCIDWidths && d.fontBudget.take(n)
	}
	for i := 0; i < len(w); {
		if _, ok := d.numOf(w[i]); !ok {
			break
		}
		first, firstOK := d.widthCID(w[i])
		if i+1 < len(w) {
			if arr := d.arrayOf(w[i+1]); arr != nil {
				if firstOK {
					if !declare(len(arr)) {
						return
					}
					for j, item := range arr {
						if v, ok := d.numOf(item); ok && int64(first)+int64(j) < maxWidthCID {
							widths[first+uint32(j)] = v
						}
					}
				}
				i += 2
				continue
			}
		}
		if i+2 < len(w) {
			last, lastOK := d.widthCID(w[i+1])
			width, widthOK := d.numOf(w[i+2])
			if firstOK && lastOK && widthOK && last >= first && last-first < maxWidthRange {
				n := int(last-first) + 1
				if !declare(n) {
					return
				}
				for k := 0; k < n; k++ {
					widths[first+uint32(k)] = width
				}
			}
			i += 3
			continue
		}
		break
	}
	f.cidWidths = widths
}

// widthCID reads a CID a /W entry names: an integer, or a real with no
// fraction, from 0 below maxWidthCID.
func (d *Document) widthCID(v object) (uint32, bool) {
	switch x := d.resolve(v).(type) {
	case int64:
		if x >= 0 && x < maxWidthCID {
			return uint32(x), true
		}
	case float64:
		if x >= 0 && x < maxWidthCID && x == math.Trunc(x) {
			return uint32(x), true
		}
	}
	return 0, false
}

// standard14Widths gives the widths of the ASCII range for the standard
// fonts a document may use without embedding metrics: Helvetica and
// Times, with Courier fixed at 600. Other names fall back to Helvetica.
var helveticaWidths = []float64{278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584}
var timesWidths = []float64{250, 333, 408, 500, 500, 833, 778, 333, 333, 333, 500, 564, 250, 333, 250, 278, 500, 500, 500, 500, 500, 500, 500, 500, 500, 500, 278, 278, 564, 564, 564, 444, 921, 722, 667, 667, 722, 611, 556, 722, 722, 333, 389, 722, 611, 889, 722, 722, 556, 722, 667, 556, 611, 722, 722, 944, 722, 722, 611, 333, 278, 333, 469, 500, 333, 444, 500, 444, 500, 444, 333, 500, 500, 278, 278, 500, 278, 778, 500, 500, 500, 500, 333, 389, 278, 500, 500, 722, 500, 500, 444, 480, 200, 480, 541}

func (d *Document) loadSimple(f *font, dict Dict, subtype Name) {
	base, _ := d.nameOf(dict["BaseFont"])
	descriptor := d.dictOf(dict["FontDescriptor"])
	flags := int64(0)
	if descriptor != nil {
		flags, _ = d.intOf(descriptor["Flags"])
		if mw, ok := d.numOf(descriptor["MissingWidth"]); ok {
			f.missingWidth = mw
		}
	}
	symbolic := flags&4 != 0 && flags&32 == 0
	// The base encoding: the font's builtin, which for a non-symbolic
	// font is Standard, then the named or dictionary encoding over it.
	var table [256]string
	hasBuiltin := descriptor != nil && (descriptor["FontFile"] != nil || descriptor["FontFile2"] != nil || descriptor["FontFile3"] != nil)
	if !symbolic || !hasBuiltin {
		table = standardEncoding
	}
	if strings.Contains(string(base), "Symbol") || strings.Contains(string(base), "Dingbat") {
		// The builtin encodings of Symbol and ZapfDingbats are not
		// carried; ToUnicode, when present, is what maps them.
		table = [256]string{}
	}
	applyNamed := func(name Name) {
		switch name {
		case "WinAnsiEncoding":
			table = winAnsiEncoding
		case "MacRomanEncoding":
			table = macRomanEncoding
		case "StandardEncoding", "PDFDocEncoding":
			table = standardEncoding
		case "MacExpertEncoding":
			// Not carried; small caps and old-style figures fall to
			// ToUnicode or stay unmapped.
		}
	}
	switch enc := d.resolve(dict["Encoding"]).(type) {
	case Name:
		applyNamed(enc)
	case Dict:
		if be, ok := d.nameOf(enc["BaseEncoding"]); ok {
			applyNamed(be)
		} else if symbolic && hasBuiltin && subtype != "Type3" {
			// Differences over a builtin encoding this reader cannot
			// see; the names given are all it has.
		}
		diffs := d.arrayOf(enc["Differences"])
		code := 0
		for _, item := range diffs {
			switch x := d.resolve(item).(type) {
			case int64:
				code = int(x)
			case float64:
				code = int(x)
			case Name:
				if code >= 0 && code < 256 {
					table[code] = string(x)
				}
				code++
			}
		}
	}
	for c := 0; c < 256; c++ {
		if table[c] == "" {
			continue
		}
		if r, ok := glyphToRune(table[c]); ok {
			f.simple[c] = r
			f.mapped[c] = true
		}
	}
	// Widths.
	first, _ := d.intOf(dict["FirstChar"])
	widths := d.arrayOf(dict["Widths"])
	for i := range f.simpleWidths {
		f.simpleWidths[i] = f.missingWidth
	}
	if len(widths) > 0 {
		for i, w := range widths {
			c := int(first) + i
			if c < 0 || c > 255 {
				continue
			}
			if v, ok := d.numOf(w); ok {
				f.simpleWidths[c] = v
			}
		}
	} else if !f.type3 {
		f.noWidths = true
		std := helveticaWidths
		name := string(base)
		switch {
		case strings.Contains(name, "Courier") || strings.Contains(name, "Mono"):
			std = nil
		case strings.Contains(name, "Times") || strings.Contains(name, "Serif") || strings.Contains(name, "Georgia") || strings.Contains(name, "Book"):
			std = timesWidths
		}
		for c := 32; c < 127; c++ {
			if std == nil {
				f.simpleWidths[c] = 600
			} else {
				f.simpleWidths[c] = std[c-32]
			}
		}
		for c := 127; c < 256; c++ {
			f.simpleWidths[c] = 500
		}
	}
}

// glyphs splits a string into glyphs, yielding each as it is read: a long
// string's glyphs are never all held at once. A glyph's runes may be the
// font's own, and are not to be modified.
func (f *font) glyphs(s []byte) iter.Seq[glyph] {
	return func(yield func(glyph) bool) {
		if !f.composite {
			for _, b := range s {
				g := glyph{isSpace: b == 32}
				code := uint32(b)
				if f.toUnicode != nil {
					if rs, ok := f.toUnicode.toUnicode(code, 1); ok {
						g.runes = rs
					}
				}
				if g.runes == nil && f.mapped[b] {
					g.runes = f.simple[b : int(b)+1 : int(b)+1]
				}
				if g.runes == nil {
					g.unmapped = true
				}
				w := f.simpleWidths[b]
				if f.type3 {
					// Glyph space through the font matrix: the x advance.
					g.width = w*f.fontMatrix[0] + 0*f.fontMatrix[2]
				} else {
					g.width = w / 1000
				}
				if !yield(g) {
					return
				}
			}
			return
		}
		enc := f.encoding
		if enc == nil {
			enc = identityCMap()
		}
		for len(s) > 0 {
			code, n, declared := enc.nextCode(s)
			if n <= 0 {
				n = 1
			}
			s = s[n:]
			if f.encodingUnusable {
				// The font's own encoding is one the reader cannot use: no
				// code it might make is one the file gives it.
				if !yield(glyph{unmapped: true, width: f.defaultWidth / 1000}) {
					return
				}
				continue
			}
			if !declared {
				// Bytes in no codespace range of the encoding are no code of
				// this font: the number they make is not one the CMap gives,
				// and reading a mapping at it would put on the page a
				// character the page does not show. The glyph is unmapped and
				// counted, and takes the width the font gives a CID it has no
				// width for.
				if !yield(glyph{unmapped: true, width: f.defaultWidth / 1000}) {
					return
				}
				continue
			}
			g := glyph{isSpace: n == 1 && code == 32}
			cid, hasCID := enc.toCID(code, n)
			if f.toUnicode != nil {
				if rs, ok := f.toUnicode.toUnicode(code, n); ok {
					g.runes = rs
				}
			}
			if g.runes == nil {
				g.unmapped = true
			}
			w := f.defaultWidth
			if hasCID {
				if cw, ok := f.cidWidths[cid]; ok {
					w = cw
				}
			}
			g.width = w / 1000
			if !yield(g) {
				return
			}
		}
	}
}
