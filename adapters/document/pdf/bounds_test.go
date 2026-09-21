package pdf

import (
	"bytes"
	"compress/flate"
	"compress/lzw"
	"compress/zlib"
	"context"
	"encoding/ascii85"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strings"
	"testing"
	"time"

	"adapters/internal/pdfgen"
)

// childTest names the test a child process of the test binary runs.
const childTest = "PDF_TEST_CHILD"

// isolated runs the calling test's body in a child process of the test
// binary, where a runaway -- a recursion without end, an allocation without
// end -- ends the child and fails the test instead of exhausting the machine
// running it. In the parent it runs the child, fails the test unless the child
// passed, and returns false. In the child it lowers the goroutine stack
// ceiling to maxStack, starts a watchdog that exits once the process has
// allocated more than maxAlloc bytes, and returns true for the body to run.
func isolated(t *testing.T, maxStack int, maxAlloc uint64) bool {
	t.Helper()
	if os.Getenv(childTest) == t.Name() {
		debug.SetMaxStack(maxStack)
		go allocationWatchdog(maxAlloc)
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), childTest+"="+t.Name())
	out, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("--- PASS: "+t.Name())) {
		lines := strings.SplitN(string(out), "\n", 41)
		if len(lines) > 40 {
			lines = lines[:40]
		}
		t.Fatalf("the child process did not pass (%v):\n%s", err, strings.Join(lines, "\n"))
	}
	return false
}

func allocationWatchdog(ceiling uint64) {
	sample := []metrics.Sample{{Name: "/gc/heap/allocs:bytes"}}
	for {
		metrics.Read(sample)
		if sample[0].Value.Uint64() > ceiling {
			fmt.Fprintf(os.Stderr, "the child allocated more than %d bytes and was ended\n", ceiling)
			os.Exit(3)
		}
		time.Sleep(time.Millisecond)
	}
}

// allocated reports the bytes run allocates.
func allocated(run func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	run()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// openGenerated opens a generated document for a test that reads its
// objects directly.
func openGenerated(t *testing.T, data []byte) *Document {
	t.Helper()
	d, err := open(context.Background(), data, &inflateBudget{total: 64 << 20, one: 16 << 20})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return d
}

// cidFont adds a Type0 font over Identity-H whose descendant has a default
// width of 1000 and the members given, and, when toUnicode is not zero, the
// ToUnicode stream with that number.
func cidFont(b *pdfgen.Builder, descendant string, toUnicode int) int {
	cid := b.Add(pdfgen.Object{Body: "<< /Type /Font /Subtype /CIDFontType2 /BaseFont /TestSans /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /DW 1000 " + descendant + " >>"})
	tu := ""
	if toUnicode != 0 {
		tu = fmt.Sprintf(" /ToUnicode %d 0 R", toUnicode)
	}
	return b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Font /Subtype /Type0 /BaseFont /TestSans /Encoding /Identity-H /DescendantFonts [%d 0 R]%s >>", cid, tu)})
}

// widthOf is the width, in thousandths of an em, the font gives the
// two-byte code cid.
func widthOf(f *font, cid uint16) float64 {
	return firstGlyph(f, []byte{byte(cid >> 8), byte(cid)}).width * 1000
}

// firstGlyph is the first glyph the font reads from s.
func firstGlyph(f *font, s []byte) glyph {
	for g := range f.glyphs(s) {
		return g
	}
	return glyph{}
}

func loadFontNumbered(d *Document, num int) *font {
	return d.loadFont(d.dictOf(ref{num, 0}))
}

// A /W range names its codes by integers within the CIDs the reader holds;
// any other endpoint leaves the range out, and a font whose /W declares more
// widths than the reader holds takes its default width for every glyph.
func TestCIDWidthsAreBounded(t *testing.T) {
	cases := []struct {
		name   string
		w      string
		widths map[uint16]float64
		// absent and present are CIDs past what a code of two bytes names,
		// which must hold no width and the width given.
		absent  []uint32
		present map[uint32]float64
	}{
		{"ranges and arrays", "[1 3 700 10 [800 900]]", map[uint16]float64{2: 700, 3: 700, 4: 1000, 10: 800, 11: 900, 12: 1000}, nil, nil},
		{"a real endpoint with a fraction", "[1.5 3.5 700 20.0 22 600]", map[uint16]float64{2: 1000, 3: 1000, 21: 600}, nil, nil},
		{"a negative endpoint", "[-5 2 700]", map[uint16]float64{0: 1000, 1: 1000}, nil, nil},
		{"an endpoint past 32 bits", "[4294967296 4294967297 700]", map[uint16]float64{0: 1000, 1: 1000}, nil, nil},
		{"a start past 32 bits before an array", "[4294967296 [700 700]]", map[uint16]float64{0: 1000, 1: 1000}, nil, nil},
		{"a real endpoint past 32 bits", "[4294967296.0 [700 700] 4294967296.0 4294967297.0 800]", map[uint16]float64{0: 1000, 1: 1000}, nil, nil},
		{"a range one CID longer than a range may be", fmt.Sprintf("[0 %d 500]", maxWidthRange), map[uint16]float64{0: 1000, 5: 1000}, nil, nil},
		{"an array running past the CIDs the reader holds", fmt.Sprintf("[%d [700 800]]", maxWidthCID-1), nil, []uint32{maxWidthCID}, map[uint32]float64{maxWidthCID - 1: 700}},
		{"a range endpoint at the CIDs the reader holds", fmt.Sprintf("[7 7 600 %d %d 500]", maxWidthCID-1, maxWidthCID), map[uint16]float64{7: 600}, []uint32{maxWidthCID - 1, maxWidthCID}, nil},
		{"a real range endpoint at the CIDs the reader holds", fmt.Sprintf("[7 7 600 %d.0 %d.0 500]", maxWidthCID-1, maxWidthCID), map[uint16]float64{7: 600}, []uint32{maxWidthCID - 1, maxWidthCID}, nil},
		{"an array start at the CIDs the reader holds", fmt.Sprintf("[7 7 600 %d [500 500]]", maxWidthCID), map[uint16]float64{7: 600}, []uint32{maxWidthCID, maxWidthCID + 1}, nil},
		{"a range within the CIDs the reader holds", fmt.Sprintf("[7 7 600 %d %d 500]", maxWidthCID-2, maxWidthCID-1), map[uint16]float64{7: 600}, nil, map[uint32]float64{maxWidthCID - 2: 500, maxWidthCID - 1: 500}},
		{"a real range within the CIDs the reader holds", fmt.Sprintf("[7 7 600 %d.0 %d.0 500]", maxWidthCID-2, maxWidthCID-1), map[uint16]float64{7: 600}, nil, map[uint32]float64{maxWidthCID - 2: 500, maxWidthCID - 1: 500}},
		{"ranges past the widths a font holds", "[" + strings.Repeat("0 65535 500 ", 4) + "0 0 500]", map[uint16]float64{0: 1000, 5: 1000}, nil, nil},
		{"arrays past the widths a font holds", "[0 [" + strings.Repeat("500 ", 1<<17) + "] 0 [" + strings.Repeat("500 ", 1<<17+1) + "]]", map[uint16]float64{5: 1000}, nil, nil},
		{"ranges up to the widths a font holds", "[" + strings.Repeat("0 65535 500 ", 4) + "]", map[uint16]float64{0: 500, 5: 500}, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := &pdfgen.Builder{}
			num := cidFont(b, "/W "+c.w, 0)
			b.Catalog(b.Pages([]pdfgen.Page{{Content: ""}}))
			f := loadFontNumbered(openGenerated(t, b.Bytes()), num)
			for cid, want := range c.widths {
				if got := widthOf(f, cid); got != want {
					t.Errorf("CID %d: width %v, want %v", cid, got, want)
				}
			}
			for _, cid := range c.absent {
				if w, ok := f.cidWidths[cid]; ok {
					t.Errorf("CID %d: width %v, want none", cid, w)
				}
			}
			for cid, want := range c.present {
				if w, ok := f.cidWidths[cid]; !ok || w != want {
					t.Errorf("CID %d: width %v (%v), want %v", cid, w, ok, want)
				}
			}
		})
	}
}

// A range ending at the largest 32-bit code is read in bounded time and
// memory: the endpoint is outside the CIDs the reader holds.
func TestCIDWidthRangeAtTheLargestCodeEnds(t *testing.T) {
	if !isolated(t, 64<<20, 512<<20) {
		return
	}
	b := &pdfgen.Builder{}
	num := cidFont(b, "/W [4294967295 4294967295 500 7 7 600]", 0)
	b.Catalog(b.Pages([]pdfgen.Page{{Content: ""}}))
	f := loadFontNumbered(openGenerated(t, b.Bytes()), num)
	if got := widthOf(f, 7); got != 600 {
		t.Fatalf("CID 7: width %v, want 600", got)
	}
}

// mappingShapes are a ToUnicode CMap's mappings of code 5 to "A", one of each
// shape a mapping takes.
var mappingShapes = map[string]string{
	"a bfchar string":   "1 beginbfchar <0005> <0041> endbfchar",
	"a bfchar integer":  "1 beginbfchar <0005> 65 endbfchar",
	"a bfchar name":     "1 beginbfchar <0005> /A endbfchar",
	"a bfrange string":  "1 beginbfrange <0005> <0005> <0041> endbfrange",
	"a bfrange integer": "1 beginbfrange <0005> <0005> 65 endbfrange",
	"a bfrange array":   "1 beginbfrange <0005> <0005> [<0041>] endbfrange",
}

// Every font of a document draws its widths and its CMap mappings from one
// budget: a shared /W array read by many fonts spends it exactly, and a font
// loaded after it is spent keeps its default widths, even for a single range,
// and maps no glyph through its CMap, whatever the shape of the mapping.
func TestFontsShareOneBudget(t *testing.T) {
	b := &pdfgen.Builder{}
	w := b.Add(pdfgen.Object{Body: "[" + strings.Repeat("0 65535 500 ", 4) + "]"})
	one := b.Add(pdfgen.Object{Body: "[0 65535 500]"})
	perFont := 4 * 65536
	if maxFontEntries%perFont != 0 {
		t.Fatalf("the test spends the budget exactly in fonts of %d widths; the bound is %d", perFont, maxFontEntries)
	}
	fonts := maxFontEntries / perFont
	var nums []int
	for i := 0; i < fonts; i++ {
		nums = append(nums, cidFont(b, fmt.Sprintf("/W %d 0 R", w), 0))
	}
	nums = append(nums, cidFont(b, fmt.Sprintf("/W %d 0 R", one), 0))
	mapped := map[string]int{}
	for shape, mapping := range mappingShapes {
		tu := b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte("begincmap\n1 begincodespacerange <0000> <FFFF> endcodespacerange\n" + mapping + "\nendcmap\n")})
		mapped[shape] = cidFont(b, "", tu)
	}
	b.Catalog(b.Pages([]pdfgen.Page{{Content: ""}}))
	d := openGenerated(t, b.Bytes())
	for i, num := range nums {
		want := 500.0
		if i == fonts {
			want = 1000
		}
		if got := widthOf(loadFontNumbered(d, num), 5); got != want {
			t.Fatalf("font %d of %d: width %v, want %v", i+1, len(nums), got, want)
		}
	}
	for shape, num := range mapped {
		if g := firstGlyph(loadFontNumbered(d, num), []byte{0, 5}); !g.unmapped || len(g.runes) != 0 {
			t.Errorf("%s: a CMap read after the budget was spent mapped %q", shape, string(g.runes))
		}
	}
	// Each shape maps within a budget.
	b = &pdfgen.Builder{}
	for shape, mapping := range mappingShapes {
		tu := b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte("begincmap\n1 begincodespacerange <0000> <FFFF> endcodespacerange\n" + mapping + "\nendcmap\n")})
		mapped[shape] = cidFont(b, "", tu)
	}
	b.Catalog(b.Pages([]pdfgen.Page{{Content: ""}}))
	d = openGenerated(t, b.Bytes())
	for shape, num := range mapped {
		if g := firstGlyph(loadFontNumbered(d, num), []byte{0, 5}); string(g.runes) != "A" {
			t.Errorf("%s: code 5 maps to %q", shape, string(g.runes))
		}
	}
}

// Fonts that share one ToUnicode stream share its decoding: the stream is
// inflated, and its bytes counted against the inflate budget, once.
func TestSharedCMapStreamIsDecodedOnce(t *testing.T) {
	b := &pdfgen.Builder{Compress: true}
	tu := b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte("begincmap\n1 begincodespacerange <0000> <FFFF> endcodespacerange\n1 beginbfchar <0005> <0041> endbfchar\nendcmap\n" + strings.Repeat(" ", 4096))})
	first := cidFont(b, "", tu)
	second := cidFont(b, "", tu)
	b.Catalog(b.Pages([]pdfgen.Page{{Content: ""}}))
	d := openGenerated(t, b.Bytes())
	for _, num := range []int{first, second} {
		if g := firstGlyph(loadFontNumbered(d, num), []byte{0, 5}); string(g.runes) != "A" {
			t.Fatalf("font %d: code 5 maps to %q", num, string(g.runes))
		}
	}
	if d.budget.used > 8192 {
		t.Fatalf("the shared stream was counted %d bytes against the budget", d.budget.used)
	}
}

// bfrangeCMap is a ToUnicode CMap mapping every two-byte code through one
// bfrange to the destination given as UTF-16BE hex.
func bfrangeCMap(destination string) []byte {
	return []byte("/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n1 beginbfrange\n<0000> <FFFF> <" + destination + ">\nendbfrange\nendcmap\nend\nend\n")
}

// A bfrange whose destination is several characters is held once, not once
// per code it spans. A destination longer than the 512 bytes the
// specification allows maps nothing; one at that length maps each code to it
// with its last character advanced by the code's distance from the range's
// start.
func TestBfrangeDestinationIsNotCopiedPerCode(t *testing.T) {
	if !isolated(t, 64<<20, 1<<30) {
		return
	}
	const ceiling = 8 << 20
	b := &pdfgen.Builder{Compress: true}
	long := cidFont(b, "", b.Add(pdfgen.Object{Body: "<< >>", Stream: bfrangeCMap(strings.Repeat("0041", 65536))}))
	atLimit := cidFont(b, "", b.Add(pdfgen.Object{Body: "<< >>", Stream: bfrangeCMap(strings.Repeat("0041", 255) + "0042")}))
	b.Catalog(b.Pages([]pdfgen.Page{{Content: ""}}))
	d := openGenerated(t, b.Bytes())

	var f *font
	if n := allocated(func() { f = loadFontNumbered(d, atLimit) }); n > ceiling {
		t.Fatalf("a 256-unit destination allocated %d bytes", n)
	}
	// Code 5 first, then code 0, then code 5 again: a lookup that wrote into
	// the range's one destination would show in what the later ones map to.
	for _, lookup := range []struct {
		code uint16
		last rune
	}{{5, 'G'}, {0, 'B'}, {5, 'G'}} {
		code, last := lookup.code, lookup.last
		g := firstGlyph(f, []byte{byte(code >> 8), byte(code)})
		want := strings.Repeat("A", 255) + string(last)
		if g.unmapped || string(g.runes) != want {
			t.Fatalf("code %d maps to %q, want %q", code, string(g.runes), want)
		}
	}

	if n := allocated(func() { f = loadFontNumbered(d, long) }); n > ceiling {
		t.Fatalf("a 65536-unit destination allocated %d bytes", n)
	}
	if g := firstGlyph(f, []byte{0, 5}); !g.unmapped {
		t.Fatalf("a destination past 512 bytes mapped code 5 to %d characters", len(g.runes))
	}
}

// Stray closing delimiters are skipped without a call per byte: millions of
// them in a content stream are read under a small goroutine stack, and the
// text on either side of them is kept.
func TestStrayDelimitersDoNotDeepenTheStack(t *testing.T) {
	if !isolated(t, 4<<20, 512<<20) {
		return
	}
	b := &pdfgen.Builder{Compress: true}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	content := "BT /F1 12 Tf 1 0 0 1 72 700 Tm (before) Tj\n" +
		strings.Repeat(")", 3<<20) + strings.Repeat(">)", 1<<20) + strings.Repeat("]", 4096) + strings.Repeat("}", 4096) +
		strings.Repeat(">>", 1<<20) + strings.Repeat("{", 1<<20) +
		"\n1 0 0 1 72 686 Tm (after) Tj ET\n"
	b.Catalog(b.Pages([]pdfgen.Page{{Content: content, Fonts: map[string]int{"F1": helv}}}))
	r := extract(t, b.Bytes())
	if r.Fatal != nil || len(r.Pages) != 1 || len(r.Problems) != 0 {
		t.Fatalf("fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
	}
	if p := r.Pages[0]; p.Status != PageOK || p.Text != "before\nafter" {
		t.Fatalf("page: %s %q", p.Status, p.Text)
	}
}

// Encoders for the stream filters the tests write.

func flateOf(data []byte) []byte {
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	w.Write(data)
	w.Close()
	return z.Bytes()
}

// lzwOf encodes without the early code-length change, which the standard
// library's LZW is; the stream says /EarlyChange 0.
func lzwOf(data []byte) []byte {
	var out bytes.Buffer
	w := lzw.NewWriter(&out, lzw.MSB, 8)
	w.Write(data)
	w.Close()
	return out.Bytes()
}

func hexStreamOf(data []byte) []byte { return []byte(hex.EncodeToString(data) + ">") }

// a85Of encodes with a line break every 60 characters.
func a85Of(data []byte) []byte {
	enc := make([]byte, ascii85.MaxEncodedLen(len(data)))
	enc = enc[:ascii85.Encode(enc, data)]
	var out bytes.Buffer
	out.WriteString("<~")
	for len(enc) > 60 {
		out.Write(enc[:60])
		out.WriteByte('\n')
		enc = enc[60:]
	}
	out.Write(enc)
	out.WriteString("~>")
	return out.Bytes()
}

// runLengthOf writes a repeated run for every stretch of identical bytes
// and literal runs for the rest.
func runLengthOf(data []byte) []byte {
	var out bytes.Buffer
	for i := 0; i < len(data); {
		j := i + 1
		for j < len(data) && j-i < 128 && data[j] == data[i] {
			j++
		}
		if j-i >= 2 {
			out.WriteByte(byte(257 - (j - i)))
			out.WriteByte(data[i])
			i = j
			continue
		}
		j = i + 1
		for j < len(data) && j-i < 128 && !(j+1 < len(data) && data[j+1] == data[j]) {
			j++
		}
		out.WriteByte(byte(j - i - 1))
		out.Write(data[i:j])
		i = j
	}
	out.WriteByte(128)
	return out.Bytes()
}

// pngRowsOf applies the PNG predictors to rows of columns bytes, one byte
// per pixel, cycling the row filters through None, Sub, Up, Average and
// Paeth. The data is padded with spaces to whole rows.
func pngRowsOf(data []byte, columns int) []byte {
	for len(data)%columns != 0 {
		data = append(data, ' ')
	}
	var out bytes.Buffer
	prior := make([]byte, columns)
	for r := 0; r*columns < len(data); r++ {
		row := data[r*columns : (r+1)*columns]
		ft := byte(r % 5)
		out.WriteByte(ft)
		for i, x := range row {
			var left, up, upLeft byte
			if i > 0 {
				left, upLeft = row[i-1], prior[i-1]
			}
			up = prior[i]
			switch ft {
			case 1:
				x -= left
			case 2:
				x -= up
			case 3:
				x -= byte((int(left) + int(up)) / 2)
			case 4:
				x -= paeth(left, up, upLeft)
			}
			out.WriteByte(x)
		}
		prior = row
	}
	return out.Bytes()
}

// tiffRowsOf applies the TIFF predictor to rows of columns bytes, one byte
// per pixel, a last row the data ends inside included: its bytes stand to
// the bytes before them in that row as any other row's do.
func tiffRowsOf(data []byte, columns int) []byte {
	out := append([]byte{}, data...)
	for r := 0; r < len(data); r += columns {
		for i := min(r+columns, len(data)) - 1; i > r; i-- {
			out[i] -= out[i-1]
		}
	}
	return out
}

// lzwLiteralsThenBadCode writes data as nine-bit literal codes after a clear
// code, then a code outside the table. data is short enough that the code
// length stays nine bits.
func lzwLiteralsThenBadCode(data []byte) []byte {
	codes := []int{256}
	for _, c := range data {
		codes = append(codes, int(c))
	}
	codes = append(codes, 511)
	var out []byte
	var acc uint32
	bits := 0
	for _, code := range codes {
		acc = acc<<9 | uint32(code)
		bits += 9
		for bits >= 8 {
			out = append(out, byte(acc>>(bits-8)))
			bits -= 8
		}
	}
	if bits > 0 {
		out = append(out, byte(acc<<(8-bits)))
	}
	return out
}

type filterCase struct {
	name   string
	dict   string
	encode func([]byte) []byte
}

var filterCases = []filterCase{
	{"FlateDecode", "<< /Filter /FlateDecode >>", flateOf},
	{"LZWDecode", "<< /Filter /LZWDecode /DecodeParms << /EarlyChange 0 >> >>", lzwOf},
	{"ASCIIHexDecode", "<< /Filter /ASCIIHexDecode >>", hexStreamOf},
	{"ASCII85Decode", "<< /Filter /ASCII85Decode >>", a85Of},
	{"RunLengthDecode", "<< /Filter /RunLengthDecode >>", runLengthOf},
	{"ASCII85 over Flate", "<< /Filter [/ASCII85Decode /FlateDecode] >>", func(b []byte) []byte { return a85Of(flateOf(b)) }},
	{"PNG predictors", "<< /Filter /FlateDecode /DecodeParms << /Predictor 15 /Columns 7 >> >>", func(b []byte) []byte { return flateOf(pngRowsOf(b, 7)) }},
	{"TIFF predictor", "<< /Filter /LZWDecode /DecodeParms << /Predictor 2 /Columns 7 /EarlyChange 0 >> >>", func(b []byte) []byte { return lzwOf(tiffRowsOf(b, 7)) }},
}

// textContent shows the text at the top of a page; padded, it is a stream
// of at least pad bytes.
func textContent(text string, pad int) []byte {
	s := "BT /F1 12 Tf 1 0 0 1 72 700 Tm (" + text + ") Tj ET\n"
	if len(s) < pad {
		s = strings.Repeat(" ", pad-len(s)) + s
	}
	return []byte(s)
}

// Every filter the reader implements decodes a page's content, the long
// text of a stream whose output needs more than one step of every
// decoder's state (LZW code lengths, several rows) included.
func TestEveryFilterDecodesContent(t *testing.T) {
	var long strings.Builder
	for i := 0; long.Len() < 20000; i++ {
		fmt.Fprintf(&long, "word%d ", i*7919%10007)
	}
	for _, fc := range filterCases {
		t.Run(fc.name, func(t *testing.T) {
			b := &pdfgen.Builder{}
			helv := b.Font("Helvetica", "WinAnsiEncoding", "")
			b.Catalog(b.Pages([]pdfgen.Page{
				{Content: string(fc.encode(textContent("short", 0))), ContentDict: fc.dict, Fonts: map[string]int{"F1": helv}},
				{Content: string(fc.encode(textContent(strings.TrimSpace(long.String()), 0))), ContentDict: fc.dict, Fonts: map[string]int{"F1": helv}},
			}))
			r := extract(t, b.Bytes())
			if r.Fatal != nil || len(r.Pages) != 2 || len(r.Problems) != 0 {
				t.Fatalf("fatal %+v pages %d problems %+v", r.Fatal, len(r.Pages), r.Problems)
			}
			if r.Pages[0].Text != "short" || r.Pages[1].Text != strings.TrimSpace(long.String()) {
				t.Fatalf("pages: %q and %d bytes", r.Pages[0].Text, len(r.Pages[1].Text))
			}
		})
	}
}

// Every filter charges what it produces to the document's inflate total as
// it produces it: a stream stopped at the total leaves it spent, and the
// next page's stream is past it too, an empty one included.
func TestEveryFilterChargesTheInflateTotal(t *testing.T) {
	for _, fc := range filterCases {
		t.Run(fc.name, func(t *testing.T) {
			b := &pdfgen.Builder{}
			helv := b.Font("Helvetica", "WinAnsiEncoding", "")
			b.Catalog(b.Pages([]pdfgen.Page{
				{Content: string(fc.encode(textContent("first", 200))), ContentDict: fc.dict, Fonts: map[string]int{"F1": helv}},
				{Content: string(fc.encode(textContent("after", 0))), ContentDict: fc.dict, Fonts: map[string]int{"F1": helv}},
				{Content: string(fc.encode(nil)), ContentDict: fc.dict, Fonts: map[string]int{"F1": helv}},
			}))
			opt := testOptions()
			opt.MaxInflateTotal = 100
			r := Extract(context.Background(), b.Bytes(), opt)
			if r.Fatal != nil || len(r.Pages) != 3 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			for i, p := range r.Pages {
				if p.Status != PageFailed || len(r.Problems) != 3 || r.Problems[i].Code != "stream-over-bound" || r.Problems[i].Page != i+1 {
					t.Fatalf("pages %+v problems %+v", r.Pages, r.Problems)
				}
			}
		})
	}
}

// A predictor's output is charged as well as the filter's before it: a
// stream whose inflated rows fit the total and whose rows with the
// predictor undone do not is past the bound.
func TestPredictorOutputIsCharged(t *testing.T) {
	for _, fc := range filterCases[len(filterCases)-2:] {
		t.Run(fc.name, func(t *testing.T) {
			b := &pdfgen.Builder{}
			helv := b.Font("Helvetica", "WinAnsiEncoding", "")
			b.Catalog(b.Pages([]pdfgen.Page{
				{Content: string(fc.encode(textContent("first", 203))), ContentDict: fc.dict, Fonts: map[string]int{"F1": helv}},
			}))
			opt := testOptions()
			opt.MaxInflateTotal = 300
			r := Extract(context.Background(), b.Bytes(), opt)
			if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Status != PageFailed || len(r.Problems) != 1 || r.Problems[0].Code != "stream-over-bound" {
				t.Fatalf("fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
			}
		})
	}
}

// A decoder that stops at a defect has charged what it produced before it:
// the page it fails leaves less of the total for the next.
func TestDecoderStoppedByADefectHasCharged(t *testing.T) {
	cases := []filterCase{
		{"LZWDecode", "<< /Filter /LZWDecode >>", func(b []byte) []byte { return lzwLiteralsThenBadCode(b) }},
		{"ASCIIHexDecode", "<< /Filter /ASCIIHexDecode >>", func(b []byte) []byte { return append(bytes.TrimSuffix(hexStreamOf(b), []byte(">")), "G>"...) }},
		{"ASCII85Decode", "<< /Filter /ASCII85Decode >>", func(b []byte) []byte { return append(bytes.TrimSuffix(a85Of(b), []byte("~>")), "\x7f~>"...) }},
	}
	for _, fc := range cases {
		t.Run(fc.name, func(t *testing.T) {
			b := &pdfgen.Builder{}
			helv := b.Font("Helvetica", "WinAnsiEncoding", "")
			b.Catalog(b.Pages([]pdfgen.Page{
				{Content: string(fc.encode(textContent("first", 80))), ContentDict: fc.dict, Fonts: map[string]int{"F1": helv}},
				{Content: string(hexStreamOf(textContent("after", 0))), ContentDict: "<< /Filter /ASCIIHexDecode >>", Fonts: map[string]int{"F1": helv}},
			}))
			opt := testOptions()
			opt.MaxInflateTotal = 100
			r := Extract(context.Background(), b.Bytes(), opt)
			if r.Fatal != nil || len(r.Pages) != 2 || len(r.Problems) != 2 {
				t.Fatalf("fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
			}
			if r.Problems[0].Code != "pdf-page-failed" || r.Problems[1].Code != "stream-over-bound" || r.Pages[1].Status != PageFailed {
				t.Fatalf("pages %+v problems %+v", r.Pages, r.Problems)
			}
		})
	}
}

// An ASCII85 stream whose 'z' groups decode to more bytes than a group of
// five characters is read to its end.
func TestASCII85ZeroGroupsAreReadToTheEnd(t *testing.T) {
	content := append(make([]byte, 100), textContent("VISIBLE", 0)...)
	b := &pdfgen.Builder{}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	b.Catalog(b.Pages([]pdfgen.Page{{Content: string(a85Of(content)), ContentDict: "<< /Filter /ASCII85Decode >>", Fonts: map[string]int{"F1": helv}}}))
	if !bytes.Contains(a85Of(content), []byte("zzzz")) {
		t.Fatal("the encoding holds no z group")
	}
	r := extract(t, b.Bytes())
	if r.Fatal != nil || len(r.Pages) != 1 || len(r.Problems) != 0 || r.Pages[0].Status != PageOK || r.Pages[0].Text != "VISIBLE" {
		t.Fatalf("fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
	}
}

// A string's glyphs are read one at a time: a page showing one string of
// millions of codes allocates in proportion to the string's bytes, not to
// its glyphs, and is cut at the text budget.
func TestLongStringGlyphsAreNotAllHeld(t *testing.T) {
	if !isolated(t, 64<<20, 2<<30) {
		return
	}
	// Within the characters a page's glyphs may map to.
	const n = 3 << 20
	b := &pdfgen.Builder{Compress: true}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	b.Catalog(b.Pages([]pdfgen.Page{{Content: "BT /F1 12 Tf 1 0 0 1 72 700 Tm (" + strings.Repeat("a", n) + ") Tj ET\n", Fonts: map[string]int{"F1": helv}}}))
	data := b.Bytes()
	opt := testOptions()
	opt.MaxTextBytes = 1024
	var r *Result
	// Buffers that grow to the stream's size -- inflated, concatenated,
	// lexed -- come to about twelve times its bytes; holding every glyph
	// came to more than two hundred.
	if got := allocated(func() { r = Extract(context.Background(), data, opt) }); got > 32*n {
		t.Fatalf("a string of %d bytes allocated %d bytes", n, got)
	}
	if r.Fatal != nil || len(r.Pages) != 0 || len(r.Problems) != 1 || r.Problems[0].Code != "text-over-bound" {
		t.Fatalf("fatal %+v pages %d problems %+v", r.Fatal, len(r.Pages), r.Problems)
	}
}

// Each decoder yields exactly the bytes its encoder was given, whatever
// their length: every final partial group, run and row included.
func TestDecodersRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	var inputs [][]byte
	for n := 0; n < 90; n++ {
		random := make([]byte, n)
		rng.Read(random)
		zeros := make([]byte, n)
		mixed := make([]byte, n)
		for i := range mixed {
			if rng.Intn(3) > 0 {
				mixed[i] = byte(rng.Intn(3))
			}
		}
		inputs = append(inputs, random, zeros, mixed)
	}
	for _, fc := range filterCases {
		t.Run(fc.name, func(t *testing.T) {
			p := &parser{lex: newLexer([]byte(fc.dict), 0)}
			obj, err := p.parseObject(0)
			if err != nil {
				t.Fatal(err)
			}
			for _, in := range inputs {
				d := &Document{budget: &inflateBudget{total: 1 << 30, one: 1 << 30}}
				got, err := d.decodeStream(&stream{dict: obj.(Dict), raw: fc.encode(in)}, true)
				want := in
				if strings.HasPrefix(fc.name, "PNG") {
					want = append([]byte{}, in...)
					for len(want)%7 != 0 {
						want = append(want, ' ')
					}
				}
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("%x: decoded %x (%v)", in, got, err)
				}
			}
		})
	}
}

// A CMap holding exactly the mappings one CMap may hold is used; one holding
// a mapping more is not, and its glyphs are unmapped.
func TestCMapPastItsMappingsIsNotUsed(t *testing.T) {
	cmapOf := func(extra string) []byte {
		var sb strings.Builder
		sb.WriteString("begincmap\n1 begincodespacerange <0000> <FFFF> endcodespacerange\n")
		item := strings.Repeat("<41> ", 65536)
		for i := 0; i < maxCMapEntries/65536; i++ {
			sb.WriteString("1 beginbfrange <0000> <FFFF> [" + item + "] endbfrange\n")
		}
		sb.WriteString(extra + "endcmap\n")
		return []byte(sb.String())
	}
	glyph := func(extra string) glyph {
		b := &pdfgen.Builder{}
		num := cidFont(b, "", b.Add(pdfgen.Object{Body: "<< >>", Stream: cmapOf(extra)}))
		b.Catalog(b.Pages([]pdfgen.Page{{Content: ""}}))
		return firstGlyph(loadFontNumbered(openGenerated(t, b.Bytes()), num), []byte{0, 5})
	}
	if g := glyph(""); string(g.runes) != "A" {
		t.Fatalf("at the bound: code 5 maps to %q (unmapped %v)", string(g.runes), g.unmapped)
	}
	// One mapping more, of every shape a mapping takes, a CID mapping's
	// included.
	for shape, extra := range map[string]string{
		"a bfchar string":   "1 beginbfchar <0001> <0042> endbfchar",
		"a bfchar integer":  "1 beginbfchar <0001> 66 endbfchar",
		"a bfchar name":     "1 beginbfchar <0001> /B endbfchar",
		"a bfrange string":  "1 beginbfrange <0001> <0001> <0042> endbfrange",
		"a bfrange integer": "1 beginbfrange <0001> <0001> 66 endbfrange",
		"a bfrange array":   "1 beginbfrange <0001> <0001> [<0042>] endbfrange",
		"a cidchar":         "1 begincidchar <0001> 66 endcidchar",
		"a cidrange":        "1 begincidrange <0001> <0001> 66 endcidrange",
	} {
		if g := glyph(extra + "\n"); !g.unmapped {
			t.Errorf("past the bound by %s: code 5 maps to %q", shape, string(g.runes))
		}
	}
}

// An ASCII85 stream that departs from the encoding is refused: a byte outside
// it, a 'z' inside a group, a final group of one character.
func TestASCII85DefectsAreRefused(t *testing.T) {
	for _, raw := range []string{"<~a~>", "<~ab{~>", "<~abz~>", "<~abcdea~>"} {
		d := &Document{budget: &inflateBudget{total: 1 << 20, one: 1 << 20}}
		if out, err := d.ascii85Decode([]byte(raw)); !errors.Is(err, errMalformed) {
			t.Errorf("%s: decoded %x (%v)", raw, out, err)
		}
	}
}

// A predictor is undone in a copy: after a /Crypt filter the stream's bytes
// are the document's own, and extraction leaves them as they were.
func TestPredictorLeavesTheDocumentUnchanged(t *testing.T) {
	b := &pdfgen.Builder{}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	b.Catalog(b.Pages([]pdfgen.Page{{Content: string(textContent("kept", 0)), ContentDict: "<< /Filter /Crypt /DecodeParms << /Predictor 2 /Columns 4 >> >>", Fonts: map[string]int{"F1": helv}}}))
	data := b.Bytes()
	before := append([]byte{}, data...)
	extract(t, data)
	if !bytes.Equal(data, before) {
		t.Fatal("extraction changed the document's bytes")
	}
}

// A CMap's lookups find what a scan of its declarations in order finds, however
// they overlap: the first codespace range, of any code length, each of whose
// bytes holds the byte of the head of a string at its own position, the first
// cid range and the first unicode range that hold a code.
func TestCMapLookupsFindTheFirstDeclaration(t *testing.T) {
	codeOf := func(b []byte) uint32 {
		v, _ := bytesToCode(b)
		return v
	}
	// Every string of one to four bytes, each 0, 1 or 2.
	var heads [][]byte
	var grow func(prefix []byte)
	grow = func(prefix []byte) {
		if len(prefix) > 0 {
			heads = append(heads, append([]byte{}, prefix...))
		}
		if len(prefix) == 4 {
			return
		}
		for c := byte(0); c < 3; c++ {
			grow(append(prefix, c))
		}
	}
	grow(nil)
	rng := rand.New(rand.NewSource(13))
	for trial := 0; trial < 400; trial++ {
		c := &cmap{cid: map[uint32]uint32{}, unicode: map[uint32][]rune{}}
		for n := rng.Intn(10); n > 0; n-- {
			lo, hi := heads[rng.Intn(len(heads))], heads[rng.Intn(len(heads))]
			length := len(lo)
			hi = append(append([]byte{}, hi...), 0, 0, 0)[:length]
			c.codespaces = append(c.codespaces, codespaceOf(lo, hi))
		}
		for n := rng.Intn(14); n > 0; n-- {
			lo := uint32(rng.Intn(70))
			c.uniRanges = append(c.uniRanges, cmapRange{lo: lo, hi: lo + uint32(rng.Intn(25)), dst: uint32(0x41 + rng.Intn(26))})
			lo = uint32(rng.Intn(70))
			c.cidRanges = append(c.cidRanges, cmapRange{lo: lo, hi: lo + uint32(rng.Intn(25)), dst: uint32(rng.Intn(1000))})
		}
		if rng.Intn(4) == 0 {
			// A range at the top of the codes.
			c.uniRanges = append(c.uniRanges, cmapRange{lo: 0xFFFFFFF0, hi: 0xFFFFFFFF, dst: 0x61})
		}
		c.finish()
		// The index is disjoint segments in ascending order, and two adjacent
		// segments name different spans.
		for k := 1; k < len(c.uniIndex); k++ {
			prev, seg := c.uniIndex[k-1], c.uniIndex[k]
			if prev.hi >= seg.lo || seg.lo > seg.hi || (prev.hi+1 == seg.lo && prev.order == seg.order) {
				t.Fatalf("trial %d: segments %+v then %+v", trial, prev, seg)
			}
		}
		for code := uint32(0); code < 100; code++ {
			wantCID, cidFound := uint32(0), false
			for _, r := range c.cidRanges {
				if code >= r.lo && code <= r.hi {
					wantCID, cidFound = r.dst+(code-r.lo), true
					break
				}
			}
			if got, found := c.toCID(code); found != cidFound || got != wantCID {
				t.Fatalf("trial %d, code %d: CID %d %v, want %d %v (ranges %+v)", trial, code, got, found, wantCID, cidFound, c.cidRanges)
			}
			want := ""
			for _, r := range c.uniRanges {
				if code >= r.lo && code <= r.hi {
					want = string(rune(r.dst + (code - r.lo)))
					break
				}
			}
			if got, _ := c.toUnicode(code); string(got) != want {
				t.Fatalf("trial %d, code %d: %q, want %q (ranges %+v)", trial, code, string(got), want, c.uniRanges)
			}
		}
		if got, _ := c.toUnicode(0xFFFFFFFF); len(c.uniRanges) > 0 && c.uniRanges[len(c.uniRanges)-1].hi == 0xFFFFFFFF && string(got) != string(rune(0x61+15)) {
			t.Fatalf("trial %d: the last code maps to %q", trial, string(got))
		}
		for _, head := range heads {
			wantCode, wantN, wantOK := uint32(0), 0, false
			shortest := 4
			for _, cs := range c.codespaces {
				shortest = min(shortest, cs.nbytes)
			}
			for _, cs := range c.codespaces {
				if cs.nbytes > len(head) {
					continue
				}
				within := true
				for i := 0; i < cs.nbytes; i++ {
					if head[i] < cs.lo[i] || head[i] > cs.hi[i] {
						within = false
						break
					}
				}
				if within {
					wantCode, wantN, wantOK = codeOf(head[:cs.nbytes]), cs.nbytes, true
					break
				}
			}
			if !wantOK {
				// 9.7.6.3: a head in no range takes the length of the first
				// range whose own first byte holds its first byte, and the
				// shortest length declared where none does.
				wantN = shortest
				for _, cs := range c.codespaces {
					if head[0] >= cs.lo[0] && head[0] <= cs.hi[0] {
						wantN = cs.nbytes
						break
					}
				}
				wantN = min(wantN, len(head))
				wantCode = codeOf(head[:wantN])
			}
			if code, n, ok := c.nextCode(head); code != wantCode || n != wantN || ok != wantOK {
				t.Fatalf("trial %d, %x: code %d of %d bytes %v, want %d of %d %v (codespaces %+v)", trial, head, code, n, ok, wantCode, wantN, wantOK, c.codespaces)
			}
		}
	}
}

// A CMap of many ranges is looked up without scanning them for each code: a
// page showing half a million codes through a quarter of a million ranges is
// read in seconds, where a scan would take minutes -- and the deadline is not
// consulted inside the one operator that shows them.
func TestManyCMapRangesAreLookedUpQuickly(t *testing.T) {
	if !isolated(t, 64<<20, 4<<30) {
		return
	}
	const ranges, codes = 1 << 18, 1 << 19
	var cm strings.Builder
	cm.WriteString("begincmap\n1 begincodespacerange <0000> <FFFF> endcodespacerange\n")
	fmt.Fprintf(&cm, "%d beginbfrange\n", ranges)
	for i := 0; i < ranges; i++ {
		// One code each, in the upper half of the codes, which the page
		// never shows.
		code := 0x8000 + i%0x8000
		fmt.Fprintf(&cm, "<%04X> <%04X> <0041>\n", code, code)
	}
	cm.WriteString("endbfrange\nendcmap\n")
	shown := make([]byte, 0, 4*codes)
	for i := 0; i < codes; i++ {
		shown = fmt.Appendf(shown, "%04X", 1+i%0x7FFF)
	}
	b := &pdfgen.Builder{Compress: true}
	f := cidFont(b, "", b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(cm.String())}))
	b.Catalog(b.Pages([]pdfgen.Page{{Content: "BT /F1 12 Tf 1 0 0 1 72 700 Tm <" + string(shown) + "> Tj ET\n", Fonts: map[string]int{"F1": f}}}))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	started := time.Now()
	r := Extract(ctx, b.Bytes(), testOptions())
	if elapsed := time.Since(started); r.TimedOut || elapsed > 20*time.Second {
		t.Fatalf("timed out %v after %v", r.TimedOut, elapsed)
	}
	if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Status != PageOK || r.Pages[0].Unmapped != codes || len(r.Problems) != 0 {
		t.Fatalf("fatal %+v problems %+v pages %d", r.Fatal, r.Problems, len(r.Pages))
	}
}

// A CMap that declares at most the codespace ranges one CMap may is used; one
// that declares a range more is not, and its glyphs are unmapped.
func TestCodespacesPastTheirBoundAreNotUsed(t *testing.T) {
	cmapOf := func(n int) []byte {
		var sb strings.Builder
		sb.WriteString("begincmap\n")
		for i := 0; i < n-1; i++ {
			sb.WriteString("1 begincodespacerange <FF00> <FFFF> endcodespacerange\n")
		}
		sb.WriteString("1 begincodespacerange <0000> <FEFF> endcodespacerange\n1 beginbfchar <0005> <0041> endbfchar\nendcmap\n")
		return []byte(sb.String())
	}
	for n, want := range map[int]string{maxCodespaces: "A", maxCodespaces + 1: ""} {
		b := &pdfgen.Builder{}
		num := cidFont(b, "", b.Add(pdfgen.Object{Body: "<< >>", Stream: cmapOf(n)}))
		b.Catalog(b.Pages([]pdfgen.Page{{Content: ""}}))
		if g := firstGlyph(loadFontNumbered(openGenerated(t, b.Bytes()), num), []byte{0, 5}); string(g.runes) != want || g.unmapped != (want == "") {
			t.Errorf("%d codespace ranges: code 5 maps to %q (unmapped %v)", n, string(g.runes), g.unmapped)
		}
	}
}

// A page whose glyphs map to more characters than the reader interprets is
// failed, whether or not its text is past the budget; a page at the bound is
// read. An unmapped glyph counts as one character.
func TestCharactersPastTheirBoundFailThePage(t *testing.T) {
	const per = 256
	many := maxCharacters/per - 1
	unmapped := maxCharacters - many*per
	document := func(extra string) []byte {
		b := &pdfgen.Builder{Compress: true}
		cm := "begincmap\n1 begincodespacerange <0000> <FFFF> endcodespacerange\n1 beginbfchar <0001> <" + strings.Repeat("0041", per) + "> endbfchar\nendcmap\n"
		f := cidFont(b, "", b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(cm)}))
		codes := strings.Repeat("0001", many) + strings.Repeat("0003", unmapped) + extra
		b.Catalog(b.Pages([]pdfgen.Page{
			{Content: "BT /F1 12 Tf 1 0 0 1 72 700 Tm <" + codes + "> Tj ET\n", Fonts: map[string]int{"F1": f}},
			{Content: "0 0 m 1 1 l S\n"},
		}))
		return b.Bytes()
	}
	r := extract(t, document(""))
	if r.Fatal != nil || len(r.Pages) != 2 || len(r.Problems) != 0 || r.Pages[0].Status != PageOK || r.Pages[0].Chars() != maxCharacters || r.Pages[0].Unmapped != unmapped {
		t.Fatalf("at the bound: fatal %+v problems %+v pages %d", r.Fatal, r.Problems, len(r.Pages))
	}
	past := document("0003")
	for _, budget := range []int{8 << 20, 1} {
		opt := testOptions()
		opt.MaxTextBytes = budget
		r := Extract(context.Background(), past, opt)
		if r.Fatal != nil || len(r.Pages) != 2 || r.Pages[0].Status != PageFailed || r.Pages[1].Status != PageNoText || len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" || r.Problems[0].Page != 1 {
			t.Fatalf("past the bound, a budget of %d bytes: fatal %+v problems %+v pages %+v", budget, r.Fatal, r.Problems, r.Pages)
		}
	}
}

// A decoder's write that crosses the inflate total is past the bound, whatever
// the write -- a RunLength literal run, an ASCII85 'z' group -- and a
// FlateDecode stream with no data after the total is spent is past it too.
func TestWritesCrossingTheTotalArePastIt(t *testing.T) {
	literal := append(append([]byte{126}, bytes.Repeat([]byte(" "), 127)...), 128)
	zeros := "<~" + strings.Repeat("z", 30) + "~>"
	for _, c := range []struct {
		name  string
		pages []pdfgen.Page
	}{
		{"a RunLength literal run", []pdfgen.Page{{Content: string(literal), ContentDict: "<< /Filter /RunLengthDecode >>"}}},
		{"ASCII85 'z' groups", []pdfgen.Page{{Content: zeros, ContentDict: "<< /Filter /ASCII85Decode >>"}}},
		{"an empty FlateDecode stream after the total is spent", []pdfgen.Page{
			{Content: zeros, ContentDict: "<< /Filter /ASCII85Decode >>"},
			{Content: "", ContentDict: "<< /Filter /FlateDecode >>"},
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := &pdfgen.Builder{}
			b.Catalog(b.Pages(c.pages))
			opt := testOptions()
			opt.MaxInflateTotal = 100
			r := Extract(context.Background(), b.Bytes(), opt)
			if r.Fatal != nil || len(r.Pages) != len(c.pages) || len(r.Problems) != len(c.pages) {
				t.Fatalf("fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
			}
			for i, p := range r.Pages {
				if p.Status != PageFailed || r.Problems[i].Code != "stream-over-bound" || r.Problems[i].Page != i+1 {
					t.Fatalf("pages %+v problems %+v", r.Pages, r.Problems)
				}
			}
		})
	}
}

// A CMap destination past the 512 bytes the specification allows maps
// nothing, at each of the three places a destination string is read -- a
// bfchar's, a bfrange's, an element of a bfrange's array -- and whether its
// length is odd or even. Array elements past the codes the range spans map
// nothing too.
func TestCMapDestinationsPastTheirBoundsMapNothing(t *testing.T) {
	atBound := strings.Repeat("0041", maxCMapDestinationBytes/2)
	// One byte past the bound, and two.
	odd, long := atBound+"41", atBound+"0041"
	whole := strings.Repeat("A", maxCMapDestinationBytes/2)
	for name, c := range map[string]struct {
		mapping string
		code    byte
		want    string
	}{
		"a bfchar at the bound":                    {"1 beginbfchar <0005> <" + atBound + "> endbfchar", 5, whole},
		"a bfchar one byte past the bound":         {"1 beginbfchar <0005> <" + odd + "> endbfchar", 5, ""},
		"a bfchar past the bound":                  {"1 beginbfchar <0005> <" + long + "> endbfchar", 5, ""},
		"a bfrange destination at the bound":       {"1 beginbfrange <0005> <0005> <" + atBound + "> endbfrange", 5, whole},
		"a bfrange destination one byte past it":   {"1 beginbfrange <0005> <0005> <" + odd + "> endbfrange", 5, ""},
		"a bfrange destination past the bound":     {"1 beginbfrange <0005> <0005> <" + long + "> endbfrange", 5, ""},
		"a bfrange array element at the bound":     {"1 beginbfrange <0005> <0005> [<" + atBound + ">] endbfrange", 5, whole},
		"a bfrange array element one byte past it": {"1 beginbfrange <0005> <0005> [<" + odd + ">] endbfrange", 5, ""},
		"a bfrange array element past the bound":   {"1 beginbfrange <0005> <0005> [<" + long + ">] endbfrange", 5, ""},
		"the last element a bfrange spans":         {"1 beginbfrange <0000> <0001> [<41> <42> <43>] endbfrange", 1, "B"},
		"an element past the codes it spans":       {"1 beginbfrange <0000> <0001> [<41> <42> <43>] endbfrange", 2, ""},
	} {
		b := &pdfgen.Builder{}
		num := cidFont(b, "", b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte("begincmap\n1 begincodespacerange <0000> <FFFF> endcodespacerange\n" + c.mapping + "\nendcmap\n")}))
		b.Catalog(b.Pages([]pdfgen.Page{{Content: ""}}))
		if g := firstGlyph(loadFontNumbered(openGenerated(t, b.Bytes()), num), []byte{0, c.code}); string(g.runes) != c.want || g.unmapped != (c.want == "") {
			t.Errorf("%s: code %d maps to %d characters (unmapped %v)", name, c.code, len(g.runes), g.unmapped)
		}
	}
}

// ASCII85 skips every byte up to and including the space wherever it falls,
// inside a group included: the white space the specification names, and the
// other controls below it.
func TestASCII85SkipsEveryByteUpToTheSpace(t *testing.T) {
	const skipped = "\r\t\f\x00\x01\x1f "
	encoded := a85Of(textContent("crlf", 0))
	var spaced []byte
	for i, c := range encoded {
		spaced = append(spaced, c)
		if i >= 2 && i < len(encoded)-2 {
			spaced = append(spaced, skipped[i%len(skipped)])
		}
	}
	b := &pdfgen.Builder{}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	b.Catalog(b.Pages([]pdfgen.Page{{Content: "\r\n" + string(spaced), ContentDict: "<< /Filter /ASCII85Decode >>", Fonts: map[string]int{"F1": helv}}}))
	r := extract(t, b.Bytes())
	if r.Fatal != nil || len(r.Pages) != 1 || len(r.Problems) != 0 || r.Pages[0].Text != "crlf" {
		t.Fatalf("fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
	}
}

// A PNG row whose filter type is past the five the format defines is refused.
func TestPNGPredictorRefusesAnUnknownRowFilter(t *testing.T) {
	parms := Dict{"Predictor": int64(12), "Columns": int64(2)}
	d := &Document{budget: &inflateBudget{total: 1 << 20, one: 1 << 20}}
	// Paeth on a first row adds the byte to the left.
	if out, err := d.applyPredictor([]byte{4, 1, 2}, parms); err != nil || !bytes.Equal(out, []byte{1, 3}) {
		t.Fatalf("filter type 4: %x %v", out, err)
	}
	if out, err := d.applyPredictor([]byte{5, 1, 2}, parms); !errors.Is(err, errMalformed) {
		t.Fatalf("filter type 5: %x %v", out, err)
	}
}

// rawDeflateOf is deflate data without the zlib wrapper.
func rawDeflateOf(data []byte) []byte {
	var z bytes.Buffer
	w, _ := flate.NewWriter(&z, flate.DefaultCompression)
	w.Write(data)
	w.Close()
	return z.Bytes()
}

// storedDeflateLikeZlib is raw deflate data of stored blocks whose first two
// bytes also read as a zlib header: a first block, not the final one, of 29
// bytes -- a header byte of 0x08 and a length whose low byte is 0x1D -- and
// then blocks of the rest.
func storedDeflateLikeZlib(data []byte) []byte {
	block := func(final bool, header byte, part []byte) []byte {
		if final {
			header |= 1
		}
		n := uint16(len(part))
		return append([]byte{header, byte(n), byte(n >> 8), byte(^n), byte(^n >> 8)}, part...)
	}
	out := block(false, 0x08, data[:29])
	for rest := data[29:]; ; {
		part := rest[:min(len(rest), 65535)]
		rest = rest[len(part):]
		out = append(out, block(len(rest) == 0, 0, part)...)
		if len(rest) == 0 {
			return out
		}
	}
}

// FlateDecode data must reach the end of its final block: data cut off before
// it, or corrupt, is not decoded, and a page whose content it is fails with
// none of its text listed. A zlib checksum that is missing or wrong after data
// that ended cleanly is no defect.
func TestFlateDataCutOffOrCorruptIsNotDecoded(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 3000; i++ {
		fmt.Fprintf(&sb, "BT /F1 12 Tf 1 0 0 1 72 %d Tm (LINE%05d) Tj ET\n", 700-i%600, i)
	}
	content := []byte(sb.String())
	whole := flateOf(content)
	raw := rawDeflateOf(content)
	with := func(data []byte, at int, b ...byte) []byte {
		out := append([]byte{}, data...)
		return append(out[:at], append(b, out[at+len(b):]...)...)
	}
	for _, c := range []struct {
		name    string
		stream  []byte
		decoded bool
	}{
		{"whole", whole, true},
		{"after leading white space", append([]byte("\r\n "), whole...), true},
		{"raw deflate", raw, true},
		{"raw deflate whose first bytes read as a zlib header", storedDeflateLikeZlib(content), true},
		{"without its checksum", whole[:len(whole)-4], true},
		{"with part of its checksum", whole[:len(whole)-2], true},
		{"with a wrong checksum", with(whole, len(whole)-1, whole[len(whole)-1]^0xFF), true},
		{"cut off in half", whole[:len(whole)/2], false},
		{"cut off by its last byte of deflate data", whole[:len(whole)-5], false},
		{"with a block of the reserved type", with(whole, 2, 0xFF), false},
		{"raw deflate cut off", raw[:len(raw)/2], false},
		{"a zlib header alone", whole[:2], false},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := &Document{budget: &inflateBudget{total: 64 << 20, one: 16 << 20}}
			out, err := d.inflate(c.stream)
			if c.decoded && (err != nil || !bytes.Equal(out, content)) {
				t.Fatalf("decoded %d bytes (%v)", len(out), err)
			}
			if !c.decoded && (err == nil || out != nil) {
				t.Fatalf("decoded %d bytes of damaged data", len(out))
			}
			b := &pdfgen.Builder{}
			helv := b.Font("Helvetica", "WinAnsiEncoding", "")
			b.Catalog(b.Pages([]pdfgen.Page{
				{Content: string(c.stream), ContentDict: "<< /Filter /FlateDecode >>", Fonts: map[string]int{"F1": helv}},
				{Content: shown("next", 700), Fonts: map[string]int{"F1": helv}},
			}))
			r := extract(t, b.Bytes())
			if r.Fatal != nil || len(r.Pages) != 2 || r.Pages[1].Text != "next" {
				t.Fatalf("fatal %+v pages %d", r.Fatal, len(r.Pages))
			}
			if c.decoded && (r.Pages[0].Status != PageOK || !strings.HasSuffix(r.Pages[0].Text, "LINE02999") || len(r.Problems) != 0) {
				t.Fatalf("page 1: %s, %d bytes, problems %+v", r.Pages[0].Status, len(r.Pages[0].Text), r.Problems)
			}
			if !c.decoded && (r.Pages[0].Status != PageFailed || r.Pages[0].Text != "" || len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" || r.Problems[0].Page != 1) {
				t.Fatalf("page 1: %s, %d bytes, problems %+v", r.Pages[0].Status, len(r.Pages[0].Text), r.Problems)
			}
		})
	}
}

// A page whose content streams together are past the bound on a page's
// content, with no stream past an inflate bound, is failed as past a
// structure bound; one within it is read.
func TestContentStreamsPastTheirBoundFailThePage(t *testing.T) {
	if testing.Short() {
		t.Skip("inflates two pages of more than fifty megabytes")
	}
	// The page's first stream holds n spaces; its second is the text. Each
	// stream is joined to the one before it with a newline, so the page's
	// content is n + 1 + len(text) + 1 bytes.
	text := shown("text", 700)
	document := func(n int) []byte {
		b := &pdfgen.Builder{}
		helv := b.Font("Helvetica", "WinAnsiEncoding", "")
		refs := []string{fmt.Sprintf("%d 0 R", b.Add(pdfgen.Object{Body: "<< /Filter /FlateDecode >>", Stream: flateOf(bytes.Repeat([]byte(" "), n)), Raw: true}))}
		last := b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(text)})
		refs = append(refs, fmt.Sprintf("%d 0 R", last))
		pages := b.Next()
		b.Add(pdfgen.Object{Body: "placeholder"})
		resources := fmt.Sprintf("/Resources << /Font << /F1 %d 0 R >> >>", helv)
		first := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Page /Parent %d 0 R %s /Contents [%s] >>", pages, resources, strings.Join(refs, " "))})
		second := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Page /Parent %d 0 R %s /Contents %d 0 R >>", pages, resources, last)})
		b.Set(pages, pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%d 0 R %d 0 R] /Count 2 >>", first, second)})
		b.Catalog(pages)
		return b.Bytes()
	}
	// The spaces that take the page's content to exactly the bound.
	exact := maxContentBytes - len(text) - 2
	opt := testOptions()
	opt.MaxInflateTotal = 4 << 30
	// The page's content is one stream, past the per-stream bound: this
	// test is of the bound on the content, not of the inflate bounds.
	opt.MaxInflateOne = 4 << 30
	r := Extract(context.Background(), document(exact), opt)
	if r.Fatal != nil || len(r.Pages) != 2 || r.Pages[0].Text != "text" || len(r.Problems) != 0 {
		t.Fatalf("at the bound: fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
	}
	r = Extract(context.Background(), document(exact+1), opt)
	if r.Fatal != nil || len(r.Pages) != 2 || r.Pages[0].Status != PageFailed || r.Pages[1].Text != "text" || len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" || r.Problems[0].Page != 1 {
		t.Fatalf("one byte past it: fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
	}
}

// budgeted is a document whose decoders write into a budget of the total
// and per-stream bounds given.
func budgeted(total, one int64) *Document {
	return &Document{budget: &inflateBudget{total: total, one: one}}
}

// The inflate bound is exact on both sides, for a decoder that writes whole
// chunks and for one that writes a byte at a time: a decode that fills what
// is left of the bound is kept whole and charges what it produced, and one
// byte more is past the bound. A decoder's last write is held like the
// writes before it -- an ASCIIHex stream's odd final nibble, an ASCII85
// stream's short final group -- and a write the bound refuses charges the
// room that was left, not the write, so what a stream stopped at the
// per-stream bound charges is that bound and no more.
func TestTheInflateBoundIsExactOnBothSides(t *testing.T) {
	hexOf := func(s string) func(*Document) ([]byte, error) {
		return func(d *Document) ([]byte, error) { return d.asciiHexDecode([]byte(s)) }
	}
	a85 := func(s string) func(*Document) ([]byte, error) {
		return func(d *Document) ([]byte, error) { return d.ascii85Decode([]byte(s)) }
	}
	const plenty = 1 << 20
	for _, c := range []struct {
		name       string
		total, one int64
		decode     func(*Document) ([]byte, error)
		// want is what the decode yields, or "" when the bound refuses it.
		want string
		used int64
	}{
		{"a chunk write that fills what is left", plenty, 4, a85("z"), "\x00\x00\x00\x00", 4},
		{"a chunk write one byte past what is left", plenty, 3, a85("z"), "", 3},
		{"a byte write that fills what is left", plenty, 5, hexOf("4142434445>"), "ABCDE", 5},
		{"a byte write one byte past what is left", plenty, 4, hexOf("4142434445>"), "", 4},
		{"an ASCIIHex final nibble that fills what is left", plenty, 3, hexOf("41424>"), "AB@", 3},
		{"an ASCIIHex final nibble past what is left", plenty, 2, hexOf("41424>"), "", 2},
		{"an ASCII85 final group that fills what is left", plenty, 6, a85("z!!!"), "\x00\x00\x00\x00\x00\x00", 6},
		{"an ASCII85 final group past what is left", plenty, 5, a85("z!!!"), "", 5},
		// The total bounds the decode instead of the per-stream bound.
		{"a decode that fills the total", 4, plenty, a85("z"), "\x00\x00\x00\x00", 4},
		{"a decode one byte past the total", 3, plenty, a85("z"), "", 3},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := budgeted(c.total, c.one)
			out, err := c.decode(d)
			if c.want == "" {
				if !errors.Is(err, errInflateBound) {
					t.Fatalf("%d bytes, %v, want the inflate bound", len(out), err)
				}
			} else if err != nil || string(out) != c.want {
				t.Fatalf("%q, %v, want %q", out, err, c.want)
			}
			if d.budget.used != c.used {
				t.Fatalf("charged %d bytes, want %d", d.budget.used, c.used)
			}
		})
	}
	// A stream stopped at the per-stream bound charges that bound, and the
	// rest of the total is there for the streams after it.
	d := budgeted(1000, 4)
	if out, err := d.ascii85Decode([]byte("zzzzzzzz")); !errors.Is(err, errInflateBound) || len(out) != 0 {
		t.Fatalf("past the per-stream bound: %d bytes, %v", len(out), err)
	}
	if d.budget.used != 4 {
		t.Fatalf("a stream stopped at the per-stream bound of 4 charged %d bytes", d.budget.used)
	}
	if out, err := d.ascii85Decode([]byte("z")); err != nil || len(out) != 4 {
		t.Fatalf("the stream after it: %d bytes, %v", len(out), err)
	}
	if d.budget.used != 8 {
		t.Fatalf("two streams of four bytes charged %d bytes", d.budget.used)
	}
}

// A charge that does not fit the font budget charges nothing: the /W or CMap
// it was for is not used, and a smaller one read after it still fits.
func TestAFontChargeThatDoesNotFitChargesNothing(t *testing.T) {
	b := &fontBudget{used: maxFontEntries - 100}
	if b.take(200) {
		t.Fatal("a charge of 200 fitted 100 left")
	}
	if b.used != maxFontEntries-100 {
		t.Fatalf("a refused charge left %d used, want %d", b.used, maxFontEntries-100)
	}
	if !b.take(100) || b.used != maxFontEntries {
		t.Fatalf("the charge of 100 after it: used %d, want %d", b.used, maxFontEntries)
	}
	if b.take(1) {
		t.Fatal("a charge fitted a spent budget")
	}
}

// A bfrange or cidrange longer than the codes one range may span is cut to
// that span: the highest code it maps is the lowest plus the span less one,
// and the code after that maps nothing.
func TestALongCMapRangeIsCutToItsSpan(t *testing.T) {
	head := "begincmap\n1 begincodespacerange <00000000> <FFFFFFFF> endcodespacerange\n"
	t.Run("a cidrange", func(t *testing.T) {
		c := parseCMap([]byte(head+"1 begincidrange <00000000> <00FF0000> 0 endcidrange\nendcmap\n"), &fontBudget{})
		if c == nil {
			t.Fatal("the CMap was not used")
		}
		for _, code := range []uint32{0, maxCMapRange - 1} {
			if cid, ok := c.toCID(code); !ok || cid != code {
				t.Errorf("code %d maps to CID %d (mapped %v)", code, cid, ok)
			}
		}
		if cid, ok := c.toCID(maxCMapRange); ok {
			t.Errorf("code %d maps to CID %d; a cut range spans %d codes", maxCMapRange, cid, maxCMapRange)
		}
	})
	t.Run("a bfrange", func(t *testing.T) {
		c := parseCMap([]byte(head+"1 beginbfrange <00000000> <00FF0000> <0041> endbfrange\nendcmap\n"), &fontBudget{})
		if c == nil {
			t.Fatal("the CMap was not used")
		}
		if rs, ok := c.toUnicode(0); !ok || string(rs) != "A" {
			t.Errorf("code 0 maps to %q (mapped %v)", string(rs), ok)
		}
		if _, ok := c.toUnicode(maxCMapRange - 1); !ok {
			t.Errorf("code %d maps nothing; a cut range spans %d codes", maxCMapRange-1, maxCMapRange)
		}
		if rs, ok := c.toUnicode(maxCMapRange); ok {
			t.Errorf("code %d maps to %q; a cut range spans %d codes", maxCMapRange, string(rs), maxCMapRange)
		}
	})
}

// A ToUnicode destination that is not a Unicode scalar value is no character
// a text can carry: the code maps nothing, whatever the shape of the
// mapping, so the glyph is U+FFFD and counted rather than dropped.
func TestCMapDestinationsOutsideTheScalarValuesMapNothing(t *testing.T) {
	for name, c := range map[string]struct {
		mapping string
		code    byte
		want    string
	}{
		"a bfchar integer that is a scalar":                  {"1 beginbfchar <0005> 65 endbfchar", 5, "A"},
		"a bfchar integer that is a surrogate":               {"1 beginbfchar <0005> 55296 endbfchar", 5, ""},
		"a bfchar integer past the scalar values":            {"1 beginbfchar <0005> 1114112 endbfchar", 5, ""},
		"a bfrange integer advanced onto a surrogate":        {"1 beginbfrange <0004> <0005> 55295 endbfrange", 5, ""},
		"a bfrange destination advanced within the scalars":  {"1 beginbfrange <0004> <0005> <0041D7FD> endbfrange", 5, "A퟾"},
		"a bfrange destination advanced onto a surrogate":    {"1 beginbfrange <0004> <0005> <0041D7FF> endbfrange", 5, ""},
		"a bfrange destination whose first code is a scalar": {"1 beginbfrange <0004> <0005> <0041D7FF> endbfrange", 4, "A퟿"},
	} {
		b := &pdfgen.Builder{}
		num := cidFont(b, "", b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte("begincmap\n1 begincodespacerange <0000> <FFFF> endcodespacerange\n" + c.mapping + "\nendcmap\n")}))
		b.Catalog(b.Pages([]pdfgen.Page{{Content: ""}}))
		if g := firstGlyph(loadFontNumbered(openGenerated(t, b.Bytes()), num), []byte{0, c.code}); string(g.runes) != c.want || g.unmapped != (c.want == "") {
			t.Errorf("%s: code %d maps to %q (unmapped %v), want %q", name, c.code, string(g.runes), g.unmapped, c.want)
		}
	}
}

// A page whose glyphs are mapped outside the scalar values renders each of
// them U+FFFD and counts it in unmapped, beside the glyphs the same font
// maps.
func TestGlyphsMappedOutsideTheScalarValuesAreCounted(t *testing.T) {
	b := &pdfgen.Builder{}
	cmap := "begincmap\n1 begincodespacerange <0000> <FFFF> endcodespacerange\n" +
		"2 beginbfchar <0001> 55296 <0002> <0041> endbfchar\n" +
		"1 beginbfrange <0010> <0012> <0041D7FE> endbfrange\n" +
		"endcmap\n"
	font := cidFont(b, "", b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(cmap)}))
	b.Catalog(b.Pages([]pdfgen.Page{{
		Content: "BT /F1 12 Tf 1 0 0 1 72 700 Tm <000200010010001100120002> Tj ET\n",
		Fonts:   map[string]int{"F1": font},
	}}))
	const want = "A�A퟾A퟿�A"
	r := extract(t, b.Bytes())
	if r.Fatal != nil || len(r.Pages) != 1 || len(r.Problems) != 0 {
		t.Fatalf("fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
	}
	if r.Pages[0].Text != want || r.Pages[0].Unmapped != 2 {
		t.Fatalf("text %q unmapped %d, want %q and 2", r.Pages[0].Text, r.Pages[0].Unmapped, want)
	}
}

// scanned is a document with no cross-reference of its own, n objects to
// find by scanning the file, and a catalog: opening it rebuilds the
// cross-reference. Every object heads with a type reconstruction parses and
// begins a stream the file never ends, so each of them is a stream whose
// /Length locates nothing.
func scanned(n int) []byte {
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&out, "%d 0 obj<< /Type /ObjStm >>stream\n", i)
	}
	fmt.Fprintf(&out, "%d 0 obj<< /Type /Catalog >>endobj\n", n+1)
	return out.Bytes()
}

// timeExtracting is what extracting data under ctx takes, with the result.
func timeExtracting(ctx context.Context, data []byte) (time.Duration, *Result) {
	started := time.Now()
	r := Extract(ctx, data, testOptions())
	return time.Since(started), r
}

// Opening a document is bounded by the deadline, not only walking its page
// tree: a document whose cross-reference must be rebuilt by scanning is given
// up on part-way when the deadline passes while it is opened, and the record
// is the walk's deadline ending -- timeout, truncated, no page -- and not
// pdf-malformed.
func TestOpeningADocumentIsBoundedByTheDeadline(t *testing.T) {
	if testing.Short() {
		t.Skip("the document is large enough to take a measurable time to open")
	}
	if !isolated(t, 64<<20, 512<<20) {
		return
	}
	data := scanned(60000)
	// What opening it whole costs, so that the deadline's cut is measured
	// against this machine and not against a fixed time.
	whole, r := timeExtracting(context.Background(), data)
	if r.Fatal == nil || r.Fatal.Code != "pdf-malformed" || r.TimedOut {
		t.Fatalf("opened whole: fatal %+v timedOut %v", r.Fatal, r.TimedOut)
	}
	// A deadline of a millisecond, which passes while the file is scanned for
	// objects, and one that passes at the twentieth reading of it, which is
	// while the objects found are parsed: each ends opening where it falls.
	for _, c := range []struct {
		name string
		ctx  func() (context.Context, func())
	}{
		{"a deadline of a millisecond", func() (context.Context, func()) {
			return context.WithTimeout(context.Background(), time.Millisecond)
		}},
		{"a deadline that passes while the objects found are parsed", func() (context.Context, func()) {
			return newCountdown(20), func() {}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := c.ctx()
			defer cancel()
			cut, r := timeExtracting(ctx, data)
			if r.Fatal != nil || !r.TimedOut || !r.Truncated || r.PageCount != 0 || len(r.Pages) != 0 {
				t.Fatalf("fatal %+v timedOut %v truncated %v count %d pages %d", r.Fatal, r.TimedOut, r.Truncated, r.PageCount, len(r.Pages))
			}
			if len(r.Problems) != 1 || r.Problems[0].Code != "timeout" || r.Problems[0].Page != 0 {
				t.Fatalf("problems %+v", r.Problems)
			}
			t.Logf("whole %v, cut %v", whole, cut)
			if cut > whole/2 {
				t.Fatalf("opening ran %v past a deadline that had passed, and opening it whole takes %v", cut, whole)
			}
		})
	}
}

// Reconstruction does not grow with the square of the file: a stream whose
// /Length locates no end is searched for one within a block, the file's own
// "endstream" offsets answering beyond it, so four times the objects take
// about four times as long and not sixteen. Neither document is opened under
// a deadline: a deadline would cut the search short and hide its cost.
func TestReconstructionDoesNotGrowWithTheSquareOfTheFile(t *testing.T) {
	if testing.Short() {
		t.Skip("the documents are large enough to take a measurable time to open")
	}
	// Neither document is opened under a deadline, so a reader that searched
	// the rest of the file for each stream would run for minutes: the child
	// process bounds what that costs the machine running the tests.
	if !isolated(t, 64<<20, 512<<20) {
		return
	}
	small, r := timeExtracting(context.Background(), scanned(20000))
	if r.Fatal == nil || r.Fatal.Code != "pdf-malformed" || r.TimedOut {
		t.Fatalf("20,000 objects: fatal %+v timedOut %v", r.Fatal, r.TimedOut)
	}
	large, r := timeExtracting(context.Background(), scanned(80000))
	if r.Fatal == nil || r.Fatal.Code != "pdf-malformed" || r.TimedOut {
		t.Fatalf("80,000 objects: fatal %+v timedOut %v", r.Fatal, r.TimedOut)
	}
	t.Logf("20,000 objects %v, 80,000 objects %v", small, large)
	if large > 8*small+2*time.Second {
		t.Fatalf("four times the objects took %v against %v", large, small)
	}
}

// The first "endstream" at or after an offset is the one a search of the rest
// of the file would find, wherever the offsets fall around a block's edge.
func TestTheEndstreamIndexFindsWhatASearchWouldFind(t *testing.T) {
	random := rand.New(rand.NewSource(11))
	data := make([]byte, 5*endstreamBlock)
	for i := range data {
		data[i] = byte('a' + random.Intn(3))
	}
	// Matches at a block's edge, one byte either side of it, and adjacent.
	for _, at := range []int{0, 1, endstreamBlock - len(endstreamKeyword), endstreamBlock - 1, endstreamBlock, endstreamBlock + 1, 2*endstreamBlock - 3, 3 * endstreamBlock, 3*endstreamBlock + len(endstreamKeyword), len(data) - len(endstreamKeyword)} {
		copy(data[at:], endstreamKeyword)
	}
	d := &Document{data: data}
	for start := 0; start < len(data); start++ {
		want := bytes.Index(data[start:], endstreamKeyword)
		if want >= 0 {
			want += start
		}
		if got := d.nextEndstream(start); got != want {
			t.Fatalf("from %d: %d, want %d", start, got, want)
		}
	}
	if got := d.nextEndstream(len(data)); got != -1 {
		t.Fatalf("from the end: %d, want -1", got)
	}
}

// The fonts held while one page's content is read are bounded: a name the
// page's /Resources does not hold yields the same font whatever the name, and
// past the cache's bound a name is not held at all.
func TestFontsHeldWhileOnePageIsReadAreBounded(t *testing.T) {
	it := &interp{d: &Document{}, ctx: context.Background(), fonts: map[string]*font{}}
	first := it.fontFor(Dict{}, "one")
	if second := it.fontFor(Dict{}, "two"); second != first {
		t.Fatal("two names the resources do not hold yielded two fonts")
	}
	for i := 0; i < maxFontCacheEntries+1000; i++ {
		if f := it.fontFor(Dict{}, Name(fmt.Sprintf("f%d", i))); f != first {
			t.Fatalf("name %d yielded another font", i)
		}
	}
	if len(it.fonts) > maxFontCacheEntries {
		t.Fatalf("%d fonts held for one page, past %d", len(it.fonts), maxFontCacheEntries)
	}
}

// A page whose content names far more fonts than the reader caches, none of
// them in its /Resources, yields a record: the font of an unknown name is one
// value and the cache is bounded, so what the page holds does not grow with
// the names it shows. Held in a child process, since without either the page
// allocates a font for every name.
func TestAPageNamingManyFontsYieldsARecord(t *testing.T) {
	if !isolated(t, 64<<20, 192<<20) {
		return
	}
	const names = 100000
	var content strings.Builder
	for i := 0; i < names; i++ {
		fmt.Fprintf(&content, "/f%07d 0 Tf ", i)
	}
	b := &pdfgen.Builder{}
	b.Catalog(b.Pages([]pdfgen.Page{{Content: content.String()}}))
	r := extract(t, b.Bytes())
	if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Status != PageNoText || len(r.Problems) != 0 {
		t.Fatalf("fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
	}
}

// xrefStreamDeclaring is a document whose cross-reference is one stream
// declaring n entries from object 4 on, each of them a byte of its data, so
// that a few kilobytes of file declare as many entries as the reader holds.
func xrefStreamDeclaring(n int) []byte {
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	for i, body := range []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
	} {
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, body)
	}
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	w.Write(make([]byte, n))
	w.Close()
	at := out.Len()
	fmt.Fprintf(&out, "4 0 obj\n<< /Type /XRef /Size %d /Index [4 %d] /W [0 1 0] /Root 1 0 R /Filter /FlateDecode /Length %d >>\nstream\n", n+4, n, z.Len())
	out.Write(z.Bytes())
	out.WriteString("\nendstream\nendobj\n")
	fmt.Fprintf(&out, "startxref\n%d\n%%%%EOF\n", at)
	return out.Bytes()
}

// tabled writes the objects given, numbered from 1, with a cross-reference
// table naming them and freeEntries free entries past them, and a trailer
// naming object 1 as the catalog.
func tabled(objects []string, freeEntries int) []byte {
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	offsets := make([]int, 0, len(objects))
	for i, body := range objects {
		offsets = append(offsets, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, body)
	}
	at := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, off := range offsets {
		fmt.Fprintf(&out, "%010d 00000 n \n", off)
	}
	if freeEntries > 0 {
		fmt.Fprintf(&out, "%d %d\n", len(objects)+1, freeEntries)
		for i := 0; i < freeEntries; i++ {
			out.WriteString("0000000000 65535 f \n")
		}
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1+freeEntries, at)
	return out.Bytes()
}

// pageTreeObjects is a catalog that names no /Pages, a page, and either a
// page tree over it or an object that is not one: a document whose page tree
// is found, or not found, by looking through its objects.
func pageTreeObjects(holdsOne bool) []string {
	tree := "<< /Type /Outlines /Count 0 >>"
	if holdsOne {
		tree = "<< /Type /Pages /Count 1 /Kids [3 0 R] >>"
	}
	return []string{"<< /Type /Catalog >>", tree, "<< /Type /Page /MediaBox [0 0 612 792] >>"}
}

// xrefTableDeclaring is a document whose cross-reference is a table
// declaring n entries past the three objects it holds.
func xrefTableDeclaring(n int) []byte {
	return tabled([]string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
	}, n)
}

// Looking for the page tree among a document's objects is bounded by the
// deadline: a document whose catalog names no /Pages has every object it
// names resolved to find one, and past the deadline that search stops rather
// than resolving them all. The record of a document whose page tree was not
// found because the deadline passed is the walk's deadline ending, not the
// defect of a file that names no page tree.
func TestLookingForThePageTreeIsBoundedByTheDeadline(t *testing.T) {
	d, err := open(context.Background(), tabled(pageTreeObjects(true), 0), &inflateBudget{total: 64 << 20, one: 16 << 20})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if root := d.findPagesRoot(); root == nil {
		t.Fatal("no page tree found with time to look for one")
	}
	passed, cancel := context.WithCancel(context.Background())
	cancel()
	d.ctx = passed
	if root := d.findPagesRoot(); root != nil {
		t.Fatal("a page tree was looked for past the deadline")
	}
	// A document with no page tree to find, given up on while it is looked
	// for: the record says the deadline, not the defect.
	_, r := timeExtracting(newCountdown(1), tabled(pageTreeObjects(false), 0))
	if r.Fatal != nil || !r.TimedOut || !r.Truncated || len(r.Pages) != 0 || len(r.Problems) != 1 || r.Problems[0].Code != "timeout" {
		t.Fatalf("fatal %+v timedOut %v truncated %v pages %d problems %+v", r.Fatal, r.TimedOut, r.Truncated, len(r.Pages), r.Problems)
	}
	// With time to look, the same document is the defect it is.
	_, r = timeExtracting(context.Background(), tabled(pageTreeObjects(false), 0))
	if r.Fatal == nil || r.Fatal.Code != "pdf-malformed" || r.TimedOut {
		t.Fatalf("fatal %+v timedOut %v", r.Fatal, r.TimedOut)
	}
}

// The entries of a cross-reference are read under the deadline too, whether
// the section is a stream or a table: a file whose section declares hundreds
// of thousands of them is given up on part-way, rather than read to its end
// and only then found to be past the deadline. Opening is timed on its own,
// since what a document costs after it is opened is not what this bounds.
func TestCrossReferenceEntriesAreReadUnderTheDeadline(t *testing.T) {
	if testing.Short() {
		t.Skip("the cross-reference is large enough to take a measurable time to read")
	}
	if !isolated(t, 64<<20, 512<<20) {
		return
	}
	for _, c := range []struct {
		name string
		data []byte
	}{
		{"a cross-reference stream", xrefStreamDeclaring(400000)},
		{"a cross-reference table", xrefTableDeclaring(200000)},
	} {
		t.Run(c.name, func(t *testing.T) {
			opening := func(ctx context.Context) (time.Duration, error) {
				started := time.Now()
				_, err := open(ctx, c.data, &inflateBudget{total: 64 << 20, one: 16 << 20})
				return time.Since(started), err
			}
			whole, err := opening(context.Background())
			if err != nil {
				t.Fatalf("opened whole: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
			defer cancel()
			cut, err := opening(ctx)
			if !isDeadline(err) {
				t.Fatalf("opening ended at %v, want the deadline", err)
			}
			t.Logf("whole %v, cut %v", whole, cut)
			if cut > whole/2 {
				t.Fatalf("opening ran %v against a deadline of a millisecond, and opening it whole takes %v", cut, whole)
			}
			// The record such a document yields is the walk's deadline ending.
			deadline, cancelDeadline := context.WithTimeout(context.Background(), time.Millisecond)
			defer cancelDeadline()
			_, r := timeExtracting(deadline, c.data)
			if r.Fatal != nil || !r.TimedOut || !r.Truncated || len(r.Pages) != 0 || len(r.Problems) != 1 || r.Problems[0].Code != "timeout" {
				t.Fatalf("fatal %+v timedOut %v truncated %v pages %d problems %+v", r.Fatal, r.TimedOut, r.Truncated, len(r.Pages), r.Problems)
			}
		})
	}
}

// A chain of small sections must consult the deadline even when its total
// entry count is below the batch checkpoint. The context expires between
// sections, so a check made later by the page walker cannot mask this one.
func TestDeadlineBetweenSmallCrossReferenceSections(t *testing.T) {
	data := withSections(t, xrefTableDeclaring(0), 3, false)
	d := openGenerated(t, data)
	d.ctx = newCountdown(1)
	if err := d.readXref(); !isDeadline(err) {
		t.Fatalf("cross-reference chain ended at %v, want the deadline", err)
	}
}

// A deadline during reconstruction stops adding scanned objects to the
// cross-reference. Checking only when those objects are parsed afterwards
// would still report a timeout, but would first retain the entire scan.
func TestDeadlineStopsRetainingScannedObjects(t *testing.T) {
	d := &Document{
		ctx: newCountdown(0), data: scanned(3 * entriesPerCheck),
		xref: map[int]xrefEntry{}, budget: &inflateBudget{total: 64 << 20, one: 16 << 20},
	}
	if err := d.reconstruct(); !isDeadline(err) {
		t.Fatalf("reconstruction ended at %v, want the deadline", err)
	}
	if len(d.xref) == 0 || len(d.xref) > entriesPerCheck {
		t.Fatalf("retained %d objects before stopping, want a partial scan within %d", len(d.xref), entriesPerCheck)
	}
}

// Where deflate data begins is decided by the two bytes of a zlib header, and
// by each of that header's four conditions: a stream whose first two bytes
// are one is inflated from its third byte, and a stream whose first two bytes
// are not is inflated from its first. Reading the header wrongly costs the
// text -- about one raw deflate stream in six does not decode when two of its
// bytes are taken for a header it does not have -- and costs the inflate
// budget what the misreading wrote before it failed, which is why the budget
// is held to the bytes decoded.
func TestZlibHeaderDecidesWhereDeflateDataBegins(t *testing.T) {
	payload := []byte(strings.Repeat("the payload of a deflate stream, long enough to need a few codes ", 4))
	body := rawDeflateOf(payload)
	header := func(cmf, flg byte) []byte {
		return append([]byte{cmf, flg}, body...)
	}
	// A raw deflate stream that decodes from its first byte and whose first
	// two bytes are neither a zlib header nor white space; taking them for one
	// decodes nothing of it.
	own := hexBytes(t, "7ac97afa5a489944e0df8b5fa64b5d343a73d6cec5e295c8ff2d0baf2b1907bedec07324c32c0b100000ffff")
	ownText := hexBytes(t, "e905cbd65476185 1fdd1f4971ad132cccd3e4438ea14ffb4a1d7223351ebb00cc468366a")
	for _, c := range []struct {
		name   string
		stream []byte
		want   []byte
	}{
		{"a zlib header", header(0x78, 0x01), payload},
		{"a compression method other than deflate", header(0x79, 0x18), nil},
		{"a window larger than deflate names", header(0x88, 0x1C), nil},
		{"check bits that are not a multiple of 31", header(0x78, 0x02), nil},
		{"a header naming a preset dictionary", header(0x78, 0x20), nil},
		{"two bytes that are no zlib header", own, ownText},
	} {
		t.Run(c.name, func(t *testing.T) {
			budget := &inflateBudget{total: 64 << 20, one: 16 << 20}
			d := &Document{budget: budget}
			out, err := d.inflate(c.stream)
			if c.want == nil {
				if err == nil || out != nil {
					t.Fatalf("decoded %d bytes (%v) of data read from the wrong byte", len(out), err)
				}
				return
			}
			if err != nil || !bytes.Equal(out, c.want) {
				t.Fatalf("decoded %d bytes (%v), want %d", len(out), err, len(c.want))
			}
			if budget.used != int64(len(c.want)) {
				t.Fatalf("charged %d bytes to the inflate budget for %d decoded", budget.used, len(c.want))
			}
		})
	}
}

// hexBytes is the bytes the hexadecimal digits of s name, white space in it
// passed over.
func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	out, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return out
}
