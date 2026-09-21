package pdf

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"adapters/internal/pdfgen"
)

// What the record reads of a page is what the page shows. The tests here are
// of the readings a document can bend: the bytes of an inline image, a
// predictor's last row, a page named twice, the codes of a CMap, a font held
// across a rebuilt cross-reference, an object stream's index.

// readsPoppler is what pdftotext reads from the document, with the page break
// and the blank lines around it removed; ok is false where poppler is not on
// the machine, as it is not on CI. It is a second reader's answer to log
// beside this one's, never the assertion itself.
func readsPoppler(t *testing.T, data []byte) (string, bool) {
	t.Helper()
	tool, err := exec.LookPath("pdftotext")
	if err != nil {
		return "", false
	}
	file := filepath.Join(t.TempDir(), "doc.pdf")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(tool, file, "-").CombinedOutput()
	if err != nil {
		t.Logf("pdftotext refused the document: %v\n%s", err, out)
		return "", false
	}
	return strings.Trim(string(out), "\n\f"), true
}

// readsInlineImagePage is a one-page document whose content is one inline
// image -- the dictionary and the sample bytes given -- and the content after
// it, under a Helvetica resource named F1.
func readsInlineImagePage(dict string, samples []byte, after string) []byte {
	var content bytes.Buffer
	content.WriteString("BI " + dict + " ID ")
	content.Write(samples)
	content.WriteString("\nEI\n")
	content.WriteString(after)
	return readsContentPage(content.Bytes())
}

// readsContentPage is a one-page document whose content is the bytes given,
// with a Helvetica resource named F1.
func readsContentPage(content []byte) []byte {
	b := &pdfgen.Builder{}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	pages := b.Next()
	b.Add(pdfgen.Object{Body: "placeholder"})
	cs := b.Add(pdfgen.Object{Body: "<< >>", Stream: content})
	page := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>", pages, helv, cs)})
	b.Set(pages, pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%d 0 R] /Count 1 >>", page)})
	b.Catalog(pages)
	return b.Bytes()
}

// An inline image's samples are the image's, not the page's operators. A
// reader that looks for "EI" rather than reading the length the image states,
// or the length its samples take, reads whatever the image carries after a
// byte sequence that reads as one -- text no viewer shows, in a record that
// is signed.
func TestReadsInlineImageSamplesAreNotContent(t *testing.T) {
	// 40 by 8 samples of one byte: 320 bytes, the first of them an "EI"
	// delimited on both sides and a text operator after it.
	hidden := "\n EI\n" + pdfgen.Text("F1", 12, []string{"NOT ON THE PAGE"})
	samples := append([]byte(hidden), bytes.Repeat([]byte{0x41}, 320-len(hidden))...)
	after := pdfgen.Text("F1", 12, []string{"ON THE PAGE"})
	for _, c := range []struct{ name, dict string }{
		{"the length the image states", fmt.Sprintf("/W 40 /H 8 /BPC 8 /CS /G /L %d", len(samples))},
		{"the length its samples take", "/W 40 /H 8 /BPC 8 /CS /G"},
		{"both, written in full", fmt.Sprintf("/Width 40 /Height 8 /BitsPerComponent 8 /ColorSpace /DeviceGray /Length %d", len(samples))},
		{"an image mask, one bit a sample", "/IM true /W 320 /H 8"},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsInlineImagePage(c.dict, samples, after)
			r := extract(t, data)
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if got := r.Pages[0].Text; got != "ON THE PAGE" {
				t.Errorf("the record reads %q; the page shows %q and the rest lies inside the image", got, "ON THE PAGE")
			}
			if r.Pages[0].Status != PageOK || len(r.Problems) != 0 {
				t.Errorf("page %s, problems %+v", r.Pages[0].Status, r.Problems)
			}
		})
	}
}

// An inline image whose end is nowhere -- no length the content bears out and
// no "EI" -- fails the page. What the page shows after the image is not
// known, and listing what came before it as the page would be a page the
// record says is whole.
func TestReadsInlineImageWithNoEndFailsThePage(t *testing.T) {
	b := &pdfgen.Builder{}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	// Sixteen samples, which is what 4 by 4 of one byte take, and then the
	// rest of the content, with no "EI" anywhere in it.
	first := shown("before", 700) + "BI /W 4 /H 4 /BPC 8 /CS /G ID " + strings.Repeat("A", 16) + "\n" + shown("after", 680)
	b.Catalog(b.Pages([]pdfgen.Page{
		{Content: first, Fonts: map[string]int{"F1": helv}},
		{Content: shown("next", 700), Fonts: map[string]int{"F1": helv}},
	}))
	r := extract(t, b.Bytes())
	if r.Fatal != nil || len(r.Pages) != 2 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if r.Pages[0].Status != PageFailed || r.Pages[0].Text != "" {
		t.Errorf("page 1 is %s %q; the image has no end, so what the page shows after it is not known", r.Pages[0].Status, r.Pages[0].Text)
	}
	if len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" || r.Problems[0].Page != 1 {
		t.Errorf("problems %+v", r.Problems)
	}
	if r.Pages[1].Text != "next" {
		t.Errorf("page 2 is %s %q", r.Pages[1].Status, r.Pages[1].Text)
	}
}

// An image whose length neither the dictionary nor its samples give -- a
// filtered image with no /L -- ends at an "EI" in its data, and only at one
// that operators follow: those two bytes lie in the samples of any image
// large enough, and the page is what follows the image, not what the image
// carries.
func TestReadsFilteredInlineImageEndsAtItsEI(t *testing.T) {
	for _, c := range []struct {
		name    string
		samples []byte
	}{
		{"samples holding no EI of their own", []byte("41414141>")},
		{"an EI in the samples that no operator follows",
			append([]byte("41 EI \xff\xff\xff"), pdfgen.Text("F1", 12, []string{"NOT ON THE PAGE"})...)},
	} {
		t.Run(c.name, func(t *testing.T) {
			var content bytes.Buffer
			content.WriteString(shown("before", 700))
			content.WriteString("BI /W 4 /H 4 /BPC 8 /CS /G /F /AHx ID ")
			content.Write(c.samples)
			content.WriteString(" EI\n")
			content.WriteString(shown("after", 680))
			r := extract(t, readsContentPage(content.Bytes()))
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != "before\nafter" {
				t.Errorf("the record reads %q, want %q (problems %+v)", got, "before\nafter", r.Problems)
			}
		})
	}
}

// Whether operators follow an "EI" is answered from the head of what follows
// it. A keyword the head ends inside is not a keyword read whole and says
// nothing either way: taking the bytes of it the head holds for a token no
// operator is would refuse the image's real end, and fail a page a viewer
// shows whole. The operator here is a marked-content sequence whose property
// list is long enough to carry it to the end of the head, placed so that the
// head ends before it, inside it at each byte, and after it.
func TestReadsInlineImageEndWhoseOperatorTheHeadCuts(t *testing.T) {
	const before, after = "\n/Artifact << /Type /Pagination /Pad (", ") >> "
	for at := inlineImageLookahead - 3; at <= inlineImageLookahead+1; at++ {
		t.Run(fmt.Sprintf("BDC %d bytes after EI", at), func(t *testing.T) {
			pad := strings.Repeat("p", at-len(before)-len(after))
			var content bytes.Buffer
			content.WriteString(shown("before", 700))
			content.WriteString("BI /W 4 /H 4 /BPC 8 /CS /G /F /AHx ID 41414141> EI")
			content.WriteString(before + pad + after + "BDC\n")
			content.WriteString(shown("after", 680))
			content.WriteString("EMC\n")
			data := readsContentPage(content.Bytes())
			r := extract(t, data)
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if got := r.Pages[0].Text; got != "before\nafter" || r.Pages[0].Status != PageOK {
				t.Errorf("the record reads %q, page %s, want %q (problems %+v)", got, r.Pages[0].Status, "before\nafter", r.Problems)
			}
		})
	}
}

// A PNG predictor whose row is longer than the data holds is a row the data
// ends inside: it is undone as far as it goes, and the text of the stream is
// the page's. Emptying the stream instead would list the page as holding no
// text, with nothing said of what was dropped.
func TestReadsPNGPredictorRowLongerThanTheData(t *testing.T) {
	content := []byte(pdfgen.Text("F1", 12, []string{"hello world"}))
	// One row, filter type 0: the data is the content as it lies.
	raw := append([]byte{0}, content...)
	for _, columns := range []int{len(content), len(content) + 1, 1 << 20} {
		t.Run(fmt.Sprint(columns), func(t *testing.T) {
			b := &pdfgen.Builder{}
			helv := b.Font("Helvetica", "WinAnsiEncoding", "")
			dict := fmt.Sprintf("<< /Filter /FlateDecode /DecodeParms << /Predictor 12 /Colors 1 /BitsPerComponent 8 /Columns %d >> >>", columns)
			b.Catalog(b.Pages([]pdfgen.Page{{Content: string(flateOf(raw)), ContentDict: dict, Fonts: map[string]int{"F1": helv}}}))
			data := b.Bytes()
			r := extract(t, data)
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Pages[0].Text != "hello world" || r.Pages[0].Status != PageOK || len(r.Problems) != 0 {
				t.Errorf("a row of %d over %d bytes of data: the record reads %s %q, problems %+v", columns, len(raw), r.Pages[0].Status, r.Pages[0].Text, r.Problems)
			}
		})
	}
}

// The TIFF predictor undoes a last row the data ends inside too: its bytes
// stand to the bytes before them in that row as any other row's do.
func TestReadsTIFFPredictorUndoesTheLastRow(t *testing.T) {
	d := budgeted(1<<20, 1<<20)
	parms := Dict{"Predictor": int64(2), "Colors": int64(1), "BitsPerComponent": int64(8), "Columns": int64(3)}
	out, err := d.applyPredictor([]byte{1, 1, 1, 1, 1}, parms)
	if want := []byte{1, 2, 3, 1, 2}; err != nil || !bytes.Equal(out, want) {
		t.Fatalf("rows of three over five bytes: %v, %v, want %v", out, err, want)
	}
}

// A page object a /Kids array names twice is two pages: that is what the tree
// says, what its /Count says, and what a viewer shows. Cycles are held by the
// nodes the walk stands under, not by every node it has seen.
func TestReadsAPageNamedTwiceIsTwoPages(t *testing.T) {
	t.Run("named twice", func(t *testing.T) {
		b := &pdfgen.Builder{}
		helv := b.Font("Helvetica", "WinAnsiEncoding", "")
		pages := b.Next()
		b.Add(pdfgen.Object{Body: "placeholder"})
		cs := b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(shown("one", 700))})
		page := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>", pages, helv, cs)})
		b.Set(pages, pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%d 0 R %d 0 R] /Count 2 >>", page, page)})
		b.Catalog(pages)
		data := b.Bytes()
		r := extract(t, data)
		if out, ok := readsPoppler(t, data); ok {
			t.Logf("pdftotext reads %q", out)
		}
		if r.Fatal != nil || r.PageCount != 2 || len(r.Pages) != 2 {
			t.Fatalf("a /Kids of two entries: fatal %+v count %d pages %+v", r.Fatal, r.PageCount, r.Pages)
		}
		for _, p := range r.Pages {
			if p.Status != PageOK || p.Text != "one" {
				t.Errorf("page %d is %s %q", p.Number, p.Status, p.Text)
			}
		}
	})
	// A control: a node under itself is still walked once, and the page below
	// it is read. It holds whether cycles are kept by ancestors or by every
	// node seen, and so tells neither apart.
	t.Run("a node under itself", func(t *testing.T) {
		b := &pdfgen.Builder{}
		helv := b.Font("Helvetica", "WinAnsiEncoding", "")
		outer, inner := b.Next(), b.Next()+1
		b.Add(pdfgen.Object{Body: "placeholder"})
		b.Add(pdfgen.Object{Body: "placeholder"})
		cs := b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(shown("one", 700))})
		page := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>", inner, helv, cs)})
		b.Set(outer, pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%d 0 R] /Count 1 >>", inner)})
		b.Set(inner, pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%d 0 R %d 0 R] /Count 1 >>", outer, page)})
		b.Catalog(outer)
		r := extract(t, b.Bytes())
		if r.Fatal != nil || r.PageCount != 1 || len(r.Pages) != 1 || r.Pages[0].Text != "one" {
			t.Fatalf("fatal %+v count %d pages %+v", r.Fatal, r.PageCount, r.Pages)
		}
	})
}

// readsCodespaces are the codespace ranges of a CMap shaped like the
// Shift-JIS encodings: one-byte codes from 00 to 80 and from A0 to DF,
// two-byte codes whose first byte is 81 to 9F or E0 to FC and whose second is
// 40 to FC. 9.7.6.2 matches a code against a range byte by byte.
const readsCodespaces = `begincmap
4 begincodespacerange
<00> <80>
<A0> <DF>
<8140> <9FFC>
<E040> <FCFC>
endcodespacerange
`

// readsMixedWidthFont writes a one-page document showing the bytes given
// under a composite font whose encoding CMap declares the codespaces given
// and maps the one-byte codes to ASCII and the two-byte codes to the CJK
// punctuation block; its ToUnicode CMap declares the same codespaces.
func readsMixedWidthFont(codespaces, shown string) []byte {
	b := &pdfgen.Builder{}
	enc := b.Add(pdfgen.Object{
		Body:   "<< /Type /CMap /CMapName /Test-H /CIDSystemInfo << /Registry (Adobe) /Ordering (Japan1) /Supplement 2 >> >>",
		Stream: []byte(codespaces + "2 begincidrange\n<20> <7E> 1\n<8140> <9FFC> 200\nendcidrange\nendcmap\n")})
	tu := b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(codespaces +
		"1 beginbfrange\n<20> <7E> <0020>\n<8140> <9FFC> <3000>\nendbfrange\nendcmap\n")})
	cid := b.Add(pdfgen.Object{Body: "<< /Type /Font /Subtype /CIDFontType0 /BaseFont /Test /CIDSystemInfo << /Registry (Adobe) /Ordering (Japan1) /Supplement 2 >> /DW 1000 >>"})
	f := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Font /Subtype /Type0 /BaseFont /Test /Encoding %d 0 R /DescendantFonts [%d 0 R] /ToUnicode %d 0 R >>", enc, cid, tu)})
	content := "BT /F1 12 Tf 1 0 0 1 72 700 Tm <" + shown + "> Tj ET\n"
	b.Catalog(b.Pages([]pdfgen.Page{{Content: content, Fonts: map[string]int{"F1": f}}}))
	return b.Bytes()
}

// A codespace range holds a code when each of the code's bytes falls in the
// range's own byte at that position. Read as one interval of code values, a
// range admits codes it does not hold, and the bytes of a code the page shows
// as one glyph are split into codes of their own -- characters in the record
// that the page does not show.
func TestReadsCodespaceRangesAreMatchedByteByByte(t *testing.T) {
	for _, c := range []struct {
		name, codespaces, shown, want, note string
	}{
		{"a second byte below the range", readsCodespaces, "813F", "�",
			"81 3F is one two-byte code, 81 being in 81..9F; 3F is no code of its own"},
		{"a page of them", readsCodespaces, "8130813081308130", "����",
			"four two-byte codes in no range, not four codes and four digits"},
		{"a code in the range on both bytes", readsCodespaces, "8141", "、",
			"in 81..9F on the first byte and in 40..FC on the second"},
		{"a range whose ends are of different lengths", `begincmap
3 begincodespacerange
<00> <80>
<81> <9FFC>
<8140> <9FFC>
endcodespacerange
`, "8141", "、",
			"the second pair declares no range: one end says a code is one byte and the other says two"},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsMixedWidthFont(c.codespaces, c.shown)
			r := extract(t, data)
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if got := r.Pages[0].Text; got != c.want {
				t.Errorf("the page shows <%s> and the record reads %q, want %q: %s", c.shown, got, c.want, c.note)
			}
		})
	}
}

// readsStaleFontFile writes a two-page file whose pages both name font 7,
// which the file defines twice: first as mapping code 65 to B, then as
// mapping it to Z. The cross-reference names the first definition; the
// content stream of the page given is named at an offset that holds no
// object, so reading it rebuilds the cross-reference by scanning, after which
// object 7 is the second definition.
func readsStaleFontFile(brokenPage int) []byte {
	type object struct {
		num  int
		body string
	}
	content := func(text string) string {
		s := "BT /F1 12 Tf 1 0 0 1 72 700 Tm (" + text + ") Tj ET\n"
		return fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(s), s)
	}
	page := func(contents int) string {
		return fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 7 0 R >> >> /Contents %d 0 R >>", contents)
	}
	objects := []object{
		{1, "<< /Type /Catalog /Pages 2 0 R >>"},
		{2, "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>"},
		{3, page(5)},
		{4, page(6)},
		{5, content("A")},
		{6, content("A")},
		{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding << /Type /Encoding /Differences [65 /B] >> >>"},
		{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding << /Type /Encoding /Differences [65 /Z] >> >>"},
	}
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n%\xE2\xE3\xCF\xD3\n")
	offsets := map[int]int{}
	for _, o := range objects {
		if _, seen := offsets[o.num]; !seen {
			offsets[o.num] = out.Len()
		}
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", o.num, o.body)
	}
	offsets[4+brokenPage] = 3
	startxref := out.Len()
	fmt.Fprintf(&out, "xref\n0 8\n0000000000 65535 f \n")
	for num := 1; num <= 7; num++ {
		fmt.Fprintf(&out, "%010d 00000 n \n", offsets[num])
	}
	fmt.Fprintf(&out, "trailer\n<< /Size 8 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", startxref)
	return out.Bytes()
}

// A font is held by the reference that named it, and a rebuilt
// cross-reference gives that reference other bytes. A font built before the
// rebuild is not the font the page names after it: held across the rebuild,
// the text of a page depends on which other page of the file was damaged.
func TestReadsFontsAreDroppedWithTheObjectsTheyWereBuiltFrom(t *testing.T) {
	texts := map[int][]string{}
	for _, broken := range []int{1, 2} {
		r := extract(t, readsStaleFontFile(broken))
		if r.Fatal != nil || len(r.Pages) != 2 {
			t.Fatalf("page %d damaged: fatal %+v pages %+v", broken, r.Fatal, r.Pages)
		}
		for _, p := range r.Pages {
			texts[broken] = append(texts[broken], p.Text)
		}
		t.Logf("page %d damaged: the record reads %q", broken, texts[broken])
	}
	// Both files are rebuilt before page 2 is read, and the rebuilt object 7
	// maps code 65 to Z.
	for _, broken := range []int{1, 2} {
		if texts[broken][1] != "Z" {
			t.Errorf("page %d damaged: page 2 reads %q, and the object the page names maps its code to %q", broken, texts[broken][1], "Z")
		}
	}
	if texts[1][1] != texts[2][1] {
		t.Errorf("page 2 reads %q when page 1's content is damaged and %q when page 2's is; the same page, the same font, and the damage is in neither", texts[1][1], texts[2][1])
	}
}

// A predefined CMap the reader does not carry leaves the font's own ToUnicode
// map to say how long its codes are: reading every code as two bytes loses
// the text of an encoding whose codes are one byte or two.
func TestReadsPredefinedCMapCodesAreSplitByTheToUnicodeCMap(t *testing.T) {
	b := &pdfgen.Builder{}
	tu := b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(readsCodespaces +
		"1 beginbfrange\n<20> <7E> <0020>\n<8140> <9FFC> <3000>\nendbfrange\nendcmap\n")})
	cid := b.Add(pdfgen.Object{Body: "<< /Type /Font /Subtype /CIDFontType0 /BaseFont /Test /CIDSystemInfo << /Registry (Adobe) /Ordering (Japan1) /Supplement 2 >> /DW 1000 >>"})
	f := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Font /Subtype /Type0 /BaseFont /Test /Encoding /90ms-RKSJ-H /DescendantFonts [%d 0 R] /ToUnicode %d 0 R >>", cid, tu)})
	b.Catalog(b.Pages([]pdfgen.Page{{Content: "BT /F1 12 Tf 1 0 0 1 72 700 Tm <48656C6C6F> Tj ET\n", Fonts: map[string]int{"F1": f}}}))
	data := b.Bytes()
	r := extract(t, data)
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if got := r.Pages[0].Text; got != "Hello" {
		t.Errorf("the page shows the one-byte codes of %q and the record reads %q with %d glyphs unmapped; the font's ToUnicode CMap declares <00> <80> as a codespace", "Hello", got, r.Pages[0].Unmapped)
	}
}

// A string shown before any Tf leaves no font under the empty name: that is a
// name a page's /Font may carry, and a Tf that selects it must find the font
// the page declares.
func TestReadsAFontResourceNamedByTheEmptyNameIsFound(t *testing.T) {
	b := &pdfgen.Builder{}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	b.Catalog(b.Pages([]pdfgen.Page{{
		Content: "BT 1 0 0 1 72 700 Tm (first) Tj / 12 Tf 1 0 0 1 72 680 Tm (second) Tj ET\n",
		Fonts:   map[string]int{"": helv}}}))
	r := extract(t, b.Bytes())
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	// The first string is shown under no font and is unmapped, one glyph for
	// each of its five bytes; the second is shown under Helvetica.
	if got, want := r.Pages[0].Text, strings.Repeat("�", 5)+"\nsecond"; got != want {
		t.Errorf("the record reads %q with %d glyphs unmapped, want %q", got, r.Pages[0].Unmapped, want)
	}
}

// readsObjStmDocument writes a document whose object 3 -- the one page the
// page tree names -- the cross-reference stream places inside object stream 5
// at the index given. The object stream's own header declares object 99 at
// index 0 and object 3 at index 1.
func readsObjStmDocument(indexForObject3 int) []byte {
	page := func(contents int) string {
		return fmt.Sprintf("<< /Type /Page /Parent 2 0 R /Contents %d 0 R /Resources << /Font << /F1 7 0 R >> >> >>", contents)
	}
	bodies := []string{page(6), page(8)}
	header := fmt.Sprintf("99 0 3 %d ", len(bodies[0]))
	payload := header + bodies[0] + bodies[1]

	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	offsets := map[int]int{}
	add := func(num int, body string) {
		offsets[num] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj%s endobj\n", num, body)
	}
	addStream := func(num int, dict string, data string) {
		offsets[num] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj<< %s /Length %d >>stream\n%s\nendstream endobj\n", num, dict, len(data), data)
	}
	add(1, "<< /Type /Catalog /Pages 2 0 R >>")
	add(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	addStream(5, fmt.Sprintf("/Type /ObjStm /N 2 /First %d", len(header)), payload)
	addStream(6, "", "BT /F1 12 Tf 10 700 Td (WRONG) Tj ET")
	add(7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	addStream(8, "", "BT /F1 12 Tf 10 700 Td (RIGHT) Tj ET")

	// The cross-reference stream, object 4, with /W [1 2 2].
	xrefAt := out.Len()
	entries := make([]byte, 0, 9*5)
	put := func(typ, f2, f3 int) {
		entries = append(entries, byte(typ), byte(f2>>8), byte(f2), byte(f3>>8), byte(f3))
	}
	put(0, 0, 65535)
	for num := 1; num <= 8; num++ {
		switch num {
		case 3:
			put(2, 5, indexForObject3)
		case 4:
			put(1, xrefAt, 0)
		default:
			put(1, offsets[num], 0)
		}
	}
	fmt.Fprintf(&out, "4 0 obj<< /Type /XRef /Size 9 /W [1 2 2] /Root 1 0 R /Length %d >>stream\n", len(entries))
	out.Write(entries)
	out.WriteString("\nendstream endobj\n")
	fmt.Fprintf(&out, "startxref\n%d\n%%%%EOF\n", xrefAt)
	return out.Bytes()
}

// An object stream is read by the number wanted, which its own header says
// where to find. A cross-reference entry names a position in that header, and
// a position is not a name: an entry that names another object's position
// would otherwise have the record carry, under the number the page asked for,
// whatever the stream holds there.
func TestReadsObjectStreamServesTheNumberWanted(t *testing.T) {
	for _, index := range []int{1, 0} {
		r := extract(t, readsObjStmDocument(index))
		got := ""
		if len(r.Pages) == 1 {
			got = r.Pages[0].Text
		}
		if got != "RIGHT" {
			t.Errorf("object 3 placed at index %d: the record reads %q, the stream declares object 3 to be the page whose content is %q (fatal %+v pages %+v)", index, got, "RIGHT", r.Fatal, r.Pages)
		}
	}
}

// readsTwoSectionDoc writes a readable one-page document whose cross-reference
// is a table naming a second section: a cross-reference stream whose /W is a
// chain of chainLen indirect references. The stream is damage the reader
// rebuilds past by scanning; a chain longer than maxRefDepth is a bound met
// on the way, in the cross-reference the reader then throws away.
func readsTwoSectionDoc(chainLen int) []byte {
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	offsets := map[int]int{}
	add := func(num int, body string) {
		offsets[num] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj %s endobj\n", num, body)
	}
	add(1, "<< /Type /Catalog /Pages 2 0 R >>")
	add(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	add(3, "<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>")
	content := "BT /F1 12 Tf 10 700 Td (Hello) Tj ET"
	offsets[4] = out.Len()
	fmt.Fprintf(&out, "4 0 obj<< /Length %d >>stream\n%s\nendstream endobj\n", len(content), content)
	add(5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	// The chain: 10 -> 11 -> ... -> 10+chainLen-1, which is a dictionary and
	// so is not the array /W wants either way.
	for i := 0; i < chainLen-1; i++ {
		add(10+i, fmt.Sprintf("%d 0 R", 11+i))
	}
	add(10+chainLen-1, "<< >>")
	sectionB := out.Len()
	fmt.Fprintf(&out, "44 0 obj<< /Type /XRef /W 10 0 R /Size 50 /Length 5 >>stream\nAAAAA\nendstream endobj\n")
	sectionA := out.Len()
	out.WriteString("xref\n1 5\n")
	for num := 1; num <= 5; num++ {
		fmt.Fprintf(&out, "%010d %05d n \n", offsets[num], 0)
	}
	fmt.Fprintf(&out, "10 %d\n", chainLen)
	for i := 0; i < chainLen; i++ {
		fmt.Fprintf(&out, "%010d %05d n \n", offsets[10+i], 0)
	}
	fmt.Fprintf(&out, "trailer<< /Size 50 /Root 1 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n", sectionB, sectionA)
	return out.Bytes()
}

// A bound met reading a cross-reference the reader then throws away goes with
// it: the document the walk then reads is the one the rebuild produced, and
// its page tree is whole.
func TestReadsBoundFromADiscardedCrossReferenceDoesNotEndTheWalk(t *testing.T) {
	for _, chainLen := range []int{5, maxRefDepth + 2} {
		data := readsTwoSectionDoc(chainLen)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		r := Extract(ctx, data, testOptions())
		cancel()
		got := ""
		if len(r.Pages) == 1 {
			got = r.Pages[0].Text
		}
		if got != "Hello" {
			t.Errorf("a chain of %d: the record reads %q, the rebuilt document holds %q (fatal %+v pages %+v)", chainLen, got, "Hello", r.Fatal, r.Pages)
		}
	}
}
