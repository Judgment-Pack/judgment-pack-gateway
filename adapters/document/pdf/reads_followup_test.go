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
// beside this one's, never the assertion itself. What it reads is its
// standard output alone: the diagnostics it writes beside it are logged as
// diagnostics and are not the text it read.
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
	cmd := exec.Command(tool, file, "-")
	var diagnostics bytes.Buffer
	cmd.Stderr = &diagnostics
	out, err := cmd.Output()
	if diagnostics.Len() > 0 {
		t.Logf("pdftotext wrote %q as diagnostics", diagnostics.String())
	}
	if err != nil {
		t.Logf("pdftotext refused the document: %v", err)
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
	return readsResourcePage(content, "", false)
}

// readsResourcePage is a one-page document whose content is the bytes given,
// with a Helvetica resource named F1 and the resource entries given beside
// it. Where inForm is set the content is a form XObject the page draws, with
// those resources its own: what the content names is then what the form
// declares and not what the page does.
func readsResourcePage(content []byte, resources string, inForm bool) []byte {
	b := &pdfgen.Builder{}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	declared := fmt.Sprintf("<< /Font << /F1 %d 0 R >> %s >>", helv, resources)
	page := declared
	if inForm {
		form := b.Add(pdfgen.Object{Body: "<< /Type /XObject /Subtype /Form /BBox [0 0 612 792] /Resources " + declared + " >>", Stream: content})
		content = []byte("/X Do")
		page = fmt.Sprintf("<< /XObject << /X %d 0 R >> >>", form)
	}
	pages := b.Next()
	b.Add(pdfgen.Object{Body: "placeholder"})
	cs := b.Add(pdfgen.Object{Body: "<< >>", Stream: content})
	num := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] /Resources %s /Contents %d 0 R >>", pages, page, cs)})
	b.Set(pages, pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%d 0 R] /Count 1 >>", num)})
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

// An image a filter encodes ends where the filter's data ends, whatever the
// data holds: an "EI" among the encoded bytes is one of them, and so is one
// that operators follow.
func TestReadsFilteredInlineImageEndsAtItsEI(t *testing.T) {
	for _, c := range []struct {
		name    string
		samples string
	}{
		{"encoded bytes holding no EI", "41414141>"},
		{"an EI among the encoded bytes", "41 EI \xff\xff\xff41>"},
		{"an EI among them that operators follow", "41 EI \n" + hexOf(pdfgen.Text("F1", 12, []string{"NOT ON THE PAGE"})) + ">"},
	} {
		t.Run(c.name, func(t *testing.T) {
			content := shown("before", 700) + "BI /W 4 /H 4 /BPC 8 /CS /G /F /AHx ID " + c.samples + " EI\n" + shown("after", 680)
			data := readsContentPage([]byte(content))
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != "before\nafter" {
				t.Errorf("the record reads %q, want %q (problems %+v)", got, "before\nafter", r.Problems)
			}
		})
	}
}

// What follows an inline image does not decide where it ends. The image
// below is framed by its filter, and the bytes after it -- a marked-content
// sequence long enough to run past any window a reader might look through,
// carrying "EI" inside its own property list -- are the page's content and
// nothing to do with the image.
func TestReadsWhatFollowsAnInlineImageDoesNotEndIt(t *testing.T) {
	for _, pad := range []int{4, 64, 200, 4096} {
		t.Run(fmt.Sprintf("%d bytes of property list", pad), func(t *testing.T) {
			var content bytes.Buffer
			content.WriteString(shown("before", 700))
			content.WriteString("BI /W 4 /H 4 /BPC 8 /CS /G /F /AHx ID 41414141> EI")
			content.WriteString("\n/Artifact << /Type /Pagination /Pad (" + strings.Repeat("p", pad) + " EI Q) >> BDC\n")
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

// readsHiddenSamples are 320 sample bytes whose first hold a delimited "EI"
// and the operators of a line of text: what a reader that looks for "EI"
// rather than for the end the image states would put on the page.
func readsHiddenSamples() []byte {
	hidden := "\n EI\n" + shown("HIDDEN", 650)
	return []byte(hidden + strings.Repeat("A", 320-len(hidden)))
}

// A colour space an inline image names is one of the resources in force, and
// how many components it has says how long the image's samples are. Without
// it the samples cannot be measured, and an "EI" among them would end the
// image where the image does not.
func TestReadsInlineImageInANamedColourSpace(t *testing.T) {
	const declared = "/ColorSpace << /MyGray [/CalGray << /WhitePoint [1 1 1] >>] >>"
	for _, c := range []struct {
		name   string
		inForm bool
	}{{"named by the page", false}, {"named by the form that draws it", true}} {
		t.Run(c.name, func(t *testing.T) {
			var content bytes.Buffer
			content.WriteString("BI /W 40 /H 8 /BPC 8 /CS /MyGray ID ")
			content.Write(readsHiddenSamples())
			content.WriteString("\nEI\n")
			content.WriteString(shown("REAL", 700))
			data := readsResourcePage(content.Bytes(), declared, c.inForm)
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != "REAL" {
				t.Errorf("the record reads %q; the page shows %q and the rest lies inside the image", got, "REAL")
			}
		})
	}
}

// The length an image states is not read over the length its samples take: a
// viewer draws the samples the image describes, and where the two disagree
// the image has not said where its data ends.
func TestReadsInlineImageLengthDoesNotOverrideTheSamples(t *testing.T) {
	samples := readsHiddenSamples()
	t.Run("a length of nothing over samples that measure", func(t *testing.T) {
		data := readsInlineImagePage("/W 40 /H 8 /BPC 8 /CS /G /L 0", samples, shown("REAL", 700))
		r := extract(t, data)
		if out, ok := readsPoppler(t, data); ok {
			t.Logf("pdftotext reads %q", out)
		}
		if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Text != "REAL" {
			t.Fatalf("the record reads %+v (fatal %+v); the samples of a 40 by 8 image of one byte take 320 bytes", r.Pages, r.Fatal)
		}
	})
	t.Run("a length the samples contradict", func(t *testing.T) {
		// 40 by 80 samples of one byte take 3,200, and the image carries 320.
		data := readsInlineImagePage("/W 40 /H 80 /BPC 8 /CS /G /L 320", samples, shown("REAL", 700))
		r := extract(t, data)
		if out, ok := readsPoppler(t, data); ok {
			t.Logf("pdftotext reads %q", out)
		}
		if r.Fatal != nil || len(r.Pages) != 1 {
			t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
		}
		// The samples say the data runs past the "EI" the length points at,
		// and nothing in the file says which of the two the image meant.
		if r.Pages[0].Status != PageFailed || r.Pages[0].Text != "" {
			t.Errorf("the record reads %s %q, and the image says both 320 bytes and 3,200", r.Pages[0].Status, r.Pages[0].Text)
		}
	})
}

// A key of an inline image's dictionary given twice, in either of the two
// spellings 8.9.7 gives it, with values that disagree, says two things about
// where the data ends. The page fails rather than the reader preferring one
// of them -- which of the two it preferred would decide whether the record
// carries text the page does not show.
func TestReadsInlineImageThatSaysTwoThings(t *testing.T) {
	samples := readsHiddenSamples()
	for _, c := range []struct {
		name, dict string
		fails      bool
	}{
		{"the abbreviated key first", "/W 40 /Width 1 /H 8 /BPC 8 /CS /G", true},
		{"the written key first", "/Width 1 /W 40 /H 8 /BPC 8 /CS /G", true},
		{"the same key twice", "/W 40 /W 1 /H 8 /BPC 8 /CS /G", true},
		{"both spellings, agreeing", "/W 40 /Width 40 /H 8 /BPC 8 /CS /G", false},
		{"a key that does not bear on the end, twice", "/W 40 /H 8 /BPC 8 /CS /G /I true /Interpolate false", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsInlineImagePage(c.dict, samples, shown("REAL", 700))
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			want, status := "", PageFailed
			if !c.fails {
				want, status = "REAL", PageOK
			}
			if r.Pages[0].Status != status || r.Pages[0].Text != want {
				t.Errorf("the record reads %s %q, want %s %q", r.Pages[0].Status, r.Pages[0].Text, status, want)
			}
		})
	}
}

// readsJPEG is a JPEG the reader never decodes: a marker segment, a scan
// whose entropy-coded data holds a delimited "EI", the operators of a line of
// text, a stuffed FF 00 and a restart marker, and the end-of-image marker.
func readsJPEG() []byte {
	out := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x04, 0x41, 0x42, 0xFF, 0xDA, 0x00, 0x04, 0x00, 0x00}
	out = append(out, " EI\n"+shown("HIDDEN", 650)...)
	out = append(out, 0xFF, 0x00, 0xFF, 0xD0, 'x', 0xFF, 0xD9)
	return out
}

// readsStoredFlate is a zlib stream of one stored deflate block: the bytes
// given lie in it as they are, so an image encoded by it carries whatever
// they hold, and only the deflate framing says where the stream ends.
func readsStoredFlate(data []byte) []byte {
	out := []byte{0x78, 0x01, 0x01, byte(len(data)), byte(len(data) >> 8), byte(^len(data)), byte(^len(data) >> 8)}
	out = append(out, data...)
	a, b := uint32(1), uint32(0)
	for _, x := range data {
		a = (a + uint32(x)) % 65521
		b = (b + a) % 65521
	}
	sum := b<<16 | a
	return append(out, byte(sum>>24), byte(sum>>16), byte(sum>>8), byte(sum))
}

// An image a filter encodes ends where that filter's own framing ends. The
// samples of such an image are not the reader's to measure, and the bytes
// they hold -- an "EI" and a line of text among them -- are the image's.
func TestReadsFilteredInlineImageIsFramedByItsFilter(t *testing.T) {
	hidden := []byte("\n EI\n" + shown("HIDDEN", 650) + strings.Repeat("A", 32))
	for _, c := range []struct {
		name, dict string
		samples    []byte
	}{
		{"ASCIIHexDecode", "/W 8 /H 8 /BPC 8 /CS /G /F /AHx", hexStreamOf(hidden)},
		{"ASCII85Decode", "/W 8 /H 8 /BPC 8 /CS /G /F /A85", a85Of(hidden)},
		{"RunLengthDecode", "/W 8 /H 8 /BPC 8 /CS /G /F [/RL]", runLengthOf(hidden)},
		{"FlateDecode", "/W 8 /H 8 /BPC 8 /CS /G /F /Fl", flateOf(hidden)},
		{"FlateDecode, stored", "/W 40 /H 8 /BPC 8 /CS /G /F /Fl", readsStoredFlate(readsHiddenSamples())},
		{"LZWDecode", "/W 8 /H 8 /BPC 8 /CS /G /F /LZW /DP << /EarlyChange 0 >>", lzwOf(hidden)},
		{"DCTDecode", "/W 8 /H 8 /BPC 8 /CS /G /F /DCT", readsJPEG()},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsInlineImagePage(c.dict, c.samples, shown("REAL", 700))
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != "REAL" {
				t.Errorf("the record reads %q; %s frames the image's data, and the rest lies inside it (problems %+v)", got, c.name, r.Problems)
			}
		})
	}
}

// A compatibility section is where a writer may use operators this reader
// does not know. An image inside one ends where its filter's data ends, and
// an operator the reader has never heard of after it is no reason to read the
// image differently.
func TestReadsInlineImageInACompatibilitySection(t *testing.T) {
	content := "BX\n" + shown("before", 700) + "BI /W 4 /H 1 /BPC 8 /CS /G /F /AHx ID 41414141> EI\nFutureOperator\nEX\n" + shown("after", 680)
	data := readsContentPage([]byte(content))
	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if got := r.Pages[0].Text; got != "before\nafter" {
		t.Errorf("the record reads %q, want %q (problems %+v)", got, "before\nafter", r.Problems)
	}
}

// An image whose dictionary never reaches its data fails the page. What lies
// after BI was read as a dictionary and is not the page's content, and where
// the image would have ended is not known either.
func TestReadsInlineImageThatNeverReachesItsDataFailsThePage(t *testing.T) {
	for _, c := range []struct{ name, content string }{
		{"no ID", shown("before", 700) + "BI /W 4 /H 4 /BPC 8 /CS /G " + shown("after", 680)},
		{"an EI before the ID", shown("before", 700) + "BI /W 4 /H 4 /BPC 8 /CS /G EI\n" + shown("after", 680)},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsContentPage([]byte(c.content))
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if r.Pages[0].Status != PageFailed || r.Pages[0].Text != "" {
				t.Errorf("the record reads %s %q; the image's data never begins", r.Pages[0].Status, r.Pages[0].Text)
			}
			if len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" {
				t.Errorf("problems %+v", r.Problems)
			}
		})
	}
}

// An image the reader can neither measure nor frame ends nowhere it can
// establish: not at the length the image states, which viewers disagree over,
// and not at an "EI" among its bytes, which a page's own content holds as
// readily as an image's data does. The page fails, and says so.
func TestReadsUnframedInlineImageFailsThePage(t *testing.T) {
	samples := readsHiddenSamples()
	for _, c := range []struct{ name, dict string }{
		{"a filter the reader does not frame", "/W 40 /H 8 /BPC 8 /CS /G /F /CCF /DP << /EndOfBlock false >>"},
		{"and the length it states", "/W 40 /H 8 /BPC 8 /CS /G /F /CCF /DP << /EndOfBlock false >> /L 0"},
		{"a length over the whole of the data", "/W 40 /H 8 /BPC 8 /CS /G /F /CCF /DP << /EndOfBlock false >> /L 320"},
		{"a filter the reader does not know", "/W 40 /H 8 /BPC 8 /CS /G /F /SomeFutureDecode"},
		{"the identity filter, which frames nothing", "/W 40 /H 8 /BPC 8 /CS /G /F /Crypt"},
		{"samples it cannot measure", "/W 40 /H 8 /BPC 8 /CS /NotAResource"},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsInlineImagePage(c.dict, samples, shown("REAL", 700))
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if r.Pages[0].Status != PageFailed || r.Pages[0].Text != "" {
				t.Errorf("the record reads %s %q; where the image's data ends is not something this file establishes", r.Pages[0].Status, r.Pages[0].Text)
			}
			if len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" {
				t.Errorf("problems %+v", r.Problems)
			}
		})
	}
}

// Bytes in no codespace range of a font's encoding are no code of that font.
// The number they make may fall inside a mapping, and what that mapping holds
// is not what the page shows: the glyph is unmapped and counted.
func TestReadsACodeInNoCodespaceIsUnmapped(t *testing.T) {
	for _, shown := range []string{"8200", "82FF"} {
		t.Run(shown, func(t *testing.T) {
			data := readsMixedWidthFont(readsCodespaces, shown)
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if r.Pages[0].Text != "�" || r.Pages[0].Unmapped != 1 {
				t.Errorf("the page shows <%s>, which the font's codespace ranges do not hold, and the record reads %q with %d glyphs unmapped",
					shown, r.Pages[0].Text, r.Pages[0].Unmapped)
			}
		})
	}
}

// A code in no range is consumed by the partial match of 9.7.6.3: the range
// holding the longest run of its leading bytes says how many bytes it has,
// and the shortest of the ranges holding the same run decides between them.
// Taking too few leaves bytes of one code to be read as codes of their own --
// characters the page does not show -- and taking too many swallows the code
// after it.
func TestReadsPartialMatchTakesTheLongestPrefix(t *testing.T) {
	for _, c := range []struct{ name, ranges, shown, want string }{
		{"a longer range matches further", "<8140> <81FC> <813040> <8130FC> <20> <7E>", "81303141", "�A"},
		{"ranges that match as far as each other", "<813040> <8130FC> <8140> <81FC> <20> <7E>", "813141", "�A"},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsMixedWidthFont("begincmap 3 begincodespacerange "+c.ranges+" endcodespacerange\n", c.shown)
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != c.want {
				t.Errorf("the page shows <%s> and the record reads %q, want %q", c.shown, got, c.want)
			}
		})
	}
}

// readsObject is one indirect object of a hand-written file. A number given
// twice is written twice: the cross-reference names the first, and a rebuild
// by scanning finds the last.
type readsObject struct {
	num  int
	body string
}

// readsStreamObject is a stream object's body, with the /Length it needs.
func readsStreamObject(dict, data string) string {
	return fmt.Sprintf("<< %s /Length %d >>\nstream\n%s\nendstream", dict, len(data), data)
}

// readsRawFile writes a document whose cross-reference is a stream: the
// objects given at their offsets, the numbers of inStream declared to lie in
// an object stream at an index, and the offset of the object numbered broken
// written as 3, so that reading that object rebuilds the cross-reference by
// scanning the file.
func readsRawFile(objects []readsObject, broken int, inStream map[int][2]int) []byte {
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	offsets := map[int]int{}
	for _, o := range objects {
		if _, written := offsets[o.num]; !written {
			offsets[o.num] = out.Len()
		}
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", o.num, o.body)
	}
	if broken > 0 {
		offsets[broken] = 3
	}
	const numbers = 20
	at := out.Len()
	var entries []byte
	put := func(kind, first, second int) {
		entries = append(entries, byte(kind), byte(first>>24), byte(first>>16), byte(first>>8), byte(first), byte(second>>8), byte(second))
	}
	for num := 0; num <= numbers; num++ {
		switch pair, compressed := inStream[num]; {
		case num == numbers:
			put(1, at, 0)
		case compressed:
			put(2, pair[0], pair[1])
		case num > 0 && offsets[num] > 0:
			put(1, offsets[num], 0)
		default:
			put(0, 0, 0)
		}
	}
	fmt.Fprintf(&out, "%d 0 obj << /Type /XRef /Size %d /W [1 4 2] /Root 1 0 R /Length %d >> stream\n", numbers, numbers+1, len(entries))
	out.Write(entries)
	fmt.Fprintf(&out, "\nendstream endobj\nstartxref\n%d\n%%%%EOF\n", at)
	return out.Bytes()
}

// An object read out of an object stream is dropped with the cross-reference
// that said it was there. Under the rebuilt one that stream's number names an
// ordinary dictionary: the object is not in the file at all, and the font it
// held is not the page's font.
func TestReadsAStaleObjectStreamIsDroppedWithItsCrossReference(t *testing.T) {
	font := "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding << /Differences [65 /B] >> >>"
	data := readsRawFile([]readsObject{
		{1, "<< /Type /Catalog /Pages 2 0 R >>"},
		{2, "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 /Resources << /Font << /F1 9 0 R >> >> >>"},
		{3, "<< /Type /Page /Parent 2 0 R /Contents 6 0 R >>"},
		{4, "<< /Type /Page /Parent 2 0 R /Contents 8 0 R >>"},
		{5, readsStreamObject("/Type /ObjStm /N 1 /First 4", "9 0 "+font)},
		{6, readsStreamObject("", shown("A", 700))},
		{8, readsStreamObject("", shown("A", 700))},
		// The rebuild finds this at object 5 instead of the object stream.
		{5, "<< /Type /SomethingElse >>"},
	}, 8, map[int][2]int{9: {5, 0}})

	// The reader's own resolver: object 9 is read out of the object stream
	// under the cross-reference the file carries, and is nowhere under the
	// one the rebuild produces.
	d := openGenerated(t, data)
	if _, read := d.resolveRead(ref{9, 0}); !read {
		t.Fatal("object 9 was not read out of the object stream the cross-reference names")
	}
	if err := d.reconstruct(); err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if v, read := d.resolveRead(ref{9, 0}); read {
		t.Errorf("object 9 reads %v after the rebuild, and object 5 is %v", v, d.object(5))
	}

	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 2 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	for _, p := range r.Pages {
		if p.Text != "�" || p.Unmapped != 1 {
			t.Errorf("page %d reads %q with %d glyphs unmapped; the font the page names is not in the rebuilt document", p.Number, p.Text, p.Unmapped)
		}
	}
}

// A font selected before the cross-reference was rebuilt is not the font the
// page names after it. The reading begins again rather than carrying the
// font, the graphics state and the pages it gathered across the rebuild.
func TestReadsAFontSelectedBeforeARebuildIsNotReusedAfterIt(t *testing.T) {
	font := func(glyph string) string {
		return "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding << /Differences [65 /" + glyph + "] >> >>"
	}
	data := readsRawFile([]readsObject{
		{1, "<< /Type /Catalog /Pages 2 0 R >>"},
		{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
		{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> /XObject << /X 8 0 R >> >> /Contents 6 0 R >>"},
		{6, readsStreamObject("", shown("A", 700)+"/X Do\n"+shown("A", 680))},
		{7, font("B")},
		// The form is read between the two lines, and its offset is damaged.
		{8, readsStreamObject("/Type /XObject /Subtype /Form /BBox [0 0 10 10]", " ")},
		{7, font("Z")},
	}, 8, nil)
	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	// Both lines are shown under the font object 7 names in the rebuilt
	// document, and neither under the one it named before.
	if got := r.Pages[0].Text; got != "Z\nZ" {
		t.Errorf("the record reads %q, want %q: one page, one font, one cross-reference", got, "Z\nZ")
	}
}

// The resources a page carries are read while the page tree is walked, before
// any page is extracted. A rebuild during the extraction leaves them naming
// objects the document no longer has, and the pages are walked again.
func TestReadsResourcesWalkedUnderAnOldCrossReferenceAreReadAgain(t *testing.T) {
	font := func(glyph string) string {
		return "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding << /Differences [65 /" + glyph + "] >> >>"
	}
	data := readsRawFile([]readsObject{
		{1, "<< /Type /Catalog /Pages 2 0 R >>"},
		{2, "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>"},
		{3, "<< /Type /Page /Parent 2 0 R /Resources 10 0 R /Contents 6 0 R >>"},
		{4, "<< /Type /Page /Parent 2 0 R /Resources 10 0 R /Contents 8 0 R >>"},
		// Page 1's content is at a damaged offset: reading it rebuilds.
		{6, readsStreamObject("", shown("A", 700))},
		{8, readsStreamObject("", shown("A", 700))},
		{10, "<< /Font << /F1 7 0 R >> >>"},
		{7, font("B")},
		{10, "<< /Font << /F1 11 0 R >> >>"},
		{11, font("Z")},
	}, 6, nil)
	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 2 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	for _, p := range r.Pages {
		if p.Text != "Z" {
			t.Errorf("page %d reads %q; both pages name the resources object the rebuilt document holds", p.Number, p.Text)
		}
	}
}

// An object stream whose header declares one number twice says two things
// about it, and the number alone no longer finds a body. The cross-reference
// entry's index decides, and only where the header declares that number at
// it: the reader reads the body the file's two statements agree on.
func TestReadsObjectStreamHeaderDeclaringANumberTwice(t *testing.T) {
	// The header of the fixture declares object 3 at both indexes, the first
	// holding the page whose content reads WRONG and the second RIGHT.
	for _, c := range []struct {
		index int
		want  string
	}{{0, "WRONG"}, {1, "RIGHT"}} {
		t.Run(fmt.Sprint(c.index), func(t *testing.T) {
			data := bytes.Replace(readsObjStmDocument(c.index), []byte("99 0 3 "), []byte("3  0 3 "), 1)
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			got := ""
			if len(r.Pages) == 1 {
				got = r.Pages[0].Text
			}
			if got != c.want {
				t.Errorf("object 3 declared twice and named at index %d: the record reads %q, want %q (fatal %+v)", c.index, got, c.want, r.Fatal)
			}
		})
	}
	// An entry naming a position the header does not declare that number at
	// leaves the object unread: the two do not agree, and neither body is the
	// object's own.
	data := bytes.Replace(readsObjStmDocument(5), []byte("99 0 3 "), []byte("3  0 3 "), 1)
	r := extract(t, data)
	if r.Fatal == nil || r.Fatal.Code != "pdf-malformed" {
		t.Errorf("an index the header declares another number at: fatal %+v pages %+v", r.Fatal, r.Pages)
	}
}

// A page tree whose root is among its own kids holds the pages below it once:
// the root stands under itself as every other node does.
func TestReadsARootAmongItsOwnKidsListsItsPagesOnce(t *testing.T) {
	data := tabled([]string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [2 0 R 3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
		readsStreamObject("", shown("ONE", 700)),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}, 0)
	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || r.PageCount != 1 || len(r.Pages) != 1 || r.Pages[0].Text != "ONE" {
		t.Fatalf("fatal %+v count %d pages %+v", r.Fatal, r.PageCount, r.Pages)
	}
}

// A font whose encoding is a predefined CMap the reader does not carry has no
// CID for a code: the CMap that would give it is not in the file. The width
// such a glyph takes is the font's own default, /DW, and not the width of the
// CID a reader would invent by taking the code for one -- an invented CID
// hits whatever /W declares at that number, and the space the record carries
// between two glyphs is inferred from where the pen lands.
func TestReadsWidthOfACodeUnderAnUncarriedCMap(t *testing.T) {
	b := &pdfgen.Builder{}
	tu := b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(readsCodespaces + "1 beginbfchar <8141> <3001> endbfchar endcmap")})
	// 33,089 is the code read as a CID; 634 is the CID the registry's own
	// CMap gives it. The font declares half an em for both, and a whole em
	// for every CID it does not name.
	cid := b.Add(pdfgen.Object{Body: "<< /Type /Font /Subtype /CIDFontType0 /BaseFont /Test /CIDSystemInfo << /Registry (Adobe) /Ordering (Japan1) /Supplement 2 >> /DW 1000 /W [634 [500] 33089 [500]] >>"})
	f := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Font /Subtype /Type0 /BaseFont /Test /Encoding /90ms-RKSJ-H /ToUnicode %d 0 R /DescendantFonts [%d 0 R] >>", tu, cid)})
	content := "BT /F1 12 Tf 1 0 0 1 72 700 Tm <8141> Tj 1 0 0 1 80 700 Tm <8141> Tj ET"
	b.Catalog(b.Pages([]pdfgen.Page{{Content: content, Fonts: map[string]int{"F1": f}}}))
	data := b.Bytes()
	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if got := r.Pages[0].Text; got != "、、" {
		t.Errorf("the record reads %q, want %q: the glyphs take the default width the font declares, so the second stands where the first ends and no space is inferred", got, "、、")
	}
}

// Encoded data that carries, inside itself, a delimited "EI" and the
// operators of a line of text: what a reader that looked for "EI" in an
// image's data rather than for the end of its encoding would put on the page.
func readsHiddenEncoded() []byte {
	return []byte("\n EI\n" + shown("HIDDEN", 650))
}

// readsEndOfLines is the bits of n end-of-line codes of T.4 -- eleven zeros
// and a one, twelve bits each -- laid end to end: two of them are the
// end-of-facsimile-block of Group 4, and six the return-to-control of Group 3.
func readsEndOfLines(n int) []byte {
	var out []byte
	var acc, bits uint32
	for i := 0; i < n; i++ {
		acc, bits = acc<<12|1, bits+12
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

// readsJBIG2 is an embedded JBIG2 image of one segment: the header of 7.2 of
// ISO 14492 -- number, flags, no referred-to segments, page, and the length
// of what follows -- and the bytes given as that segment's data.
func readsJBIG2(data []byte) []byte {
	out := []byte{0, 0, 0, 1, 0x00, 0x00, 0x01}
	n := len(data)
	out = append(out, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	return append(out, data...)
}

// readsJPX is a JPEG 2000 codestream: its start-of-codestream marker, one
// marker segment carrying the bytes given, and its end-of-codestream marker.
func readsJPX(data []byte) []byte {
	n := len(data) + 2
	out := []byte{0xFF, 0x4F, 0xFF, 0x51, byte(n >> 8), byte(n)}
	return append(append(out, data...), 0xFF, 0xD9)
}

// Every filter the reader frames says for itself where its data ends, and an
// image encoded by one ends there: the "EI" and the operators its encoded
// bytes carry are bytes of the image, and the page is what follows the
// encoding. Disabling any one of these framings fails its own case: nothing
// else establishes an image's end.
func TestReadsInlineImageFramedByEachFilter(t *testing.T) {
	hidden := readsHiddenEncoded()
	for _, c := range []struct {
		name, dict string
		samples    []byte
	}{
		{"ASCIIHexDecode", "/W 8 /H 8 /BPC 8 /CS /G /F /AHx", hexStreamOf(hidden)},
		{"ASCII85Decode", "/W 8 /H 8 /BPC 8 /CS /G /F /A85", a85Of(hidden)},
		{"RunLengthDecode", "/W 8 /H 8 /BPC 8 /CS /G /F [/RL]", runLengthOf(hidden)},
		{"FlateDecode", "/W 8 /H 8 /BPC 8 /CS /G /F /Fl", flateOf(hidden)},
		{"FlateDecode, stored", "/W 40 /H 8 /BPC 8 /CS /G /F /Fl", readsStoredFlate(readsHiddenSamples())},
		{"LZWDecode", "/W 8 /H 8 /BPC 8 /CS /G /F /LZW /DP << /EarlyChange 0 >>", lzwOf(hidden)},
		{"DCTDecode", "/W 8 /H 8 /BPC 8 /CS /G /F /DCT", readsJPEG()},
		{"CCITTFaxDecode, Group 4", "/W 8 /H 8 /BPC 1 /CS /G /F /CCF /DP << /K -1 /Columns 8 >>",
			append(hidden, readsEndOfLines(2)...)},
		{"CCITTFaxDecode, Group 3", "/W 8 /H 8 /BPC 1 /CS /G /F /CCF /DP << /K 0 /Columns 8 >>",
			append(hidden, readsEndOfLines(6)...)},
		{"JBIG2Decode", "/W 8 /H 8 /BPC 1 /CS /G /F /JBIG2Decode", readsJBIG2(hidden)},
		{"JPXDecode", "/W 8 /H 8 /BPC 8 /CS /G /F /JPXDecode", readsJPX(hidden)},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsInlineImagePage(c.dict, c.samples, shown("REAL", 700))
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != "REAL" {
				t.Errorf("the record reads %q; %s says where the image's data ends, and the rest lies inside it (problems %+v)", got, c.name, r.Problems)
			}
		})
	}
}

// A framing that meets the inflate budget has not found the image's end, and
// there is no lesser way to find it: the page fails at the bound it met, and
// the record says a stream of the page went past it.
func TestReadsInlineImageFramingThatMeetsTheInflateBound(t *testing.T) {
	for _, c := range []struct {
		name, dict string
		samples    []byte
	}{
		{"FlateDecode", "/W 40 /H 8 /BPC 8 /CS /G /F /Fl", flateOf(bytes.Repeat([]byte("A"), 320))},
		{"LZWDecode", "/W 40 /H 8 /BPC 8 /CS /G /F /LZW /DP << /EarlyChange 0 >>", lzwOf(bytes.Repeat([]byte("A"), 320))},
	} {
		t.Run(c.name, func(t *testing.T) {
			opt := testOptions()
			opt.MaxInflateTotal, opt.MaxInflateOne = 100, 100
			r := Extract(context.Background(), readsInlineImagePage(c.dict, c.samples, shown("REAL", 700)), opt)
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if r.Pages[0].Status != PageFailed || r.Pages[0].Text != "" {
				t.Errorf("the record reads %s %q; the image's data was not read to its end", r.Pages[0].Status, r.Pages[0].Text)
			}
			if len(r.Problems) != 1 || r.Problems[0].Code != "stream-over-bound" {
				t.Errorf("problems %+v, want the bound the framing met", r.Problems)
			}
		})
	}
}

// readsFax is a Group 4 image of one row, ending in the end-of-facsimile-block
// its encoding puts there.
func readsFax() string {
	return "BI /W 8 /H 1 /BPC 1 /CS /G /F /CCF /DP << /K -1 /Columns 8 /Rows 1 >> ID " +
		string([]byte{0x80, 0x08, 0, 0x80}) + " EI\n"
}

// What follows a whole image is the page's content, whatever it holds: a
// comment, a string or another image may carry the two bytes of an "EI"
// without bearing on where the image before them ended.
func TestReadsContentAfterAWholeImageIsRead(t *testing.T) {
	for _, c := range []struct{ name, tail, want string }{
		{"a comment holding EI", "% EI Q\n" + shown("REAL", 700), "REAL"},
		{"a string holding EI", shown("REAL EI Q", 700), "REAL EI Q"},
		{"a measured image", "BI /W 1 /H 1 /BPC 8 /CS /G ID A EI\n" + shown("REAL", 700), "REAL"},
		{"a framed image", "BI /W 1 /H 1 /BPC 8 /CS /G /F /AHx ID 41> EI\n" + shown("REAL", 700), "REAL"},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsContentPage([]byte(readsFax() + c.tail))
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != c.want {
				t.Errorf("the record reads %q, want %q (status %s, problems %+v)", got, c.want, r.Pages[0].Status, r.Problems)
			}
		})
	}
}

// Two whole images on one page are two images: each ends where its own
// encoding does, and the text around them is the page's.
func TestReadsTwoWholeImagesOnOnePage(t *testing.T) {
	data := readsContentPage([]byte(shown("BEFORE", 700) + readsFax() + readsFax() + shown("AFTER", 680)))
	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if got := r.Pages[0].Text; got != "BEFORE\nAFTER" {
		t.Errorf("the record reads %q, want %q (problems %+v)", got, "BEFORE\nAFTER", r.Problems)
	}
}

// An abbreviation of 8.9.7 and the name it abbreviates are one value written
// twice, and so are a filter written alone and the same filter in an array of
// one: the image says one thing, and the page is read.
func TestReadsInlineImageAbbreviationsAreOneValue(t *testing.T) {
	for _, c := range []struct{ name, dict, samples string }{
		{"a colour space and its name", "/W 4 /H 1 /BPC 8 /CS /G /ColorSpace /DeviceGray", "AAAA"},
		{"the name and its colour space", "/W 4 /H 1 /BPC 8 /ColorSpace /DeviceGray /CS /G", "AAAA"},
		{"a filter and its name", "/W 4 /H 1 /BPC 8 /CS /G /F /AHx /Filter /ASCIIHexDecode", "41414141>"},
		{"the name and its filter", "/W 4 /H 1 /BPC 8 /CS /G /Filter /ASCIIHexDecode /F /AHx", "41414141>"},
		{"a filter alone and in an array", "/W 4 /H 1 /BPC 8 /CS /G /F /AHx /Filter [/AHx]", "41414141>"},
		{"a filter in an array and alone", "/W 4 /H 1 /BPC 8 /CS /G /F [/ASCIIHexDecode] /Filter /AHx", "41414141>"},
		{"parameters as a dictionary and in an array", "/W 4 /H 1 /BPC 8 /CS /G /F /AHx /DP << /K 0 >> /DecodeParms [<< /K 0 >>]", "41414141>"},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsInlineImagePage(c.dict, []byte(c.samples), shown("REAL", 700))
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != "REAL" {
				t.Errorf("the record reads %q (status %s); the two spellings are one value (problems %+v)", got, r.Pages[0].Status, r.Problems)
			}
		})
	}
}

// A colour space of more components than a device has is measured too: a
// DeviceN space separates up to 32 colourants (8.6.6.5), and an image in one
// is as long as its samples say.
func TestReadsInlineImageInAManyComponentColourSpace(t *testing.T) {
	b := &pdfgen.Builder{}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	tint := b.Add(pdfgen.Object{Body: "<< /FunctionType 4 /Domain [0 1 0 1 0 1 0 1 0 1] /Range [0 1 0 1 0 1 0 1] >>", Stream: []byte("{ pop pop pop pop pop 0 0 0 0 }")})
	spaces := fmt.Sprintf("/ColorSpace << /CS5 [/DeviceN [/Cyan /Magenta /Yellow /Black /Spot] /DeviceCMYK %d 0 R] >>", tint)
	var content bytes.Buffer
	// 64 samples of five components of one byte: 320 bytes.
	content.WriteString("BI /W 64 /H 1 /BPC 8 /CS /CS5 ID ")
	content.Write(readsHiddenSamples())
	content.WriteString(" EI\n")
	content.WriteString(shown("REAL", 700))
	_ = helv
	data := readsResourcePage(content.Bytes(), spaces, false)
	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if got := r.Pages[0].Text; got != "REAL" {
		t.Errorf("the record reads %q; five components of 64 samples take 320 bytes (problems %+v)", got, r.Problems)
	}
}

// A pair of an object stream's header the reader cannot use still holds its
// place: a cross-reference entry names an object by the position the header
// gives it, and a place dropped would move every place after it.
func TestReadsObjectStreamHeaderKeepsEveryPosition(t *testing.T) {
	page := func(contents int) string {
		return fmt.Sprintf("<< /Type /Page /Parent 2 0 R /Contents %d 0 R /Resources << /Font << /F1 7 0 R >> >> >>", contents)
	}
	first, second := page(6), page(8)
	// The first pair names an offset the stream does not hold; object 3 is
	// declared at the two places after it.
	header := fmt.Sprintf("99 999999 3 0 3 %d ", len(first))
	for _, c := range []struct {
		index int
		want  string
	}{
		{0, ""}, {1, "FIRST"}, {2, "SECOND"},
	} {
		t.Run(fmt.Sprint(c.index), func(t *testing.T) {
			data := readsRawFile([]readsObject{
				{1, "<< /Type /Catalog /Pages 2 0 R >>"},
				{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
				{5, readsStreamObject(fmt.Sprintf("/Type /ObjStm /N 3 /First %d", len(header)), header+first+second)},
				{6, readsStreamObject("", shown("FIRST", 700))},
				{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"},
				{8, readsStreamObject("", shown("SECOND", 700))},
			}, 0, map[int][2]int{3: {5, c.index}})
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			got := ""
			if len(r.Pages) == 1 {
				got = r.Pages[0].Text
			}
			if got != c.want {
				t.Errorf("index %d: the record reads %q, want %q (fatal %+v)", c.index, got, c.want, r.Fatal)
			}
			if c.want == "" && (r.Fatal == nil || r.Fatal.Code != "pdf-malformed") {
				t.Errorf("index %d: fatal %+v; the header holds no object at that place", c.index, r.Fatal)
			}
		})
	}
}

// A font whose encoding is a predefined CMap the reader does not carry has no
// CID for any code, whether the font declares a ToUnicode map or not: the
// CMap that would give the CID is not in the file, and a width taken at the
// code's own number would be some other glyph's.
func TestReadsNoCIDUnderACMapTheReaderDoesNotCarry(t *testing.T) {
	for _, c := range []struct{ name, toUnicode string }{
		{"no ToUnicode map", ""},
		{"a ToUnicode map declaring no codespace range", "begincmap endcmap"},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := &pdfgen.Builder{}
			extra := ""
			if c.toUnicode != "" {
				num := b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(c.toUnicode)})
				extra = fmt.Sprintf("/ToUnicode %d 0 R", num)
			}
			cid := b.Add(pdfgen.Object{Body: "<< /Type /Font /Subtype /CIDFontType0 /DW 1000 /W [65 [500]] >>"})
			num := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Font /Subtype /Type0 /Encoding /90ms-RKSJ-H /DescendantFonts [%d 0 R] %s >>", cid, extra)})
			b.Catalog(b.Pages([]pdfgen.Page{{}}))
			f := loadFontNumbered(openGenerated(t, b.Bytes()), num)
			g := firstGlyph(f, []byte{0, 65})
			if !g.unmapped || g.width != 1 {
				t.Errorf("code <0041> is %q, unmapped %v, %g em wide; the font declares /DW 1000 and a width for CID 65, which this code is not",
					string(g.runes), g.unmapped, g.width)
			}
		})
	}
}

// A reading of a document's pages stands on one cross-reference. Where an
// object read part of the way through one rebuilds it, nothing read under the
// old one is published or kept: the reading begins again, and what it carries
// is what the rebuilt document holds.
func TestReadsNothingReadUnderAnOldCrossReferenceSurvives(t *testing.T) {
	font := func(glyph, extra string) string {
		return "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding << /Differences [65 /" + glyph + "] >> " + extra + " >>"
	}
	old := shown("OLD", 700)
	for _, c := range []struct {
		name    string
		objects []readsObject
		broken  int
		want    string
	}{
		{"a font whose ToUnicode reference is damaged", []readsObject{
			{1, "<< /Type /Catalog /Pages 2 0 R >>"},
			{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
			{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
			{6, readsStreamObject("", shown("A", 700))},
			{7, font("B", "/ToUnicode 8 0 R")},
			{8, readsStreamObject("", "begincmap endcmap")},
			{7, font("Z", "")},
		}, 8, "Z"},
		{"a stream whose length is a damaged reference", []readsObject{
			{1, "<< /Type /Catalog /Pages 2 0 R >>"},
			{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
			{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
			{6, "<< /Length 8 0 R >>\nstream\n" + old + "endstream"},
			{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"},
			{8, fmt.Sprint(len(old))},
			{6, readsStreamObject("", shown("NEW", 700))},
		}, 8, "NEW"},
		{"a catalog whose page tree is a damaged reference", []readsObject{
			{1, "<< /Type /Catalog /Pages 2 0 R >>"},
			{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 /Resources << /Font << /F1 7 0 R >> >> >>"},
			{3, "<< /Type /Page /Parent 2 0 R /Contents 6 0 R >>"},
			{6, readsStreamObject("", shown("OLD", 700))},
			{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"},
			{1, "<< /Type /Catalog /Pages 12 0 R >>"},
			{12, "<< /Type /Pages /Kids [13 0 R] /Count 1 /Resources << /Font << /F1 7 0 R >> >> >>"},
			{13, "<< /Type /Page /Parent 12 0 R /Contents 16 0 R >>"},
			{16, readsStreamObject("", shown("NEW", 700))},
		}, 2, "NEW"},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsRawFile(c.objects, c.broken, nil)
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != c.want {
				t.Errorf("the record reads %q, want %q: the rebuilt document is the one the record carries", got, c.want)
			}
		})
	}
}

// A bound met in an object the old cross-reference named is a defect of a
// document this one no longer is: the rebuilt document holds a font within
// every bound, and the record carries its pages.
func TestReadsABoundOfADiscardedCrossReferenceDoesNotRefuseTheDocument(t *testing.T) {
	data := readsRawFile([]readsObject{
		{1, "<< /Type /Catalog /Pages 2 0 R >>"},
		{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
		{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> /XObject << /X 8 0 R >> >> /Contents 6 0 R >>"},
		{6, readsStreamObject("", shown("A", 700)+"/X Do\n")},
		{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Junk " + strings.Repeat("[", maxNesting+2) + strings.Repeat("]", maxNesting+2) + " >>"},
		{8, readsStreamObject("/Type /XObject /Subtype /Form /BBox [0 0 10 10]", " ")},
		{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding << /Differences [65 /Z] >> >>"},
	}, 8, nil)
	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil {
		t.Fatalf("fatal %+v; the rebuilt document holds a font the reader reads whole", r.Fatal)
	}
	if len(r.Pages) != 1 || r.Pages[0].Text != "Z" {
		t.Errorf("the record reads %+v, want one page reading %q", r.Pages, "Z")
	}
}
