package pdf

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"context"
	"crypto/md5"
	"crypto/rc4"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
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
	out, _, ok := readsPopplerRead(t, data)
	return out, ok
}

// readsPopplerRead is readsPoppler with the diagnostics poppler wrote beside
// the text, for the tests that ask what the other reader made of a file as
// well as what it read from it.
func readsPopplerRead(t *testing.T, data []byte) (string, string, bool) {
	t.Helper()
	tool, err := exec.LookPath("pdftotext")
	if err != nil {
		return "", "", false
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
		return "", diagnostics.String(), false
	}
	return strings.Trim(string(out), "\n\f"), diagnostics.String(), true
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
	return readsResourceDocument(content, func(*pdfgen.Builder) string { return resources }, inForm)
}

// readsResourceDocument is readsResourcePage whose resource entries are
// written by the caller into the same document: a colour space with a tint
// transformation, say, whose function is an object the file holds, so that
// what the resources name is there to be read.
func readsResourceDocument(content []byte, resources func(*pdfgen.Builder) string, inForm bool) []byte {
	b := &pdfgen.Builder{}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	declared := fmt.Sprintf("<< /Font << /F1 %d 0 R >> %s >>", helv, resources(b))
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

// An image a filter encodes ends where that filter's data ends, whatever the
// encoded bytes hold. An encoding the reader cannot read to an end -- a byte
// outside its alphabet, a group it does not admit, a checksum that is not the
// checksum of the data -- is no encoding, and the page fails: the file says
// two things about where the image ends and the reader signs neither.
func TestReadsFilteredInlineImageEncodingIsRead(t *testing.T) {
	for _, c := range []struct {
		name, dict, samples string
		want                string
	}{
		{"hexadecimal digits and the end-of-data marker", "/F /AHx", "41414141>", "before\nafter"},
		{"a byte outside the hexadecimal alphabet", "/F /AHx", "41G1>", ""},
		{"an EI among hexadecimal digits", "/F /AHx", "41 EI \xff\xff\xff41>", ""},
		{"base-85 with a z between groups", "/F /A85", "z!!!!!~>", "before\nafter"},
		{"a z inside a base-85 group", "/F /A85", "!z!!!~>", ""},
		{"a final base-85 group of one character", "/F /A85", "!!!!!!~>", ""},
		{"a base-85 byte outside the alphabet", "/F /A85", "v!!!!~>", ""},
		{"a base-85 group past the largest word", "/F /A85", "uuuuu~>", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			content := shown("before", 700) + "BI /W 4 /H 4 /BPC 8 /CS /G " + c.dict + " ID " + c.samples + " EI\n" + shown("after", 680)
			data := readsContentPage([]byte(content))
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != c.want {
				t.Errorf("the record reads %s %q, want %q (problems %+v)", r.Pages[0].Status, got, c.want, r.Problems)
			}
			if c.want == "" && (len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed") {
				t.Errorf("problems %+v", r.Problems)
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
	hidden := " EI " + shown("HIDDEN", 650)
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
		{"two decode arrays that disagree", "/W 40 /H 8 /BPC 8 /CS /G /D [0 1] /Decode [1 0]", false},
		{"two depths written the same value two ways", "/W 40 /H 8 /BPC 8 /BitsPerComponent 8.0 /CS /G", false},
		{"the same value written the other way about", "/W 40 /H 8 /BitsPerComponent 8.0 /BPC 8 /CS /G", false},
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
	// Enough numbers for a chain of references longer than the reader
	// follows, and for the objects the tests here name.
	const numbers = 64
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
	return []byte(" EI " + shown("HIDDEN", 650))
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

// Every filter an inline image may declare says for itself where its data
// ends, and an image encoded by one ends there: the "EI" and the operators
// its encoded bytes carry are bytes of the image, and the page is what
// follows the encoding. Disabling any one of these framings fails its own
// case: nothing else establishes an image's end.
func TestReadsInlineImageFramedByEachFilter(t *testing.T) {
	hidden := readsHiddenEncoded()
	for _, c := range []struct {
		name, dict string
		samples    []byte
		carries    bool
	}{
		{"ASCIIHexDecode", "/W 8 /H 8 /BPC 8 /CS /G /F /AHx", hexStreamOf(hidden), false},
		{"ASCII85Decode", "/W 8 /H 8 /BPC 8 /CS /G /F /A85", readsASCII85Carrying(t, hidden), true},
		{"RunLengthDecode", "/W 8 /H 8 /BPC 8 /CS /G /F [/RL]", runLengthOf(hidden), true},
		{"FlateDecode", "/W 8 /H 8 /BPC 8 /CS /G /F /Fl", flateOf(hidden), false},
		{"FlateDecode, stored", "/W 40 /H 8 /BPC 8 /CS /G /F /Fl", readsStoredFlate(readsHiddenSamples()), true},
		{"LZWDecode", "/W 8 /H 8 /BPC 8 /CS /G /F /LZW /DP << /EarlyChange 0 >>", readsLZWCarrying(t, hidden), true},
		{"DCTDecode", "/W 8 /H 8 /BPC 8 /CS /G /F /DCT", readsJPEGCarrying(hidden), true},
		{"CCITTFaxDecode, Group 4", "/W 8 /H 1 /BPC 1 /CS /G /F /CCF /DP << /K -1 /Columns 8 /Rows 1 >>",
			readsBits("1" + strings.Repeat(readsEOL, 2)), false},
		{"CCITTFaxDecode, Group 3", "/W 8 /H 1 /BPC 1 /CS /G /F /CCF /DP << /K 0 /Columns 8 /Rows 1 >>",
			readsBits(readsEOL + "10011" + strings.Repeat(readsEOL, 6)), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.carries && !bytes.Contains(c.samples, []byte(" EI ")) {
				t.Fatalf("the encoded bytes of this case do not carry the sequence the image is meant to hide")
			}
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

// readsEOL is the end-of-line code of T.4: eleven zero bits and a one.
const readsEOL = "000000000001"

// readsBits is the bytes the bit string given makes, padded with zeros.
func readsBits(s string) []byte {
	out := make([]byte, (len(s)+7)/8)
	for i, c := range s {
		if c == '1' {
			out[i/8] |= 1 << uint(7-i%8)
		}
	}
	return out
}

// readsJPEGCarrying is a JPEG the standard library encodes, with a comment
// segment carrying the bytes given: a decoder reads it whole, and its
// entropy-coded data is followed by the end-of-image marker that ends it.
func readsJPEGCarrying(carried []byte) []byte {
	var raw bytes.Buffer
	jpeg.Encode(&raw, image.NewGray(image.Rect(0, 0, 8, 8)), nil)
	out := raw.Bytes()
	comment := append([]byte{0xFF, 0xFE, byte((len(carried) + 2) >> 8), byte(len(carried) + 2)}, carried...)
	// After the start-of-image marker, where a comment segment may stand.
	return append(append(append([]byte{}, out[:2]...), comment...), out[2:]...)
}

// readsASCII85Carrying is base-85 data whose own bytes carry the bytes given:
// every byte of them is one the encoding admits, and white space between
// groups is skipped, so they stand in the encoded data as they are.
func readsASCII85Carrying(t *testing.T, carried []byte) []byte {
	t.Helper()
	for _, c := range carried {
		if c > ' ' && (c < '!' || c > 'u' || c == 'z') {
			t.Fatalf("the byte %q is not one base-85 admits", c)
		}
	}
	for pad := 0; pad < 8; pad++ {
		body := append(bytes.Repeat([]byte("!"), pad), carried...)
		body = append(body, bytes.Repeat([]byte("!"), 16)...)
		group, value, ok := 0, uint64(0), true
		for _, c := range body {
			if c <= ' ' {
				continue
			}
			value = value*85 + uint64(c-'!')
			group++
			if group == 5 {
				ok = ok && value <= 0xFFFFFFFF
				group, value = 0, 0
			}
		}
		if ok && group != 1 {
			return append(append([]byte("<~"), body...), []byte("~>")...)
		}
	}
	t.Fatal("no base-85 padding made the groups readable")
	return nil
}

// readsBitWriter packs codes of a given width, most significant bit first.
type readsBitWriter struct {
	out  []byte
	acc  uint32
	bits int
}

func (w *readsBitWriter) put(code, width int) {
	w.acc = w.acc<<uint(width) | uint32(code)
	w.bits += width
	for w.bits >= 8 {
		w.out = append(w.out, byte(w.acc>>uint(w.bits-8)))
		w.bits -= 8
	}
}

func (w *readsBitWriter) done() []byte {
	if w.bits > 0 {
		w.out = append(w.out, byte(w.acc<<uint(8-w.bits)))
	}
	return w.out
}

// readsLZWCarrying is LZW data, written without the early code-length change,
// whose own bytes carry the bytes given: at the twelve-bit width two codes
// take three bytes exactly, so three bytes written as two codes stand in the
// encoded data as they are. The table is filled first, so that every code
// those bytes make is one the table holds.
func readsLZWCarrying(t *testing.T, carried []byte) []byte {
	t.Helper()
	payload := append([]byte{}, carried...)
	for len(payload)%3 != 0 {
		payload = append(payload, 'A')
	}
	// Codes more at the nine-bit width shift everything after them, which is
	// what decides whether the twelve-bit codes can begin on a byte boundary
	// at all: a twelve-bit code moves the boundary by four bits, so the
	// shift must leave the filler ending on one of the two offsets from
	// which a boundary is reachable.
	for shift := 0; shift < 8; shift++ {
		w := &readsBitWriter{}
		width, next, first := 9, 258, true
		put := func(code int) {
			w.put(code, width)
			if !first {
				next++
			}
			first = false
			if width < 12 && next >= 1<<uint(width) {
				width++
			}
		}
		// A clear code says only "begin the table again": it moves the
		// codes after it by nine bits and leaves the table where it was.
		for i := 0; i < shift; i++ {
			w.put(256, 9)
		}
		first = true
		// Literal codes until the table is full and the width is twelve, the
		// table growing as the reader grows it: the first code adds nothing.
		for next < 4096 {
			put(next % 256)
		}
		// Twelve-bit codes until the next one begins on a byte boundary,
		// where three bytes are two codes and the bytes stand as they are.
		if w.bits == 4 {
			w.put(65, 12)
		}
		if w.bits != 0 {
			continue
		}
		control := false
		for i := 0; i < len(payload); i += 3 {
			a := int(payload[i])<<4 | int(payload[i+1])>>4
			b := int(payload[i+1]&15)<<8 | int(payload[i+2])
			if a == 256 || a == 257 || b == 256 || b == 257 {
				control = true
				break
			}
			w.put(a, 12)
			w.put(b, 12)
		}
		if control {
			continue
		}
		w.put(257, 12)
		if out := w.done(); bytes.Contains(out, []byte(" EI ")) {
			return out
		}
	}
	t.Fatal("no shift put the sequence in the encoded bytes")
	return nil
}

// The filters this reader frames are the seven the specification's
// inline-image abbreviation list holds (Table 93). JBIG2Decode and JPXDecode
// are not in that list and this reader frames neither: an image declaring one
// as its first filter fails its page, since where its data ends is not
// something this reader establishes, and the text after such an image is not
// read as the page's.
func TestReadsInlineImageFiltersTheSpecificationDoesNotAbbreviate(t *testing.T) {
	for _, filter := range []string{"JBIG2Decode", "JPXDecode"} {
		t.Run(filter, func(t *testing.T) {
			encoded := readsJBIG2(readsHiddenEncoded())
			if filter == "JPXDecode" {
				encoded = readsJPX(readsHiddenEncoded())
			}
			content := shown("before", 700) +
				"BI /W 8 /H 8 /BPC 1 /CS /G /F /" + filter + " ID " + string(encoded) + " EI\n" +
				shown("after", 680)
			data := readsContentPage([]byte(content))
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if _, err := budgeted(1<<20, 1<<20).filterFraming(Name(filter), nil, encoded); !errors.Is(err, errFilterNotFramed) {
				t.Errorf("framing %s ended with %v; this reader frames neither encoding, whatever the bytes hold", filter, err)
			}
			if r.Pages[0].Status != PageFailed || r.Pages[0].Text != "" {
				t.Errorf("the record reads %s %q; the page's own text after such an image is not read either",
					r.Pages[0].Status, r.Pages[0].Text)
			}
			if len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" {
				t.Errorf("problems %+v", r.Problems)
			}
		})
	}
}

// Two declarations of one key are the same declaration when they say the same
// thing, however deep what they say goes: the reader compares them to the
// bottom, and only a genuine disagreement fails the page.
func TestReadsIdenticalDeeplyNestedParametersAgree(t *testing.T) {
	parms := "<< /Unused " + strings.Repeat("[", 9) + "0" + strings.Repeat("]", 9) + " >>"
	data := readsInlineImagePage("/W 1 /H 1 /BPC 8 /CS /G /F /AHx /DP "+parms+" /DecodeParms "+parms, []byte("41>"), shown("REAL", 700))
	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if got := r.Pages[0].Text; got != "REAL" {
		t.Errorf("the record reads %s %q; the two declarations are one value (problems %+v)", r.Pages[0].Status, got, r.Problems)
	}
}

// readsRawTrailer writes a document as readsRawFile does, with the extra
// members given added to the cross-reference stream's dictionary, which is
// the trailer of a file whose cross-reference is a stream.
func readsRawTrailer(objects []readsObject, broken int, inStream map[int][2]int, trailer string) []byte {
	data := readsRawFile(objects, broken, inStream)
	return bytes.Replace(data, []byte("/Root 1 0 R"), []byte("/Root 1 0 R "+trailer), 1)
}

// The standard security handler's revision 2, written from the algorithms of
// 7.6.3 so that a test can hold two encryption dictionaries deriving two
// different keys: the owner password decides /O, /O and the file identifier
// decide the key, and the key decides /U.
var readsPasswordPad = []byte{
	0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
	0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
}

const readsFileID = "\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00"

// readsRC4Key is the /O string, the file key and the /U string of a revision-2
// encryption dictionary whose owner password is the one given and whose user
// password is empty.
func readsRC4Key(owner string, permissions int32) (o, key, u []byte) {
	padded := func(p string) []byte { return append([]byte(p), readsPasswordPad...)[:32] }
	sum := md5.Sum(padded(owner))
	c, _ := rc4.NewCipher(sum[:5])
	o = make([]byte, 32)
	c.XORKeyStream(o, padded(""))
	h := md5.New()
	h.Write(padded(""))
	h.Write(o)
	h.Write([]byte{byte(permissions), byte(permissions >> 8), byte(permissions >> 16), byte(permissions >> 24)})
	h.Write([]byte(readsFileID))
	key = h.Sum(nil)[:5]
	c, _ = rc4.NewCipher(key)
	u = make([]byte, 32)
	c.XORKeyStream(u, readsPasswordPad)
	return o, key, u
}

// readsRC4Encrypt is data encrypted for the object numbered, as the standard
// handler encrypts a stream under a revision-2 key.
func readsRC4Encrypt(key []byte, num int, data []byte) []byte {
	m := md5.New()
	m.Write(key)
	m.Write([]byte{byte(num), byte(num >> 8), byte(num >> 16), 0, 0})
	c, _ := rc4.NewCipher(m.Sum(nil)[:10])
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out
}

// An encryption dictionary belongs to the cross-reference that names it. A
// rebuilt one may name another, deriving another key, and the pages are
// encrypted under the key the document names now: nothing of them is read
// through the handler the replaced cross-reference gave.
func TestReadsEncryptionIsEstablishedUnderTheCrossReferenceInForce(t *testing.T) {
	const permissions = -1
	oldO, _, oldU := readsRC4Key("one", permissions)
	newO, newKey, newU := readsRC4Key("two", permissions)
	dictionary := func(o, u []byte, extra string) string {
		return fmt.Sprintf("<< /Filter /Standard /V 1 /R 2 /P %d /O <%x> /U <%x> %s >>", permissions, o, u, extra)
	}
	content := []byte(shown("NEW", 700))
	for _, c := range []struct {
		name    string
		objects []readsObject
		broken  int
	}{
		{"the page's content is what rebuilds", []readsObject{
			{1, "<< /Type /Catalog /Pages 2 0 R >>"},
			{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
			{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
			{6, readsStreamObject("", string(readsRC4Encrypt(newKey, 6, content)))},
			{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"},
			{9, dictionary(oldO, oldU, "")},
			{9, dictionary(newO, newU, "")},
		}, 6},
		{"a member of the encryption dictionary is", []readsObject{
			{1, "<< /Type /Catalog /Pages 2 0 R >>"},
			{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
			{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
			{6, readsStreamObject("", string(readsRC4Encrypt(newKey, 6, content)))},
			{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"},
			// The owner string of the first dictionary is an object the
			// cross-reference damages: reading it is what rebuilds.
			{9, fmt.Sprintf("<< /Filter /Standard /V 1 /R 2 /P %d /O 10 0 R /U <%x> >>", permissions, oldU)},
			{10, fmt.Sprintf("<%x>", oldO)},
			{9, dictionary(newO, newU, "")},
		}, 10},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsRawTrailer(c.objects, c.broken, nil, fmt.Sprintf("/Encrypt 9 0 R /ID [<%x> <%x>]", readsFileID, readsFileID))
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != "NEW" {
				t.Errorf("the record reads %s %q; the rebuilt document names the key its pages are encrypted under", r.Pages[0].Status, got)
			}
			if r.Encryption == nil || !r.Encryption.Opened {
				t.Errorf("encryption %+v", r.Encryption)
			}
		})
	}
}

// A bound met scanning the file is the file's, not one cross-reference's:
// installing the security handler drops what was read under the same
// cross-reference, and a bound the scan met stands.
func TestReadsAFileBoundSurvivesTheEncryptionHandler(t *testing.T) {
	const permissions = -1
	o, _, u := readsRC4Key("one", permissions)
	headers := strings.Repeat("1 0 obj\n", maxScanObjects+1)
	data := readsRawTrailer([]readsObject{
		{1, "<< /Type /Catalog /Pages 2 0 R >>"},
		{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
		{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
		{6, readsStreamObject("", shown("A", 700))},
		{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"},
		// The handler's /Length is a reference the cross-reference damages:
		// reading it sends the reader scanning, which meets the bound.
		{9, fmt.Sprintf("<< /Filter /Standard /V 1 /R 2 /P %d /O <%x> /U <%x> /Length 11 0 R >>", permissions, o, u)},
		{11, "40"},
		{12, readsStreamObject("", headers)},
	}, 11, nil, fmt.Sprintf("/Encrypt 9 0 R /ID [<%x> <%x>]", readsFileID, readsFileID))
	r := extract(t, data)
	if r.Fatal == nil || r.Fatal.Code != "pdf-malformed" || r.Fatal.Message != boundMessage {
		t.Errorf("fatal %+v pages %+v; the file holds more objects than a rebuild may find", r.Fatal, r.Pages)
	}
}

// An object stream resolved by a read that straddles a rebuild belongs to the
// cross-reference the read began under: neither its header nor the font built
// from it is held, and neither its bound nor its failure is the rebuilt
// document's.
func TestReadsAnObjectStreamAcrossARebuildIsNotPublished(t *testing.T) {
	font := func(glyph string) string {
		return "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding << /Differences [65 /" + glyph + "] >> >>"
	}
	old := "7 0 " + font("B")
	for _, c := range []struct{ name, dict string }{
		{"a length the cross-reference damages", "/Type /ObjStm /N 1 /First 4 /Length 8 0 R"},
		{"a count the cross-reference damages", "/Type /ObjStm /N 8 0 R /First 4"},
		{"a first offset the cross-reference damages", "/Type /ObjStm /N 1 /First 8 0 R"},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsRawFile([]readsObject{
				{1, "<< /Type /Catalog /Pages 2 0 R >>"},
				{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
				{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
				{5, "<< " + c.dict + " >>\nstream\n" + old + "\nendstream"},
				{6, readsStreamObject("", shown("A", 700))},
				// The damaged reference: the value the old stream needs, and
				// one the rebuilt stream does not.
				{8, fmt.Sprint(maxObjStmObjects + 1)},
				{5, readsStreamObject("/Type /ObjStm /N 1 /First 4", "7 0 "+font("Z"))},
			}, 8, map[int][2]int{7: {5, 0}})
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v; the rebuilt stream holds a font within every bound", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != "Z" {
				t.Errorf("the record reads %q, want %q: the stream the rebuilt cross-reference names", got, "Z")
			}
		})
	}
}

// A CMap read from a stream a replaced cross-reference named is not held
// either: what the document holds of its fonts was read under the
// cross-reference it has.
func TestReadsACMapAcrossARebuildIsNotHeld(t *testing.T) {
	data := readsRawFile([]readsObject{
		{1, "<< /Type /Catalog /Pages 2 0 R >>"},
		{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
		{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
		{6, readsStreamObject("", shown("A", 700))},
		{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /ToUnicode 9 0 R >>"},
		{9, "<< /Length 8 0 R >>\nstream\nbegincmap endcmap\nendstream"},
		{8, "18"},
	}, 8, nil)
	d := openGenerated(t, data)
	before := d.generation
	loadFontNumbered(d, 7)
	if d.generation == before {
		t.Fatal("reading the font did not rebuild the cross-reference")
	}
	if len(d.cmaps) != 0 {
		t.Errorf("the reader holds %d CMaps read under the cross-reference the rebuild replaced", len(d.cmaps))
	}
}

// A page whose reading straddles a rebuilt cross-reference ends where it
// stands: what was read before the rebuild and what would be read after it
// are two documents' pages.
func TestReadsAPageStraddlingARebuildEndsThere(t *testing.T) {
	data := readsRawFile([]readsObject{
		{1, "<< /Type /Catalog /Pages 2 0 R >>"},
		{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
		{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> /XObject << /X 8 0 R >> >> /Contents 6 0 R >>"},
		{6, readsStreamObject("", shown("A", 700)+"/X Do\n")},
		{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"},
		{8, readsStreamObject("/Type /XObject /Subtype /Form /BBox [0 0 10 10]", " ")},
	}, 8, nil)
	d := openGenerated(t, data)
	root, _ := d.pagesRoot()
	page := d.dictOf(d.arrayOf(root["Kids"])[0])
	content, err := pageContent(d, page)
	if err != nil {
		t.Fatalf("content: %v", err)
	}
	pr := d.interpretPage(context.Background(), content, d.dictOf(page["Resources"]), 1<<20)
	if !errors.Is(pr.err, errCrossReferenceRebuilt) {
		t.Errorf("the page ended with %v; drawing the form rebuilt the cross-reference under it", pr.err)
	}
}

// An object stream's offsets are from the first object's, and lie within what
// the stream holds after it: an offset before it names the header, where the
// numbers and offsets are, and no object of the stream lies there.
func TestReadsObjectStreamOffsetBeforeTheFirstObject(t *testing.T) {
	font := "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding << /Differences [65 /B] >> >>"
	header := fmt.Sprintf("7 -%d 9 0 ", len(font)+1)
	body := "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
	payload := header + font + " " + body
	data := readsRawFile([]readsObject{
		{1, "<< /Type /Catalog /Pages 2 0 R >>"},
		{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
		{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
		{5, readsStreamObject(fmt.Sprintf("/Type /ObjStm /N 2 /First %d", len(header)+len(font)+1), payload)},
		{6, readsStreamObject("", shown("A", 700))},
	}, 0, map[int][2]int{7: {5, 0}})
	d := openGenerated(t, data)
	if v, read := d.resolveRead(ref{7, 0}); read {
		t.Errorf("object 7 reads %v; its offset names the header and not an object of the stream", v)
	}
	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if got := r.Pages[0].Text; got == "B" {
		t.Errorf("the record reads %q, which the page does not show", got)
	}
}

// Every place an object stream's header gives is kept, whether or not the
// reader can use it: a place the cross-reference names decides which body an
// object declared twice has, and a place the reader cannot use holds no
// object at all. A pair whose two tokens can be read is one place; where the
// header ends or cannot be read, the places after it hold nothing.
func TestReadsObjectStreamHeaderSlotsAreExact(t *testing.T) {
	page := func(contents int) string {
		return fmt.Sprintf("<< /Type /Page /Parent 2 0 R /Contents %d 0 R /Resources << /Font << /F1 7 0 R >> >> >>", contents)
	}
	first, second := page(6), page(8)
	for _, c := range []struct {
		name, header string
		places       int
		index        int
		want         string
	}{
		{"a number declared twice, once at a place with no offset", "3 999999 3 0 ", 2, 0, ""},
		{"and at the place that has one", "3 999999 3 0 ", 2, 1, "FIRST"},
		{"a place declaring another number", fmt.Sprintf("3 0 4 %d 3 %d ", len(first), len(first)), 3, 1, ""},
		{"a pair the reader cannot read, and the places after it", fmt.Sprintf("99 /Bad 3 %d 3 0 ", len(first)), 3, 1, "SECOND"},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsRawFile([]readsObject{
				{1, "<< /Type /Catalog /Pages 2 0 R >>"},
				{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
				{5, readsStreamObject(fmt.Sprintf("/Type /ObjStm /N %d /First %d", c.places, len(c.header)), c.header+first+second)},
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
				t.Errorf("the record reads %q, want %q (fatal %+v)", got, c.want, r.Fatal)
			}
			if c.want == "" && (r.Fatal == nil || r.Fatal.Code != "pdf-malformed") {
				t.Errorf("fatal %+v; the place the cross-reference names holds no object", r.Fatal)
			}
		})
	}
}

// A code is its bytes, and how many of them it has: 9.7.6.2 gives a mapping
// for codes of one length, so <41> and <0041> are two codes and the mapping
// of one says nothing about the other.
func TestReadsACodeIsLookedUpAmongCodesOfItsOwnLength(t *testing.T) {
	spaces := "begincmap\n2 begincodespacerange\n<01> <7F>\n<0000> <00FF>\nendcodespacerange\n"
	b := &pdfgen.Builder{}
	enc := b.Add(pdfgen.Object{Body: "<< /Type /CMap /CMapName /Test-H /CIDSystemInfo << /Registry (Adobe) /Ordering (Japan1) /Supplement 2 >> >>",
		Stream: []byte(spaces + "endcmap\n")})
	tu := b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(spaces +
		"2 beginbfchar\n<41> <0041>\n<0041> <0042>\nendbfchar\nendcmap\n")})
	cid := b.Add(pdfgen.Object{Body: "<< /Type /Font /Subtype /CIDFontType0 /BaseFont /Test /CIDSystemInfo << /Registry (Adobe) /Ordering (Japan1) /Supplement 2 >> /DW 1000 >>"})
	f := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Font /Subtype /Type0 /BaseFont /Test /Encoding %d 0 R /DescendantFonts [%d 0 R] /ToUnicode %d 0 R >>", enc, cid, tu)})
	b.Catalog(b.Pages([]pdfgen.Page{{Content: "BT /F1 12 Tf 1 0 0 1 72 700 Tm <410041> Tj ET\n", Fonts: map[string]int{"F1": f}}}))
	data := b.Bytes()
	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if got := r.Pages[0].Text; got != "AB" {
		t.Errorf("the page shows the one-byte code <41> and the two-byte code <0041>, and the record reads %q, want %q", got, "AB")
	}
}

// Codespace ranges of two lengths that hold the same leading bytes say two
// things about how long a code is. The CMap is not used at all -- its glyphs
// are unmapped and counted, as they are for any CMap the reader cannot use --
// and which of the two ranges the file declared first makes no difference.
func TestReadsAmbiguousCodespacesAreNotUsed(t *testing.T) {
	for _, c := range []struct{ name, ranges string }{
		{"the longer range first", "<8140> <81FC> <81> <81> <20> <7E>"},
		{"the shorter range first", "<81> <81> <8140> <81FC> <20> <7E>"},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsMixedWidthFont("begincmap 3 begincodespacerange "+c.ranges+" endcodespacerange\n", "8141")
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if r.Pages[0].Text != "�" || r.Pages[0].Unmapped != 1 {
				t.Errorf("the record reads %q with %d glyphs unmapped; the CMap says a code beginning 81 is one byte and says it is two",
					r.Pages[0].Text, r.Pages[0].Unmapped)
			}
		})
	}
}

// A document is rebuilt once however its opening goes: a rebuild that ran
// while the file's own cross-reference was being read is the document's
// cross-reference, and scanning the same bytes again would charge the file
// for them twice.
func TestReadsAnOpeningRebuildsAtMostOnce(t *testing.T) {
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
	// The /W of the second section, which is no array: reading it is what
	// sends the reader scanning.
	add(10, "<< >>")
	section := out.Len()
	fmt.Fprintf(&out, "44 0 obj<< /Type /XRef /W 10 0 R /Size 50 /Length 5 >>stream\nAAAAA\nendstream endobj\n")
	at := out.Len()
	out.WriteString("xref\n1 5\n")
	for num := 1; num <= 5; num++ {
		fmt.Fprintf(&out, "%010d %05d n \n", offsets[num], 0)
	}
	// Object 10 at an offset that holds no object: reading it rebuilds.
	fmt.Fprintf(&out, "10 1\n%010d %05d n \n", 3, 0)
	fmt.Fprintf(&out, "trailer<< /Size 50 /Root 1 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n", section, at)
	data := out.Bytes()

	d, err := open(context.Background(), data, &inflateBudget{total: 64 << 20, one: 16 << 20})
	if d == nil {
		t.Fatalf("not opened: %v", err)
	}
	if d.generation > 1 {
		t.Errorf("opening the document moved the generation to %d; a document is rebuilt once", d.generation)
	}
	r := extract(t, data)
	if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Text != "Hello" {
		t.Errorf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
}

// What reading the file has cost is not given back when a rebuild makes the
// reader read it again: the inflate budget is what the document has spent,
// and a file whose pages are read twice has spent it twice.
func TestReadsTheInflateBudgetIsNotGivenBackByARestart(t *testing.T) {
	font := func(glyph string) string {
		return "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding << /Differences [65 /" + glyph + "] >> >>"
	}
	content := shown("A", 700)
	compressed := flateOf([]byte(content))
	objects := []readsObject{
		{1, "<< /Type /Catalog /Pages 2 0 R >>"},
		{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
		{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
		{6, fmt.Sprintf("<< /Filter /FlateDecode /Length %d >>\nstream\n%s\nendstream", len(compressed), compressed)},
		{7, font("B")},
		{7, font("Z")},
	}
	data := readsRawFile(objects, 7, nil)
	for _, c := range []struct {
		name  string
		total int64
		want  string
	}{
		{"room for both readings", int64(2 * len(content)), "Z"},
		{"room for one", int64(len(content)), ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			opt := testOptions()
			opt.MaxInflateTotal, opt.MaxInflateOne = c.total, c.total
			r := Extract(context.Background(), data, opt)
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != c.want {
				t.Errorf("with %d bytes of inflate budget the record reads %q, want %q (problems %+v)", c.total, got, c.want, r.Problems)
			}
			if c.want == "" && (len(r.Problems) != 1 || r.Problems[0].Code != "stream-over-bound") {
				t.Errorf("problems %+v, want the budget the second reading found spent", r.Problems)
			}
		})
	}
}

// Group 3 fax data may mix one- and two-dimensional rows, and then a tag bit
// follows each end-of-line and belongs to it. The end-of-block is six
// end-of-lines whatever those tag bits say.
func TestReadsGroup3FaxWithTaggedEndOfLines(t *testing.T) {
	for _, k := range []int{1, 4} {
		for _, tag := range []string{"0", "1"} {
			t.Run(fmt.Sprintf("K %d, tag %s", k, tag), func(t *testing.T) {
				bits := readsEOL + tag + "10011" + strings.Repeat(readsEOL+tag, 6)
				dict := fmt.Sprintf("/W 8 /H 1 /BPC 1 /CS /G /F /CCF /DP << /K %d /Columns 8 /Rows 1 >>", k)
				data := readsInlineImagePage(dict, readsBits(bits), shown("REAL", 700))
				r := extract(t, data)
				if out, ok := readsPoppler(t, data); ok {
					t.Logf("pdftotext reads %q", out)
				}
				if r.Fatal != nil || len(r.Pages) != 1 {
					t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
				}
				if got := r.Pages[0].Text; got != "REAL" {
					t.Errorf("the record reads %q; the block ends at its six end-of-lines (problems %+v)", got, r.Problems)
				}
			})
		}
	}
}

// Fax data written with /EncodedByteAlign begins each row on a byte boundary,
// and the fill bits before a row make the eleven zeros of an end-of-line
// where no end-of-line stands. The reader does not frame it: telling a row
// boundary from an end-of-line means decoding the rows, and a page whose
// image ends where the reader cannot say fails rather than guessing.
func TestReadsByteAlignedFaxIsNotFramed(t *testing.T) {
	for _, c := range []struct{ name, parms, bits string }{
		{"a Group 3 image whose rows are aligned", "/K 0 /Columns 29 /Rows 2 /EndOfLine false /EncodedByteAlign true",
			"0001000" + "000100" + "000" + "00000010" + strings.Repeat("0000"+readsEOL, 6)},
		{"a Group 4 image whose rows are aligned", "/K -1 /Columns 19 /Rows 2 /EncodedByteAlign true",
			"001" + "000111" + "0000001000" + "00000" + "0001" + "0000" + readsEOL + readsEOL},
		{"five end-of-lines, text, and the sixth", "/K 0 /Columns 29 /Rows 2 /EndOfLine false /EncodedByteAlign true",
			"0001000" + "000100" + "000" + "00000010" + strings.Repeat("0000"+readsEOL, 5)},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsInlineImagePage("/W 29 /H 2 /BPC 1 /CS /G /F /CCF /DP << "+c.parms+" >>", readsBits(c.bits), shown("REAL", 700))
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if r.Pages[0].Status != PageFailed || r.Pages[0].Text != "" {
				t.Errorf("the record reads %s %q; where such an image ends is not something the reader can say",
					r.Pages[0].Status, r.Pages[0].Text)
			}
		})
	}
}

// LZW data ends at its end-of-data code and nowhere else: data that runs out
// before it is data whose end the reader has not seen, and the bytes the
// reader may read of one image are not its end either.
func TestReadsLZWEndsAtItsEndOfDataCode(t *testing.T) {
	encoded := lzwOf([]byte(shown("HIDDEN", 650)))
	// The framing itself: data the codes do not end is data whose end the
	// reader has not seen, wherever the bytes it was given happen to stop.
	d := budgeted(1<<20, 1<<20)
	if _, err := d.lzwFraming(encoded[:len(encoded)-1], false); !errors.Is(err, errFilterUnended) {
		t.Errorf("framing data with no end-of-data code ended with %v", err)
	}
	if n, err := d.lzwFraming(encoded, false); err != nil || n != len(encoded) {
		t.Errorf("framing whole data gave %d, %v", n, err)
	}
	for _, c := range []struct {
		name    string
		samples []byte
		want    string
	}{
		{"ending at its end-of-data code", encoded, "before\nafter"},
		{"running out before it", encoded[:len(encoded)-1], ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			content := shown("before", 700) + "BI /W 4 /H 4 /BPC 8 /CS /G /F /LZW /DP << /EarlyChange 0 >> ID " +
				string(c.samples) + " EI\n" + shown("after", 680)
			data := readsContentPage([]byte(content))
			r := extract(t, data)
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != c.want {
				t.Errorf("the record reads %s %q, want %q (problems %+v)", r.Pages[0].Status, got, c.want, r.Problems)
			}
		})
	}
}

// A zlib stream is its header, its deflate data and the checksum of what that
// decodes to: data with no header, or whose checksum is not the checksum of
// the data, is no FlateDecode stream, and where such an image ends is not
// something the file establishes.
func TestReadsFlateFramingIsTheWholeWrapper(t *testing.T) {
	whole := readsStoredFlate([]byte("SAMPLES"))
	for _, c := range []struct {
		name    string
		samples []byte
		want    string
	}{
		{"the whole wrapper", whole, "before\nafter"},
		{"a checksum that is not the data's", append(append([]byte{}, whole[:len(whole)-4]...), 'J', 'U', 'N', 'K'), ""},
		{"no checksum at all", whole[:len(whole)-4], ""},
		{"deflate data with no zlib header", whole[2:], ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			content := shown("before", 700) + "BI /W 7 /H 1 /BPC 8 /CS /G /F /Fl ID " +
				string(c.samples) + " EI\n" + shown("after", 680)
			data := readsContentPage([]byte(content))
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != c.want {
				t.Errorf("the record reads %s %q, want %q (problems %+v)", r.Pages[0].Status, got, c.want, r.Problems)
			}
		})
	}
}

// An encoding whose end lies past the bytes the reader may read of one image
// has met that bound, and the record says which bound the page met.
func TestReadsFramingPastTheInputBoundIsThatBound(t *testing.T) {
	if testing.Short() {
		t.Skip("writes inline images of sixteen megabytes")
	}
	const window = maxInlineImageBytes
	// Encodings that hold no end within the bytes the reader may read of one
	// image: hexadecimal digits with no end-of-data marker; base-85 whose
	// tilde stands at the last byte of the window, so that the byte which
	// would end it lies past it; runs whose lengths walk past it; deflate
	// blocks that never end; LZW codes that never end; a JPEG of segments
	// that never reach an end-of-image; and fax data with no
	// end-of-facsimile-block.
	stored := []byte{0x78, 0x01}
	for len(stored) < window+8 {
		stored = append(stored, 0x00, 0x00, 0x00, 0xFF, 0xFF)
	}
	codes := &readsBitWriter{}
	for len(codes.out) < window+8 {
		codes.put(256, 9)
	}
	jpegs := []byte{0xFF, 0xD8}
	for len(jpegs) < window+8 {
		jpegs = append(jpegs, 0xFF, 0xFE, 0x00, 0x02)
	}
	for _, c := range []struct {
		name, dict string
		samples    []byte
	}{
		{"ASCIIHexDecode", "/F /AHx", bytes.Repeat([]byte{'4'}, window+8)},
		{"ASCII85Decode with its terminator split at the window", "/F /A85", append(bytes.Repeat([]byte{'!'}, window-1), '~', '>')},
		{"RunLengthDecode", "/F /RL", bytes.Repeat([]byte{127}, window+8)},
		{"FlateDecode", "/F /Fl", stored},
		{"LZWDecode", "/F /LZW", codes.done()},
		{"DCTDecode", "/F /DCT", jpegs},
		{"CCITTFaxDecode", "/F /CCF /DP << /K -1 /Columns 8 /Rows 1 >>", bytes.Repeat([]byte{0xFF}, window+8)},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsInlineImagePage("/W 1 /H 1 /BPC 8 /CS /G "+c.dict, c.samples, shown("REAL", 700))
			opt := testOptions()
			opt.MaxInflateOne, opt.MaxInflateTotal = 64<<20, 64<<20
			r := Extract(context.Background(), data, opt)
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			want := "the content of page 1 is past a structure bound the reader holds"
			if r.Pages[0].Status != PageFailed || len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" || r.Problems[0].Message != want {
				t.Errorf("pages %+v problems %+v; the encoding held no end within the bytes the reader may read of one image", r.Pages, r.Problems)
			}
		})
	}
}

// Data that is not deflate data is the encoding's own defect, and not the
// bound on what the reader may read of one image: the two are told apart
// whether the corruption lies below that bound or past it.
func TestReadsCorruptDeflateIsNotTheInputBound(t *testing.T) {
	if testing.Short() {
		t.Skip("writes an inline image of sixteen megabytes")
	}
	// A zlib header, a block of the type deflate reserves, and padding.
	corrupt := func(n int) []byte {
		return append([]byte{0x78, 0x01, 0x07}, bytes.Repeat([]byte{0x00}, n)...)
	}
	for _, c := range []struct {
		name    string
		samples []byte
	}{
		{"corrupt below the bound", corrupt(64)},
		{"corrupt past the bound", corrupt(maxInlineImageBytes + 8)},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsInlineImagePage("/W 1 /H 1 /BPC 8 /CS /G /F /Fl", c.samples, shown("REAL", 700))
			opt := testOptions()
			opt.MaxInflateOne, opt.MaxInflateTotal = 64<<20, 64<<20
			r := Extract(context.Background(), data, opt)
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			want := "the content of page 1 could not be interpreted"
			if r.Pages[0].Status != PageFailed || len(r.Problems) != 1 || r.Problems[0].Message != want {
				t.Errorf("pages %+v problems %+v, want %q; what the reader was given is not deflate data at all", r.Pages, r.Problems, want)
			}
		})
	}
}

// The deadline is read while an image is framed, not only before it: an
// encoding that decodes to nothing charges nothing, and would otherwise be
// walked to its end whatever the clock says. The decoders are asked directly,
// since an image large enough to outlast a deadline of its own would be a
// slow test of a fast check; the reader's own cadence is set up so that the
// first reading of the clock falls where the framing begins.
func TestReadsFramingReadsTheDeadline(t *testing.T) {
	clears := &readsBitWriter{}
	for i := 0; i < 1<<16; i++ {
		clears.put(256, 9)
	}
	empty := &bytes.Buffer{}
	w, _ := flate.NewWriter(empty, flate.NoCompression)
	w.Write(nil)
	w.Flush()
	w.Close()
	longFill := readsRestartJPEG(t, []byte(" EI "), entriesPerCheck+64)
	// A zlib stream of whole stored blocks: a decoder is handed each block in
	// one read, so the whole stream is read in a few calls.
	var stored bytes.Buffer
	zw, err := zlib.NewWriterLevel(&stored, zlib.NoCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(bytes.Repeat([]byte{'A'}, 256<<10)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		// checks is what the cadence stands at when the framing begins: the
		// rows that read the clock at their first step set it so, and the
		// two rows below them, of work the cadence does not count step by
		// step, begin a whole cadence away from a reading.
		checks int
		read   func(*Document) error
	}{
		{"LZW codes that decode to nothing", entriesPerCheck - 1, func(d *Document) error {
			_, err := d.lzwFraming(clears.done(), false)
			return err
		}},
		{"deflate blocks that decode to nothing", entriesPerCheck - 1, func(d *Document) error {
			_, _, err := d.deflateConsumed(bytes.Repeat(empty.Bytes(), 64))
			return err
		}},
		// The five framings that decode nothing walk their input, which the
		// caller bounds but the clock does not: each reads the deadline as
		// it goes, so that data it would otherwise frame whole is left where
		// the deadline was found.
		{"hexadecimal digits", entriesPerCheck - 1, func(d *Document) error {
			_, err := d.asciiHexFraming([]byte("41>"))
			return err
		}},
		{"base-85 groups", entriesPerCheck - 1, func(d *Document) error {
			_, err := d.ascii85Framing([]byte("!!!!!~>"))
			return err
		}},
		{"run lengths", entriesPerCheck - 1, func(d *Document) error {
			_, err := d.runLengthFraming([]byte{128})
			return err
		}},
		{"the markers of a JPEG", entriesPerCheck - 1, func(d *Document) error {
			_, err := d.jpegFraming(readsJPEG())
			return err
		}},
		{"the bits of fax data", entriesPerCheck - 1, func(d *Document) error {
			_, err := d.ccittFraming(Dict{"K": int64(-1)}, []byte{0x80, 0x08, 0, 0x80})
			return err
		}},
		// A run of fill bytes before a restart marker, and a block of deflate
		// data handed over whole, are each the work of many bytes done in one
		// step of the loop that counts steps: they read the clock as the
		// bytes they hold would have read it, not as the steps do.
		{"a JPEG's fill bytes", 0, func(d *Document) error {
			_, err := d.jpegFraming(longFill)
			return err
		}},
		{"deflate blocks handed over whole", 0, func(d *Document) error {
			_, _, err := d.deflateConsumed(stored.Bytes()[2:])
			return err
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := budgeted(1<<20, 1<<20)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			d.ctx = ctx
			d.checks = c.checks
			if err := c.read(d); !isDeadline(err) {
				t.Errorf("framing ended with %v; the deadline had passed before it began", err)
			}
		})
	}
}

// A colour space an inline image names on its own is a device space or the
// name of one of the resources in force; the families are written as arrays.
// A resource named after a family is that resource, and how many components
// its samples have is what the resource says.
func TestReadsInlineImageColourSpaceNames(t *testing.T) {
	// Every family name, declared as a resource of three components, under an
	// image whose samples are 320 bytes only if the reader measures three.
	for _, family := range []string{"CalGray", "CalRGB", "Lab", "Indexed", "I", "Separation", "DeviceN", "ICCBased", "Pattern"} {
		t.Run(family, func(t *testing.T) {
			resources := fmt.Sprintf("/ColorSpace << /%s [/CalRGB << /WhitePoint [1 1 1] >>] >>", family)
			var content bytes.Buffer
			// 320 bytes of samples: 106 by 1 of three components, one byte each,
			// is 318, and the two after it are the image's too.
			content.WriteString(fmt.Sprintf("BI /W 106 /H 1 /BPC 8 /CS /%s ID ", family))
			content.Write(readsHiddenSamples()[:318])
			content.WriteString(" EI\n")
			content.WriteString(shown("REAL", 700))
			data := readsResourcePage(content.Bytes(), resources, false)
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != "REAL" {
				t.Errorf("the record reads %q; the resource named %s has three components (problems %+v)", got, family, r.Problems)
			}
		})
	}
}

// The depth of a sample is one the specification gives, as an integer: an
// image that says anything else says nothing the reader can measure by, and
// a mask's samples are one bit whatever else it says.
func TestReadsInlineImageBitsPerComponent(t *testing.T) {
	for _, c := range []struct{ name, dict, want string }{
		{"a depth of eight", "/W 40 /H 8 /BPC 8 /CS /G", "REAL"},
		{"no depth at all", "/W 40 /H 8 /CS /G", ""},
		{"a depth of nothing", "/W 40 /H 8 /BPC 0 /CS /G", ""},
		{"a depth written as a real", "/W 40 /H 8 /BPC 8.0 /CS /G", ""},
		{"a depth written as a string", "/W 40 /H 8 /BPC (8) /CS /G", ""},
		{"a depth of three", "/W 40 /H 8 /BPC 3 /CS /G", ""},
		{"a mask, which says nothing", "/IM true /W 320 /H 8", "REAL"},
		{"a mask that says one bit", "/IM true /BPC 1 /W 320 /H 8", "REAL"},
		{"a mask that says eight", "/IM true /BPC 8 /W 320 /H 8", ""},
		{"a mask that says a depth of nothing", "/IM true /BPC 0 /W 320 /H 8", ""},
		{"a mask whose depth is written null", "/IM true /BPC null /W 320 /H 8", "REAL"},
		{"a depth written null", "/W 40 /H 8 /BPC null /CS /G", ""},
		{"a depth written null and then given", "/W 40 /H 8 /BPC null /BitsPerComponent 8 /CS /G", "REAL"},
		{"a depth given and then written null", "/W 40 /H 8 /BitsPerComponent 8 /BPC null /CS /G", "REAL"},
		{"a width written null and then given", "/W null /Width 40 /H 8 /BPC 8 /CS /G", "REAL"},
		{"a width given and then written null", "/Width 40 /W null /H 8 /BPC 8 /CS /G", "REAL"},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsInlineImagePage(c.dict, readsHiddenSamples(), shown("REAL", 700))
			r := extract(t, data)
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != c.want {
				t.Errorf("the record reads %s %q, want %q (problems %+v)", r.Pages[0].Status, got, c.want, r.Problems)
			}
		})
	}
}

// Samples are measured by the row: a row takes whole bytes, and the bits a
// row does not fill are the row's too.
func TestReadsInlineImageSampleArithmetic(t *testing.T) {
	// Rows of 17 samples at each depth, two rows: the bytes a row takes are
	// the bits it holds rounded up, and the image is twice that.
	for _, c := range []struct {
		bits, bytes int
	}{{1, 3}, {2, 5}, {4, 9}, {8, 17}, {16, 34}} {
		for _, where := range []struct {
			name string
			at   int
		}{
			{"an EI among the first samples", 0},
			{"an EI among the last", -1},
		} {
			t.Run(fmt.Sprintf("%d, %s", c.bits, where.name), func(t *testing.T) {
				samples := bytes.Repeat([]byte{'A'}, 2*c.bytes)
				at := where.at
				if at < 0 {
					at = max(0, len(samples)-len(" EI BT"))
				}
				copy(samples[at:], " EI BT")
				dict := fmt.Sprintf("/W 17 /H 2 /BPC %d /CS /G", c.bits)
				data := readsInlineImagePage(dict, samples, shown("REAL", 700))
				r := extract(t, data)
				if r.Fatal != nil || len(r.Pages) != 1 {
					t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
				}
				if got := r.Pages[0].Text; got != "REAL" {
					t.Errorf("at %d bits a row of 17 samples takes %d bytes, and the record reads %q (problems %+v)",
						c.bits, c.bytes, got, r.Problems)
				}
			})
		}
	}
}

// An image declaring a colour space of many components is measured by what
// that space holds: /DeviceN separates up to 32 colourants, and one that
// names more is no colour space the reader can measure by.
func TestReadsInlineImageDeviceNComponentCounts(t *testing.T) {
	for _, c := range []struct {
		count int
		want  string
	}{{5, "REAL"}, {32, "REAL"}, {33, ""}} {
		t.Run(fmt.Sprint(c.count), func(t *testing.T) {
			names, domain, pops := "", "", ""
			for i := 0; i < c.count; i++ {
				names += fmt.Sprintf("/Ink%d ", i)
				domain += "0 1 "
				pops += "pop "
			}
			resources := func(b *pdfgen.Builder) string {
				tint := b.Add(pdfgen.Object{
					Body:   fmt.Sprintf("<< /FunctionType 4 /Domain [%s] /Range [0 1] >>", strings.TrimSpace(domain)),
					Stream: []byte("{ " + pops + "0 }")})
				return fmt.Sprintf("/ColorSpace << /CSN [/DeviceN [%s] /DeviceGray %d 0 R] >>", names, tint)
			}
			// One row of samples, one byte each: as many bytes as the space
			// has components times the width.
			width := 320 / c.count
			samples := readsHiddenSamples()[:width*c.count]
			var content bytes.Buffer
			content.WriteString(fmt.Sprintf("BI /W %d /H 1 /BPC 8 /CS /CSN ID ", width))
			content.Write(samples)
			content.WriteString(" EI\n")
			content.WriteString(shown("REAL", 700))
			data := readsResourceDocument(content.Bytes(), resources, false)
			r := extract(t, data)
			out, diagnostics, ok := readsPopplerRead(t, data)
			if ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != c.want {
				t.Errorf("a space of %d colourants: the record reads %s %q, want %q (problems %+v)",
					c.count, r.Pages[0].Status, got, c.want, r.Problems)
			}
			if ok && c.want != "" && (out != c.want || strings.Contains(diagnostics, "image parameters")) {
				t.Errorf("pdftotext reads %q with %q as diagnostics; the colour space and its tint transformation are objects of this file", out, diagnostics)
			}
		})
	}
}

// An image's dictionary is pairs: a key with no value where ID stands, a
// keyword inside a value, and an image that begins again before its data are
// each a dictionary the reader cannot read to its end.
func TestReadsInlineImageDictionaryIsPairs(t *testing.T) {
	for _, c := range []struct{ name, dict, want string }{
		{"a complete dictionary", "/W 40 /H 8 /BPC 8 /CS /G", "REAL"},
		{"a key with no value", "/W 40 /H 8 /BPC 8 /CS /G /Width", ""},
		{"a keyword inside a dictionary value", "/W 40 /H 8 /BPC 8 /CS /G /DP << /A EI /B 2 >>", ""},
		{"a keyword inside an array value", "/W 40 /H 8 /BPC 8 /CS /G /D [0 EI 1]", ""},
		{"an image that begins again", "/W 40 /H 8 /BPC 8 /CS /G BI /W 40", ""},
		{"a value where a key stands", "/W 40 /H 8 /BPC 8 /CS /G 42 /IM false", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsInlineImagePage(c.dict, readsHiddenSamples(), shown("REAL", 700))
			r := extract(t, data)
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != c.want {
				t.Errorf("the record reads %s %q, want %q (problems %+v)", r.Pages[0].Status, got, c.want, r.Problems)
			}
		})
	}
}

// One white-space byte stands between ID and the data, and a carriage return
// and a line feed are one end-of-line marker (7.2.3): a writer that ends the
// line that way has not made the line feed a sample.
func TestReadsInlineImageDataBeginsAfterOneEndOfLine(t *testing.T) {
	for _, c := range []struct{ name, separator string }{
		{"a space", " "},
		{"a line feed", "\n"},
		{"a carriage return and a line feed", "\r\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var content bytes.Buffer
			content.WriteString(shown("before", 700))
			content.WriteString("BI /W 4 /H 1 /BPC 8 /CS /G ID" + c.separator)
			content.WriteString("AAAA EI\n")
			content.WriteString(shown("after", 680))
			data := readsContentPage(content.Bytes())
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != "before\nafter" {
				t.Errorf("the record reads %s %q (problems %+v)", r.Pages[0].Status, got, r.Problems)
			}
		})
	}
}

// A comment is white space (7.2.3): one between an image's data and its EI
// stands where white space stands, and the image ends after it as it would
// after a space.
func TestReadsCommentBetweenTheDataAndTheEI(t *testing.T) {
	for _, c := range []struct{ name, dict, samples string }{
		{"a measured image", "/W 4 /H 1 /BPC 8 /CS /G", "AAAA"},
		{"a framed image", "/W 4 /H 1 /BPC 8 /CS /G /F /AHx", "41414141>"},
	} {
		t.Run(c.name, func(t *testing.T) {
			content := shown("before", 700) + "BI " + c.dict + " ID " + c.samples + "\n% image end\nEI\n" + shown("after", 680)
			data := readsContentPage([]byte(content))
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != "before\nafter" {
				t.Errorf("the record reads %s %q (problems %+v)", r.Pages[0].Status, got, r.Problems)
			}
		})
	}
}

// Two declarations of a key that bears on the end are read as what they say,
// not as how they were written: a number is a number, and only a genuine
// disagreement fails the page.
func TestReadsInlineImageNumbersAreComparedByValue(t *testing.T) {
	for _, c := range []struct{ name, dict, want string }{
		{"a width as an integer and as a real", "/W 40 /Width 40.0 /H 8 /BPC 8 /CS /G", "REAL"},
		{"parameters as an integer and as a real", "/W 40 /H 8 /BPC 8 /CS /G /F /AHx /DP << /K 1 >> /DecodeParms << /K 1.0 >>", "REAL"},
		{"widths that disagree", "/W 40 /Width 41.0 /H 8 /BPC 8 /CS /G", ""},
		{"a third declaration that disagrees", "/W 40 /Width 40 /W 1 /H 8 /BPC 8 /CS /G", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			samples := readsHiddenSamples()
			if strings.Contains(c.dict, "/AHx") {
				samples = append(hexStreamOf(readsHiddenSamples()[:320]), ' ')
			}
			data := readsInlineImagePage(c.dict, samples, shown("REAL", 700))
			r := extract(t, data)
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != c.want {
				t.Errorf("the record reads %s %q, want %q (problems %+v)", r.Pages[0].Status, got, c.want, r.Problems)
			}
		})
	}
}

// An image with no width, no height or dimensions that are not positive says
// nothing the reader can measure by.
func TestReadsInlineImageDimensions(t *testing.T) {
	for _, dict := range []string{
		"/H 8 /BPC 8 /CS /G", "/W 40 /BPC 8 /CS /G",
		"/W 0 /H 8 /BPC 8 /CS /G", "/W 40 /H 0 /BPC 8 /CS /G",
		"/W -40 /H 8 /BPC 8 /CS /G", "/W 40 /H -8 /BPC 8 /CS /G",
	} {
		t.Run(dict, func(t *testing.T) {
			data := readsInlineImagePage(dict, readsHiddenSamples(), shown("REAL", 700))
			r := extract(t, data)
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if r.Pages[0].Status != PageFailed || r.Pages[0].Text != "" {
				t.Errorf("the record reads %s %q; the image gives no measurement", r.Pages[0].Status, r.Pages[0].Text)
			}
		})
	}
}

// Establishing the security handler is a reading of the document from the
// top, and a rebuilt cross-reference may name another encryption dictionary.
// Where the rebuild happens while the page tree's root is looked for, the
// walk does not stand in for that reading: it hands back the cross-reference
// it began on, the whole reading begins again, and the pages are read under
// the key the document names now.
func TestReadsEncryptionIsEstablishedAfterARebuiltRootIsFound(t *testing.T) {
	const permissions = -1
	oldO, _, oldU := readsRC4Key("one", permissions)
	newO, newKey, newU := readsRC4Key("two", permissions)
	dictionary := func(o, u []byte) string {
		return fmt.Sprintf("<< /Filter /Standard /V 1 /R 2 /P %d /O <%x> /U <%x> >>", permissions, o, u)
	}
	for _, c := range []struct {
		name   string
		broken int
	}{
		{"the catalog", 1},
		{"the page tree's root", 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsRawTrailer([]readsObject{
				{1, "<< /Type /Catalog /Pages 2 0 R >>"},
				{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
				{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
				{6, readsStreamObject("", string(readsRC4Encrypt(newKey, 6, []byte(shown("NEW", 700)))))},
				{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"},
				{9, dictionary(oldO, oldU)},
				{9, dictionary(newO, newU)},
			}, c.broken, nil, fmt.Sprintf("/Encrypt 9 0 R /ID [<%x> <%x>]", readsFileID, readsFileID))
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != "NEW" {
				t.Errorf("the record reads %s %q; the rebuilt document names the key its page is encrypted under", r.Pages[0].Status, got)
			}
			if r.Encryption == nil || !r.Encryption.Opened {
				t.Errorf("encryption %+v", r.Encryption)
			}
		})
	}
}

// A read that outlives the cross-reference it began on publishes nothing of
// what it finds afterwards, at every depth it reaches. Building the font
// below rebuilds the cross-reference, and the load goes on resolving what the
// old font named: the bound it meets there is a defect of a document this one
// no longer is, and the rebuilt document -- whose font maps the code to Z --
// is the one the record carries.
func TestReadsABoundMetAfterARebuildInAFontIsNotPublished(t *testing.T) {
	font := func(glyph, extra string) string {
		return "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding << /Differences [65 /" + glyph + "] >> " + extra + " >>"
	}
	// The subtype is read first and is a damaged reference: reading it
	// rebuilds. What the load reads after that meets a bound -- of the
	// document the rebuild replaced -- either in the object itself or in the
	// chain of references it follows to reach one.
	chain := []readsObject{{10, "<< /Junk " + strings.Repeat("[", maxNesting+2) + strings.Repeat("]", maxNesting+2) + " >>"}}
	var references []readsObject
	for i := 0; i <= maxRefDepth+4; i++ {
		references = append(references, readsObject{20 + i, fmt.Sprintf("%d 0 R", 21+i)})
	}
	for _, c := range []struct {
		name      string
		trailing  []readsObject
		toUnicode string
	}{
		{"an object nested past what the parser admits", chain, "10 0 R"},
		{"a chain of references longer than the reader follows", references, "20 0 R"},
	} {
		t.Run(c.name, func(t *testing.T) {
			objects := []readsObject{
				{1, "<< /Type /Catalog /Pages 2 0 R >>"},
				{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
				{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
				{6, readsStreamObject("", shown("A", 700))},
				{7, font("B", "/Subtype 8 0 R /ToUnicode "+c.toUnicode)},
				{8, "/Type1"},
			}
			objects = append(objects, c.trailing...)
			objects = append(objects, readsObject{7, font("Z", "")})
			data := readsRawFile(objects, 8, nil)
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil {
				t.Fatalf("fatal %+v; the bound was met in a font of the document the rebuild replaced", r.Fatal)
			}
			if len(r.Pages) != 1 || r.Pages[0].Text != "Z" || len(r.Problems) != 0 {
				t.Errorf("the record reads %+v with problems %+v, want one page reading %q", r.Pages, r.Problems, "Z")
			}
		})
	}
}

// readsEncodedFont is a composite font whose encoding is the CMap given, with
// a descendant that gives one CID a width of its own, and a page showing the
// code given. The font number is returned with the file, so that a test may
// read the font as well as the record.
func readsEncodedFont(encoding, toUnicode, show string) ([]byte, int) {
	b := &pdfgen.Builder{}
	extra := ""
	if toUnicode != "" {
		extra = fmt.Sprintf("/ToUnicode %d 0 R", b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(toUnicode)}))
	}
	enc := b.Add(pdfgen.Object{
		Body:   "<< /Type /CMap /CMapName /Test-H /CIDSystemInfo << /Registry (Adobe) /Ordering (Japan1) /Supplement 2 >> >>",
		Stream: []byte(encoding)})
	cid := b.Add(pdfgen.Object{Body: "<< /Type /Font /Subtype /CIDFontType0 /BaseFont /Test /CIDSystemInfo << /Registry (Adobe) /Ordering (Japan1) /Supplement 2 >> /DW 700 /W [33089 [123]] >>"})
	f := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Font /Subtype /Type0 /BaseFont /Test /Encoding %d 0 R /DescendantFonts [%d 0 R] %s >>", enc, cid, extra)})
	b.Catalog(b.Pages([]pdfgen.Page{{Content: "BT /F1 12 Tf 1 0 0 1 72 700 Tm <" + show + "> Tj ET\n", Fonts: map[string]int{"F1": f}}}))
	return b.Bytes(), f
}

// A font's own encoding CMap says how its bytes split into codes and what
// each code stands for. An encoding the reader cannot use says neither, and
// Identity is not what is left: a code Identity would make is a code the file
// does not give, so the glyphs are unmapped and counted, at the width a CID
// the font has no width for is given. A ToUnicode map is a second reading of
// codes this font's encoding never established.
func TestReadsAnEncodingTheReaderCannotUseIsNotIdentity(t *testing.T) {
	for _, ranges := range []struct{ name, spaces string }{
		{"the one-byte range first", "<81> <81>\n<8140> <81FC>"},
		{"the two-byte range first", "<8140> <81FC>\n<81> <81>"},
		{"a two-byte range over the whole lead byte", "<81> <81>\n<8100> <81FF>"},
	} {
		for _, tu := range []struct{ name, body string }{
			{"with no ToUnicode map", ""},
			{"with a ToUnicode map of its own", "begincmap\n1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n1 beginbfchar\n<8141> <005A>\nendbfchar\nendcmap\n"},
		} {
			t.Run(ranges.name+", "+tu.name, func(t *testing.T) {
				data, num := readsEncodedFont("begincmap\n2 begincodespacerange\n"+ranges.spaces+"\nendcodespacerange\nendcmap\n", tu.body, "8141")
				r := extract(t, data)
				if out, diagnostics, ok := readsPopplerRead(t, data); ok {
					t.Logf("pdftotext reads %q, with %q as diagnostics", out, diagnostics)
				}
				if r.Fatal != nil || len(r.Pages) != 1 {
					t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
				}
				if r.Pages[0].Text != "�" || r.Pages[0].Unmapped != 1 {
					t.Errorf("the record reads %q with %d glyphs unmapped; this font's encoding says a code beginning 81 is one byte and says it is two",
						r.Pages[0].Text, r.Pages[0].Unmapped)
				}
				if g := firstGlyph(loadFontNumbered(openGenerated(t, data), num), []byte{0x81, 0x41}); !g.unmapped || len(g.runes) != 0 || g.width != 0.7 {
					t.Errorf("the code is %q, unmapped %v, %g em wide; the font gives no CID for it and its width is the default width",
						string(g.runes), g.unmapped, g.width)
				}
			})
		}
	}
}

// A font whose encoding is a predefined CMap the reader does not carry splits
// its bytes by the codespace ranges its ToUnicode map declares. A range the
// reader inferred from what that map holds is not one the map declares: a map
// that declares none leaves the font with the two-byte fallback, whether the
// map's parsing ended at its endcmap or at the end of its bytes.
func TestReadsCodespacesAreBorrowedOnlyWhereTheyAreDeclared(t *testing.T) {
	for _, c := range []struct{ name, tail string }{
		{"a map that ends at its endcmap", "endcmap\n"},
		{"a map that ends where its bytes do", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := &pdfgen.Builder{}
			tu := b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(
				"begincmap\n1 beginbfrange\n<41> <41> <0058>\nendbfrange\n1 beginbfchar\n<0041> <005A>\nendbfchar\n" + c.tail)})
			cid := b.Add(pdfgen.Object{Body: "<< /Type /Font /Subtype /CIDFontType0 /BaseFont /Test /DW 700 /W [65 [123]] >>"})
			num := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Font /Subtype /Type0 /BaseFont /Test /Encoding /90ms-RKSJ-H /DescendantFonts [%d 0 R] /ToUnicode %d 0 R >>", cid, tu)})
			b.Catalog(b.Pages([]pdfgen.Page{{Content: "BT /F1 12 Tf 1 0 0 1 72 700 Tm <0041> Tj ET\n", Fonts: map[string]int{"F1": num}}}))
			data := b.Bytes()
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != "Z" || r.Pages[0].Unmapped != 0 {
				t.Errorf("the record reads %q with %d glyphs unmapped; the map declares no codespace range, so the code is the two bytes the page shows", got, r.Pages[0].Unmapped)
			}
			if g := firstGlyph(loadFontNumbered(openGenerated(t, data), num), []byte{0, 65}); g.width != 0.7 {
				t.Errorf("the code is %g em wide; the CMap that would give it a CID is not in the file, so the width is the default width", g.width)
			}
		})
	}
}

// A code is its bytes and how many of them it has, at every length a code may
// have. Codes of four lengths stand one after another in the string below,
// and each is looked up among the mappings for codes of its own length.
func TestReadsCodesOfEveryLengthAreLookedUpByTheirOwnLength(t *testing.T) {
	for _, c := range []struct {
		name, spaces, mappings, show, want string
	}{
		{
			"one code of each length",
			"4 begincodespacerange\n<41> <41>\n<0000> <00FF>\n<820000> <82FFFF>\n<83000000> <83FFFFFF>\nendcodespacerange\n",
			"4 beginbfchar\n<41> <0041>\n<0041> <0042>\n<820041> <0043>\n<83000041> <0044>\nendbfchar\n",
			"41004182004183000041", "ABCD",
		},
		{
			"codes of two lengths that share no leading byte",
			"2 begincodespacerange\n<41> <42>\n<0041> <0042>\nendcodespacerange\n",
			"4 beginbfchar\n<41> <0041>\n<0041> <0058>\n<42> <0042>\n<0042> <0059>\nendbfchar\n",
			"410041420042", "AXBY",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			data, _ := readsEncodedFont("begincmap\n"+c.spaces+"endcmap\n", "begincmap\n"+c.spaces+c.mappings+"endcmap\n", c.show)
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != c.want {
				t.Errorf("the record reads %q, want %q: each code is looked up among the codes of its own length", got, c.want)
			}
		})
	}
}

// A page of a million codes, each looked up over as many codespace ranges as
// one CMap may declare, is a page the deadline ends: the reading stops at the
// check that finds the deadline passed, the record says it timed out, and no
// page of half a reading is listed.
func TestReadsAPageOfManyCodesMeetsItsDeadline(t *testing.T) {
	if testing.Short() {
		t.Skip("shows a million codes")
	}
	var spaces bytes.Buffer
	fmt.Fprintf(&spaces, "begincmap\n%d begincodespacerange\n", maxCodespaces)
	for i := 0; i < maxCodespaces; i++ {
		fmt.Fprintf(&spaces, "<%02X00> <%02XFF>\n", i, i)
	}
	spaces.WriteString("endcodespacerange\n1 beginbfrange\n<0000> <FFFF> <0041>\nendbfrange\nendcmap\n")
	show := strings.Repeat(fmt.Sprintf("%02X41", maxCodespaces-1), 1<<20)
	data, _ := readsEncodedFont(spaces.String(), spaces.String(), show)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	r := Extract(ctx, data, testOptions())
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Errorf("the reading took %v past a deadline of 50ms", elapsed)
	}
	if !r.TimedOut || len(r.Pages) != 0 {
		t.Errorf("timed out %v, pages %+v; the reading stopped at the deadline and carries no page of half a reading", r.TimedOut, r.Pages)
	}
}

// readsFax is a Group 4 image of one row: the row's own code, and the
// end-of-facsimile-block of T.6 -- two end-of-line codes -- which is where
// its encoding puts the end of the data.
func readsFax() string {
	return "BI /W 8 /H 1 /BPC 1 /CS /G /F /CCF /DP << /K -1 /Columns 8 /Rows 1 >> ID " +
		string([]byte{0x80, 0x08, 0, 0x80}) + " EI\n"
}

// readsJBIG2 is an embedded JBIG2 image carrying the bytes given: the
// page-information segment of 7.4.8 of ISO 14492 -- the header of 7.2, and
// the nineteen bytes of the page's size, resolution and flags -- and a
// generic region segment holding them. Each header states its data's length,
// which is what a reader that framed this encoding would walk.
func readsJBIG2(carried []byte) []byte {
	segment := func(number int, kind byte, data []byte) []byte {
		out := []byte{byte(number >> 24), byte(number >> 16), byte(number >> 8), byte(number), kind, 0x00, 0x01}
		n := len(data)
		out = append(out, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
		return append(out, data...)
	}
	page := make([]byte, 19)
	page[3], page[7] = 8, 8
	return append(segment(1, 48, page), segment(2, 38, carried)...)
}

// readsJPX is a JPEG 2000 image carrying the bytes given: the signature,
// file-type and header boxes of ISO 15444-1, and the contiguous codestream
// box holding them between the start- and end-of-codestream markers. Each box
// states its own length, which is what a reader that framed this encoding
// would walk.
func readsJPX(carried []byte) []byte {
	box := func(kind string, data []byte) []byte {
		n := len(data) + 8
		out := []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
		return append(append(out, kind...), data...)
	}
	header := make([]byte, 14)
	header[3], header[7], header[9], header[10], header[11] = 8, 8, 1, 7, 7
	out := box("jP  ", []byte{0x0D, 0x0A, 0x87, 0x0A})
	out = append(out, box("ftyp", []byte("jp2 \x00\x00\x00\x00jp2 "))...)
	out = append(out, box("jp2h", box("ihdr", header))...)
	codestream := append([]byte{0xFF, 0x4F}, carried...)
	return append(out, box("jp2c", append(codestream, 0xFF, 0xD9))...)
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
		{"a width and its name", "/W 4 /Width 4 /H 1 /BPC 8 /CS /G", "AAAA"},
		{"a depth written as an integer and as a real", "/W 4 /H 1 /BPC 8 /BitsPerComponent 8.0 /CS /G", "AAAA"},
		{"a depth written as a real and as an integer", "/W 4 /H 1 /BitsPerComponent 8.0 /BPC 8 /CS /G", "AAAA"},
		{"a mask depth written both ways", "/W 32 /H 1 /IM true /BitsPerComponent 1.0 /BPC 1 /D [0 1]", "AAAA"},
		{"a mask depth written the other way about", "/W 32 /H 1 /IM true /BPC 1 /BitsPerComponent 1.0 /D [0 1]", "AAAA"},
		{"a colour space written in place under both names", "/W 4 /H 1 /BPC 8 /CS [/I /DeviceGray 1 <FFEE>] /ColorSpace [/Indexed /DeviceGray 1 <FFEE>]", "AAAA"},
		{"an entry written null and not written at all", "/W 4 /H 1 /BPC 8 /CS /G /L null", "AAAA"},
		{"a device space and its array", "/W 4 /H 1 /BPC 8 /CS /G /ColorSpace [/DeviceGray]", "AAAA"},
		{"the array and the device space", "/W 4 /H 1 /BPC 8 /CS [/DeviceGray] /ColorSpace /G", "AAAA"},
		{"three components, the name first", "/W 4 /H 1 /BPC 8 /CS /RGB /ColorSpace [/DeviceRGB]", "AAAAAAAAAAAA"},
		{"three components, the array first", "/W 4 /H 1 /BPC 8 /CS [/RGB] /ColorSpace /DeviceRGB", "AAAAAAAAAAAA"},
		{"four components, the name first", "/W 4 /H 1 /BPC 8 /CS /CMYK /ColorSpace [/DeviceCMYK]", "AAAAAAAAAAAAAAAA"},
		{"four components, the array first", "/W 4 /H 1 /BPC 8 /CS [/DeviceCMYK] /ColorSpace /CMYK", "AAAAAAAAAAAAAAAA"},
		{"parameters differing by an absent entry", "/W 8 /H 1 /BPC 1 /CS /G /F /CCF /DP << /K -1 /Columns 8 /Rows 1 >> /DecodeParms << /K -1 /Columns 8 /Rows 1 /Unrelated null >>", "\x80\x08\x00\x80"},
		{"the absent entry written first", "/W 8 /H 1 /BPC 1 /CS /G /F /CCF /DP << /K -1 /Columns 8 /Rows 1 /Unrelated null >> /DecodeParms << /K -1 /Columns 8 /Rows 1 >>", "\x80\x08\x00\x80"},
		{"a colour space differing by an absent entry", "/W 4 /H 1 /BPC 8 /CS [/CalGray << /WhitePoint [1 1 1] /Gamma null >>] /ColorSpace [/CalGray << /WhitePoint [1 1 1] >>]", "AAAA"},
		{"the absent entry in the second writing", "/W 4 /H 1 /BPC 8 /CS [/CalGray << /WhitePoint [1 1 1] >>] /ColorSpace [/CalGray << /WhitePoint [1 1 1] /Gamma null >>]", "AAAA"},
		{"parameters that hold only an absent entry", "/W 4 /H 1 /BPC 8 /CS /G /DP << /Unused null >> /DecodeParms << >>", "AAAA"},
		{"the empty parameters first", "/W 4 /H 1 /BPC 8 /CS /G /DP << >> /DecodeParms << /Unused null >>", "AAAA"},
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
			if got := r.Pages[0].Text; got != "REAL" || r.Pages[0].Status != PageOK || len(r.Problems) != 0 {
				t.Errorf("the record reads %s %q with problems %+v; the two spellings are one value", r.Pages[0].Status, got, r.Problems)
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

// A colour space of more components than a device has is measured too: a
// DeviceN space separates up to 32 colourants (8.6.6.5), and an image in one
// is as long as its samples say.
func TestReadsInlineImageInAManyComponentColourSpace(t *testing.T) {
	var content bytes.Buffer
	// 64 samples of five components of one byte: 320 bytes.
	content.WriteString("BI /W 64 /H 1 /BPC 8 /CS /CS5 ID ")
	content.Write(readsHiddenSamples())
	content.WriteString(" EI\n")
	content.WriteString(shown("REAL", 700))
	data := readsResourceDocument(content.Bytes(), func(b *pdfgen.Builder) string {
		tint := b.Add(pdfgen.Object{
			Body:   "<< /FunctionType 4 /Domain [0 1 0 1 0 1 0 1 0 1] /Range [0 1 0 1 0 1 0 1] >>",
			Stream: []byte("{ pop pop pop pop pop 0 0 0 0 }")})
		return fmt.Sprintf("/ColorSpace << /CS5 [/DeviceN [/Cyan /Magenta /Yellow /Black /Spot] /DeviceCMYK %d 0 R] >>", tint)
	}, false)
	r := extract(t, data)
	out, diagnostics, ok := readsPopplerRead(t, data)
	if ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if got := r.Pages[0].Text; got != "REAL" {
		t.Errorf("the record reads %q; five components of 64 samples take 320 bytes (problems %+v)", got, r.Problems)
	}
	if ok && (out != "REAL" || strings.Contains(diagnostics, "image parameters")) {
		t.Errorf("pdftotext reads %q with %q as diagnostics; the space and its tint transformation are objects of this file", out, diagnostics)
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

// An inline image's dictionary is read as pairs at every depth it holds. A
// keyword inside an array or a nested dictionary, a value where a key stands
// in one, a container that does not close, and a keyword between pairs are
// each a dictionary that does not reach the data it describes: ID stands
// between complete pairs of the dictionary itself, and nowhere else.
func TestReadsInlineImageDictionaryIsPairsAtEveryDepth(t *testing.T) {
	for _, c := range []struct{ name, dict string }{
		{"an array a value stands in that does not close", "/W 40 /H 8 /BPC 8 /CS /G /D [0"},
		{"an operator inside an array value", "/W 40 /H 8 /BPC 8 /CS /G /D [0 Q"},
		{"a nested dictionary that does not close", "/W 40 /H 8 /BPC 8 /CS /G /DP << /K 0"},
		{"a key with no value inside a nested dictionary", "/W 40 /H 8 /BPC 8 /CS /G /DP << /A >>"},
		{"a value where a key stands inside a nested dictionary", "/W 40 /H 8 /BPC 8 /CS /G /DP << 42 /A 1 >>"},
		{"a keyword where a value stands", "/W bogus 40 /H 8 /BPC 8 /CS /G"},
		{"a keyword between two pairs", "/W 40 /H 8 bogus /BPC 8 /CS /G"},
		{"a stray closing delimiter between two pairs", "/W 40 /H 8 ] /BPC 8 /CS /G"},
		// An EI and a second BI stand where a key would, with the image's
		// own ID after them: a reader that read past either would reach that
		// ID and measure an image whose dictionary it never read to an end.
		{"an image that ends before its data begins", "/W 40 /H 8 /BPC 8 /CS /G EI"},
		{"an image that begins again before its data", "/W 40 /H 8 /BPC 8 /CS /G BI"},
		// A byte that begins no token -- a parenthesis that closes no
		// string, an angle bracket that is not half of a dictionary's end --
		// is skipped where a damaged file is read for what it still holds.
		// Here it is not: the dictionary is read to the image's data or the
		// page fails.
		{"a closing parenthesis where a value stands", "/W ) 40 /H 8 /BPC 8 /CS /G"},
		{"an angle bracket where a value stands", "/W > 40 /H 8 /BPC 8 /CS /G"},
		{"a closing parenthesis between two pairs", "/W 40 ) /H 8 /BPC 8 /CS /G"},
		{"an angle bracket between two pairs", "/W 40 > /H 8 /BPC 8 /CS /G"},
		{"a closing parenthesis inside an array value", "/W 40 /H 8 /BPC 8 /CS /G /D [0 ) 1]"},
		{"an angle bracket inside an array value", "/W 40 /H 8 /BPC 8 /CS /G /D [0 > 1]"},
		{"a closing parenthesis inside a nested dictionary", "/W 40 /H 8 /BPC 8 /CS /G /DP << /A ) 1 >>"},
		{"an angle bracket inside a nested dictionary", "/W 40 /H 8 /BPC 8 /CS /G /DP << /A > 1 >>"},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsInlineImagePage(c.dict, readsHiddenSamples(), shown("REAL", 700))
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if r.Pages[0].Status != PageFailed || r.Pages[0].Text != "" || len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" {
				t.Errorf("the record reads %s %q with problems %+v; the dictionary does not reach the image's data",
					r.Pages[0].Status, r.Pages[0].Text, r.Problems)
			}
		})
	}
}

// What an inline image's dictionary declares is what says where its data
// ends. A key written in full says what its abbreviation says; a bare name
// that is no device colour space is the name of a resource, and two such
// names are two resources however alike they look; a dimension is an integer
// and nothing else; a name no resource declares sizes nothing; and where the
// samples say the data ends is where the EI must stand.
func TestReadsInlineImageDeclarationsDecideTheEnd(t *testing.T) {
	// Resources naming two colour spaces of one and of three components,
	// under the two names an abbreviation would make one name.
	const spaces = "/ColorSpace << /I /DeviceGray /Indexed /DeviceRGB /Other /DeviceGray >>"
	sample := func(n int) []byte { return bytes.Repeat([]byte{'A'}, n) }
	for _, c := range []struct {
		name, dict, resources string
		samples               []byte
		want                  string
	}{
		{"every key written in full", "/Width 40 /Height 8 /BitsPerComponent 8 /ColorSpace /DeviceGray", "", readsHiddenSamples(), "REAL"},
		{"a mask written in full", "/Width 320 /Height 8 /ImageMask true", "", readsHiddenSamples(), "REAL"},
		{"a filter written in full", "/Width 4 /Height 4 /BitsPerComponent 8 /ColorSpace /DeviceGray /Filter /ASCIIHexDecode", "", []byte("41414141>"), "REAL"},
		{"parameters written in full", "/Width 8 /Height 1 /BitsPerComponent 1 /ColorSpace /DeviceGray /Filter /CCITTFaxDecode /DecodeParms << /K -1 /Columns 8 /Rows 1 >>", "", []byte{0x80, 0x08, 0, 0x80}, "REAL"},
		{"the resource named I", "/W 64 /H 1 /BPC 8 /CS /I", spaces, sample(64), "REAL"},
		{"the resource named Indexed", "/W 64 /H 1 /BPC 8 /CS /Indexed", spaces, sample(192), "REAL"},
		{"both resource names, the family's last", "/W 64 /H 1 /BPC 8 /CS /I /ColorSpace /Indexed", spaces, sample(192), ""},
		{"both resource names, the abbreviation last", "/W 64 /H 1 /BPC 8 /ColorSpace /Indexed /CS /I", spaces, sample(192), ""},
		{"a family written in place under both names", "/W 64 /H 1 /BPC 8 /CS [/I /DeviceGray 1 <FFEE>] /ColorSpace [/Indexed /DeviceGray 1 <FFEE>]", spaces, sample(64), "REAL"},
		{"a name the resources do not declare", "/W 40 /H 8 /BPC 8 /CS /Missing", spaces, readsHiddenSamples(), ""},
		{"a pattern space, which sizes no sample", "/W 40 /H 8 /BPC 8 /CS [/Pattern]", "", readsHiddenSamples(), ""},
		{"a width written as a real", "/W 40.0 /H 8 /BPC 8 /CS /G", "", readsHiddenSamples(), ""},
		{"a width written as a string", "/W (40) /H 8 /BPC 8 /CS /G", "", readsHiddenSamples(), ""},
		{"samples the EI does not follow", "/W 4 /H 1 /BPC 8 /CS /G", "", []byte("AAAAJUNK"), ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			var content bytes.Buffer
			content.WriteString("BI " + c.dict + " ID ")
			content.Write(c.samples)
			content.WriteString("\nEI\n")
			content.WriteString(shown("REAL", 700))
			data := readsResourcePage(content.Bytes(), c.resources, false)
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			status, problems := PageOK, 0
			if c.want == "" {
				status, problems = PageFailed, 1
			}
			if r.Pages[0].Text != c.want || r.Pages[0].Status != status || len(r.Problems) != problems {
				t.Errorf("the record reads %s %q with problems %+v, want %s %q", r.Pages[0].Status, r.Pages[0].Text, r.Problems, status, c.want)
			}
		})
	}
}

// The bound on an inline image's data is a bound on its bytes. A row of
// samples one bit wide holds eight times the pixels of a row of the same
// length at eight bits, and an image is past the bound when its bytes are
// past it and not when its pixels are.
func TestReadsAWideImageIsBoundedByItsBytes(t *testing.T) {
	if testing.Short() {
		t.Skip("writes images of several megabytes")
	}
	const width = maxInlineImageBytes + 1
	for _, c := range []struct {
		name, dict string
		bytes      int
		want       string
	}{
		{"one bit a sample", fmt.Sprintf("/W %d /H 1 /BPC 1 /CS /G", width), (width + 7) / 8, "REAL"},
		{"one bit a sample, as a mask", fmt.Sprintf("/W %d /H 1 /IM true", width), (width + 7) / 8, "REAL"},
		{"two bits a sample", fmt.Sprintf("/W %d /H 1 /BPC 2 /CS /G", width), (2*width + 7) / 8, "REAL"},
		{"four bits a sample", fmt.Sprintf("/W %d /H 1 /BPC 4 /CS /G", width), (4*width + 7) / 8, "REAL"},
		{"eight bits a sample", fmt.Sprintf("/W %d /H 1 /BPC 8 /CS /G", width), width, ""},
		{"a width no arithmetic of the bound could hold", "/W 9223372036854775807 /H 1 /BPC 16 /CS /G", 16, ""},
		// Two dimensions whose products wrap where an int64 ends: unguarded,
		// the first measures 320 bytes and the second 256, which is what
		// each of these fixtures holds.
		{"a width whose packed bits wrap", "/W 1152921504606847016 /H 4 /BPC 16 /CS /G", 320, ""},
		{"a height whose rows wrap", "/W 32 /H 576460752303423496 /BPC 8 /CS /G", 256, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsInlineImagePage(c.dict, bytes.Repeat([]byte{'A'}, c.bytes), shown("REAL", 700))
			r := extract(t, data)
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != c.want {
				t.Errorf("%d bytes of samples: the record reads %s %q, want %q (problems %+v)",
					c.bytes, r.Pages[0].Status, got, c.want, r.Problems)
			}
		})
	}
}

// A final base-85 group of fewer than five characters stands for one byte
// less than it has characters, completed as 7.4.3 completes it -- with the
// largest character of the alphabet -- and the number that completion makes
// is one a four-byte word holds or the data is no ASCII85Decode data. The
// white space such data admits is the white space of 7.2.3, not every byte
// below a space.
func TestReadsBase85FinalGroupsAndWhiteSpace(t *testing.T) {
	for _, c := range []struct{ name, samples, want string }{
		{"a final group of two characters past the largest word", "!!!!!uu~>", ""},
		{"a final group of three past it", "!!!!!uuu~>", ""},
		{"a final group of four past it", "!!!!!uuuu~>", ""},
		{"a final group of four the word holds", "!!!!!!!!!~>", "before\nafter"},
		{"the white space of the specification between the characters", "!\x00!\t!\n!\f!\r! !!~>", "before\nafter"},
		{"a byte below a space that is not white space", "!\x01!!!!~>", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			content := shown("before", 700) + "BI /W 4 /H 4 /BPC 8 /CS /G /F /A85 ID " + c.samples + " EI\n" + shown("after", 680)
			data := readsContentPage([]byte(content))
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != c.want {
				t.Errorf("the record reads %s %q, want %q (problems %+v)", r.Pages[0].Status, got, c.want, r.Problems)
			}
		})
	}
}

// readsRestartJPEG is a JPEG of sixteen by sixteen samples whose restart
// interval is one block, carrying the bytes given in a comment segment. Its
// tables and frame header are the ones Go's encoder writes; each block is
// coded as a difference of nothing and an end-of-block, which under those
// tables is six bits filled to a byte with ones, and a restart marker stands
// between the blocks. Before the first restart stand as many fill bytes as
// fill says, which 4.10 of ITU T.81 allows a writer to put there.
func readsRestartJPEG(t *testing.T, carried []byte, fill int) []byte {
	t.Helper()
	var base bytes.Buffer
	if err := jpeg.Encode(&base, image.NewGray(image.Rect(0, 0, 16, 16)), nil); err != nil {
		t.Fatal(err)
	}
	out := []byte{0xFF, 0xD8, 0xFF, 0xFE, byte((len(carried) + 2) >> 8), byte(len(carried) + 2)}
	out = append(out, carried...)
	src := base.Bytes()
	for i := 2; i+3 < len(src); {
		marker, length := src[i+1], int(src[i+2])<<8|int(src[i+3])
		if marker == 0xDA {
			break
		}
		if marker == 0xDB || marker == 0xC4 || marker == 0xC0 {
			out = append(out, src[i:i+2+length]...)
		}
		i += 2 + length
	}
	// The restart interval, and a scan of the one component under table 0.
	out = append(out, 0xFF, 0xDD, 0x00, 0x04, 0x00, 0x01)
	out = append(out, 0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00)
	for block := 0; block < 4; block++ {
		if block > 0 {
			if block == 1 {
				out = append(out, bytes.Repeat([]byte{0xFF}, fill)...)
			}
			out = append(out, 0xFF, byte(0xD0+block-1))
		}
		out = append(out, 0x2B)
	}
	return append(out, 0xFF, 0xD9)
}

// A restart marker resumes a JPEG's entropy-coded data, and the fill bytes a
// writer may put before one belong to it: an image whose blocks are coded
// between restarts ends at its end-of-image like any other, and the text its
// coded data carries is the image's and not the page's.
func TestReadsJPEGRestartsWithFillBytes(t *testing.T) {
	for _, c := range []struct {
		name string
		fill int
	}{
		{"a restart marker", 0},
		{"a fill byte before a restart marker", 1},
		{"a run of fill bytes longer than the deadline's cadence", entriesPerCheck + 64},
	} {
		t.Run(c.name, func(t *testing.T) {
			samples := readsRestartJPEG(t, []byte(" EI\n"+shown("HIDDEN", 650)), c.fill)
			if _, err := jpeg.Decode(bytes.NewReader(samples)); err != nil {
				t.Fatalf("the fixture is not a JPEG a decoder reads: %v", err)
			}
			data := readsInlineImagePage("/W 16 /H 16 /BPC 8 /CS /G /F /DCT", samples, shown("REAL", 700))
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != "REAL" || r.Pages[0].Status != PageOK {
				t.Errorf("the record reads %s %q, want %q (problems %+v)", r.Pages[0].Status, got, "REAL", r.Problems)
			}
		})
	}
}

// An ICCBased colour space says how many components its samples have in the
// /N of its stream, and an inline image in one is measured by that: the space
// is a resource the page declares, since an inline image's dictionary holds
// no indirect reference to name the stream by.
func TestReadsInlineImageInAnICCBasedSpace(t *testing.T) {
	for _, c := range []struct {
		components, samples int
		want                string
	}{
		{1, 64, "REAL"},
		{3, 192, "REAL"},
		{4, 256, "REAL"},
		{3, 64, ""},
	} {
		t.Run(fmt.Sprintf("%d components, %d bytes", c.components, c.samples), func(t *testing.T) {
			var content bytes.Buffer
			content.WriteString("BI /W 64 /H 1 /BPC 8 /CS /ICC ID ")
			content.Write(bytes.Repeat([]byte{'A'}, c.samples))
			content.WriteString("\nEI\n")
			content.WriteString(shown("REAL", 700))
			data := readsResourceDocument(content.Bytes(), func(b *pdfgen.Builder) string {
				profile := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /N %d >>", c.components), Stream: bytes.Repeat([]byte{0}, 8)})
				return fmt.Sprintf("/ColorSpace << /ICC [/ICCBased %d 0 R] >>", profile)
			}, false)
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != c.want {
				t.Errorf("a profile of %d components and %d bytes of samples: the record reads %s %q, want %q (problems %+v)",
					c.components, c.samples, r.Pages[0].Status, got, c.want, r.Problems)
			}
		})
	}
}

// Where the samples end is where the image ends, at every depth: an image
// whose samples end before the measurement or past it is an image whose end
// the page does not establish, and a reader that looked forward from the
// measured offset for an "EI" would find the one the image's own bytes carry.
func TestReadsSamplesMustEndAtTheMeasurement(t *testing.T) {
	for _, c := range []struct{ bits, bytes int }{{1, 3}, {2, 5}, {4, 9}, {8, 17}, {16, 34}} {
		for _, where := range []struct {
			name  string
			delta int
		}{
			{"two bytes short of it", -2},
			{"one byte past it", 1},
		} {
			t.Run(fmt.Sprintf("%d bits, %s", c.bits, where.name), func(t *testing.T) {
				// The samples carry an "EI" of their own, which the
				// measurement passes over and a search would stop at.
				samples := bytes.Repeat([]byte{'A'}, 2*c.bytes+where.delta)
				copy(samples, " EI ")
				dict := fmt.Sprintf("/W 17 /H 2 /BPC %d /CS /G", c.bits)
				data := readsInlineImagePage(dict, samples, shown("REAL", 700))
				r := extract(t, data)
				if out, ok := readsPoppler(t, data); ok {
					t.Logf("pdftotext reads %q", out)
				}
				if r.Fatal != nil || len(r.Pages) != 1 {
					t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
				}
				if r.Pages[0].Status != PageFailed || r.Pages[0].Text != "" || len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" {
					t.Errorf("%d samples where the image says %d: the record reads %s %q with problems %+v",
						len(samples), 2*c.bytes, r.Pages[0].Status, r.Pages[0].Text, r.Problems)
				}
			})
		}
	}
}

// readsOverNested is an object nested past what the parser admits: reading it
// meets a structure bound, wherever the reference to it is resolved from.
func readsOverNested() string {
	return "<< /Junk " + strings.Repeat("[", maxNesting+2) + strings.Repeat("]", maxNesting+2) + " >>"
}

// An operation that resolves more than one of an object's fields is one read:
// the fields after the first belong to the cross-reference the first was read
// under, and where reading one of them rebuilds it, what the rest find -- a
// bound included -- is of a document this one no longer is. Each file below
// resolves a damaged reference, which rebuilds, and then a second field of
// the same object, which is nested past what the parser admits; the rebuilt
// document names neither, and the record carries its page.
func TestReadsAnOperationIsOneReadFromItsFirstFieldToItsLast(t *testing.T) {
	font := "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding << /Differences [65 /Z] >> >>"
	page := "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"
	for _, c := range []struct {
		name    string
		objects []readsObject
		broken  int
	}{
		{"a page-tree node whose resources are damaged and whose kids are nested past the parser", []readsObject{
			{1, "<< /Type /Catalog /Pages 2 0 R >>"},
			{2, "<< /Type /Pages /Resources 8 0 R /Kids 10 0 R /Count 1 >>"},
			{3, page},
			{6, readsStreamObject("", shown("A", 700))},
			{7, font},
			{8, "<< /Font << /F1 7 0 R >> >>"},
			{10, readsOverNested()},
			{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
		}, 8},
		{"a form whose matrix is damaged and whose resources are nested past the parser", []readsObject{
			{1, "<< /Type /Catalog /Pages 2 0 R >>"},
			{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
			{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> /XObject << /X 8 0 R >> >> /Contents 6 0 R >>"},
			{6, readsStreamObject("", shown("A", 700)+"/X Do\n")},
			{7, font},
			{8, readsStreamObject("/Type /XObject /Subtype /Form /BBox [0 0 10 10] /Matrix 12 0 R /Resources 10 0 R", " ")},
			{10, readsOverNested()},
			{12, "[1 0 0 1 0 0]"},
			{8, readsStreamObject("/Type /XObject /Subtype /Form /BBox [0 0 10 10]", " ")},
		}, 12},
		{"a chain of references through a damaged one to an object nested past the parser", []readsObject{
			{1, "<< /Type /Catalog /Pages 8 0 R >>"},
			{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
			{3, page},
			{6, readsStreamObject("", shown("A", 700))},
			{7, font},
			{8, "9 0 R"},
			{9, "10 0 R"},
			{10, readsOverNested()},
			{1, "<< /Type /Catalog /Pages 2 0 R >>"},
		}, 9},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsRawFile(c.objects, c.broken, nil)
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil {
				t.Fatalf("fatal %+v; the bound was met in a document the rebuild replaced", r.Fatal)
			}
			if len(r.Pages) != 1 || r.Pages[0].Text != "Z" || len(r.Problems) != 0 {
				t.Errorf("the record reads %+v with problems %+v, want one page reading %q", r.Pages, r.Problems, "Z")
			}
		})
	}
}

// Reading the encryption dictionary is one read as any other operation is:
// its version is a damaged reference, which rebuilds, and the length beside
// it is nested past what the parser admits. The dictionary the rebuilt
// trailer names is read in its place, and the page is read under the key that
// one derives.
func TestReadsTheEncryptionDictionaryIsOneRead(t *testing.T) {
	const permissions = -1
	oldO, _, oldU := readsRC4Key("one", permissions)
	newO, newKey, newU := readsRC4Key("two", permissions)
	data := readsRawTrailer([]readsObject{
		{1, "<< /Type /Catalog /Pages 2 0 R >>"},
		{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
		{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
		{6, readsStreamObject("", string(readsRC4Encrypt(newKey, 6, []byte(shown("NEW", 700)))))},
		{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"},
		{9, fmt.Sprintf("<< /Filter /Standard /V 12 0 R /R 2 /P %d /O <%x> /U <%x> /Length 10 0 R >>", permissions, oldO, oldU)},
		{10, readsOverNested()},
		{12, "1"},
		{9, fmt.Sprintf("<< /Filter /Standard /V 1 /R 2 /P %d /O <%x> /U <%x> >>", permissions, newO, newU)},
	}, 12, nil, fmt.Sprintf("/Encrypt 9 0 R /ID [<%x> <%x>]", readsFileID, readsFileID))
	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil {
		t.Fatalf("fatal %+v; the bound was met in a dictionary the rebuilt trailer does not name", r.Fatal)
	}
	if len(r.Pages) != 1 || r.Pages[0].Text != "NEW" {
		t.Errorf("the record reads %+v, want one page reading %q", r.Pages, "NEW")
	}
	if r.Encryption == nil || !r.Encryption.Opened {
		t.Errorf("encryption %+v", r.Encryption)
	}
}

// A rebuilt trailer may name no encryption at all. What was read through the
// handler the old one named was read through a key this document does not
// have: those objects, and the fonts and CMaps built from them, are dropped
// before the document is read again, and the page below reads the text its
// unencrypted map gives it.
func TestReadsAHandlerARebuildRemovesDropsWhatItDecoded(t *testing.T) {
	const permissions = -1
	o, _, u := readsRC4Key("one", permissions)
	for _, c := range []struct {
		name   string
		broken int
	}{
		{"the catalog", 1},
		{"the page tree's root", 2},
		{"the page", 3},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsRawTrailer([]readsObject{
				{1, "<< /Type /Catalog /Pages 2 0 R >>"},
				{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
				{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
				{6, readsStreamObject("", shown("A", 700))},
				{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /ToUnicode 8 0 R >>"},
				{8, readsStreamObject("", "begincmap\n1 begincodespacerange\n<00> <FF>\nendcodespacerange\n1 beginbfchar\n<41> <005A>\nendbfchar\nendcmap\n")},
				{9, fmt.Sprintf("<< /Filter /Standard /V 1 /R 2 /P %d /O <%x> /U <%x> >>", permissions, o, u)},
				{9, "null"},
			}, c.broken, nil, fmt.Sprintf("/Encrypt 9 0 R /ID [<%x> <%x>]", readsFileID, readsFileID))
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if got := r.Pages[0].Text; got != "Z" {
				t.Errorf("the record reads %s %q; the rebuilt trailer names no encryption, and nothing read through the handler the old one named is kept", r.Pages[0].Status, got)
			}
			if r.Encryption != nil && r.Encryption.Opened {
				t.Errorf("encryption %+v; the document the record carries is not encrypted", r.Encryption)
			}
		})
	}
}

// Extraction ends the moment the cross-reference is rebuilt: the pages listed
// after that one are of a document this one no longer is, and reading them
// would spend on them what the reading that follows needs. The allowance
// below is exactly the two readings of the first page.
func TestReadsARebuiltCrossReferenceEndsTheExtraction(t *testing.T) {
	content := shown("Z", 700)
	data := readsRawFile([]readsObject{
		{1, "<< /Type /Catalog /Pages 2 0 R >>"},
		{2, "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>"},
		{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
		{4, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 10 0 R >>"},
		{6, readsStreamObject("/Filter /FlateDecode", string(flateOf([]byte(content))))},
		{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"},
		{10, readsStreamObject("/Filter /FlateDecode", string(flateOf([]byte(shown("OTHER", 700)))))},
		{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
	}, 6, nil)
	// The page's content is inflated twice: once under the cross-reference
	// the file holds -- reading it is what rebuilds -- and once under the
	// rebuilt one. An allowance of exactly that leaves nothing for a page of
	// the document the rebuild replaced.
	opt := testOptions()
	opt.MaxInflateTotal = int64(2 * len(content))
	opt.MaxInflateOne = opt.MaxInflateTotal
	r := Extract(context.Background(), data, opt)
	if r.Fatal != nil {
		t.Fatalf("fatal %+v", r.Fatal)
	}
	if len(r.Pages) != 1 || r.Pages[0].Text != "Z" || len(r.Problems) != 0 {
		t.Errorf("the record reads %+v with problems %+v, want one page reading %q", r.Pages, r.Problems, "Z")
	}
}

// An /Encoding a Type0 font gives that is not Identity and is not a CMap the
// reader can use says nothing about how the font's bytes split into codes:
// the glyphs are counted and unmapped at the font's default width, and the
// ToUnicode map is not a second reading of codes the encoding never gave.
func TestReadsEveryUnusableEncodingIsNotIdentity(t *testing.T) {
	for _, c := range []struct{ name, encoding string }{
		{"a reference to an object the file does not hold", "88 0 R"},
		{"null", "null"},
		{"a number", "42"},
		{"an empty dictionary", "<< >>"},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := &pdfgen.Builder{}
			tu := b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(
				"begincmap\n1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n1 beginbfchar\n<0041> <005A>\nendbfchar\nendcmap\n")})
			cid := b.Add(pdfgen.Object{Body: "<< /Type /Font /Subtype /CIDFontType0 /BaseFont /Test /DW 700 /W [65 [123]] >>"})
			num := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Font /Subtype /Type0 /BaseFont /Test /Encoding %s /DescendantFonts [%d 0 R] /ToUnicode %d 0 R >>", c.encoding, cid, tu)})
			b.Catalog(b.Pages([]pdfgen.Page{{Content: "BT /F1 12 Tf 1 0 0 1 72 700 Tm <0041> Tj ET\n", Fonts: map[string]int{"F1": num}}}))
			data := b.Bytes()
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if r.Pages[0].Text != "�" || r.Pages[0].Unmapped != 1 {
				t.Errorf("the record reads %q with %d glyphs unmapped; this font's encoding is none the reader can use", r.Pages[0].Text, r.Pages[0].Unmapped)
			}
			if g := firstGlyph(loadFontNumbered(openGenerated(t, data), num), []byte{0, 65}); !g.unmapped || g.width != 0.7 {
				t.Errorf("the code is %q, unmapped %v, %g em wide; no CID stands behind it and its width is the default width", string(g.runes), g.unmapped, g.width)
			}
		})
	}
}

// A number an object stream's header declares is declared by its place
// whatever stands beside it: a pair whose offset the header does not hold, or
// holds as a token the reader cannot read, is a place that holds no object,
// and the number is declared there all the same. A number declared at two
// places is found by neither alone, so the place the cross-reference names
// decides -- and an unreadable place holds nothing.
func TestReadsAnObjectStreamNumberIsDeclaredBeforeItsOffsetIsRead(t *testing.T) {
	page := func(contents int) string {
		return fmt.Sprintf("<< /Type /Page /Parent 2 0 R /Contents %d 0 R /Resources << /Font << /F1 7 0 R >> >> >>", contents)
	}
	first := page(6)
	for _, c := range []struct{ name, header string }{
		{"a pair whose offset the header does not hold", "3 0 3 "},
		{"a pair whose offset is a number longer than one", "3 0 3 " + strings.Repeat("9", maxNameBytes+8)},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsRawFile([]readsObject{
				{1, "<< /Type /Catalog /Pages 2 0 R >>"},
				{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
				{5, readsStreamObject(fmt.Sprintf("/Type /ObjStm /N 2 /First %d", len(c.header)), c.header+first)},
				{6, readsStreamObject("", shown("FIRST", 700))},
				{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"},
			}, 0, map[int][2]int{3: {5, 1}})
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			got := ""
			if len(r.Pages) == 1 {
				got = r.Pages[0].Text
			}
			if got != "" || r.Fatal == nil || r.Fatal.Code != "pdf-malformed" {
				t.Errorf("the record reads %q with fatal %+v; the number is declared at two places and the place named holds no object", got, r.Fatal)
			}
		})
	}
}

// What reading the file has cost is not given back by a rebuild: the objects
// counted and the mappings a font charged stand, since a file that made the
// reader read it twice has spent them twice.
func TestReadsTheObjectsAndMappingsCountedAreNotGivenBack(t *testing.T) {
	data := readsRawFile([]readsObject{
		{1, "<< /Type /Catalog /Pages 2 0 R >>"},
		{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
		{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
		{6, readsStreamObject("", shown("A", 700))},
		{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /ToUnicode 8 0 R >>"},
		{8, readsStreamObject("", "begincmap\n1 begincodespacerange\n<00> <FF>\nendcodespacerange\n1 beginbfchar\n<41> <005A>\nendbfchar\nendcmap\n")},
		{10, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Subtype 11 0 R >>"},
		{11, "/Type1"},
	}, 11, nil)
	d := openGenerated(t, data)
	loadFontNumbered(d, 7)
	objects, mappings, generation := d.parsed, d.fontBudget.used, d.generation
	if objects == 0 || mappings == 0 {
		t.Fatalf("the first font read %d objects and charged %d mappings", objects, mappings)
	}
	loadFontNumbered(d, 10)
	if d.generation == generation {
		t.Fatal("reading the second font did not rebuild the cross-reference")
	}
	if d.parsed <= objects || d.fontBudget.used < mappings {
		t.Errorf("the rebuilt document counts %d objects and %d mappings, where %d and %d were read before it: what the file has cost is not given back",
			d.parsed, d.fontBudget.used, objects, mappings)
	}
}
