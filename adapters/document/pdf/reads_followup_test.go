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
	"io"
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
// readsCIDFont is readsEncodedFont whose descendant gives the one CID named
// the width given, in thousandths, and every other CID the default 700.
func readsCIDFont(encoding, toUnicode, show string, cid, width int) ([]byte, int) {
	b := &pdfgen.Builder{}
	extra := ""
	if toUnicode != "" {
		extra = fmt.Sprintf("/ToUnicode %d 0 R", b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(toUnicode)}))
	}
	enc := b.Add(pdfgen.Object{
		Body:   "<< /Type /CMap /CMapName /Test-H /CIDSystemInfo << /Registry (Adobe) /Ordering (Japan1) /Supplement 2 >> >>",
		Stream: []byte(encoding)})
	desc := b.Add(pdfgen.Object{Body: fmt.Sprintf(
		"<< /Type /Font /Subtype /CIDFontType0 /BaseFont /Test /CIDSystemInfo << /Registry (Adobe) /Ordering (Japan1) /Supplement 2 >> /DW 700 /W [%d [%d]] >>", cid, width)})
	f := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Font /Subtype /Type0 /BaseFont /Test /Encoding %d 0 R /DescendantFonts [%d 0 R] %s >>", enc, desc, extra)})
	b.Catalog(b.Pages([]pdfgen.Page{{Content: "BT /F1 12 Tf 1 0 0 1 72 700 Tm <" + show + "> Tj ET\n", Fonts: map[string]int{"F1": f}}}))
	return b.Bytes(), f
}

// A CMap that declares no codespace range of its own says how long its codes
// are by the sources it maps -- every one of them, the single codes of a
// cidchar or a bfchar section as much as the ends of a range. A map whose
// sources are one byte long is read a byte at a time and one whose sources
// are three bytes long three at a time, as a map of two-byte sources is read
// two at a time: the code the page shows is the code the map holds.
func TestReadsCodespacesAreInferredFromEverySourceLength(t *testing.T) {
	for _, c := range []struct {
		name, source, unicode, show string
	}{
		{"a source of one byte", "<41>", "<00> <FF>", "4141"},
		{"a source of two bytes", "<0041>", "<0000> <FFFF>", "00410041"},
		{"a source of three bytes", "<000041>", "<000000> <FFFFFF>", "000041000041"},
	} {
		t.Run(c.name, func(t *testing.T) {
			encoding := "begincmap\n1 begincidchar\n" + c.source + " 5\nendcidchar\nendcmap\n"
			unicode := "begincmap\n1 begincodespacerange\n" + c.unicode +
				"\nendcodespacerange\n1 beginbfchar\n" + c.source + " <005A>\nendbfchar\nendcmap\n"
			data, num := readsCIDFont(encoding, unicode, c.show, 5, 123)
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if r.Pages[0].Text != "ZZ" || r.Pages[0].Unmapped != 0 || r.Pages[0].Status != PageOK || len(r.Problems) != 0 {
				t.Errorf("the record reads %s %q with %d glyphs unmapped and problems %+v; the map's sources are %s, so the page shows two of them",
					r.Pages[0].Status, r.Pages[0].Text, r.Pages[0].Unmapped, r.Problems, c.source)
			}
			// The code is read at the length the map's sources have, and the
			// glyph takes the width its CID declares and not the default.
			bytes := readsBytesOf(t, c.source)
			if g := firstGlyph(loadFontNumbered(openGenerated(t, data), num), bytes); g.unmapped || string(g.runes) != "Z" || g.width != 0.123 {
				t.Errorf("the code is %q, unmapped %v, %g em wide; it is CID 5, which the font gives 123 thousandths",
					string(g.runes), g.unmapped, g.width)
			}
		})
	}
}

// readsBytesOf is the bytes a hexadecimal string written as a PDF string
// holds, for a fixture that shows the same code it declares.
func readsBytesOf(t *testing.T, hex string) []byte {
	t.Helper()
	var out []byte
	digits := strings.Trim(hex, "<>")
	for i := 0; i+1 < len(digits); i += 2 {
		var v int
		if _, err := fmt.Sscanf(digits[i:i+2], "%02x", &v); err != nil {
			t.Fatal(err)
		}
		out = append(out, byte(v))
	}
	return out
}

// A CMap read no further than a bound is not used at all, wherever the bound
// was met: a section of it holding an object nested past what the parser
// admits ends the parse there, and what the section read before it is no
// reading of the map. The glyphs it would have mapped are unmapped and
// counted, and take the font's default width, as they are for every other
// encoding this reader could not establish.
func TestReadsACMapStoppedAtABoundIsNotUsed(t *testing.T) {
	for _, c := range []struct{ name, encoding string }{
		{"a bound inside a cidchar section",
			"begincmap\n2 begincidchar\n<0041> 5\n" + readsOverNested() + " 6\nendcidchar\nendcmap\n"},
		{"a bound inside a cidrange section",
			"begincmap\n2 begincidrange\n<0041> <0041> 5\n" + readsOverNested() + " <0042> 6\nendcidrange\nendcmap\n"},
		{"a bound inside a codespace section",
			"begincmap\n2 begincodespacerange\n<0000> <FFFF>\n" + readsOverNested() + " <FFFF>\nendcodespacerange\n1 begincidchar\n<0041> 5\nendcidchar\nendcmap\n"},
		{"a bound at the outer parse",
			"begincmap\n1 begincidchar\n<0041> 5\nendcidchar\n" + readsOverNested() + "\nendcmap\n"},
		// The bound in an operand after the first, each after a section the
		// map could use: the section before it is no more the map's for
		// standing before the bound, so the code it maps is unmapped too.
		{"a bound in a codespace range's high code",
			"begincmap\n1 begincidchar\n<0041> 5\nendcidchar\n1 begincodespacerange\n<0000> " + readsOverNested() + "\nendcodespacerange\nendcmap\n"},
		{"a bound in a range's high code",
			"begincmap\n1 begincidchar\n<0041> 5\nendcidchar\n1 begincidrange\n<0042> " + readsOverNested() + " 6\nendcidrange\nendcmap\n"},
		{"a bound in a range's destination",
			"begincmap\n1 begincidchar\n<0041> 5\nendcidchar\n1 begincidrange\n<0042> <0043> " + readsOverNested() + "\nendcidrange\nendcmap\n"},
		{"a bound in a single mapping's destination",
			"begincmap\n1 begincidchar\n<0041> 5\n<0042> " + readsOverNested() + "\nendcidchar\nendcmap\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			unicode := "begincmap\n1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n1 beginbfchar\n<0041> <005A>\nendbfchar\nendcmap\n"
			data, num := readsCIDFont(c.encoding, unicode, "00410041", 5, 123)
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if r.Pages[0].Text != "��" || r.Pages[0].Unmapped != 2 || r.Pages[0].Status != PageOK || len(r.Problems) != 0 {
				t.Errorf("the record reads %s %q with %d glyphs unmapped and problems %+v; the encoding was read no further than a bound, so it is none the reader can use",
					r.Pages[0].Status, r.Pages[0].Text, r.Pages[0].Unmapped, r.Problems)
			}
			if g := firstGlyph(loadFontNumbered(openGenerated(t, data), num), []byte{0, 0x41}); !g.unmapped || g.width != 0.7 {
				t.Errorf("the code is %q, unmapped %v, %g em wide; no CID stands behind it and its width is the default width",
					string(g.runes), g.unmapped, g.width)
			}
		})
	}
}

// What a CMap establishes is what it holds that a code can be looked up in,
// and not what the parser was given to read: a destination that is no text --
// an unpaired surrogate, an empty string, a string of an odd number of bytes
// -- maps its code to nothing, and a map holding nothing else establishes no
// encoding. The budget is charged for the entry all the same: the reader read
// it.
func TestReadsADestinationThatMapsNothingEstablishesNoEncoding(t *testing.T) {
	for _, c := range []struct{ name, section string }{
		{"an unpaired surrogate", "1 beginbfchar\n<0041> <D800>\nendbfchar"},
		{"an empty destination", "1 beginbfchar\n<0041> <>\nendbfchar"},
		{"an odd number of bytes", "1 beginbfchar\n<0041> <414243>\nendbfchar"},
		// One byte is half a code unit, and half a code unit is no
		// character: a destination of an odd number of bytes maps nothing
		// whether the odd byte stands alone or after whole ones (9.10.3).
		{"a destination of one byte", "1 beginbfchar\n<0041> <41>\nendbfchar"},
		// A range of codes whose destinations are none of them a character:
		// the one code it holds stands at a surrogate half, or past the last
		// scalar value Unicode has, in each of the three forms a destination
		// takes.
		{"a range at a surrogate", "1 beginbfrange\n<0041> <0041> 55296\nendbfrange"},
		{"a range past the last scalar value", "1 beginbfrange\n<0041> <0041> 1114112\nendbfrange"},
		{"a range whose destination string is no text", "1 beginbfrange\n<0041> <0041> <D800>\nendbfrange"},
		{"a range whose destination array holds no text", "1 beginbfrange\n<0041> <0041> [<D800>]\nendbfrange"},
	} {
		t.Run(c.name, func(t *testing.T) {
			encoding := "begincmap\n" + c.section + "\nendcmap\n"
			unicode := "begincmap\n1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n1 beginbfchar\n<0041> <005A>\nendbfchar\nendcmap\n"
			data, num := readsCIDFont(encoding, unicode, "00410041", 5, 123)
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if r.Pages[0].Text != "��" || r.Pages[0].Unmapped != 2 || r.Pages[0].Status != PageOK || len(r.Problems) != 0 {
				t.Errorf("the record reads %s %q with %d glyphs unmapped and problems %+v; the one entry of this encoding maps nothing, so the encoding establishes nothing",
					r.Pages[0].Status, r.Pages[0].Text, r.Pages[0].Unmapped, r.Problems)
			}
			if g := firstGlyph(loadFontNumbered(openGenerated(t, data), num), []byte{0, 0x41}); !g.unmapped || g.width != 0.7 {
				t.Errorf("the code is %q, unmapped %v, %g em wide; no CID stands behind it and its width is the default width",
					string(g.runes), g.unmapped, g.width)
			}
		})
	}
}

// The ranges a CMap that declares none of its own is read at are drawn about
// the codes it maps and no wider. A range holds a byte at a time, so a run
// that carries from one leading byte to the next is two ranges -- <00FF> to
// <0100> is not the one range whose first byte runs from 00 to 01 and whose
// second runs from FF to 00, which holds neither of those codes -- and a
// length takes in no leading byte another length's codes begin with, so that
// codes of two lengths told apart by their leading bytes stand beside one
// another. Where the leading bytes really are shared, the map says two things
// about how long a code is and is not used at all.
func TestReadsInferredCodespacesHoldTheCodesTheMapMaps(t *testing.T) {
	for _, c := range []struct {
		name, sources, unicode, show, want string
		unmapped                           int
	}{
		{
			"a run of codes that carries from one leading byte to the next",
			"1 begincidrange\n<00FF> <0100> 5\nendcidrange\n1 begincidchar\n<41> 7\nendcidchar\n",
			"3 beginbfchar\n<00FF> <0058>\n<0100> <0059>\n<41> <005A>\nendbfchar\n",
			"00FF010041", "XYZ", 0,
		},
		{
			"codes of two lengths whose leading bytes are their own",
			"3 begincidchar\n<40> 5\n<42> 6\n<4100> 7\nendcidchar\n",
			"3 beginbfchar\n<40> <0058>\n<42> <0059>\n<4100> <005A>\nendbfchar\n",
			"40424100", "XYZ", 0,
		},
		{
			"codes of two lengths that share a leading byte",
			"2 begincidchar\n<41> 5\n<4100> 7\nendcidchar\n",
			"2 beginbfchar\n<41> <0058>\n<4100> <005A>\nendbfchar\n",
			"41004100", "\uFFFD\uFFFD", 2,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			encoding := "begincmap\n" + c.sources + "endcmap\n"
			unicode := "begincmap\n1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n" + c.unicode + "endcmap\n"
			data, _ := readsCIDFont(encoding, unicode, c.show, 5, 123)
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if r.Pages[0].Text != c.want || r.Pages[0].Unmapped != c.unmapped || r.Pages[0].Status != PageOK || len(r.Problems) != 0 {
				t.Errorf("the record reads %s %q with %d glyphs unmapped and problems %+v, want %q with %d unmapped",
					r.Pages[0].Status, r.Pages[0].Text, r.Pages[0].Unmapped, r.Problems, c.want, c.unmapped)
			}
		})
	}
}

// What a CMap cost the font budget is charged whatever came of it: a
// destination the reader cannot use is charged as a usable one is, in each of
// the three forms a destination takes, and a map put down at a bound or at
// two readings of how long a code is keeps what it charged. The budget below
// has one entry left, so a map that charged for its unusable destination has
// nothing left for the mapping after it and is not used at all.
func TestReadsAnUnusableCMapIsChargedForAllTheSame(t *testing.T) {
	for _, c := range []struct{ name, section string }{
		{"a single mapping whose destination is no text", "1 beginbfchar\n<0041> <D800>\nendbfchar"},
		{"a range whose destination is no text", "1 beginbfrange\n<0041> <0041> <D800>\nendbfrange"},
		{"a range whose destination array holds no text", "1 beginbfrange\n<0041> <0041> [<D800>]\nendbfrange"},
	} {
		t.Run(c.name, func(t *testing.T) {
			budget := &fontBudget{used: maxFontEntries - 1}
			data := "begincmap\n" + c.section + "\n1 begincidchar\n<0042> 5\nendcidchar\nendcmap\n"
			if m := parseCMap([]byte(data), budget); m != nil {
				t.Error("the CMap was used; the one entry left went on a destination that maps nothing, so the mapping after it takes the map past the budget")
			}
			if budget.used != maxFontEntries {
				t.Errorf("the budget holds %d entries of %d; what the reader read is charged whether it could use it or not", budget.used, maxFontEntries)
			}
		})
	}
	for _, c := range []struct{ name, tail string }{
		{"a map put down at a bound", readsOverNested() + "\nendcmap\n"},
		{"a map that says two things about how long a code is", "1 begincidchar\n<4100> 6\nendcidchar\nendcmap\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			budget := &fontBudget{}
			data := "begincmap\n1 begincidchar\n<41> 5\nendcidchar\n" + c.tail
			if m := parseCMap([]byte(data), budget); m != nil {
				t.Error("the CMap was used; it is one the reader puts down")
			}
			if budget.used == 0 {
				t.Error("the budget holds nothing; what a map cost to read is charged even where the map is not used")
			}
		})
	}
}

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

// The framing of a JPEG walks the markers of the marker set and no other
// bytes: outside entropy-coded data FF 00 is the stuffing of a sample byte
// and no marker, and two bytes of what follows it are no segment length. A
// walk that read them as one would carry over the end-of-image the image
// really has, over the EI after it and over the operators the page shows,
// to whatever end-of-image lay beyond -- and the record would carry a page
// with its text taken out.
func TestReadsAJPEGFramingWalksMarkersOnly(t *testing.T) {
	// The bytes the image carries: a start-of-image, FF 00, and two bytes a
	// walk would read as the length of a segment reaching past the image's
	// own end-of-image, past the EI that ends it and past the text between
	// them, to a second end-of-image with an EI of its own.
	body := append(bytes.Repeat([]byte{0x41}, 8), 0xFF, 0xD9)
	between := []byte("\nEI\n" + shown("VISIBLE", 650))
	length := 2 + len(body) + len(between)
	var image bytes.Buffer
	image.Write([]byte{0xFF, 0xD8, 0xFF, 0x00, byte(length >> 8), byte(length)})
	image.Write(body)
	image.Write(between)
	image.Write([]byte{0xFF, 0xD9})
	var content bytes.Buffer
	content.WriteString("BI /W 1 /H 1 /BPC 8 /CS /G /F /DCT ID ")
	content.Write(image.Bytes())
	content.WriteString("\nEI\n")
	content.WriteString(shown("AFTER", 700))
	data := readsContentPage(content.Bytes())
	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if r.Pages[0].Text != "" || r.Pages[0].Status != PageFailed || len(r.Problems) != 1 {
		t.Errorf("the record reads %s %q with problems %+v; FF 00 is no marker, so this image's encoding establishes no end and the page is not read",
			r.Pages[0].Status, r.Pages[0].Text, r.Problems)
	}
	if len(r.Problems) == 1 && r.Problems[0].Code != "pdf-page-failed" {
		t.Errorf("problems %+v", r.Problems)
	}
}

// readsSpanningJPEG is an image whose marker stands where a segment's marker
// would, with two bytes after it that a walk reading them as a length would
// take for one: the length spans a JPEG body, the end-of-image that ends it,
// the EI after that and a line of text, to a second end-of-image. A reader
// that read those two bytes as a length would end the image at the second
// one and put only what follows it on the page, dropping the line between.
// Where afterSegment is set the marker stands after a comment segment of no
// payload rather than immediately after the start-of-image.
func readsSpanningJPEG(marker byte, afterSegment bool) []byte {
	body := append(bytes.Repeat([]byte{0x41}, 8), 0xFF, 0xD9)
	between := []byte("\nEI\n" + shown("VISIBLE", 650))
	length := 2 + len(body) + len(between)
	var image bytes.Buffer
	image.Write([]byte{0xFF, 0xD8})
	if afterSegment {
		image.Write([]byte{0xFF, 0xFE, 0x00, 0x02})
	}
	image.Write([]byte{0xFF, marker, byte(length >> 8), byte(length)})
	image.Write(body)
	image.Write(between)
	image.Write([]byte{0xFF, 0xD9})
	return image.Bytes()
}

// readsJPEGPage is a page of one DCTDecode inline image carrying the bytes
// given, with AFTER shown after it.
func readsJPEGPage(samples []byte) []byte {
	var content bytes.Buffer
	content.WriteString("BI /W 1 /H 1 /BPC 8 /CS /G /F /DCT ID ")
	content.Write(samples)
	content.WriteString("\nEI\n")
	content.WriteString(shown("AFTER", 700))
	return readsContentPage(content.Bytes())
}

// readsJPEGFailsThePage asserts that the image given establishes no end, so
// that the page is failed and empty and the record says why.
func readsJPEGFailsThePage(t *testing.T, samples []byte, why string) {
	t.Helper()
	data := readsJPEGPage(samples)
	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		// The other reader recovers AFTER and the line between; what it
		// reads is logged beside this reader's answer and is not asserted.
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if r.Pages[0].Text != "" || r.Pages[0].Status != PageFailed || len(r.Problems) != 1 {
		t.Errorf("the record reads %s %q with problems %+v, want %s %q: %s",
			r.Pages[0].Status, r.Pages[0].Text, r.Problems, PageFailed, "", why)
	}
	if len(r.Problems) == 1 && r.Problems[0].Code != "pdf-page-failed" {
		t.Errorf("problems %+v", r.Problems)
	}
}

// The codes JPG and JPGn -- C8, and F0 to FD -- are reserved for extensions
// of the format (T.81 Table B.1), and what an extension's segments hold is
// not something this reader establishes. Two bytes after such a code are no
// segment length, and a walk that took them for one would carry the image's
// end over the end-of-image it really has, over the EI after it and over the
// text between, to whatever end-of-image lay beyond. The page fails instead.
func TestReadsAJPEGExtensionCodeFramesNothing(t *testing.T) {
	codes := []byte{0xC8}
	for marker := byte(0xF0); marker <= 0xFD; marker++ {
		codes = append(codes, marker)
	}
	for _, marker := range codes {
		t.Run(fmt.Sprintf("the code %02X", marker), func(t *testing.T) {
			readsJPEGFailsThePage(t, readsSpanningJPEG(marker, false),
				"a code reserved for an extension frames nothing, so the image's end is not established")
		})
	}
}

// The two other codes that begin no segment, each where a segment's marker
// may stand: a second start-of-image, which carries no length of its own, and
// a reserved code below C0 that is neither the temporary marker nor a
// restart. Both are refused immediately after the start-of-image and after a
// segment the walk read, since what precedes them says nothing about them.
func TestReadsJPEGMarkersThatBeginNoSegment(t *testing.T) {
	for _, c := range []struct {
		name   string
		marker byte
	}{
		{"a second start-of-image", 0xD8},
		{"a reserved code below C0", 0x02},
	} {
		for _, where := range []struct {
			name  string
			after bool
		}{
			{"immediately after the start-of-image", false},
			{"after a segment the walk read", true},
		} {
			t.Run(c.name+", "+where.name, func(t *testing.T) {
				readsJPEGFailsThePage(t, readsSpanningJPEG(c.marker, where.after),
					"the code begins no segment, so the two bytes after it are no length")
			})
		}
	}
}

// readsScanThenSegmentJPEG is a JPEG whose scan is followed by a segment of
// its own: a Huffman table whose payload holds an end-of-image, an EI and a
// line of text. The scan's data ends at a marker that is neither a stuffed
// sample byte nor a restart, and the segment's length steps over everything
// it carries, so the image ends at the end-of-image after it.
func readsScanThenSegmentJPEG() []byte {
	hidden := append([]byte{0xFF, 0xD9}, []byte("\nEI\n"+shown("HIDDEN", 650))...)
	var out bytes.Buffer
	out.Write([]byte{0xFF, 0xD8})
	out.Write([]byte{0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00})
	out.WriteByte(0x2B)
	out.Write([]byte{0xFF, 0xC4, byte((len(hidden) + 2) >> 8), byte(len(hidden) + 2)})
	out.Write(hidden)
	return append(out.Bytes(), 0xFF, 0xD9)
}

// Entropy-coded data resumes at a restart marker and at the stuffing of a
// sample byte, and at nothing else: a marker of any other kind ends the scan,
// and the walk reads it as a marker again. A reader whose restarts began
// below D0 would carry the scan over a segment's marker and end the image at
// the end-of-image that segment's payload holds -- putting the text inside it
// on the page.
func TestReadsAJPEGScanEndsAtASegmentOfItsOwn(t *testing.T) {
	data := readsJPEGPage(readsScanThenSegmentJPEG())
	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		// The other reader decodes what this one only walks, and recovers
		// the text the synthetic table carries; it is logged, not asserted.
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if r.Pages[0].Text != "AFTER" || r.Pages[0].Status != PageOK || len(r.Problems) != 0 {
		t.Errorf("the record reads %s %q with problems %+v, want %s %q: what the table's payload holds is the image's",
			r.Pages[0].Status, r.Pages[0].Text, r.Problems, PageOK, "AFTER")
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
			status, problems := PageOK, 0
			if c.want == "" {
				status, problems = PageFailed, 1
			}
			if r.Pages[0].Text != c.want || r.Pages[0].Status != status || len(r.Problems) != problems {
				t.Errorf("%d bytes of samples: the record reads %s %q with problems %+v, want %s %q",
					c.bytes, r.Pages[0].Status, r.Pages[0].Text, r.Problems, status, c.want)
			}
			// An image past the bound is a page past a structure bound, and the
			// record says which bound the page met.
			const bound = "the content of page 1 is past a structure bound the reader holds"
			if c.want == "" && len(r.Problems) == 1 && (r.Problems[0].Code != "pdf-page-failed" || r.Problems[0].Message != bound) {
				t.Errorf("problems %+v, want %q", r.Problems, bound)
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
		// The two bounds of the alphabet, each in a full group the word
		// holds: what fails the page there is the byte and nothing else
		// about the group it stands in.
		{"a byte below the alphabet completing a group", "!!!!\x01~>", ""},
		{"a byte above the alphabet completing a group", "!!!!v~>", ""},
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

// A run of fill bytes is walked once. The framing reads the clock as the
// bytes go, so a walk that stepped back over a run it had already walked
// would read the clock again for every byte of it, and often enough would
// find a deadline a walk going forward never reaches. What is asserted here
// is how far the walk went and not how long it took: the context below
// counts the readings rather than the time, and a JPEG of 8,192 fill bytes
// before its first restart is framed whole within them.
func TestReadsAJPEGFillRunIsWalkedOnce(t *testing.T) {
	samples := readsRestartJPEG(t, []byte(" EI\n"), 2*entriesPerCheck)
	if _, err := jpeg.Decode(bytes.NewReader(samples)); err != nil {
		t.Fatalf("the fixture is not a JPEG a decoder reads: %v", err)
	}
	d := budgeted(1<<20, 1<<20)
	// A deadline that passes at the fifth reading of the clock: the walk
	// reads it twice for the fill run and once more for the markers around
	// it, and a walk that went over the run again would read it far more.
	d.ctx = newCountdown(4)
	if n, err := d.jpegFraming(samples); n != len(samples) || err != nil {
		t.Errorf("framing gave %d, %v, want %d and no error: the fill run is walked once, within the readings the deadline allows",
			n, err, len(samples))
	}
}

// readsICCProfile is an ICC profile of the number of components given: the
// 128-byte header of ICC.1 clause 7.2, a tag table, and the tags a colour
// management system reads a profile through -- a white point and a tone curve
// for each channel of a one- or three-component profile, and an eight-bit
// lookup table for a four-component one. What colours it describes is of no
// interest here; that it is a profile a second reader opens without
// complaint is. It is built rather than taken from the machine, so that what
// a fixture holds is the fixture's own.
func readsICCProfile(components int) []byte {
	be32 := func(v uint32) []byte { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }
	fixed := func(v float64) []byte { return be32(uint32(int32(v*65536 + 0.5))) }
	xyz := func(x, y, z float64) []byte {
		out := append([]byte("XYZ "), 0, 0, 0, 0)
		out = append(out, fixed(x)...)
		out = append(out, fixed(y)...)
		return append(out, fixed(z)...)
	}
	// D50, the profile connection space's illuminant (ICC.1 Table 15).
	white := xyz(0.9642, 1.0, 0.8249)
	// A curve of no points is the identity (ICC.1 10.6).
	curve := append([]byte("curv"), 0, 0, 0, 0, 0, 0, 0, 0)
	type tag struct {
		sig  string
		data []byte
	}
	class, space, pcs := "mntr", "GRAY", "XYZ "
	tags := []tag{{"wtpt", white}, {"kTRC", curve}}
	switch components {
	case 3:
		space = "RGB "
		tags = []tag{
			{"wtpt", white},
			{"rXYZ", xyz(0.4360, 0.2225, 0.0139)},
			{"gXYZ", xyz(0.3851, 0.7169, 0.0971)},
			{"bXYZ", xyz(0.1431, 0.0606, 0.7141)},
			{"rTRC", curve}, {"gTRC", curve}, {"bTRC", curve},
		}
	case 4:
		class, space, pcs = "prtr", "CMYK", "Lab "
		// An eight-bit lookup table (ICC.1 10.9) for each direction: the
		// grid is two points a side, the tables either side of it are the
		// identity, and so is the matrix a table whose connection space is
		// not XYZ carries. A profile of this class is read in both
		// directions -- the black point a colour manager looks for is found
		// through the one from the connection space -- so both are written.
		lookup := func(in, out int) []byte {
			lut := append([]byte("mft1"), 0, 0, 0, 0)
			lut = append(lut, byte(in), byte(out), 2, 0)
			for _, v := range []float64{1, 0, 0, 0, 1, 0, 0, 0, 1} {
				lut = append(lut, fixed(v)...)
			}
			for i := 0; i < in*256; i++ {
				lut = append(lut, byte(i%256))
			}
			for grid := 0; grid < 1<<in; grid++ {
				for channel := 0; channel < out; channel++ {
					lut = append(lut, 128)
				}
			}
			for i := 0; i < out*256; i++ {
				lut = append(lut, byte(i%256))
			}
			return lut
		}
		tags = []tag{{"wtpt", white}, {"A2B0", lookup(4, 3)}, {"B2A0", lookup(3, 4)}}
	}
	var table, body []byte
	table = append(table, be32(uint32(len(tags)))...)
	offset := 128 + 4 + 12*len(tags)
	for _, tg := range tags {
		table = append(table, tg.sig...)
		table = append(table, be32(uint32(offset+len(body)))...)
		table = append(table, be32(uint32(len(tg.data)))...)
		body = append(body, tg.data...)
		for len(body)%4 != 0 {
			body = append(body, 0)
		}
	}
	header := make([]byte, 128)
	copy(header[0:], be32(uint32(128+len(table)+len(body))))
	copy(header[8:], be32(0x02100000))
	copy(header[12:], class)
	copy(header[16:], space)
	copy(header[20:], pcs)
	copy(header[36:], "acsp")
	copy(header[68:], white[8:])
	return append(append(header, table...), body...)
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
				profile := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /N %d >>", c.components), Stream: readsICCProfile(c.components)})
				return fmt.Sprintf("/ColorSpace << /ICC [/ICCBased %d 0 R] >>", profile)
			}, false)
			r := extract(t, data)
			out, diagnostics, ok := readsPopplerRead(t, data)
			if ok {
				t.Logf("pdftotext reads %q", out)
				for _, complaint := range []string{"ICC", "profile", "image parameters"} {
					if strings.Contains(diagnostics, complaint) {
						t.Errorf("pdftotext wrote %q as diagnostics; the profile of %d components is one it reads", diagnostics, c.components)
						break
					}
				}
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			status, problems := PageOK, 0
			if c.want == "" {
				status, problems = PageFailed, 1
			}
			if r.Pages[0].Text != c.want || r.Pages[0].Status != status || len(r.Problems) != problems {
				t.Errorf("a profile of %d components and %d bytes of samples: the record reads %s %q with problems %+v, want %s %q",
					c.components, c.samples, r.Pages[0].Status, r.Pages[0].Text, r.Problems, status, c.want)
			}
			if c.want == "" && len(r.Problems) == 1 && r.Problems[0].Code != "pdf-page-failed" {
				t.Errorf("problems %+v", r.Problems)
			}
		})
	}
}

// What an ICCBased image is measured by is the /N of its stream and not the
// colour space the profile that stream carries is of. The two are written to
// agree (8.6.5.5), and where they do not it is /N the samples were packed
// under: the profile below is a four-component one, its /N says three, and
// the image carries the 333 bytes three components take.
func TestReadsAnICCBasedImageIsMeasuredByTheDeclaredComponents(t *testing.T) {
	for _, c := range []struct {
		name   string
		inForm bool
	}{{"named by the page", false}, {"named by the form that draws it", true}} {
		t.Run(c.name, func(t *testing.T) {
			var content bytes.Buffer
			// 37 samples of three eight-bit components are 111 bytes a row,
			// and 333 for the three rows; four components would be 444.
			content.WriteString("BI /W 37 /H 3 /BPC 8 /CS /ICC ID ")
			content.Write(bytes.Repeat([]byte{'A'}, 333))
			content.WriteString("\nEI\n")
			content.WriteString(shown("REAL", 700))
			data := readsResourceDocument(content.Bytes(), func(b *pdfgen.Builder) string {
				profile := b.Add(pdfgen.Object{Body: "<< /N 3 >>", Stream: readsICCProfile(4)})
				return fmt.Sprintf("/ColorSpace << /ICC [/ICCBased %d 0 R] >>", profile)
			}, c.inForm)
			r := extract(t, data)
			out, diagnostics, ok := readsPopplerRead(t, data)
			if ok {
				t.Logf("pdftotext reads %q", out)
				// The diagnostics are asserted on, and the text is not: that
				// the other reader finds nothing to complain of in the
				// profile is what says the fixture holds the profile it
				// claims to.
				for _, complaint := range []string{"ICC", "profile", "image parameters"} {
					if strings.Contains(diagnostics, complaint) {
						t.Errorf("pdftotext wrote %q as diagnostics; the profile is one it reads", diagnostics)
						break
					}
				}
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if r.Pages[0].Text != "REAL" || r.Pages[0].Status != PageOK || len(r.Problems) != 0 {
				t.Errorf("the record reads %s %q with problems %+v; the image is measured by the /N of its stream, which says three components",
					r.Pages[0].Status, r.Pages[0].Text, r.Problems)
			}
		})
	}
}

// An ICCBased colour space has one, three or four components, and the /N of
// its stream says which of the three as an integer (8.6.5.5). A stream
// declaring any other count -- a 2, a 5, a 3 written as the real 3.0, a
// fraction, no number at all -- has declared a packing no such space has, and
// how long the samples of an image in it are is not then something the file
// says. Each image below carries the bytes its declared count would imply, so
// that a reader measuring by the count as written would find the "EI" after
// them and read the page: what the record does instead is fail it.
func TestReadsAnICCBasedComponentCountIsOneThreeOrFour(t *testing.T) {
	for _, c := range []struct {
		name, declared string
		samples        int
		want           string
	}{
		{"one component", "/N 1", 57, "REAL"},
		{"three components", "/N 3", 171, "REAL"},
		{"four components", "/N 4", 228, "REAL"},
		{"two components", "/N 2", 114, ""},
		{"five components", "/N 5", 285, ""},
		{"three written as a real", "/N 3.0", 171, ""},
		{"a count of nothing", "/N 0", 171, ""},
		{"a fractional count", "/N 2.5", 171, ""},
		{"a count that is no number", "/N /Three", 171, ""},
		{"no count at all", "", 171, ""},
	} {
		for _, where := range []struct {
			name   string
			inForm bool
		}{{"named by the page", false}, {"named by the form that draws it", true}} {
			t.Run(c.name+", "+where.name, func(t *testing.T) {
				var content bytes.Buffer
				// 19 samples a row of eight bits, and three rows: 57 bytes of
				// one component, 114 of two, 171 of three, 228 of four, 285
				// of five.
				content.WriteString("BI /W 19 /H 3 /BPC 8 /CS /ICC ID ")
				content.Write(bytes.Repeat([]byte{'A'}, c.samples))
				content.WriteString("\nEI\n")
				content.WriteString(shown("REAL", 700))
				data := readsResourceDocument(content.Bytes(), func(b *pdfgen.Builder) string {
					// The profile is of three components whatever the stream
					// declares: what the image is measured by is the
					// declaration, and the counts refused here are refused
					// for being counts no ICCBased space has.
					profile := b.Add(pdfgen.Object{Body: "<< " + c.declared + " >>", Stream: readsICCProfile(3)})
					return fmt.Sprintf("/ColorSpace << /ICC [/ICCBased %d 0 R] >>", profile)
				}, where.inForm)
				r := extract(t, data)
				if out, ok := readsPoppler(t, data); ok {
					// The other reader recovers what it can from a count it
					// refuses; what it reads is logged beside this reader's
					// answer and is not the assertion.
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
					t.Errorf("a stream declaring %q and %d bytes of samples: the record reads %s %q with problems %+v, want %s %q",
						c.declared, c.samples, r.Pages[0].Status, r.Pages[0].Text, r.Problems, status, c.want)
				}
				if c.want == "" && len(r.Problems) == 1 && r.Problems[0].Code != "pdf-page-failed" {
					t.Errorf("problems %+v", r.Problems)
				}
			})
		}
	}
}

// What a count no ICCBased space has costs the record is text the page shows.
// The image below is a hundred samples of one row at eight bits: the four
// components of a CMYK space would measure the 400 bytes it opens with, and
// the 5 its stream declares would measure 500 -- those bytes, the "EI" that
// ends them, a line of text and the comment padding the rest. A reader
// measuring by that 5 reads the page without the line between, which is no
// viewer's reading of it; the other reader recovers the line and diagnoses
// the count. The record fails the page rather than carry either.
func TestReadsAnICCBasedCountNoSpaceHasDropsNoText(t *testing.T) {
	var samples bytes.Buffer
	samples.Write(bytes.Repeat([]byte{'A'}, 400))
	samples.WriteString(" EI ")
	samples.WriteString(shown("BETWEEN", 686))
	samples.WriteString("%" + strings.Repeat("x", 500-samples.Len()-1))
	var content bytes.Buffer
	content.WriteString("BI /W 100 /H 1 /BPC 8 /CS /ICC ID ")
	content.Write(samples.Bytes())
	content.WriteString("\nEI\n")
	content.WriteString(shown("VISIBLE", 650))
	data := readsResourceDocument(content.Bytes(), func(b *pdfgen.Builder) string {
		profile := b.Add(pdfgen.Object{Body: "<< /N 5 >>", Stream: readsICCProfile(3)})
		return fmt.Sprintf("/ColorSpace << /ICC [/ICCBased %d 0 R] >>", profile)
	}, false)
	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if r.Pages[0].Text != "" || r.Pages[0].Status != PageFailed || len(r.Problems) != 1 {
		t.Errorf("the record reads %s %q with problems %+v, want %s %q: five components are no ICCBased space's",
			r.Pages[0].Status, r.Pages[0].Text, r.Problems, PageFailed, "")
	}
	if len(r.Problems) == 1 && r.Problems[0].Code != "pdf-page-failed" {
		t.Errorf("problems %+v", r.Problems)
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
	// The content carries the identity crypt filter, so that it is the page's
	// operators whichever handler is in force and the font is selected either
	// way; the map that font is read through is not filtered, so what it says
	// is what the handler leaves of it.
	objects := []readsObject{
		{1, "<< /Type /Catalog /Pages 2 0 R >>"},
		{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
		{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
		{6, readsStreamObject("/Filter /Crypt /DecodeParms << /Type /CryptFilterDecodeParms /Name /Identity >>", shown("A", 700))},
		{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /ToUnicode 8 0 R >>"},
		{8, readsStreamObject("", "begincmap\n1 begincodespacerange\n<00> <FF>\nendcodespacerange\n1 beginbfchar\n<41> <005A>\nendbfchar\nendcmap\n")},
		{9, fmt.Sprintf("<< /Filter /Standard /V 1 /R 2 /P %d /O <%x> /U <%x> >>", permissions, o, u)},
		{9, "null"},
	}
	// The same objects with the page tree's root inside an object stream the
	// file holds in plain text, which the cross-reference already names: the
	// root is looked for again after the rebuild, and that retry parses the
	// object stream through whatever handler is in force. Nothing of the page
	// is interpreted before it.
	compressed := append([]readsObject{}, objects...)
	compressed[1] = readsObject{10, readsObjectStream(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")}
	for _, c := range []struct {
		name     string
		objects  []readsObject
		broken   int
		inStream map[int][2]int
	}{
		{"the catalog", objects, 1, nil},
		{"the page tree's root", objects, 2, nil},
		{"the page", objects, 3, nil},
		{"the page's content", objects, 6, nil},
		{"the catalog, with the root in an object stream", compressed, 1, map[int][2]int{2: {10, 0}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsRawTrailer(c.objects, c.broken, c.inStream, fmt.Sprintf("/Encrypt 9 0 R /ID [<%x> <%x>]", readsFileID, readsFileID))
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if r.Pages[0].Text != "Z" || r.Pages[0].Status != PageOK || len(r.Problems) != 0 {
				t.Errorf("the record reads %s %q with problems %+v; the rebuilt trailer names no encryption, and nothing read through the handler the old one named is kept",
					r.Pages[0].Status, r.Pages[0].Text, r.Problems)
			}
			if r.Encryption != nil {
				t.Errorf("encryption %+v; the trailer this document has names none, so the record declares none", r.Encryption)
			}
		})
	}
}

// readsObjectStream is an object stream holding the one object given.
// The encryption dictionary a rebuilt trailer names is read as it stands. The
// file below is opened under one handler and rebuilt under another: the scan
// finds a trailer naming a second dictionary, and the object stream holding
// the page tree's root is encrypted under the key that dictionary derives.
// The stream's /Length is an indirect reference to that dictionary, so the
// dictionary is resolved while the handler being replaced is still installed
// -- and a dictionary whose strings were deciphered with the old key is no
// reading of the dictionary the rebuilt trailer names. Were that reading kept,
// the handler would not open, the object stream would not be decoded and the
// root would go unregistered; the reader takes the dictionary as it stands
// and reads the page.
func TestReadsTheRebuiltHandlerIsOpenedFromTheDictionaryAsItStands(t *testing.T) {
	const permissions = -1
	const toUnicode = "begincmap\n1 begincodespacerange\n<00> <FF>\nendcodespacerange\n1 beginbfchar\n<41> <005A>\nendbfchar\nendcmap\n"
	oldO, _, oldU := readsRC4Key("one", permissions)
	newO, newKey, newU := readsRC4Key("two", permissions)
	header := "2 0 "
	stm := string(readsRC4Encrypt(newKey, 10, []byte(header+"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")))
	for _, c := range []struct{ name, length string }{
		{"a length naming the dictionary the rebuilt trailer names", "19 0 R"},
		{"a length written in place", fmt.Sprint(len(stm))},
	} {
		t.Run(c.name, func(t *testing.T) {
			objects := []readsObject{
				{1, "<< /Type /Catalog /Pages 2 0 R >>"},
				{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
				{6, readsStreamObject("", string(readsRC4Encrypt(newKey, 6, []byte(shown("A", 700)))))},
				{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /ToUnicode 8 0 R >>"},
				{8, readsStreamObject("", string(readsRC4Encrypt(newKey, 8, []byte(toUnicode))))},
				{9, fmt.Sprintf("<< /Filter /Standard /V 1 /R 2 /P %d /O <%x> /U <%x> >>", permissions, oldO, oldU)},
				{19, fmt.Sprintf("<< /Filter /Standard /V 1 /R 2 /P %d /O <%x> /U <%x> >>", permissions, newO, newU)},
				{10, fmt.Sprintf("<< /Type /ObjStm /N 1 /First %d /Length %s >>\nstream\n%s\nendstream", len(header), c.length, stm)},
			}
			data := readsTableFile(objects, 1, fmt.Sprintf("/Encrypt 9 0 R /ID [<%x> <%x>]", readsFileID, readsFileID))
			data = append(data, []byte(fmt.Sprintf("\ntrailer\n<< /Root 1 0 R /Encrypt 19 0 R /ID [<%x> <%x>] >>\n", readsFileID, readsFileID))...)
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				// The other reader refuses the damaged file; the record is of
				// the reading the rebuilt trailer names.
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v; the page tree's root is in the object stream the rebuilt handler decodes", r.Fatal, r.Pages)
			}
			if r.Pages[0].Text != "Z" || r.Pages[0].Status != PageOK || len(r.Problems) != 0 {
				t.Errorf("the record reads %s %q with problems %+v, want %s %q: the handler is opened from the dictionary the rebuilt trailer names",
					r.Pages[0].Status, r.Pages[0].Text, r.Problems, PageOK, "Z")
			}
			if r.Encryption == nil || r.Encryption.Revision == nil || *r.Encryption.Revision != 2 {
				t.Errorf("encryption %+v; the document is read through the handler the rebuilt trailer names", r.Encryption)
			}
		})
	}
}

// The encryption dictionary's own strings are not encrypted (7.6.1), and the
// reader takes them as they stand whichever read reaches the dictionary: the
// opening of a handler, which reads it with none installed, or an ordinary
// reference from another object's field, which may be read long after one is.
// A reader that deciphered it through the installed handler would hold a
// dictionary no handler opens, and an opening that found that reading would
// refuse a document whose password is the empty one.
func TestReadsTheEncryptionDictionaryIsReadAsItStands(t *testing.T) {
	const permissions = -1
	o, _, u := readsRC4Key("one", permissions)
	objects := []readsObject{
		{1, "<< /Type /Catalog /Pages 2 0 R >>"},
		{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
		{3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 6 0 R >>"},
		{6, readsStreamObject("", "")},
		{9, fmt.Sprintf("<< /Filter /Standard /V 1 /R 2 /P %d /O <%x> /U <%x> >>", permissions, o, u)},
	}
	data := readsTableFile(objects, 0, fmt.Sprintf("/Encrypt 9 0 R /ID [<%x> <%x>]", readsFileID, readsFileID))
	d := openGenerated(t, data)
	if _, err := d.openEncryption(); err != nil {
		t.Fatalf("the handler did not open: %v", err)
	}
	if d.crypt == nil {
		t.Fatal("no handler was installed")
	}
	// The dictionary read again, through an ordinary reference, with the
	// handler in force.
	d.dropCachedObjects()
	enc := d.dictOf(ref{9, 0})
	if enc == nil {
		t.Fatal("the encryption dictionary is not a dictionary")
	}
	if got, _ := enc["O"].(String); !bytes.Equal(got, o) {
		t.Errorf("the dictionary's /O reads %x, want %x: the encryption dictionary is read as the file holds it", got, o)
	}
}

func readsObjectStream(num int, body string) string {
	header := fmt.Sprintf("%d 0 ", num)
	data := header + body
	return fmt.Sprintf("<< /Type /ObjStm /N 1 /First %d /Length %d >>\nstream\n%s\nendstream", len(header), len(data), data)
}

// readsTableFile is a file whose cross-reference is a table naming the
// objects given and nothing else: a number no object of the file has is a
// number the cross-reference does not name at all, rather than one it names
// as free. The object numbered broken has its offset written as 3, so that
// reading it rebuilds by scanning.
func readsTableFile(objects []readsObject, broken int, trailer string) []byte {
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	offsets := map[int]int{}
	var order []int
	for _, o := range objects {
		if _, written := offsets[o.num]; !written {
			offsets[o.num] = out.Len()
			order = append(order, o.num)
		}
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", o.num, o.body)
	}
	if broken > 0 {
		offsets[broken] = 3
	}
	at := out.Len()
	sortInts(order)
	out.WriteString("xref\n0 1\n0000000000 65535 f \n")
	for _, num := range order {
		fmt.Fprintf(&out, "%d 1\n%010d 00000 n \n", num, offsets[num])
	}
	fmt.Fprintf(&out, "trailer\n<< /Size 64 /Root 1 0 R %s >>\nstartxref\n%d\n%%%%EOF\n", trailer, at)
	return out.Bytes()
}

// What the scan registers, it registers under the trailer it is rebuilding.
// An object the file holds only inside an object stream is registered by
// decoding that stream, and a stream is decoded through the handler the
// document is read under: the old trailer's key is not this document's, and a
// stream decoded with it holds no object the scan could register -- a number
// no later reading could recover, since the file is scanned once. Below, the
// page tree's root is in a plaintext object stream the cross-reference does
// not name, the trailer being replaced names a handler, and the trailer the
// scan finds names none.
func TestReadsTheScanRegistersObjectStreamsUnderTheTrailerItRebuilt(t *testing.T) {
	const permissions = -1
	o, _, u := readsRC4Key("one", permissions)
	objects := []readsObject{
		{1, "<< /Type /Catalog /Pages 2 0 R >>"},
		{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
		{6, readsStreamObject("", shown("A", 700))},
		{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /ToUnicode 8 0 R >>"},
		{8, readsStreamObject("", "begincmap\n1 begincodespacerange\n<00> <FF>\nendcodespacerange\n1 beginbfchar\n<41> <005A>\nendbfchar\nendcmap\n")},
		{9, fmt.Sprintf("<< /Filter /Standard /V 1 /R 2 /P %d /O <%x> /U <%x> >>", permissions, o, u)},
		{9, "null"},
		{10, readsObjectStream(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")},
	}
	trailer := fmt.Sprintf("/Encrypt 9 0 R /ID [<%x> <%x>]", readsFileID, readsFileID)
	for _, c := range []struct {
		name string
		data []byte
	}{
		{"a scan begun at a damaged catalog", readsTableFile(objects, 1, trailer)},
		{"a scan begun at a startxref that names nothing", readsPastTheStartxref(readsTableFile(objects, 0, trailer))},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := extract(t, c.data)
			if out, ok := readsPoppler(t, c.data); ok {
				// The other reader refuses the damaged file; the record is of
				// the reading the rebuilt trailer names.
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v; the page tree's root is in the object stream the scan found", r.Fatal, r.Pages)
			}
			if r.Pages[0].Text != "Z" || r.Pages[0].Status != PageOK || len(r.Problems) != 0 {
				t.Errorf("the record reads %s %q with problems %+v; the object stream holds the root in plain text, and the trailer the scan rebuilt names no handler to read it through",
					r.Pages[0].Status, r.Pages[0].Text, r.Problems)
			}
			if r.Encryption != nil {
				t.Errorf("encryption %+v; the trailer this document has names none", r.Encryption)
			}
		})
	}
}

// How deep the scan's reads go is how many references the scan itself
// followed. A caller that was half way down a chain when the rebuild began
// has its chain put aside with its read: those objects are of a document this
// one no longer is, and counting them would have the scan report a depth it
// never reached -- a bound on the file, which no rebuild drops. Below, a
// page's content reaches a damaged reference through a chain of stream
// lengths, and the scan that rebuilds parses a candidate whose own length
// takes a few reads of its own.
func TestReadsTheScanCountsItsOwnNesting(t *testing.T) {
	objects := []readsObject{
		{1, "<< /Type /Catalog /Pages 2 0 R >>"},
		{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
		{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
		// The content, whose length is the head of a chain of stream lengths
		// ending at a reference the cross-reference has damaged.
		{6, "<< /Length 11 0 R >>\nstream\n" + shown("A", 700) + "\nendstream"},
		{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /ToUnicode 8 0 R >>"},
		{8, readsStreamObject("", "begincmap\n1 begincodespacerange\n<00> <FF>\nendcodespacerange\n1 beginbfchar\n<41> <005A>\nendbfchar\nendcmap\n")},
	}
	for num := 11; num <= 38; num++ {
		objects = append(objects, readsObject{num, fmt.Sprintf("<< /Length %d 0 R >>\nstream\nx\nendstream", num+1)})
	}
	objects = append(objects, readsObject{39, "1"})
	// A candidate the scan parses -- its bytes name a cross-reference stream
	// -- whose own length takes five reads to resolve.
	objects = append(objects,
		readsObject{50, "<< /Type /XRef /W [1 4 2] /Length 51 0 R >>\nstream\nx\nendstream"},
		readsObject{51, "<< /Length 52 0 R >>\nstream\nx\nendstream"},
		readsObject{52, "<< /Length 53 0 R >>\nstream\nx\nendstream"},
		readsObject{53, "<< /Length 54 0 R >>\nstream\nx\nendstream"},
		readsObject{54, "<< /Length 55 0 R >>\nstream\nx\nendstream"},
		readsObject{55, "1"},
		// The content again, later in the file, with a length of its own:
		// this is the definition the scan finds, and the page the rebuilt
		// document carries.
		readsObject{6, readsStreamObject("", shown("A", 700))})
	for _, c := range []struct {
		name string
		data []byte
	}{
		{"a scan begun at a damaged reference met down a chain of lengths", readsRawFile(objects, 39, nil)},
		{"a scan begun at a startxref that names nothing", readsPastTheStartxref(readsRawFile(objects, 0, nil))},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := extract(t, c.data)
			if out, ok := readsPoppler(t, c.data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v; the chain the caller was following is no part of the scan's own depth", r.Fatal, r.Pages)
			}
			if r.Pages[0].Text != "Z" || r.Pages[0].Status != PageOK || len(r.Problems) != 0 {
				t.Errorf("the record reads %s %q with problems %+v; the rebuilt document's content states its own length",
					r.Pages[0].Status, r.Pages[0].Text, r.Problems)
			}
		})
	}
}

// A bound met parsing a trailer the scan found is a bound the scan met
// reading the file, as every other bound it meets is: the scan reads the
// file's bytes, and a candidate nested past what the parser admits is past
// the bound wherever it stands. The file below is a whole one-page document
// with such a dictionary after it and a startxref that names nothing.
func TestReadsABoundInAScannedTrailerEndsTheScan(t *testing.T) {
	b := &pdfgen.Builder{}
	num := b.Add(pdfgen.Object{Body: "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"})
	b.Catalog(b.Pages([]pdfgen.Page{{Content: shown("Z", 700), Fonts: map[string]int{"F1": num}}}))
	data := append(readsPastTheStartxref(b.Bytes()), []byte("\ntrailer\n"+readsOverNested()+"\n")...)
	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		// The other reader recovers the page; its recovery is not this
		// reader's bound.
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal == nil || r.Fatal.Code != "pdf-malformed" || r.Fatal.Message != boundMessage {
		t.Errorf("fatal %+v pages %+v; the scan parsed a trailer past the bound of the parser, and a bound is not read past", r.Fatal, r.Pages)
	}
}

// Extraction ends the moment the cross-reference is rebuilt: the pages listed
// after that one are of a document this one no longer is, and reading them
// would spend on them what the reading that follows needs. The allowance
// below is exactly the two readings of the first page.
// readsHiddenFontFile is a file whose font is defined only where the scan
// does not look: the '+' before the definition's header makes the bytes
// after it no object header at all as the scan reads the file, while a
// cross-reference entry pointing at the header reads the object there. The
// one cross-reference that names it is a /Prev section, a stream whose
// /Length is an indirect reference the newest table puts at an offset holding
// no object: resolving that reference rebuilds the cross-reference, and the
// section is then a section of a document the reader no longer has. A later,
// empty definition of the section's own number is what the scan finds under
// it.
func readsHiddenFontFile() []byte {
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	offsets := map[int]int{}
	add := func(num int, body string) {
		offsets[num] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", num, body)
	}
	add(1, "<< /Type /Catalog /Pages 2 0 R >>")
	add(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	add(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 11 0 R >> >> /Contents 6 0 R >>")
	add(6, readsStreamObject("", shown("A", 700)))
	out.WriteString("+")
	hidden := out.Len()
	fmt.Fprintf(&out, "11 0 obj\n%s\nendobj\n", readsHelvetica("X"))
	add(22, "7")
	// One entry under /W [1 4 2]: object 11, in use, at the hidden header.
	entry := []byte{1, byte(hidden >> 24), byte(hidden >> 16), byte(hidden >> 8), byte(hidden), 0, 0}
	section := out.Len()
	fmt.Fprintf(&out, "30 0 obj\n<< /Type /XRef /Size 41 /W [1 4 2] /Index [11 1] /Length 22 0 R >>\nstream\n%s\nendstream\nendobj\n", entry)
	fmt.Fprint(&out, "30 0 obj\n<< >>\nendobj\n")
	at := out.Len()
	out.WriteString("xref\n0 1\n0000000000 65535 f \n")
	for _, num := range []int{1, 2, 3, 6, 22} {
		offset := offsets[num]
		if num == 22 {
			offset = 3
		}
		fmt.Fprintf(&out, "%d 1\n%010d 00000 n \n", num, offset)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size 41 /Root 1 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n", section, at)
	return out.Bytes()
}

// A section abandoned while its own /Length was resolved declares none of its
// entries. The entry below names the one object that says what the page's
// glyph is, and the scan that replaced the section does not find that object:
// a reader that installed the entry all the same would read the page through
// a font of a document it no longer has. The glyph is a counted replacement
// instead, and the rebuilt cross-reference holds no entry for the number.
func TestReadsASectionAbandonedAtItsLengthDeclaresNothing(t *testing.T) {
	data := readsHiddenFontFile()
	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		// The other reader recovers the abandoned definition; what it reads
		// is logged beside this reader's answer and is not the assertion.
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if r.Pages[0].Text != "�" || r.Pages[0].Unmapped != 1 || r.Pages[0].Status != PageOK || len(r.Problems) != 0 {
		t.Errorf("the record reads %s %q with %d glyphs unmapped and problems %+v, want %q with one unmapped: the entry naming the font is a section's the rebuild replaced",
			r.Pages[0].Status, r.Pages[0].Text, r.Pages[0].Unmapped, r.Problems, "�")
	}
	if d := openGenerated(t, data); d.xref[11] != (xrefEntry{}) {
		t.Errorf("the cross-reference names object 11 as %+v; no entry of the abandoned section stands in it", d.xref[11])
	}
}

// The sections a traversal has queued are named by the trailers of the
// sections before them. Where one section's own read rebuilds the
// cross-reference, those trailers are a document's the reader no longer has:
// the traversal ends there and the queue is dropped, so that a /Prev queued
// before the rebuild is not opened afterwards and what it is past is no bound
// of this document. The file below names a hybrid file's /XRefStm and a
// /Prev; the stream's damaged /W rebuilds, and the queued /Prev declares more
// objects than a section may.
func TestReadsSectionsQueuedBeforeARebuildAreNotRead(t *testing.T) {
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	offsets := map[int]int{}
	add := func(num int, body string) {
		if _, written := offsets[num]; !written {
			offsets[num] = out.Len()
		}
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", num, body)
	}
	entries := string(make([]byte, 7))
	add(1, "<< /Type /Catalog /Pages 2 0 R >>")
	add(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	add(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>")
	add(6, readsStreamObject("", shown("A", 700)))
	add(7, readsHelvetica("Z"))
	// The /W of the hybrid stream, at an offset holding no object.
	add(20, "[1 4 2]")
	hybrid := out.Len()
	add(30, "<< /Type /XRef /Size 41 /W 20 0 R /Index [0 1] /Length 7 >>\nstream\n"+entries+"\nendstream")
	// The section queued behind it, which declares more objects than one may.
	prev := out.Len()
	add(31, "<< /Type /XRef /Size 41 /W [1 4 2] /Index [0 4194305] /Length 7 >>\nstream\n"+entries+"\nendstream")
	// The later definition the scan finds of the stream whose /W was damaged.
	add(30, "<< >>")
	at := out.Len()
	out.WriteString("xref\n0 1\n0000000000 65535 f \n")
	for _, num := range []int{1, 2, 3, 6, 7, 20, 30, 31} {
		offset := offsets[num]
		if num == 20 {
			offset = 3
		}
		fmt.Fprintf(&out, "%d 1\n%010d 00000 n \n", num, offset)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size 41 /Root 1 0 R /XRefStm %d /Prev %d >>\nstartxref\n%d\n%%%%EOF\n", hybrid, prev, at)
	data := out.Bytes()
	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v; the section past the bound was queued by a document the rebuild replaced", r.Fatal, r.Pages)
	}
	if r.Pages[0].Text != "Z" || r.Pages[0].Status != PageOK || len(r.Problems) != 0 {
		t.Errorf("the record reads %s %q with problems %+v, want %s %q", r.Pages[0].Status, r.Pages[0].Text, r.Problems, PageOK, "Z")
	}
}

// A bound met reading the file itself ends the reading wherever it is met.
// The file below is opened from a cross-reference of its own, and the scan
// begins only when a page's font is read: the offset the table gives it holds
// no object. The scan then meets a trailer the parser will not read -- nested
// past what it holds, of more members than one dictionary holds, or carrying
// a string of more bytes than one holds -- and a bound is not read past. The
// document is refused, as it is refused when the same bound is met opening
// it: what the reader has of the pages was read while the file was being
// scanned, and the scan ended at the file's own defect.
func TestReadsABoundMetWhileAPageIsReadRefusesTheDocument(t *testing.T) {
	// A dictionary of more members than one holds: the members are named
	// apart, since a key written twice is one member written twice.
	var members strings.Builder
	members.WriteString("<< ")
	for i := 0; i <= maxContainerItems; i++ {
		fmt.Fprintf(&members, "/K%d 1 ", i)
	}
	members.WriteString(">>")
	for _, c := range []struct {
		name, trailer string
		// large says the trailer is megabytes of it. What the other reader
		// makes of the file is logged and never asserted, and handing it a
		// file of that size says no more than the small one does, so it is
		// asked about the small one alone.
		large bool
	}{
		{"a dictionary nested past the parser", readsOverNested(), false},
		{"a dictionary of more members than one holds", members.String(), true},
		{"a string of more bytes than one holds", "<< /K (" + strings.Repeat("x", maxStringBytes+1) + ") >>", true},
	} {
		for _, where := range []struct {
			name    string
			objects []readsObject
			broken  int
		}{
			{"a font the page names", []readsObject{
				{1, "<< /Type /Catalog /Pages 2 0 R >>"},
				{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
				{3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
				{6, readsStreamObject("", shown("A", 700))},
				{7, readsHelvetica("Z")},
			}, 7},
			{"the ToUnicode map of a font the page names", []readsObject{
				{1, "<< /Type /Catalog /Pages 2 0 R >>"},
				{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
				{3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
				{6, readsStreamObject("", shown("A", 700))},
				{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /ToUnicode 8 0 R >>"},
				{8, readsStreamObject("", "begincmap\n1 beginbfchar\n<41> <005A>\nendbfchar\nendcmap\n")},
			}, 8},
		} {
			t.Run(c.name+", reached through "+where.name, func(t *testing.T) {
				data := append(readsTableFile(where.objects, where.broken, ""), []byte("\ntrailer\n"+c.trailer+"\n")...)
				r := extract(t, data)
				if !c.large {
					// The other reader recovers the page; its recovery is not
					// this reader's bound. It is not asked about the files of
					// megabytes: what it reads of them is logged and never
					// asserted, and says no more than the small file does.
					if out, ok := readsPoppler(t, data); ok {
						t.Logf("pdftotext reads %q", out)
					}
				}
				if r.Fatal == nil || r.Fatal.Code != "pdf-malformed" || r.Fatal.Message != boundMessage {
					t.Errorf("fatal %+v pages %+v; the scan met a bound of the parser reading the file, and a bound is not read past",
						r.Fatal, r.Pages)
				}
			})
		}
	}
}

func TestReadsARebuiltCrossReferenceEndsTheExtraction(t *testing.T) {
	content := shown("Z", 700)
	// Two places a page's reading rebuilds the cross-reference: loading its
	// content, and interpreting what was loaded -- the font the page selects
	// is looked up there. The reading stops at either, before the pages after
	// it are touched: they are pages of a document this one no longer has.
	for _, c := range []struct {
		name   string
		broken int
	}{
		{"a rebuild while the page's content is loaded", 6},
		{"a rebuild while the page's font is looked up", 7},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsRawFile([]readsObject{
				{1, "<< /Type /Catalog /Pages 2 0 R >>"},
				{2, "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>"},
				{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
				{4, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 10 0 R >>"},
				{6, readsStreamObject("/Filter /FlateDecode", string(flateOf([]byte(content))))},
				{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"},
				{10, readsStreamObject("/Filter /FlateDecode", string(flateOf([]byte(shown("OTHER", 700)))))},
				{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
			}, c.broken, nil)
			// The page's content is inflated twice: once under the
			// cross-reference the file holds -- reading it is what rebuilds --
			// and once under the rebuilt one. An allowance of exactly that
			// leaves nothing for a page of the document the rebuild replaced.
			opt := testOptions()
			opt.MaxInflateTotal = int64(2 * len(content))
			opt.MaxInflateOne = opt.MaxInflateTotal
			r := Extract(context.Background(), data, opt)
			if r.Fatal != nil {
				t.Fatalf("fatal %+v", r.Fatal)
			}
			if len(r.Pages) != 1 || r.Pages[0].Text != "Z" || r.Pages[0].Status != PageOK || len(r.Problems) != 0 {
				t.Errorf("the record reads %+v with problems %+v, want one page reading %q; the page the rebuild dropped is not read at all",
					r.Pages, r.Problems, "Z")
			}
		})
	}
}

// An /Encoding a Type0 font gives that is not Identity and is not a CMap the
// reader can use says nothing about how the font's bytes split into codes:
// the glyphs are counted and unmapped at the font's default width, and the
// ToUnicode map is not a second reading of codes the encoding never gave.
func TestReadsEveryUnusableEncodingIsNotIdentity(t *testing.T) {
	for _, c := range []struct{ name, encoding string }{
		{"a reference to an object the file does not hold", "/Encoding 88 0 R"},
		{"null", "/Encoding null"},
		{"a number", "/Encoding 42"},
		{"an empty dictionary", "/Encoding << >>"},
		{"no /Encoding at all", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := &pdfgen.Builder{}
			tu := b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(
				"begincmap\n1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n1 beginbfchar\n<0041> <005A>\nendbfchar\nendcmap\n")})
			cid := b.Add(pdfgen.Object{Body: "<< /Type /Font /Subtype /CIDFontType0 /BaseFont /Test /DW 700 /W [65 [123]] >>"})
			num := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Font /Subtype /Type0 /BaseFont /Test %s /DescendantFonts [%d 0 R] /ToUnicode %d 0 R >>", c.encoding, cid, tu)})
			b.Catalog(b.Pages([]pdfgen.Page{{Content: "BT /F1 12 Tf 1 0 0 1 72 700 Tm <0041> Tj ET\n", Fonts: map[string]int{"F1": num}}}))
			data := b.Bytes()
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if r.Pages[0].Text != "�" || r.Pages[0].Unmapped != 1 || r.Pages[0].Status != PageOK || len(r.Problems) != 0 {
				t.Errorf("the record reads %s %q with %d glyphs unmapped and problems %+v; this font's encoding is none the reader can use",
					r.Pages[0].Status, r.Pages[0].Text, r.Pages[0].Unmapped, r.Problems)
			}
			if g := firstGlyph(loadFontNumbered(openGenerated(t, data), num), []byte{0, 65}); !g.unmapped || g.width != 0.7 {
				t.Errorf("the code is %q, unmapped %v, %g em wide; no CID stands behind it and its width is the default width", string(g.runes), g.unmapped, g.width)
			}
		})
	}
}

// A CMap stream a font gives as its own encoding may parse to nothing at all:
// no bytes, bytes that hold no operator of the syntax, a begincmap and an
// endcmap with nothing between them, or a stream that names a parent CMap,
// which this reader does not look up. None of them declares a codespace range
// or maps a code, so none says how the font's bytes split into codes or what
// they stand for: the font's encoding is one the reader cannot use, its bytes
// are split into codes of two so that the glyphs can be counted, every one of
// them is unmapped at the font's default width, and the ToUnicode map is not
// a second reading of codes the encoding never gave.
func TestReadsAnEncodingCMapThatParsesToNothingIsUnusable(t *testing.T) {
	const toUnicode = "begincmap\n1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n1 beginbfchar\n<0041> <005A>\nendbfchar\nendcmap\n"
	for _, c := range []struct {
		name, encoding, show, want string
		unmapped                   int
	}{
		{"a stream of no bytes", "", "0041", "�", 1},
		{"bytes that hold no operator of the syntax", "<GG>", "0041", "�", 1},
		{"a begincmap and an endcmap with nothing between", "begincmap endcmap", "0041", "�", 1},
		{"a stream naming a parent CMap", "/UseCMap /Identity-H", "0041", "�", 1},
		{"two codes of two bytes", "begincmap endcmap", "00410041", "��", 2},
		{"no bytes shown at all", "begincmap endcmap", "", "", 0},
		// A CMap that maps a code declares an encoding, and declares no
		// codespace range: its codes are the two bytes the reader infers from
		// what it holds, and not the four a map declaring nothing would leave.
		{"a map that declares an encoding and no codespace range",
			"begincmap\n1 begincidchar\n<0041> 5\nendcidchar\nendcmap\n", "00410041", "ZZ", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			data, num := readsEncodedFont(c.encoding, toUnicode, c.show)
			r := extract(t, data)
			if out, diagnostics, ok := readsPopplerRead(t, data); ok {
				t.Logf("pdftotext reads %q, with %q as diagnostics", out, diagnostics)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			status := PageOK
			if c.want == "" {
				status = PageNoText
			}
			if r.Pages[0].Text != c.want || r.Pages[0].Unmapped != c.unmapped || r.Pages[0].Status != status || len(r.Problems) != 0 {
				t.Errorf("the record reads %s %q with %d glyphs unmapped and problems %+v, want %s %q with %d unmapped",
					r.Pages[0].Status, r.Pages[0].Text, r.Pages[0].Unmapped, r.Problems, status, c.want, c.unmapped)
			}
			if c.unmapped > 0 {
				if g := firstGlyph(loadFontNumbered(openGenerated(t, data), num), []byte{0, 65}); !g.unmapped || len(g.runes) != 0 || g.width != 0.7 {
					t.Errorf("the code is %q, unmapped %v, %g em wide; no CID stands behind it and its width is the font's default width",
						string(g.runes), g.unmapped, g.width)
				}
			}
		})
	}
}

// The operations that resolve more than one of an object's fields are one
// read each, and each of them separately: finding a font, sizing a colour
// space, reading a page's content and decoding a stream. Every file below
// resolves a damaged reference through one of them -- which rebuilds -- and
// then a second field of the same object, which is nested past what the
// parser admits. The rebuilt document names neither, and the record carries
// its page.
func TestReadsEveryNamedOperationIsOneReadOfItsOwn(t *testing.T) {
	page := func(extra, contents string) string {
		return "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> " + extra + " >> /Contents " + contents + " >>"
	}
	head := []readsObject{
		{1, "<< /Type /Catalog /Pages 2 0 R >>"},
		{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
	}
	var image bytes.Buffer
	image.WriteString("BI /W 64 /H 1 /BPC 8 /CS /ICC ID ")
	image.Write(readsHiddenSamples()[:64])
	image.WriteString("\nEI\n")
	image.WriteString(shown("A", 700))
	for _, c := range []struct {
		name string
		data func() []byte
	}{
		{"finding a font", func() []byte {
			return readsRawFile(append(head,
				readsObject{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font 8 0 R >> /Contents 6 0 R >>"},
				readsObject{6, readsStreamObject("", shown("A", 700))},
				// The resource is a stream whose length is a damaged
				// reference, and whose /F1 is nested past the parser.
				readsObject{8, "<< /F1 9 0 R /Length 10 0 R >>\nstream\n \nendstream"},
				readsObject{9, readsOverNested()},
				readsObject{10, "1"},
				readsObject{8, "<< /F1 11 0 R >>"},
				readsObject{11, readsHelvetica("Z")},
			), 10, nil)
		}},
		{"sizing a colour space", func() []byte {
			return readsRawFile(append(head,
				readsObject{3, page("/ColorSpace << /ICC [/ICCBased 8 0 R] >>", "6 0 R")},
				readsObject{6, readsStreamObject("", image.String())},
				readsObject{7, readsHelvetica("Z")},
				readsObject{8, "<< /N 9 0 R /Length 10 0 R >>\nstream\n \nendstream"},
				readsObject{9, readsOverNested()},
				readsObject{10, "1"},
				readsObject{8, readsStreamObject("/N 1", " ")},
			), 10, nil)
		}},
		{"reading a page's content", func() []byte {
			return readsRawFile(append(head,
				readsObject{3, page("", "[6 0 R 8 0 R 9 0 R]")},
				readsObject{6, readsStreamObject("", shown("A", 700))},
				readsObject{7, readsHelvetica("Z")},
				readsObject{8, readsStreamObject("", " ")},
				readsObject{9, readsOverNested()},
				readsObject{3, page("", "10 0 R")},
				readsObject{10, readsStreamObject("", shown("A", 700))},
			), 8, nil)
		}},
		{"decoding a stream", func() []byte {
			return readsSectionFile(append(head,
				readsObject{3, page("", "6 0 R")},
				readsObject{6, readsStreamObject("", shown("A", 700))},
				readsObject{7, readsHelvetica("Z")},
				readsObject{40, "/FlateDecode"},
				readsObject{41, readsOverNested()},
			), 40, readsObject{30, "<< /Type /XRef /Size 41 /W [1 4 2] /Filter [/FlateDecode 40 0 R 41 0 R] /Length 7 >>\nstream\n" + string(make([]byte, 7)) + "\nendstream"}, false)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := c.data()
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil {
				t.Fatalf("fatal %+v; the bound was met in an object the rebuild replaced", r.Fatal)
			}
			if len(r.Pages) != 1 || r.Pages[0].Text != "Z" || r.Pages[0].Status != PageOK || len(r.Problems) != 0 {
				t.Errorf("the record reads %+v with problems %+v, want one page reading %q", r.Pages, r.Problems, "Z")
			}
		})
	}
}

// A ToUnicode map the reader cannot use is not an encoding the reader cannot
// use. A simple font's bytes are codes of one byte whatever its ToUnicode map
// says, so a map that says two things about how long a code is is dropped and
// the font's own encoding reads the page: the glyph is the one the encoding
// gives, mapped and not counted. A composite font's unusable *encoding* is
// the other rule, and leaves its glyphs unmapped and counted.
func TestReadsAnUnusableToUnicodeLeavesASimpleFontsEncoding(t *testing.T) {
	for _, c := range []struct {
		name, differences, text string
		unmapped                int
	}{
		{"a glyph the font's own encoding maps", "", "A", 0},
		{"a glyph it does not", " /Differences [65 /UnrecognizedGlyph]", "\ufffd", 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := &pdfgen.Builder{}
			tu := b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(
				"begincmap\n2 begincodespacerange\n<41> <41>\n<4100> <41FF>\nendcodespacerange\n1 beginbfchar\n<41> <005A>\nendbfchar\nendcmap\n")})
			encoding := "/Encoding /WinAnsiEncoding"
			if c.differences != "" {
				encoding = "/Encoding << /Type /Encoding /BaseEncoding /WinAnsiEncoding" + c.differences + " >>"
			}
			num := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica %s /ToUnicode %d 0 R >>", encoding, tu)})
			b.Catalog(b.Pages([]pdfgen.Page{{Content: shown("A", 700), Fonts: map[string]int{"F1": num}}}))
			data := b.Bytes()
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				// Poppler reads the map this reader drops, and shows its Z.
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if r.Pages[0].Text != c.text || r.Pages[0].Unmapped != c.unmapped || r.Pages[0].Status != PageOK || len(r.Problems) != 0 {
				t.Errorf("the record reads %s %q with %d glyphs unmapped and problems %+v, want %q with %d unmapped; dropping the map is no defect of the document, and the font's own encoding maps what it can",
					r.Pages[0].Status, r.Pages[0].Text, r.Pages[0].Unmapped, r.Problems, c.text, c.unmapped)
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

// An array of one element is another writing of a device colour space only
// where the element the image wrote is a device family's name. An array whose
// element is itself an array has no name at its family position: it is not
// the space that inner array would be, and beside a device name it is a
// second thing said about the image. A family that takes parameters, written
// alone, is not the bare name of the same spelling either -- that name is one
// of the resources in force, and a resource is not a family.
func TestReadsASingletonColourArrayIsADeviceFamilyAlone(t *testing.T) {
	// Every resource here has one component, so that a reader unwrapping the
	// arrays below would find the two declarations agreeing and measure the
	// samples the image holds -- and read the page.
	const resources = "/ColorSpace << /Indexed [/CalGray << /WhitePoint [1 1 1] >>] /ICCBased [/CalGray << /WhitePoint [1 1 1] >>] /CalGray [/CalGray << /WhitePoint [1 1 1] >>] /Pattern [/CalGray << /WhitePoint [1 1 1] >>] >>"
	for _, c := range []struct{ name, space, want string }{
		{"a device family's array beside its name", "/CS [/DeviceGray] /ColorSpace /DeviceGray", "REAL"},
		{"a device family's name beside its array", "/CS /DeviceGray /ColorSpace [/DeviceGray]", "REAL"},
		{"the array of a family's abbreviation beside the name it abbreviates", "/CS [/G] /ColorSpace /DeviceGray", "REAL"},
		{"the name beside the array of the abbreviation of it", "/CS /DeviceGray /ColorSpace [/G]", "REAL"},
		{"an array of an array beside the name", "/CS [[/DeviceGray]] /ColorSpace /DeviceGray", ""},
		{"the name beside an array of an array", "/CS /DeviceGray /ColorSpace [[/DeviceGray]]", ""},
		{"an Indexed array beside the resource of that name", "/CS [/Indexed] /ColorSpace /Indexed", ""},
		{"the resource named Indexed beside that array", "/CS /Indexed /ColorSpace [/Indexed]", ""},
		{"an ICCBased array beside the resource of that name", "/CS [/ICCBased] /ColorSpace /ICCBased", ""},
		{"the resource named ICCBased beside that array", "/CS /ICCBased /ColorSpace [/ICCBased]", ""},
		{"a CalGray array beside the resource of that name", "/CS [/CalGray] /ColorSpace /CalGray", ""},
		{"the resource named CalGray beside that array", "/CS /CalGray /ColorSpace [/CalGray]", ""},
		{"a Pattern array beside the resource of that name", "/CS [/Pattern] /ColorSpace /Pattern", ""},
		{"the resource named Pattern beside that array", "/CS /Pattern /ColorSpace [/Pattern]", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			var content bytes.Buffer
			content.WriteString("BI /W 40 /H 8 /BPC 8 " + c.space + " ID ")
			content.Write(readsHiddenSamples())
			content.WriteString("\nEI\n")
			content.WriteString(shown("REAL", 700))
			data := readsResourcePage(content.Bytes(), resources, false)
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
			if c.want == "" && len(r.Problems) == 1 && r.Problems[0].Code != "pdf-page-failed" {
				t.Errorf("problems %+v", r.Problems)
			}
		})
	}
}

// The device colour spaces are the families themselves wherever they are
// named (8.6.8): a resource named /DeviceGray is not what an image declaring
// /DeviceGray is in, and neither is it what the array of that family alone is
// in. The image below is measured as one component under both writings,
// whatever the page's /ColorSpace holds under that name.
func TestReadsADeviceNameIsTheFamilyAndNotAResource(t *testing.T) {
	const resources = "/ColorSpace << /DeviceGray /DeviceRGB >>"
	for _, c := range []struct{ name, space string }{
		{"the device name", "/CS /DeviceGray"},
		{"the array of that family alone", "/CS [/DeviceGray]"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var content bytes.Buffer
			content.WriteString("BI /W 40 /H 8 /BPC 8 " + c.space + " ID ")
			content.Write(readsHiddenSamples())
			content.WriteString("\nEI\n")
			content.WriteString(shown("REAL", 700))
			data := readsResourcePage(content.Bytes(), resources, false)
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				// Poppler looks the bare name up among the resources and
				// measures the three components it finds there; the array it
				// reads as the family.
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if r.Pages[0].Text != "REAL" || r.Pages[0].Status != PageOK || len(r.Problems) != 0 {
				t.Errorf("the record reads %s %q with problems %+v; the samples are 320 bytes of one component, and the text among them is the image's",
					r.Pages[0].Status, r.Pages[0].Text, r.Problems)
			}
		})
	}
}

// A colour space stands at more positions than the outermost one: the base of
// an Indexed space and the alternate of a Separation or a DeviceN one are
// colour spaces in their own right, and two writings of one of them -- a
// device family's name, the abbreviation of it, or the array of that family
// alone -- are one value there as they are at the top. What such an array
// holds besides those positions is the family's parameters: a colourant's
// name, a tint transformation, a hival, a lookup table, each compared as the
// image wrote it, so two images differing there say two things and the page
// fails. A space standing at one of those positions is read under that rule
// again and not once: the base of a base is read as far down as the image
// writes one. A head that is no family's name is no writing of a space at any
// depth and is left as the image wrote it, so two such heads differ where
// they are written differently.
func TestReadsColourSpacesAreComparedAtEveryColourSpacePosition(t *testing.T) {
	// A tint transformation is written in place: an inline image's dictionary
	// holds no indirect reference to name a function by.
	const rgbTint = "<< /FunctionType 2 /Domain [0 1] /C0 [0 0 0] /C1 [1 1 1] /N 1 >>"
	const cmykTint = "<< /FunctionType 2 /Domain [0 1] /C0 [0 0 0 0] /C1 [1 1 1 1] /N 1 >>"
	// A second transformation of each, mapping the tint elsewhere: two
	// functions are two parameters, whatever the space around them is.
	const otherRGBTint = "<< /FunctionType 2 /Domain [0 1] /C0 [0 0 0] /C1 [1 1 0] /N 1 >>"
	const otherCMYKTint = "<< /FunctionType 2 /Domain [0 1] /C0 [0 0 0 0] /C1 [1 1 0 0] /N 1 >>"
	// Every space below measures one component -- an Indexed image has one
	// index whatever its base, a Separation one tint, and a DeviceN one for
	// each colourant it separates -- so the 320 bytes the image carries are
	// the samples of all of them, and what differs is only what is declared.
	for _, c := range []struct{ name, one, other, want string }{
		{"an Indexed base as the array of its family alone", "[/Indexed [/DeviceRGB] 1 <000000FFFFFF>]", "[/Indexed /DeviceRGB 1 <000000FFFFFF>]", "REAL"},
		{"an Indexed base under the abbreviation of it", "[/Indexed /RGB 1 <000000FFFFFF>]", "[/Indexed /DeviceRGB 1 <000000FFFFFF>]", "REAL"},
		{"an Indexed base as the array of that abbreviation", "[/Indexed [/RGB] 1 <000000FFFFFF>]", "[/Indexed /DeviceRGB 1 <000000FFFFFF>]", "REAL"},
		{"an Indexed head and base both abbreviated", "[/I [/G] 1 <00FF>]", "[/Indexed /DeviceGray 1 <00FF>]", "REAL"},
		{"a Separation alternate as the array of its family alone", "[/Separation /Spot [/DeviceRGB] " + rgbTint + "]", "[/Separation /Spot /DeviceRGB " + rgbTint + "]", "REAL"},
		{"a Separation alternate under the abbreviation of it", "[/Separation /Spot /RGB " + rgbTint + "]", "[/Separation /Spot /DeviceRGB " + rgbTint + "]", "REAL"},
		{"a DeviceN alternate as the array of its family alone", "[/DeviceN [/Spot] [/DeviceCMYK] " + cmykTint + "]", "[/DeviceN [/Spot] /DeviceCMYK " + cmykTint + "]", "REAL"},
		{"a DeviceN alternate under the abbreviation of it", "[/DeviceN [/Spot] /CMYK " + cmykTint + "]", "[/DeviceN [/Spot] /DeviceCMYK " + cmykTint + "]", "REAL"},
		{"the base of an Indexed base as the array of its family alone", "[/Indexed [/Indexed [/DeviceRGB] 1 <000000FFFFFF>] 1 <0041>]", "[/Indexed [/Indexed /DeviceRGB 1 <000000FFFFFF>] 1 <0041>]", "REAL"},
		{"two Indexed bases that are two spaces", "[/Indexed /DeviceRGB 1 <000000FFFFFF>]", "[/Indexed /DeviceGray 1 <000000FFFFFF>]", ""},
		{"two Separation alternates that are two spaces", "[/Separation /Spot /DeviceRGB " + rgbTint + "]", "[/Separation /Spot /DeviceGray " + rgbTint + "]", ""},
		{"two colourants that are two colourants", "[/Separation /G /DeviceRGB " + rgbTint + "]", "[/Separation /DeviceGray /DeviceRGB " + rgbTint + "]", ""},
		{"two lists of colourants that are two lists", "[/DeviceN [/G] /DeviceCMYK " + cmykTint + "]", "[/DeviceN [/DeviceGray] /DeviceCMYK " + cmykTint + "]", ""},
		{"two lookup tables that are two tables", "[/Indexed /DeviceGray 1 <0041>]", "[/Indexed /DeviceGray 1 <0042>]", ""},
		{"two hivals that are two hivals", "[/Indexed /DeviceGray 1 <0041>]", "[/Indexed /DeviceGray 2 <0041>]", ""},
		{"two Separation tint transformations that are two transformations", "[/Separation /Spot /DeviceRGB " + rgbTint + "]", "[/Separation /Spot /DeviceRGB " + otherRGBTint + "]", ""},
		{"two DeviceN tint transformations that are two transformations", "[/DeviceN [/Spot] /DeviceCMYK " + cmykTint + "]", "[/DeviceN [/Spot] /DeviceCMYK " + otherCMYKTint + "]", ""},
		{"an invalid base beside the same head written out", "[/Indexed [[/RGB]] 1 <000000FFFFFF>]", "[/Indexed [[/DeviceRGB]] 1 <000000FFFFFF>]", ""},
	} {
		for _, order := range []struct{ name, cs, colourSpace string }{
			{"as written", c.one, c.other},
			{"the other way about", c.other, c.one},
		} {
			t.Run(c.name+", "+order.name, func(t *testing.T) {
				var content bytes.Buffer
				content.WriteString("BI /W 40 /H 8 /BPC 8 /CS " + order.cs + " /ColorSpace " + order.colourSpace + " ID ")
				content.Write(readsHiddenSamples())
				content.WriteString("\nEI\n")
				content.WriteString(shown("REAL", 700))
				data := readsContentPage(content.Bytes())
				r := extract(t, data)
				if out, ok := readsPoppler(t, data); ok {
					// The other reader recovers from the declarations that
					// disagree and reads the page; what it reads is logged
					// beside this reader's answer and is not the assertion.
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
					t.Errorf("%s beside %s: the record reads %s %q with problems %+v, want %s %q",
						order.cs, order.colourSpace, r.Pages[0].Status, r.Pages[0].Text, r.Problems, status, c.want)
				}
				if c.want == "" && len(r.Problems) == 1 && r.Problems[0].Code != "pdf-page-failed" {
					t.Errorf("problems %+v", r.Problems)
				}
			})
		}
	}
}

// A hexadecimal string in an inline image's dictionary holds hexadecimal
// digits and white space and nothing else. A byte that is neither begins no
// token of the string: skipping it, as a reader of a damaged file's objects
// does, would read the bytes after it -- the image's data among them, where
// the '>' that would end the string lies past the dictionary -- as the
// value's own, and the page would be read from a dictionary the file does not
// hold. The white space is 7.2.3's and not every byte below a space: a NUL
// stands between two digits as a space does, where a start of heading, a unit
// separator and a delete stand between nothing. A string of no digits is a
// string all the same -- it is complete where it ends -- and the image it
// stands in is read.
func TestReadsAHexadecimalValueInAnInlineDictionaryIsHexadecimal(t *testing.T) {
	for _, c := range []struct{ name, parms, want string }{
		{"a hexadecimal value", "/DP << /Unused <4142> >>", "REAL"},
		{"white space among the digits", "/DP << /Unused <41 42\n43> >>", "REAL"},
		{"a NUL among the digits", "/DP << /Unused <4\x001> >>", "REAL"},
		{"an odd final digit", "/DP << /Unused <4> >>", "REAL"},
		{"no digits at all", "/DP << /Unused <> >>", "REAL"},
		{"no digits at all, in an array in a nested dictionary", "/DP << /A << /B [<>] >> >>", "REAL"},
		{"a byte outside the alphabet", "/DP << /Unused <4)1> >>", ""},
		{"a start of heading among the digits", "/DP << /Unused <4\x011> >>", ""},
		{"a unit separator among the digits", "/DP << /Unused <4\x1f1> >>", ""},
		{"a delete among the digits", "/DP << /Unused <4\x7f1> >>", ""},
		{"a start of heading in an array in a nested dictionary", "/DP << /A << /B [<4\x011>] >> >>", ""},
		{"a unit separator in an array in a nested dictionary", "/DP << /A << /B [<4\x1f1>] >> >>", ""},
		{"operators before a later terminator", "/DP << /Unused <41 (EI) Tj 41> >>", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			var content bytes.Buffer
			content.WriteString("BI /W 80 /H 2 /BPC 8 /CS /G " + c.parms + " ID ")
			content.Write(bytes.Repeat([]byte{'A'}, 160))
			content.WriteString("\nEI\n")
			content.WriteString(shown("REAL", 700))
			data := readsContentPage(content.Bytes())
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
			if c.want == "" && len(r.Problems) == 1 && r.Problems[0].Code != "pdf-page-failed" {
				t.Errorf("problems %+v", r.Problems)
			}
		})
	}
}

// Two writings of one key say the same thing to the bottom of what they hold.
// An entry written null is an entry the dictionary does not have at every
// depth, including a dictionary inside a dictionary, where the members are
// compared by name and not by how many are written; an array's null element
// is a position and is not absent; a member only one dictionary has must be
// null there, whichever of the two holds it.
func TestReadsTwoWritingsOfADictionaryAreCompleteToTheirDepth(t *testing.T) {
	for _, c := range []struct{ name, parms, want string }{
		{"a null member of a nested dictionary", "/DP << /A << /B null >> >> /DecodeParms << /A << >> >>", "REAL"},
		{"a nested dictionary beside its null member, the other way", "/DP << /A << >> >> /DecodeParms << /A << /B null >> >>", "REAL"},
		{"an array holding null beside an empty array", "/DP << /A [null] >> /DecodeParms << /A [] >>", ""},
		{"an empty array beside one holding null", "/DP << /A [] >> /DecodeParms << /A [null] >>", ""},
		{"a member only the second dictionary has", "/DP << >> /DecodeParms << /K -1 >>", ""},
		{"a member only the first dictionary has", "/DP << /K -1 >> /DecodeParms << >>", ""},
		{"a member written null beside one written -1", "/DP << /K null >> /DecodeParms << /K -1 >>", ""},
		{"a member written -1 beside one written null", "/DP << /K -1 >> /DecodeParms << /K null >>", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			var content bytes.Buffer
			content.WriteString("BI /W 80 /H 2 /BPC 8 /CS /G " + c.parms + " ID ")
			content.Write(bytes.Repeat([]byte{'A'}, 160))
			content.WriteString("\nEI\n")
			content.WriteString(shown("REAL", 700))
			data := readsContentPage(content.Bytes())
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
			if c.want == "" && len(r.Problems) == 1 && r.Problems[0].Code != "pdf-page-failed" {
				t.Errorf("problems %+v", r.Problems)
			}
		})
	}
}

// The strict reading of the bytes belongs to the image's dictionary and ends
// with it: the content after the image is the page's, and a ')' or a '>'
// standing in it where a damaged file's objects hold one is skipped as it is
// anywhere else. Two measured images on one page, with such content between
// them, are both read.
func TestReadsStrictBytesEndWithTheInlineDictionary(t *testing.T) {
	var content bytes.Buffer
	content.WriteString("BI /W 80 /H 2 /BPC 8 /CS /G ID ")
	content.Write(bytes.Repeat([]byte{'A'}, 160))
	content.WriteString("\nEI\n")
	content.WriteString(shown("REAL", 700))
	content.WriteString(") >\n")
	content.WriteString("BI /W 80 /H 2 /BPC 8 /CS /G ID ")
	content.Write(bytes.Repeat([]byte{'B'}, 160))
	content.WriteString("\nEI\n")
	content.WriteString(shown("REAL", 686))
	data := readsContentPage(content.Bytes())
	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if r.Pages[0].Text != "REAL\nREAL" || r.Pages[0].Status != PageOK || len(r.Problems) != 0 {
		t.Errorf("the record reads %s %q with problems %+v, want %q: the strict reading is the dictionary's own",
			r.Pages[0].Status, r.Pages[0].Text, r.Problems, "REAL\nREAL")
	}
}

// The strict reading is put down however the dictionary ends: at ID, at a
// byte the lexer refuses, at a keyword where a pair stands, at a value the
// dictionary declares twice with values that disagree, at the bound on the
// objects one dictionary holds, or at the end of the content.
func TestReadsTheStrictReadingEndsWithEveryPathOutOfTheDictionary(t *testing.T) {
	for _, c := range []struct {
		name, dictionary string
		wantErr          bool
	}{
		{"the data begins", "/W 4 /H 4 /BPC 8 /CS /G ID ....", false},
		{"the content ends inside the dictionary", "/W 4 /H 4", true},
		{"a value where a key stands", "/W 4 (H) 4 ID ", true},
		{"a keyword where a pair stands", "/W 4 BI /H 4 ID ", true},
		{"a byte that begins no token", "/W 4 /H ) 4 ID ", true},
		{"a key the image declares twice with values that disagree", "/W 4 /Width 8 ID ", true},
		{"more objects than one dictionary holds", strings.Repeat("/K 1 ", 2*maxOperands+2) + "ID ", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			it := &interp{d: &Document{}, ctx: context.Background(), fonts: map[string]*font{}}
			lex := newLexer([]byte(c.dictionary), 0)
			_, err := it.readInlineImage(lex)
			if (err != nil) != c.wantErr {
				t.Errorf("readInlineImage returned %v, want an error: %v", err, c.wantErr)
			}
			if lex.strict {
				t.Error("the lexer is still reading strictly; the content after the image is the page's")
			}
		})
	}
}

// readsSectionFile writes a document of two cross-reference sections: a
// table naming every object it holds, whose trailer names the older section
// -- by /Prev, or by /XRefStm where hybrid is set, which 7.5.8.4 gives a
// hybrid-reference file -- and that older section, the cross-reference stream
// given. The offset of the object numbered broken is written as 3, so that
// reading it rebuilds the cross-reference by scanning the file.
func readsSectionFile(objects []readsObject, broken int, section readsObject, hybrid bool) []byte {
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	offsets := map[int]int{}
	var order []int
	for _, o := range append(append([]readsObject{}, objects...), section) {
		if _, written := offsets[o.num]; !written {
			offsets[o.num] = out.Len()
			order = append(order, o.num)
		}
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", o.num, o.body)
	}
	at := out.Len()
	sortInts(order)
	out.WriteString("xref\n0 1\n0000000000 65535 f \n")
	for _, num := range order {
		offset := offsets[num]
		if num == broken {
			offset = 3
		}
		fmt.Fprintf(&out, "%d 1\n%010d 00000 n \n", num, offset)
	}
	key := "Prev"
	if hybrid {
		key = "XRefStm"
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R /%s %d >>\nstartxref\n%d\n%%%%EOF\n",
		order[len(order)-1]+1, key, offsets[section.num], at)
	return out.Bytes()
}

// readsPastTheStartxref is the document given with the offset its startxref
// names put past the end of the file: the reader finds no cross-reference
// where the file says one is, and rebuilds by scanning.
func readsPastTheStartxref(data []byte) []byte {
	i := bytes.LastIndex(data, []byte("startxref"))
	if i < 0 {
		return data
	}
	end := bytes.Index(data[i:], []byte("%%EOF"))
	if end < 0 {
		return data
	}
	out := append([]byte{}, data[:i]...)
	out = append(out, "startxref\n999999999\n"...)
	return append(out, data[i+end:]...)
}

// Reading one cross-reference section is one read from its first field to its
// last: a stream's length, the objects it decodes through, its /W, its /Index
// and its /Size are fields of one object. Where resolving one of them rebuilds
// the cross-reference, the fields after it belong to a section this document
// no longer has, and what they meet -- a bound included -- is published to
// nothing. Each file below names an older section whose first field is a
// damaged reference and whose second is nested past what the parser admits;
// the rebuilt document names neither, and the record carries its page.
func TestReadsACrossReferenceSectionIsOneRead(t *testing.T) {
	page := []readsObject{
		{1, "<< /Type /Catalog /Pages 2 0 R >>"},
		{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
		{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
		{6, readsStreamObject("", shown("A", 700))},
		{7, readsHelvetica("Z")},
	}
	entries := string(make([]byte, 7))
	// One entry under /W [1 4 2]: type 2, object stream 4,194,305, index 0 --
	// an object stream one past the object numbers a section may declare.
	pastTheBound := string([]byte{2, 0x00, 0x40, 0x00, 0x01, 0x00, 0x00})
	for _, c := range []struct {
		name    string
		extra   []readsObject
		section readsObject
		broken  int
		hybrid  bool
		// absent is an object number the file defines nowhere, which the
		// abandoned section's own /Index declares: no entry of that section
		// stands in the cross-reference the rebuild left, so the number is
		// named by nothing.
		absent int
	}{
		{"a section whose /W is damaged and whose /Index is nested past the parser",
			[]readsObject{{20, "[1 4 2]"}, {21, readsOverNested()}},
			readsObject{30, "<< /Type /XRef /Size 41 /W 20 0 R /Index 21 0 R /Length 7 >>\nstream\n" + entries + "\nendstream"},
			20, false, 0},
		{"a section whose /Length is damaged and whose /W is nested past the parser",
			[]readsObject{{22, "7"}, {23, readsOverNested()}},
			readsObject{30, "<< /Type /XRef /Size 41 /W 23 0 R /Length 22 0 R >>\nstream\n" + entries + "\nendstream"},
			22, false, 0},
		{"a hybrid file whose /XRefStm has a damaged /W and a /Size nested past the parser",
			[]readsObject{{20, "[1 4 2]"}, {24, readsOverNested()}},
			readsObject{30, "<< /Type /XRef /Size 24 0 R /W 20 0 R /Length 7 >>\nstream\n" + entries + "\nendstream"},
			20, true, 0},
		// The field the rebuilt section is past is its own, written in
		// place: a bound met without an object to resolve is still met in a
		// section the rebuild replaced, and is published no more than an
		// entry of it is. The file defines the stream twice -- the damaged
		// definition the old section named, and a later one the scan finds,
		// whose fields are all direct and within the bounds -- and the
		// control differs from it only in the number of objects its /Index
		// declares.
		{"a section whose /W is damaged and whose own /Index is past the bound",
			[]readsObject{{20, "[1 4 2]"},
				{30, "<< /Type /XRef /Size 41 /W 20 0 R /Index [0 4194305] /Length 7 >>\nstream\n" + entries + "\nendstream"}},
			readsObject{30, "<< /Type /XRef /Size 41 /W [1 4 2] /Index [0 1] /Length 7 >>\nstream\n" + entries + "\nendstream"},
			20, false, 0},
		{"a section whose /W is damaged and whose own /Index names one object",
			[]readsObject{{20, "[1 4 2]"},
				{30, "<< /Type /XRef /Size 41 /W 20 0 R /Index [29 1] /Length 7 >>\nstream\n" + entries + "\nendstream"}},
			readsObject{30, "<< /Type /XRef /Size 41 /W [1 4 2] /Index [29 1] /Length 7 >>\nstream\n" + entries + "\nendstream"},
			20, false, 29},
		{"a section whose /W is damaged and whose /Index is past the bound through another object",
			[]readsObject{{20, "[1 4 2]"}, {25, "[0 4194305]"},
				{30, "<< /Type /XRef /Size 41 /W 20 0 R /Index 25 0 R /Length 7 >>\nstream\n" + entries + "\nendstream"}},
			readsObject{30, "<< /Type /XRef /Size 41 /W [1 4 2] /Index [0 1] /Length 7 >>\nstream\n" + entries + "\nendstream"},
			20, false, 0},
		// The entry itself is past the bound: a type-2 entry naming object
		// stream 4,194,305, read from the seven bytes the section carries.
		{"a section whose /W is damaged and whose entry names an object stream past the bound",
			[]readsObject{{20, "[1 4 2]"},
				{30, "<< /Type /XRef /Size 41 /W 20 0 R /Index [29 1] /Length 7 >>\nstream\n" + pastTheBound + "\nendstream"}},
			readsObject{30, "<< /Type /XRef /Size 41 /W [1 4 2] /Index [29 1] /Length 7 >>\nstream\n" + entries + "\nendstream"},
			20, false, 29},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsSectionFile(append(append([]readsObject{}, page...), c.extra...), c.broken, c.section, c.hybrid)
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil {
				t.Fatalf("fatal %+v; the bound was met in a section the rebuild replaced", r.Fatal)
			}
			if len(r.Pages) != 1 || r.Pages[0].Text != "Z" || r.Pages[0].Status != PageOK || len(r.Problems) != 0 {
				t.Errorf("the record reads %+v with problems %+v, want one page reading %q", r.Pages, r.Problems, "Z")
			}
			if c.absent != 0 {
				if _, named := openGenerated(t, data).xref[c.absent]; named {
					t.Errorf("the cross-reference names object %d; the only section that declared it is one the rebuild replaced", c.absent)
				}
			}
		})
	}
}

// The scan that rebuilds a cross-reference reads objects of its own, and what
// they meet is the file's: the same scan of the same file meets it wherever
// the scan was begun from. Below, the scan finds a cross-reference stream
// whose length resolves to an object nested past what the parser admits --
// a bound on the file the reader read -- and the document is refused whether
// the scan began at a startxref that names nothing or at a damaged reference
// met while a page was read.
func TestReadsTheScanThatRebuildsHasAScopeOfItsOwn(t *testing.T) {
	objects := []readsObject{
		{1, "<< /Type /Catalog /Pages 2 0 R >>"},
		{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
		{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
		{6, readsStreamObject("", shown("A", 700))},
		{7, readsHelvetica("Z")},
		// A cross-reference stream the scan parses, whose length is an object
		// the parser cannot read to its end.
		{30, "<< /Type /XRef /W [1 4 2] /Length 31 0 R >>\nstream\n" + string(make([]byte, 7)) + "\nendstream"},
		{31, readsOverNested()},
	}
	for _, c := range []struct {
		name string
		data []byte
	}{
		{"a scan begun at a startxref that names nothing", readsPastTheStartxref(readsRawFile(objects, 0, nil))},
		{"a scan begun at a damaged reference met while a page was read", readsRawFile(objects, 7, nil)},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := extract(t, c.data)
			if out, ok := readsPoppler(t, c.data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal == nil || r.Fatal.Code != "pdf-malformed" || r.Fatal.Message != boundMessage {
				t.Errorf("fatal %+v pages %+v; the scan met a bound reading the file, and rebuilding does not drop it", r.Fatal, r.Pages)
			}
		})
	}
	// The bound the scan met is the file's and not the cross-reference's: a
	// scan reads the file, and what it meets is no defect of the
	// cross-reference it is replacing.
	d := openGenerated(t, readsRawFile(objects, 7, nil))
	if _, read := d.resolveRead(ref{7, 0}); read {
		t.Fatal("the damaged reference was read without the scan")
	}
	if d.fileBound == nil || d.bound != nil {
		t.Errorf("the scan left the file's bound %v and the cross-reference's %v; the bound a scan meets is the file's", d.fileBound, d.bound)
	}
}

// readsHelvetica is a simple font whose code 65 shows the glyph given, so
// that a page showing "A" reads as that glyph and says which of a file's
// definitions the record was read under.
func readsHelvetica(glyph string) string {
	return "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding << /Differences [65 /" + glyph + "] >> >>"
}

// Reading a page's content may rebuild the cross-reference, and the bytes it
// gives back are then the content of a page this document no longer has: the
// resources the walk gathered beside them name objects it no longer has
// either. Nothing of that page is interpreted -- the font the old page named
// is not resolved, and the bound that resolving it would meet is not this
// document's -- and the reading begins again on the rebuilt one.
func TestReadsAPageWhoseContentRebuildsIsNotInterpreted(t *testing.T) {
	old := shown("A", 700)
	data := readsRawFile([]readsObject{
		{1, "<< /Type /Catalog /Pages 2 0 R >>"},
		{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
		// The old page: a font nested past what the parser admits, and a
		// content stream whose length is a damaged reference.
		{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
		{6, "<< /Length 8 0 R >>\nstream\n" + old + "endstream"},
		{7, readsOverNested()},
		{8, fmt.Sprint(len(old))},
		// The final definitions: a page whose font and content are the
		// rebuilt document's.
		{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 9 0 R >> >> /Contents 10 0 R >>"},
		{9, readsHelvetica("Z")},
		{10, readsStreamObject("", shown("A", 700))},
	}, 8, nil)
	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil {
		t.Fatalf("fatal %+v; the bound lies in a font the rebuilt page does not name", r.Fatal)
	}
	if len(r.Pages) != 1 || r.Pages[0].Text != "Z" || r.Pages[0].Status != PageOK || len(r.Problems) != 0 {
		t.Errorf("the record reads %+v with problems %+v, want one page reading %q", r.Pages, r.Problems, "Z")
	}
}

// A walk that meets a rebuild is a walk of a page tree this document no
// longer has. It ends there -- the nodes after the one that rebuilt are not
// this walk's to count -- and the pages it gathered are not extracted at all:
// reading them would spend on a discarded tree what the reading that follows
// needs, and would meet in it defects that are no defects of the document the
// record carries.
func TestReadsAWalkThatRebuildsIsNotExtracted(t *testing.T) {
	content := shown("Z", 700)
	blank := strings.Repeat(" ", 200)
	for _, c := range []struct {
		name    string
		objects []readsObject
		broken  int
		// readings is how many times the page the rebuilt document holds may
		// be inflated, and inTheWalk says the rebuild is met walking the tree
		// rather than looking for its root: the walk ends at the one and is a
		// walk of the rebuilt tree in the other.
		readings  int
		inTheWalk bool
	}{
		{"a discarded page whose content inflates past what is left", []readsObject{
			{1, "<< /Type /Catalog /Pages 2 0 R >>"},
			{2, "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>"},
			{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
			{4, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 10 0 R >>"},
			{6, readsStreamObject("/Filter /FlateDecode", string(flateOf([]byte(content))))},
			{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"},
			{10, readsStreamObject("/Filter /FlateDecode", string(flateOf([]byte(blank))))},
			{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
		}, 4, 2, true},
		{"a discarded page naming a font nested past the parser", []readsObject{
			{1, "<< /Type /Catalog /Pages 2 0 R >>"},
			{2, "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>"},
			{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 11 0 R >> >> /Contents 6 0 R >>"},
			{4, "<< /Type /Page /Parent 2 0 R /Contents 6 0 R >>"},
			{6, readsStreamObject("/Filter /FlateDecode", string(flateOf([]byte(content))))},
			{11, readsOverNested()},
			{2, "<< /Type /Pages /Kids [12 0 R] /Count 1 >>"},
			{12, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 13 0 R >>"},
			{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"},
			{13, readsStreamObject("/Filter /FlateDecode", string(flateOf([]byte(content))))},
		}, 4, 2, true},
		{"a tree whose root was found under the cross-reference the catalog rebuilt", []readsObject{
			{1, "<< /Type /Catalog /Pages 2 0 R >>"},
			{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
			{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
			{6, readsStreamObject("/Filter /FlateDecode", string(flateOf([]byte(content))))},
			{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"},
		}, 1, 1, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsRawFile(c.objects, c.broken, nil)
			// The allowance is what the pages the rebuilt document holds take
			// to read once, or twice where the discarded tree holds a second
			// page: reading a discarded page leaves the reading that follows
			// short of what it needs.
			opt := testOptions()
			opt.MaxInflateTotal = int64(c.readings * len(content))
			opt.MaxInflateOne = opt.MaxInflateTotal
			r := Extract(context.Background(), data, opt)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil {
				t.Fatalf("fatal %+v; the rebuilt tree holds one page the reader reads whole", r.Fatal)
			}
			if len(r.Pages) != 1 || r.Pages[0].Text != "Z" || r.Pages[0].Status != PageOK || len(r.Problems) != 0 {
				t.Errorf("the record reads %+v with problems %+v, want one page reading %q", r.Pages, r.Problems, "Z")
			}
			// The walk itself: where the rebuild was met walking the tree it
			// ends there and hands back no pages, so there is no discarded
			// page list to extract; where it was met looking for the root the
			// walk is of the rebuilt tree, and the generation it began on is
			// what tells the caller to read the document again.
			doc := openGenerated(t, data)
			w, generation, stop := walkPages(context.Background(), doc, testOptions(), &Result{})
			if doc.generation == generation {
				t.Fatal("reading the tree did not rebuild the cross-reference")
			}
			if c.inTheWalk && (stop == nil || w != nil) {
				t.Errorf("the walk ended with %v and handed back %+v; a walk that met a rebuild ends there", stop, w)
			}
			if !c.inTheWalk && (stop != nil || w == nil) {
				t.Errorf("the walk ended with %v and handed back %+v; the rebuild was met before it began", stop, w)
			}
		})
	}
}

// readsCommentedJPEG is a JPEG a decoder reads whole whose markers are many:
// the comment segments before its frame carry nothing, and walking them is
// the work the marker loop does.
func readsCommentedJPEG(t *testing.T, segments int) []byte {
	t.Helper()
	var raw bytes.Buffer
	if err := jpeg.Encode(&raw, image.NewGray(image.Rect(0, 0, 8, 8)), nil); err != nil {
		t.Fatal(err)
	}
	src := raw.Bytes()
	out := append([]byte{}, src[:2]...)
	for i := 0; i < segments; i++ {
		out = append(out, 0xFF, 0xFE, 0x00, 0x02)
	}
	return append(out, src[2:]...)
}

// readsLongScanJPEG is a JPEG a decoder reads whole whose markers are few and
// whose entropy-coded data is long: walking it is the work the scan loop
// does, and the marker loop does almost none of it.
func readsLongScanJPEG(t *testing.T) []byte {
	t.Helper()
	img := image.NewGray(image.Rect(0, 0, 512, 512))
	for i := range img.Pix {
		// A pattern no two blocks of which are alike, so that the encoder
		// writes a long scan rather than a short one repeated.
		img.Pix[i] = byte(i*i>>7 ^ i>>2)
	}
	var raw bytes.Buffer
	if err := jpeg.Encode(&raw, img, nil); err != nil {
		t.Fatal(err)
	}
	return raw.Bytes()
}

// readsEmptyDeflateBlocks is deflate data of n blocks that decode to nothing:
// each is a fixed-Huffman block holding the end-of-block code alone -- three
// bits of header and seven of code -- so the data is handed to the decoder a
// byte at a time and no block of bytes is ever copied out of it.
func readsEmptyDeflateBlocks(n int) []byte {
	var out []byte
	var acc uint32
	var bits uint
	put := func(v uint32, width uint) {
		acc |= v << bits
		bits += width
		for bits >= 8 {
			out = append(out, byte(acc))
			acc >>= 8
			bits -= 8
		}
	}
	for i := 0; i < n; i++ {
		final := uint32(0)
		if i == n-1 {
			final = 1
		}
		put(final, 1)
		put(1, 2)
		put(0, 7)
	}
	if bits > 0 {
		out = append(out, byte(acc))
	}
	return out
}

// Each loop that walks an inline image's encoded bytes reads the deadline for
// itself. The three below are the loops another loop's reading would
// otherwise stand for: a JPEG's markers, a JPEG's entropy-coded data and a
// deflate stream handed over a byte at a time. Each fixture walks one of them
// and barely touches the others, so a reading removed from one is a fixture
// framed whole past a deadline that had already passed.
func TestReadsEveryFramingLoopReadsTheDeadlineForItself(t *testing.T) {
	comments := readsCommentedJPEG(t, 2*entriesPerCheck)
	scan := readsLongScanJPEG(t)
	blocks := readsEmptyDeflateBlocks(3 * entriesPerCheck)
	for _, c := range []struct {
		name string
		data []byte
		read func(*Document, []byte) error
	}{
		{"the markers of a JPEG of many comment segments", comments, func(d *Document, data []byte) error {
			_, err := d.jpegFraming(data)
			return err
		}},
		{"the entropy-coded data of a JPEG of few markers", scan, func(d *Document, data []byte) error {
			_, err := d.jpegFraming(data)
			return err
		}},
		{"the bytes of a deflate stream of empty blocks", blocks, func(d *Document, data []byte) error {
			_, _, err := d.deflateConsumed(data)
			return err
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := budgeted(1<<20, 1<<20)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			d.ctx = ctx
			// The cadence stands at nothing: the loop that walks these bytes
			// is the one that reaches the first reading of the clock.
			d.checks = 0
			if err := c.read(d, c.data); !isDeadline(err) {
				t.Errorf("framing %d bytes ended with %v; the deadline had passed before it began", len(c.data), err)
			}
		})
	}
	// The fixtures are what they say they are: two a decoder reads whole, and
	// one that is deflate data decoding to nothing.
	for _, c := range []struct {
		name string
		data []byte
	}{{"the JPEG of many comment segments", comments}, {"the JPEG of few markers", scan}} {
		if _, err := jpeg.Decode(bytes.NewReader(c.data)); err != nil {
			t.Errorf("%s is not a JPEG a decoder reads: %v", c.name, err)
		}
	}
	if len(scan) < 4*entriesPerCheck {
		t.Errorf("the JPEG of few markers is %d bytes; its scan is walked past the cadence of %d", len(scan), entriesPerCheck)
	}
	out, err := io.ReadAll(flate.NewReader(bytes.NewReader(blocks)))
	if err != nil || len(out) != 0 {
		t.Errorf("the deflate blocks decode to %d bytes, %v; they are data that decodes to nothing", len(out), err)
	}
}

// A FlateDecode stream is the whole zlib wrapper, its two header bytes
// included: data whose header is no zlib header is no such stream, whatever
// the deflate data and the checksum after it hold. The fixture below is a
// valid stored block carrying the image's samples, with the checksum those
// samples make, behind a header the encoding does not admit.
func TestReadsFlateFramingNeedsItsOwnHeader(t *testing.T) {
	whole := readsStoredFlate([]byte("SAMPLES"))
	damaged := append([]byte{}, whole...)
	damaged[0], damaged[1] = 0x79, 0x01
	for _, c := range []struct {
		name    string
		samples []byte
		want    string
	}{
		{"the header the encoding gives it", whole, "before\nafter"},
		{"a header no zlib stream has", damaged, ""},
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
			status, problems := PageOK, 0
			if c.want == "" {
				status, problems = PageFailed, 1
			}
			if r.Pages[0].Text != c.want || r.Pages[0].Status != status || len(r.Problems) != problems {
				t.Errorf("the record reads %s %q with problems %+v, want %s %q", r.Pages[0].Status, r.Pages[0].Text, r.Problems, status, c.want)
			}
			if c.want == "" && len(r.Problems) == 1 && r.Problems[0].Code != "pdf-page-failed" {
				t.Errorf("problems %+v", r.Problems)
			}
		})
	}
}

// readsFramedEncodings is a complete encoding for each of the seven filters an
// inline image may be framed by, under the dictionary that declares it.
func readsFramedEncodings(t *testing.T) []struct {
	name, dict string
	samples    []byte
} {
	t.Helper()
	return []struct {
		name, dict string
		samples    []byte
	}{
		{"ASCIIHexDecode", "/W 4 /H 4 /BPC 8 /CS /G /F /AHx", hexStreamOf([]byte("SAMPLES"))},
		{"ASCII85Decode", "/W 4 /H 4 /BPC 8 /CS /G /F /A85", a85Of([]byte("SAMPLES"))},
		{"RunLengthDecode", "/W 4 /H 4 /BPC 8 /CS /G /F /RL", runLengthOf([]byte("SAMPLES"))},
		{"FlateDecode", "/W 4 /H 4 /BPC 8 /CS /G /F /Fl", readsStoredFlate([]byte("SAMPLES"))},
		{"LZWDecode", "/W 4 /H 4 /BPC 8 /CS /G /F /LZW /DP << /EarlyChange 0 >>", lzwOf([]byte("SAMPLES"))},
		{"DCTDecode", "/W 8 /H 8 /BPC 8 /CS /G /F /DCT", readsJPEG()},
		{"CCITTFaxDecode", "/W 8 /H 1 /BPC 1 /CS /G /F /CCF /DP << /K -1 /Columns 8 /Rows 1 >>",
			readsBits("1" + strings.Repeat(readsEOL, 2))},
	}
}

// An image is the encoding the file gives it and the "EI" that stands where
// that encoding ends. An encoding complete to its own end with operators
// after it and no EI, or with an EI only past those operators, is an image
// whose end the file states twice over: the page fails rather than the reader
// reading the operators between as the page's -- they lie where the image's
// data would have to end, and the file does not say which it is.
func TestReadsAFramedImageEndsAtItsEncodingAndTheEIThere(t *testing.T) {
	for _, c := range readsFramedEncodings(t) {
		for _, where := range []struct{ name, after string }{
			{"no EI after the encoding", shown("after", 680)},
			{"an EI after the operators", shown("after", 680) + "EI\n" + shown("last", 660)},
		} {
			t.Run(c.name+", "+where.name, func(t *testing.T) {
				var content bytes.Buffer
				content.WriteString(shown("before", 700))
				content.WriteString("BI " + c.dict + " ID ")
				content.Write(c.samples)
				content.WriteString("\n")
				content.WriteString(where.after)
				data := readsContentPage(content.Bytes())
				r := extract(t, data)
				if out, ok := readsPoppler(t, data); ok {
					t.Logf("pdftotext reads %q", out)
				}
				if r.Fatal != nil || len(r.Pages) != 1 {
					t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
				}
				if r.Pages[0].Status != PageFailed || r.Pages[0].Text != "" || len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" {
					t.Errorf("the record reads %s %q with problems %+v; the EI does not stand where %s ends",
						r.Pages[0].Status, r.Pages[0].Text, r.Problems, c.name)
				}
			})
		}
	}
}

// What a framing decodes is charged to the document's inflate budget as it
// goes, and the charge stands for the images after it: two images each within
// what one stream may inflate to are past the budget together, and the second
// fails at the bound the first left it. What the failed framing decoded is
// charged too -- the reader read it -- so a file is not handed the room it
// spent.
func TestReadsFramingChargesEveryImageItDecodes(t *testing.T) {
	samples := []byte("SAMPLES")
	// The framings themselves: seven bytes decoded, then a bound three bytes
	// from the total, which the second framing meets and is charged for.
	d := budgeted(10, 100)
	if _, err := d.flateFraming(readsStoredFlate(samples)); err != nil {
		t.Fatalf("framing the first image: %v", err)
	}
	if d.budget.used != int64(len(samples)) {
		t.Errorf("the first image charged %d of the budget, want %d", d.budget.used, len(samples))
	}
	if _, err := d.lzwFraming(lzwOf(samples), false); !errors.Is(err, errInflateBound) {
		t.Errorf("framing the second image ended with %v, want the bound", err)
	}
	if d.budget.used != 10 {
		t.Errorf("the budget holds %d of 10 charged after the bound; what a framing decoded is charged whether or not it ended", d.budget.used)
	}
	// The page: both images decode to fewer bytes than one stream may, and
	// past what the document may inflate together.
	var content bytes.Buffer
	content.WriteString(shown("before", 700))
	content.WriteString("BI /W 7 /H 1 /BPC 8 /CS /G /F /Fl ID ")
	content.Write(readsStoredFlate(samples))
	content.WriteString(" EI\n")
	content.WriteString("BI /W 7 /H 1 /BPC 8 /CS /G /F /LZW /DP << /EarlyChange 0 >> ID ")
	content.Write(lzwOf(samples))
	content.WriteString(" EI\n")
	content.WriteString(shown("after", 680))
	data := readsContentPage(content.Bytes())
	opt := testOptions()
	opt.MaxInflateTotal, opt.MaxInflateOne = 10, 100
	r := Extract(context.Background(), data, opt)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if r.Pages[0].Status != PageFailed || r.Pages[0].Text != "" || len(r.Problems) != 1 || r.Problems[0].Code != "stream-over-bound" {
		t.Errorf("the record reads %s %q with problems %+v; the two images inflate past what the document may",
			r.Pages[0].Status, r.Pages[0].Text, r.Problems)
	}
}

// Fax data whose /DecodeParms turns the end-of-block off carries no end of
// its own, and the reader does not frame it -- whatever its bytes hold. The
// image below ends its one row with a complete end-of-facsimile-block, and an
// EI stands where that block ends: the declaration is what the reader answers
// to, since a writer that turned the end-of-block off may have written data
// that holds none, and the page fails rather than the reader taking a
// boundary the file says is not there.
func TestReadsFaxWithTheEndOfBlockOffIsNotFramed(t *testing.T) {
	bits := readsBits("1" + strings.Repeat(readsEOL, 2))
	// The framing itself: the declaration is refused before the bytes are
	// walked, and the same bytes are framed where the declaration is absent.
	d := budgeted(1<<20, 1<<20)
	if _, err := d.ccittFraming(Dict{"K": int64(-1), "EndOfBlock": false}, bits); !errors.Is(err, errFilterNotFramed) {
		t.Errorf("framing data whose end-of-block is turned off ended with %v, want a filter the reader does not frame", err)
	}
	if n, err := d.ccittFraming(Dict{"K": int64(-1)}, bits); err != nil || n != len(bits) {
		t.Errorf("framing the same bytes without that declaration gave %d, %v, want %d", n, err, len(bits))
	}
	for _, c := range []struct{ name, parms, want string }{
		{"the end-of-block as the file has it", "/K -1 /Columns 8 /Rows 1", "before\nafter"},
		{"the end-of-block turned off", "/K -1 /Columns 8 /Rows 1 /EndOfBlock false", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			var content bytes.Buffer
			content.WriteString(shown("before", 700))
			content.WriteString("BI /W 8 /H 1 /BPC 1 /CS /G /F /CCF /DP << " + c.parms + " >> ID ")
			content.Write(bits)
			content.WriteString(" EI\n")
			content.WriteString(shown("after", 680))
			data := readsContentPage(content.Bytes())
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
			if c.want == "" && len(r.Problems) == 1 && r.Problems[0].Code != "pdf-page-failed" {
				t.Errorf("problems %+v", r.Problems)
			}
		})
	}
}

// A framing stopped at the inflate bound is charged the room it had: the
// write the bound refused leaves the budget spent to its limit rather than at
// what the writes before it held, so an image the bound stopped hands the
// file back nothing. The two images below each decode seven bytes under a
// ten-byte total, and what the second was charged is what is left for a third.
func TestReadsAFramingStoppedAtTheBoundIsChargedTheRoomItHad(t *testing.T) {
	samples := []byte("SAMPLES")
	d := budgeted(10, 100)
	if _, err := d.flateFraming(readsStoredFlate(samples)); err != nil {
		t.Fatalf("framing the first image: %v", err)
	}
	if d.budget.used != int64(len(samples)) {
		t.Fatalf("the first image charged %d of the budget, want %d", d.budget.used, len(samples))
	}
	if _, err := d.flateFraming(readsStoredFlate(samples)); !errors.Is(err, errInflateBound) {
		t.Errorf("framing the second image ended with %v, want the bound", err)
	}
	if d.budget.used != 10 {
		t.Errorf("the budget holds %d of 10 charged after the bound; the room the refused write had is charged with the writes before it", d.budget.used)
	}
	if _, err := d.flateFraming(readsStoredFlate([]byte("ABC"))); !errors.Is(err, errInflateBound) {
		t.Errorf("framing a third image of three bytes ended with %v; the bound the second image met leaves nothing for it", err)
	}
}

// Framing an image decodes it, which is a stream's work: the deadline is read
// before that work begins, as it is before a form is read, and not only on the
// cadence a framing's own loop reads it at. The image below is three bytes
// complete -- its framing reaches no reading of its own -- and the deadline
// that had passed before it began is what the page meets.
func TestReadsAnInlineImageReadsTheDeadlineBeforeItIsFramed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := budgeted(1<<20, 1<<20)
	d.ctx = ctx
	// The cadence stands at nothing: the first reading of the clock within a
	// framing lies a whole cadence away, and three bytes do not reach it.
	d.checks = 0
	it := &interp{d: d, ctx: ctx}
	lex := newLexer([]byte("/W 1 /H 1 /BPC 8 /CS /G /F /AHx ID 41>\nEI\n"), 0)
	if err := it.skipInlineImage(lex, nil); !isDeadline(err) {
		t.Errorf("the image was skipped with %v; the deadline had passed before it was framed", err)
	}
}

// A framing begins by asking the budget for the output it charges what it
// decodes to, and takes the answer: with nothing left of the allowance there
// is no output to decode into, and the framing ends at the bound rather than
// walking an encoding whose bytes it could not charge. Both encodings below
// are complete and decode to nothing at all, so only the answer to that
// question stands between them and an end.
func TestReadsAFramingWithNothingLeftToInflateMeetsTheBound(t *testing.T) {
	for _, c := range []struct {
		name  string
		frame func(*Document) error
	}{
		{"a Flate encoding that decodes to nothing", func(d *Document) error {
			_, err := d.flateFraming(flateOf(nil))
			return err
		}},
		{"an LZW encoding that decodes to nothing", func(d *Document) error {
			_, err := d.lzwFraming(lzwOf(nil), false)
			return err
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			// Nothing left of the total, under a per-stream bound that would
			// hold the encoding: what a framing may inflate is what is left.
			d := budgeted(7, 1<<20)
			d.budget.used = 7
			if err := c.frame(d); !errors.Is(err, errInflateBound) {
				t.Errorf("the framing ended with %v, want the bound", err)
			}
			if err := c.frame(budgeted(1<<20, 1<<20)); err != nil {
				t.Errorf("the framing of the same bytes with the allowance whole ended with %v", err)
			}
		})
	}
}

// The bound an output meets is the answer both framings that decode give
// their caller: a page whose first image spends what the document may inflate
// leaves the second nothing to decode into, and the record says a stream of
// the page went past the bound -- whatever the second image's encoding decodes
// to, an encoding that decodes to nothing at all included.
func TestReadsASecondImageWithNothingLeftToInflateFailsThePage(t *testing.T) {
	for _, c := range []struct {
		name, dict string
		samples    []byte
	}{
		{"a Flate encoding that decodes to nothing", "/W 1 /H 1 /BPC 8 /CS /G /F /Fl", flateOf(nil)},
		{"an LZW encoding that decodes to nothing", "/W 1 /H 1 /BPC 8 /CS /G /F /LZW /DP << /EarlyChange 0 >>", lzwOf(nil)},
	} {
		t.Run(c.name, func(t *testing.T) {
			var content bytes.Buffer
			content.WriteString(shown("before", 700))
			content.WriteString("BI /W 7 /H 1 /BPC 8 /CS /G /F /Fl ID ")
			content.Write(readsStoredFlate([]byte("SAMPLES")))
			content.WriteString(" EI\n")
			content.WriteString("BI " + c.dict + " ID ")
			content.Write(c.samples)
			content.WriteString(" EI\n")
			content.WriteString(shown("after", 680))
			data := readsContentPage(content.Bytes())
			opt := testOptions()
			opt.MaxInflateTotal, opt.MaxInflateOne = 7, 100
			r := Extract(context.Background(), data, opt)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if r.Pages[0].Status != PageFailed || r.Pages[0].Text != "" || len(r.Problems) != 1 || r.Problems[0].Code != "stream-over-bound" {
				t.Errorf("the record reads %s %q with problems %+v; the first image left the second nothing to inflate into",
					r.Pages[0].Status, r.Pages[0].Text, r.Problems)
			}
		})
	}
}

// What one stream may inflate to bounds a framing on its own, and not only
// what the document may inflate in total: an image that decodes to eleven
// bytes under a ten-byte per-stream bound stops at that bound with a hundred
// bytes of the total unspent, and the page fails at the bound it met.
func TestReadsAFramingIsBoundedByWhatOneStreamMayInflate(t *testing.T) {
	eleven := []byte("ELEVENBYTES")
	for _, c := range []struct {
		name, dict string
		samples    []byte
		frame      func(*Document, []byte) error
	}{
		{"FlateDecode", "/W 11 /H 1 /BPC 8 /CS /G /F /Fl", readsStoredFlate(eleven), func(d *Document, data []byte) error {
			_, err := d.flateFraming(data)
			return err
		}},
		{"LZWDecode", "/W 11 /H 1 /BPC 8 /CS /G /F /LZW /DP << /EarlyChange 0 >>", lzwOf(eleven), func(d *Document, data []byte) error {
			_, err := d.lzwFraming(data, false)
			return err
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			// The framing itself: ten bytes of the hundred the document may
			// inflate are charged, and the eleventh is past what one stream may.
			d := budgeted(100, 10)
			if err := c.frame(d, c.samples); !errors.Is(err, errInflateBound) {
				t.Errorf("framing an image of eleven bytes ended with %v, want the bound", err)
			}
			if d.budget.used != 10 {
				t.Errorf("the framing charged %d bytes, want the ten one stream may inflate", d.budget.used)
			}
			opt := testOptions()
			opt.MaxInflateTotal, opt.MaxInflateOne = 100, 10
			data := readsInlineImagePage(c.dict, c.samples, shown("REAL", 700))
			r := Extract(context.Background(), data, opt)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if r.Pages[0].Status != PageFailed || r.Pages[0].Text != "" || len(r.Problems) != 1 || r.Problems[0].Code != "stream-over-bound" {
				t.Errorf("the record reads %s %q with problems %+v; the image inflates past what one stream may",
					r.Pages[0].Status, r.Pages[0].Text, r.Problems)
			}
		})
	}
}

// Base-85 data ends at the two bytes "~>" and nowhere else: a tilde with any
// other byte after it ends nothing, and data walked to its end without that
// pair holds no end at all. An image the file ends the first way fails its
// page -- the tilde is where the encoding says the data ends, and the file
// contradicts itself there.
func TestReadsBase85EndsAtTheTildeAndItsPartner(t *testing.T) {
	// The framing itself: five characters with no terminator are data whose
	// end the reader has not been given.
	d := budgeted(1<<20, 1<<20)
	if n, err := d.ascii85Framing([]byte("!!!!!")); !errors.Is(err, errFilterUnended) || n != 0 {
		t.Errorf("framing five characters with no terminator gave %d, %v, want data that holds no end", n, err)
	}
	if n, err := d.ascii85Framing([]byte("!!!!!~>")); err != nil || n != 7 {
		t.Errorf("framing the same characters with their terminator gave %d, %v, want 7", n, err)
	}
	content := shown("before", 700) + "BI /W 4 /H 1 /BPC 8 /CS /G /F /A85 ID !!!!!~!\nEI\n" + shown("after", 680)
	data := readsContentPage([]byte(content))
	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if r.Pages[0].Status != PageFailed || r.Pages[0].Text != "" || len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" {
		t.Errorf("the record reads %s %q with problems %+v; a tilde whose partner is not '>' ends nothing",
			r.Pages[0].Status, r.Pages[0].Text, r.Problems)
	}
}

// Base-85 data that fills the bytes the reader may read of one image without
// ending has met that bound, and the bound is what the record says: the last
// byte of the window is no end, whatever stands immediately past it. The "EI"
// below stands at the first byte beyond the window, where a reader that took
// the window's end for the encoding's would find it.
func TestReadsBase85FillingTheInputWindowIsThatBound(t *testing.T) {
	if testing.Short() {
		t.Skip("writes an inline image of sixteen megabytes")
	}
	samples := bytes.Repeat([]byte{'!'}, maxInlineImageBytes)
	data := readsInlineImagePage("/W 1 /H 1 /BPC 8 /CS /G /F /A85", samples, shown("REAL", 700))
	opt := testOptions()
	opt.MaxInflateOne, opt.MaxInflateTotal = 64<<20, 64<<20
	r := Extract(context.Background(), data, opt)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	want := "the content of page 1 is past a structure bound the reader holds"
	if r.Pages[0].Status != PageFailed || len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" || r.Problems[0].Message != want {
		t.Errorf("pages %+v problems %+v; the encoding held no end within the bytes the reader may read of one image", r.Pages, r.Problems)
	}
}

// A final group of fewer than five characters stands for its characters
// completed with 'u', the largest the alphabet has, and a group the
// completion carries past a four-byte word is a group no four bytes encode.
// The three below each fit a word when completed with zeros and pass it when
// completed as 7.4.3 completes them.
func TestReadsBase85FinalGroupsAreCompletedWithTheLargestDigit(t *testing.T) {
	for _, c := range []struct{ name, samples string }{
		{"a final group of two characters", "!!!!!s8~>"},
		{"a final group of three characters", "!!!!!s8W~>"},
		{"a final group of four characters", "!!!!!s8W-~>"},
	} {
		t.Run(c.name, func(t *testing.T) {
			content := shown("before", 700) + "BI /W 4 /H 1 /BPC 8 /CS /G /F /A85 ID " + c.samples + " EI\n" + shown("after", 680)
			data := readsContentPage([]byte(content))
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if r.Pages[0].Status != PageFailed || r.Pages[0].Text != "" || len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" {
				t.Errorf("the record reads %s %q with problems %+v; the group's completion carries it past the largest word",
					r.Pages[0].Status, r.Pages[0].Text, r.Problems)
			}
		})
	}
}

// Hexadecimal data admits the white space of 7.2.3 wherever it falls, all six
// bytes of it: an image whose two digits are parted by every one of them is
// one sample, and the page is read as the page shows it.
func TestReadsHexadecimalDataAdmitsEveryWhiteSpaceByte(t *testing.T) {
	samples := append([]byte{'4', 0x00, '\t', '\n', '\f', '\r', ' '}, "1>"...)
	data := readsInlineImagePage("/W 1 /H 1 /BPC 8 /CS /G /F /AHx", samples, shown("REAL", 700))
	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if r.Pages[0].Status != PageOK || r.Pages[0].Text != "REAL" || len(r.Problems) != 0 {
		t.Errorf("the record reads %s %q with problems %+v, want %s %q; white space stands anywhere in hexadecimal data",
			r.Pages[0].Status, r.Pages[0].Text, r.Problems, PageOK, "REAL")
	}
}

// A zlib header is two bytes, and bytes that cannot hold two are no header:
// the reader says so of them rather than reading bytes it was not given. The
// whole wrapper ends with the four bytes of the checksum, and a wrapper whose
// checksum is cut short is one whose end the reader has not been given --
// whatever the bytes past what it was handed happen to hold.
func TestReadsFlateFramingNeedsTheWholeWrapperWithinTheBytesItHas(t *testing.T) {
	for _, c := range []struct {
		name string
		data []byte
	}{
		{"no bytes at all", nil}, {"one byte", []byte{0x78}}, {"the two a header takes", []byte{0x78, 0x01}},
	} {
		if got, want := zlibHeader(c.data), len(c.data) == 2; got != want {
			t.Errorf("%s: zlibHeader is %v, want %v", c.name, got, want)
		}
	}
	// The bytes past the slice are the checksum the wrapper was written with:
	// a reader that read them would take this for a wrapper that ends.
	whole := readsStoredFlate([]byte("SAMPLES"))
	short := whole[:len(whole)-2]
	d := budgeted(1<<20, 1<<20)
	if n, err := d.flateFraming(short); !errors.Is(err, errFilterUnended) || n != 0 {
		t.Errorf("framing a wrapper whose checksum is two bytes short gave %d, %v, want data that holds no end", n, err)
	}
	if n, err := d.flateFraming(whole); err != nil || n != len(whole) {
		t.Errorf("framing the whole wrapper gave %d, %v, want %d", n, err, len(whole))
	}
}

// readsStoredFlateBlocks is a zlib stream of stored deflate blocks whose
// whole wrapper -- two header bytes, the blocks, and the four bytes of the
// checksum of what they decode to -- is exactly the number of bytes given. A
// stored block holds at most 65,535 bytes and takes five of its own, so the
// blocks are as many as that length needs.
func readsStoredFlateBlocks(t *testing.T, whole int) []byte {
	t.Helper()
	const most = 65535
	payload := 0
	for blocks := 1; ; blocks++ {
		payload = whole - 6 - 5*blocks
		if payload < 1 {
			t.Fatalf("no number of stored blocks makes a wrapper of %d bytes", whole)
		}
		if (payload+most-1)/most == blocks {
			break
		}
	}
	data := make([]byte, payload)
	for i := range data {
		data[i] = byte('A' + i%26)
	}
	out := make([]byte, 0, whole)
	out = append(out, 0x78, 0x01)
	for at := 0; at < payload; at += most {
		n := min(most, payload-at)
		final := byte(0)
		if at+n == payload {
			final = 1
		}
		out = append(out, final, byte(n), byte(n>>8), byte(^n), byte(^n>>8))
		out = append(out, data[at:at+n]...)
	}
	a, b := uint32(1), uint32(0)
	for _, x := range data {
		a = (a + uint32(x)) % 65521
		b = (b + a) % 65521
	}
	sum := b<<16 | a
	out = append(out, byte(sum>>24), byte(sum>>16), byte(sum>>8), byte(sum))
	if len(out) != whole {
		t.Fatalf("the wrapper is %d bytes, want %d", len(out), whole)
	}
	return out
}

// A wrapper whose last two checksum bytes lie past the bytes the reader may
// read of one image is a wrapper the reader was not given the end of, and the
// record says which bound the page met. The image below is the window and two
// bytes: the deflate data within it ends cleanly, and only the checksum the
// reader would have to read to believe in that end lies beyond.
func TestReadsAFlateChecksumPastTheInputWindowIsThatBound(t *testing.T) {
	if testing.Short() {
		t.Skip("writes an inline image of sixteen megabytes")
	}
	samples := readsStoredFlateBlocks(t, maxInlineImageBytes+2)
	data := readsInlineImagePage("/W 1 /H 1 /BPC 8 /CS /G /F /Fl", samples, shown("REAL", 700))
	opt := testOptions()
	opt.MaxInflateOne, opt.MaxInflateTotal = 64<<20, 64<<20
	r := Extract(context.Background(), data, opt)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	want := "the content of page 1 is past a structure bound the reader holds"
	if r.Pages[0].Status != PageFailed || len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" || r.Problems[0].Message != want {
		t.Errorf("pages %+v problems %+v; the checksum that would end the wrapper lies past the bytes the reader may read", r.Pages, r.Problems)
	}
}

// readsLZWEarly is LZW data written the way a PDF writer writes it unless the
// stream says otherwise: each byte given is one literal code, and the codes
// grow one code before the table needs the width -- /EarlyChange 1, which a
// stream that gives no parameters means. The table grows here as the reader
// grows it, so the width each code is written at is the width it is read at.
func readsLZWEarly(data []byte) []byte { return readsLZWCodes(data, 1) }

// readsLZWCodes is readsLZWEarly with the code length changed one code early
// where delta is 1 and at the width's own bound where it is 0: what a stream
// declaring /EarlyChange 0 is written as. Either way one code stands for each
// byte given, so the codes cross the widths a shorter encoding never reaches.
func readsLZWCodes(data []byte, delta int) []byte {
	w := &readsBitWriter{}
	width, next, first := 9, 258, true
	put := func(code int) {
		w.put(code, width)
		if !first && next < 4096 {
			next++
		}
		first = false
		if next+delta >= 1<<uint(width) && width < 12 {
			width++
		}
	}
	for _, b := range data {
		put(int(b))
	}
	// The end-of-data code stands at the width the codes before it left.
	w.put(257, width)
	return w.done()
}

// LZW's codes grow one code before the table is full where the stream does not
// say otherwise: /EarlyChange is 1 by default, and a reader that grew them a
// code late would read every code after the first change at a width the writer
// did not write it at. The image below crosses both changes -- 254 codes nine
// bits wide, 512 ten bits wide, and the rest eleven -- and the same samples
// written the other way stand beside it.
func TestReadsLZWCodesGrowAsTheEarlyChangeSays(t *testing.T) {
	samples := make([]byte, 900)
	for i := range samples {
		samples[i] = byte('A' + i%26)
	}
	for _, c := range []struct {
		name, parms string
		encoded     []byte
		early       bool
	}{
		{"the early change a stream that declares nothing means", "", readsLZWEarly(samples), true},
		{"the early change declared", " /DP << /EarlyChange 1 >>", readsLZWEarly(samples), true},
		{"the early change turned off", " /DP << /EarlyChange 0 >>", lzwOf(samples), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			// The framing itself: the codes end at the end-of-data code, and
			// the bytes they took are the image's.
			d := budgeted(1<<20, 1<<20)
			if n, err := d.lzwFraming(c.encoded, c.early); err != nil || n != len(c.encoded) {
				t.Errorf("framing gave %d, %v, want %d", n, err, len(c.encoded))
			}
			content := shown("before", 700) + "BI /W 900 /H 1 /BPC 8 /CS /G /F /LZW" + c.parms + " ID " +
				string(c.encoded) + " EI\n" + shown("after", 680)
			data := readsContentPage([]byte(content))
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if r.Pages[0].Status != PageOK || r.Pages[0].Text != "before\nafter" || len(r.Problems) != 0 {
				t.Errorf("the record reads %s %q with problems %+v, want %s %q", r.Pages[0].Status, r.Pages[0].Text, r.Problems, PageOK, "before\nafter")
			}
		})
	}
}

// An inline image's decode parameters may be written as an array with nothing
// in it, which says of the one filter what a dictionary the stream leaves out
// says: nothing. The image below is framed under the defaults, and the page is
// read as it shows.
func TestReadsAnEmptyDecodeParameterArrayDeclaresNothing(t *testing.T) {
	samples := readsLZWEarly([]byte("SAMPLES"))
	content := shown("before", 700) + "BI /W 7 /H 1 /BPC 8 /CS /G /F /LZW /DP [] ID " +
		string(samples) + " EI\n" + shown("after", 680)
	data := readsContentPage([]byte(content))
	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if r.Pages[0].Status != PageOK || r.Pages[0].Text != "before\nafter" || len(r.Problems) != 0 {
		t.Errorf("the record reads %s %q with problems %+v, want %s %q", r.Pages[0].Status, r.Pages[0].Text, r.Problems, PageOK, "before\nafter")
	}
}

// Decode parameters written as an array are the parameters of the filters in
// order, and the first filter's are the first of them: an image framed by one
// filter written in an array of one, with its parameters in an array of one,
// is framed under those parameters. The image below is encoded without the
// early code-length change and says so, and a reader that did not look inside
// the array would frame it under the change it does not use and find no end.
func TestReadsDecodeParametersInAnArrayAreTheFirstFilters(t *testing.T) {
	samples := make([]byte, 900)
	for i := range samples {
		samples[i] = byte('A' + i%26)
	}
	// One code for each sample, so that the codes reach the width the early
	// change would have changed at a code earlier: an image framed under the
	// wrong one of the two reads the codes after that width at the wrong
	// length and finds no end.
	encoded := readsLZWCodes(samples, 0)
	content := shown("before", 700) + "BI /W 900 /H 1 /BPC 8 /CS /G /F [/LZW] /DP [<< /EarlyChange 0 >>] ID " +
		string(encoded) + " EI\n" + shown("after", 680)
	data := readsContentPage([]byte(content))
	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if r.Pages[0].Status != PageOK || r.Pages[0].Text != "before\nafter" || len(r.Problems) != 0 {
		t.Errorf("the record reads %s %q with problems %+v, want %s %q: the parameters of the first filter are the array's first entry",
			r.Pages[0].Status, r.Pages[0].Text, r.Problems, PageOK, "before\nafter")
	}
}

// The first code of an LZW stream stands for an entry the table already has.
// The code 258 is the entry the next addition would make, which a stream may
// use for the entry its own previous code builds -- but a first code has no
// previous code, so there is nothing there for it to stand for and the data
// is not the encoding it claims.
func TestReadsAnLZWCodeWithNoPreviousEntryIsMalformed(t *testing.T) {
	w := &readsBitWriter{}
	w.put(258, 9)
	// The end-of-data code, so that what the decoder answers is the first
	// code's and not the end of the data.
	w.put(257, 9)
	d := budgeted(1<<20, 1<<20)
	if _, err := d.lzwDecode(w.done(), true); !errors.Is(err, errMalformed) {
		t.Errorf("decoding gave %v, want a malformed encoding: 258 stands for nothing where no code stands before it", err)
	}
}

// An empty stream is decoded to nothing, and nothing is not a defect: a page
// whose content is an array of streams is read from all of them, and a
// FlateDecode stream that holds no bytes -- or none but white space -- leaves
// the content of the streams beside it as it is. This is the decoder the
// whole reader shares; an inline image's framing is another matter, and there
// a FlateDecode image must still carry the whole of a zlib wrapper.
func TestReadsAnEmptyFlateContentStreamIsNoDefect(t *testing.T) {
	for _, c := range []struct {
		name  string
		empty []byte
	}{
		{"a stream of no bytes", []byte{}},
		{"a stream of white space alone", []byte("  \r\n\t ")},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := &pdfgen.Builder{}
			helv := b.Font("Helvetica", "WinAnsiEncoding", "")
			pages := b.Next()
			b.Add(pdfgen.Object{Body: "placeholder"})
			first := b.Add(pdfgen.Object{Body: "<< /Filter /FlateDecode >>", Stream: c.empty, Raw: true})
			second := b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(shown("AFTER", 700))})
			num := b.Add(pdfgen.Object{Body: fmt.Sprintf(
				"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 %d 0 R >> >> /Contents [%d 0 R %d 0 R] >>",
				pages, helv, first, second)})
			b.Set(pages, pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%d 0 R] /Count 1 >>", num)})
			b.Catalog(pages)
			data := b.Bytes()
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if r.Pages[0].Text != "AFTER" || r.Pages[0].Status != PageOK || len(r.Problems) != 0 {
				t.Errorf("the record reads %s %q with problems %+v, want %s %q: a stream that decodes to nothing decodes",
					r.Pages[0].Status, r.Pages[0].Text, r.Problems, PageOK, "AFTER")
			}
		})
	}
}

// The "EI" that ends an image is a token of its own: two bytes another token
// begins at are not it, and an image whose encoding ends where no EI stands
// fails its page rather than the reader cutting a token in two to find one.
func TestReadsAnEIThatBeginsAnotherTokenEndsNoImage(t *testing.T) {
	content := shown("before", 700) + "BI /W 1 /H 1 /BPC 8 /CS /G /F /AHx ID 41> EI" + shown("after", 680)
	data := readsContentPage([]byte(content))
	r := extract(t, data)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if r.Pages[0].Status != PageFailed || r.Pages[0].Text != "" || len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" {
		t.Errorf("the record reads %s %q with problems %+v; the bytes where the encoding ends begin the token EIBT and not EI",
			r.Pages[0].Status, r.Pages[0].Text, r.Problems)
	}
}

// A fax image's /DecodeParms say what they say however they are written: a
// writer that turns the end-of-block off with the number 0, or aligns the
// rows with the number 1, has said what a writer that wrote false and true
// said, and the reader does not frame either. The bytes below are a complete
// white Group 4 row and the end-of-facsimile-block that ends it, which the
// reader frames where the declaration is absent.
func TestReadsFaxParametersWrittenAsNumbersSayWhatTheySay(t *testing.T) {
	bits := readsBits("1" + strings.Repeat(readsEOL, 2))
	for _, c := range []struct {
		name, parms string
		declared    Dict
	}{
		{"an end-of-block turned off with a number", "/EndOfBlock 0", Dict{"K": int64(-1), "EndOfBlock": int64(0)}},
		{"rows aligned to bytes with a number", "/EncodedByteAlign 1", Dict{"K": int64(-1), "EncodedByteAlign": int64(1)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			// The framing itself: the declaration is refused before the bytes
			// are walked, and the same bytes are framed without it.
			d := budgeted(1<<20, 1<<20)
			if n, err := d.ccittFraming(c.declared, bits); !errors.Is(err, errFilterNotFramed) || n != 0 {
				t.Errorf("framing gave %d, %v, want a filter the reader does not frame", n, err)
			}
			if n, err := d.ccittFraming(Dict{"K": int64(-1)}, bits); err != nil || n != len(bits) {
				t.Errorf("framing the same bytes without that declaration gave %d, %v, want %d", n, err, len(bits))
			}
			var content bytes.Buffer
			content.WriteString(shown("before", 700))
			content.WriteString("BI /W 8 /H 1 /BPC 1 /CS /G /F /CCF /DP << /K -1 /Columns 8 /Rows 1 " + c.parms + " >> ID ")
			content.Write(bits)
			content.WriteString(" EI\n")
			content.WriteString(shown("after", 680))
			data := readsContentPage(content.Bytes())
			r := extract(t, data)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if r.Pages[0].Status != PageFailed || r.Pages[0].Text != "" || len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" {
				t.Errorf("the record reads %s %q with problems %+v; where such an image ends is not something the reader can say",
					r.Pages[0].Status, r.Pages[0].Text, r.Problems)
			}
		})
	}
}

// An end-of-line is eleven zero bits and a one, and ten zeros and a one are
// none: no end-of-facsimile-block stands in the data below, and the reader
// says the data holds no end rather than ending it at a run the codes may
// hold. The same data one zero longer in each run is the block's end.
func TestReadsFaxEndOfLineIsElevenZeroBits(t *testing.T) {
	d := budgeted(1<<20, 1<<20)
	ten := readsBits(strings.Repeat("00000000001", 2))
	if n, err := d.ccittFraming(Dict{"K": int64(-1)}, ten); !errors.Is(err, errFilterUnended) || n != 0 {
		t.Errorf("framing two runs of ten zeros and a one gave %d, %v, want data that holds no end", n, err)
	}
	eleven := readsBits(strings.Repeat(readsEOL, 2))
	if n, err := d.ccittFraming(Dict{"K": int64(-1)}, eleven); err != nil || n != len(eleven) {
		t.Errorf("framing two runs of eleven zeros and a one gave %d, %v, want %d", n, err, len(eleven))
	}
}

// Where a JPEG ends is what its markers say, and a JPEG is walked by the
// rules T.81 gives for reading them: the start-of-image the file must begin
// with, the FF every marker begins with, the fill bytes that may stand before
// one, the markers that carry no segment at all, the two bytes of length a
// segment must have, and the entropy-coded data a scan begins. Each structure
// below is the shortest one that turns on a single rule.
func TestReadsAJPEGFramingReadsTheStructureItIsGiven(t *testing.T) {
	for _, c := range []struct {
		name string
		data []byte
		// end is where the framing ends, and want the error it ends with: a
		// structure the reader refuses is malformed, and one whose end it was
		// not given holds no end.
		end  int
		want error
	}{
		{"bytes where the start-of-image stands", []byte{0x00, 0x00, 0xFF, 0xD9}, 0, errMalformed},
		{"no bytes at all", nil, 0, errMalformed},
		{"one byte where the start-of-image's two stand", []byte{0xFF}, 0, errMalformed},
		{"a start-of-image whose first byte is not FF", []byte{0x00, 0xD8, 0xFF, 0xD9}, 0, errMalformed},
		{"a start-of-image whose second byte is not D8", []byte{0xFF, 0x00, 0xFF, 0xD9}, 0, errMalformed},
		{"a marker that does not begin with FF", []byte{0xFF, 0xD8, 0x42, 0xD9}, 0, errMalformed},
		{"a fill byte before the end-of-image", []byte{0xFF, 0xD8, 0xFF, 0xFF, 0xD9}, 5, nil},
		{"the temporary-use marker, which carries no segment", []byte{0xFF, 0xD8, 0xFF, 0x01, 0xFF, 0xD9}, 6, nil},
		{"a restart marker outside a scan", []byte{0xFF, 0xD8, 0xFF, 0xD0, 0xFF, 0xD9}, 6, nil},
		{"a segment shorter than the two bytes of its own length", []byte{0xFF, 0xD8, 0xFF, 0xFE, 0x00, 0x01}, 0, errMalformed},
		{"fill bytes the data ends inside", []byte{0xFF, 0xD8, 0xFF, 0xDA, 0x00, 0x02, 0xFF, 0xFF}, 0, errFilterUnended},
		{"a segment the data ends after, with no end-of-image", []byte{0xFF, 0xD8, 0xFF, 0xFE, 0x00, 0x02}, 0, errFilterUnended},
		{"a byte that is no marker where no scan has begun", []byte{0xFF, 0xD8, 0xFF, 0xFE, 0x00, 0x02, 0x42, 0xFF, 0xD9}, 0, errMalformed},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := budgeted(1<<20, 1<<20)
			n, err := d.jpegFraming(c.data)
			ok := n == c.end && (c.want == nil) == (err == nil) && (c.want == nil || errors.Is(err, c.want))
			if !ok {
				t.Errorf("framing gave %d, %v, want %d, %v", n, err, c.end, c.want)
			}
		})
	}
}

// A JPEG whose segments fill the bytes the reader may read of one image
// without reaching an end-of-image has met that bound, and the bound is what
// the record says. The image below is the window exactly: the "EI" stands at
// the first byte past it, where a reader that ended the walk at the window
// would find one.
func TestReadsAJPEGFillingTheInputWindowIsThatBound(t *testing.T) {
	if testing.Short() {
		t.Skip("writes an inline image of sixteen megabytes")
	}
	// A start-of-image, a comment segment carrying two bytes, and comment
	// segments carrying none to the end of the window.
	samples := append([]byte{0xFF, 0xD8, 0xFF, 0xFE, 0x00, 0x04, 0x41, 0x42},
		bytes.Repeat([]byte{0xFF, 0xFE, 0x00, 0x02}, (maxInlineImageBytes-8)/4)...)
	if len(samples) != maxInlineImageBytes {
		t.Fatalf("the image is %d bytes, want the window of %d", len(samples), maxInlineImageBytes)
	}
	data := readsInlineImagePage("/W 1 /H 1 /BPC 8 /CS /G /F /DCT", samples, shown("REAL", 700))
	opt := testOptions()
	opt.MaxInflateOne, opt.MaxInflateTotal = 64<<20, 64<<20
	r := Extract(context.Background(), data, opt)
	if out, ok := readsPoppler(t, data); ok {
		t.Logf("pdftotext reads %q", out)
	}
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	want := "the content of page 1 is past a structure bound the reader holds"
	if r.Pages[0].Status != PageFailed || len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" || r.Problems[0].Message != want {
		t.Errorf("pages %+v problems %+v; the markers held no end-of-image within the bytes the reader may read of one image", r.Pages, r.Problems)
	}
}

// readsWalkAllowance is what the readings a walk that ends at the rebuild it
// meets asks for cost the inflate budget: the rebuild itself, asked for
// outside any walk by resolving the object whose offset the file damaged, and
// then the whole reading of the rebuilt document -- its tree walked and its
// pages extracted, with no rebuild left to meet. The allowance is measured
// this way rather than through the walk that meets the rebuild, so that what
// it measures is what those readings cost and not what a walk happens to
// read. A reading that spends more has read something of the discarded tree.
func readsWalkAllowance(t *testing.T, data []byte, damaged int) int64 {
	t.Helper()
	ctx := context.Background()
	opt := testOptions()
	result := &Result{}
	doc, stop := openDocument(ctx, data, opt, result)
	if stop != nil {
		t.Fatal("the document was not opened")
	}
	generation := doc.generation
	doc.resolve(ref{damaged, 0})
	if doc.generation == generation {
		t.Fatalf("reading object %d did not rebuild the cross-reference", damaged)
	}
	w, generation, stop := walkPages(ctx, doc, opt, result)
	if stop != nil || doc.generation != generation {
		t.Fatalf("the walk of the rebuilt document ended with %v", stop)
	}
	extractPages(ctx, w, opt, result)
	if len(result.Pages) != 1 || result.Pages[0].Text != "Z" {
		t.Fatalf("the rebuilt document reads %+v, want one page reading %q", result.Pages, "Z")
	}
	return doc.budget.used
}

// A walk reads the cross-reference it stands on at each of the two places it
// may be replaced under it: after a node's own fields are read, and after
// each kid is resolved. Neither reading stands for the other, and a walk
// missing one reads the tree this document no longer has -- the second page
// of the discarded tree in the first file below, the discarded node's own
// compressed resources in the second. Either reading spends on that tree what
// the reading of the rebuilt document needs, and the allowance below is what
// that reading costs and no more.
func TestReadsAWalkNoticesARebuildWhereverItMeetsOne(t *testing.T) {
	content := shown("Z", 700)
	font := "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
	sibling := "<< /Type /Page /Parent 2 0 R /Contents 6 0 R >>"
	resources := "<< /Font << /F1 7 0 R >> >>"
	for _, c := range []struct {
		name     string
		objects  []readsObject
		broken   int
		inStream map[int][2]int
	}{
		// The rebuild is met reading a leaf's own resources, before that leaf's
		// /Kids is read: a walk that read on would take the leaf for a page of
		// this document and resolve the kid after it, which lies in a
		// compressed stream of objects.
		{"a rebuild met reading a leaf's resources", []readsObject{
			{1, "<< /Type /Catalog /Pages 2 0 R >>"},
			{2, "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>"},
			{3, "<< /Type /Page /Parent 2 0 R /Resources 11 0 R /Contents 6 0 R >>"},
			{5, readsStreamObject("/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode", string(flateOf([]byte("4 0 "+sibling))))},
			{6, readsStreamObject("", content)},
			{7, font},
			{11, resources},
			// The rebuilt document: one page, whose content is compressed.
			{2, "<< /Type /Pages /Kids [12 0 R] /Count 1 >>"},
			{12, "<< /Type /Page /Parent 2 0 R /Resources " + resources + " /Contents 13 0 R >>"},
			{13, readsStreamObject("/Filter /FlateDecode", string(flateOf([]byte(content))))},
		}, 11, map[int][2]int{4: {5, 0}}},
		// The rebuild is met resolving the kid itself: a walk that read on
		// would walk that kid, whose resources lie in a compressed stream of
		// objects, and spend on them what the reading after the rebuild needs.
		{"a rebuild met resolving a kid", []readsObject{
			{1, "<< /Type /Catalog /Pages 2 0 R >>"},
			{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
			{3, "<< /Type /Page /Parent 2 0 R /Resources 14 0 R /Contents 6 0 R >>"},
			{5, readsStreamObject("/Type /ObjStm /N 1 /First 5 /Filter /FlateDecode", string(flateOf([]byte("14 0 "+resources))))},
			{6, readsStreamObject("", content)},
			{7, font},
		}, 3, map[int][2]int{14: {5, 0}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := readsRawFile(c.objects, c.broken, c.inStream)
			// What the readings this document asks for cost, measured from a
			// reading that meets no bound rather than counted by hand.
			allowance := readsWalkAllowance(t, data, c.broken)
			opt := testOptions()
			opt.MaxInflateTotal, opt.MaxInflateOne = allowance, allowance
			r := Extract(context.Background(), data, opt)
			if out, ok := readsPoppler(t, data); ok {
				t.Logf("pdftotext reads %q", out)
			}
			if r.Fatal != nil {
				t.Fatalf("fatal %+v; the rebuilt document holds one page the reader reads whole", r.Fatal)
			}
			if len(r.Pages) != 1 || r.Pages[0].Text != "Z" || r.Pages[0].Status != PageOK || len(r.Problems) != 0 {
				t.Errorf("the record reads %+v with problems %+v, want one page reading %q", r.Pages, r.Problems, "Z")
			}
		})
	}
}
