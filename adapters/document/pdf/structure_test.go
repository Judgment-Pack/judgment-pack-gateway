package pdf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"adapters/internal/pdfgen"
)

// shown is a content stream showing text with the font F1 at the height y.
func shown(text string, y int) string {
	return fmt.Sprintf("BT /F1 12 Tf 1 0 0 1 72 %d Tm (%s) Tj ET\n", y, text)
}

// formChain adds n form XObjects, each drawing the one before it as X1, the
// first showing "deep", and returns the last.
func formChain(b *pdfgen.Builder, n, font int) int {
	inner := 0
	for i := 0; i < n; i++ {
		content := shown("deep", 690)
		resources := fmt.Sprintf("/Font << /F1 %d 0 R >>", font)
		if inner != 0 {
			content = "/X1 Do\n"
			resources += fmt.Sprintf(" /XObject << /X1 %d 0 R >>", inner)
		}
		inner = b.Add(pdfgen.Object{Body: "<< /Type /XObject /Subtype /Form /BBox [0 0 612 792] /Resources << " + resources + " >> >>", Stream: []byte(content)})
	}
	return inner
}

// A structure bound met in a page's content fails the page, and the text
// before it is not listed; the same structure within the bound is read, and
// the text on both sides of it is the page's.
func TestContentStructureBoundsFailThePage(t *testing.T) {
	type content struct {
		middle string
		form   func(b *pdfgen.Builder, font int) int
	}
	// The keys that measure an image of one byte: a dictionary bound is what
	// these cases are about, so the image itself says where it ends.
	const measured = "/W 1 /H 1 /BPC 8 /CS /G"
	cases := []struct {
		name           string
		within, pastIt content
	}{
		{"arrays nested",
			content{middle: strings.Repeat("[", maxNesting+1) + strings.Repeat("]", maxNesting+1)},
			content{middle: strings.Repeat("[", maxNesting+2) + strings.Repeat("]", maxNesting+2)}},
		{"a number token",
			content{middle: strings.Repeat("1", maxNumberBytes)},
			content{middle: strings.Repeat("1", maxNumberBytes+1)}},
		{"a name token",
			content{middle: "/" + strings.Repeat("N", maxNameBytes)},
			content{middle: "/" + strings.Repeat("N", maxNameBytes+1)}},
		{"operands",
			content{middle: strings.Repeat("0 ", maxOperands) + "n"},
			content{middle: strings.Repeat("0 ", maxOperands+1) + "n"}},
		{"graphics states saved",
			content{middle: strings.Repeat("q ", maxGraphicsStates) + strings.Repeat("Q ", maxGraphicsStates)},
			content{middle: strings.Repeat("q ", maxGraphicsStates+1) + strings.Repeat("Q ", maxGraphicsStates+1)}},
		{"an inline image's dictionary",
			content{middle: "BI " + strings.Repeat("/A ", 2*maxOperands-8) + measured + " ID x EI"},
			content{middle: "BI " + strings.Repeat("/A ", 2*maxOperands-7) + measured + " ID x EI"}},
		{"a name token in an inline image's dictionary",
			content{middle: "BI " + measured + " /" + strings.Repeat("N", maxNameBytes) + " /V ID x EI"},
			content{middle: "BI " + measured + " /" + strings.Repeat("N", maxNameBytes+1) + " /V ID x EI"}},
		{"forms drawn within forms",
			content{middle: "/X1 Do", form: func(b *pdfgen.Builder, font int) int { return formChain(b, maxFormDepth, font) }},
			content{middle: "/X1 Do", form: func(b *pdfgen.Builder, font int) int { return formChain(b, maxFormDepth+1, font) }}},
		{"a form that draws itself",
			content{middle: "/X1 Do", form: func(b *pdfgen.Builder, font int) int { return formChain(b, 1, font) }},
			content{middle: "/X1 Do", form: func(b *pdfgen.Builder, font int) int {
				self := b.Next()
				return b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /XObject /Subtype /Form /BBox [0 0 1 1] /Resources << /XObject << /X1 %d 0 R >> >> >>", self), Stream: []byte("/X1 Do\n")})
			}}},
	}
	document := func(c content) []byte {
		b := &pdfgen.Builder{Compress: true}
		helv := b.Font("Helvetica", "WinAnsiEncoding", "")
		first := pdfgen.Page{Content: shown("before", 700) + c.middle + "\n" + shown("after", 680), Fonts: map[string]int{"F1": helv}}
		if c.form != nil {
			first.XObjects = map[string]int{"X1": c.form(b, helv)}
		}
		b.Catalog(b.Pages([]pdfgen.Page{first, {Content: shown("next", 700), Fonts: map[string]int{"F1": helv}}}))
		return b.Bytes()
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := extract(t, document(c.within))
			if r.Fatal != nil || len(r.Pages) != 2 || len(r.Problems) != 0 || r.Pages[0].Status != PageOK || !strings.HasPrefix(r.Pages[0].Text, "before\n") || !strings.HasSuffix(r.Pages[0].Text, "\nafter") {
				t.Fatalf("within the bound: fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
			}
			r = extract(t, document(c.pastIt))
			if r.Fatal != nil || len(r.Pages) != 2 || r.Pages[0].Status != PageFailed || r.Pages[0].Text != "" || r.Pages[1].Text != "next" {
				t.Fatalf("past the bound: fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
			}
			if len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" || r.Problems[0].Page != 1 {
				t.Fatalf("past the bound: problems %+v", r.Problems)
			}
		})
	}
}

// An inline image whose data runs past the bound without its EI fails the
// page: the content after it cannot be found. Data up to the bound is read.
// The image is encoded by a filter the reader does not frame and carries no
// length, so where its data ends is looked for in the data itself, which is
// what the bound bounds.
func TestInlineImagePastItsBoundFailsThePage(t *testing.T) {
	if testing.Short() {
		t.Skip("writes two inline images of sixteen megabytes")
	}
	opt := testOptions()
	opt.MaxInflateOne = 64 << 20
	for _, c := range []struct {
		bytes  int
		failed bool
	}{{maxInlineImageBytes, false}, {maxInlineImageBytes + 1, true}} {
		b := &pdfgen.Builder{}
		helv := b.Font("Helvetica", "WinAnsiEncoding", "")
		content := shown("before", 700) + "BI /W 1 /H 1 /BPC 8 /CS /G /F /AHx ID " + strings.Repeat("4", c.bytes-1) + "> EI\n" + shown("after", 680)
		b.Catalog(b.Pages([]pdfgen.Page{{Content: content, Fonts: map[string]int{"F1": helv}}}))
		r := Extract(context.Background(), b.Bytes(), opt)
		if r.Fatal != nil || len(r.Pages) != 1 {
			t.Fatalf("%d bytes: fatal %+v pages %+v", c.bytes, r.Fatal, r.Pages)
		}
		if c.failed && (r.Pages[0].Status != PageFailed || len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed") {
			t.Fatalf("%d bytes: pages %+v problems %+v", c.bytes, r.Pages, r.Problems)
		}
		if !c.failed && (r.Pages[0].Text != "before\nafter" || len(r.Problems) != 0) {
			t.Fatalf("%d bytes: pages %+v problems %+v", c.bytes, r.Pages, r.Problems)
		}
	}
}

// A page whose /Contents is present and is not a stream or an array of
// streams the reader could read is failed; one whose /Contents is absent or
// null has no text. The page after it is read either way.
func TestPageContentThatCannotBeReadFailsThePage(t *testing.T) {
	cases := []struct {
		name, contents string
		want           PageStatus
	}{
		{"a reference to no object", "/Contents 999 0 R", PageFailed},
		{"a number", "/Contents 5", PageFailed},
		{"a dictionary", "/Contents << /Length 0 >>", PageFailed},
		{"a reference to a dictionary", "/Contents FONT 0 R", PageFailed},
		{"a reference to a reference to no object", "/Contents REF 0 R", PageFailed},
		{"an array holding a reference to no object", "/Contents [STREAM 0 R 999 0 R]", PageFailed},
		{"an array holding a number", "/Contents [STREAM 0 R 5]", PageFailed},
		{"an array holding null", "/Contents [STREAM 0 R null]", PageFailed},
		{"absent", "", PageNoText},
		{"null", "/Contents null", PageNoText},
		{"a reference to the null object", "/Contents NULL 0 R", PageNoText},
		{"a stream", "/Contents STREAM 0 R", PageOK},
		{"an array of streams", "/Contents [STREAM 0 R STREAM 0 R]", PageOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := &pdfgen.Builder{}
			helv := b.Font("Helvetica", "WinAnsiEncoding", "")
			stream := b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(shown("text", 700))})
			null := b.Add(pdfgen.Object{Body: "null"})
			toNothing := b.Add(pdfgen.Object{Body: "999 0 R"})
			next := b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(shown("next", 700))})
			pages := b.Next()
			b.Add(pdfgen.Object{Body: "placeholder"})
			contents := strings.NewReplacer("STREAM", fmt.Sprint(stream), "NULL", fmt.Sprint(null), "FONT", fmt.Sprint(helv), "REF", fmt.Sprint(toNothing)).Replace(c.contents)
			resources := fmt.Sprintf("/Resources << /Font << /F1 %d 0 R >> >>", helv)
			first := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Page /Parent %d 0 R %s %s >>", pages, resources, contents)})
			second := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Page /Parent %d 0 R %s /Contents %d 0 R >>", pages, resources, next)})
			b.Set(pages, pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%d 0 R %d 0 R] /Count 2 >>", first, second)})
			b.Catalog(pages)
			r := extract(t, b.Bytes())
			if r.Fatal != nil || len(r.Pages) != 2 || r.Pages[0].Status != c.want || r.Pages[1].Text != "next" {
				t.Fatalf("fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
			}
			wantProblems := 0
			if c.want == PageFailed {
				wantProblems = 1
			}
			if len(r.Problems) != wantProblems || (wantProblems == 1 && (r.Problems[0].Code != "pdf-page-failed" || r.Problems[0].Page != 1)) {
				t.Fatalf("problems %+v", r.Problems)
			}
		})
	}
}

// A glyph's characters reach the normalisation as the font maps them, in
// order: a NUL removed there does not make the byte order mark after it the
// text's first character, and a tab, a CR LF pair, a CR alone and the
// characters around them are what the normalisation keeps of them. The text
// budget is decided on that text.
func TestMappedCharactersReachTheNormalisationInOrder(t *testing.T) {
	multi := func(b *pdfgen.Builder, destination string) int {
		cmap := "begincmap\n1 begincodespacerange <0000> <FFFF> endcodespacerange\n1 beginbfchar <0001> <" + destination + "> endbfchar\nendcmap\n"
		return cidFont(b, "", b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(cmap)}))
	}
	cases := []struct {
		name  string
		font  func(b *pdfgen.Builder) int
		codes string
		want  string
	}{
		{"a glyph each for NUL, a byte order mark and A", func(b *pdfgen.Builder) int { return b.Type0Font([]rune{0, 0xFEFF, 'A'}) }, "000100020003", "\xef\xbb\xbfA"},
		{"one glyph for NUL, a byte order mark and A", func(b *pdfgen.Builder) int { return multi(b, "0000FEFF0041") }, "0001", "\xef\xbb\xbfA"},
		{"a glyph each for x, a tab, y, CR, LF and z", func(b *pdfgen.Builder) int { return b.Type0Font([]rune{'x', '\t', 'y', '\r', '\n', 'z'}) }, "000100020003000400050006", "x\ty\nz"},
		{"one glyph for x, a tab, y, CR, LF and z", func(b *pdfgen.Builder) int { return multi(b, "007800090079000D000A007A") }, "0001", "x\ty\nz"},
		{"a glyph each for x, CR and y", func(b *pdfgen.Builder) int { return b.Type0Font([]rune{'x', '\r', 'y'}) }, "000100020003", "x\ny"},
		{"one glyph for x, CR and y", func(b *pdfgen.Builder) int { return multi(b, "0078000D0079") }, "0001", "x\ny"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := &pdfgen.Builder{}
			font := c.font(b)
			b.Catalog(b.Pages([]pdfgen.Page{{Content: "BT /F1 12 Tf 1 0 0 1 72 700 Tm <" + c.codes + "> Tj ET\n", Fonts: map[string]int{"F1": font}}}))
			data := b.Bytes()
			r := extract(t, data)
			if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Status != PageOK || r.Pages[0].Text != c.want || len(r.Problems) != 0 {
				t.Fatalf("fatal %+v pages %+v problems %+v, want %q", r.Fatal, r.Pages, r.Problems, c.want)
			}
			opt := testOptions()
			opt.MaxTextBytes = 1
			r = Extract(context.Background(), data, opt)
			if r.Fatal != nil || len(r.Pages) != 0 || len(r.Problems) != 1 || r.Problems[0].Code != "text-over-bound" {
				t.Fatalf("a budget of %d bytes: fatal %+v pages %+v problems %+v", opt.MaxTextBytes, r.Fatal, r.Pages, r.Problems)
			}
		})
	}
}

// A page whose text goes past the budget is still interpreted to its end:
// content that then fails fails the page, which spends no budget and lets the
// next page be read; content that does not leaves the page past the budget.
func TestTextPastTheBudgetWaitsForTheContent(t *testing.T) {
	cases := []struct {
		name, after string
		code        string
	}{
		{"a form with a filter the reader does not implement", "/X1 Do\n", "pdf-unsupported"},
		{"a structure bound", strings.Repeat("[", maxNesting+2), "pdf-page-failed"},
		{"nothing", "", "text-over-bound"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := &pdfgen.Builder{}
			helv := b.Font("Helvetica", "WinAnsiEncoding", "")
			form := b.Add(pdfgen.Object{Body: "<< /Type /XObject /Subtype /Form /BBox [0 0 1 1] /Filter /DCTDecode >>", Stream: []byte("x"), Raw: true})
			fonts := map[string]int{"F1": helv}
			b.Catalog(b.Pages([]pdfgen.Page{
				{Content: shown("TOOLONG", 700) + c.after, Fonts: fonts, XObjects: map[string]int{"X1": form}},
				{Content: shown("B", 700), Fonts: fonts},
			}))
			opt := testOptions()
			opt.MaxTextBytes = 1
			r := Extract(context.Background(), b.Bytes(), opt)
			if r.Fatal != nil || len(r.Problems) != 1 || r.Problems[0].Code != c.code || r.Problems[0].Page != 1 {
				t.Fatalf("fatal %+v problems %+v", r.Fatal, r.Problems)
			}
			if c.code == "text-over-bound" {
				if len(r.Pages) != 0 || !r.Truncated || r.TextBytes != 0 {
					t.Fatalf("pages %+v truncated %v text %d", r.Pages, r.Truncated, r.TextBytes)
				}
				return
			}
			if len(r.Pages) != 2 || r.Pages[0].Status != PageFailed || r.Pages[1].Status != PageOK || r.Pages[1].Text != "B" || r.Truncated || r.TextBytes != 1 {
				t.Fatalf("pages %+v truncated %v text %d", r.Pages, r.Truncated, r.TextBytes)
			}
		})
	}
}

// An object that could not be read is not read the next time as the null
// object: two pages naming the same unreadable content both fail, whether the
// object is past a bound or damaged, and whether it is at an offset in the
// file -- read again after the cross-reference is rebuilt -- or in an object
// stream.
func TestUnreadContentFailsEveryPageNamingIt(t *testing.T) {
	for _, c := range []struct {
		name   string
		body   string
		layout pdfgen.Builder
	}{
		{"a name past its bound", "/" + strings.Repeat("N", maxNameBytes+1), pdfgen.Builder{}},
		{"a reference out of range", "4294967296 0 R", pdfgen.Builder{}},
		{"a reference out of range in an object stream", "4294967296 0 R", pdfgen.Builder{XrefStream: true, ObjectStreams: true, Compress: true}},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := &c.layout
			unreadable := b.Add(pdfgen.Object{Body: c.body})
			pages := b.Next()
			b.Add(pdfgen.Object{Body: "placeholder"})
			var kids []string
			for i := 0; i < 2; i++ {
				page := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Page /Parent %d 0 R /Contents %d 0 R >>", pages, unreadable)})
				kids = append(kids, fmt.Sprintf("%d 0 R", page))
			}
			b.Set(pages, pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count 2 >>", strings.Join(kids, " "))})
			b.Catalog(pages)
			r := extract(t, b.Bytes())
			if r.Fatal != nil || len(r.Pages) != 2 || r.Pages[0].Status != PageFailed || r.Pages[1].Status != PageFailed || len(r.Problems) != 2 {
				t.Fatalf("fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
			}
			// The words the record carries say which defect it was: content
			// that could not be read, not content that could not be
			// interpreted.
			for i, p := range r.Problems {
				want := fmt.Sprintf("the content of page %d could not be read", i+1)
				if p.Code != "pdf-page-failed" || p.Message != want {
					t.Errorf("problem %d: %+v, want %q", i+1, p, want)
				}
			}
		})
	}
}

// An object stream the cross-reference names that cannot be decoded, or is not
// an object stream, is met while the page tree is walked -- a page's
// resources are in it -- and ends the walk at a defect, as one past the
// inflate bound does. The same object stream decoded is read.
func TestObjectStreamThatCannotBeReadEndsTheWalk(t *testing.T) {
	document := func(stream func(payload []byte, first int) pdfgen.Object) []byte {
		b := &pdfgen.Builder{XrefStream: true}
		helv := b.Font("Helvetica", "WinAnsiEncoding", "")
		// The object at this number is in the object stream: its row of the
		// cross-reference stream is rewritten to say so.
		resources := b.Add(pdfgen.Object{Body: "null"})
		header := fmt.Sprintf("%d 0 ", resources)
		objStm := b.Add(stream([]byte(header+fmt.Sprintf("<< /Font << /F1 %d 0 R >> >>", helv)), len(header)))
		content := b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(shown("resources", 700))})
		pages := b.Next()
		b.Add(pdfgen.Object{Body: "placeholder"})
		page := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Page /Parent %d 0 R /Resources %d 0 R /Contents %d 0 R >>", pages, resources, content)})
		b.Set(pages, pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%d 0 R] /Count 1 >>", page)})
		b.Catalog(pages)
		data := b.Bytes()
		rows := bytes.LastIndex(data, []byte(">>\nstream\n")) + len(">>\nstream\n")
		copy(data[rows+9*resources:], []byte{2, byte(objStm >> 24), byte(objStm >> 16), byte(objStm >> 8), byte(objStm), 0, 0, 0, 0})
		return data
	}
	objStm := func(filter string, encode func([]byte) []byte) func([]byte, int) pdfgen.Object {
		return func(payload []byte, first int) pdfgen.Object {
			return pdfgen.Object{Body: fmt.Sprintf("<< /Type /ObjStm /N 1 /First %d %s >>", first, filter), Stream: encode(payload), Raw: true}
		}
	}
	r := extract(t, document(objStm("/Filter /FlateDecode", flateOf)))
	if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Text != "resources" || len(r.Problems) != 0 {
		t.Fatalf("decoded: fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
	}
	for name, stream := range map[string]func([]byte, int) pdfgen.Object{
		"corrupt FlateDecode data": objStm("/Filter /FlateDecode", func([]byte) []byte { return []byte("\x78\x9cgarbage") }),
		"FlateDecode data cut off": objStm("/Filter /FlateDecode", func(p []byte) []byte { z := flateOf(p); return z[:len(z)/2] }),
		"a filter not implemented": objStm("/Filter /DCTDecode", func(p []byte) []byte { return p }),
		"not an object stream": func(payload []byte, first int) pdfgen.Object {
			return pdfgen.Object{Body: fmt.Sprintf("<< /Type /XObject /N 1 /First %d >>", first), Stream: payload, Raw: true}
		},
	} {
		r := extract(t, document(stream))
		if r.Fatal == nil || r.Fatal.Code != "pdf-malformed" || r.Fatal.Message != undecodedMessage || len(r.Pages) != 0 || r.PageCount != 0 || len(r.Problems) != 0 {
			t.Errorf("%s: fatal %+v pages %+v problems %+v", name, r.Fatal, r.Pages, r.Problems)
		}
	}
}

// withSections appends sections to a document written with a
// cross-reference table, each naming the one before it by /Prev -- and by
// /XRefStm too when twice is set -- so that the chain from startxref is n
// sections long.
func withSections(t *testing.T, data []byte, n int, twice bool) []byte {
	t.Helper()
	at := bytes.LastIndex(data, []byte("startxref"))
	prev, err := strconv.Atoi(strings.Fields(string(data[at+len("startxref"):]))[0])
	if err != nil {
		t.Fatal(err)
	}
	trailer := data[bytes.LastIndex(data, []byte("trailer")):at]
	end := bytes.LastIndex(trailer, []byte(">>"))
	out := append([]byte{}, data...)
	for i := 1; i < n; i++ {
		offset := len(out)
		out = append(out, "xref\n0 1\n0000000000 65535 f \n"...)
		out = append(out, trailer[:end]...)
		if twice {
			out = fmt.Appendf(out, " /XRefStm %d", prev)
		}
		out = fmt.Appendf(out, " /Prev %d >>\nstartxref\n%d\n%%%%EOF\n", prev, offset)
		prev = offset
	}
	return out
}

// replaceOnce replaces the one match of pattern in data, failing the test
// when there is not exactly one.
func replaceOnce(t *testing.T, data []byte, pattern, replacement string) []byte {
	t.Helper()
	re := regexp.MustCompile(pattern)
	if n := len(re.FindAllIndex(data, -1)); n != 1 {
		t.Fatalf("%q matches %d times", pattern, n)
	}
	return re.ReplaceAll(data, []byte(replacement))
}

// members is a dictionary's members, n of them, each named apart.
func members(n int) string {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "/m%d 0 ", i)
	}
	return sb.String()
}

// truncatedWith is a normal document with the objects given added and its
// cross-reference cut off, so that opening it scans the file.
func truncatedWith(t *testing.T, objects ...pdfgen.Object) []byte {
	t.Helper()
	b := &pdfgen.Builder{}
	for _, o := range objects {
		b.Add(o)
	}
	data := normalDocument(b)
	return data[:bytes.LastIndex(data, []byte("xref"))]
}

// A bound met while the document is opened or its page tree walked is
// pdf-malformed: the reader neither rebuilds the cross-reference past it, as
// it does past damage, nor walks on without the object the bound left unread.
// The counterpart of each document, within the bound, opens.
func TestOpeningBoundsArePDFMalformed(t *testing.T) {
	table := normalDocument(&pdfgen.Builder{})
	stream := normalDocument(&pdfgen.Builder{XrefStream: true})
	compressedStream := normalDocument(&pdfgen.Builder{XrefStream: true, Compress: true})
	nested := strings.Repeat("[", maxNesting+2) + strings.Repeat("]", maxNesting+2)

	// The rows of an uncompressed cross-reference stream, with the row of
	// object 1 naming an object stream past the object numbers the reader
	// holds.
	farObjectStream := func() []byte {
		data := append([]byte{}, stream...)
		rows := bytes.LastIndex(data, []byte(">>\nstream\n")) + len(">>\nstream\n")
		copy(data[rows+9:], []byte{2, 0x7f, 0xff, 0xff, 0xff, 0, 0, 0, 0})
		return data
	}
	scanned := func(extra int) []byte {
		cut := table[:bytes.LastIndex(table, []byte("xref"))]
		found := len(objHeader.FindAllIndex(cut, -1))
		return append(append([]byte{}, cut...), strings.Repeat("900000 0 obj\n", extra-found)...)
	}
	// These fixtures isolate the object-count bound. The unread header places
	// also consume the parsed-memory allowance, so give the file enough bytes
	// for that independent allowance to admit maxObjStmObjects places.
	emptyObjectStream := func(n int) pdfgen.Object {
		return pdfgen.Object{Body: fmt.Sprintf("<< /Type /ObjStm /N %d /First 0 >>", n), Stream: bytes.Repeat([]byte(" "), 256<<10), Raw: true}
	}
	// Objects at offsets the cross-reference misstates send the first read
	// to rebuilding it, where an object stream past its bound waits.
	misstated := func(objStmN int) []byte {
		b := &pdfgen.Builder{BrokenOffsets: 7}
		b.Add(emptyObjectStream(objStmN))
		return normalDocument(b)
	}
	// A catalog without /Pages sends the walk to rebuilding the
	// cross-reference, where an object stream past its bound waits.
	catalogWithout := func(objStmN int) []byte {
		b := &pdfgen.Builder{}
		b.Add(emptyObjectStream(objStmN))
		helv := b.Font("Helvetica", "WinAnsiEncoding", "")
		b.Pages([]pdfgen.Page{{Content: shown("text", 700), Fonts: map[string]int{"F1": helv}}})
		b.Root = b.Add(pdfgen.Object{Body: "<< /Type /Catalog >>"})
		return b.Bytes()
	}
	// A page tree reached through references to references, n of them.
	pagesThrough := func(n int) []byte {
		b := &pdfgen.Builder{}
		helv := b.Font("Helvetica", "WinAnsiEncoding", "")
		node := b.Pages([]pdfgen.Page{{Content: shown("text", 700), Fonts: map[string]int{"F1": helv}}})
		for i := 0; i < n; i++ {
			node = b.Add(pdfgen.Object{Body: fmt.Sprintf("%d 0 R", node)})
		}
		b.Catalog(node)
		return b.Bytes()
	}
	// A page whose resources are reached through n references, or are a
	// dictionary holding the member given.
	resourcesOf := func(n int, member string) []byte {
		b := &pdfgen.Builder{}
		helv := b.Font("Helvetica", "WinAnsiEncoding", "")
		res := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Font << /F1 %d 0 R >> %s >>", helv, member)})
		for i := 0; i < n; i++ {
			res = b.Add(pdfgen.Object{Body: fmt.Sprintf("%d 0 R", res)})
		}
		content := b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(shown("text", 700))})
		pages := b.Next()
		b.Add(pdfgen.Object{Body: "placeholder"})
		page := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Page /Parent %d 0 R /Resources %d 0 R /Contents %d 0 R >>", pages, res, content)})
		b.Set(pages, pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%d 0 R] /Count 1 >>", page)})
		b.Catalog(pages)
		return b.Bytes()
	}

	cases := []struct {
		name           string
		within, pastIt []byte
		opt            func(*Options)
	}{
		{"a /Prev chain", withSections(t, table, maxXrefSections, false), withSections(t, table, maxXrefSections+1, false), nil},
		{"a chain naming each section twice", withSections(t, table, maxXrefSections, true), withSections(t, table, maxXrefSections+1, true), nil},
		{"a table subsection's count", table, replaceOnce(t, table, `xref\n0 \d+\n`, fmt.Sprintf("xref\n0 %d\n", maxXrefEntries+1)), nil},
		{"a table subsection's start", table, replaceOnce(t, table, `xref\n0 \d+\n`, "xref\n9223372036854775807 1\n"), nil},
		{"a trailer's nesting", table, replaceOnce(t, table, `trailer\n<< `, "trailer\n<< /Junk "+nested+" "), nil},
		{"a trailer's array", table, replaceOnce(t, table, `trailer\n<< `, "trailer\n<< /Junk ["+strings.Repeat("0 ", maxContainerItems+1)+"] "), nil},
		{"a trailer's dictionary", table, replaceOnce(t, table, `trailer\n<< `, "trailer\n<< /Junk << "+members(maxContainerItems+1)+">> "), nil},
		{"a trailer's name", table, replaceOnce(t, table, `trailer\n<< `, "trailer\n<< /"+strings.Repeat("N", maxNameBytes+1)+" 1 "), nil},
		{"a cross-reference stream's /Size", stream, replaceOnce(t, stream, `/Size \d+ /W`, fmt.Sprintf("/Size %d /W", maxXrefEntries+1)), nil},
		{"a cross-reference stream's /Index start and count", stream, replaceOnce(t, stream, `/Size \d+ /W`, "/Size 9 /Index [1 9223372036854775807] /W"), nil},
		{"a cross-reference stream's object stream", stream, farObjectStream(), nil},
		// Nested ahead of /Type /XRef, so that rebuilding does not look at it.
		{"a cross-reference stream's nesting", stream, replaceOnce(t, stream, `<< /Type /XRef `, "<< /Junk "+nested+" /Type /XRef "), nil},
		{"a cross-reference stream past the inflate bound", compressedStream, compressedStream, func(o *Options) { o.MaxInflateTotal = 32 }},
		{"objects found by scanning", scanned(maxScanObjects), scanned(maxScanObjects + 1), nil},
		{"an object stream found by scanning", truncatedWith(t, emptyObjectStream(maxObjStmObjects)), truncatedWith(t, emptyObjectStream(maxObjStmObjects+1)), nil},
		{"an object's nesting found by scanning", truncatedWith(t, pdfgen.Object{Body: "<< /Type /ObjStm /Junk [] >>", Stream: []byte{}, Raw: true}), truncatedWith(t, pdfgen.Object{Body: "<< /Type /ObjStm /Junk " + nested + " >>", Stream: []byte{}, Raw: true}), nil},
		{"an object stream met rebuilding for a misstated offset", misstated(maxObjStmObjects), misstated(maxObjStmObjects + 1), nil},
		{"an object stream met rebuilding for the page tree", catalogWithout(maxObjStmObjects), catalogWithout(maxObjStmObjects + 1), nil},
		{"references to the page tree", pagesThrough(maxRefDepth - 1), pagesThrough(maxRefDepth), nil},
		{"references to a page's resources", resourcesOf(maxRefDepth-1, ""), resourcesOf(maxRefDepth, ""), nil},
		{"a page's resources' nesting", resourcesOf(0, "/Junk "+strings.Repeat("[", maxNesting)+strings.Repeat("]", maxNesting)), resourcesOf(0, "/Junk "+nested), nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opt := testOptions()
			r := Extract(context.Background(), c.within, opt)
			if r.Fatal != nil || len(r.Pages) == 0 {
				t.Fatalf("within the bound: fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
			}
			if c.opt != nil {
				c.opt(&opt)
			}
			r = Extract(context.Background(), c.pastIt, opt)
			if r.Fatal == nil || r.Fatal.Code != "pdf-malformed" || len(r.Pages) != 0 || r.PageCount != 0 || r.Truncated || len(r.Problems) != 0 {
				t.Fatalf("past the bound: fatal %+v pages %+v count %d truncated %v problems %+v", r.Fatal, r.Pages, r.PageCount, r.Truncated, r.Problems)
			}
			// The words the record carries say it was a bound, not a file
			// with nothing to read.
			if r.Fatal.Message != boundMessage {
				t.Errorf("past the bound: the message is %q, want %q", r.Fatal.Message, boundMessage)
			}
		})
	}
}

// An object the reader cannot read past a bound -- the objects it reads, an
// object stream past the inflate bound, an object in a stream nested past
// the bound -- is unread, and the bound is kept for the walk to end at.
func TestObjectsPastABoundAreUnreadAndKept(t *testing.T) {
	// The objects read in one document are what the file has cost the reader,
	// which rebuilding its cross-reference does not give back: that bound is
	// the file's and not one cross-reference's.
	t.Run("the objects the reader reads", func(t *testing.T) {
		d := openGenerated(t, normalDocument(&pdfgen.Builder{}))
		d.parsed = maxObjects
		if _, read := d.objectRead(1); read || !errors.Is(d.fileBound, errStructureBound) {
			t.Fatalf("read %v, bound %v", read, d.fileBound)
		}
	})
	objectStreams := func(extra string) (*pdfgen.Builder, int) {
		b := &pdfgen.Builder{XrefStream: true, ObjectStreams: true, Compress: true}
		num := b.Add(pdfgen.Object{Body: extra})
		b.Add(pdfgen.Object{Body: strings.Repeat("(padding) ", 64)})
		normalDocument(b)
		return b, num
	}
	t.Run("an object stream past the inflate bound", func(t *testing.T) {
		b, num := objectStreams("[1 2 3]")
		d, err := open(context.Background(), b.Bytes(), &inflateBudget{total: 256, one: 16 << 20})
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if _, read := d.objectRead(num); read || !errors.Is(d.bound, errInflateBound) {
			t.Fatalf("read %v, bound %v", read, d.bound)
		}
	})
	t.Run("an object in a stream nested past the bound", func(t *testing.T) {
		b, num := objectStreams(strings.Repeat("[", maxNesting+2) + strings.Repeat("]", maxNesting+2))
		d := openGenerated(t, b.Bytes())
		if _, read := d.objectRead(num); read || !errors.Is(d.bound, errStructureBound) {
			t.Fatalf("read %v, bound %v", read, d.bound)
		}
		if _, read := d.objectRead(num + 1); !read {
			t.Fatal("the object beside it was not read")
		}
	})
}

// An integer read from the file may be written as a real, since writers
// emit "3.0"; a real outside the integers is not one, and a parameter that
// names such a real is left at its default rather than read as a huge
// negative number.
func TestARealOutsideTheIntegersIsNotAnInteger(t *testing.T) {
	d := &Document{budget: &inflateBudget{total: 1 << 20, one: 1 << 20}}
	for _, v := range []float64{1e30, -1e30, math.MaxFloat64, -math.MaxFloat64, 1 << 63} {
		if n, ok := d.intOf(v); ok {
			t.Errorf("the real %g was read as the integer %d", v, n)
		}
	}
	for v, want := range map[float64]int64{3: 3, -3: -3, 0: 0} {
		if n, ok := d.intOf(v); !ok || n != want {
			t.Errorf("the real %g was read as %d (read %v), want %d", v, n, ok, want)
		}
	}
	// One row of one column: /Columns is not read from the real, so the
	// predictor is undone at its default width rather than refused.
	out, err := d.applyPredictor([]byte{2, 5}, Dict{"Predictor": int64(12), "Columns": 1e30})
	if err != nil || !bytes.Equal(out, []byte{5}) {
		t.Fatalf("a /Columns of 1e30: %x, %v", out, err)
	}
}

// An object the reader could not read stays unread: a second reading of it
// reports it unread rather than handing back the marker the first left, so
// the marker never reaches the object graph.
func TestASecondReadingOfADamagedObjectIsStillUnread(t *testing.T) {
	b := &pdfgen.Builder{}
	num := b.Add(pdfgen.Object{Body: "/" + strings.Repeat("N", maxNameBytes+1)})
	d := openGenerated(t, normalDocument(b))
	for reading := 1; reading <= 2; reading++ {
		if v, read := d.resolveRead(ref{num, 0}); read || v != nil {
			t.Fatalf("reading %d: %#v, read %v", reading, v, read)
		}
	}
}

// Where a bound is met decides what it is, and a page's /Resources is read
// while the page tree is walked: the same bound met reading it ends the
// walk, and met reading a font the resources name is no error, leaving the
// page listed with its glyphs unmapped.
func TestABoundInAPagesResourcesEndsTheWalkAndOneInItsFontDoesNot(t *testing.T) {
	nested := "/Junk " + strings.Repeat("[", maxNesting+2) + strings.Repeat("]", maxNesting+2)
	document := func(inResources, inFont string) []byte {
		b := &pdfgen.Builder{}
		font := b.Add(pdfgen.Object{Body: "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding " + inFont + " >>"})
		res := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Font << /F1 %d 0 R >> %s >>", font, inResources)})
		content := b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(shown("text", 700))})
		pages := b.Next()
		b.Add(pdfgen.Object{Body: "placeholder"})
		page := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Page /Parent %d 0 R /Resources %d 0 R /Contents %d 0 R >>", pages, res, content)})
		b.Set(pages, pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%d 0 R] /Count 1 >>", page)})
		b.Catalog(pages)
		return b.Bytes()
	}
	t.Run("within both", func(t *testing.T) {
		r := extract(t, document("", ""))
		if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Text != "text" || r.Pages[0].Unmapped != 0 || len(r.Problems) != 0 {
			t.Fatalf("fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
		}
	})
	t.Run("in the page's resources", func(t *testing.T) {
		r := extract(t, document(nested, ""))
		if r.Fatal == nil || r.Fatal.Code != "pdf-malformed" || r.Fatal.Message != boundMessage || len(r.Pages) != 0 || r.PageCount != 0 {
			t.Fatalf("fatal %+v pages %+v count %d", r.Fatal, r.Pages, r.PageCount)
		}
	})
	t.Run("in a font the resources name", func(t *testing.T) {
		r := extract(t, document("", nested))
		if r.Fatal != nil || len(r.Pages) != 1 || len(r.Problems) != 0 {
			t.Fatalf("fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
		}
		if r.Pages[0].Status != PageOK || r.Pages[0].Unmapped != len("text") {
			t.Fatalf("page %+v, want an ok page of %d unmapped glyphs", r.Pages[0], len("text"))
		}
	})
}
