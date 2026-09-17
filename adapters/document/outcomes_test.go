package document

import (
	"testing"

	"adapters/attachment"
	"adapters/internal/pdfgen"
)

// A ToUnicode map from three codes to NUL, a byte order mark and A yields the
// text the normalisation makes of those characters in that order: the NUL is
// the first character, so the byte order mark after it stays. Under
// --max-text 1 that text is past the budget.
func TestMappedCharactersAreNormalisedInOrder(t *testing.T) {
	b := &pdfgen.Builder{}
	f := b.Type0Font([]rune{0, 0xFEFF, 'A'})
	b.Catalog(b.Pages([]pdfgen.Page{{Content: "BT /F1 12 Tf 1 0 0 1 72 700 Tm <000100020003> Tj ET\n", Fonts: map[string]int{"F1": f}}}))
	cfg := DefaultConfig()
	rec := processed(t, cfg, mustParse(t, cfg, requestJSON("bom.pdf", "application/pdf", b.Bytes(), "")), nil)
	if rec.Processing.Status != attachment.StatusComplete || len(rec.Content.Pages) != 1 || rec.Content.Pages[0].Text != "\xef\xbb\xbfA" || rec.Content.Pages[0].Chars != 2 {
		t.Fatalf("status %s errors %+v pages %+v", rec.Processing.Status, rec.Processing.Errors, rec.Content.Pages)
	}
	cfg.MaxText = 1
	rec = processed(t, cfg, mustParse(t, cfg, requestJSON("bom.pdf", "application/pdf", b.Bytes(), "")), nil)
	if rec.Processing.Status != attachment.StatusFailed || len(rec.Content.Pages) != 0 || codes(rec) != attachment.CodeTextOverBound || !rec.Content.Truncated {
		t.Fatalf("under --max-text 1: status %s errors %+v pages %+v", rec.Processing.Status, rec.Processing.Errors, rec.Content.Pages)
	}
}

// Under --max-text 1, a page showing more text than that and then drawing a
// form with a filter the reader does not implement is failed as unsupported,
// takes nothing from the budget, and the page after it is read.
func TestPagePastTheBudgetWithFailingContentIsFailed(t *testing.T) {
	b := &pdfgen.Builder{}
	f := b.Font("Helvetica", "WinAnsiEncoding", "")
	form := b.Add(pdfgen.Object{Body: "<< /Type /XObject /Subtype /Form /BBox [0 0 1 1] /Filter /DCTDecode >>", Stream: []byte("x"), Raw: true})
	fonts := map[string]int{"F1": f}
	b.Catalog(b.Pages([]pdfgen.Page{
		{Content: "BT /F1 12 Tf 1 0 0 1 72 700 Tm (TOOLONG) Tj ET\n/X1 Do\n", Fonts: fonts, XObjects: map[string]int{"X1": form}},
		{Content: "BT /F1 12 Tf 1 0 0 1 72 700 Tm (B) Tj ET\n", Fonts: fonts},
	}))
	cfg := DefaultConfig()
	cfg.MaxText = 1
	rec := processed(t, cfg, mustParse(t, cfg, requestJSON("form.pdf", "application/pdf", b.Bytes(), "")), nil)
	if rec.Processing.Status != attachment.StatusPartial || codes(rec) != attachment.CodePDFUnsupported || rec.Content.Truncated {
		t.Fatalf("status %s errors %+v truncated %v", rec.Processing.Status, rec.Processing.Errors, rec.Content.Truncated)
	}
	pages := rec.Content.Pages
	if len(pages) != 2 || pages[0].Status != attachment.PageFailed || pages[1].Status != attachment.PageOK || pages[1].Text != "B" || rec.Content.Chars != 1 {
		t.Fatalf("pages %+v", pages)
	}
}
