package document

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"adapters/attachment"
	"adapters/internal/pdfgen"
)

const shownText = "BT /F1 12 Tf 1 0 0 1 72 700 Tm (before) Tj ET\n"

// A content stream every filter decodes is charged to --max-inflate: an
// ASCIIHex stream under a bound of one byte fails its page.
func TestASCIIHexContentIsChargedToMaxInflate(t *testing.T) {
	b := &pdfgen.Builder{}
	f := b.Font("Helvetica", "WinAnsiEncoding", "")
	b.Catalog(b.Pages([]pdfgen.Page{{Content: hex.EncodeToString([]byte(shownText)) + ">", ContentDict: "<< /Filter /ASCIIHexDecode >>", Fonts: map[string]int{"F1": f}}}))
	cfg := DefaultConfig()
	cfg.MaxInflate = 1
	rec := processed(t, cfg, mustParse(t, cfg, requestJSON("hex.pdf", "application/pdf", b.Bytes(), "")), nil)
	if rec.Processing.Status != attachment.StatusPartial || len(rec.Content.Pages) != 1 || rec.Content.Pages[0].Status != attachment.PageFailed || codes(rec) != attachment.CodeStreamOverBound {
		t.Fatalf("status %s errors %+v pages %+v", rec.Processing.Status, rec.Processing.Errors, rec.Content.Pages)
	}
	cfg.MaxInflate = int64(len(shownText))
	rec = processed(t, cfg, mustParse(t, cfg, requestJSON("hex.pdf", "application/pdf", b.Bytes(), "")), nil)
	if rec.Processing.Status != attachment.StatusComplete || rec.Content.Pages[0].Text != "before" {
		t.Fatalf("at the bound: status %s errors %+v pages %+v", rec.Processing.Status, rec.Processing.Errors, rec.Content.Pages)
	}
}

// A page whose FlateDecode content is cut off is failed, and none of the text
// decoded before the cut is listed: the record is partial, not complete.
func TestFlateContentCutOffFailsItsPage(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 3000; i++ {
		fmt.Fprintf(&sb, "BT /F1 12 Tf 72 %d Td (LINE%05d) Tj ET\n", 700-i%600, i)
	}
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	w.Write([]byte(sb.String()))
	w.Close()
	b := &pdfgen.Builder{}
	f := b.Font("Helvetica", "WinAnsiEncoding", "")
	b.Catalog(b.Pages([]pdfgen.Page{
		{Content: string(z.Bytes()[:z.Len()/2]), ContentDict: "<< /Filter /FlateDecode >>", Fonts: map[string]int{"F1": f}},
		{Content: shownText, Fonts: map[string]int{"F1": f}},
	}))
	cfg := DefaultConfig()
	rec := processed(t, cfg, mustParse(t, cfg, requestJSON("cut.pdf", "application/pdf", b.Bytes(), "")), nil)
	if rec.Processing.Status != attachment.StatusPartial || codes(rec) != attachment.CodePDFPageFailed || len(rec.Content.Pages) != 2 {
		t.Fatalf("status %s errors %+v pages %d", rec.Processing.Status, rec.Processing.Errors, len(rec.Content.Pages))
	}
	if p := rec.Content.Pages[0]; p.Status != attachment.PageFailed || p.Text != "" || rec.Content.Pages[1].Text != "before" {
		t.Fatalf("pages %+v", rec.Content.Pages)
	}
}

// A RunLength stream that runs past the total leaves it spent: the next
// page's stream, small as it is, finds nothing left and fails too.
func TestRunLengthPastTheTotalSpendsIt(t *testing.T) {
	b := &pdfgen.Builder{}
	f := b.Font("Helvetica", "WinAnsiEncoding", "")
	literal := append([]byte{byte(len(shownText) - 1)}, shownText...)
	b.Catalog(b.Pages([]pdfgen.Page{
		// 128 spaces, then the end-of-data marker.
		{Content: "\x81 \x80", ContentDict: "<< /Filter /RunLengthDecode >>", Fonts: map[string]int{"F1": f}},
		{Content: string(append(literal, 128)), ContentDict: "<< /Filter /RunLengthDecode >>", Fonts: map[string]int{"F1": f}},
	}))
	cfg := DefaultConfig()
	cfg.MaxInflate = 50
	rec := processed(t, cfg, mustParse(t, cfg, requestJSON("rl.pdf", "application/pdf", b.Bytes(), "")), nil)
	if rec.Processing.Status != attachment.StatusPartial || len(rec.Content.Pages) != 2 || codes(rec) != attachment.CodeStreamOverBound+","+attachment.CodeStreamOverBound {
		t.Fatalf("status %s errors %+v pages %+v", rec.Processing.Status, rec.Processing.Errors, rec.Content.Pages)
	}
	for i, pg := range rec.Content.Pages {
		if pg.Status != attachment.PageFailed || rec.Processing.Errors[i].Page == nil || *rec.Processing.Errors[i].Page != int64(i+1) {
			t.Fatalf("page %d: %+v errors %+v", i+1, pg, rec.Processing.Errors)
		}
	}
}
