package connections

import (
	"adapters/attachment"
	"adapters/internal/pdfgen"
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestResourcePageBoundsAndAvailability(t *testing.T) {
	valid := func() ResourcePage {
		return ResourcePage{SelectionContext: "epoch", Items: []ResourceItem{{ID: "a", Title: "Policy", URL: "", UnavailableReason: "archived"}}, More: true, NextPageToken: "page-2"}
	}
	if err := ValidateResourcePage(valid()); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ResourcePage){
		func(p *ResourcePage) { p.Items = append(p.Items, p.Items[0]) },
		func(p *ResourcePage) { p.Items[0].URL = "https://example.com/file?token=secret" },
		func(p *ResourcePage) { p.Items[0].UnavailableReason = "guess" },
		func(p *ResourcePage) { p.NextPageToken = "" },
		func(p *ResourcePage) { p.SelectionContext = "" },
		func(p *ResourcePage) { p.Items[0].ID = "bad\nname" },
		func(p *ResourcePage) { n := int64(-1); p.Items[0].SizeBytes = &n },
		func(p *ResourcePage) { p.Items[0].Title = strings.Repeat("x", 1025) },
		func(p *ResourcePage) {
			for i := 0; i < 50; i++ {
				p.Items = append(p.Items, ResourceItem{ID: strconv.Itoa(i) + "other", Title: "Title", URL: ""})
			}
		},
		func(p *ResourcePage) {
			for i := 0; i < 30; i++ {
				p.Items = append(p.Items, ResourceItem{ID: strconv.Itoa(i) + strings.Repeat("x", 2048), Title: "Title", URL: ""})
			}
		},
	} {
		p := valid()
		mutate(&p)
		if ValidateResourcePage(p) == nil {
			t.Fatal("invalid resource page admitted")
		}
	}
}
func TestGenericResourcePDFUsesSharedRecord(t *testing.T) {
	b := &pdfgen.Builder{}
	font := b.Font("Helvetica", "WinAnsiEncoding", "")
	b.Catalog(b.Pages([]pdfgen.Page{{Fonts: map[string]int{"F1": font}, Content: pdfgen.Text("F1", 12, []string{"Fixture PDF policy."})}}))
	raw, err := ResourceDocument(context.Background(), "fixture-files", "bucket/policy.pdf", "Policy.pdf", "application/pdf", "", b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err = attachment.Check(raw); err != nil {
		t.Fatal(err)
	}
	var record attachment.Record
	if json.Unmarshal(raw, &record) != nil || record.Provenance.Source.Kind != attachment.SourceResource || record.Document.MediaType != "application/pdf" || record.Content.Extraction != "text-layer" || len(record.Content.Pages) != 1 || !strings.Contains(record.Content.Pages[0].Text, "Fixture PDF policy.") || record.Provenance.OCR != nil {
		t.Fatal("generic PDF not retained/extracted", string(raw))
	}
	if path := os.Getenv("JPACK_TEST_RESOURCE_PDF"); path != "" {
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
