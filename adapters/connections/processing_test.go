//go:build linux || darwin

package connections

import (
	"adapters/attachment"
	"adapters/document"
	"adapters/internal/pdfgen"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDriveProcessingAppliesItsDeclaredDeadline(t *testing.T) {
	pdf := &pdfgen.Builder{}
	pages := pdf.Add(pdfgen.Object{Body: "placeholder"})
	content := pdf.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(strings.Repeat("n ", 200000)), Raw: true})
	var kids []string
	for i := 0; i < 100; i++ {
		id := pdf.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] /Resources << >> /Contents %d 0 R >>", pages, content)})
		kids = append(kids, fmt.Sprintf("%d 0 R", id))
	}
	pdf.Set(pages, pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Count 100 /Kids [%s] >>", strings.Join(kids, " "))})
	pdf.Root = pdf.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Catalog /Pages %d 0 R >>", pages)})
	bytes := pdf.Bytes()
	cfg := document.DefaultConfig()
	cfg.Timeout = time.Millisecond
	cfg.MaxOutput = 8 << 20
	started := time.Now()
	raw, err := processDriveDocument(context.Background(), cfg, document.Request{Name: "bounded.pdf", MediaType: "application/pdf", Bytes: bytes, SHA256: digest(bytes), OCR: "never", ReceivedAt: started}, attachment.Identity{Name: "adapter-drive", Version: "test", Digest: digest([]byte("test"))}, started)
	if err != nil {
		t.Fatal(err)
	}
	var record attachment.Record
	if err = json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, issue := range record.Processing.Errors {
		if issue.Code == attachment.CodeTimeout {
			found = true
		}
	}
	if !found || record.Processing.Bounds.TimeoutMs != 1 {
		t.Fatalf("deadline was not applied: %+v", record.Processing)
	}
	if err = attachment.Check(raw); err != nil {
		t.Fatal(err)
	}
}

// The schema job consumes actual producer output, rather than a hand-authored
// substitute. This is a test-only export; production has no output-path option.
func TestDriveRecordForPublishedSchema(t *testing.T) {
	b, _, _ := testBroker(t)
	f := finish(t, b, start(t, b, "pick"), url.Values{"picked_file_ids": {"file-A"}})
	raw, err := b.provider.read(context.Background(), b.store, mustJSON(ReadRequest{f.Selections[0].Grant, "file-A"}))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
	}
	if err = json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if err = attachment.Check(envelope.Result); err != nil {
		t.Fatal(err)
	}
	if path := os.Getenv("JPACK_TEST_DRIVE_RECORD"); path != "" {
		if err = os.WriteFile(path, envelope.Result, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
