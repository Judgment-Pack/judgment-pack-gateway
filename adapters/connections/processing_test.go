//go:build linux || darwin

package connections

import (
	"adapters/attachment"
	"adapters/document"
	"adapters/internal/canon"
	"adapters/internal/pdfgen"
	"context"
	"encoding/base64"
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

// readingsFrom is a deadline that passes at the reading of it numbered n and
// at every reading after it; with n of zero it never passes.
type readingsFrom struct {
	context.Context
	n, reads int
}

func (c *readingsFrom) Err() error {
	c.reads++
	if c.n > 0 && c.reads >= c.n {
		return context.DeadlineExceeded
	}
	return nil
}

func (c *readingsFrom) Deadline() (time.Time, bool) { return time.Time{}, false }

// A Drive record of an encrypted PDF whose encryption dictionary the deadline
// stopped the adapter reading is a record the route returns, and not a
// processing failure: the record the document processor writes, given the
// Drive route's source, version and original as the route gives them, passes
// the check at every reading the deadline can pass at. The stream filter the
// dictionary names is an object of its own, followed by a comment of 40,000
// bytes the reader reads the deadline in. The processing seam's own deadline
// is set on a context derived from the route's, which a counting context
// does not reach, so the processor is called as the seam calls it.
func TestDriveRecordOfAnEncryptionTheDeadlineStopped(t *testing.T) {
	b := &pdfgen.Builder{Encrypt: &pdfgen.Encryption{Revision: 4, Permissions: -4}}
	f := b.Font("Helvetica", "WinAnsiEncoding", "")
	b.Catalog(b.Pages([]pdfgen.Page{{Content: pdfgen.Text("F1", 12, []string{"Hello"}), Fonts: map[string]int{"F1": f}}}))
	held := b.Add(pdfgen.Object{Body: "/StdCF %" + strings.Repeat("x", 40000) + "\n"})
	b.Encrypt.Dictionary = func(dict string) string {
		return strings.Replace(dict, "/StmF /StdCF ", fmt.Sprintf("/StmF %d 0 R ", held), 1)
	}
	data := b.Bytes()
	cfg := document.DefaultConfig()
	cfg.OCR = ""
	cfg.MaxOutput = 8 << 20
	identity := attachment.Identity{Name: "adapter-drive", Version: "test", Digest: digest([]byte("test"))}
	started := time.Now()
	request := document.Request{Name: "locked.pdf", MediaType: "application/pdf", Bytes: data, SHA256: digest(data), OCR: "never", ReceivedAt: started}
	live := &readingsFrom{Context: context.Background()}
	if _, err := document.Process(live, cfg, request, identity, started); err != nil {
		t.Fatal(err)
	}
	stopped := 0
	for n := 1; n <= live.reads; n++ {
		encoded, err := document.Process(&readingsFrom{Context: context.Background(), n: n}, cfg, request, identity, started)
		if err != nil {
			t.Fatal(err)
		}
		var record map[string]any
		dec := json.NewDecoder(strings.NewReader(string(encoded)))
		dec.UseNumber()
		if err := dec.Decode(&record); err != nil {
			t.Fatal(err)
		}
		record["document"].(map[string]any)["version"] = "7"
		record["original"] = map[string]any{"retention": "inline", "encoding": "base64", "bytes": base64.StdEncoding.EncodeToString(data)}
		record["provenance"].(map[string]any)["source"] = map[string]any{"kind": "google-drive", "fileId": "file-A", "version": "7", "mediaType": "application/pdf"}
		recordBytes, err := canon.EncodeJSON(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := attachment.Check(recordBytes); err != nil {
			t.Fatalf("deadline at reading %d: the route would fail the record: %v\n%s", n, err, recordBytes)
		}
		if enc, _ := record["document"].(map[string]any)["encryption"].(map[string]any); enc != nil && enc["opened"] == false {
			stopped++
		}
	}
	if stopped == 0 {
		t.Fatal("no reading position left the encryption unopened")
	}
}
