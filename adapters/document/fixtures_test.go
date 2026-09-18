package document

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"adapters/attachment"
)

var update = flag.Bool("update", false, "rewrite the golden records under testdata/records")

// The fixtures docs/design/attachments.md names, each held to the record
// it yields with the volatile members normalised: observedAt, durationMs
// and the executable digests. `go test ./document/ -update` rewrites the
// golden records after a deliberate change.
func TestFixturesYieldTheirRecords(t *testing.T) {
	cases := []struct {
		file, mediaType string
		cfg             func(*Config)
		status          string
		extraction      string
		codes           []string
	}{
		{"normal.pdf", "application/pdf", nil, attachment.StatusComplete, attachment.ExtractionTextLayer, nil},
		{"scanned.pdf", "application/pdf", nil, attachment.StatusPartial, attachment.ExtractionNone, []string{"ocr-not-run"}},
		{"mixed.pdf", "application/pdf", nil, attachment.StatusPartial, attachment.ExtractionTextLayer, []string{"ocr-not-run"}},
		{"encrypted-rc4.pdf", "application/pdf", nil, attachment.StatusComplete, attachment.ExtractionTextLayer, nil},
		{"encrypted-aes.pdf", "application/pdf", nil, attachment.StatusComplete, attachment.ExtractionTextLayer, nil},
		{"encrypted-user.pdf", "application/pdf", nil, attachment.StatusFailed, attachment.ExtractionNone, []string{"pdf-encrypted"}},
		{"malformed-truncated.pdf", "application/pdf", nil, attachment.StatusFailed, attachment.ExtractionNone, []string{"pdf-malformed"}},
		{"malformed-xref.pdf", "application/pdf", nil, attachment.StatusComplete, attachment.ExtractionTextLayer, nil},
		{"not-a-pdf.pdf", "application/pdf", nil, attachment.StatusFailed, attachment.ExtractionNone, []string{"media-type-mismatch"}},
		{"many-pages.pdf", "application/pdf", func(c *Config) { c.MaxPages = 50 }, attachment.StatusPartial, attachment.ExtractionTextLayer, []string{"pdf-pages-over-bound"}},
		{"inflate-bomb.pdf", "application/pdf", func(c *Config) { c.MaxInflate = 4 << 20 }, attachment.StatusPartial, attachment.ExtractionNone, []string{"stream-over-bound", "stream-over-bound"}},
		{"notes.txt", "text/plain", nil, attachment.StatusComplete, attachment.ExtractionVerbatim, nil},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", c.file))
			if err != nil {
				t.Fatal(err)
			}
			cfg := DefaultConfig()
			if c.cfg != nil {
				c.cfg(&cfg)
			}
			req, err := ParseRequest(strings.NewReader(`{"document":{"name":"`+c.file+`","mediaType":"`+c.mediaType+`","bytes":"`+base64.StdEncoding.EncodeToString(data)+`"}}`), cfg, fixedNow)
			if err != nil {
				t.Fatal(err)
			}
			p := &processor{cfg: cfg, identity: attachment.Identity{Name: adapterName, Version: "fixture", Digest: "sha256:" + strings.Repeat("00", 32)}, reading: fixedNow(), now: fixedNow, runOCR: runOCRProgram}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			out, err := p.process(ctx, req)
			if err != nil {
				t.Fatalf("process: %v", err)
			}
			if err := attachment.Check(out); err != nil {
				t.Fatalf("the record breaks the note's rules: %v", err)
			}
			var rec attachment.Record
			dec := json.NewDecoder(strings.NewReader(string(out)))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&rec); err != nil {
				t.Fatalf("record: %v", err)
			}
			if rec.Processing.Status != c.status || rec.Content.Extraction != c.extraction {
				t.Fatalf("status %s extraction %s, want %s %s; errors %+v", rec.Processing.Status, rec.Content.Extraction, c.status, c.extraction, rec.Processing.Errors)
			}
			var codes []string
			for _, e := range rec.Processing.Errors {
				codes = append(codes, e.Code)
			}
			if strings.Join(codes, ",") != strings.Join(c.codes, ",") {
				t.Fatalf("error codes %v, want %v (%+v)", codes, c.codes, rec.Processing.Errors)
			}
			var pretty map[string]any
			if err := json.Unmarshal(out, &pretty); err != nil {
				t.Fatal(err)
			}
			golden, _ := json.MarshalIndent(pretty, "", "  ")
			golden = append(golden, '\n')
			path := filepath.Join("testdata", "records", strings.TrimSuffix(c.file, filepath.Ext(c.file))+".json")
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, golden, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("no golden record (run with -update): %v", err)
			}
			if string(want) != string(golden) {
				t.Fatalf("the record differs from the golden one at %s; run with -update after a deliberate change\n%s", path, golden)
			}
		})
	}
}
