package document

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"adapters/attachment"
	"adapters/internal/canon"
	"adapters/internal/pdfgen"
)

var testIdentity = attachment.Identity{Name: adapterName, Version: "test", Digest: "sha256:" + strings.Repeat("ab", 32)}

func fixedNow() time.Time { return time.Date(2026, 9, 16, 14, 5, 11, 0, time.UTC) }

func requestJSON(name, mediaType string, data []byte, extra string) string {
	return `{"document":{"name":` + quote(name) + `,"mediaType":` + quote(mediaType) + `,"bytes":` + quote(base64.StdEncoding.EncodeToString(data)) + extra + `}}`
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func parse(t *testing.T, cfg Config, in string) (Request, error) {
	t.Helper()
	return ParseRequest(context.Background(), strings.NewReader(in), cfg, fixedNow)
}

func refusalCode(err error) string {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Code
	}
	return ""
}

func TestParseRequestRefusals(t *testing.T) {
	cfg := DefaultConfig()
	cases := map[string]struct{ in, code string }{
		"not an object":         {`[]`, "arguments-invalid"},
		"unknown top member":    {`{"document":{"name":"a","mediaType":"text/plain","bytes":"aGk="},"x":1}`, "arguments-invalid"},
		"missing document":      {`{"options":{}}`, "arguments-invalid"},
		"unknown doc member":    {`{"document":{"name":"a","mediaType":"text/plain","bytes":"aGk=","x":1}}`, "arguments-invalid"},
		"duplicate member":      {`{"document":{"name":"a","name":"b","mediaType":"text/plain","bytes":"aGk="}}`, "arguments-invalid"},
		"empty name":            {requestJSON("", "text/plain", []byte("hi"), ""), "arguments-invalid"},
		"control in name":       {requestJSON("a\x01b", "text/plain", []byte("hi"), ""), "arguments-invalid"},
		"long name":             {requestJSON(strings.Repeat("n", 256), "text/plain", []byte("hi"), ""), "arguments-invalid"},
		"name not a string":     {`{"document":{"name":null,"mediaType":"text/plain","bytes":"aGk="}}`, "arguments-invalid"},
		"uppercase type":        {requestJSON("a", "Text/Plain", []byte("hi"), ""), "arguments-invalid"},
		"type with parameter":   {requestJSON("a", "text/plain; charset=utf-8", []byte("hi"), ""), "arguments-invalid"},
		"type part of 128":      {requestJSON("a", "text/"+strings.Repeat("x", 128), []byte("hi"), ""), "arguments-invalid"},
		"empty bytes":           {`{"document":{"name":"a","mediaType":"text/plain","bytes":""}}`, "arguments-invalid"},
		"not base64":            {`{"document":{"name":"a","mediaType":"text/plain","bytes":"a*b"}}`, "arguments-invalid"},
		"url-safe base64":       {`{"document":{"name":"a","mediaType":"text/plain","bytes":"aGk-"}}`, "arguments-invalid"},
		"nonzero pad bits":      {`{"document":{"name":"a","mediaType":"text/plain","bytes":"Zh=="}}`, "arguments-invalid"},
		"unpadded":              {`{"document":{"name":"a","mediaType":"text/plain","bytes":"Zg"}}`, "arguments-invalid"},
		"digest form":           {requestJSON("a", "text/plain", []byte("hi"), `,"sha256":"SHA256:`+strings.Repeat("0", 64)+`"`), "arguments-invalid"},
		"bad ocr option":        {`{"document":{"name":"a","mediaType":"text/plain","bytes":"aGk="},"options":{"ocr":"always"}}`, "arguments-invalid"},
		"unknown option":        {`{"document":{"name":"a","mediaType":"text/plain","bytes":"aGk="},"options":{"x":1}}`, "arguments-invalid"},
		"digest mismatch":       {requestJSON("a", "text/plain", []byte("hi"), `,"sha256":"sha256:`+strings.Repeat("0", 64)+`"`), "digest-mismatch"},
		"not JSON":              {`not json`, "arguments-invalid"},
		"an unsupported syntax": {requestJSON("a", "application/x-", []byte("hi"), ""), ""},
		// Outside the canonical domain, which the gateway refuses before the
		// adapter runs: the name would reach the record as U+FFFD.
		"a name not valid UTF-8":            {`{"document":{"name":"a` + "\xff" + `","mediaType":"text/plain","bytes":"aGk="}}`, "arguments-invalid"},
		"a name with an unpaired surrogate": {`{"document":{"name":"a\ud800","mediaType":"text/plain","bytes":"aGk="}}`, "arguments-invalid"},
		"a name with a surrogate pair":      {`{"document":{"name":"a\ud83d\ude00","mediaType":"text/plain","bytes":"aGk="}}`, ""},
		"a number past the domain":          {`{"document":{"name":"a","mediaType":"text/plain","bytes":"aGk="},"options":{"ocr":1.5}}`, "arguments-invalid"},
	}
	for name, c := range cases {
		_, err := parse(t, cfg, c.in)
		if c.code == "" {
			if err != nil {
				t.Errorf("%s: refused %v, want admitted", name, err)
			}
			continue
		}
		if got := refusalCode(err); got != c.code {
			t.Errorf("%s: refused %q (%v), want %q", name, got, err, c.code)
		}
	}
	req, err := parse(t, cfg, requestJSON("a.txt", "text/plain", []byte("hi"), ""))
	if err != nil || req.Name != "a.txt" || string(req.Bytes) != "hi" || req.OCR != "auto" || req.ReceivedAt != fixedNow() {
		t.Fatalf("good request: %+v %v", req, err)
	}
	withDigest := requestJSON("a", "text/plain", []byte("hi"), `,"sha256":"`+digestOf([]byte("hi"))+`"`)
	if req, err := parse(t, cfg, withDigest); err != nil || req.SHA256 == "" {
		t.Fatalf("digest claim: %+v %v", req, err)
	}
	withNever := `{"document":{"name":"a","mediaType":"text/plain","bytes":"aGk="},"options":{"ocr":"never"}}`
	if req, err := parse(t, cfg, withNever); err != nil || req.OCR != "never" {
		t.Fatalf("options: %+v %v", req, err)
	}
}

// The four checks run in order and the first that fails is the refusal.
func TestRefusalsTakeTheFirstCheckThatFails(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxBytes = 1
	wrongDigest := `,"sha256":"sha256:` + strings.Repeat("0", 64) + `"`
	// Past the document bound and with a wrong digest: the size check comes first.
	if code := refusalCode(second(parse(t, cfg, requestJSON("a", "text/plain", []byte("ab"), wrongDigest)))); code != "document-over-bound" {
		t.Errorf("size before digest: %s", code)
	}
	// A defective argument past the document bound: the arguments come first.
	if code := refusalCode(second(parse(t, cfg, requestJSON("a", "Text/Plain", []byte("ab"), "")))); code != "arguments-invalid" {
		t.Errorf("arguments before size: %s", code)
	}
	// Past the read bound, whatever else: the read bound comes first.
	bound, _ := ReadBound(cfg)
	if code := refusalCode(second(parse(t, cfg, `{"x":"`+strings.Repeat("y", int(bound))+`"}`))); code != "request-over-bound" {
		t.Errorf("read bound first: %s", code)
	}
}

func second(_ Request, err error) error { return err }

func TestReadBoundFitsADocumentAtMaxBytes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxBytes = 3000
	if bound, ok := ReadBound(cfg); !ok || bound != 4000+65536 {
		t.Fatalf("read bound %d, want 4 x ceil(3000/3) + 65536", bound)
	}
	doc := strings.Repeat("x", 3000)
	name := strings.Repeat("\"", 255) // escaped to 510 bytes
	in := requestJSON(name, "application/"+strings.Repeat("p", 127), []byte(doc), `,"sha256":"`+digestOf([]byte(doc))+`"`)
	in = strings.TrimSuffix(in, "}") + `,"options":{"ocr":"never"}}`
	if _, err := parse(t, cfg, in); err != nil {
		t.Fatalf("a document at the bound with the longest name and type is refused: %v", err)
	}
	over := requestJSON("a", "text/plain", []byte(strings.Repeat("x", 60000)), "")
	if _, err := parse(t, cfg, over); refusalCode(err) != "request-over-bound" {
		t.Fatalf("a document past the read bound: %v", err)
	}
	// Within the read bound's slack but past the document bound: refused
	// too, never a record.
	slack := requestJSON("a", "text/plain", []byte(strings.Repeat("x", 3001)), "")
	if _, err := parse(t, cfg, slack); refusalCode(err) != "document-over-bound" {
		t.Fatalf("a document just past the bound: %v", err)
	}
}

// A refusal line is ASCII, at most 160 bytes, and starts with its code,
// whatever the caller wrote into the arguments.
func TestRefusalLineIsBoundedASCII(t *testing.T) {
	cfg := DefaultConfig()
	_, err := parse(t, cfg, `{"document":{"name":"a","mediaType":"text/plain","bytes":"aGk=","`+strings.Repeat("\xc3\xa9", 200)+`":1}}`)
	var r *Refusal
	if !errors.As(err, &r) {
		t.Fatalf("not a refusal: %v", err)
	}
	line := (&Refusal{Code: r.Code, Reason: r.Reason + strings.Repeat(" \xc3\xa9\x01", 100)}).Line()
	if len(line) > 160 || !strings.HasPrefix(line, "arguments-invalid: ") {
		t.Fatalf("line %d bytes: %q", len(line), line)
	}
	for i := 0; i < len(line); i++ {
		if line[i] < 0x20 || line[i] > 0x7e {
			t.Fatalf("byte %d of the line is %#x", i, line[i])
		}
	}
	if strings.Contains(r.Reason, "\xc3\xa9") {
		t.Fatalf("the reason quotes the caller's member name: %q", r.Reason)
	}
	// No member name the caller wrote is named, however short and plain, at
	// any level of the arguments.
	for _, in := range []string{
		`{"document":{"name":"a","mediaType":"text/plain","bytes":"aGk=","PATIENT_ID_1234":1}}`,
		`{"document":{"name":"a","mediaType":"text/plain","bytes":"aGk="},"PATIENT_ID_1234":1}`,
		`{"document":{"name":"a","mediaType":"text/plain","bytes":"aGk="},"options":{"PATIENT_ID_1234":1}}`,
		`{"document":{"name":"a","mediaType":"text/plain","bytes":"aGk=","x":1}}`,
	} {
		_, err := parse(t, cfg, in)
		var r *Refusal
		if !errors.As(err, &r) || r.Code != "arguments-invalid" {
			t.Fatalf("%s: %v", in, err)
		}
		if line := r.Line(); strings.Contains(line, "PATIENT") || strings.Contains(line, "1234") || strings.Contains(line, "(x)") || !strings.Contains(line, "a member the contract does not name") {
			t.Errorf("the refusal names the caller's member: %q", line)
		}
	}
	// A member given twice is one the contract names, and is named.
	_, err = parse(t, cfg, `{"document":{"name":"a","name":"b","mediaType":"text/plain","bytes":"aGk="}}`)
	if !errors.As(err, &r) || !strings.Contains(r.Line(), "name") {
		t.Fatalf("a duplicate member: %v", err)
	}
}

// processed runs a request through the processor and holds the record to
// attachment.Check before returning it.
func processed(t *testing.T, cfg Config, req Request, ocr OCRRunner) attachment.Record {
	t.Helper()
	return processedIn(t, context.Background(), cfg, req, ocr)
}

func processedIn(t *testing.T, ctx context.Context, cfg Config, req Request, ocr OCRRunner) attachment.Record {
	t.Helper()
	p := &processor{cfg: cfg, identity: testIdentity, reading: fixedNow(), now: fixedNow, runOCR: ocr}
	if ocr == nil {
		p.runOCR = func(context.Context, string, []int, []byte, int64) ([]byte, string, error) {
			t.Fatal("the OCR program ran")
			return nil, "", nil
		}
	}
	out, err := p.process(ctx, req)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if err := attachment.Check(out); err != nil {
		t.Fatalf("the record breaks the note's rules: %v\n%s", err, out)
	}
	var rec attachment.Record
	dec := json.NewDecoder(strings.NewReader(string(out)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		t.Fatalf("record does not decode: %v\n%s", err, out)
	}
	return rec
}

func mustParse(t *testing.T, cfg Config, in string) Request {
	t.Helper()
	req, err := parse(t, cfg, in)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestTextDocumentIsVerbatim(t *testing.T) {
	cfg := DefaultConfig()
	raw := []byte("\xEF\xBB\xBFline one\r\nline two\r\n")
	rec := processed(t, cfg, mustParse(t, cfg, requestJSON("notes.txt", "text/plain", raw, "")), nil)
	if rec.Processing.Status != attachment.StatusComplete || rec.Content.Extraction != attachment.ExtractionVerbatim || len(rec.Content.Pages) != 1 || rec.Content.PageCount != 1 {
		t.Fatalf("%+v", rec)
	}
	pg := rec.Content.Pages[0]
	if pg.Text != "line one\nline two" || pg.Chars != 17 || pg.Status != attachment.PageOK || pg.Extraction != attachment.ExtractionVerbatim {
		t.Fatalf("page: %+v", pg)
	}
	if rec.Document.ID != digestOf(raw) || rec.Document.Size != int64(len(raw)) || *rec.Document.DetectedMediaType != attachment.MediaText || *rec.Provenance.Processor != attachment.ProcessorText {
		t.Fatalf("document: %+v provenance: %+v", rec.Document, rec.Provenance)
	}
	if rec.Provenance.ObservedAt != "2026-09-16T14:05:11Z" || rec.Processing.DurationMs != 0 {
		t.Fatalf("provenance: %+v processing: %+v", rec.Provenance, rec.Processing)
	}
	// A file of blank lines is a no-text page, and still complete.
	rec = processed(t, cfg, mustParse(t, cfg, requestJSON("blank.txt", "text/plain", []byte(" \n\t\n"), "")), nil)
	if rec.Processing.Status != attachment.StatusComplete || rec.Content.Pages[0].Status != attachment.PageNoText || rec.Content.Extraction != attachment.ExtractionVerbatim {
		t.Fatalf("blank: %+v", rec)
	}
	// Past the text budget: nothing listed, a failed record, counted and truncated.
	cfg.MaxText = 4
	rec = processed(t, cfg, mustParse(t, cfg, requestJSON("long.txt", "text/plain", []byte("12345"), "")), nil)
	if rec.Processing.Status != attachment.StatusFailed || len(rec.Content.Pages) != 0 || rec.Content.PageCount != 1 || !rec.Content.Truncated || rec.Processing.Errors[0].Code != attachment.CodeTextOverBound {
		t.Fatalf("over the budget: %+v", rec)
	}
	cfg.MaxText = 5
	rec = processed(t, cfg, mustParse(t, cfg, requestJSON("long.txt", "text/plain", []byte("12345"), "")), nil)
	if rec.Processing.Status != attachment.StatusComplete {
		t.Fatalf("exactly at the budget: %+v", rec)
	}
}

func TestUnsupportedAndMismatchedTypes(t *testing.T) {
	cfg := DefaultConfig()
	rec := processed(t, cfg, mustParse(t, cfg, requestJSON("b.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", []byte("PK"), "")), nil)
	if rec.Processing.Status != attachment.StatusFailed || rec.Processing.Errors[0].Code != attachment.CodeMediaTypeUnsupported || rec.Provenance.Processor != nil || rec.Document.DetectedMediaType != nil {
		t.Fatalf("%+v", rec)
	}
	rec = processed(t, cfg, mustParse(t, cfg, requestJSON("x.pdf", "application/pdf", []byte("plain text"), "")), nil)
	if rec.Processing.Status != attachment.StatusFailed || rec.Processing.Errors[0].Code != attachment.CodeMediaTypeMismatch || rec.Provenance.Processor != nil || rec.Document.DetectedMediaType != nil {
		t.Fatalf("%+v", rec)
	}
	rec = processed(t, cfg, mustParse(t, cfg, requestJSON("x.txt", "text/plain", []byte{0xff, 0xfe, 'a'}, "")), nil)
	if rec.Processing.Status != attachment.StatusFailed || rec.Processing.Errors[0].Code != attachment.CodeMediaTypeMismatch {
		t.Fatalf("%+v", rec)
	}
	// A PDF header within the first 1024 bytes, and just past them.
	late := append([]byte(strings.Repeat(" ", 1019)), []byte("%PDF-1.4")...)
	rec = processed(t, cfg, mustParse(t, cfg, requestJSON("late.pdf", "application/pdf", late, "")), nil)
	if rec.Processing.Errors[0].Code != attachment.CodePDFMalformed {
		t.Fatalf("a header ending at byte 1024 is a header: %+v", rec.Processing.Errors)
	}
	later := append([]byte(strings.Repeat(" ", 1020)), []byte("%PDF-1.4")...)
	rec = processed(t, cfg, mustParse(t, cfg, requestJSON("later.pdf", "application/pdf", later, "")), nil)
	if rec.Processing.Errors[0].Code != attachment.CodeMediaTypeMismatch {
		t.Fatalf("a header past byte 1024 is not: %+v", rec.Processing.Errors)
	}
}

func scannedPDF(t *testing.T) []byte {
	t.Helper()
	b := &pdfgen.Builder{Compress: true}
	img := b.Image()
	f := b.Font("Helvetica", "WinAnsiEncoding", "")
	b.Catalog(b.Pages([]pdfgen.Page{
		{Content: pdfgen.Text("F1", 12, []string{"Cover letter"}), Fonts: map[string]int{"F1": f}},
		{Content: "q 612 0 0 792 0 0 cm /Im1 Do Q\n", XObjects: map[string]int{"Im1": img}},
		{Content: "q 612 0 0 792 0 0 cm /Im1 Do Q\n", XObjects: map[string]int{"Im1": img}},
	}))
	return b.Bytes()
}

func TestScannedPagesWithoutOCR(t *testing.T) {
	cfg := DefaultConfig()
	rec := processed(t, cfg, mustParse(t, cfg, requestJSON("scan.pdf", "application/pdf", scannedPDF(t), "")), nil)
	if rec.Processing.Status != attachment.StatusPartial || rec.Content.Extraction != attachment.ExtractionTextLayer {
		t.Fatalf("%+v", rec.Processing)
	}
	if len(rec.Processing.Errors) != 1 || rec.Processing.Errors[0].Code != attachment.CodeOCRNotRun || !strings.Contains(rec.Processing.Errors[0].Message, "no OCR program is configured") {
		t.Fatalf("errors: %+v", rec.Processing.Errors)
	}
	if rec.Content.Pages[1].Status != attachment.PageNeedsOCR || rec.Content.Pages[1].Extraction != attachment.ExtractionNone || rec.Content.Pages[2].Status != attachment.PageNeedsOCR {
		t.Fatalf("pages: %+v", rec.Content.Pages)
	}
	cfg.OCR = "some-program"
	req := mustParse(t, cfg, `{"document":{"name":"s.pdf","mediaType":"application/pdf","bytes":"`+base64.StdEncoding.EncodeToString(scannedPDF(t))+`"},"options":{"ocr":"never"}}`)
	rec = processed(t, cfg, req, nil)
	if rec.Processing.Errors[0].Code != attachment.CodeOCRNotRun || !strings.Contains(rec.Processing.Errors[0].Message, "asked for no OCR") {
		t.Fatalf("errors: %+v", rec.Processing.Errors)
	}
}

func answering(stdout string) OCRRunner {
	return func(context.Context, string, []int, []byte, int64) ([]byte, string, error) {
		return []byte(stdout), "sha256:" + strings.Repeat("cd", 32), nil
	}
}

func failing(err error) OCRRunner {
	return func(context.Context, string, []int, []byte, int64) ([]byte, string, error) {
		return nil, "sha256:" + strings.Repeat("cd", 32), err
	}
}

func codes(rec attachment.Record) string {
	var out []string
	for _, e := range rec.Processing.Errors {
		out = append(out, e.Code)
	}
	return strings.Join(out, ",")
}

func TestOCRAnswerOutcomes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OCR = "ocr-pages"
	doc := scannedPDF(t)
	req := mustParse(t, cfg, requestJSON("scan.pdf", "application/pdf", doc, ""))
	var asked []int
	rec := processed(t, cfg, req, func(ctx context.Context, program string, pages []int, data []byte, maxOutput int64) ([]byte, string, error) {
		asked = pages
		if string(data) != string(doc) || program != "ocr-pages" || maxOutput != cfg.OCRMaxOutput {
			t.Fatalf("the program was given %d bytes, program %q, bound %d", len(data), program, maxOutput)
		}
		return []byte(`{"pages":[{"number":2,"text":"SIGNED\r\n"},{"number":3,"text":"   "}]}`), "sha256:" + strings.Repeat("cd", 32), nil
	})
	if len(asked) != 2 || asked[0] != 2 || asked[1] != 3 {
		t.Fatalf("asked %v", asked)
	}
	if rec.Processing.Status != attachment.StatusComplete || rec.Content.Extraction != attachment.ExtractionMixed || len(rec.Processing.Errors) != 0 {
		t.Fatalf("complete: %+v", rec.Processing)
	}
	if p := rec.Content.Pages[1]; p.Status != attachment.PageOK || p.Text != "SIGNED" || p.Extraction != attachment.ExtractionOCR || p.Chars != 6 {
		t.Fatalf("page 2: %+v", p)
	}
	if p := rec.Content.Pages[2]; p.Status != attachment.PageNoText || p.Text != "" || p.Extraction != attachment.ExtractionOCR {
		t.Fatalf("page 3: %+v", p)
	}
	if rec.Provenance.OCR == nil || rec.Provenance.OCR.Program != "ocr-pages" || len(rec.Provenance.OCR.Pages) != 2 {
		t.Fatalf("provenance: %+v", rec.Provenance.OCR)
	}
	// The answer's own order does not matter.
	rec = processed(t, cfg, req, answering(`{"pages":[{"number":3,"text":"three"},{"number":2,"text":"two"}]}`))
	if rec.Content.Pages[1].Text != "two" || rec.Content.Pages[2].Text != "three" || rec.Provenance.OCR.Pages[0] != 2 {
		t.Fatalf("order: %+v", rec.Content.Pages)
	}
	// Incomplete: applied where answered, counted where not.
	rec = processed(t, cfg, req, answering(`{"pages":[{"number":3,"text":"last"}]}`))
	if codes(rec) != "ocr-incomplete" || rec.Content.Pages[1].Status != attachment.PageNeedsOCR || rec.Content.Pages[2].Text != "last" || rec.Provenance.OCR.Pages[0] != 3 {
		t.Fatalf("incomplete: %+v %+v", rec.Processing, rec.Content.Pages)
	}
	// An admitted answer of no pages is incomplete for all.
	rec = processed(t, cfg, req, answering(`{"pages":[]}`))
	if codes(rec) != "ocr-incomplete" || rec.Provenance.OCR != nil {
		t.Fatalf("empty: %+v", rec.Processing)
	}
	// Refused answers apply nothing.
	for name, answer := range map[string]string{
		"a page not asked for":     `{"pages":[{"number":2,"text":"a"},{"number":1,"text":"b"}]}`,
		"a page past the document": `{"pages":[{"number":9,"text":"a"}]}`,
		"a page twice":             `{"pages":[{"number":2,"text":"a"},{"number":2,"text":"b"}]}`,
		"a duplicate member":       `{"pages":[{"number":2,"text":"a","text":"b"}]}`,
		"an unpaired surrogate":    `{"pages":[{"number":2,"text":"\` + `ud800"}]}`,
		"a fraction":               `{"pages":[{"number":2.0,"text":"a"}]}`,
		"an exponent":              `{"pages":[{"number":2e0,"text":"a"}]}`,
		"a quoted number":          `{"pages":[{"number":"2","text":"a"}]}`,
		"a null text":              `{"pages":[{"number":2,"text":null}]}`,
		"null pages":               `{"pages":null}`,
		"an extra member":          `{"pages":[],"x":1}`,
		"an entry's extra member":  `{"pages":[{"number":2,"text":"a","x":1}]}`,
		"trailing content":         `{"pages":[]} {}`,
		"invalid UTF-8":            "{\"pages\":[{\"number\":2,\"text\":\"\xff\"}]}",
		"not JSON":                 `pages: 2`,
	} {
		rec = processed(t, cfg, req, answering(answer))
		if codes(rec) != "ocr-failed" || rec.Provenance.OCR != nil || rec.Content.Pages[1].Status != attachment.PageNeedsOCR || rec.Content.Pages[2].Status != attachment.PageNeedsOCR {
			t.Errorf("%s: %s %+v", name, codes(rec), rec.Content.Pages)
		}
	}
	// Whitespace around the value is admitted.
	rec = processed(t, cfg, req, answering(" \n"+`{"pages":[{"number":2,"text":"a"},{"number":3,"text":"b"}]}`+"\n"))
	if codes(rec) != "" {
		t.Fatalf("whitespace: %s", codes(rec))
	}
	// A failure and a timeout.
	rec = processed(t, cfg, req, failing(errors.New("exited with a non-zero status")))
	if codes(rec) != "ocr-failed" {
		t.Fatalf("failed: %+v", rec.Processing)
	}
	rec = processed(t, cfg, req, failing(errOCRTimeout))
	if codes(rec) != "ocr-timeout" {
		t.Fatalf("timeout: %+v", rec.Processing)
	}
	// The text budget is shared: page 1 has 12 bytes of text.
	cfg.MaxText = 20
	rec = processed(t, cfg, req, answering(`{"pages":[{"number":2,"text":"1234567"},{"number":3,"text":"12345678901"}]}`))
	if rec.Content.Pages[1].Text != "1234567" || rec.Content.Pages[2].Status != attachment.PageNeedsOCR || rec.Content.Truncated {
		t.Fatalf("budget: %+v", rec.Content)
	}
	if codes(rec) != "text-over-bound" || *rec.Processing.Errors[0].Page != 3 {
		t.Fatalf("budget errors: %+v", rec.Processing.Errors)
	}
	// A budget stop holds back every later answered page, even one that
	// would fit: page 2 crosses the budget, page 3's one byte stays unapplied.
	four := &pdfgen.Builder{Compress: true}
	img := four.Image()
	helv := four.Font("Helvetica", "WinAnsiEncoding", "")
	scan := pdfgen.Page{Content: "q 612 0 0 792 0 0 cm /Im1 Do Q\n", XObjects: map[string]int{"Im1": img}}
	four.Catalog(four.Pages([]pdfgen.Page{{Content: pdfgen.Text("F1", 12, []string{"Cover letter"}), Fonts: map[string]int{"F1": helv}}, scan, scan, scan}))
	fourReq := mustParse(t, cfg, requestJSON("four.pdf", "application/pdf", four.Bytes(), ""))
	rec = processed(t, cfg, fourReq, answering(`{"pages":[{"number":2,"text":"123456789"},{"number":3,"text":"1"},{"number":4,"text":"2"}]}`))
	if codes(rec) != "text-over-bound" || *rec.Processing.Errors[0].Page != 2 || rec.Content.Pages[2].Status != attachment.PageNeedsOCR || rec.Content.Pages[3].Status != attachment.PageNeedsOCR || rec.Provenance.OCR != nil {
		t.Fatalf("after the budget stop: %s %+v", codes(rec), rec.Content.Pages)
	}
	// Exactly at the budget fits.
	rec = processed(t, cfg, req, answering(`{"pages":[{"number":2,"text":"1234"},{"number":3,"text":"5678"}]}`))
	if codes(rec) != "" {
		t.Fatalf("at the budget: %+v", rec.Processing.Errors)
	}
}

// The deadline found passed after the program was resolved and digested
// and before its start: timeout, one deadline code, and nothing applied.
func TestDeadlineBeforeTheOCRStart(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OCR = "ocr-pages"
	req := mustParse(t, cfg, requestJSON("scan.pdf", "application/pdf", scannedPDF(t), ""))
	rec := processed(t, cfg, req, failing(errOCRNotStarted))
	if codes(rec) != "timeout" || rec.Content.Pages[1].Status != attachment.PageNeedsOCR || rec.Provenance.OCR != nil || rec.Content.Truncated {
		t.Fatalf("%s %+v", codes(rec), rec.Content)
	}
	// The runner makes that check itself: a context already past its
	// deadline starts nothing.
	dir := t.TempDir()
	marker := filepath.Join(dir, "started")
	program := filepath.Join(dir, "program")
	if err := os.WriteFile(program, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, digest, err := runOCRProgram(ctx, program, []int{1}, nil, 100); !errors.Is(err, errOCRNotStarted) || !attachment.ValidDigest(digest) {
		t.Fatalf("a passed deadline: %v %q", err, digest)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the program was started after the deadline had passed")
	}
}

func TestConfigRefusesATimeoutThatIsNotWholeMilliseconds(t *testing.T) {
	for _, d := range []time.Duration{0, 500 * time.Microsecond, 1500 * time.Microsecond, -time.Second} {
		cfg := DefaultConfig()
		cfg.Timeout = d
		if cfg.Check() == nil {
			t.Errorf("timeout %v accepted", d)
		}
	}
	cfg := DefaultConfig()
	cfg.Timeout = time.Millisecond
	if err := cfg.Check(); err != nil {
		t.Fatalf("one millisecond: %v", err)
	}
}

func TestRecordPastTheOutputBoundFails(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxOutput = 200
	p := &processor{cfg: cfg, identity: testIdentity, reading: fixedNow(), now: fixedNow}
	_, err := p.process(context.Background(), mustParse(t, cfg, requestJSON("n.txt", "text/plain", []byte(strings.Repeat("a", 300)), "")))
	if refusalCode(err) != "record-over-bound" {
		t.Fatalf("err: %v", err)
	}
}

func TestRecordIsCanonicalBeforeItsOutputBoundIsChecked(t *testing.T) {
	cfg := DefaultConfig()
	p := &processor{cfg: cfg, identity: testIdentity, reading: fixedNow(), now: fixedNow}
	req := mustParse(t, cfg, requestJSON("n.txt", "text/plain", []byte("left\u2028right"), ""))
	out, err := p.process(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	want, err := canon.Canonicalize(out, canon.RefuseNumbers)
	if err != nil || !bytes.Equal(out, want) {
		t.Fatalf("record bytes are not canonical: %v\n%s", err, out)
	}
	p.cfg.MaxOutput = int64(len(out))
	if at, err := p.process(context.Background(), req); err != nil || !bytes.Equal(at, out) {
		t.Fatalf("canonical record at the output bound: %v", err)
	}
	p.cfg.MaxOutput--
	if _, err := p.process(context.Background(), req); refusalCode(err) != "record-over-bound" {
		t.Fatalf("canonical record one byte past the output bound: %v", err)
	}
}

// The OCR program itself: run as a real process, its output bounded, its
// exit status and its deadline held to step 6.
func TestRunOCRProgram(t *testing.T) {
	dir := t.TempDir()
	script := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	answer := script("answer", `cat >/dev/null; printf '{"pages":[{"number":%s,"text":"x"}]}' "$1"`)
	out, digest, err := runOCRProgram(context.Background(), answer, []int{2}, []byte("doc"), 1<<20)
	if err != nil || string(out) != `{"pages":[{"number":2,"text":"x"}]}` || !attachment.ValidDigest(digest) {
		t.Fatalf("answer: %q %q %v", out, digest, err)
	}
	// Past the output bound the program is ended, not waited for: it would
	// otherwise sleep for ten seconds after writing.
	loud := script("loud", `cat >/dev/null; head -c 5000 /dev/zero; sleep 10`)
	started := time.Now()
	if _, _, err := runOCRProgram(context.Background(), loud, []int{1}, nil, 100); err == nil || !strings.Contains(err.Error(), "output bound") {
		t.Fatalf("past the output bound: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("the program was not ended when it wrote past the bound: %v", elapsed)
	}
	fails := script("fails", `exit 3`)
	if _, _, err := runOCRProgram(context.Background(), fails, []int{1}, nil, 100); err == nil || errors.Is(err, errOCRTimeout) {
		t.Fatalf("non-zero exit: %v", err)
	}
	slow := script("slow", `sleep 5`)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	started = time.Now()
	if _, _, err := runOCRProgram(ctx, slow, []int{1}, nil, 100); !errors.Is(err, errOCRTimeout) {
		t.Fatalf("deadline: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("the program was not ended at the deadline: %v", elapsed)
	}
	// A program that exits and leaves its stdout held open by a process it
	// left behind is not finished: two seconds later its pipe is closed and
	// the run has failed, without waiting for the deadline.
	lingering := script("lingering", `cat >/dev/null; printf '{"pages":[]}'; sleep 5 & exit 0`)
	started = time.Now()
	_, _, err = runOCRProgram(context.Background(), lingering, []int{1}, nil, 100)
	if err == nil || errors.Is(err, errOCRTimeout) || !strings.Contains(err.Error(), "left its stdout open") {
		t.Fatalf("a program that left its stdout open: %v", err)
	}
	// The process left behind sleeps for five seconds: a run that waited for
	// it would take them all.
	if elapsed := time.Since(started); elapsed < ocrPipeWait || elapsed > ocrPipeWait+1500*time.Millisecond {
		t.Fatalf("the open stdout was waited on for %v, not the two-second wait", elapsed)
	}
	if _, _, err := runOCRProgram(context.Background(), filepath.Join(dir, "absent"), []int{1}, nil, 100); err == nil || !strings.Contains(err.Error(), "resolved") {
		t.Fatalf("absent: %v", err)
	}
}
