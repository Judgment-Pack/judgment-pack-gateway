// Package document is the gateway's document adapter: it reads one
// document from the canonical arguments on stdin -- the bytes, a name and a
// declared media type -- establishes its identity by digest, extracts its
// text within stated bounds, delegates scanned pages to an operator's OCR
// program when one is configured, and writes the version 1 attachment
// record of docs/design/attachments.md on stdout. It is wired as a bare
// source, so the receipt carries the command shape; it holds no credential
// and imports nothing of the core module. The record's types, its text
// normalisation and the check every record here is held to are
// adapters/attachment's.
package document

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"adapters/attachment"
	"adapters/document/pdf"
	"adapters/internal/canon"
)

// Version is what the adapter reports of itself in the record's provenance.
var Version = "0"

const (
	adapterName = "adapter-document"
	stampLayout = "2006-01-02T15:04:05Z"
	// readSlack is what the read bound allows beyond the document's base64:
	// the longest name, media type, digest and options.
	readSlack = 64 << 10
	// maxMessageBytes bounds an error's message.
	maxMessageBytes = 512
	// maxInflateOne is the bound on one stream's inflation.
	maxInflateOne = 16 << 20
	// The ceilings of the bounds, as adapters/README.md states them: each
	// keeps the bound, and every figure derived from it -- the read bound,
	// timeoutMs -- well within 2^53 - 1, the canonical domain's integers.
	maxBytesCeiling     = 1 << 30
	maxPagesCeiling     = 1_000_000
	maxTextCeiling      = 1 << 30
	maxInflateCeiling   = 4 << 30
	ocrMaxOutputCeiling = 1 << 30
	maxOutputCeiling    = 1 << 40
	timeoutCeiling      = 10 * time.Minute
	// maxRefusalBytes bounds the refusal line, inside the 200 bytes of
	// stderr the reference gateway forwards.
	maxRefusalBytes = 160
)

// Config is the operator's configuration of one adapter invocation.
type Config struct {
	MaxBytes     int64
	MaxPages     int
	MaxText      int
	MaxInflate   int64
	OCRMaxOutput int64
	MaxOutput    int64
	Timeout      time.Duration
	// OCR is the OCR program, one word, or empty for none.
	OCR string
}

// DefaultConfig is the configuration the flags default to.
func DefaultConfig() Config {
	return Config{MaxBytes: 16 << 20, MaxPages: 500, MaxText: 8 << 20, MaxInflate: 64 << 20, OCRMaxOutput: 32 << 20, MaxOutput: 1 << 20, Timeout: 25 * time.Second}
}

// Check holds the configuration to its rules: every bound a positive
// integer at most its ceiling, the timeout a positive whole number of
// milliseconds at most its ceiling, the OCR program one word.
func (c Config) Check() error {
	switch {
	case c.MaxBytes < 1 || c.MaxBytes > maxBytesCeiling:
		return fmt.Errorf("max-bytes must be positive and at most %d bytes", maxBytesCeiling)
	case c.MaxPages < 1 || c.MaxPages > maxPagesCeiling:
		return fmt.Errorf("max-pages must be positive and at most %d", maxPagesCeiling)
	case c.MaxText < 1 || c.MaxText > maxTextCeiling:
		return fmt.Errorf("max-text must be positive and at most %d bytes", maxTextCeiling)
	case c.MaxInflate < 1 || c.MaxInflate > maxInflateCeiling:
		return fmt.Errorf("max-inflate must be positive and at most %d bytes", int64(maxInflateCeiling))
	case c.OCRMaxOutput < 1 || c.OCRMaxOutput > ocrMaxOutputCeiling:
		return fmt.Errorf("ocr-max-output must be positive and at most %d bytes", ocrMaxOutputCeiling)
	case c.MaxOutput < 1 || c.MaxOutput > maxOutputCeiling:
		return fmt.Errorf("max-output must be positive and at most %d bytes", int64(maxOutputCeiling))
	case c.Timeout < time.Millisecond || c.Timeout > timeoutCeiling || c.Timeout%time.Millisecond != 0:
		return fmt.Errorf("timeout must be a positive whole number of milliseconds, at most %v", timeoutCeiling)
	case c.OCR != "" && strings.ContainsAny(c.OCR, " \t\r\n\x00"):
		return errors.New("ocr must name one program, one word")
	}
	return nil
}

// Refusal is a request the adapter refuses, or a failure after admission:
// the code of the note's refusal list and the reason, in the adapter's own
// words.
type Refusal struct {
	Code   string
	Reason string
}

func (r *Refusal) Error() string { return r.Code + ": " + r.Reason }

// Line is the refusal as the adapter writes it on stderr: ASCII, at most
// 160 bytes, the code first.
func (r *Refusal) Line() string {
	var b strings.Builder
	for _, c := range []byte(r.Code + ": " + r.Reason) {
		if c < 0x20 || c > 0x7e {
			c = '?'
		}
		b.WriteByte(c)
	}
	line := b.String()
	if len(line) > maxRefusalBytes {
		line = line[:maxRefusalBytes]
	}
	return line
}

func refuse(code, format string, args ...any) *Refusal {
	return &Refusal{Code: code, Reason: fmt.Sprintf(format, args...)}
}

// Request is the canonical arguments the gateway hands the adapter.
type Request struct {
	Name      string
	MediaType string
	Bytes     []byte
	// SHA256 is the caller's claim, or empty.
	SHA256 string
	// OCR is "auto" or "never".
	OCR string
	// ReceivedAt is when the request had been read in full.
	ReceivedAt time.Time
}

// ReadBound is the most the adapter reads from stdin under a configuration:
// 4 x ceil(max-bytes / 3), the base64 of a document at max-bytes, plus the
// slack for the rest. It is computed without overflow; ok is false when
// max-bytes is not positive, or when the bound, and the one byte read past
// it, would not fit an int64 -- which no max-bytes within its ceiling does.
func ReadBound(cfg Config) (bound int64, ok bool) {
	if cfg.MaxBytes < 1 {
		return 0, false
	}
	groups := cfg.MaxBytes / 3
	if cfg.MaxBytes%3 != 0 {
		groups++
	}
	if groups > (math.MaxInt64-readSlack-1)/4 {
		return 0, false
	}
	return groups*4 + readSlack, true
}

// ParseRequest reads the request and refuses it at the first of the note's
// four checks that fails: the read bound, the arguments, the decoded size,
// the digest. The read is bounded in time as well as in bytes: the deadline
// runs from the adapter's start, and a request that has not arrived in full
// by requestPipeWait past it is refused, since nothing the adapter does makes
// the writer of its stdin close it or write.
func ParseRequest(ctx context.Context, r io.Reader, cfg Config, now func() time.Time) (Request, error) {
	bound, ok := ReadBound(cfg)
	if !ok {
		return Request{}, refuse("adapter-failed", "--max-bytes %d has no read bound", cfg.MaxBytes)
	}
	raw, err := readWithin(ctx, r, bound+1)
	if err != nil {
		if errors.Is(err, errRequestNotRead) {
			return Request{}, refuse("adapter-failed", "the deadline passed and the request had not been read in full")
		}
		return Request{}, refuse("adapter-failed", "stdin could not be read")
	}
	if int64(len(raw)) > bound {
		return Request{}, refuse("request-over-bound", "stdin holds more than the read bound of %d bytes (--max-bytes %d)", bound, cfg.MaxBytes)
	}
	received := now()
	req, data, err := parseArguments(raw)
	if err != nil {
		return Request{}, err
	}
	req.ReceivedAt = received
	if int64(len(data)) > cfg.MaxBytes {
		return Request{}, refuse("document-over-bound", "the document is %d bytes, past --max-bytes %d", len(data), cfg.MaxBytes)
	}
	if req.SHA256 != "" && req.SHA256 != digestOf(data) {
		return Request{}, refuse("digest-mismatch", "document.sha256 does not match the digest of the decoded document")
	}
	req.Bytes = data
	return req, nil
}

// requestPipeWait is how long past the deadline the adapter waits for the
// reading of its request to end, as ocrPipeWait is for the OCR program's
// stdout: a request that is there to be read is read, however late the
// deadline finds the adapter, and only a stdin whose writer neither writes
// nor closes it is given up on. It is measured from the deadline itself, so
// the wait is the same whenever the adapter comes to it.
const requestPipeWait = 2 * time.Second

// requestReadFloor is the least the adapter waits for a read that has begun,
// however old the deadline is by then: long enough for a read of bytes that
// are there to end, and short enough that a stdin nobody writes is not
// waited on.
const requestReadFloor = 50 * time.Millisecond

// errRequestNotRead is a request whose reading had not ended requestPipeWait
// past the deadline.
var errRequestNotRead = errors.New("the request was not read in full")

// readWithin reads at most n bytes of r, waiting for the read no longer than
// requestPipeWait past the deadline the context carries. A read of a pipe
// ends when the writer closes it or writes, and neither is the adapter's to
// make happen, so it runs in a goroutine of its own and the wait is beside
// it: nothing here interrupts the read, and one still waiting when the
// adapter exits ends with the process. The channel is buffered, so such a
// read hands its bytes over and stops rather than holding the goroutine.
//
// The cutoff is an instant, not a duration waited from wherever the deadline
// was noticed: requestPipeWait past the deadline the context declares, so a
// deadline already old when the read begins does not buy the read another
// wait of its own. The read stamps the instant it ended, and a read that
// ended at or before the cutoff is taken however late it is noticed: the
// stamp decides, where waiting on two things at once would leave it to
// whichever the runtime happened to offer. A context with no deadline is
// waited on until the read ends, since there is no instant to measure from.
//
// The deadline passing does not by itself refuse the request. A request that
// has arrived is a document to establish and record, and the record then
// says timeout, from the first check of the deadline after it: that is what
// the note has the deadline do, and it holds when the deadline had passed
// before the read began, where a read of bytes already there ends at once.
// What the wait past the deadline bounds is a read that does not end.
func readWithin(ctx context.Context, r io.Reader, n int64) ([]byte, error) {
	type read struct {
		data []byte
		err  error
		// at is when the read ended, by the clock the cutoff is on.
		at time.Time
	}
	done := make(chan read, 1)
	go func() {
		data, err := io.ReadAll(io.LimitReader(r, n))
		done <- read{data: data, err: err, at: time.Now()}
	}()
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		got := <-done
		return got.data, got.err
	}
	cutoff := deadline.Add(requestPipeWait)
	// A deadline already past when the read begins leaves no wait at all,
	// where a request that is there needs only the moment its read takes to
	// end. The cutoff is never nearer than that moment: what it bounds is a
	// read waiting on a writer, not the scheduling of a read that can end at
	// once.
	if floor := time.Now().Add(requestReadFloor); cutoff.Before(floor) {
		cutoff = floor
	}
	wait := time.NewTimer(time.Until(cutoff))
	defer wait.Stop()
	select {
	case got := <-done:
		return got.data, got.err
	case <-wait.C:
	}
	// The cutoff has passed. A read that ended at or before it is still the
	// request; one that ends after it is not, and is left to the goroutine.
	select {
	case got := <-done:
		if !readTaken(got.at, cutoff) {
			return nil, errRequestNotRead
		}
		return got.data, got.err
	default:
		return nil, errRequestNotRead
	}
}

// readTaken reports whether a read that ended at an instant is the request:
// one that ended at or before the cutoff is, and one that ended after it is
// not. The instant decides it, so that a read and a cutoff that are ready at
// the same moment are not settled by whichever a select happens to offer.
func readTaken(ended, cutoff time.Time) bool { return !ended.After(cutoff) }

// parseArguments is the second check: the arguments table. Once the members
// are known to be exactly the table's, arguments outside the canonical domain
// -- not valid UTF-8, an unpaired surrogate escape, a number past its range --
// are refused before any string is read, as the gateway refuses them before
// the adapter runs, so that a string carried into the record is the one the
// caller gave.
func parseArguments(raw []byte) (Request, []byte, error) {
	invalid := func(format string, args ...any) (Request, []byte, error) {
		return Request{}, nil, refuse("arguments-invalid", format, args...)
	}
	top, err := exactMembers(raw, map[string]bool{"document": true, "options": false})
	if err != nil {
		return invalid("arguments: %v", err)
	}
	doc, err := exactMembers(top["document"], map[string]bool{"name": true, "mediaType": true, "bytes": true, "sha256": false})
	if err != nil {
		return invalid("document: %v", err)
	}
	var opts map[string]json.RawMessage
	if options, ok := top["options"]; ok {
		if opts, err = exactMembers(options, map[string]bool{"ocr": false}); err != nil {
			return invalid("options: %v", err)
		}
	}
	if _, err := canon.Canonicalize(raw, canon.RefuseNumbers); err != nil {
		return invalid("the arguments are outside the canonical domain")
	}
	var req Request
	if !stringInto(doc["name"], &req.Name) || !attachment.ValidName(req.Name) {
		return invalid("document.name must be 1 to 255 bytes of UTF-8 with no control character")
	}
	if !stringInto(doc["mediaType"], &req.MediaType) || !attachment.ValidMediaType(req.MediaType) {
		return invalid("document.mediaType must be a lowercase type/subtype with no parameters")
	}
	var encoded string
	if !stringInto(doc["bytes"], &encoded) || encoded == "" {
		return invalid("document.bytes must be a non-empty string")
	}
	if !attachment.CanonicalBase64(encoded) {
		return invalid("document.bytes is not the one standard padded base64 encoding of its bytes")
	}
	data, _ := base64.StdEncoding.DecodeString(encoded)
	if claim, ok := doc["sha256"]; ok {
		if !stringInto(claim, &req.SHA256) || !attachment.ValidDigest(req.SHA256) {
			return invalid("document.sha256 must be \"sha256:\" and 64 lowercase hex characters")
		}
	}
	req.OCR = "auto"
	if o, ok := opts["ocr"]; ok {
		if !stringInto(o, &req.OCR) || (req.OCR != "auto" && req.OCR != "never") {
			return invalid("options.ocr must be \"auto\" or \"never\"")
		}
	}
	return req, data, nil
}

// stringInto decodes a JSON string, and only a string, into out.
func stringInto(raw json.RawMessage, out *string) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return false
	}
	return json.Unmarshal(trimmed, out) == nil
}

// exactMembers decodes one JSON object whose members are exactly those
// named (true for required), each once. Its errors name no member the
// caller wrote that the contract does not name: an unknown member is
// reported without its name, however short or plain.
func exactMembers(raw json.RawMessage, members map[string]bool) (map[string]json.RawMessage, error) {
	if !canon.IsObject(raw) {
		return nil, errors.New("not a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if _, err := dec.Token(); err != nil {
		return nil, errors.New("not a JSON object")
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, errors.New("not a JSON object")
		}
		key, _ := keyTok.(string)
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, errors.New("not a JSON object")
		}
		if _, known := members[key]; !known {
			return nil, errors.New("a member the contract does not name")
		}
		if _, dup := out[key]; dup {
			// A known member: its name is the contract's.
			return nil, fmt.Errorf("member %s given twice", key)
		}
		out[key] = value
	}
	for name, required := range members {
		if _, ok := out[name]; required && !ok {
			return nil, fmt.Errorf("member %s is missing", name)
		}
	}
	return out, nil
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// OwnIdentity is the adapter as it describes itself: its name, its version,
// and the digest of the file the operating system reports as its executable.
func OwnIdentity() (attachment.Identity, error) {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return attachment.Identity{}, refuse("adapter-failed", "the adapter's own executable could not be located")
	}
	digest, err := fileDigest(exe)
	if err != nil {
		return attachment.Identity{}, refuse("adapter-failed", "the adapter's own executable could not be read")
	}
	return attachment.Identity{Name: adapterName, Version: Version, Digest: digest}, nil
}

func fileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// OCRRunner runs the OCR program: its stdout and the digest of the file its
// name resolved to, or an error -- errOCRTimeout when the deadline ended it,
// any other for ocr-failed. Tests replace it.
type OCRRunner func(ctx context.Context, program string, pages []int, doc []byte, maxOutput int64) (stdout []byte, digest string, err error)

type processor struct {
	cfg      Config
	identity attachment.Identity
	// reading is when the adapter began reading the request: durationMs
	// runs from there, not from the process's start, which the deadline
	// runs from.
	reading time.Time
	now     func() time.Time
	runOCR  OCRRunner
}

// Process builds the record for one admitted request. reading is the instant
// the adapter began reading the request, which durationMs is measured from.
func Process(ctx context.Context, cfg Config, req Request, identity attachment.Identity, reading time.Time) ([]byte, error) {
	p := &processor{cfg: cfg, identity: identity, reading: reading, now: time.Now, runOCR: runOCRProgram}
	return p.process(ctx, req)
}

func (p *processor) process(ctx context.Context, req Request) ([]byte, error) {
	rec := attachment.Record{
		AttachmentVersion: attachment.Version,
		Document: attachment.Document{
			ID: digestOf(req.Bytes), Name: req.Name, MediaType: req.MediaType, Size: int64(len(req.Bytes)),
		},
		Original: attachment.Original{Retention: attachment.RetentionCaller},
		Content:  attachment.Content{Kind: "text", Pages: []attachment.Page{}},
		Processing: attachment.Processing{
			Errors: []attachment.Error{},
			Bounds: attachment.Bounds{MaxBytes: p.cfg.MaxBytes, MaxPages: int64(p.cfg.MaxPages), MaxTextBytes: int64(p.cfg.MaxText), MaxInflateBytes: p.cfg.MaxInflate, MaxOcrOutputBytes: p.cfg.OCRMaxOutput, TimeoutMs: p.cfg.Timeout.Milliseconds()},
		},
		Provenance: attachment.Provenance{Adapter: p.identity, Source: attachment.Source{Kind: attachment.SourceInline}, ObservedAt: req.ReceivedAt.UTC().Format(stampLayout)},
	}
	// Step 2: the declaration.
	processor, processed := attachment.ProcessedMediaTypes[req.MediaType]
	switch {
	case !processed:
		addError(&rec, attachment.CodeMediaTypeUnsupported, 0, "version 1 processes application/pdf, text/plain, text/markdown, text/csv and application/json")
	case processor == attachment.ProcessorPDF && !bytes.Contains(head(req.Bytes, 1024), []byte("%PDF-")):
		addError(&rec, attachment.CodeMediaTypeMismatch, 0, "declared application/pdf, and the first 1024 bytes hold no %PDF- header")
	case processor == attachment.ProcessorText && !utf8.Valid(req.Bytes):
		addError(&rec, attachment.CodeMediaTypeMismatch, 0, fmt.Sprintf("declared %s, and the bytes are not valid UTF-8", req.MediaType))
	case processor == attachment.ProcessorText:
		rec.Document.DetectedMediaType = ptr(attachment.MediaText)
		rec.Provenance.Processor = ptr(attachment.ProcessorText)
		p.processText(req, &rec)
	default:
		rec.Document.DetectedMediaType = ptr(attachment.MediaPDF)
		rec.Provenance.Processor = ptr(attachment.ProcessorPDF)
		p.processPDF(ctx, req, &rec)
	}
	// Step 7.
	settle(&rec)
	rec.Processing.DurationMs = max(p.now().Sub(p.reading).Milliseconds(), 0)
	out, err := canon.EncodeJSON(rec)
	if err == nil {
		out, err = canon.Canonicalize(out, canon.RefuseNumbers)
	}
	if err != nil {
		return nil, refuse("adapter-failed", "the record could not be encoded")
	}
	if int64(len(out)) > p.cfg.MaxOutput {
		return nil, refuse("record-over-bound", "the record is %d bytes, past --max-output %d", len(out), p.cfg.MaxOutput)
	}
	return out, nil
}

func ptr(s string) *string { return &s }

func head(data []byte, n int) []byte {
	if len(data) > n {
		return data[:n]
	}
	return data
}

func addError(rec *attachment.Record, code string, page int, message string) {
	e := attachment.Error{Code: code, Message: bound(message, maxMessageBytes)}
	if page > 0 {
		n := int64(page)
		e.Page = &n
	}
	rec.Processing.Errors = append(rec.Processing.Errors, e)
}

func bound(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// settle derives what step 7 derives: content.chars, content.extraction
// and processing.status.
func settle(rec *attachment.Record) {
	methods := map[string]bool{}
	rec.Content.Chars = 0
	for _, page := range rec.Content.Pages {
		rec.Content.Chars += page.Chars
		if page.Extraction != attachment.ExtractionNone {
			methods[page.Extraction] = true
		}
	}
	switch {
	case methods[attachment.ExtractionTextLayer] && methods[attachment.ExtractionOCR]:
		rec.Content.Extraction = attachment.ExtractionMixed
	case methods[attachment.ExtractionTextLayer]:
		rec.Content.Extraction = attachment.ExtractionTextLayer
	case methods[attachment.ExtractionOCR]:
		rec.Content.Extraction = attachment.ExtractionOCR
	case methods[attachment.ExtractionVerbatim]:
		rec.Content.Extraction = attachment.ExtractionVerbatim
	default:
		rec.Content.Extraction = attachment.ExtractionNone
	}
	switch {
	case len(rec.Content.Pages) == 0:
		rec.Processing.Status = attachment.StatusFailed
	case len(rec.Processing.Errors) == 0 && !rec.Content.Truncated:
		rec.Processing.Status = attachment.StatusComplete
	default:
		rec.Processing.Status = attachment.StatusPartial
	}
}

// processText is step 3: one verbatim page.
func (p *processor) processText(req Request, rec *attachment.Record) {
	rec.Content.PageCount = 1
	text := attachment.NormalizeText(string(req.Bytes))
	if len(text) > p.cfg.MaxText {
		rec.Content.Truncated = true
		addError(rec, attachment.CodeTextOverBound, 1, fmt.Sprintf("listing page 1 would take the text past %d bytes; page 1 is not listed", p.cfg.MaxText))
		return
	}
	page := attachment.Page{Number: 1, Status: attachment.PageNoText, Extraction: attachment.ExtractionVerbatim, Text: text, Chars: int64(utf8.RuneCountInString(text))}
	if text != "" {
		page.Status = attachment.PageOK
	}
	rec.Content.Pages = append(rec.Content.Pages, page)
}

// processPDF is steps 4 to 6.
func (p *processor) processPDF(ctx context.Context, req Request, rec *attachment.Record) {
	r := pdf.Extract(ctx, req.Bytes, pdf.Options{MaxPages: p.cfg.MaxPages, MaxTextBytes: p.cfg.MaxText, MaxInflateTotal: p.cfg.MaxInflate, MaxInflateOne: maxInflateOne})
	if r.Encryption != nil {
		rec.Document.Encryption = &attachment.Encryption{Handler: r.Encryption.Handler, Revision: r.Encryption.Revision, Opened: r.Encryption.Opened}
	}
	if r.Fatal != nil {
		addError(rec, r.Fatal.Code, 0, r.Fatal.Message)
		return
	}
	rec.Content.PageCount = int64(r.PageCount)
	rec.Content.Truncated = r.Truncated
	var needOCR []int
	for _, pg := range r.Pages {
		page := attachment.Page{Number: int64(pg.Number), Status: string(pg.Status), Extraction: attachment.ExtractionNone}
		switch pg.Status {
		case pdf.PageOK:
			page.Extraction, page.Text, page.Chars, page.Unmapped = attachment.ExtractionTextLayer, pg.Text, int64(pg.Chars()), int64(pg.Unmapped)
		case pdf.PageNoText:
			page.Extraction = attachment.ExtractionTextLayer
		case pdf.PageNeedsOCR:
			needOCR = append(needOCR, pg.Number)
		}
		rec.Content.Pages = append(rec.Content.Pages, page)
	}
	for _, pr := range r.Problems {
		addError(rec, pr.Code, pr.Page, pr.Message)
	}
	if r.TimedOut || len(needOCR) == 0 {
		return
	}
	// Step 6.
	switch {
	case req.OCR == "never":
		addError(rec, attachment.CodeOCRNotRun, 0, fmt.Sprintf("%s images and no text layer, and the caller asked for no OCR", pagesHave(len(needOCR))))
	case p.cfg.OCR == "":
		addError(rec, attachment.CodeOCRNotRun, 0, fmt.Sprintf("%s images and no text layer, and no OCR program is configured for this source", pagesHave(len(needOCR))))
	default:
		p.applyOCR(ctx, req, rec, needOCR, r.TextBytes)
	}
}

func pagesHave(n int) string {
	if n == 1 {
		return "1 page has"
	}
	return fmt.Sprintf("%d pages have", n)
}

// applyOCR runs the program for the pages that need it, admits its answer,
// and applies it page by page within the text budget left.
func (p *processor) applyOCR(ctx context.Context, req Request, rec *attachment.Record, pages []int, textBytes int) {
	stdout, digest, err := p.runOCR(ctx, p.cfg.OCR, pages, req.Bytes, p.cfg.OCRMaxOutput)
	if errors.Is(err, errOCRNotStarted) {
		addError(rec, attachment.CodeTimeout, 0, "the deadline had passed after the OCR program was resolved and before it was started")
		return
	}
	if errors.Is(err, errOCRTimeout) {
		addError(rec, attachment.CodeOCRTimeout, 0, "the OCR program had not finished at the deadline and was ended; no answer of it was applied")
		return
	}
	if err != nil {
		addError(rec, attachment.CodeOCRFailed, 0, "the OCR program "+err.Error()+"; no answer of it was applied")
		return
	}
	answers, err := admitOCRAnswer(stdout, pages)
	if err != nil {
		addError(rec, attachment.CodeOCRFailed, 0, "the OCR program's answer "+err.Error()+"; no answer of it was applied")
		return
	}
	index := map[int64]int{}
	for i, page := range rec.Content.Pages {
		index[page.Number] = i
	}
	var applied []int64
	stopped := false
	for _, n := range pages {
		text, answered := answers[n]
		if !answered || stopped {
			continue
		}
		text = attachment.NormalizeText(text)
		if len(text) > p.cfg.MaxText-textBytes {
			stopped = true
			addError(rec, attachment.CodeTextOverBound, n, fmt.Sprintf("the OCR answer for page %d would take the text past %d bytes; it and later answered pages stay needs-ocr", n, p.cfg.MaxText))
			continue
		}
		textBytes += len(text)
		page := &rec.Content.Pages[index[int64(n)]]
		page.Extraction, page.Text, page.Chars, page.Unmapped = attachment.ExtractionOCR, text, int64(utf8.RuneCountInString(text)), 0
		page.Status = attachment.PageNoText
		if text != "" {
			page.Status = attachment.PageOK
		}
		applied = append(applied, int64(n))
	}
	if missing := len(pages) - len(answers); missing > 0 {
		addError(rec, attachment.CodeOCRIncomplete, 0, fmt.Sprintf("the OCR program was asked for %d pages and answered %d; %d stay needs-ocr", len(pages), len(answers), missing))
	}
	if len(applied) > 0 {
		rec.Provenance.OCR = &attachment.OCR{Program: p.cfg.OCR, Digest: digest, Pages: applied}
	}
}
