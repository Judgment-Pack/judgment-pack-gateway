// Package render is the gateway's rendering adapter: it reads one request
// from the canonical arguments on stdin -- a format, a title and content as a
// closed structure of blocks -- renders it, and writes the version 1 render
// record of docs/design/rendering.md on stdout, which holds the file. It is
// wired as a bare source, so the receipt carries the command shape
// (docs/adr/0006-documents-are-rendered-by-an-adapter.md); it holds no
// credential, opens no connection and imports nothing of the core module.
//
// It writes Word files itself, in this module and against the standard
// library. A PDF is produced by a rendering program the operator configures,
// which is handed the Word file the adapter wrote for the same content and
// is run under the lifecycle of adapters/internal/program; with no program
// configured, a request for a PDF is refused by name.
package render

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"adapters/attachment"
	"adapters/document"
	"adapters/internal/canon"
	"adapters/internal/program"
)

// Version is what the adapter reports of itself in the record's provenance.
var Version = "0"

const (
	// RecordVersion is the version of the record this package writes.
	RecordVersion = "1"
	adapterName   = "adapter-render"
	stampLayout   = "2006-01-02T15:04:05Z"

	// FormatDocx and FormatPDF are the formats a request may name.
	FormatDocx = "docx"
	FormatPDF  = "pdf"

	// MediaTypeDocx is the media type of a Word file, and MediaTypePDF of
	// a PDF.
	MediaTypeDocx = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	MediaTypePDF  = "application/pdf"

	// RendererDocx names the module's own Word writer in a record.
	RendererDocx = "adapter-render/docx/1"

	// The ceilings of the bounds: each keeps the bound, and every figure
	// derived from it, within 2^53 - 1, the canonical domain's integers.
	maxRequestCeiling = 64 << 20
	maxBlocksCeiling  = 100_000
	maxFileCeiling    = 64 << 20
	maxOutputCeiling  = 1 << 40
	timeoutCeiling    = 10 * time.Minute

	// maxRefusalBytes bounds the refusal line, inside the 200 bytes of
	// stderr the reference gateway forwards.
	maxRefusalBytes = 160
)

// Config is the operator's configuration of one adapter invocation.
type Config struct {
	// MaxRequest bounds what is read from stdin.
	MaxRequest int64
	// MaxBlocks bounds the blocks of one document.
	MaxBlocks int
	// MaxFile bounds the rendered file, and what its parts hold once they
	// are read out of it.
	MaxFile int64
	// MaxOutput bounds the record.
	MaxOutput int64
	Timeout   time.Duration
	// Renderer is the rendering program, one word, or empty for none.
	Renderer string
}

// DefaultConfig is the configuration the flags default to. The request and
// the record default to the gateway's own defaults for an /acquire body and
// for a source's output; the file defaults to the storage controls' payload
// ceiling, so that no rendering is too large for them.
func DefaultConfig() Config {
	return Config{MaxRequest: 1 << 20, MaxBlocks: 2000, MaxFile: 4 << 20, MaxOutput: 1 << 20, Timeout: 25 * time.Second}
}

// Check holds the configuration to its rules: every bound a positive integer
// at most its ceiling, the timeout a positive whole number of milliseconds at
// most its ceiling.
func (c Config) Check() error {
	switch {
	case c.MaxRequest < 1 || c.MaxRequest > maxRequestCeiling:
		return fmt.Errorf("max-request must be positive and at most %d bytes", maxRequestCeiling)
	case c.MaxBlocks < 1 || c.MaxBlocks > maxBlocksCeiling:
		return fmt.Errorf("max-blocks must be positive and at most %d", maxBlocksCeiling)
	case c.MaxFile < 1 || c.MaxFile > maxFileCeiling:
		return fmt.Errorf("max-file must be positive and at most %d bytes", maxFileCeiling)
	case c.MaxOutput < 1 || c.MaxOutput > maxOutputCeiling:
		return fmt.Errorf("max-output must be positive and at most %d bytes", int64(maxOutputCeiling))
	case c.Timeout < time.Millisecond || c.Timeout > timeoutCeiling || c.Timeout%time.Millisecond != 0:
		return fmt.Errorf("timeout must be a positive whole number of milliseconds, at most %v", timeoutCeiling)
	case c.Renderer != "" && (strings.ContainsAny(c.Renderer, " \t\r\n\x00") || !attachment.ValidName(c.Renderer)):
		return errors.New("renderer must name one program, one word of at most 255 bytes")
	}
	return nil
}

// Refusal is a request the adapter refuses, or a failure after admission:
// the code of the note's refusal list and the reason, in the adapter's own
// words. A refused request renders nothing and writes no record.
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

// The refusal codes of docs/design/rendering.md.
const (
	CodeRequestOverBound      = "request-over-bound"
	CodeArgumentsInvalid      = "arguments-invalid"
	CodeContentInvalid        = "content-invalid"
	CodeContentOverBound      = "content-over-bound"
	CodeRendererNotConfigured = "renderer-not-configured"
	CodeRendererFailed        = "renderer-failed"
	CodeFileOverBound         = "file-over-bound"
	CodeRecordOverBound       = "record-over-bound"
	CodeTimeout               = "timeout"
	CodeAdapterFailed         = "adapter-failed"
)

func refuse(code, format string, args ...any) *Refusal {
	return &Refusal{Code: code, Reason: fmt.Sprintf(format, args...)}
}

// OwnIdentity is the adapter as it describes itself: its name, its version,
// and the digest of the file the operating system reports as its executable.
func OwnIdentity() (attachment.Identity, error) {
	identity, err := document.OwnIdentity()
	if err != nil {
		return attachment.Identity{}, refuse(CodeAdapterFailed, "the adapter's own executable could not be read")
	}
	identity.Name, identity.Version = adapterName, Version
	return identity, nil
}

// ParseRequest reads the request and refuses it at the first check that
// fails: the read bound, the arguments, the content's rules, the content's
// bounds. The read is bounded in time as the document adapter's is.
func ParseRequest(ctx context.Context, r io.Reader, cfg Config, now func() time.Time) (Request, error) {
	raw, err := document.ReadWithin(ctx, r, cfg.MaxRequest+1)
	if err != nil {
		if errors.Is(err, document.ErrRequestNotRead) {
			return Request{}, refuse(CodeAdapterFailed, "the deadline passed and the request had not been read in full")
		}
		return Request{}, refuse(CodeAdapterFailed, "stdin could not be read")
	}
	if int64(len(raw)) > cfg.MaxRequest {
		return Request{}, refuse(CodeRequestOverBound, "stdin holds more than the read bound of %d bytes (--max-request)", cfg.MaxRequest)
	}
	received := now()
	req, err := parseArguments(raw, cfg)
	if err != nil {
		return Request{}, err
	}
	req.ReceivedAt = received
	return req, nil
}

// Runner runs the rendering program: its stdout and the digest of the file
// its name resolved to, or an error -- program.ErrNotStarted where the
// deadline kept it from starting, program.ErrTimeout where the deadline had
// passed when its outcome was taken, any other for renderer-failed. Tests
// replace it.
type Runner func(ctx context.Context, name string, args []string, stdin []byte, maxOutput int64) (stdout []byte, digest string, err error)

// runProgram is the Runner of the adapter: the program under the lifecycle
// of adapters/internal/program.
func runProgram(ctx context.Context, name string, args []string, stdin []byte, maxOutput int64) ([]byte, string, error) {
	return program.Run{Program: name, Args: args, Stdin: stdin, MaxOutput: maxOutput}.Do(ctx)
}

// Process renders one admitted request and builds its record. reading is the
// instant the adapter began reading the request, which durationMs is measured
// from. It returns the record, or a refusal and no record: a rendering is
// whole or it is not made.
func Process(ctx context.Context, cfg Config, req Request, identity attachment.Identity, reading time.Time) ([]byte, error) {
	return process(ctx, cfg, req, identity, reading, time.Now)
}

// process is Process by a clock the caller gives.
func process(ctx context.Context, cfg Config, req Request, identity attachment.Identity, reading time.Time, now func() time.Time) ([]byte, error) {
	return processWith(ctx, cfg, req, identity, reading, now, runProgram)
}

// processWith is process with the runner of the rendering program given.
func processWith(ctx context.Context, cfg Config, req Request, identity attachment.Identity, reading time.Time, now func() time.Time, run Runner) ([]byte, error) {
	if req.Format == FormatPDF && cfg.Renderer == "" {
		return nil, refuse(CodeRendererNotConfigured, "a PDF is produced by a rendering program, and this adapter is configured with none")
	}
	if deadlinePassed(ctx, now) {
		return nil, refuse(CodeTimeout, "the deadline had passed before the file was written")
	}
	// The Word file is written for either format: it is the file of one,
	// and what the rendering program is handed for the other.
	file, err := writeDocx(req.Document, cfg.MaxFile)
	// The deadline is read before anything is said of the file: a rendering
	// whose deadline passed while it was written is refused for that,
	// whatever else is true of it.
	if deadlinePassed(ctx, now) {
		return nil, refuse(CodeTimeout, "the deadline had passed when the file had been written")
	}
	if errors.Is(err, errPartsOverBound) {
		return nil, refuse(CodeFileOverBound, "the parts of the file hold more than --max-file %d bytes", cfg.MaxFile)
	}
	if err != nil {
		return nil, refuse(CodeAdapterFailed, "the Word file could not be written")
	}
	if int64(len(file)) > cfg.MaxFile {
		return nil, refuse(CodeFileOverBound, "the file is %d bytes, past --max-file %d", len(file), cfg.MaxFile)
	}
	rendering := Rendering{
		Status:   StatusComplete,
		Renderer: Renderer{Kind: RendererModule, Name: RendererDocx},
		Bounds: Bounds{
			MaxRequestBytes: cfg.MaxRequest, MaxBlocks: int64(cfg.MaxBlocks), MaxFileBytes: cfg.MaxFile,
			MaxOutputBytes: cfg.MaxOutput, TimeoutMs: cfg.Timeout.Milliseconds(),
		},
	}
	mediaType := MediaTypeDocx
	if req.Format == FormatPDF {
		pdf, digest, refusal := renderPDF(ctx, cfg, file, run)
		if refusal != nil {
			return nil, refusal
		}
		rendering.Source = &Source{MediaType: MediaTypeDocx, Size: int64(len(file)), SHA256: digestOf(file), Renderer: rendering.Renderer}
		rendering.Renderer = Renderer{Kind: RendererProgram, Name: cfg.Renderer, Digest: &digest}
		file, mediaType = pdf, MediaTypePDF
	}
	// The record holds the file in base64, so a file whose base64 alone is
	// past the bound on the record cannot be written. It is refused here,
	// before the file is encoded, put in canonical form and checked, each of
	// which holds a copy of it.
	if encoded := int64(base64.StdEncoding.EncodedLen(len(file))); encoded > cfg.MaxOutput {
		return nil, refuse(CodeRecordOverBound, "the file is %d bytes and its base64 alone %d, past --max-output %d", len(file), encoded, cfg.MaxOutput)
	}
	rec := Record{
		RenderVersion: RecordVersion,
		Request: RequestSummary{
			Format: req.Format, Title: req.Document.Title, Language: optional(req.Document.Language),
			ContentDigest: req.ContentDigest, Blocks: int64(len(req.Document.Blocks)), TextBytes: req.TextBytes,
		},
		File: File{
			MediaType: mediaType, Size: int64(len(file)), SHA256: digestOf(file),
			Encoding: "base64", Bytes: base64.StdEncoding.EncodeToString(file),
		},
		Rendering:  rendering,
		Provenance: Provenance{Adapter: identity, ObservedAt: req.ReceivedAt.UTC().Format(stampLayout)},
	}
	if req.Decision != "" {
		rec.Request.Cites = &Cites{Decision: req.Decision}
	}
	rec.Rendering.DurationMs = max(now().Sub(reading).Milliseconds(), 0)
	// The record is written in the canonical form, as the gateway would
	// write it: what the adapter wrote and what the gateway attests are then
	// the same bytes.
	out, err := canon.EncodeJSON(rec)
	if err == nil {
		out, err = canon.Canonicalize(out, canon.RefuseNumbers)
	}
	if err != nil {
		return nil, refuse(CodeAdapterFailed, "the record could not be encoded")
	}
	if err := Check(out); err != nil {
		return nil, refuse(CodeAdapterFailed, "the record the adapter built does not pass its own check")
	}
	if int64(len(out)) > cfg.MaxOutput {
		return nil, refuse(CodeRecordOverBound, "the record is %d bytes, past --max-output %d", len(out), cfg.MaxOutput)
	}
	return out, nil
}

// The arguments the rendering program is run with: what it is handed on its
// stdin, and what is asked of it on its stdout.
var rendererArgs = []string{FormatDocx, FormatPDF}

// renderPDF hands the Word file to the rendering program and admits its
// answer. What the program wrote is used only where it had finished before
// the deadline, within the bound on the file, with a successful exit, and
// where what it wrote begins and ends as a PDF does. The refusals carry
// nothing the program wrote.
func renderPDF(ctx context.Context, cfg Config, docx []byte, run Runner) ([]byte, string, *Refusal) {
	out, digest, err := run(ctx, cfg.Renderer, rendererArgs, docx, cfg.MaxFile)
	switch {
	case errors.Is(err, program.ErrNotStarted):
		return nil, "", refuse(CodeTimeout, "the deadline had passed after the rendering program was resolved and before it was started")
	case errors.Is(err, program.ErrTimeout):
		// The run does not say whether the program was ended at the deadline
		// or had exited and left its stdout open, so neither does this.
		return nil, "", refuse(CodeTimeout, "the deadline had passed when the rendering program's outcome was taken; nothing it wrote was used")
	case err != nil:
		return nil, "", refuse(CodeRendererFailed, "the rendering program %s", err.Error())
	case !isPDF(out):
		return nil, "", refuse(CodeRendererFailed, "the rendering program's answer does not begin and end as a PDF does")
	case !attachment.ValidDigest(digest):
		return nil, "", refuse(CodeAdapterFailed, "the rendering program was run and no digest of it was taken")
	}
	return out, digest, nil
}

// pdfTail is how far from its end a PDF is looked at for the marker of its
// end.
const pdfTail = 1024

// isPDF reports whether data begins and ends as a PDF does: the header
// "%PDF-", a digit, a full stop and a digit, and the marker "%%EOF" within
// the last 1,024 bytes. It is a test of form. It does not read the PDF, and
// says nothing of what it holds.
func isPDF(data []byte) bool {
	const header = "%PDF-"
	if len(data) < len(header)+3 || string(data[:len(header)]) != header {
		return false
	}
	version := data[len(header) : len(header)+3]
	if version[0] < '0' || version[0] > '9' || version[1] != '.' || version[2] < '0' || version[2] > '9' {
		return false
	}
	tail := data
	if len(tail) > pdfTail {
		tail = tail[len(tail)-pdfTail:]
	}
	return strings.Contains(string(tail), "%%EOF")
}

// deadlinePassed reads the deadline as the document adapter does: the
// context's own error, and the clock as well, so that a deadline the clock
// has reached counts whether or not the timer that cancels the context has
// run.
func deadlinePassed(ctx context.Context, now func() time.Time) bool {
	if ctx.Err() != nil {
		return true
	}
	at, ok := ctx.Deadline()
	return ok && !now().Before(at)
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
