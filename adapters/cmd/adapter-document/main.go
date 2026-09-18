// Command adapter-document is the gateway's document adapter, spawned by
// `gateway serve` as a bare source (`--source documents='adapter-document
// ...'`, no shape, SPEC.md §1.2a "command"). It reads the canonical
// arguments on stdin -- a document's bytes, name and declared media type --
// establishes the document's identity, extracts its text within the
// bounds on its command line, delegates scanned pages to the OCR program
// named with --ocr when one is, and writes the version 1 attachment
// record of docs/design/attachments.md on stdout.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"adapters/document"
	"adapters/internal/redact"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// ownIdentity reads the adapter's own executable for its identity. Tests
// replace it.
var ownIdentity = document.OwnIdentity

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	started := time.Now()
	fs := flag.NewFlagSet("adapter-document", flag.ContinueOnError)
	// Flag diagnostics quote the operator's own command line; they are
	// bounded before they are written. This adapter holds no credential,
	// so there is nothing to redact from them, and the bound is the
	// whole boundary.
	var flagOut boundedWriter
	fs.SetOutput(&flagOut)
	defer func() {
		if flagOut.n > 0 {
			fmt.Fprint(stderr, redact.Diagnostic(flagOut.String(), flagOut.truncated, nil))
		}
	}()
	def := document.DefaultConfig()
	maxBytes := fs.Int64("max-bytes", def.MaxBytes, "bound on the decoded document in bytes; the read bound derives from it")
	maxPages := fs.Int("max-pages", def.MaxPages, "bound on the pages listed")
	maxText := fs.Int("max-text", def.MaxText, "the text budget: the sum of listed pages' normalised text, in bytes of UTF-8")
	maxInflate := fs.Int64("max-inflate", def.MaxInflate, "bound on what a document's streams may inflate to in total, in bytes")
	ocrMaxOutput := fs.Int64("ocr-max-output", def.OCRMaxOutput, "bound on the OCR program's stdout in bytes")
	maxOutput := fs.Int64("max-output", def.MaxOutput, "bound on the record in bytes; keep it at or below the gateway's --source-max-output")
	timeout := fs.Duration("timeout", def.Timeout, "the deadline, from the adapter's start; keep it under the gateway's thirty seconds")
	ocr := fs.String("ocr", "", "the OCR program, one word, run for pages that need OCR; none when empty")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: adapter-document [--max-bytes N] [--max-pages N] [--max-text N] [--max-inflate N] [--ocr-max-output N] [--max-output N] [--timeout D] [--ocr PROGRAM]")
		return 2
	}
	cfg := document.Config{MaxBytes: *maxBytes, MaxPages: *maxPages, MaxText: *maxText, MaxInflate: *maxInflate, OCRMaxOutput: *ocrMaxOutput, MaxOutput: *maxOutput, Timeout: *timeout, OCR: *ocr}
	if err := cfg.Check(); err != nil {
		fmt.Fprintln(stderr, "adapter-document:", err)
		return 2
	}
	// The deadline runs from the adapter's start, before the request is
	// read: reading its own executable for its identity is inside it.
	ctx, cancel := context.WithDeadline(context.Background(), started.Add(cfg.Timeout))
	defer cancel()
	identity, err := ownIdentity()
	if err != nil {
		return refused(stderr, err)
	}
	// durationMs is the time from reading the request to writing the record,
	// which begins here: resolving and digesting the executable above is
	// inside the deadline, not inside the duration the record reports.
	reading := time.Now()
	req, err := document.ParseRequest(stdin, cfg, time.Now)
	if err != nil {
		return refused(stderr, err)
	}
	out, err := document.Process(ctx, cfg, req, identity, reading)
	if err != nil {
		return refused(stderr, err)
	}
	if _, err := stdout.Write(out); err != nil {
		return refused(stderr, &document.Refusal{Code: "adapter-failed", Reason: "stdout could not be written"})
	}
	return 0
}

// refused writes the one refusal line docs/design/attachments.md's
// "Refusals" names -- its code, a colon and the reason, ASCII, at most 160
// bytes -- and exits 1.
func refused(stderr io.Writer, err error) int {
	var refusal *document.Refusal
	if !errors.As(err, &refusal) {
		refusal = &document.Refusal{Code: "adapter-failed", Reason: "the adapter could not continue"}
	}
	fmt.Fprintln(stderr, refusal.Line())
	return 1
}

// boundedWriter keeps the first kilobyte of what is written to it.
type boundedWriter struct {
	buf       [1024]byte
	n         int
	truncated bool
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	room := len(w.buf) - w.n
	if len(p) > room {
		w.truncated = true
		p = p[:room]
	}
	copy(w.buf[w.n:], p)
	w.n += len(p)
	return len(p), nil
}

func (w *boundedWriter) String() string { return string(w.buf[:w.n]) }
