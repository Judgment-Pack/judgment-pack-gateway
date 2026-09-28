// Command adapter-render is the gateway's rendering adapter, spawned by
// `gateway serve` as a bare source (`--source render='adapter-render ...'`,
// no shape, SPEC.md §1.2a "command"). It reads the canonical arguments on
// stdin -- a format, a title and content as a closed structure of blocks --
// renders the content within the bounds on its command line, and writes the
// version 1 render record of docs/design/rendering.md on stdout, which holds
// the file.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"adapters/internal/redact"
	"adapters/render"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// ownIdentity reads the adapter's own executable for its identity. Tests
// replace it.
var ownIdentity = render.OwnIdentity

const usage = "usage: adapter-render [--max-request N] [--max-blocks N] [--max-file N] [--max-output N] [--timeout D]"

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	started := time.Now()
	fs := flag.NewFlagSet("adapter-render", flag.ContinueOnError)
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
	def := render.DefaultConfig()
	maxRequest := fs.Int64("max-request", def.MaxRequest, "bound on the request read from stdin, in bytes; keep it at or below the gateway's --max-request")
	maxBlocks := fs.Int("max-blocks", def.MaxBlocks, "bound on the blocks of one document")
	maxFile := fs.Int64("max-file", def.MaxFile, "bound on the rendered file, and on what its parts hold uncompressed, in bytes")
	maxOutput := fs.Int64("max-output", def.MaxOutput, "bound on the record in bytes; keep it at or below the gateway's --source-max-output")
	timeout := fs.Duration("timeout", def.Timeout, "the deadline, from the adapter's start; keep it under the gateway's thirty seconds")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	cfg := render.Config{MaxRequest: *maxRequest, MaxBlocks: *maxBlocks, MaxFile: *maxFile, MaxOutput: *maxOutput, Timeout: *timeout}
	if err := cfg.Check(); err != nil {
		fmt.Fprintln(stderr, "adapter-render:", err)
		return 2
	}
	// The deadline runs from the adapter's start, before the request is
	// read: reading its own executable for its identity is inside it, and
	// the wait for the request itself is held to it.
	ctx, cancel := context.WithDeadline(context.Background(), started.Add(cfg.Timeout))
	defer cancel()
	identity, err := ownIdentity()
	if err != nil {
		return refused(stderr, err)
	}
	// durationMs is the time from reading the request to writing the record,
	// which begins here.
	reading := time.Now()
	req, err := render.ParseRequest(ctx, stdin, cfg, time.Now)
	if err != nil {
		return refused(stderr, err)
	}
	out, err := render.Process(ctx, cfg, req, identity, reading)
	if err != nil {
		return refused(stderr, err)
	}
	if _, err := stdout.Write(out); err != nil {
		return refused(stderr, &render.Refusal{Code: render.CodeAdapterFailed, Reason: "stdout could not be written"})
	}
	return 0
}

// refused writes the one refusal line docs/design/rendering.md's "Refusals"
// names -- its code, a colon and the reason, ASCII, at most 160 bytes -- and
// exits 1.
func refused(stderr io.Writer, err error) int {
	var refusal *render.Refusal
	if !errors.As(err, &refusal) {
		refusal = &render.Refusal{Code: render.CodeAdapterFailed, Reason: "the adapter could not continue"}
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
