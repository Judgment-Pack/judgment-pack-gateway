package document

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"adapters/internal/canon"
	"adapters/internal/program"
)

// The OCR program's contract is step 6 of docs/design/attachments.md, "How
// a document is processed": run once per document with the page numbers
// as its arguments and the document's bytes on stdin, in the adapter's own
// process group, answering {"pages": [{"number", "text"}, ...]} on stdout
// within the output bound and the time left.

// errOCRTimeout is the deadline found passed when the adapter took the
// outcome of a program that had started.
var errOCRTimeout = program.ErrTimeout

// errOCRNotStarted is the deadline found passed after the program was
// resolved and digested and before it was started: the program is not
// started, and the record carries timeout.
var errOCRNotStarted = program.ErrNotStarted

// ocrPipeWait is how long the adapter waits for the program's stdout to
// reach its end once the program has exited, or once the adapter has ended
// it at the deadline, before it closes the pipe itself.
const ocrPipeWait = program.PipeWait

// deadlinePassed reports whether the context's deadline has passed, or the
// context has otherwise ended.
func deadlinePassed(ctx context.Context) bool {
	return program.DeadlinePassed(ctx)
}

// readOCRStdout reads the program's stdout up to limit, one byte past the
// output bound, and reports what it read and why the read ended. A read that
// fails is a guard: the pipe is the adapter's own, and only the tests that
// replace this make it fail.
var readOCRStdout = program.ReadStdout

// runOCRProgram resolves, digests and runs the program, with the page numbers
// as its arguments and the document on its stdin, under the lifecycle of
// adapters/internal/program, which is where step 6's rules for the run are
// kept: when the program has finished, when it is ended, how long its stdout
// is waited for, and what a deadline passed by then makes of what it wrote.
// Its errors are phrased to follow "the OCR program" and carry nothing the
// program wrote.
//
// The page numbers are made into arguments here, before the run, where they
// were made after the program had been resolved and digested and the deadline
// checked: a deadline that passes while they are made is now found by that
// check, and the program is not started.
func runOCRProgram(ctx context.Context, name string, pages []int, doc []byte, maxOutput int64) ([]byte, string, error) {
	return runOCRWithArgs(ctx, name, nil, pages, doc, maxOutput)
}

// runOCRWithArgs is runOCRProgram with the operator's arguments before the
// page numbers.
func runOCRWithArgs(ctx context.Context, name string, prefix []string, pages []int, doc []byte, maxOutput int64) ([]byte, string, error) {
	args := append([]string(nil), prefix...)
	for _, n := range pages {
		args = append(args, strconv.Itoa(n))
	}
	// The reader is looked up when the program's stdout is read, as it was
	// when this function read it itself, and not when the run is begun.
	read := func(r io.Reader, limit int64) ([]byte, error) { return readOCRStdout(r, limit) }
	return program.Run{Program: name, Args: args, Stdin: doc, MaxOutput: maxOutput, Read: read}.Do(ctx)
}

// admitOCRAnswer holds the program's output to step 6's admission: one
// value in the canonical domain; an object whose only member is pages, an
// array; entries whose only members are number, an integer, and text, a
// string; every number one the program was given, at most once. It returns
// the answered text by page number. Its errors follow "the OCR program's
// answer" and quote nothing the program wrote but a page number.
func admitOCRAnswer(raw []byte, asked []int) (map[int]string, error) {
	if _, err := canon.Canonicalize(raw, canon.RefuseNumbers); err != nil {
		return nil, errors.New("is not one JSON value in the canonical domain")
	}
	top, err := exactMembers(raw, map[string]bool{"pages": true})
	if err != nil || !isArray(top["pages"]) {
		return nil, errors.New("is not an object whose only member is pages, an array")
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(top["pages"], &entries); err != nil {
		return nil, errors.New("is not an object whose only member is pages, an array")
	}
	wanted := map[int]bool{}
	for _, n := range asked {
		wanted[n] = true
	}
	out := map[int]string{}
	for _, entry := range entries {
		members, err := exactMembers(entry, map[string]bool{"number": true, "text": true})
		if err != nil {
			return nil, errors.New("has an entry that is not an object whose only members are number and text")
		}
		literal := string(bytes.TrimSpace(members["number"]))
		number, err := strconv.ParseInt(literal, 10, 64)
		if err != nil {
			return nil, errors.New("has an entry whose number is not an integer")
		}
		var text string
		if !stringInto(members["text"], &text) {
			return nil, errors.New("has an entry whose text is not a string")
		}
		if number < 1 || number > int64(^uint(0)>>1) || !wanted[int(number)] {
			return nil, fmt.Errorf("answers page %d, which it was not asked for", number)
		}
		if _, twice := out[int(number)]; twice {
			return nil, fmt.Errorf("answers page %d twice", number)
		}
		out[int(number)] = text
	}
	return out, nil
}

func isArray(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '['
}
