package document

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"strconv"
	"time"

	"adapters/internal/canon"
)

// The OCR program's contract is step 6 of docs/design/attachments.md, "How
// a document is processed": run once per document with the page numbers
// as its arguments and the document's bytes on stdin, in the adapter's own
// process group, answering {"pages": [{"number", "text"}, ...]} on stdout
// within the output bound and the time left.

// errOCRTimeout is the deadline found passed when the adapter took the
// outcome of a program that had started.
var errOCRTimeout = errors.New("had not finished at the deadline")

// errOCRNotStarted is the deadline found passed after the program was
// resolved and digested and before it was started: the program is not
// started, and the record carries timeout.
var errOCRNotStarted = errors.New("was not started: the deadline had passed")

// ocrPipeWait is how long the adapter waits for the program's stdout to
// reach its end once the program has exited, or once the adapter has ended
// it at the deadline, before it closes the pipe itself.
const ocrPipeWait = 2 * time.Second

// deadlinePassed reports whether the context's deadline has passed, or the
// context has otherwise ended.
func deadlinePassed(ctx context.Context) bool {
	if ctx.Err() != nil {
		return true
	}
	deadline, ok := ctx.Deadline()
	return ok && !time.Now().Before(deadline)
}

// readOCRStdout reads the program's stdout up to limit, one byte past the
// output bound, and reports what it read and why the read ended. A read that
// fails is a guard: the pipe is the adapter's own, and only the tests that
// replace this make it fail.
var readOCRStdout = func(r io.Reader, limit int64) ([]byte, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(io.LimitReader(r, limit))
	return buf.Bytes(), err
}

// runOCRProgram resolves, digests and runs the program. Its errors are
// phrased to follow "the OCR program" and carry nothing the program wrote.
//
// The program has finished when it has exited and its stdout has reached
// its end, as observed here, in either order. A program still running at the
// deadline is killed -- the process started, not its children -- and one that
// writes past the output bound is killed at once. A stdout that has not
// reached its end two seconds after the exit, or after the kill at the
// deadline, is closed here. The outcome is taken once the exit and the end of
// stdout, or that closing, have been observed; a deadline passed by then
// makes it errOCRTimeout, whatever the program wrote.
func runOCRProgram(ctx context.Context, program string, pages []int, doc []byte, maxOutput int64) ([]byte, string, error) {
	path, err := exec.LookPath(program)
	if err != nil {
		return nil, "", errors.New("could not be resolved on the adapter's PATH")
	}
	digest, err := fileDigest(path)
	if err != nil {
		return nil, "", errors.New("could not be read for its digest")
	}
	// The deadline's one check in step 6: after resolution and digest,
	// immediately before the start.
	if deadlinePassed(ctx) {
		return nil, digest, errOCRNotStarted
	}
	args := make([]string, 0, len(pages))
	for _, n := range pages {
		args = append(args, strconv.Itoa(n))
	}
	// The pipes are the adapter's own files: the command then copies nothing
	// itself and its Wait returns when the process has exited, so the exit
	// and the end of stdout are observed apart.
	stdinRead, stdinWrite, err := os.Pipe()
	if err != nil {
		return nil, digest, errors.New("could not be started")
	}
	defer stdinWrite.Close()
	stdoutRead, stdoutWrite, err := os.Pipe()
	if err != nil {
		stdinRead.Close()
		return nil, digest, errors.New("could not be started")
	}
	defer stdoutRead.Close()
	cmd := exec.Command(path, args...)
	cmd.Args[0] = program
	cmd.Stdin, cmd.Stdout = stdinRead, stdoutWrite
	// Stderr is discarded: nil connects it to the null device.
	startErr := cmd.Start()
	stdinRead.Close()
	stdoutWrite.Close()
	if startErr != nil {
		return nil, digest, errors.New("could not be started")
	}

	go func() {
		// A program that does not read its stdin leaves this write blocked
		// until the pipe is closed on return.
		stdinWrite.Write(doc)
		stdinWrite.Close()
	}()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	type stdout struct {
		data       []byte
		overflowed bool
		err        error
	}
	ended := make(chan stdout, 1)
	go func() {
		limit := maxOutput
		if limit < math.MaxInt64 {
			limit++
		}
		data, err := readOCRStdout(stdoutRead, limit)
		ended <- stdout{data: data, overflowed: int64(len(data)) > maxOutput, err: err}
	}()

	var (
		waitErr                error
		out                    stdout
		hasExited, stdoutEnded bool
		killed, pipeClosed     bool
		pipeWait               *time.Timer
		pipeWaitC              <-chan time.Time
	)
	kill := func() {
		if !killed {
			killed = true
			_ = cmd.Process.Kill()
		}
	}
	startPipeWait := func() {
		if pipeWait == nil {
			pipeWait = time.NewTimer(ocrPipeWait)
			pipeWaitC = pipeWait.C
		}
	}
	defer func() {
		if pipeWait != nil {
			pipeWait.Stop()
		}
	}()
	deadline := ctx.Done()
	for !hasExited || !(stdoutEnded || pipeClosed) {
		select {
		case waitErr = <-exited:
			hasExited, exited = true, nil
			startPipeWait()
		case out = <-ended:
			stdoutEnded, ended = true, nil
			if out.overflowed {
				kill()
			}
		case <-deadline:
			deadline = nil
			if !hasExited {
				kill()
			}
			startPipeWait()
		case <-pipeWaitC:
			pipeWaitC = nil
			if !stdoutEnded {
				// The reader is not waited for: its read ends with the
				// pipe, and nothing it holds is used.
				stdoutRead.Close()
				pipeClosed = true
			}
		}
	}
	switch {
	case deadlinePassed(ctx):
		return nil, digest, errOCRTimeout
	case stdoutEnded && out.overflowed:
		return nil, digest, fmt.Errorf("wrote past the output bound of %d bytes", maxOutput)
	case !stdoutEnded:
		// Exited, with its stdout still held open two seconds later by a
		// process it left behind: not finished, and not the deadline.
		return nil, digest, errors.New("exited and left its stdout open past the two-second wait")
	case out.err != nil:
		return nil, digest, errors.New("wrote a stdout that could not be read")
	case waitErr != nil:
		return nil, digest, errors.New("exited with a non-zero status or could not be waited for")
	}
	return out.data, digest, nil
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
