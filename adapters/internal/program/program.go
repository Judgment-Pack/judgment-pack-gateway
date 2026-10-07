// Package program runs a program an operator configured for an adapter: the
// OCR program of the document adapter, under the lifecycle that step 6 of
// docs/design/attachments.md, "How a document is processed", states for it.
// It is a package of its own so that a second adapter that runs an operator's
// program runs it under the same lifecycle, from the same code.
//
// It confines nothing. The program runs as the adapter does, with what the
// adapter can reach: the adapter's environment, its working directory and its
// process group are the program's, and a run has no way to give it others.
// Its stderr is discarded.
//
// What a caller must know of a run that its types do not say:
//
//   - The context ends a run by its deadline or its cancellation, and is read
//     before the program is started and while it runs. Resolving the name,
//     reading the file for its digest and starting the process are not
//     interrupted by it.
//   - The stdin is written as the program reads it. A program that does not
//     read all of it, or any of it, is not failed for that: its exit and its
//     stdout are what decide.
//   - MaxOutput is not held to any rule here. With zero, a program may write
//     nothing; with less than zero, every run is one that wrote past the
//     bound. A caller holds its own bound to its own rules.
//   - On an error no stdout is returned. The digest is returned with every
//     outcome but those of a name that did not resolve and a file that could
//     not be read, and is "sha256:" and 64 lowercase hexadecimal characters.
//   - A run waits for the exit of the process it started with no timer of
//     its own. PipeWait bounds the wait for a stdout still open, and nothing
//     else: it is one timer, started when the exit or the end of the context
//     is first observed, whichever comes first, and not started again.
//   - Only a program still running is ended, at the end of the context or
//     where it writes past the bound. One that has exited and left its
//     stdout open is not: its stdout is closed when the timer ends.
package program

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"time"
)

// ErrTimeout is the deadline found passed when the adapter took the outcome
// of a program that had started.
var ErrTimeout = errors.New("had not finished at the deadline")

// ErrNotStarted is the deadline found passed after the program was resolved
// and digested and before it was started: the program is not started.
var ErrNotStarted = errors.New("was not started: the deadline had passed")

// PipeWait is how long the adapter waits for the program's stdout to reach
// its end once the program has exited, or once the adapter has ended it at
// the deadline, before it closes the pipe itself.
const PipeWait = 2 * time.Second

// DeadlinePassed reports whether the context's deadline has passed, or the
// context has otherwise ended.
func DeadlinePassed(ctx context.Context) bool {
	if ctx.Err() != nil {
		return true
	}
	deadline, ok := ctx.Deadline()
	return ok && !time.Now().Before(deadline)
}

// ReadStdout reads the program's stdout up to limit, one byte past the
// output bound, and reports what it read and why the read ended. It is what
// a Run reads with where it names no other.
func ReadStdout(r io.Reader, limit int64) ([]byte, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(io.LimitReader(r, limit))
	return buf.Bytes(), err
}

// Run is one run of a program.
type Run struct {
	// Program is the program as the operator configured it: a name to be
	// resolved on the adapter's PATH, or a path.
	Program string
	// Args are its arguments, after its name.
	Args []string
	// Stdin is what it is given to read.
	Stdin []byte
	// MaxOutput bounds what it may write on stdout.
	MaxOutput int64
	// Read reads its stdout, or is nil for ReadStdout. A read that fails is
	// a guard: the pipe is the adapter's own, and only a test that names
	// another reader makes it fail.
	//
	// A reader is trusted. It is given a limit one byte past MaxOutput, or
	// the largest a limit can be where MaxOutput is that, and is to read to
	// the end of r or to the limit, whichever comes first, and return what
	// it read: what it returns past MaxOutput is how a run knows the bound
	// was passed, and a reader that returns before the end has made a
	// stdout that had not ended count as ended. It runs in a goroutine of
	// its own, which is not waited for where the wait for stdout gives up:
	// the pipe is closed under it, and what it does after that is its own.
	Read func(r io.Reader, limit int64) ([]byte, error)
	// Env, NAME=value entries, is added to the environment the program
	// inherits; none, it inherits the adapter's as it is. What a program is
	// given here stays out of its argument list, which every process on the
	// host can read.
	Env []string
}

// Do resolves, digests and runs the program, and returns what it wrote on
// stdout and the digest of the file its name resolved to, read before it was
// started. Its errors are phrased to follow the name of the program's role,
// "the OCR program", and carry nothing the program wrote.
//
// The program has finished when it has exited and its stdout has reached
// its end, as observed here, in either order. A program still running at the
// deadline is killed -- the process started, not its children -- and one that
// writes past the output bound is killed at once. A stdout that has not
// reached its end two seconds after the exit, or after the kill at the
// deadline, is closed here. The outcome is taken once the exit and the end of
// stdout, or that closing, have been observed; a deadline passed by then
// makes it ErrTimeout, whatever the program wrote.
func (r Run) Do(ctx context.Context) ([]byte, string, error) {
	path, err := exec.LookPath(r.Program)
	if err != nil {
		return nil, "", errors.New("could not be resolved on the adapter's PATH")
	}
	digest, err := fileDigest(path)
	if err != nil {
		return nil, "", errors.New("could not be read for its digest")
	}
	// The deadline's one check before the start: after resolution and
	// digest, immediately before the program is started.
	if DeadlinePassed(ctx) {
		return nil, digest, ErrNotStarted
	}
	read := r.Read
	if read == nil {
		read = ReadStdout
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
	cmd := exec.Command(path, r.Args...)
	cmd.Args[0] = r.Program
	if len(r.Env) > 0 {
		cmd.Env = append(os.Environ(), r.Env...)
	}
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
		stdinWrite.Write(r.Stdin)
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
		limit := r.MaxOutput
		if limit < math.MaxInt64 {
			limit++
		}
		data, err := read(stdoutRead, limit)
		ended <- stdout{data: data, overflowed: int64(len(data)) > r.MaxOutput, err: err}
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
			pipeWait = time.NewTimer(PipeWait)
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
	case DeadlinePassed(ctx):
		return nil, digest, ErrTimeout
	case stdoutEnded && out.overflowed:
		return nil, digest, fmt.Errorf("wrote past the output bound of %d bytes", r.MaxOutput)
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
