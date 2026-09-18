package document

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"adapters/attachment"
)

// ocrScript writes a shell program for the OCR runner, or skips the test
// where there is no /bin/sh.
func ocrScript(t *testing.T, body string) string {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	path := filepath.Join(t.TempDir(), "ocr")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// underDeadline is the real runner for the program at path, under a
// deadline of its own that starts when the processor calls it.
func underDeadline(path string, timeout time.Duration) OCRRunner {
	return func(ctx context.Context, _ string, pages []int, doc []byte, maxOutput int64) ([]byte, string, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return runOCRProgram(ctx, path, pages, doc, maxOutput)
	}
}

// The answer both scanned pages of scannedPDF take.
const bothPagesAnswer = `{"pages":[{"number":2,"text":"two"},{"number":3,"text":"three"}]}`

// A program that writes a whole answer and exits, leaving its stdout held
// open by a process it started, has not finished: the deadline that passes
// before its stdout ends makes the run ocr-timeout, and the whole answer it
// wrote is not applied.
func TestOCRAnswerWrittenBeforeTheDeadlineIsNotTakenAfterIt(t *testing.T) {
	program := ocrScript(t, `cat >/dev/null; printf '`+bothPagesAnswer+`'; sleep 0.5 & exit 0`)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	out, _, err := runOCRProgram(ctx, program, []int{2, 3}, []byte("doc"), 1<<20)
	if !errors.Is(err, errOCRTimeout) || out != nil {
		t.Fatalf("an answer whose stdout ended past the deadline: %q %v", out, err)
	}
	if elapsed := time.Since(started); elapsed > ocrPipeWait+time.Second {
		t.Fatalf("the run took %v", elapsed)
	}

	cfg := DefaultConfig()
	cfg.OCR = "ocr-pages"
	req := mustParse(t, cfg, requestJSON("scan.pdf", "application/pdf", scannedPDF(t), ""))
	rec := processed(t, cfg, req, underDeadline(program, 100*time.Millisecond))
	if codes(rec) != "ocr-timeout" || rec.Provenance.OCR != nil || rec.Content.Pages[1].Status != attachment.PageNeedsOCR || rec.Content.Pages[2].Status != attachment.PageNeedsOCR {
		t.Fatalf("%s %+v %+v", codes(rec), rec.Content.Pages, rec.Provenance.OCR)
	}
}

// The same program under a deadline its stdout ends well within is
// finished once it has exited and its stdout has ended -- in either order --
// and its answer is applied, including an answer written by the process it
// left behind after it exited.
func TestOCRAnswerTakenOnceExitAndEndOfStdoutAreBothObserved(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OCR = "ocr-pages"
	req := mustParse(t, cfg, requestJSON("scan.pdf", "application/pdf", scannedPDF(t), ""))
	for name, body := range map[string]string{
		"a child that closes quickly":          `cat >/dev/null; printf '` + bothPagesAnswer + `'; sleep 0.3 & exit 0`,
		"an answer written after the exit":     `cat >/dev/null; (sleep 0.3; printf '` + bothPagesAnswer + `') & exit 0`,
		"stdout ended before the exit":         `cat >/dev/null; printf '` + bothPagesAnswer + `'; exec >&-; sleep 0.3`,
		"an answer written with no child":      `cat >/dev/null; printf '` + bothPagesAnswer + `'`,
		"a document the program does not read": `printf '` + bothPagesAnswer + `'`,
	} {
		program := ocrScript(t, body)
		rec := processed(t, cfg, req, underDeadline(program, 3*time.Second))
		if codes(rec) != "" || rec.Content.Pages[1].Text != "two" || rec.Content.Pages[2].Text != "three" || rec.Provenance.OCR == nil || len(rec.Provenance.OCR.Pages) != 2 {
			t.Errorf("%s: %s %+v", name, codes(rec), rec.Content.Pages)
		}
	}
}

// A program that exits and leaves its stdout open is ocr-failed when its
// pipe is closed two seconds after its exit, unless the deadline has passed
// by then: then it is ocr-timeout, and the pipe is still closed two seconds
// after the exit.
func TestOCRStdoutLeftOpenPastTheDeadline(t *testing.T) {
	program := ocrScript(t, `cat >/dev/null; printf '{"pages":[]}'; sleep 5 & exit 0`)
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, _, err := runOCRProgram(ctx, program, []int{1}, nil, 100)
	if !errors.Is(err, errOCRTimeout) {
		t.Fatalf("a stdout held open past the deadline: %v", err)
	}
	if elapsed := time.Since(started); elapsed > ocrPipeWait+1500*time.Millisecond {
		t.Fatalf("the open stdout was waited on for %v", elapsed)
	}
}

// A program still running at the deadline whose stdout has already ended
// is ended, and the answer it wrote is not applied.
func TestOCRProgramRunningAtTheDeadlineAfterItsAnswer(t *testing.T) {
	program := ocrScript(t, `cat >/dev/null; printf '`+bothPagesAnswer+`'; exec >&-; sleep 5`)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	started := time.Now()
	if out, _, err := runOCRProgram(ctx, program, []int{2, 3}, nil, 1<<20); !errors.Is(err, errOCRTimeout) || out != nil {
		t.Fatalf("%q %v", out, err)
	}
	if elapsed := time.Since(started); elapsed > ocrPipeWait+time.Second {
		t.Fatalf("the program was not ended at the deadline: %v", elapsed)
	}
}

// A program that writes past the output bound while a process it started
// holds its stdout open is ended and fails without the two-second wait for
// that process.
func TestOCROutputPastTheBoundDoesNotWaitForTheChild(t *testing.T) {
	program := ocrScript(t, `cat >/dev/null; (head -c 5000 /dev/zero; sleep 10) & wait`)
	started := time.Now()
	_, _, err := runOCRProgram(context.Background(), program, []int{1}, nil, 100)
	if err == nil || !strings.Contains(err.Error(), "output bound") {
		t.Fatalf("past the output bound: %v", err)
	}
	if elapsed := time.Since(started); elapsed >= ocrPipeWait {
		t.Fatalf("the run waited %v", elapsed)
	}
}

// passAfter is a context whose deadline has not passed at its first n
// readings of the clock and has passed at every reading after them. Its Done
// never closes and its Err is always nil, so only a reading of the deadline
// itself sees that it has passed.
type passAfter struct {
	context.Context
	left int
}

func (c *passAfter) Deadline() (time.Time, bool) {
	c.left--
	if c.left < 0 {
		return time.Now().Add(-time.Second), true
	}
	return time.Now().Add(time.Hour), true
}

func (c *passAfter) Done() <-chan struct{} { return nil }

func (c *passAfter) Err() error { return nil }

// A deadline that has passed on the clock has passed, whether or not the
// context has ended: the program is not started before it, and a program
// started before it is ocr-timeout once it has. An outcome that is both past
// the output bound and past the deadline is ocr-timeout, which the note
// admits beside ocr-failed and which says the record carries no answer of a
// run the deadline ended.
func TestADeadlinePassedOnTheClockEndsTheRun(t *testing.T) {
	t.Run("before the start", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), "started")
		program := ocrScript(t, "touch "+marker+"; printf '{\"pages\":[]}'")
		if _, _, err := runOCRProgram(&passAfter{Context: context.Background()}, program, []int{1}, nil, 1<<20); !errors.Is(err, errOCRNotStarted) {
			t.Fatalf("a deadline passed on the clock: %v", err)
		}
		if _, err := os.Stat(marker); err == nil {
			t.Fatal("the program was started after the deadline had passed")
		}
	})
	t.Run("past the output bound and past the deadline", func(t *testing.T) {
		program := ocrScript(t, `cat >/dev/null; head -c 5000 /dev/zero; sleep 5`)
		out, _, err := runOCRProgram(&passAfter{Context: context.Background(), left: 1}, program, []int{1}, nil, 100)
		if !errors.Is(err, errOCRTimeout) || out != nil {
			t.Fatalf("both past the output bound and past the deadline: %q %v", out, err)
		}
	})
}

// A stdout that could not be read is a failed run, not an empty answer. The
// pipe is the adapter's own, so the read is made to fail here.
func TestOCRStdoutThatCouldNotBeReadFails(t *testing.T) {
	program := ocrScript(t, `cat >/dev/null; printf '{"pages":[]}'`)
	defer func(saved func(io.Reader, int64) ([]byte, error)) { readOCRStdout = saved }(readOCRStdout)
	readOCRStdout = func(io.Reader, int64) ([]byte, error) { return nil, errors.New("the pipe") }
	out, _, err := runOCRProgram(context.Background(), program, []int{1}, nil, 1<<20)
	if err == nil || !strings.Contains(err.Error(), "wrote a stdout that could not be read") || out != nil {
		t.Fatalf("a stdout that could not be read: %q %v", out, err)
	}
}
