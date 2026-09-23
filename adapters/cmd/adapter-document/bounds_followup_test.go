package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"adapters/attachment"
	"adapters/document"
	"adapters/internal/pdfgen"
)

// boundsHeldOpen is a stdin whose writer never writes and never closes it:
// the read of it ends when the reader of this test lets it, and at no
// deadline of its own.
type boundsHeldOpen struct{ release chan struct{} }

func (s *boundsHeldOpen) Read([]byte) (int, error) {
	<-s.release
	return 0, io.EOF
}

// boundsNotReadLine is the whole of what the adapter writes on stderr when a
// request had not been read in full by the cutoff: the refusal the document
// package makes there, put through the same Line the command prints it with,
// and the newline the command ends it with. The reason is the document
// package's own wording, which it keeps inside ParseRequest rather than in
// anything this package can name, so it is written out here.
var boundsNotReadLine = (&document.Refusal{
	Code:   "adapter-failed",
	Reason: "the deadline passed and the request had not been read in full",
}).Line() + "\n"

// The deadline bounds the reading of the request as well as the work after
// it: a writer that holds the adapter's stdin open cannot hold the adapter
// past its deadline, and what comes back is the refusal that names the
// deadline, with nothing on stdout.
func TestBoundsTimeoutBoundsTheReadOfTheRequest(t *testing.T) {
	stdin := &boundsHeldOpen{release: make(chan struct{})}
	defer close(stdin.release)
	type outcome struct {
		code   int
		stderr string
		took   time.Duration
	}
	done := make(chan outcome, 1)
	go func() {
		var stdout, stderr bytes.Buffer
		started := time.Now()
		code := run([]string{"--timeout", "100ms"}, stdin, &stdout, &stderr)
		if stdout.Len() != 0 {
			t.Errorf("a refused request wrote %d bytes on stdout", stdout.Len())
		}
		done <- outcome{code: code, stderr: stderr.String(), took: time.Since(started)}
	}()
	select {
	case got := <-done:
		if got.code != 1 || got.stderr != boundsNotReadLine {
			t.Fatalf("exit %d after %v: %q", got.code, got.took, got.stderr)
		}
		// The deadline, and then the wait the adapter gives a read that has
		// begun: two seconds, with room for a loaded machine.
		if got.took > 6*time.Second {
			t.Errorf("a deadline of 100ms was answered after %v", got.took)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a deadline of 100ms left the adapter reading a stdin that was never closed")
	}
}

// A request that is there is read and recorded, whatever the deadline does:
// the bound on the read is a bound on waiting for a request, not one on
// reading a request that has arrived. Within the deadline the record is
// complete; with a deadline that passes before the read has begun, the
// request is still read and the record says timeout, as the note has a
// deadline found passed do. It is run many times over because the deadline
// and the read are both ready at once, and neither order of the two may
// refuse it. Which of them the runtime offers first does not decide the
// outcome: the read is judged by the instant it ended against the cutoff the
// deadline fixes, and every check of the deadline reads the clock as well as
// the context, so a deadline the clock has reached is found passed whether
// or not the timer that cancels the context has run.
//
// This runs the command, so the instants are the machine's and not the test's:
// the seams the reader's own tests drive are the document package's, and
// nothing here can reach them. What the machine can therefore do is leave a
// read that has bytes waiting to be scheduled, and where the deadline has
// already gone the cutoff is only two seconds off: a read the machine has not
// scheduled by then is refused, and that refusal is what the note says such a
// read gets rather than a defect to fail on. That row admits it and says how
// often it happened; admission under a deadline that has gone is established
// where the instants are driven, by the document package's
// TestBoundsAnOnTimeRequestHeldBackIsStillRecorded. The row whose deadline is
// still to come has twelve seconds of cutoff, which a machine that is running
// this test at all does not miss, and it asserts the complete record.
func TestBoundsRequestThatIsThereIsRecordedWhateverTheDeadline(t *testing.T) {
	identity, err := document.OwnIdentity()
	if err != nil {
		t.Fatal(err)
	}
	defer func(saved func() (attachment.Identity, error)) { ownIdentity = saved }(ownIdentity)
	// The identity step takes longer than the shorter deadline below, so that
	// deadline has passed before the read of the request begins.
	ownIdentity = func() (attachment.Identity, error) {
		time.Sleep(5 * time.Millisecond)
		return identity, nil
	}
	b := &pdfgen.Builder{Compress: true}
	f := b.Font("Helvetica", "WinAnsiEncoding", "")
	b.Catalog(b.Pages([]pdfgen.Page{{Content: pdfgen.Text("F1", 12, []string{"Hello record"}), Fonts: map[string]int{"F1": f}}}))
	in := request(t, "hello.pdf", "application/pdf", b.Bytes())
	for _, c := range []struct {
		timeout, want string
		// starved is whether the cutoff of this row is near enough that a read
		// the machine has not scheduled can miss it.
		starved bool
	}{
		{"10s", `"status":"complete"`, false},
		{"1ms", `"code":"timeout"`, true},
	} {
		unscheduled := 0
		for i := 0; i < 50; i++ {
			var stdout, stderr bytes.Buffer
			code := run([]string{"--timeout", c.timeout}, strings.NewReader(in), &stdout, &stderr)
			if code != 0 {
				if c.starved && code == 1 && stdout.Len() == 0 && stderr.String() == boundsNotReadLine {
					// The read of bytes that were there had not ended by the
					// cutoff, which is the one thing the wait past a deadline
					// bounds, and the refusal names it and says nothing else:
					// stderr is that one line and its newline, so a refusal
					// that went on to say more is not counted as this one.
					unscheduled++
					continue
				}
				t.Fatalf("--timeout %s, run %d: exit %d: %s", c.timeout, i, code, stderr.String())
			}
			if !strings.Contains(stdout.String(), c.want) {
				t.Fatalf("--timeout %s, run %d: the record does not carry %s: %s", c.timeout, i, c.want, stdout.String())
			}
		}
		if unscheduled != 0 {
			t.Logf("--timeout %s: %d of 50 reads were not scheduled by the cutoff and were refused", c.timeout, unscheduled)
		}
	}
}
