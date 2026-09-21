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
		if got.code != 1 || !strings.HasPrefix(got.stderr, "adapter-failed: the deadline passed and the request had not been read in full") {
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
// refuse it.
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
	for _, c := range []struct{ timeout, want string }{
		{"10s", `"status":"complete"`},
		{"1ms", `"code":"timeout"`},
	} {
		for i := 0; i < 50; i++ {
			var stdout, stderr bytes.Buffer
			if code := run([]string{"--timeout", c.timeout}, strings.NewReader(in), &stdout, &stderr); code != 0 {
				t.Fatalf("--timeout %s, run %d: exit %d: %s", c.timeout, i, code, stderr.String())
			}
			if !strings.Contains(stdout.String(), c.want) {
				t.Fatalf("--timeout %s, run %d: the record does not carry %s: %s", c.timeout, i, c.want, stdout.String())
			}
		}
	}
}
