package document

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"adapters/internal/pdfgen"
)

// boundsHeldReader ends its read when the test releases it, and not before:
// the instant the read ends is the test's to choose.
type boundsHeldReader struct {
	release chan struct{}
	data    string
}

func (r *boundsHeldReader) Read(p []byte) (int, error) {
	<-r.release
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, io.EOF
	}
	return n, nil
}

// boundsReleasedReader ends its read when the test releases it, and reports
// when it did.
type boundsReleasedReader struct {
	release chan struct{}
	data    string
}

func (r *boundsReleasedReader) Read(p []byte) (int, error) {
	<-r.release
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, io.EOF
	}
	return n, nil
}

// boundsDrivenRead is a read whose completion instant and publication are
// the test's to choose: it ends when the test releases it, stamps the instant
// the test names, and tells the test when its result is there to be taken.
// Nothing in these tests waits on the scheduler to have done something.
type boundsDrivenRead struct {
	release chan struct{}
	data    string
}

func (r *boundsDrivenRead) Read(p []byte) (int, error) {
	<-r.release
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, io.EOF
	}
	return n, nil
}

// boundsRestoreReadSeams puts the seams of readWithin back as they were.
func boundsRestoreReadSeams(t *testing.T) {
	t.Helper()
	clock, stamp, waiting := readClock, readStamp, readWaiting
	stamping, stamped, arbitrated := readStamping, readStamped, readArbitrated
	t.Cleanup(func() {
		readClock, readStamp, readWaiting = clock, stamp, waiting
		readStamping, readStamped, readArbitrated = stamping, stamped, arbitrated
	})
}

// boundsReadAt drives one reading of a request: the clock stands at now, the
// read ends stamped at ended, and the wait is not decided until the result
// has been published. It reports what readWithin made of it.
func boundsReadAt(t *testing.T, deadline, now, ended time.Time) ([]byte, error) {
	t.Helper()
	boundsRestoreReadSeams(t)
	// The clock the cutoff is measured from, and the instant the read ends,
	// are two things the test names apart.
	readClock = func() time.Time { return now }
	readStamp = func() time.Time { return ended }
	readStamping = nil
	readArbitrated = nil
	published := make(chan struct{})
	readStamped = func(time.Time) { close(published) }
	r := &boundsDrivenRead{release: make(chan struct{}), data: "hello"}
	close(r.release)
	// The wait is not decided until the read's result is there to be taken,
	// so both outcomes are ready and only the instants decide between them.
	readWaiting = func() { <-published }
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	return readWithin(ctx, r, 1<<20)
}

// boundsCutoffSources are the two instants a request's cutoff can come from,
// each arranged so that the cutoff has already passed by the clock the timer
// runs on: the wait is ready before the arbitration begins, so which of the
// two outcomes the runtime offers first is not what decides.
func boundsCutoffSources() []struct {
	name          string
	deadline, now time.Time
	cutoff        time.Time
} {
	started := time.Now()
	// The deadline and the grace past it: the clock stands at the deadline, so
	// the floor under the cutoff is well inside it.
	deadline := started.Add(-time.Hour)
	// The floor: a deadline so old that the grace past it is behind the clock.
	floorNow := started.Add(-time.Hour)
	return []struct {
		name          string
		deadline, now time.Time
		cutoff        time.Time
	}{
		{"the deadline and the grace past it", deadline, deadline, deadline.Add(requestPipeWait)},
		{"the floor under the cutoff", floorNow.Add(-time.Hour), floorNow, floorNow.Add(requestReadFloor)},
	}
}

// A read and the cutoff that are both ready are decided by the instant the
// read ended, and not by which of them the runtime offers first: the test
// drives the clock, the completion and the cutoff, so neither side depends on
// when the scheduler ran anything, and both instants a cutoff can come from
// are driven.
func TestBoundsBothReadyIsDecidedByTheInstant(t *testing.T) {
	for _, src := range boundsCutoffSources() {
		for _, c := range []struct {
			name  string
			ended time.Time
			read  bool
		}{
			{"a read that ended before the cutoff", src.cutoff.Add(-time.Millisecond), true},
			{"a read that ended at the cutoff", src.cutoff, true},
			{"a read that ended after the cutoff", src.cutoff.Add(time.Nanosecond), false},
		} {
			t.Run(src.name+", "+c.name, func(t *testing.T) {
				for i := 0; i < 20; i++ {
					got, err := boundsReadAt(t, src.deadline, src.now, c.ended)
					if c.read && (err != nil || string(got) != "hello") {
						t.Fatalf("run %d: %q %v", i, string(got), err)
					}
					if !c.read && err == nil {
						t.Fatalf("run %d: a read that ended after the cutoff was taken: %q", i, string(got))
					}
				}
			})
		}
	}
}

// The cutoff is an instant, and which instant it is decides the request: a
// read is taken where it ended at or before that instant and refused where it
// ended after it, at each of the two instants a cutoff comes from -- the
// deadline with the grace past it, and the floor under that -- and a moment
// either side of each.
func TestBoundsRequestReadIsDecidedByAnInstant(t *testing.T) {
	for _, src := range boundsCutoffSources() {
		for _, c := range []struct {
			name  string
			ended time.Time
			read  bool
		}{
			{"a moment before the cutoff", src.cutoff.Add(-time.Nanosecond), true},
			{"at the cutoff", src.cutoff, true},
			{"a moment after the cutoff", src.cutoff.Add(time.Nanosecond), false},
			{"long after the cutoff", src.cutoff.Add(time.Hour), false},
		} {
			t.Run(src.name+", a read that ended "+c.name, func(t *testing.T) {
				got, err := boundsReadAt(t, src.deadline, src.now, c.ended)
				if c.read && (err != nil || string(got) != "hello") {
					t.Fatalf("a read that ended %s was not taken: %q %v", c.name, string(got), err)
				}
				if !c.read && err == nil {
					t.Fatalf("a read that ended %s was taken: %q", c.name, string(got))
				}
			})
		}
	}
}

// boundsReadHeldPastTheCutoff drives a reading whose result is stamped and
// then held back, with a cutoff that has already passed: the arbitration
// meets a request that has arrived and has not been handed over, which is the
// ordering an on-time request must survive. The result is released from
// inside the arbitration, once what the stamp settled is known, so that what
// admits or refuses the request is the arbitration and not a race with the
// send. past is where the read's instant falls against the cutoff.
func boundsReadHeldPastTheCutoff(t *testing.T, past time.Duration) ([]byte, error) {
	t.Helper()
	boundsRestoreReadSeams(t)
	// A deadline old enough that the floor is the cutoff, and a clock far
	// enough behind the real one that the cutoff has already passed when the
	// wait is armed: the arbitration is reached, and reached with nothing
	// published.
	now := time.Now().Add(-time.Hour)
	deadline := now.Add(-time.Hour)
	ended := now.Add(requestReadFloor).Add(past)
	readClock = func() time.Time { return now }
	readStamp = func() time.Time { return ended }
	reached := make(chan struct{})
	published := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	// The read stamps, records its instant, and is held there: nothing is
	// published, so the wait below has only the cutoff to offer.
	readStamping = func(time.Time) { close(reached); <-release }
	readStamped = func(time.Time) { close(published) }
	readWaiting = func() { <-reached }
	readArbitrated = func(taken bool) {
		free()
		if !taken {
			// A refusal looks at the channel once: the result is there by
			// then, so what refuses it is the instant it carries and not an
			// empty channel.
			<-published
		}
	}
	r := &boundsDrivenRead{release: make(chan struct{}), data: "hello"}
	close(r.release)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	got, err := readWithin(ctx, r, 1<<20)
	// Whatever the arbitration did, the read is let go and waited for before
	// the seams it reads are put back.
	free()
	<-published
	return got, err
}

// A request that had arrived by the cutoff is read although its result had
// not been handed over when the cutoff fired: the instant is stamped under
// the same lock the arbitration takes, so a read the runtime paused between
// stamping and publishing is waited for rather than refused.
func TestBoundsARequestStampedByTheCutoffIsRead(t *testing.T) {
	// Exactly at the cutoff: the last instant a request is the request.
	got, err := boundsReadHeldPastTheCutoff(t, 0)
	if err != nil || string(got) != "hello" {
		t.Fatalf("a request stamped at the cutoff and published after it was refused: %q %v", string(got), err)
	}
}

// And one that ended after the cutoff is not the request, however promptly
// its result arrives: the instant decides, not the arrival.
func TestBoundsARequestStampedAfterTheCutoffIsRefused(t *testing.T) {
	got, err := boundsReadHeldPastTheCutoff(t, time.Nanosecond)
	if !errors.Is(err, errRequestNotRead) {
		t.Fatalf("a request stamped after the cutoff was taken: %q %v", string(got), err)
	}
}

// The whole of it, through the adapter's own reading of its request: a
// request that arrived by the cutoff and was published after it is parsed,
// and the record the deadline it arrived past yields says timeout.
func TestBoundsAnOnTimeRequestHeldBackIsStillRecorded(t *testing.T) {
	boundsRestoreReadSeams(t)
	now := time.Now().Add(-time.Hour)
	deadline := now.Add(-time.Hour)
	readClock = func() time.Time { return now }
	readStamp = func() time.Time { return now.Add(requestReadFloor) }
	reached := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	t.Cleanup(free)
	published := make(chan struct{})
	readStamping = func(time.Time) { close(reached); <-release }
	readStamped = func(time.Time) { close(published) }
	readWaiting = func() { <-reached }
	readArbitrated = func(taken bool) {
		if taken {
			free()
		}
	}
	cfg := DefaultConfig()
	in := requestJSON("held.pdf", "application/pdf", boundsOnePagePDF(), "")
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	req, err := ParseRequest(ctx, &boundsDrivenRead{release: closedChan(), data: in}, cfg, fixedNow)
	// The read is let go and waited for before the seams it reads are put
	// back, whatever the arbitration made of it.
	free()
	<-published
	if err != nil {
		t.Fatalf("a request that arrived by the cutoff was refused: %v", err)
	}
	out, err := Process(ctx, cfg, req, testIdentity, fixedNow())
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if !strings.Contains(string(out), `"timeout"`) {
		t.Errorf("the record of a request read past its deadline does not say timeout: %s", string(out))
	}
}

// closedChan is a release that has already happened.
func closedChan() chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}

// boundsOnePagePDF is a document of one page of text.
func boundsOnePagePDF() []byte {
	b := &pdfgen.Builder{}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	b.Catalog(b.Pages([]pdfgen.Page{{Content: pdfgen.Text("F1", 12, []string{"held"}), Fonts: map[string]int{"F1": helv}}}))
	return b.Bytes()
}

// A request that is already there is read, whatever the deadline says: the
// wait bounds a read that does not end, and a read of bytes that are there
// ends within the floor under the cutoff. The instants are the test's, so
// nothing here rests on when the scheduler ran the read.
func TestBoundsRequestAlreadyThereIsRead(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		name     string
		deadline time.Time
		ended    time.Time
	}{
		{"a deadline an hour old", now.Add(-time.Hour), now},
		{"a deadline just passed", now.Add(-time.Millisecond), now},
		{"a deadline still to come", now.Add(time.Hour), now},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := boundsReadAt(t, c.deadline, now, c.ended)
			if err != nil || string(got) != "hello" {
				t.Errorf("a request that was there read as %q (%v)", string(got), err)
			}
		})
	}
}

// boundsStaleDeadline is a context whose deadline has passed and whose error
// is not set: the timer that would cancel it has not run.
type boundsStaleDeadline struct{ context.Context }

func (boundsStaleDeadline) Err() error { return nil }

func (boundsStaleDeadline) Deadline() (time.Time, bool) {
	return time.Now().Add(-time.Second), true
}

// Every check of the deadline reads the clock as well as the context, so a
// deadline the clock has reached stops the work whether or not the timer
// that cancels the context has run.
func TestBoundsDeadlinePassedReadsTheClock(t *testing.T) {
	if !deadlinePassed(boundsStaleDeadline{context.Background()}) {
		t.Error("a deadline the clock has passed, whose context is not cancelled, was not read as passed")
	}
	live, cancelLive := context.WithDeadline(context.Background(), time.Now().Add(time.Hour))
	defer cancelLive()
	if deadlinePassed(live) {
		t.Error("a deadline an hour away was read as passed")
	}
}

// A read is taken by the instant it ended against the cutoff: one that ended
// at the cutoff is the request, and one a moment after it is not.
func TestBoundsReadIsTakenByItsInstant(t *testing.T) {
	cutoff := time.Now()
	for _, c := range []struct {
		name  string
		ended time.Time
		taken bool
	}{
		{"before the cutoff", cutoff.Add(-time.Millisecond), true},
		{"at the cutoff", cutoff, true},
		{"after the cutoff", cutoff.Add(time.Nanosecond), false},
	} {
		if got := readTaken(c.ended, cutoff); got != c.taken {
			t.Errorf("a read that ended %s is taken %v, want %v", c.name, got, c.taken)
		}
	}
}
