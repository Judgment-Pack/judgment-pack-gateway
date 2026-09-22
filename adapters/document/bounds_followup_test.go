package document

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"
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

// A read and the cutoff that are both ready are decided by the instant the
// read ended, and not by which of them the runtime offers first. The reader
// is held at the moment both are ready -- the read has delivered and the
// cutoff has passed -- and the outcome is taken many times over: a read that
// ended after the cutoff is refused every time, and one that ended before it
// is taken every time.
func TestBoundsBothReadyIsDecidedByTheInstant(t *testing.T) {
	defer func(saved func()) { readWaiting = saved }(readWaiting)
	for _, c := range []struct {
		name    string
		release time.Duration
		read    bool
	}{
		{"a read that ended before the cutoff", 0, true},
		{"a read that ended after the cutoff", requestReadFloor + 20*time.Millisecond, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			for i := 0; i < 20; i++ {
				// The deadline is old, so the cutoff is the floor past now.
				ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-requestPipeWait))
				r := &boundsReleasedReader{release: make(chan struct{}), data: "hello"}
				if c.release == 0 {
					close(r.release)
				} else {
					time.AfterFunc(c.release, func() { close(r.release) })
				}
				// Held until the read has delivered and the cutoff has
				// passed, so that both outcomes are ready when one is taken.
				readWaiting = func() { time.Sleep(c.release + requestReadFloor + 40*time.Millisecond) }
				got, err := readWithin(ctx, r, 1<<20)
				cancel()
				if c.read && err != nil {
					t.Fatalf("run %d: a read that ended before the cutoff was refused: %v", i, err)
				}
				if !c.read && err == nil {
					t.Fatalf("run %d: a read that ended after the cutoff was taken: %q", i, string(got))
				}
			}
		})
	}
}

// The cutoff for a request still being read is an instant -- the deadline
// the context declares, plus the wait past it -- and not a wait that begins
// wherever the deadline was noticed. A read that ended at or before that
// instant is the request; one that ended after it is not, and which of the
// two happened is decided by when the read ended and not by which of two
// things a select offered first.
func TestBoundsRequestReadIsDecidedByAnInstant(t *testing.T) {
	for _, c := range []struct {
		name     string
		release  time.Duration
		read     bool
		atMost   time.Duration
		deadline time.Duration
	}{
		// The deadline is already old: what is left of the wait is what
		// remains of requestPipeWait from the deadline, not another two
		// seconds from now.
		{"a read that ends within the wait", 50 * time.Millisecond, true, time.Second, requestPipeWait - 300*time.Millisecond},
		{"a read that ends past the wait", 800 * time.Millisecond, false, time.Second, requestPipeWait - 300*time.Millisecond},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-c.deadline))
			defer cancel()
			r := &boundsHeldReader{release: make(chan struct{}), data: "hello"}
			// The read ends when the test says so, and the wait is held until
			// it has: neither side of the cutoff is left to the scheduler.
			timer := time.AfterFunc(c.release, func() { close(r.release) })
			defer timer.Stop()
			readWaiting = func() { time.Sleep(c.release + 40*time.Millisecond) }
			defer func() { readWaiting = nil }()
			started := time.Now()
			got, err := readWithin(ctx, r, 1<<20)
			took := time.Since(started)
			t.Logf("%s: %q %v after %v", c.name, string(got), err, took)
			if c.read && (err != nil || string(got) != "hello") {
				t.Errorf("a read that ended within the wait yielded %q and %v", string(got), err)
			}
			if !c.read && err == nil {
				t.Errorf("a read that ended past the wait yielded %q", string(got))
			}
			if took > c.atMost {
				t.Errorf("the wait took %v; it runs to an instant %v past the deadline", took, requestPipeWait)
			}
		})
	}
}

// A request that is already there is read, whatever the deadline says: the
// wait bounds a read that does not end, and a read of bytes that are there
// ends at once.
func TestBoundsRequestAlreadyThereIsRead(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
	defer cancel()
	// The wait is held until the read of bytes that are there has delivered,
	// so that what is established is the rule and not the scheduling.
	defer func(saved func()) { readWaiting = saved }(readWaiting)
	readWaiting = func() { time.Sleep(20 * time.Millisecond) }
	started := time.Now()
	got, err := readWithin(ctx, strings.NewReader("hello"), 1<<20)
	if err != nil || string(got) != "hello" {
		t.Fatalf("%q %v", string(got), err)
	}
	if took := time.Since(started); took > time.Second {
		t.Errorf("reading a request that was there took %v with a deadline an hour old", took)
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
