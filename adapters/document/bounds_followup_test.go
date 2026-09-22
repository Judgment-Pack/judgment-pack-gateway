package document

import (
	"context"
	"io"
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

// boundsReadAt drives one reading of a request: the clock stands at now, the
// read ends stamped at ended, and the wait is not decided until the result
// has been published. It reports what readWithin made of it.
func boundsReadAt(t *testing.T, deadline, now, ended time.Time) ([]byte, error) {
	t.Helper()
	defer func(clock, stamp func() time.Time, waiting func(), stamped func(time.Time)) {
		readClock, readStamp, readWaiting, readStamped = clock, stamp, waiting, stamped
	}(readClock, readStamp, readWaiting, readStamped)
	// The clock the cutoff is measured from, and the instant the read ends,
	// are two things the test names apart.
	readClock = func() time.Time { return now }
	readStamp = func() time.Time { return ended }
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

// A read and the cutoff that are both ready are decided by the instant the
// read ended, and not by which of them the runtime offers first: the test
// drives the clock and the completion, so neither side depends on when the
// scheduler ran anything.
func TestBoundsBothReadyIsDecidedByTheInstant(t *testing.T) {
	now := time.Now()
	// A deadline long past, so the cutoff is the floor past the clock.
	deadline := now.Add(-time.Hour)
	cutoff := now.Add(requestReadFloor)
	for _, c := range []struct {
		name  string
		ended time.Time
		read  bool
	}{
		{"a read that ended before the cutoff", cutoff.Add(-time.Millisecond), true},
		{"a read that ended at the cutoff", cutoff, true},
		{"a read that ended after the cutoff", cutoff.Add(time.Nanosecond), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			for i := 0; i < 20; i++ {
				got, err := boundsReadAt(t, deadline, now, c.ended)
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
