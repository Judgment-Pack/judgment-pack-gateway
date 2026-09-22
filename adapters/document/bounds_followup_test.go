package document

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
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
	locking, receiving := readLocking, readReceiving
	t.Cleanup(func() {
		readClock, readStamp, readWaiting = clock, stamp, waiting
		readStamping, readStamped, readArbitrated = stamping, stamped, arbitrated
		readLocking, readReceiving = locking, receiving
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
	readLocking, readReceiving = nil, nil
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

// boundsStalledClockEscape is the look at which the standing clock of the
// stalled-clock test below gives up standing still and moves past the cutoff.
// It is past every look an arbitration is allowed, so a reader that bounds its
// looks never reaches it and the clock stands still for every look it makes;
// a reader that does not bound them is let out here rather than left looking
// for ever, and fails on the count of looks it made rather than by hanging.
const boundsStalledClockEscape = requestArbitrationSpins + 64

// boundsReadHeldPastTheCutoff drives a reading whose result is stamped and
// then held back, with a cutoff that has already passed: the arbitration
// meets a request that has arrived and has not been handed over, which is the
// ordering an on-time request must survive. past is where the read's instant
// falls against the cutoff, and want what the arbitration must make of that
// instant, which is asserted here.
//
// The two outcomes have their own control over publication, and neither hands
// the result over on a decision the instant does not call for: what the test
// establishes is the arbitration's own, and a wrong decision is not to be
// rescued by the result arriving anyway. An on-time request's result is
// published only once the arbitration has entered the receive it committed to
// -- the seam it calls immediately before that receive is what publishes it --
// so that a reader which decided to wait and then did not wait finds the
// channel as empty as it was when it looked; a refused one's is published and
// waited for before the arbitration returns, so that what refuses it is the
// instant it carries and not an empty channel. Nothing here is timed: the
// seams are the whole of the ordering.
func boundsReadHeldPastTheCutoff(t *testing.T, past time.Duration, want bool) ([]byte, error) {
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
	readLocking = nil
	// The result is handed over inside the receive seam, which is to say at
	// the instant the arbitration blocks on the result and not before: an
	// arbitration that never enters that receive never releases it, and the
	// channel it looks at is empty.
	receiving := make(chan struct{})
	var receivingOnce sync.Once
	decided := make(chan bool, 1)
	readReceiving = func() {
		receivingOnce.Do(func() { close(receiving) })
		free()
	}
	readArbitrated = func(taken bool) {
		decided <- taken
		if taken != want {
			// The arbitration decided against the instant the read was
			// stamped at. The result stays where it is: what this reports is
			// the decision, and a decision that is wrong is not to be made
			// right by the channel.
			return
		}
		if !taken {
			// A refusal looks at the channel once: the result is put there
			// first, so what refuses it is the instant it carries.
			free()
			<-published
			return
		}
		// An on-time request is waited for, and its result is released by the
		// receive seam rather than here: the arbitration has committed to
		// waiting and has not yet waited.
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
	select {
	case taken := <-decided:
		if taken != want {
			t.Errorf("the arbitration made %v of a read stamped %v from the cutoff; the instant makes it %v", taken, past, want)
		} else if want {
			// A read the arbitration decided was on time is waited for in the
			// receive the seam announces. One that returned without entering
			// that receive released nothing, and whatever it returned it did
			// not wait for the result it had committed to waiting for.
			select {
			case <-receiving:
			default:
				t.Error("the arbitration decided to wait for an on-time read and returned without entering the receive")
			}
		}
	default:
		t.Error("the cutoff fired and nothing was arbitrated")
	}
	return got, err
}

// A request that had arrived by the cutoff is read although its result had
// not been handed over when the cutoff fired: the instant is stamped under
// the same lock the arbitration takes, so a read the runtime paused between
// stamping and publishing is waited for rather than refused. The arbitration
// must say so of the instant, and the result is handed over only once it has.
func TestBoundsARequestStampedByTheCutoffIsRead(t *testing.T) {
	// Exactly at the cutoff: the last instant a request is the request.
	for i := 0; i < 3; i++ {
		got, err := boundsReadHeldPastTheCutoff(t, 0, true)
		if err != nil || string(got) != "hello" {
			t.Fatalf("run %d: a request stamped at the cutoff and published after it was refused: %q %v", i, string(got), err)
		}
	}
}

// And one that ended after the cutoff is not the request, however promptly
// its result arrives: the instant decides, not the arrival.
func TestBoundsARequestStampedAfterTheCutoffIsRefused(t *testing.T) {
	got, err := boundsReadHeldPastTheCutoff(t, time.Nanosecond, false)
	if !errors.Is(err, errRequestNotRead) {
		t.Fatalf("a request stamped after the cutoff was taken: %q %v", string(got), err)
	}
}

// An arbitration that finds no stamp at all is committed only once the clock
// the stamps come from is past the cutoff: the timer fires, the arbitration
// looks and finds nothing, and the read then ends and stamps exactly the
// cutoff, which is an instant a request is still read at. A reader that
// committed the empty arbitration while its clock stood at the cutoff would
// refuse a request the next look showed had arrived in time, and which of the
// two goroutines the runtime ran first would be what decided.
func TestBoundsAnEmptyArbitrationWaitsForTheClock(t *testing.T) {
	boundsRestoreReadSeams(t)
	// The cutoff is long past by the clock the timer runs on, so the wait is
	// ready; the clock the stamps come from stands exactly at the cutoff and
	// does not advance, which is where an empty arbitration must not commit.
	now := time.Now().Add(-time.Hour)
	deadline := now.Add(-time.Hour)
	cutoff := now.Add(requestReadFloor)
	r := &boundsDrivenRead{release: make(chan struct{}), data: "hello"}
	var readOnce, publishOnce sync.Once
	endRead := func() { readOnce.Do(func() { close(r.release) }) }
	release := make(chan struct{})
	publish := func() { publishOnce.Do(func() { close(release) }) }
	published := make(chan struct{})
	var looks atomic.Int32
	readClock = func() time.Time { return now }
	readStamp = func() time.Time {
		if looks.Add(1) == 1 {
			// The first look is the arbitration's: it has found no stamp and
			// is asking what time it is. The read ends here, so that the
			// instant it stamps -- exactly the cutoff -- is stamped after
			// the arbitration looked and found nothing.
			endRead()
		}
		return cutoff
	}
	// Nothing is published while the arbitration is deciding: a refusal here
	// is the arbitration's own and not an empty channel's.
	readStamping = func(time.Time) { <-release }
	readStamped = func(time.Time) { close(published) }
	readWaiting = nil
	readLocking, readReceiving = nil, nil
	decided := make(chan bool, 1)
	readArbitrated = func(taken bool) {
		decided <- taken
		if taken {
			publish()
		}
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	got, err := readWithin(ctx, r, 1<<20)
	// The read is let go and waited for before the seams it reads are put
	// back, whatever the arbitration made of it.
	endRead()
	publish()
	<-published
	select {
	case taken := <-decided:
		if !taken {
			t.Error("an arbitration that found no stamp refused a read that then stamped exactly the cutoff")
		}
	default:
		t.Error("the cutoff fired and nothing was arbitrated")
	}
	if err != nil || string(got) != "hello" {
		t.Fatalf("a request stamped at the cutoff after an empty arbitration was refused: %q %v", string(got), err)
	}
}

// A clock that stands still is the one exception to that, and it is a refusal.
// The looks an empty arbitration makes are counted, because an unbounded wait
// on a clock that never advances, for a read that never ends, would not return
// at all; where those looks are exhausted with the clock still not past the
// cutoff, the clock is treated as past and the request is refused although a
// read stamped exactly the cutoff is there to be had. This drives exactly
// that: the clock the stamps come from stands at the cutoff for every look the
// arbitration is allowed, the read then ends and records a stamp of exactly
// the cutoff before the final receive, with its publication held so that what
// refuses the request is the exhausted look and not an empty channel. The
// count of looks is asserted as well as the refusal: a reader that did not
// bound its looks is let out by the clock moving well past that count, and
// fails here on the count rather than by hanging.
//
// The adapter's clock is time.Now, which the cutoff's own timer has already
// left behind by the time this is reached, so its first look ends the wait and
// this exception is a test's clock and not the adapter's.
func TestBoundsAStalledClockIsTreatedAsPastTheCutoff(t *testing.T) {
	boundsRestoreReadSeams(t)
	now := time.Now().Add(-time.Hour)
	deadline := now.Add(-time.Hour)
	cutoff := now.Add(requestReadFloor)
	r := &boundsDrivenRead{release: make(chan struct{}), data: "hello"}
	var readOnce, publishOnce sync.Once
	endRead := func() { readOnce.Do(func() { close(r.release) }) }
	t.Cleanup(endRead)
	release := make(chan struct{})
	publish := func() { publishOnce.Do(func() { close(release) }) }
	t.Cleanup(publish)
	stamping := make(chan struct{})
	published := make(chan struct{})
	var looks atomic.Int64
	readClock = func() time.Time { return now }
	readStamp = func() time.Time {
		if looks.Add(1) > boundsStalledClockEscape {
			return cutoff.Add(time.Nanosecond)
		}
		return cutoff
	}
	// The read's instant is recorded under the lock and its result held back
	// there, so an arbitration that looks again after the read has ended finds
	// the stamp and an arbitration that looks at the channel finds nothing.
	readStamping = func(time.Time) { close(stamping); <-release }
	readStamped = func(time.Time) { close(published) }
	readWaiting, readLocking, readReceiving = nil, nil, nil
	decided := make(chan bool, 1)
	made := make(chan int64, 1)
	readArbitrated = func(taken bool) {
		// What the arbitration decided, and how many looks it took to decide
		// it: the read has not ended yet, so every look is the arbitration's.
		decided <- taken
		made <- looks.Load()
		// The read now ends and stamps exactly the cutoff -- an instant a
		// request is read at -- and records it before the final receive.
		endRead()
		<-stamping
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	got, err := readWithin(ctx, r, 1<<20)
	// The read is let go and waited for before the seams it reads are put
	// back, whatever the arbitration made of it.
	endRead()
	publish()
	<-published
	select {
	case taken := <-decided:
		if taken {
			t.Error("an arbitration with no stamp at all waited for a read on a clock that never passed the cutoff")
		}
	default:
		t.Error("the cutoff fired and nothing was arbitrated")
	}
	select {
	case n := <-made:
		if n != requestArbitrationSpins {
			t.Errorf("the arbitration looked %d times at a clock that stood still, and the looks it is allowed are %d", n, requestArbitrationSpins)
		}
	default:
	}
	if !errors.Is(err, errRequestNotRead) {
		t.Fatalf("a clock that stood still for every look was not treated as past the cutoff: %q %v", string(got), err)
	}
}

// The stamp and the arbitration are one step against each other, and the lock
// is what makes them one: a stamp being taken as the arbitration arrives is a
// stamp the arbitration sees. The stamp is held inside its own critical
// section while the arbitration reaches the lock, and what the arbitration is
// asked for is the completed stamp -- it cannot be reached at all until the
// stamp has been released, which is what the lock establishes and what no
// ordering of the two goroutines gives without it. What lets the stamp go is
// the seam the arbitration calls immediately before it takes the lock, so the
// test names the instant the arbitration came to the lock and waits out no
// interval at all: a reader held at the lock decides after the release, and a
// reader that read the stamp without the lock decides before it.
func TestBoundsAStampBeingTakenIsWaitedFor(t *testing.T) {
	boundsRestoreReadSeams(t)
	now := time.Now().Add(-time.Hour)
	deadline := now.Add(-time.Hour)
	cutoff := now.Add(requestReadFloor)
	stamping := make(chan struct{})
	hold := make(chan struct{})
	var holdOnce sync.Once
	letStamp := func() { holdOnce.Do(func() { close(hold) }) }
	var looks atomic.Int32
	var released atomic.Bool
	readClock = func() time.Time { return now }
	readStamp = func() time.Time {
		if looks.Add(1) > 1 {
			// Any look after the stamp's own is an arbitration that found no
			// stamp, and the clock it reads has moved past the cutoff: a
			// reader that looked at the stamp without the lock finds none,
			// finds the clock past the cutoff, and refuses a request that
			// was being stamped on time as it looked.
			return cutoff.Add(time.Nanosecond)
		}
		// The stamp is taken here, inside the critical section, and held
		// there while the arbitration comes to the lock.
		close(stamping)
		<-hold
		released.Store(true)
		return cutoff
	}
	published := make(chan struct{})
	arbitrated := make(chan struct{})
	var arbitratedOnce sync.Once
	freeResult := func() { arbitratedOnce.Do(func() { close(arbitrated) }) }
	// The result is held back until the arbitration has decided, so what it
	// decides on is the stamp and never a result that reached the channel
	// first. With the stamp held until the arbitration comes to the lock, and
	// the result held until it has decided, the channel the wait selects on is
	// empty when that wait is armed: the cutoff is the only outcome offered
	// there, and the arbitration is reached under every schedule rather than
	// the read being taken directly, which for a read this on time would be a
	// correct outcome and would leave nothing to arbitrate.
	readStamping = func(time.Time) { <-arbitrated }
	readStamped = func(time.Time) { close(published) }
	readReceiving = nil
	// The arbitration begins only once the stamp has begun, so the lock is
	// held when it arrives.
	readWaiting = func() { <-stamping }
	// The stamp is let go by the arbitration's coming to the lock, and by
	// nothing else -- no interval is waited out here. A reader that takes the
	// lock is held at it from this instant until the stamp has been taken,
	// recorded and released, so its decision cannot come before the release at
	// any speed at all; a reader that reads the stamp without the lock goes
	// straight on from here and decides while the stamp is still being taken.
	readLocking = letStamp
	// What the arbitration decided, and whether the stamp had been released
	// when it decided it.
	type arbitration struct{ taken, afterTheStamp bool }
	seen := make(chan arbitration, 1)
	readArbitrated = func(taken bool) {
		seen <- arbitration{taken: taken, afterTheStamp: released.Load()}
		// A reader that reached a decision without ever coming to the lock is
		// let go here rather than left holding the stamp for ever: what it
		// fails on is the order it decided in, not a hang. The result is let
		// go with it, the decision having been taken.
		letStamp()
		freeResult()
	}
	r := &boundsDrivenRead{release: closedChan(), data: "hello"}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	got, err := readWithin(ctx, r, 1<<20)
	// The stamp and the result are let go and the read waited for before the
	// seams it reads are put back, whatever the arbitration made of it.
	letStamp()
	freeResult()
	<-published
	select {
	case a := <-seen:
		if !a.afterTheStamp {
			t.Error("the arbitration decided while the stamp was still being taken")
		}
		if !a.taken {
			t.Error("the arbitration did not see the stamp taken as it arrived at the lock")
		}
	default:
		t.Error("the cutoff fired and nothing was arbitrated")
	}
	if err != nil || string(got) != "hello" {
		t.Fatalf("a request stamped as the arbitration arrived was refused: %q %v", string(got), err)
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
	readLocking, readReceiving = nil, nil
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
