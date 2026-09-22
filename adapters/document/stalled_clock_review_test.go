package document

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// A permanently frozen clock exhausts the stated 4096-look exception. A read
// then finishes exactly at the cutoff and publishes before the fallback receive.
func TestBoundsStalledClockRefusalSurvivesLaterPublication(t *testing.T) {
	boundsRestoreReadSeams(t)
	now := time.Now().Add(-time.Hour)
	cutoff := now.Add(requestReadFloor)
	r := &boundsDrivenRead{release: make(chan struct{}), data: "hello"}
	published := make(chan struct{})
	var looks atomic.Int64
	readClock = func() time.Time { return now }
	readStamp = func() time.Time { looks.Add(1); return cutoff }
	readWaiting, readStamping, readLocking, readReceiving = nil, nil, nil, nil
	readStamped = func(time.Time) { close(published) }
	readArbitrated = func(taken bool) {
		if taken {
			t.Error("read not yet finished was arbitrated as taken")
		}
		if n := looks.Load(); n != requestArbitrationSpins {
			t.Errorf("looks=%d want%d", n, requestArbitrationSpins)
		}
		close(r.release)
		<-published
	}
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(-time.Hour))
	defer cancel()
	got, err := readWithin(ctx, r, 1024)
	if !errors.Is(err, errRequestNotRead) {
		t.Fatalf("stalled-clock refusal reversed after cutoff-equal publication: got%q err%v", got, err)
	}
}
