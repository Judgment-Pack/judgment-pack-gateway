package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeLimitClock is an injected monotonic clock the test moves by hand.
type fakeLimitClock struct{ now atomic.Int64 }

func (c *fakeLimitClock) clock() limitClock {
	return func() time.Duration { return time.Duration(c.now.Load()) }
}

func (c *fakeLimitClock) advance(d time.Duration) { c.now.Add(int64(d)) }

func mustLimiter(t *testing.T, clock limitClock, before int, entries map[string]limitEntry) *requestLimiter {
	t.Helper()
	l, err := newRequestLimiter(clock, before, entries)
	if err != nil {
		t.Fatalf("newRequestLimiter: %v", err)
	}
	return l
}

func limitCallerOf(name string) *limitCallerKey {
	k := limitCallerKeyOf("token", "https://issuer.example", name)
	return &k
}

// admit is one request entering and being charged; the pass is returned
// held, for the test to release.
func limitAdmit(l *requestLimiter, scope string, caller *limitCallerKey) (*limitPass, *limitRefusal) {
	p, refused := l.enter()
	if refused == nil {
		refused = chargeOne(p, scope, caller)
	}
	return p, refused
}

// chargeOne is a charge of one scope, its refusal or nil; any other error
// fails the test's goroutine loudly.
func chargeOne(p *limitPass, scope string, caller *limitCallerKey) *limitRefusal {
	err := p.charge(caller, scope)
	var refused *limitRefusal
	if errors.As(err, &refused) {
		return refused
	}
	if err != nil {
		panic(err)
	}
	return nil
}

func wantLimitRefused(t *testing.T, r *limitRefusal, limit string, retryAfter int) {
	t.Helper()
	if r == nil {
		t.Fatalf("admitted, want refused %s", limit)
	}
	if r.limit != limit || r.retryAfter != retryAfter {
		t.Fatalf("refused %s, Retry-After %d; want %s, %d", r.limit, r.retryAfter, limit, retryAfter)
	}
}

func wantLimitAdmitted(t *testing.T, r *limitRefusal) {
	t.Helper()
	if r != nil {
		t.Fatalf("refused %s, want admitted", r.limit)
	}
}

// assertLimitNothingHeld is every counter of the limiter at zero.
func assertLimitNothingHeld(t *testing.T, l *requestLimiter) {
	t.Helper()
	if n := l.beforeHeld.Load(); n != 0 {
		t.Fatalf("gateway-wide cap holds %d", n)
	}
	for key, s := range l.scopes {
		if n := s.held.Load(); n != 0 {
			t.Fatalf("scope %s holds %d", key, n)
		}
		s.lock()
		for _, c := range s.callers {
			if n := c.held.Load(); n != 0 {
				s.unlock()
				t.Fatalf("a caller of scope %s holds %d", key, n)
			}
		}
		s.unlock()
	}
}

func TestLimitBucketRateAndBurst(t *testing.T) {
	g := gcraOf(limitValues{requestsPerMinute: 60, burst: 3})
	var tat atomic.Int64
	for i := range 3 {
		if _, _, ok := g.take(&tat, 0); !ok {
			t.Fatalf("take %d of a full bucket of 3 refused", i+1)
		}
	}
	if _, wait, ok := g.take(&tat, 0); ok || wait != time.Second {
		t.Fatalf("fourth take: ok %v, wait %v; want refused, 1s", ok, wait)
	}
	// one request a second refills it
	if _, _, ok := g.take(&tat, int64(time.Second)); !ok {
		t.Fatal("a take one second on refused")
	}
	if _, _, ok := g.take(&tat, int64(time.Second)); ok {
		t.Fatal("a second take in the same second admitted")
	}
	// a long idle spell fills the bucket to its burst, no further
	later := int64(time.Hour)
	for i := range 3 {
		if _, _, ok := g.take(&tat, later); !ok {
			t.Fatalf("take %d after an hour refused", i+1)
		}
	}
	if _, _, ok := g.take(&tat, later); ok {
		t.Fatal("an idle hour filled the bucket beyond its burst")
	}
}

func TestLimitRetryAfterRoundingAndBounds(t *testing.T) {
	cases := []struct {
		rpm, burst int
		at         time.Duration // when the refused take is made, after the bucket is spent at 0
		want       int
	}{
		{60, 1, 0, 1},
		{30, 1, 0, 2},                       // exactly 2s: 2, not 3
		{30, 1, 500 * time.Millisecond, 2},  // 1.5s rounds up
		{30, 1, 1999 * time.Millisecond, 1}, // 1ns is at least 1
		{7, 1, 0, 9},                        // 8.57s rounds up
		{1, 1, 0, 60},                       // the smallest rate: at most 60
		{1, 10000, 0, 60},
		{600000, 1, 0, 1}, // 100µs: at least 1
	}
	for _, c := range cases {
		clk := &fakeLimitClock{}
		l := mustLimiter(t, clk.clock(), 4, map[string]limitEntry{"east-ledger": {scope: limitValues{requestsPerMinute: c.rpm, burst: c.burst}}})
		for range c.burst {
			p, r := limitAdmit(l, "east-ledger", nil)
			wantLimitAdmitted(t, r)
			p.release()
		}
		clk.advance(c.at)
		p, r := limitAdmit(l, "east-ledger", nil)
		p.release()
		wantLimitRefused(t, r, limitScopeRate, c.want)
	}
}

func TestLimitRefusedTakeLeavesStateUnchanged(t *testing.T) {
	clk := &fakeLimitClock{}
	l := mustLimiter(t, clk.clock(), 4, map[string]limitEntry{"east-ledger": {scope: limitValues{requestsPerMinute: 60, burst: 1, inFlight: 1}}})
	s := l.scopes["east-ledger"]
	p, r := limitAdmit(l, "east-ledger", nil)
	wantLimitAdmitted(t, r)
	p.release()
	tat := s.tat.Load()
	// a caller that keeps sending while refused does not push its wait out
	for range 5 {
		q, r := limitAdmit(l, "east-ledger", nil)
		q.release()
		wantLimitRefused(t, r, limitScopeRate, 1)
	}
	if s.tat.Load() != tat || s.held.Load() != 0 {
		t.Fatalf("refused takes changed the bucket (%d to %d) or the cap (%d)", tat, s.tat.Load(), s.held.Load())
	}
	clk.advance(time.Second)
	held, r := limitAdmit(l, "east-ledger", nil)
	wantLimitAdmitted(t, r)
	// a refused take of the cap leaves the cap as it was, too
	clk.advance(time.Second)
	q, r := limitAdmit(l, "east-ledger", nil)
	q.release()
	wantLimitRefused(t, r, limitScopeInFlight, 1)
	if s.held.Load() != 1 {
		t.Fatalf("scope holds %d, want 1", s.held.Load())
	}
	held.release()
	assertLimitNothingHeld(t, l)
}

func TestLimitCallerRefusedByScopeGetsTokenBack(t *testing.T) {
	clk := &fakeLimitClock{}
	l := mustLimiter(t, clk.clock(), 4, map[string]limitEntry{"east-ledger": {
		scope:     limitValues{requestsPerMinute: 60, burst: 1},
		perCaller: &limitValues{requestsPerMinute: 1, burst: 1},
	}})
	other, x := limitCallerOf("other"), limitCallerOf("x")
	p, r := limitAdmit(l, "east-ledger", other)
	wantLimitAdmitted(t, r)
	p.release()
	// x's own bucket takes, the scope's refuses: x's token is given back
	p, r = limitAdmit(l, "east-ledger", x)
	p.release()
	wantLimitRefused(t, r, limitScopeRate, 1)
	clk.advance(time.Second)
	// the scope has refilled; x, whose own bucket refills once a minute,
	// still holds the token the scope's refusal gave back
	p, r = limitAdmit(l, "east-ledger", x)
	p.release()
	wantLimitAdmitted(t, r)
	assertLimitNothingHeld(t, l)
}

func TestLimitCallersTableIsBounded(t *testing.T) {
	t.Run("busy callers refuse a new one, never admit it uncounted", func(t *testing.T) {
		clk := &fakeLimitClock{}
		l := mustLimiter(t, clk.clock(), 8, map[string]limitEntry{"east-ledger": {perCaller: &limitValues{inFlight: 2}}})
		s := l.scopes["east-ledger"]
		held := make([]*limitPass, 0, maxLimitedCallers)
		for i := range maxLimitedCallers {
			p, r := limitAdmit(l, "east-ledger", limitCallerOf(fmt.Sprint("c", i)))
			wantLimitAdmitted(t, r)
			held = append(held, p)
		}
		newcomer := limitCallerOf("newcomer")
		p, r := limitAdmit(l, "east-ledger", newcomer)
		p.release()
		wantLimitRefused(t, r, limitCallers, 1)
		if len(s.callers) != maxLimitedCallers || s.callers[*newcomer] != nil {
			t.Fatalf("table of %d callers; the newcomer held: %v", len(s.callers), s.callers[*newcomer] != nil)
		}
		// a held caller is still served within its own cap
		p, r = limitAdmit(l, "east-ledger", limitCallerOf("c0"))
		wantLimitAdmitted(t, r)
		p.release()
		// one caller idle: within the interval the table is not swept
		// again, and the newcomer is refused still (#594, the sweep)
		held[0].release()
		clk.advance(limitSweepInterval - 1)
		p, r = limitAdmit(l, "east-ledger", newcomer)
		p.release()
		wantLimitRefused(t, r, limitCallers, 1)
		// once the interval has passed, the sweep drops it, and the
		// newcomer is counted
		clk.advance(1)
		p, r = limitAdmit(l, "east-ledger", newcomer)
		wantLimitAdmitted(t, r)
		if len(s.callers) != maxLimitedCallers || s.callers[*limitCallerOf("c0")] != nil || s.callers[*newcomer] == nil {
			t.Fatalf("after the sweep: %d callers", len(s.callers))
		}
		p.release()
		for _, q := range held[1:] {
			q.release()
		}
		assertLimitNothingHeld(t, l)
	})
	t.Run("a caller with a spent bucket is not idle", func(t *testing.T) {
		clk := &fakeLimitClock{}
		l := mustLimiter(t, clk.clock(), 8, map[string]limitEntry{"east-ledger": {perCaller: &limitValues{requestsPerMinute: 60, burst: 1}}})
		for i := range maxLimitedCallers {
			p, r := limitAdmit(l, "east-ledger", limitCallerOf(fmt.Sprint("c", i)))
			wantLimitAdmitted(t, r)
			p.release()
		}
		// nothing in flight, but every bucket is spent: dropping one would
		// hand its caller a full bucket again
		p, r := limitAdmit(l, "east-ledger", limitCallerOf("newcomer"))
		p.release()
		wantLimitRefused(t, r, limitCallers, 1)
		p, r = limitAdmit(l, "east-ledger", limitCallerOf("c0"))
		p.release()
		wantLimitRefused(t, r, limitCallerRate, 1)
		clk.advance(time.Second)
		p, r = limitAdmit(l, "east-ledger", limitCallerOf("newcomer"))
		p.release()
		wantLimitAdmitted(t, r)
	})
	t.Run("a request with no caller is refused where callers are counted", func(t *testing.T) {
		l := mustLimiter(t, (&fakeLimitClock{}).clock(), 8, map[string]limitEntry{"east-ledger": {perCaller: &limitValues{inFlight: 1}}})
		p, r := limitAdmit(l, "east-ledger", nil)
		p.release()
		wantLimitRefused(t, r, limitCallers, 1)
	})
}

func TestLimitInFlightIsReleasedOnEveryPath(t *testing.T) {
	clk := &fakeLimitClock{}
	l := mustLimiter(t, clk.clock(), 2, map[string]limitEntry{"east-ledger": {
		scope:     limitValues{requestsPerMinute: 60, burst: 2, inFlight: 2},
		perCaller: &limitValues{requestsPerMinute: 60, burst: 2, inFlight: 1},
	}})
	a, b := limitCallerOf("a"), limitCallerOf("b")
	serve := func(scope string, caller *limitCallerKey, then func()) (refused *limitRefusal) {
		p, r := l.enter()
		defer p.release()
		if r == nil {
			r = chargeOne(p, scope, caller)
		}
		if r == nil && then != nil {
			then()
		}
		return r
	}
	wantLimitAdmitted(t, serve("east-ledger", a, nil))
	assertLimitNothingHeld(t, l)

	// refused at the caller's cap, while the caller holds a request
	wantLimitAdmitted(t, serve("east-ledger", a, func() {
		wantLimitRefused(t, serve("east-ledger", a, nil), limitCallerInFlight, 1)
	}))
	assertLimitNothingHeld(t, l)

	// refused at the scope's cap, then at the gateway-wide cap
	clk.advance(time.Hour)
	wantLimitAdmitted(t, serve("east-ledger", a, func() {
		wantLimitAdmitted(t, serve("east-ledger", b, func() {
			wantLimitRefused(t, serve("east-ledger", limitCallerOf("c"), nil), limitScopeInFlight, 1)
			hold, _ := l.enter()
			hold2, _ := l.enter()
			_, r := l.enter()
			wantLimitRefused(t, r, limitGatewayInFlight, 1)
			hold.release()
			hold2.release()
		}))
	}))
	assertLimitNothingHeld(t, l)

	// refused at the caller's bucket, and at the scope's
	clk.advance(time.Hour)
	wantLimitAdmitted(t, serve("east-ledger", a, nil))
	wantLimitAdmitted(t, serve("east-ledger", a, nil))
	wantLimitRefused(t, serve("east-ledger", a, nil), limitCallerRate, 1)
	wantLimitRefused(t, serve("east-ledger", b, nil), limitScopeRate, 1)
	assertLimitNothingHeld(t, l)

	// never charged, as an unauthenticated request is
	wantLimitAdmitted(t, serve("", nil, nil))
	p, _ := l.enter()
	p.release()
	assertLimitNothingHeld(t, l)

	// a panic the server recovers, after the request is charged
	clk.advance(time.Hour)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("no panic")
			}
		}()
		serve("east-ledger", a, func() { panic("a handler's panic") })
	}()
	assertLimitNothingHeld(t, l)

	// a release made twice gives back once
	p, r := limitAdmit(l, "east-ledger", b)
	wantLimitAdmitted(t, r)
	p.release()
	p.release()
	assertLimitNothingHeld(t, l)
}

func TestLimitScopesAreIsolated(t *testing.T) {
	clk := &fakeLimitClock{}
	l := mustLimiter(t, clk.clock(), 8, map[string]limitEntry{
		"east-ledger": {scope: limitValues{requestsPerMinute: 60, burst: 2, inFlight: 2}, perCaller: &limitValues{inFlight: 2}},
		"west-ledger": {scope: limitValues{requestsPerMinute: 60, burst: 1, inFlight: 1}, perCaller: &limitValues{inFlight: 1}},
	})
	east := l.scopes["east-ledger"]

	// east's two requests are admitted and held inside, blocked on a
	// channel the test holds: east is at its cap and its rate
	hold := make(chan struct{})
	admitted := make(chan *limitRefusal)
	var inside sync.WaitGroup
	for i := range 2 {
		inside.Add(1)
		go func() {
			defer inside.Done()
			p, r := limitAdmit(l, "east-ledger", limitCallerOf(fmt.Sprint("e", i)))
			defer p.release()
			admitted <- r
			<-hold
		}()
	}
	for range 2 {
		wantLimitAdmitted(t, <-admitted)
	}
	p, r := limitAdmit(l, "east-ledger", limitCallerOf("e2"))
	p.release()
	wantLimitRefused(t, r, limitScopeInFlight, 1)

	// and east's own mutex is held by the test
	east.lock()
	done := make(chan *limitRefusal, 1)
	go func() {
		p, r := limitAdmit(l, "west-ledger", limitCallerOf("w0"))
		p.release()
		done <- r
	}()
	// West's request is answered while east's mutex is still held and its
	// requests still inside: the order is the assertion. The timer only ends
	// a test that would otherwise hang on east's state.
	select {
	case r := <-done:
		wantLimitAdmitted(t, r)
	case <-time.After(10 * time.Second):
		east.unlock()
		close(hold)
		t.Fatal("west's request waited on east's state")
	}
	east.unlock()
	close(hold)
	inside.Wait()
	assertLimitNothingHeld(t, l)
}

func TestLimitGatewayWideCap(t *testing.T) {
	clk := &fakeLimitClock{}
	l := mustLimiter(t, clk.clock(), 2, map[string]limitEntry{"east-ledger": {scope: limitValues{inFlight: 4}}})
	first, r := l.enter()
	wantLimitAdmitted(t, r)
	// a request never charged -- an unauthenticated /verify -- holds its
	// slot until it is released
	verify, r := l.enter()
	wantLimitAdmitted(t, r)
	third, r := l.enter()
	wantLimitRefused(t, r, limitGatewayInFlight, 1)
	if l.unauthenticatedRefusals() != 1 {
		t.Fatalf("unauthenticated refusals %d, want 1", l.unauthenticatedRefusals())
	}
	// a pass refused at the cap stays refused if a route charges it
	wantLimitRefused(t, chargeOne(third, "east-ledger", nil), limitGatewayInFlight, 1)
	third.release()
	if l.beforeHeld.Load() != 2 {
		t.Fatalf("gateway-wide cap holds %d, want 2", l.beforeHeld.Load())
	}
	// a request charged to a scope gives its gateway-wide slot back
	wantLimitAdmitted(t, chargeOne(first, "east-ledger", nil))
	if l.beforeHeld.Load() != 1 || l.scopes["east-ledger"].held.Load() != 1 {
		t.Fatalf("after the charge: gateway-wide %d, scope %d", l.beforeHeld.Load(), l.scopes["east-ledger"].held.Load())
	}
	fourth, r := l.enter()
	wantLimitAdmitted(t, r)
	_, r = l.enter()
	wantLimitRefused(t, r, limitGatewayInFlight, 1)
	// a scope with no entry is charged nothing, and frees the slot too
	wantLimitAdmitted(t, chargeOne(fourth, "west-ledger", nil))
	verify.release()
	first.release()
	fourth.release()
	assertLimitNothingHeld(t, l)
	// refusals at authentication are counted with the cap's
	l.noteUnauthenticated()
	if l.unauthenticatedRefusals() != 3 {
		t.Fatalf("unauthenticated refusals %d, want 3", l.unauthenticatedRefusals())
	}
}

func TestLimitVerifyChargedToItsCallersScope(t *testing.T) {
	// a /verify of a caller of one scope is charged to that scope like any
	// request: it holds the scope's slot, and gives the gateway-wide one back
	l := mustLimiter(t, (&fakeLimitClock{}).clock(), 1, map[string]limitEntry{unscopedMarker: {scope: limitValues{inFlight: 1}}})
	v, r := limitAdmit(l, unscopedMarker, nil)
	wantLimitAdmitted(t, r)
	p, r := limitAdmit(l, unscopedMarker, nil)
	p.release()
	wantLimitRefused(t, r, limitScopeInFlight, 1)
	v.release()
	assertLimitNothingHeld(t, l)
}

func TestLimitRefusalIsFixed(t *testing.T) {
	entries := map[string]limitEntry{
		"east-ledger": {scope: limitValues{requestsPerMinute: 60, burst: 1, inFlight: 2}, perCaller: &limitValues{requestsPerMinute: 1, burst: 1, inFlight: 1}},
		"west-ledger": {scope: limitValues{requestsPerMinute: 1, burst: 1, inFlight: 1}, perCaller: &limitValues{inFlight: 1}},
	}
	answer := func(r *limitRefusal) string {
		t.Helper()
		if r == nil {
			t.Fatal("admitted, want refused")
		}
		h := http.Header{}
		r.setRetryAfter(h)
		b, err := json.Marshal(r.body())
		if err != nil {
			t.Fatal(err)
		}
		return h.Get("Retry-After") + " " + string(b)
	}
	// east's refusals, each from its own state, with west at rest or spent
	eastRefusals := func(westSpent bool) []string {
		clk := &fakeLimitClock{}
		l := mustLimiter(t, clk.clock(), 8, entries)
		if westSpent {
			w, r := limitAdmit(l, "west-ledger", limitCallerOf("w0"))
			wantLimitAdmitted(t, r)
			defer w.release()
			for i := range 3 {
				q, _ := limitAdmit(l, "west-ledger", limitCallerOf(fmt.Sprint("w", i)))
				q.release()
			}
		}
		var out []string
		// the caller's bucket refuses: its own wait (60s), not the scope's
		p, r := limitAdmit(l, "east-ledger", limitCallerOf("a"))
		wantLimitAdmitted(t, r)
		p.release()
		p, r = limitAdmit(l, "east-ledger", limitCallerOf("a"))
		p.release()
		wantLimitRefused(t, r, limitCallerRate, 60)
		out = append(out, answer(r))
		// the scope's bucket refuses: its own wait (1s), not west's (60s)
		clk.advance(time.Second)
		p, r = limitAdmit(l, "east-ledger", limitCallerOf("b"))
		wantLimitAdmitted(t, r)
		p.release()
		p, r = limitAdmit(l, "east-ledger", limitCallerOf("c"))
		p.release()
		wantLimitRefused(t, r, limitScopeRate, 1)
		out = append(out, answer(r))
		// the caller's cap, then the scope's
		clk.advance(time.Hour)
		hold, r := limitAdmit(l, "east-ledger", limitCallerOf("d"))
		wantLimitAdmitted(t, r)
		p, r = limitAdmit(l, "east-ledger", limitCallerOf("d"))
		p.release()
		wantLimitRefused(t, r, limitCallerInFlight, 1)
		out = append(out, answer(r))
		clk.advance(time.Hour)
		hold2, r := limitAdmit(l, "east-ledger", limitCallerOf("e"))
		wantLimitAdmitted(t, r)
		p, r = limitAdmit(l, "east-ledger", limitCallerOf("f"))
		p.release()
		wantLimitRefused(t, r, limitScopeInFlight, 1)
		out = append(out, answer(r))
		hold.release()
		hold2.release()
		return out
	}
	atRest, westSpent := eastRefusals(false), eastRefusals(true)
	if !slices.Equal(atRest, westSpent) {
		t.Fatalf("east's refusals change with west's state:\n%q\n%q", atRest, westSpent)
	}
	// every limit's sentence: a constant, its own, naming no scope or number
	seen := map[string]bool{}
	for _, limit := range []string{limitScopeRate, limitScopeInFlight, limitCallerRate, limitCallerInFlight, limitCallers, limitGatewayInFlight} {
		r := &limitRefusal{limit: limit, retryAfter: 1}
		body := r.body()
		if len(body) != 3 || body["code"] != "limit_reached" || body["limit"] != limit || body["error"] != limitSentence(limit) {
			t.Fatalf("%s: body %v", limit, body)
		}
		sentence := limitSentence(limit)
		if seen[sentence] || strings.ContainsAny(sentence, "0123456789") || strings.Contains(sentence, "ledger") || strings.Contains(sentence, unscopedMarker) {
			t.Fatalf("%s: sentence %q", limit, sentence)
		}
		seen[sentence] = true
	}
}

func TestLimitConcurrentTakeAndRelease(t *testing.T) {
	l := mustLimiter(t, monotonicLimitClock(), 64, map[string]limitEntry{
		"east-ledger":  {scope: limitValues{requestsPerMinute: 600000, burst: 50, inFlight: 8}, perCaller: &limitValues{requestsPerMinute: 600000, burst: 10, inFlight: 2}},
		"west-ledger":  {scope: limitValues{inFlight: 3}},
		unscopedMarker: {perCaller: &limitValues{inFlight: 1}},
	})
	scopes := []string{"east-ledger", "west-ledger", unscopedMarker, "north-ledger", ""}
	var admitted, refused atomic.Int64
	// the highest count each cap held, raised by compare-and-swap
	highest := map[string]*atomic.Int64{"": {}}
	for key := range l.scopes {
		highest[key] = &atomic.Int64{}
	}
	note := func(key string, n int64) {
		h := highest[key]
		for {
			was := h.Load()
			if n <= was || h.CompareAndSwap(was, n) {
				return
			}
		}
	}
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 2000 {
				scope := scopes[(g+i)%len(scopes)]
				p, r := l.enter()
				if r == nil && scope != "" {
					r = chargeOne(p, scope, limitCallerOf(fmt.Sprint("c", (g*7+i)%11)))
				}
				note("", l.beforeHeld.Load())
				for key, s := range l.scopes {
					note(key, s.held.Load())
				}
				if r == nil {
					admitted.Add(1)
				} else {
					refused.Add(1)
				}
				p.release()
			}
		}()
	}
	wg.Wait()
	if admitted.Load() == 0 {
		t.Fatal("nothing admitted")
	}
	if n := highest[""].Load(); n > l.beforeMost {
		t.Fatalf("the gateway-wide cap of %d held %d", l.beforeMost, n)
	}
	for key, s := range l.scopes {
		if n := highest[key].Load(); s.most > 0 && n > s.most || s.most == 0 && n != 0 {
			t.Fatalf("scope %s, cap %d, held %d", key, s.most, n)
		}
	}
	if highest["east-ledger"].Load() == 0 || highest["west-ledger"].Load() == 0 {
		t.Fatal("no scope's cap was ever held")
	}
	assertLimitNothingHeld(t, l)
}

// A charge of several scopes is all or nothing (ADR-0057, the maintainer's
// ruling on /verify): where one scope refuses, nothing of the others stays
// taken -- neither a slot nor a bucket's request -- and the refusal is the
// refusing scope's own.
func TestLimitChargeOfSeveralScopesIsAllOrNothing(t *testing.T) {
	clk := &fakeLimitClock{}
	l := mustLimiter(t, clk.clock(), 4, map[string]limitEntry{
		"east-ledger":  {scope: limitValues{requestsPerMinute: 60, burst: 1, inFlight: 1}, perCaller: &limitValues{requestsPerMinute: 60, burst: 1, inFlight: 1}},
		"west-ledger":  {scope: limitValues{inFlight: 1}},
		unscopedMarker: {scope: limitValues{requestsPerMinute: 60, burst: 1}},
	})
	caller := limitCallerOf("all")
	// west's one slot is held by another request
	other, r := limitAdmit(l, "west-ledger", limitCallerOf("other"))
	wantLimitAdmitted(t, r)
	p, _ := l.enter()
	err := p.charge(caller, unscopedMarker, "west-ledger", "east-ledger", "north-ledger")
	var refused *limitRefusal
	if !errors.As(err, &refused) {
		t.Fatalf("charge: %v, want west's refusal", err)
	}
	wantLimitRefused(t, refused, limitScopeInFlight, 1)
	p.release()
	other.release()
	assertLimitNothingHeld(t, l)
	// east's and unscoped's buckets of one request each are whole: each
	// scope, and east's caller, admits one request now, at the same instant
	for _, scope := range []string{"east-ledger", unscopedMarker} {
		q, r := limitAdmit(l, scope, caller)
		wantLimitAdmitted(t, r)
		q.release()
	}
	// with every scope free, the charge takes each of them, once
	clk.advance(time.Minute)
	p, _ = l.enter()
	if err := p.charge(caller, "west-ledger", "east-ledger", "west-ledger", unscopedMarker); err != nil {
		t.Fatalf("charge: %v", err)
	}
	if l.scopes["west-ledger"].held.Load() != 1 || l.scopes["east-ledger"].held.Load() != 1 || l.beforeHeld.Load() != 0 {
		t.Fatal("the charge did not hold each scope once, or kept the gateway-wide slot")
	}
	p.release()
	assertLimitNothingHeld(t, l)
}

// A second charge of one request is an error the route answers, never a
// panic inside a handler, and it changes nothing (#594).
func TestLimitSecondChargeIsAnError(t *testing.T) {
	l := mustLimiter(t, (&fakeLimitClock{}).clock(), 2, map[string]limitEntry{"east-ledger": {scope: limitValues{inFlight: 2}}})
	p, _ := l.enter()
	if err := p.charge(nil, "east-ledger"); err != nil {
		t.Fatal(err)
	}
	if err := p.charge(nil, "east-ledger"); !errors.Is(err, errLimitCharged) {
		t.Fatalf("second charge: %v", err)
	}
	if n := l.scopes["east-ledger"].held.Load(); n != 1 {
		t.Fatalf("the second charge changed the scope's count to %d", n)
	}
	p.release()
	assertLimitNothingHeld(t, l)
	// the zero pass, a gateway with no limits, admits and holds nothing
	var zero limitPass
	zero.leaveBefore()
	if err := zero.charge(nil, "east-ledger"); err != nil {
		t.Fatal(err)
	}
	zero.release()
}

func TestLimitCallerKeyIsDomainSeparated(t *testing.T) {
	keys := map[limitCallerKey]string{}
	for _, c := range [][3]string{
		{"token", "ab", "c"}, {"token", "a", "bc"}, {"delegated", "ab", "c"}, {"token", "", "abc"}, {"tokena", "b", "c"},
	} {
		k := limitCallerKeyOf(c[0], c[1], c[2])
		if was, ok := keys[k]; ok {
			t.Fatalf("%v and %s share a key", c, was)
		}
		keys[k] = fmt.Sprint(c)
	}
}

func TestLimitConstructorRefusals(t *testing.T) {
	clock := (&fakeLimitClock{}).clock()
	cases := []struct {
		before int
		entry  limitEntry
		want   error
	}{
		{0, limitEntry{scope: limitValues{inFlight: 1}}, errLimitBefore},
		{maxBeforeScope + 1, limitEntry{scope: limitValues{inFlight: 1}}, errLimitBefore},
		{1, limitEntry{}, errLimitEmpty},
		{1, limitEntry{perCaller: &limitValues{}}, errLimitEmpty},
		{1, limitEntry{scope: limitValues{requestsPerMinute: 60}}, errLimitPair},
		{1, limitEntry{scope: limitValues{burst: 6}}, errLimitPair},
		{1, limitEntry{scope: limitValues{requestsPerMinute: maxRequestsPerMinute + 1, burst: 1}}, errLimitRate},
		{1, limitEntry{scope: limitValues{requestsPerMinute: 1, burst: maxLimitBurst + 1}}, errLimitBurst},
		{1, limitEntry{scope: limitValues{inFlight: maxLimitInFlight + 1}}, errLimitInFlight},
		{1, limitEntry{scope: limitValues{inFlight: 2}, perCaller: &limitValues{inFlight: 3}}, errLimitAbove},
		{1, limitEntry{scope: limitValues{requestsPerMinute: 60, burst: 5}, perCaller: &limitValues{requestsPerMinute: 61, burst: 5}}, errLimitAbove},
	}
	for i, c := range cases {
		if _, err := newRequestLimiter(clock, c.before, map[string]limitEntry{"east-ledger": c.entry}); err != c.want {
			t.Fatalf("case %d: %v, want %v", i, err, c.want)
		}
	}
	// a perCaller value under an unlimited scope member is allowed
	mustLimiter(t, clock, 1, map[string]limitEntry{"east-ledger": {scope: limitValues{inFlight: 2}, perCaller: &limitValues{requestsPerMinute: 60, burst: 5}}})
}

func TestLimitNilLimiterLimitsNothing(t *testing.T) {
	var l *requestLimiter
	p, r := l.enter()
	wantLimitAdmitted(t, r)
	wantLimitAdmitted(t, chargeOne(p, "east-ledger", nil))
	p.release()
	l.noteUnauthenticated()
	if l.unauthenticatedRefusals() != 0 {
		t.Fatal("a nil limiter counted a refusal")
	}
}
