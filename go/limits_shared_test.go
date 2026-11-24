package main

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSharedRates answers every lease in full, at once until block is set,
// and from then on only once block is closed; after delay where one is
// set; and with leaseErr, or liveErr for a count, where one is set.
type fakeSharedRates struct {
	live              int
	leases            atomic.Int64
	counts            atomic.Int64
	mu                sync.Mutex
	block             chan struct{}
	delay             time.Duration
	leaseErr, liveErr error
}

func (f *fakeSharedRates) set(fn func(*fakeSharedRates)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeSharedRates) liveInstances() (int, error) {
	f.counts.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.live, f.liveErr
}
func (f *fakeSharedRates) makeRow(string) error { return nil }
func (f *fakeSharedRates) close()               {}
func (f *fakeSharedRates) lease(_ string, want, _, _ int64) (sharedLease, error) {
	f.leases.Add(1)
	f.mu.Lock()
	block, delay, err := f.block, f.delay, f.leaseErr
	f.mu.Unlock()
	if block != nil {
		<-block
	}
	time.Sleep(delay)
	if err != nil {
		return sharedLease{}, err
	}
	return sharedLease{took: want}, nil
}

// sharedPosture is the request-limits posture line's reason for entries,
// with l's live state.
func sharedPosture(l *requestLimiter, entries map[string]limitEntry) string {
	cfg := &limitsConfig{beforeScope: 64, shared: true, scopes: entries}
	sources := map[string]sourceSpec{}
	for scope := range entries {
		sources[scope] = sourceSpec{scope: scope}
	}
	return requestLimitsLines(postureInput{limits: cfg, sources: sources, callerScopes: "checked", sharedLimits: l.sharedState()})[0].reason
}

// chargeMany charges n requests of scope, and answers how many were
// admitted.
func chargeMany(l *requestLimiter, scope string, n int) int {
	admitted := 0
	for range n {
		if chargeOnce(l, scope) == nil {
			admitted++
		}
	}
	return admitted
}

// sharedLimiter is a limiter of the entries given whose count is shared.
func sharedLimiter(t *testing.T, clock limitClock, entries map[string]limitEntry) *requestLimiter {
	t.Helper()
	l := mustLimiter(t, clock, 64, entries)
	l.shared = newSharedCount(l, entries)
	t.Cleanup(l.stopShared)
	return l
}

// chargeOnce charges one request to scope, released at once where it is
// admitted.
func chargeOnce(l *requestLimiter, scope string) error {
	p, _ := l.enter()
	defer p.release()
	return p.charge(nil, scope)
}

// The batch is the requests of 100 ms of the rate, rounded up, from 1 to
// 64 and at most the burst; the values split by N are each rounded up.
func TestASharedScopesBatchFollowsItsRate(t *testing.T) {
	for _, tc := range []struct {
		rpm, burst int
		want       int64
	}{{1, 1, 1}, {600, 10, 1}, {601, 10, 2}, {6000, 40, 10}, {6000, 4, 4}, {600000, 10000, 64}} {
		if got := sharedBatchOf(limitValues{requestsPerMinute: tc.rpm, burst: tc.burst}); got != tc.want {
			t.Errorf("rpm %d burst %d: batch %d, want %d", tc.rpm, tc.burst, got, tc.want)
		}
	}
	if got := splitValues(limitValues{requestsPerMinute: 601, burst: 5, inFlight: 5}, 2); got != (limitValues{301, 3, 3}) {
		t.Fatalf("split by 2: %+v", got)
	}
	if got := splitValues(limitValues{inFlight: 5}, 0); got != (limitValues{inFlight: 5}) {
		t.Fatalf("split by none: %+v", got)
	}
}

// A request of a shared scope is admitted from the batch this instance
// leased and sends no statement: with every refill held where it is, the
// batch's requests are admitted at once, and the next is refused
// scope-rate, at once, from the batch alone.
func TestASharedScopeAdmitsFromItsBatchWithNoRoundTrip(t *testing.T) {
	clock := &fakeLimitClock{}
	l := sharedLimiter(t, clock.clock(), map[string]limitEntry{"scope-a": rateOf(6000, 40)})
	rates := &fakeSharedRates{live: 1}
	if line := l.shareOn(rates, 1); !strings.Contains(line, "counted together by the 1 live instances") {
		t.Fatalf("start line: %s", line)
	}
	if got := l.scopes["scope-a"].shared.tokens.Load(); got != 10 {
		t.Fatalf("the first batch holds %d, want 10", got)
	}
	release := make(chan struct{})
	rates.mu.Lock()
	rates.block = release
	rates.mu.Unlock()
	defer close(release)
	done := make(chan []error, 1)
	go func() {
		var errs []error
		for range 11 {
			errs = append(errs, chargeOnce(l, "scope-a"))
		}
		done <- errs
	}()
	select {
	case errs := <-done:
		for i, err := range errs[:10] {
			if err != nil {
				t.Fatalf("request %d of the batch: %v", i, err)
			}
		}
		var refused *limitRefusal
		if !errors.As(errs[10], &refused) || refused.limit != limitScopeRate {
			t.Fatalf("the request past the batch: %v", errs[10])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("admitting the batch's requests waited for a refill: a request reached the database")
	}
}

// limits.shared is a version-51 member, and, set true, holds only on
// PostgreSQL served by several instances; each refusal names it. false is
// as the member left out, and so is a configuration without it.
func TestLimitsSharedIsRefusedByNameBelow51OnTheFilesystemAndWithOneInstance(t *testing.T) {
	byFile := `"connection":{"file":"` + abs(t, t.TempDir(), "connection") + `"}`
	several := `{"kind":"postgresql",` + byFile + `,"instances":"several"}`
	at := func(version, storage, limits string) string {
		return strings.Replace(storageConfig(t, storage, ``, ``), `"engineVersion":"24"`, `"engineVersion":"`+version+`","limits":`+limits, 1)
	}
	shared := `{"shared":true,"default":{"requestsPerMinute":60,"burst":6,"inFlight":5}}`
	for _, tc := range []struct{ name, text, want string }{
		{"below 51", at("50", several, shared), "engine configuration: limits.shared is a version-51 member; engineVersion 50 has no limits.shared"},
		{"false below 51", at("50", several, `{"shared":false}`), "engine configuration: limits.shared is a version-51 member; engineVersion 50 has no limits.shared"},
		{"the filesystem", at("51", "", shared), "engine configuration: limits.shared counts the limits together in a PostgreSQL store's database"},
		{"one instance", at("51", `{"kind":"postgresql",`+byFile+`}`, shared), "engine configuration: limits.shared counts the limits together across several instances"},
		{"not a boolean", at("51", several, `{"shared":"yes"}`), "engine configuration: limits.shared is true or false"},
	} {
		if _, err := parseEngineConfig([]byte(tc.text)); err == nil || !strings.HasPrefix(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	cfg, err := parseEngineConfig([]byte(at("51", several, shared)))
	if err != nil || !cfg.limits.shared {
		t.Fatalf("at 51 on several instances: %+v %v", cfg.limits, err)
	}
	for _, text := range []string{at("51", "", `{"shared":false,"default":{"inFlight":5}}`), at("50", "", `{"default":{"inFlight":5}}`)} {
		cfg, err := parseEngineConfig([]byte(text))
		if err != nil || cfg.limits.shared {
			t.Fatalf("shared false or left out: %+v %v", cfg.limits, err)
		}
		l, err := limiterFor(cfg.limits, map[string]sourceSpec{"x": {}})
		if err != nil || l.shared != nil || l.scopes[unscopedMarker].shared != nil || l.sharedState() != nil {
			t.Fatalf("a limiter without limits.shared shares nothing: %v", err)
		}
	}
}

// Without limits.shared, and at engineVersion 50, the start line and the
// posture line are the ones ADR-0057 gives, byte for byte.
func TestLimitsWithoutSharedSayWhatTheySaidAt50(t *testing.T) {
	cfg := &limitsConfig{beforeScope: 64, scopes: map[string]limitEntry{callerScopeA: {scope: limitValues{requestsPerMinute: 60, burst: 6, inFlight: 3}}}}
	sources := map[string]sourceSpec{"a": {scope: callerScopeA}}
	if line := requestLimitsStartLine(cfg, sources); line != "request limits: 1 of 1 scopes are limited, counted by this instance alone" {
		t.Fatalf("start line: %s", line)
	}
	lines := requestLimitsLines(postureInput{limits: cfg, sources: sources, callerScopes: "checked"})
	want := "1 of the 1 scopes this gateway serves have a request rate and an in-flight cap, and callers are held to their scopes; the gateway-wide cap holds 64 requests before their scope; counted by this instance alone; under several instances each one counts its own"
	if len(lines) != 1 || lines[0].state != postureEnforced || lines[0].reason != want {
		t.Fatalf("posture: %+v", lines)
	}
	cfg.shared = true
	shared := requestLimitsLines(postureInput{limits: cfg, sources: sources, callerScopes: "checked", sharedLimits: &sharedState{live: 2, available: true}})
	if len(shared) != 1 || shared[0].state != postureEnforced || !strings.Contains(shared[0].reason, "counted together by the instances of this database") ||
		!strings.Contains(shared[0].reason, "at most cap+N-1") || !strings.HasSuffix(shared[0].reason, "N=2 live instances") {
		t.Fatalf("shared posture: %+v", shared)
	}
}

// A probe whose count of the instances succeeds and whose lease fails
// leaves the instance counting alone, its bucket as it was: over several
// such probes the instance admits no more than its own bucket at
// ceil(limit/N) admits over the span, from the one full bucket of
// ceil(B/N) it was given as it left the shared count, plus the batch it
// held. The leases' writes refused while the reads succeed, as on a
// read-only database, do this.
func TestAFailedProbeGivesTheInstanceNoFreshBucket(t *testing.T) {
	clock := &fakeLimitClock{}
	entries := map[string]limitEntry{"scope-a": rateOf(600, 100)}
	l := sharedLimiter(t, clock.clock(), entries)
	l.shared.probeEvery = 5 * time.Millisecond
	rates := &fakeSharedRates{live: 2}
	if line := l.shareOn(rates, 2); !strings.Contains(line, "counted together by the 2 live instances") {
		t.Fatalf("start line: %s", line)
	}
	rates.set(func(f *fakeSharedRates) { f.leaseErr = errors.New("the lease's write was refused") })
	// the batch, one request, then the refill that fails
	admitted := chargeMany(l, "scope-a", 1)
	if !sharedWaitUntil(2*time.Second, func() bool { return !l.shared.available.Load() }) {
		t.Fatal("the shared count is still available with its lease failing")
	}
	step := 100 * time.Millisecond
	steps := 20
	for range steps {
		probed := rates.counts.Load() + 2
		if !sharedWaitUntil(2*time.Second, func() bool { return rates.counts.Load() >= probed }) {
			t.Fatal("the probe did not run")
		}
		admitted += chargeMany(l, "scope-a", 100)
		clock.advance(step)
	}
	// alone: ceil(600/2) a minute, one each 200 ms, from ceil(100/2) at
	// once; the last charge is (steps-1) steps after the first
	bound := 1 + 50 + int(time.Duration(steps-1)*step/(200*time.Millisecond))
	if admitted > bound {
		t.Fatalf("%d admitted over %d failed probes, above %d: a failed probe refilled the bucket", admitted, steps*2, bound)
	}
	if l.shared.available.Load() || !strings.Contains(sharedPosture(l, entries), "the database failed or did not answer") {
		t.Fatalf("posture after the failed probes: %s", sharedPosture(l, entries))
	}
}

// A count of the instances that fails after the start keeps the last N
// and moves nothing: with the leases succeeding the count stays shared,
// so a count failing beside them never makes the buckets full again.
func TestACountThatFailsBesideLeasesThatSucceedKeepsTheSharedCount(t *testing.T) {
	clock := &fakeLimitClock{}
	entries := map[string]limitEntry{"scope-a": rateOf(600, 100)}
	l := sharedLimiter(t, clock.clock(), entries)
	rates := &fakeSharedRates{live: 2}
	if line := l.shareOn(rates, 2); !strings.Contains(line, "counted together by the 2 live instances") {
		t.Fatalf("start line: %s", line)
	}
	rates.set(func(f *fakeSharedRates) { f.liveErr = errors.New("the count was refused"); f.live = 5 })
	for range 20 {
		l.shared.recount()
		chargeMany(l, "scope-a", 1)
		clock.advance(100 * time.Millisecond)
	}
	if !l.shared.available.Load() || l.shared.live.Load() != 2 {
		t.Fatalf("after failed counts: available %v, N %d; want the shared count kept at N=2", l.shared.available.Load(), l.shared.live.Load())
	}
	if got := sharedPosture(l, entries); !strings.Contains(got, "counted together") {
		t.Fatalf("posture after failed counts: %s", got)
	}
	// a count that answers no live instance is not a count: this one holds
	// its lease
	rates.set(func(f *fakeSharedRates) { f.liveErr = nil; f.live = 0 })
	l.shared.recount()
	if !l.shared.available.Load() || l.shared.live.Load() != 2 {
		t.Fatalf("after a count of none: available %v, N %d; want N=2 kept", l.shared.available.Load(), l.shared.live.Load())
	}
}

// A count that moves back and forth between shared and alone, once a
// second, admits while alone no more than one bucket and the rate alone
// over the whole time: each move carries the bucket over, so the burst is
// given once, not once per move.
func TestAnInstanceMovingBackAndForthGetsOneBucketNotOnePerMove(t *testing.T) {
	clock := &fakeLimitClock{}
	entries := map[string]limitEntry{"scope-a": rateOf(600, 100)}
	l := sharedLimiter(t, clock.clock(), entries)
	l.shared.probeEvery = 5 * time.Millisecond
	rates := &fakeSharedRates{live: 2}
	if line := l.shareOn(rates, 2); !strings.Contains(line, "counted together by the 2 live instances") {
		t.Fatalf("start line: %s", line)
	}
	alone, moves := 0, 20
	for range moves {
		rates.set(func(f *fakeSharedRates) { f.leaseErr = errors.New("the lease's write was refused") })
		if !sharedWaitUntil(2*time.Second, func() bool { chargeOnce(l, "scope-a"); return !l.shared.available.Load() }) {
			t.Fatal("the shared count is still available with its lease failing")
		}
		alone += chargeMany(l, "scope-a", 200)
		rates.set(func(f *fakeSharedRates) { f.leaseErr = nil })
		if !sharedWaitUntil(2*time.Second, func() bool { return l.shared.available.Load() }) {
			t.Fatal("the shared count did not return")
		}
		clock.advance(time.Second)
	}
	// alone: ceil(600/2) a minute, one each 200 ms, from ceil(100/2) once;
	// the last spell alone is (moves-1) seconds after the first
	bound := 50 + int(time.Duration(moves-1)*time.Second/(200*time.Millisecond)) + 1
	if alone > bound {
		t.Fatalf("%d admitted alone over %d moves, above %d: a move made the bucket full", alone, moves, bound)
	}
}

// The start's count of the instances is N from the start: where the
// refill's connection fails at once, the instance counts alone at
// ceil(limit/N) of that N, not of one instance, and says so.
func TestASharedStartThatCannotLeaseSplitsByTheStartsCount(t *testing.T) {
	clock := &fakeLimitClock{}
	entries := map[string]limitEntry{"scope-a": {scope: limitValues{requestsPerMinute: 6000, burst: 10, inFlight: 4}}}
	l := sharedLimiter(t, clock.clock(), entries)
	refused := errors.New("the connection was refused")
	rates := &fakeSharedRates{live: 2, liveErr: refused, leaseErr: refused}
	if line := l.shareOn(rates, 2); !strings.Contains(line, "the shared count is unavailable (the connection was refused)") || !strings.Contains(line, "of 2 instances") {
		t.Fatalf("start line: %s", line)
	}
	if got := sharedPosture(l, entries); !strings.Contains(got, "of N=2,") {
		t.Fatalf("posture: %s", got)
	}
	if got := chargeMany(l, "scope-a", 10); got != 5 {
		t.Fatalf("alone, %d admitted at once of a burst of 10 over 2 instances, want 5", got)
	}
	if got := l.scopes["scope-a"].inFlightCap(); got != 2 {
		t.Fatalf("alone, an in-flight cap of %d of 4 over 2 instances, want 2", got)
	}
}

// One refill serves every scope, so a database that answers each lease
// slowly, though within the bound, leaves a scope with its batch spent
// waiting for the others' leases. Once that wait passes twice the bound,
// the instance counts alone, from its own buckets as they were, and
// /posture says why; probes that still lease slowly give it no fresh
// bucket, and a probe that leases every scope in time returns it.
func TestASlowRefillFallsBackToLimitOverNAndReturns(t *testing.T) {
	clock := &fakeLimitClock{}
	entries := map[string]limitEntry{}
	scopes := []string{"scope-a", "scope-b", "scope-c", "scope-d"}
	for _, scope := range scopes {
		entries[scope] = rateOf(6000, 40)
	}
	l := sharedLimiter(t, clock.clock(), entries)
	// as 1.9 s of a lease is to the 2 s bound
	l.shared.bound = 50 * time.Millisecond
	l.shared.probeEvery = 20 * time.Millisecond
	rates := &fakeSharedRates{live: 2}
	if line := l.shareOn(rates, 2); !strings.Contains(line, "counted together by the 2 live instances") {
		t.Fatalf("start line: %s", line)
	}
	rates.set(func(f *fakeSharedRates) { f.delay = 48 * time.Millisecond })
	fell := sharedWaitUntil(3*time.Second, func() bool {
		for _, scope := range scopes {
			_ = chargeOnce(l, scope)
		}
		return !l.shared.available.Load()
	})
	if !fell {
		t.Fatal("the scopes' refills waited on one another with no fallback")
	}
	if got := sharedPosture(l, entries); !strings.Contains(got, "a scope's refill waited longer than 4s with its batch spent") || !strings.Contains(got, "of N=2,") {
		t.Fatalf("posture after the slow refills: %s", got)
	}
	// alone at ceil(40/2) at once, the clock held: no more than 20 each
	first := map[string]int{}
	for _, scope := range scopes {
		if first[scope] = chargeMany(l, scope, 40); first[scope] > 20 {
			t.Fatalf("%s alone admitted %d at once, above ceil(40/2)", scope, first[scope])
		}
	}
	// slow probes leave it alone and its buckets as they are
	probed := rates.counts.Load() + 3
	if !sharedWaitUntil(3*time.Second, func() bool { return rates.counts.Load() >= probed }) {
		t.Fatal("the probe did not run")
	}
	for _, scope := range scopes {
		if got := chargeMany(l, scope, 40); got != 0 || l.shared.available.Load() {
			t.Fatalf("%s: %d admitted after slow probes, available %v: a slow probe refilled the bucket or returned the count", scope, got, l.shared.available.Load())
		}
	}
	rates.set(func(f *fakeSharedRates) { f.delay = 0 })
	if !sharedWaitUntil(3*time.Second, func() bool { return l.shared.available.Load() }) {
		t.Fatal("the shared count did not return once the leases answered in time")
	}
	if got := sharedPosture(l, entries); strings.Contains(got, "unavailable") {
		t.Fatalf("posture after the return: %s", got)
	}
}

// Before shareOn has split the values by the live instances, a shared
// scope has neither a batch nor a bucket of its own, and admits nothing:
// no request of a shared scope is counted before the start has read N.
func TestASharedScopeAdmitsNothingBeforeTheStartSharesItsCount(t *testing.T) {
	clock := &fakeLimitClock{}
	entries := map[string]limitEntry{"scope-a": rateOf(6000, 40)}
	l := sharedLimiter(t, clock.clock(), entries)
	if l.scopes["scope-a"].shared.alone.Load() != nil || l.shared.available.Load() {
		t.Fatal("a shared scope has a bucket or a count before shareOn")
	}
	var refused *limitRefusal
	if err := chargeOnce(l, "scope-a"); !errors.As(err, &refused) || refused.limit != limitScopeRate {
		t.Fatalf("before shareOn: %v, want a scope-rate refusal", err)
	}
	if line := l.shareOn(&fakeSharedRates{live: 2}, 2); !strings.Contains(line, "counted together by the 2 live instances") {
		t.Fatalf("start line: %s", line)
	}
	if err := chargeOnce(l, "scope-a"); err != nil {
		t.Fatalf("after shareOn: %v", err)
	}
}
