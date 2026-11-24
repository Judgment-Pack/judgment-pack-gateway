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
// and from then on only once block is closed.
type fakeSharedRates struct {
	live   int
	leases atomic.Int64
	mu     sync.Mutex
	block  chan struct{}
}

func (f *fakeSharedRates) liveInstances() (int, error) { return f.live, nil }
func (f *fakeSharedRates) makeRow(string) error        { return nil }
func (f *fakeSharedRates) close()                      {}
func (f *fakeSharedRates) lease(_ string, want, _, _ int64) (sharedLease, error) {
	f.leases.Add(1)
	f.mu.Lock()
	block := f.block
	f.mu.Unlock()
	if block != nil {
		<-block
	}
	return sharedLease{took: want}, nil
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
	if line := l.shareOn(rates); !strings.Contains(line, "counted together by the 1 live instances") {
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
