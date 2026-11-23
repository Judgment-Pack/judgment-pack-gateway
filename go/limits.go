package main

// Per-scope request limits: the limiter alone (ADR-0057, decisions 2 to 4;
// gateway #507). It holds one gateway-wide cap on the requests not yet tied
// to a scope and, for each limited scope, a token bucket (GCRA), a cap on its
// requests in flight, and a table of at most maxLimitedCallers callers, each
// with its own bucket and cap.
//
// A request takes a gateway-wide slot when it arrives, before its token is
// read (enter). It gives that slot back once its token is read (leaveBefore,
// whether the token is accepted or refused) or when it is charged to a scope
// (charge), whichever comes first, and gives back what it still holds when it
// is answered (release, by a deferred call, so a recovered panic releases it
// too). A route that reads no token, /registry among them, holds the slot
// until it is answered; so does a /seal whose scope is not established, which
// takes it again once its body is read (holdBefore).
//
// Nothing here waits: a request over a limit is refused at once. A scope's
// state is its own, its atomics and its own mutex, and the map of scopes is
// fixed when the limiter is made, so it is read with no lock. The mutex
// guards the scope's callers' table alone and is never held across a
// request. The gateway-wide cap is one atomic counter. The limits bound one
// scope's effect on another; they do not remove it, since an admitted
// request still takes the points every scope shares.
//
// The configuration member, the routes that charge a request and the posture
// report are not here.

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// maxLimitedCallers is the most callers one scope's table holds.
	maxLimitedCallers = 4096
	// maxLimitInFlight is the largest inFlight of a scope or a caller.
	maxLimitInFlight = 4096
	// limitSweepInterval is how often, at most, a scope's full callers'
	// table is swept for idle entries. A newcomer refused in between is
	// told Retry-After 1, the interval.
	limitSweepInterval = time.Second
	// maxBeforeScope is the largest gateway-wide cap.
	maxBeforeScope = 65536
	// maxRequestsPerMinute and maxLimitBurst bound a bucket.
	maxRequestsPerMinute = 600000
	maxLimitBurst        = 10000
)

// The limit a refusal names (ADR-0057, decision 3).
const (
	limitScopeRate       = "scope-rate"
	limitScopeInFlight   = "scope-in-flight"
	limitCallerRate      = "caller-rate"
	limitCallerInFlight  = "caller-in-flight"
	limitCallers         = "callers"
	limitGatewayInFlight = "gateway-in-flight"
)

// limitSentence is a refusal's fixed sentence: a constant chosen by the
// limit alone. None names a scope, a caller or a number, and none gives any
// other scope's state.
func limitSentence(limit string) string {
	switch limit {
	case limitScopeRate:
		return "limit: the request rate of this request's scope is reached; send it again after Retry-After"
	case limitScopeInFlight:
		return "limit: this request's scope has as many requests in flight as it is allowed; send it again after Retry-After"
	case limitCallerRate:
		return "limit: this caller's request rate within this request's scope is reached; send it again after Retry-After"
	case limitCallerInFlight:
		return "limit: this caller has as many requests in flight within this request's scope as it is allowed; send it again after Retry-After"
	case limitCallers:
		return "limit: this request's scope holds as many callers as it can count, each with a request in flight or a spent bucket; send it again after Retry-After"
	case limitGatewayInFlight:
		return "limit: the gateway has as many requests in flight that are not yet tied to a scope as it is allowed; send it again after Retry-After"
	}
	return "limit: a request limit is reached; send it again after Retry-After"
}

// limitRefusal is a limiter's refusal: the limit that refused and the
// Retry-After, in whole seconds and at least one, of that limit's own state
// alone -- the caller's own bucket or cap, its scope's, or the gateway-wide
// cap's. A route answers it 429 (ADR-0057, decision 3).
type limitRefusal struct {
	limit      string
	retryAfter int
}

func (r *limitRefusal) Error() string { return limitSentence(r.limit) }

// body is the 429's body; /act adds "refusedAt": "limit".
func (r *limitRefusal) body() map[string]any {
	return map[string]any{"error": r.Error(), "code": "limit_reached", "limit": r.limit}
}

// setRetryAfter writes the refusal's Retry-After, as delta-seconds.
func (r *limitRefusal) setRetryAfter(h http.Header) {
	h.Set("Retry-After", strconv.Itoa(r.retryAfter))
}

// limitFull is a full cap's refusal: a slot frees when any request holding
// one is answered, which the gateway cannot foresee, so 1 is a hint.
func limitFull(limit string) *limitRefusal { return &limitRefusal{limit: limit, retryAfter: 1} }

// limitClock is the limiter's monotonic clock: the time since the limiter's
// start. A wall-clock step never moves it.
type limitClock func() time.Duration

// monotonicLimitClock reads the monotonic clock from now on.
func monotonicLimitClock() limitClock {
	start := time.Now()
	return func() time.Duration { return time.Since(start) }
}

// limitValues are an entry's members; a zero member is unlimited.
type limitValues struct {
	requestsPerMinute int
	burst             int
	inFlight          int
}

// limitEntry is a scope's effective entry: its own values and, where
// perCaller is not nil, each caller's.
type limitEntry struct {
	scope     limitValues
	perCaller *limitValues
}

var (
	errLimitEmpty    = errors.New("limits: an entry gives no limit")
	errLimitPair     = errors.New("limits: requestsPerMinute and burst are given together")
	errLimitRate     = errors.New("limits: requestsPerMinute is an integer from 1 to 600000")
	errLimitBurst    = errors.New("limits: burst is an integer from 1 to 10000")
	errLimitInFlight = errors.New("limits: inFlight is an integer from 1 to 4096")
	errLimitAbove    = errors.New("limits: a perCaller value is above its scope's value for the same member")
	errLimitBefore   = errors.New("limits: beforeScope.inFlight is an integer from 1 to 65536")
)

// check holds v to its ranges, and a caller's values to its scope's.
func (v limitValues) check(scope *limitValues) error {
	switch {
	case (v.requestsPerMinute == 0) != (v.burst == 0):
		return errLimitPair
	case v.requestsPerMinute < 0 || v.requestsPerMinute > maxRequestsPerMinute:
		return errLimitRate
	case v.burst < 0 || v.burst > maxLimitBurst:
		return errLimitBurst
	case v.inFlight < 0 || v.inFlight > maxLimitInFlight:
		return errLimitInFlight
	}
	if scope != nil && (above(v.requestsPerMinute, scope.requestsPerMinute) ||
		above(v.burst, scope.burst) || above(v.inFlight, scope.inFlight)) {
		return errLimitAbove
	}
	return nil
}

// above is a caller's value over its scope's set one.
func above(caller, scope int) bool { return scope > 0 && caller > scope }

// gcra is a bucket's parameters: one request every interval, and burst
// requests at once (tolerance, (burst-1) intervals). Its state is one
// theoretical arrival time, in nanoseconds of the limiter's clock.
type gcra struct {
	interval  int64
	tolerance int64
}

func gcraOf(v limitValues) *gcra {
	if v.requestsPerMinute == 0 {
		return nil
	}
	// rounded up, so the rate is never above the configured one
	rpm := int64(v.requestsPerMinute)
	interval := (int64(time.Minute) + rpm - 1) / rpm
	return &gcra{interval: interval, tolerance: int64(v.burst-1) * interval}
}

// take spends one request at now, and returns the arrival time it set; or
// refuses with the wait until one conforms. A refused take changes nothing.
func (g *gcra) take(tat *atomic.Int64, now int64) (taken int64, wait time.Duration, ok bool) {
	for {
		was := tat.Load()
		base := max(was, now)
		if base-now > g.tolerance {
			return 0, time.Duration(base - g.tolerance - now), false
		}
		if tat.CompareAndSwap(was, base+g.interval) {
			return base + g.interval, 0, true
		}
	}
}

// giveBack returns a request take spent. Where nothing was taken since, the
// state is the one before the take; otherwise one interval is returned.
func (g *gcra) giveBack(tat *atomic.Int64, taken int64) {
	if !tat.CompareAndSwap(taken, taken-g.interval) {
		tat.Add(-g.interval)
	}
}

// takeSlot raises held while it is below most; it never waits.
func takeSlot(held *atomic.Int64, most int64) bool {
	for {
		n := held.Load()
		if n >= most {
			return false
		}
		if held.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

// limitCallerKey is the key of the identity a request is authenticated as.
type limitCallerKey [sha256.Size]byte

// limitCallerKeyOf is a SHA-256 over a domain-separated, length-prefixed
// encoding of the kind ("token" or "delegated"), the issuer and the subject
// (ADR-0057, decision 2).
func limitCallerKeyOf(kind, issuer, subject string) limitCallerKey {
	h := sha256.New()
	h.Write([]byte("judgment-pack gateway request-limit caller v1\x00"))
	for _, part := range [...]string{kind, issuer, subject} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(part)))
		h.Write(n[:])
		h.Write([]byte(part))
	}
	var key limitCallerKey
	h.Sum(key[:0])
	return key
}

// limitedCaller is one caller's state within a scope: its bucket's arrival
// time and its requests in flight. held is raised only under the scope's
// mutex, so a sweep that holds the mutex and reads zero drops an entry no
// request holds.
type limitedCaller struct {
	tat  atomic.Int64
	held atomic.Int64
}

// scopeLimiter is one scope's state. Nothing in it is shared with another
// scope.
type scopeLimiter struct {
	// journal is the scope's refusal journal (ADR-0059), set before the
	// gateway serves; nil for none
	journal *refusalScope
	rate    *gcra
	tat     atomic.Int64
	most    int64
	held    atomic.Int64

	// callers is nil where the entry has no perCaller
	callerRate *gcra
	callerMost int64
	mu         sync.Mutex
	callers    map[limitCallerKey]*limitedCaller
	// nextSweep is when a full table may next be swept, under mu
	nextSweep int64
}

func (s *scopeLimiter) lock()   { s.mu.Lock() }
func (s *scopeLimiter) unlock() { s.mu.Unlock() }

// holdCaller finds or adds the caller's entry and takes the caller's slot,
// under this scope's mutex alone. A new caller that finds the table full
// sweeps the idle entries; if none is idle it is refused, never served
// uncounted.
func (s *scopeLimiter) holdCaller(key limitCallerKey, now int64) (*limitedCaller, *limitRefusal) {
	s.lock()
	defer s.unlock()
	c := s.callers[key]
	if c == nil {
		if len(s.callers) >= maxLimitedCallers && now >= s.nextSweep {
			// at most once per limitSweepInterval: a full table of busy
			// callers costs one walk a second, not one per newcomer
			s.nextSweep = now + int64(limitSweepInterval)
			s.sweep(now)
		}
		if len(s.callers) >= maxLimitedCallers {
			return nil, limitFull(limitCallers)
		}
		c = &limitedCaller{}
		s.callers[key] = c
	}
	if s.callerMost > 0 && c.held.Load() >= s.callerMost {
		return nil, limitFull(limitCallerInFlight)
	}
	c.held.Add(1)
	return c, nil
}

// sweep drops the idle callers: nothing in flight, and a full bucket. A
// fresh entry would be the same, so dropping one loses nothing.
func (s *scopeLimiter) sweep(now int64) {
	for key, c := range s.callers {
		if c.held.Load() == 0 && (s.callerRate == nil || c.tat.Load() <= now) {
			delete(s.callers, key)
		}
	}
}

// requestLimiter is the gateway's limiter: the gateway-wide cap and the
// limited scopes, by scope key (a scope identifier, or unscopedMarker). A nil
// limiter limits nothing.
type requestLimiter struct {
	clock limitClock

	beforeMost      int64
	beforeHeld      atomic.Int64
	unauthenticated atomic.Int64

	// fixed when the limiter is made, and read with no lock
	scopes map[string]*scopeLimiter
}

// newRequestLimiter makes the limiter: beforeScope is the gateway-wide cap,
// and entries the effective entry of each limited scope. A scope with no
// entry is not limited.
func newRequestLimiter(clock limitClock, beforeScope int, entries map[string]limitEntry) (*requestLimiter, error) {
	if beforeScope < 1 || beforeScope > maxBeforeScope {
		return nil, errLimitBefore
	}
	l := &requestLimiter{clock: clock, beforeMost: int64(beforeScope), scopes: make(map[string]*scopeLimiter, len(entries))}
	for key, e := range entries {
		if e.scope == (limitValues{}) && e.perCaller == nil {
			return nil, errLimitEmpty
		}
		if err := e.scope.check(nil); err != nil {
			return nil, err
		}
		s := &scopeLimiter{rate: gcraOf(e.scope), most: int64(e.scope.inFlight)}
		if e.perCaller != nil {
			if *e.perCaller == (limitValues{}) {
				return nil, errLimitEmpty
			}
			if err := e.perCaller.check(&e.scope); err != nil {
				return nil, err
			}
			s.callerRate = gcraOf(*e.perCaller)
			s.callerMost = int64(e.perCaller.inFlight)
			s.callers = make(map[limitCallerKey]*limitedCaller)
		}
		l.scopes[key] = s
	}
	return l, nil
}

// noteUnauthenticated counts a request answered 401, beside
// the gateway-wide cap's own refusals.
func (l *requestLimiter) noteUnauthenticated() {
	if l != nil {
		l.unauthenticated.Add(1)
	}
}

// unauthenticatedRefusals is the count since start of the requests refused
// before their token was accepted: at the gateway-wide cap, or at
// authentication.
func (l *requestLimiter) unauthenticatedRefusals() int64 {
	if l == nil {
		return 0
	}
	return l.unauthenticated.Load()
}

// limitPass is one request's hold on the limiter. Its owner releases it by
// a deferred call, whatever the answer. The zero pass, a request of a
// gateway with no limits, holds nothing and admits every charge.
type limitPass struct {
	l       *requestLimiter
	refused *limitRefusal
	before  bool
	charged bool

	holds []scopeHold
	// who is the caller a charge that took its holds was made as
	who *caller
}

// scopeHold is what a charged request holds of one scope: its slot, its
// caller's slot, and the arrival times its buckets were taken to, so a
// charge of several scopes that one of them refuses gives back whatever the
// others took.
type scopeHold struct {
	s                       *scopeLimiter
	caller                  *limitedCaller
	scopeTaken, callerTaken int64
	scopeRated, callerRated bool
}

// errLimitCharged is a second charge of one request: a fault of the route,
// answered as a refusal and never served uncounted.
var errLimitCharged = errors.New("limits: a request is charged once")

// enter takes a gateway-wide slot for a request that has just arrived,
// before its token is read. Over the cap, the request is refused, and the
// refusal is counted as unauthenticated. The pass is never nil.
func (l *requestLimiter) enter() (*limitPass, *limitRefusal) {
	if l == nil {
		return &limitPass{}, nil
	}
	if !takeSlot(&l.beforeHeld, l.beforeMost) {
		l.unauthenticated.Add(1)
		r := limitFull(limitGatewayInFlight)
		return &limitPass{l: l, refused: r}, r
	}
	return &limitPass{l: l, before: true}, nil
}

// charge ties the request to every scope given (one, for a request of one
// scope), as caller (nil with no identity), at the first step that knows
// them. It gives the gateway-wide slot back, whether the scopes admit or
// refuse. It is all or nothing: the scopes are taken in the order of their
// bytes, and where one refuses, everything the others took is given back
// and that scope's refusal answers, so a request refused is charged to no
// scope. Within each scope the checks run in order -- the callers' table,
// the caller's cap, the scope's cap, the caller's bucket, the scope's
// bucket -- and the first that refuses answers, after everything taken
// before it is given back. The error is a *limitRefusal, or errLimitCharged
// for a request charged a second time; a pass refused at enter stays
// refused.
func (p *limitPass) charge(caller *limitCallerKey, scopes ...string) error {
	if p.refused != nil {
		return p.refused
	}
	if p.l == nil {
		return nil
	}
	if p.charged {
		return errLimitCharged
	}
	p.charged = true
	p.leaveBefore()
	keys := slices.Clone(scopes)
	slices.Sort(keys)
	keys = slices.Compact(keys)
	now := int64(p.l.clock())
	holds := make([]scopeHold, 0, len(keys))
	for _, key := range keys {
		s := p.l.scopes[key]
		if s == nil {
			continue
		}
		h, refused := s.take(caller, now)
		if refused != nil {
			// counted for the scope's tally, after the answer was chosen
			// from the refusing state alone (ADR-0059 §4)
			s.journal.countLimit(refused.limit)
			for i := len(holds) - 1; i >= 0; i-- {
				holds[i].giveBack()
			}
			return refused
		}
		holds = append(holds, h)
	}
	p.holds = holds
	return nil
}

// take is one scope's part of a charge.
func (s *scopeLimiter) take(caller *limitCallerKey, now int64) (scopeHold, *limitRefusal) {
	h := scopeHold{s: s}
	if s.callers != nil {
		if caller == nil {
			// a scope that counts callers cannot count this request
			return h, limitFull(limitCallers)
		}
		var refused *limitRefusal
		if h.caller, refused = s.holdCaller(*caller, now); refused != nil {
			return h, refused
		}
	}
	if s.most > 0 && !takeSlot(&s.held, s.most) {
		dropCaller(h.caller)
		return h, limitFull(limitScopeInFlight)
	}
	if h.caller != nil && s.callerRate != nil {
		taken, wait, ok := s.callerRate.take(&h.caller.tat, now)
		if !ok {
			dropScope(s)
			dropCaller(h.caller)
			return h, &limitRefusal{limit: limitCallerRate, retryAfter: retryAfterOf(wait)}
		}
		h.callerTaken, h.callerRated = taken, true
	}
	if s.rate != nil {
		taken, wait, ok := s.rate.take(&s.tat, now)
		if !ok {
			if h.callerRated {
				s.callerRate.giveBack(&h.caller.tat, h.callerTaken)
			}
			dropScope(s)
			dropCaller(h.caller)
			return h, &limitRefusal{limit: limitScopeRate, retryAfter: retryAfterOf(wait)}
		}
		h.scopeTaken, h.scopeRated = taken, true
	}
	return h, nil
}

// giveBack undoes a hold another scope's refusal leaves behind: its
// buckets' requests and its slots.
func (h scopeHold) giveBack() {
	if h.callerRated {
		h.s.callerRate.giveBack(&h.caller.tat, h.callerTaken)
	}
	if h.scopeRated {
		h.s.rate.giveBack(&h.s.tat, h.scopeTaken)
	}
	h.release()
}

// release gives back the hold's slots, the scope's and the caller's.
func (h scopeHold) release() {
	dropScope(h.s)
	dropCaller(h.caller)
}

func dropScope(s *scopeLimiter) {
	if s.most > 0 {
		s.held.Add(-1)
	}
}

func dropCaller(c *limitedCaller) {
	if c != nil {
		c.held.Add(-1)
	}
}

// leaveBefore gives the gateway-wide slot back: at the charge, or once the
// request's token is read on a route that charges no scope, so no request
// holds the slot across its body or its run (ADR-0057, decision 2). It may
// be called more than once, and on the zero pass.
func (p *limitPass) leaveBefore() {
	if p.before {
		p.before = false
		p.l.beforeHeld.Add(-1)
	}
}

// holdBefore takes a gateway-wide slot again, once the request's body is
// read, for a request whose scope is not established and that still runs a
// lookup no scope pays for: a /seal from a caller of several scopes, naming
// none, of a session this process does not hold walks the registry and the
// store before it is answered, the work /registry does under the cap. The
// slot is held until the answer is written, and given back with the rest
// (release). Over the cap the request is refused gateway-in-flight, and
// the refusal is not counted as unauthenticated: its token was accepted. A
// pass already charged, or holding the slot, takes nothing; so does the
// zero pass.
func (p *limitPass) holdBefore() *limitRefusal {
	if p.l == nil || p.charged || p.before {
		return nil
	}
	if !takeSlot(&p.l.beforeHeld, p.l.beforeMost) {
		return limitFull(limitGatewayInFlight)
	}
	p.before = true
	return nil
}

// release gives back every slot the pass still holds: the gateway-wide
// slot of a request that never left it, or its scopes' and its callers'.
// It may be called more than once.
func (p *limitPass) release() {
	p.leaveBefore()
	for _, h := range p.holds {
		h.release()
	}
	p.holds = nil
}
