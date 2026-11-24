package main

// Request limits counted together by the instances serving one PostgreSQL
// database (limits.shared, engineVersion 51; ADR-0061, as the maintainer
// decided it; gateway #593). Without the member each instance counts alone
// (ADR-0057), and nothing here runs.
//
// The rate. Each limited scope's bucket is one row of gateway.limit_rates
// (schema version 11): its theoretical arrival time, on the database's
// clock, the one clock the instances share. An instance leases a batch of
// requests from the row by one statement (sharedRateLease) that moves the
// time on by the batch, as that many requests at once would, and admits
// from what it holds. A request is admitted from the batch the instance
// holds, by an atomic counter and nothing else: no statement, no row lock,
// no wait (sharedScope.take). Once a scope's batch is down to half, the
// request that took it there hands the scope to the refill, which runs
// beside the requests, on a connection of its own, one statement at a
// time, and never waits for a row: the lease holds its row NOWAIT, so a row
// another transaction holds fails its refill at once and the next scope's
// goes on. A scope with nothing left refuses scope-rate, as one bucket does.
//
// In flight and per caller (ADR-0061, E2 and E3). Each instance counts a
// scope's requests in flight, and each caller's rate and requests in
// flight, alone, at ceil(limit/N), N the instances whose row of the start
// lease is live. The start reads the first N on the kind's pool, beside
// the start lease, and fails where it cannot; N is read again every
// sharedInstancesInterval on the refill's connection, never on a request,
// and a count that fails keeps the last N.
//
// The database unreachable (E1). A refill that fails other than by its
// row's lock -- no connection, an error, or no answer within
// sharedRefillBound -- marks the shared count unavailable (a count of the
// instances that fails keeps the last N and moves nothing, so that a count
// failing beside leases that succeed never makes a bucket full again):
// each instance then counts the scope's rate alone too, at ceil(limit/N),
// and /posture says so. So does a scope whose batch is spent and whose
// refill has waited longer than twice sharedRefillBound, as one refill
// serves every scope. The scopes' own buckets carry over from one spell
// alone to the next: no move makes them full. A probe every
// sharedProbeInterval counts the instances and leases each limited scope's
// batch; it returns the instance to the shared count only where every
// lease succeeds, and all within twice sharedRefillBound.
//
// The gateway-wide cap (beforeScope) stays this instance's alone.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// sharedLimitsVersion is the engine configuration version from which
// limits may carry shared (ADR-0061).
const sharedLimitsVersion = "51"

const (
	// sharedBatchWindow and maxSharedBatch are the batch rule: a scope's
	// batch b is the requests of 100 ms of its rate, rounded up, at least
	// one, at most 64, and never more than its burst.
	sharedBatchWindow = 100 * time.Millisecond
	maxSharedBatch    = 64
	// sharedRefillBound bounds one refill, and one count of the
	// instances: the connection, the statements and the commit. A refill
	// that fails or takes longer, other than by its row's lock, is the
	// database unreachable.
	sharedRefillBound = 2 * time.Second
	// sharedProbeInterval is how often a refill is tried while the shared
	// count is unavailable.
	sharedProbeInterval = time.Second
	// sharedInstancesInterval is how often the live instances are counted:
	// the start lease's renewal interval.
	sharedInstancesInterval = pgStartLeaseRenewal
	// sharedBusyRetry is when a refill whose row another transaction held
	// is tried again.
	sharedBusyRetry = 50 * time.Millisecond
	// sharedRoomRetry is the least wait before a refill that found the
	// bucket spent is tried again.
	sharedRoomRetry = 10 * time.Millisecond
)

// sharedEpoch is the origin of sharedSince, the monotonic clock of the
// refill's hand-offs.
var sharedEpoch = time.Now()

// sharedSince is the time since sharedEpoch, at least 1, so 0 is none.
func sharedSince() int64 { return max(1, int64(time.Since(sharedEpoch))) }

// sharedBatchOf is a scope's batch: the requests of sharedBatchWindow at
// requestsPerMinute, rounded up, from 1 to maxSharedBatch, and at most the
// burst, so a batch is taken from a full bucket at once.
func sharedBatchOf(v limitValues) int64 {
	rpm := int64(v.requestsPerMinute)
	window := int64(time.Minute / sharedBatchWindow)
	b := (rpm + window - 1) / window
	return max(1, min(b, maxSharedBatch, int64(v.burst)))
}

// ceilDiv is ceil(n/d) for n >= 0 and d >= 1.
func ceilDiv(n, d int) int { return (n + d - 1) / d }

// splitValues are v counted by one of live instances: each member
// ceil(member/live), and a zero member, unlimited, stays zero.
func splitValues(v limitValues, live int) limitValues {
	live = max(1, live)
	return limitValues{requestsPerMinute: ceilDiv(v.requestsPerMinute, live), burst: ceilDiv(v.burst, live), inFlight: ceilDiv(v.inFlight, live)}
}

// sharedLease is what one lease answers: the requests it took, and the
// microseconds by which the bucket's time stood ahead of the database's
// clock before it took them; missing for a scope with no row yet.
type sharedLease struct {
	took, ahead int64
	missing     bool
}

// sharedRates is the database's side of the shared count, used by the
// refill's goroutine alone once it runs (and by the start before then).
type sharedRates interface {
	// liveInstances counts the rows of the start lease that are live.
	liveInstances() (int, error)
	// makeRow makes the row of a scope (as pgRowScope writes it) where it
	// is not there, and keeps one that is.
	makeRow(row string) error
	// lease takes up to want requests from the scope's row, each interval
	// microseconds apart, from a bucket of room microseconds.
	lease(row string, want, interval, room int64) (sharedLease, error)
	close()
}

// sharedCount is the limiter's link to the count the instances share: the
// live instances, whether the database answers, and the refill.
type sharedCount struct {
	live      atomic.Int64
	available atomic.Bool
	// slow is whether the count is unavailable because a scope's refill
	// waited too long, rather than because the database failed
	slow atomic.Bool
	// bound is sharedRefillBound and probeEvery sharedProbeInterval; a
	// test shortens them
	bound, probeEvery time.Duration
	// due holds each scope whose batch is to be refilled, once: a scope is
	// sent only while its pending flag is down, so it never fills
	due    chan *sharedScope
	scopes []*sharedScope

	// the run, from shareOn to stopShared
	rates  sharedRates
	end    context.CancelFunc
	done   chan struct{}
	failed atomic.Value // string: the last failure, for the start line
	once   sync.Once
}

// sharedScope is one limited scope's part of the shared count.
type sharedScope struct {
	count *sharedCount
	s     *scopeLimiter
	// row is the scope as the row of gateway.limit_rates holds it
	row   string
	scope limitValues
	// perCaller is nil where the entry has none
	perCaller *limitValues
	// batch is b; interval and room are the bucket's interval and its
	// burst's span, in microseconds
	batch, interval, room int64

	// tokens are the requests this instance leased and has not admitted
	tokens atomic.Int64
	// pending is up from a request's hand-off to the refill until the
	// refill is done with the scope
	pending atomic.Bool
	// asked is when (sharedSince) the scope was last handed to the
	// refill and the database has not answered its lease since; 0 for
	// none. A wait for the bucket's room is not counted.
	asked atomic.Int64
	// wait is how long, from the last lease, until the bucket has room
	// again, in nanoseconds: the Retry-After of a refusal
	wait atomic.Int64

	// the values split by the live instances (E1 to E3)
	most       atomic.Int64
	callerMost atomic.Int64
	callerRate atomic.Pointer[gcra]
	alone      atomic.Pointer[gcra]
}

// newSharedCount makes the shared part of l, for the entries given. Its
// values are split by the live instances once shareOn is given their count
// the start read, and the shared count is unavailable until then: before
// it, a scope admits nothing of its rate.
func newSharedCount(l *requestLimiter, entries map[string]limitEntry) *sharedCount {
	c := &sharedCount{bound: sharedRefillBound, probeEvery: sharedProbeInterval}
	for key, e := range entries {
		s := l.scopes[key]
		if s == nil {
			continue
		}
		scope := ""
		if key != unscopedMarker {
			scope = key
		}
		sh := &sharedScope{count: c, s: s, row: pgRowScope(scope), scope: e.scope, perCaller: e.perCaller}
		if g := gcraOf(e.scope); g != nil {
			sh.batch = sharedBatchOf(e.scope)
			sh.interval = (g.interval + int64(time.Microsecond) - 1) / int64(time.Microsecond)
			sh.room = int64(e.scope.burst) * sh.interval
		}
		s.shared = sh
		c.scopes = append(c.scopes, sh)
	}
	c.due = make(chan *sharedScope, len(c.scopes)+1)
	return c
}

// setLive splits every scope's values by live instances.
func (c *sharedCount) setLive(live int) {
	live = max(1, live)
	c.live.Store(int64(live))
	for _, sh := range c.scopes {
		split := splitValues(sh.scope, live)
		sh.most.Store(int64(split.inFlight))
		sh.alone.Store(gcraOf(split))
		if sh.perCaller != nil {
			callers := splitValues(*sh.perCaller, live)
			sh.callerMost.Store(int64(callers.inFlight))
			sh.callerRate.Store(gcraOf(callers))
		}
	}
}

// inFlightCap is the scope's cap on its requests in flight on this
// instance: its own, or, shared, ceil(inFlight/N).
func (s *scopeLimiter) inFlightCap() int64 {
	if s.shared != nil {
		return s.shared.most.Load()
	}
	return s.most
}

// callerCap and callerBucket are a caller's cap and bucket within the
// scope: the scope's perCaller values, or, shared, each ceil(value/N).
func (s *scopeLimiter) callerCap() int64 {
	if s.shared != nil {
		return s.shared.callerMost.Load()
	}
	return s.callerMost
}

func (s *scopeLimiter) callerBucket() *gcra {
	if s.shared != nil {
		return s.shared.callerRate.Load()
	}
	return s.callerRate
}

// take admits one request of the scope's rate at now: from the batch this
// instance leased while the shared count answers, or from the scope's own
// bucket at ceil(limit/N) while it does not. It reads atomics alone and
// sends no statement: a batch at half or less is handed to the refill,
// which never runs on a request. bucket is the bucket it took from, nil
// for a leased request.
func (sh *sharedScope) take(now int64) (taken int64, bucket *gcra, wait time.Duration, ok bool) {
	if !sh.count.available.Load() {
		g := sh.alone.Load()
		if g == nil {
			// not split by the live instances yet: shareOn has not run
			return 0, nil, 0, false
		}
		taken, wait, ok = g.take(&sh.s.tat, now)
		return taken, g, wait, ok
	}
	for {
		n := sh.tokens.Load()
		if n <= 0 {
			sh.due()
			if asked := sh.asked.Load(); asked != 0 && sharedSince()-asked > int64(2*sh.count.bound) {
				// the refill has not answered this scope in time: the
				// instance counts alone, and this request is counted so
				sh.count.fallback(fmt.Sprintf("a refill waited longer than %s with its batch spent", 2*sh.count.bound), true)
				return sh.take(now)
			}
			return 0, nil, time.Duration(sh.wait.Load()), false
		}
		if sh.tokens.CompareAndSwap(n, n-1) {
			if 2*(n-1) <= sh.batch {
				sh.due()
			}
			return 0, nil, 0, true
		}
	}
}

// due hands the scope to the refill, once until the refill is done with
// it; it never waits.
func (sh *sharedScope) due() {
	if sh.pending.CompareAndSwap(false, true) {
		sh.asked.CompareAndSwap(0, sharedSince())
		select {
		case sh.count.due <- sh:
		default:
			sh.asked.Store(0)
			sh.pending.Store(false)
		}
	}
}

// low is whether the scope's batch is at half or less.
func (sh *sharedScope) low() bool { return 2*sh.tokens.Load() <= sh.batch }

// shareOn starts the shared count on rates, with live the instances the
// start counted beside its lease: it splits the values by them, makes each
// limited scope's row, leases each one's first batch, and then refills in
// the background until stopShared. The shared count is available once a
// lease succeeds. Where the database does not answer, the instance starts
// counting alone at ceil(limit/N), and returns to the shared count once a
// probe succeeds. It answers the start's line.
func (l *requestLimiter) shareOn(rates sharedRates, live int) string {
	c := l.shared
	c.rates = rates
	c.setLive(live)
	c.leaseAll(true)
	ctx, end := context.WithCancel(context.Background())
	c.end, c.done = end, make(chan struct{})
	go c.run(ctx)
	if !c.available.Load() {
		reason, _ := c.failed.Load().(string)
		return fmt.Sprintf("request limits: the shared count is unavailable (%s); each instance counts alone at ceil(limit/N) of %d instances until the database answers a refill, tried every %s", reason, c.live.Load(), c.probeEvery)
	}
	return fmt.Sprintf("request limits: counted together by the %d live instances of this database (limits.shared): each scope's rate is leased in batches, and its in-flight cap and per-caller limits are split ceil(limit/N); the gateway-wide cap is this instance's alone", c.live.Load())
}

// leaseAll leases each limited scope's batch up to b, the first failure
// ending it, and makes the shared count available where every lease
// succeeds, all within twice the refill's bound. A scope whose row another
// transaction holds is tried again by the refill and passed over here; at
// least one lease must succeed, except where no scope has a rate, and
// there is nothing to lease. rows makes each scope's row first, as the
// start does.
func (c *sharedCount) leaseAll(rows bool) {
	began := sharedSince()
	rated, leased := 0, 0
	for _, sh := range c.scopes {
		if sh.batch == 0 {
			continue
		}
		rated++
		if rows {
			if err := c.rates.makeRow(sh.row); err != nil {
				c.unreachable(err)
				return
			}
		}
		sh.pending.Store(true)
		switch c.lease(sh) {
		case leaseFailed:
			return
		case leaseTaken:
			leased++
		}
	}
	if rated > 0 && leased == 0 {
		if !c.available.Load() {
			c.failed.Store("every limited scope's row was held by another transaction")
			c.slow.Store(false)
		}
		return
	}
	if took := time.Duration(sharedSince() - began); took > 2*c.bound {
		c.fallback(fmt.Sprintf("the probe's leases took %s, longer than %s", took.Round(time.Millisecond), 2*c.bound), true)
		return
	}
	c.slow.Store(false)
	c.available.Store(true)
}

// stopShared ends the refill and closes its connection; a limiter that
// shares nothing stops nothing.
func (l *requestLimiter) stopShared() {
	if l == nil || l.shared == nil || l.shared.end == nil {
		return
	}
	c := l.shared
	c.once.Do(func() {
		c.end()
		<-c.done
		c.rates.close()
	})
}

// run is the refill's goroutine: the scopes handed to it, the count of the
// instances every sharedInstancesInterval, and, while the database does
// not answer, a refill tried every sharedProbeInterval.
func (c *sharedCount) run(ctx context.Context) {
	defer close(c.done)
	instances := time.NewTicker(sharedInstancesInterval)
	defer instances.Stop()
	probe := time.NewTicker(c.probeEvery)
	defer probe.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case sh := <-c.due:
			if c.available.Load() {
				c.refill(sh)
			} else {
				sh.asked.Store(0)
				sh.pending.Store(false)
			}
		case <-instances.C:
			c.recount()
		case <-probe.C:
			if !c.available.Load() {
				c.probe()
			}
		}
	}
}

// recount counts the live instances again and splits the values by them;
// a count that fails, or counts no live instance (this one holds its
// lease), keeps the last N and moves nothing: whether the database answers
// is for the refills to say.
func (c *sharedCount) recount() {
	if n, err := c.rates.liveInstances(); err == nil && n >= 1 {
		c.setLive(n)
	}
}

// probe tries the database while the shared count is unavailable: the
// instances counted, then a lease of each limited scope's batch. Only
// leases that all succeed, in time, return the instance to the shared
// count; a probe that fails leaves it counting alone, its buckets as they
// are.
func (c *sharedCount) probe() {
	c.recount()
	c.leaseAll(false)
}

// unreachable is the database failed: the shared count unavailable.
func (c *sharedCount) unreachable(err error) { c.fallback(err.Error(), false) }

// fallback marks the shared count unavailable, for why: each scope's rate
// is counted by this instance alone, at ceil(limit/N), from its own bucket
// as the last spell alone left it. That bucket is not touched while the
// count is shared, so it has refilled by the time shared counting has
// lasted the burst's time, and a count that moves back and forth faster
// keeps what it spent: no move makes a bucket full. slow is whether a
// refill took too long, rather than failed. A request that finds a refill
// late calls it as the refill's goroutine does; the swap makes one of
// them the move.
func (c *sharedCount) fallback(why string, slow bool) {
	c.failed.Store(why)
	c.slow.Store(slow)
	c.available.CompareAndSwap(true, false)
}

// refill tops the scope's batch up to b, by one lease, where it is at half
// or less.
func (c *sharedCount) refill(sh *sharedScope) {
	if !sh.low() {
		sh.asked.Store(0)
		c.settle(sh)
		return
	}
	c.lease(sh)
}

// leaseOutcome is what one lease came to.
type leaseOutcome int

const (
	// leaseTaken: the database answered with the requests it had room for
	leaseTaken leaseOutcome = iota
	// leaseBusy: the scope's row was held, or missing and made; tried again
	leaseBusy
	// leaseFailed: the database unreachable
	leaseFailed
)

// lease is one lease topping the scope's batch up to b. A row another
// transaction holds is tried again after sharedBusyRetry; a bucket with
// less room than asked is tried again once it has room; any other failure
// is the database unreachable.
func (c *sharedCount) lease(sh *sharedScope) leaseOutcome {
	want := max(0, sh.batch-sh.tokens.Load())
	got, err := c.rates.lease(sh.row, want, sh.interval, sh.room)
	sh.asked.Store(0)
	switch {
	case pgCode(err) == pgLockNotAvailable:
		c.later(sh, sharedBusyRetry)
		return leaseBusy
	case err != nil:
		c.unreachable(err)
		sh.pending.Store(false)
		return leaseFailed
	case got.missing:
		if err := c.rates.makeRow(sh.row); err != nil {
			c.unreachable(err)
			sh.pending.Store(false)
			return leaseFailed
		}
		c.later(sh, 0)
		return leaseBusy
	}
	sh.tokens.Add(got.took)
	// room for one more once the bucket's time is within the burst
	ahead := got.ahead + got.took*sh.interval - (sh.room - sh.interval)
	sh.wait.Store(max(0, ahead) * int64(time.Microsecond))
	if got.took < want && sh.low() {
		c.later(sh, max(sharedRoomRetry, time.Duration(ahead)*time.Microsecond))
		return leaseTaken
	}
	c.settle(sh)
	return leaseTaken
}

// settle is the refill done with the scope; a request that found it
// pending meanwhile and took the batch to half is handed on again.
func (c *sharedCount) settle(sh *sharedScope) {
	sh.pending.Store(false)
	if sh.low() {
		sh.due()
	}
}

// later hands the scope to the refill again after d, its pending flag kept
// up meanwhile.
func (c *sharedCount) later(sh *sharedScope, d time.Duration) {
	time.AfterFunc(d, func() {
		sh.asked.CompareAndSwap(0, sharedSince())
		select {
		case c.due <- sh:
		default:
			sh.asked.Store(0)
			sh.pending.Store(false)
		}
	})
}

// sharedState is what /posture reads of the shared count: the live
// instances and whether the database answers.
type sharedState struct {
	live      int64
	available bool
	// slow is whether it is unavailable because a refill waited too long
	slow bool
}

func (l *requestLimiter) sharedState() *sharedState {
	if l == nil || l.shared == nil {
		return nil
	}
	c := l.shared
	return &sharedState{live: c.live.Load(), available: c.available.Load(), slow: c.slow.Load()}
}

// The shared count's statements. $1 is the scope's row; the lease's $2 is
// the requests wanted, $3 the bucket's interval and $4 its burst's span,
// in microseconds. The lease holds the row first, NOWAIT, so a row another
// transaction holds refuses it at once (55P03), and reads the database's
// clock once the row is held, as the start lease's renewal does; it takes
// as many of the requests wanted as the bucket has room for, and answers
// them and how far the bucket's time stood ahead of the clock. A scope with
// no row answers no row.
const (
	sharedRateLease = `WITH held AS MATERIALIZED (SELECT scope, tat FROM gateway.limit_rates
			WHERE scope = $1 FOR NO KEY UPDATE NOWAIT),
		n AS MATERIALIZED (SELECT scope, tat, (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000000)::int8 AS now FROM held),
		k AS MATERIALIZED (SELECT scope, now, GREATEST(tat, now) - now AS ahead,
			LEAST($2::int8, ($4::int8 - (GREATEST(tat, now) - now)) / $3::int8) AS took FROM n),
		up AS (UPDATE gateway.limit_rates r SET tat = k.now + k.ahead + k.took * $3::int8
			FROM k WHERE r.scope = k.scope AND k.took >= 1 RETURNING r.scope)
		SELECT GREATEST(k.took, 0), k.ahead, (SELECT pg_catalog.count(*) FROM up)::int8 FROM k`
	sharedRateRow = `INSERT INTO gateway.limit_rates (scope, tat) VALUES ($1, 0) ON CONFLICT (scope) DO NOTHING`
)

// pgSharedRates is sharedRates on the PostgreSQL kind: every statement on
// a connection of its own, never one of the kind's pool, opened again
// within sharedRefillBound where it failed. Its writes are fenced on this
// instance's row of the start lease, as every write of the kind is.
type pgSharedRates struct {
	kind *pgKind
	dsn  pgDSN
	// mu keeps one statement at a time on conn
	mu   sync.Mutex
	conn *pgConn
}

// sharedLiveAtStart is the first N of limits.shared: the live rows of the
// start lease, read on the kind's pool by the start, once it holds its own
// row. A read that fails, or counts no live row, fails the start: N is
// never taken to be 1.
func (k *pgKind) sharedLiveAtStart() (int, error) {
	n := int64(0)
	err := k.ofNoScope().transact(pgRead, func(tx pgTx) error {
		rows, err := tx.exec(pgStartLeaseLiveCount)
		if err != nil {
			return err
		}
		if len(rows.rows) != 1 {
			return errors.New("the live instances did not read")
		}
		n, _ = pgInt8(rows.rows[0][0])
		return nil
	})
	if err == nil && n < 1 {
		err = errors.New("no row of the start lease is live, this instance's among them")
	}
	if err != nil {
		return 0, fmt.Errorf("request limits: limits.shared splits the limits by the live instances, and the start could not count them: %w", err)
	}
	return int(n), nil
}

func newPgSharedRates(kind *pgKind) *pgSharedRates {
	return &pgSharedRates{kind: kind, dsn: kind.pool.dsn}
}

func (p *pgSharedRates) on(row string, mode pgMode, fn func(pgTx) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	deadline := time.Now().Add(sharedRefillBound)
	if p.conn != nil && (p.conn.broken || p.conn.status != 'I') {
		p.conn.close()
		p.conn = nil
	}
	if p.conn == nil {
		c, err := pgConnect(p.dsn, deadline)
		if err != nil {
			return err
		}
		p.conn = c
	}
	view := p.kind.ofRow(row)
	view.operation = sharedRefillBound
	return view.transactOn(p.conn, deadline, mode, fn)
}

func (p *pgSharedRates) liveInstances() (int, error) {
	n := int64(0)
	err := p.on(pgNoScope, pgRead, func(tx pgTx) error {
		rows, err := tx.exec(pgStartLeaseLiveCount)
		if err != nil {
			return err
		}
		if len(rows.rows) != 1 {
			return errors.New("store: the live instances did not read")
		}
		n, _ = pgInt8(rows.rows[0][0])
		return nil
	})
	return int(n), err
}

func (p *pgSharedRates) makeRow(row string) error {
	return p.on(row, pgWriteCommitted, func(tx pgTx) error {
		_, err := tx.exec(sharedRateRow, row)
		return err
	})
}

func (p *pgSharedRates) lease(row string, want, interval, room int64) (sharedLease, error) {
	var got sharedLease
	err := p.on(row, pgWriteCommitted, func(tx pgTx) error {
		rows, err := tx.exec(sharedRateLease, row, want, interval, room)
		if err != nil {
			return err
		}
		if len(rows.rows) == 0 {
			got.missing = true
			return nil
		}
		var ok1, ok2 bool
		got.took, ok1 = pgInt8(rows.rows[0][0])
		got.ahead, ok2 = pgInt8(rows.rows[0][1])
		if !ok1 || !ok2 {
			return errors.New("store: a lease of the shared rate did not read")
		}
		return nil
	})
	return got, err
}

func (p *pgSharedRates) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn != nil {
		p.conn.close()
		p.conn = nil
	}
}
