package main

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// cutProxy forwards connections to the database until it is cut: a cut
// closes every connection it carries and closes each new one at once, as a
// database that stopped answering would, and a mend forwards again. The
// cluster itself is never stopped.
type cutProxy struct {
	ln     net.Listener
	target string
	mu     sync.Mutex
	cut    bool
	conns  []net.Conn
}

func newCutProxy(t *testing.T, target pgDSN) (*cutProxy, pgDSN) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &cutProxy{ln: ln, target: net.JoinHostPort(target.host, target.port)}
	t.Cleanup(func() { ln.Close(); p.setCut(true) })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			if p.cut {
				p.mu.Unlock()
				c.Close()
				continue
			}
			up, err := net.Dial("tcp", p.target)
			if err != nil {
				p.mu.Unlock()
				c.Close()
				continue
			}
			p.conns = append(p.conns, c, up)
			p.mu.Unlock()
			go func() { _, _ = io.Copy(up, c); up.Close() }()
			go func() { _, _ = io.Copy(c, up); c.Close() }()
		}
	}()
	via := target
	via.host, via.port, _ = net.SplitHostPort(ln.Addr().String())
	return p, via
}

func (p *cutProxy) setCut(cut bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cut = cut
	if cut {
		for _, c := range p.conns {
			c.Close()
		}
		p.conns = nil
	}
}

// sharedWaitUntil polls cond every 20 ms for up to d.
func sharedWaitUntil(d time.Duration, cond func() bool) bool {
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if cond() {
			return true
		}
	}
	return cond()
}

// holdRateRow holds a scope's row of gateway.limit_rates FOR UPDATE, as the
// owner, until the returned function ends the transaction.
func holdRateRow(t *testing.T, db *pgTestDB, row string) func() {
	t.Helper()
	c, err := pgConnect(db.migrator, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.script("BEGIN; SET LOCAL ROLE " + db.roles.owner); err != nil {
		t.Fatal(err)
	}
	if _, err := c.exec(`SELECT pg_catalog.set_config('gateway.scope', $1, true)`, row); err != nil {
		t.Fatal(err)
	}
	if rows, err := c.exec(`SELECT tat FROM gateway.limit_rates WHERE scope = $1 FOR UPDATE`, row); err != nil || len(rows.rows) != 1 {
		t.Fatalf("holding the row: %v %v", rows.rows, err)
	}
	return func() { _ = c.script("ROLLBACK"); c.close() }
}

// sharedConfigAt51 is the several-instances configuration at engineVersion
// 51 with limits.
func sharedConfigAt51(t *testing.T, db *pgTestDB, dir, limits string) engineConfig {
	t.Helper()
	path, _ := instancesPgConfig(t, db, dir, "engine.json", false)
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text = bytes.Replace(text, []byte(`{"engineVersion":"26"`), []byte(`{"engineVersion":"51","limits":`+limits), 1)
	cfg, err := parseEngineConfig(text)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// drive charges requests of scope on each limiter at once, every 2 ms for
// span, and answers how many were admitted in all.
func drive(limiters []*requestLimiter, scope string, span time.Duration) int {
	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := 0
	end := time.Now().Add(span)
	for _, l := range limiters {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(end) {
				if chargeOnce(l, scope) == nil {
					mu.Lock()
					admitted++
					mu.Unlock()
				}
				time.Sleep(2 * time.Millisecond)
			}
		}()
	}
	wg.Wait()
	return admitted
}

// Two gateway services on one database, both under limits.shared, driven
// together over a window admit no more than one bucket leased over it plus
// the batches the two held at its start: B + ceil(W/T) + N*b. Left out,
// the same drive admits about twice that, each instance its own bucket.
func TestThePostgresInstancesUnderLimitsSharedHoldOneLimitTogether(t *testing.T) {
	for _, shared := range []bool{true, false} {
		db := newPgTestDB(t)
		db.migrate(t)
		limits := `{"default":{"requestsPerMinute":600,"burst":10}}`
		if shared {
			limits = `{"shared":true,"default":{"requestsPerMinute":600,"burst":10}}`
		}
		cfg := sharedConfigAt51(t, db, tempDirAt(t, 0o700), limits)
		sources := sealOpenPgSources(t)
		var said bytes.Buffer
		a, err := startEngineOnKind(cfg, testSeed, sources, nil, &said)
		if err != nil {
			t.Fatalf("instance a: %v", err)
		}
		b, err := startEngineOnKind(cfg, testSeed, sources, nil, &said)
		if err != nil {
			a.stop(&said)
			t.Fatalf("instance b: %v\n%s", err, said.String())
		}
		if shared {
			// a counts the instances every sharedInstancesInterval; b,
			// started second, counted both at its start
			a.service.limiter.shared.recount()
			if a.service.limiter.shared.live.Load() != 2 || b.service.limiter.shared.live.Load() != 2 {
				t.Fatalf("live instances: %d and %d", a.service.limiter.shared.live.Load(), b.service.limiter.shared.live.Load())
			}
		}
		span := 1500 * time.Millisecond
		admitted := drive([]*requestLimiter{a.service.limiter, b.service.limiter}, "scope-a", span)
		b.stop(&said)
		a.stop(&said)
		// B 10, T 100 ms, b 1, N 2
		bound := 10 + int(span/(100*time.Millisecond)) + 2*1
		t.Logf("shared %v: %d admitted over %s by two instances; the bound is %d", shared, admitted, span, bound)
		switch {
		case shared && admitted > bound:
			t.Fatalf("shared: %d admitted over %s, above the bound %d\n%s", admitted, span, bound, said.String())
		case shared && admitted < bound/2:
			t.Fatalf("shared: %d admitted over %s, far under the bound %d: the refill did not keep up\n%s", admitted, span, bound, said.String())
		case !shared && admitted <= bound+10:
			t.Fatalf("each alone: %d admitted over %s, not about twice the bound %d: the test does not tell a shared count from two", admitted, span, bound)
		}
		if shared && !strings.Contains(said.String(), "start: request limits: counted together by the 2 live instances") {
			t.Fatalf("the start lines:\n%s", said.String())
		}
	}
}

// sharedOnKind is a limiter of entries shared on kind's database, through
// dsn where it is given, its first N counted on kind's pool as the start
// counts it.
func sharedOnKind(t *testing.T, kind *pgKind, via *pgDSN, entries map[string]limitEntry) (*requestLimiter, string) {
	t.Helper()
	l := sharedLimiter(t, monotonicLimitClock(), entries)
	rates := newPgSharedRates(kind)
	if via != nil {
		rates.dsn = *via
	}
	live, err := kind.sharedLiveAtStart()
	if err != nil {
		t.Fatal(err)
	}
	return l, l.shareOn(rates, live)
}

// One scope's row held by another transaction fails that scope's refill at
// once, so it adds no wait to another scope's: the other is refilled
// request by request meanwhile, and the held scope refuses scope-rate once
// its batch is spent, at once, rather than waiting for its row.
func TestAPostgresScopesHeldRowAddsNoWaitToAnotherScope(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	kind, _ := severalKind(t, db, testSeed, pgStartLeasePeriod)
	entries := map[string]limitEntry{"scope-a": rateOf(600, 20), "scope-b": rateOf(600, 20)}
	l, line := sharedOnKind(t, kind, nil, entries)
	if !strings.Contains(line, "counted together") {
		t.Fatalf("start line: %s", line)
	}
	free := holdRateRow(t, db, pgRowScope("scope-a"))
	defer free()
	// scope-a's batch, one, then refusals each at once
	start := time.Now()
	var refusedA *limitRefusal
	if err := chargeOnce(l, "scope-a"); err != nil {
		t.Fatalf("scope-a's batch: %v", err)
	}
	for range 5 {
		if err := chargeOnce(l, "scope-a"); !errors.As(err, &refusedA) || refusedA.limit != limitScopeRate {
			t.Fatalf("scope-a past its batch: %v", err)
		}
	}
	if waited := time.Since(start); waited > 200*time.Millisecond {
		t.Fatalf("scope-a's requests waited %s for its held row", waited)
	}
	// scope-b, a request every 20 ms for a second: each needs a refill,
	// the bucket's burst of 20 admits every one
	admitted := 0
	for range 50 {
		if chargeOnce(l, "scope-b") == nil {
			admitted++
		}
		time.Sleep(20 * time.Millisecond)
	}
	if admitted < 15 {
		t.Fatalf("scope-b admitted %d of 50 while scope-a's row was held: its refills waited for scope-a's", admitted)
	}
}

// The in-flight cap is split by the live instances, ceil(cap/N): with two
// live rows of the start lease a cap of 5 gives 3; once one of them
// expires, the count read again gives 5.
func TestAPostgresInFlightCapIsSplitByTheLiveInstances(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	a, _ := severalKind(t, db, testSeed, pgStartLeasePeriod)
	_, other := severalKind(t, db, testSeed, pgStartLeasePeriod)
	l, _ := sharedOnKind(t, a, nil, map[string]limitEntry{"scope-a": {scope: limitValues{inFlight: 5}}})
	hold := func(n int) (passes []*limitPass, refused error) {
		for range n {
			p, _ := l.enter()
			if err := p.charge(nil, "scope-a"); err != nil {
				p.release()
				return passes, err
			}
			passes = append(passes, p)
		}
		return passes, nil
	}
	held, err := hold(3)
	if err != nil {
		t.Fatalf("three in flight of two instances: %v", err)
	}
	var refused *limitRefusal
	if _, err := hold(1); !errors.As(err, &refused) || refused.limit != limitScopeInFlight {
		t.Fatalf("a fourth in flight of two instances: %v", err)
	}
	if err := other.release(); err != nil {
		t.Fatal(err)
	}
	l.shared.recount()
	more, err := hold(2)
	if err != nil {
		t.Fatalf("five in flight of one instance: %v", err)
	}
	if _, err := hold(1); !errors.As(err, &refused) || refused.limit != limitScopeInFlight {
		t.Fatalf("a sixth in flight of one instance: %v", err)
	}
	for _, p := range append(held, more...) {
		p.release()
	}
}

// The database cut mid-run: the refill fails, and the instance counts
// alone at ceil(limit/N) -- rate, in flight -- and /posture says the shared
// count is unavailable; once the database answers again, a probe returns it
// to the shared count. The cut is a proxy's: the cluster runs on.
func TestAPostgresSharedCountFallsBackToLimitOverNAndReturns(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	a, _ := severalKind(t, db, testSeed, pgStartLeasePeriod)
	severalKind(t, db, testSeed, pgStartLeasePeriod)
	proxy, via := newCutProxy(t, db.runtime)
	entry := limitEntry{scope: limitValues{requestsPerMinute: 6000, burst: 10, inFlight: 4}}
	l, line := sharedOnKind(t, a, &via, map[string]limitEntry{"scope-a": entry})
	if !strings.Contains(line, "counted together by the 2 live instances") {
		t.Fatalf("start line: %s", line)
	}
	cfg := &limitsConfig{beforeScope: 64, shared: true, scopes: map[string]limitEntry{"scope-a": entry}}
	posture := func() string {
		lines := requestLimitsLines(postureInput{limits: cfg, sources: map[string]sourceSpec{"a": {scope: "scope-a"}}, callerScopes: "checked", sharedLimits: l.sharedState()})
		return lines[0].reason
	}
	if strings.Contains(posture(), "unavailable") {
		t.Fatalf("posture before the cut: %s", posture())
	}
	proxy.setCut(true)
	// the batch spent hands the scope to a refill, which fails
	for range 12 {
		_ = chargeOnce(l, "scope-a")
	}
	if !sharedWaitUntil(3*time.Second, func() bool { return !l.shared.available.Load() }) {
		t.Fatal("the shared count is still available with the database cut")
	}
	if got := posture(); !strings.Contains(got, "the shared count is unavailable") || !strings.Contains(got, "N=2") {
		t.Fatalf("posture after the cut: %s", got)
	}
	// alone at ceil(10/2) = 5 at once, and ceil(4/2) = 2 in flight
	admitted := 0
	for range 10 {
		if chargeOnce(l, "scope-a") == nil {
			admitted++
		}
	}
	if admitted != 5 {
		t.Fatalf("alone, %d admitted at once of a burst of 10 over 2 instances, want 5", admitted)
	}
	time.Sleep(100 * time.Millisecond)
	var passes []*limitPass
	for range 3 {
		p, _ := l.enter()
		if err := p.charge(nil, "scope-a"); err != nil {
			p.release()
			var refused *limitRefusal
			if !errors.As(err, &refused) || refused.limit != limitScopeInFlight || len(passes) != 2 {
				t.Fatalf("alone, in flight: %d held, then %v", len(passes), err)
			}
			break
		}
		passes = append(passes, p)
	}
	for _, p := range passes {
		p.release()
	}
	proxy.setCut(false)
	if !sharedWaitUntil(5*time.Second, func() bool { return l.shared.available.Load() }) {
		t.Fatal("the shared count did not return once the database answered")
	}
	if got := posture(); strings.Contains(got, "unavailable") {
		t.Fatalf("posture after the return: %s", got)
	}
}

// The refill's own connection refused from the start: the first N is the
// start's count of the live rows of the start lease, read on the kind's
// pool, so the instance counts alone at ceil(limit/N) of those N -- the
// start line, /posture and the split say so -- never as the one instance.
func TestAPostgresSharedStartWithItsConnectionRefusedSplitsByTheLeaseRows(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	a, _ := severalKind(t, db, testSeed, pgStartLeasePeriod)
	severalKind(t, db, testSeed, pgStartLeasePeriod)
	proxy, via := newCutProxy(t, db.runtime)
	proxy.setCut(true)
	entry := limitEntry{scope: limitValues{requestsPerMinute: 6000, burst: 10, inFlight: 4}}
	l, line := sharedOnKind(t, a, &via, map[string]limitEntry{"scope-a": entry})
	if !strings.Contains(line, "the shared count is unavailable") || !strings.Contains(line, "of 2 instances") {
		t.Fatalf("start line: %s", line)
	}
	cfg := &limitsConfig{beforeScope: 64, shared: true, scopes: map[string]limitEntry{"scope-a": entry}}
	lines := requestLimitsLines(postureInput{limits: cfg, sources: map[string]sourceSpec{"a": {scope: "scope-a"}}, callerScopes: "checked", sharedLimits: l.sharedState()})
	if got := lines[0].reason; !strings.Contains(got, "the database failed or did not answer") || !strings.Contains(got, "of N=2,") {
		t.Fatalf("posture: %s", got)
	}
	admitted := 0
	for range 10 {
		if chargeOnce(l, "scope-a") == nil {
			admitted++
		}
	}
	if admitted != 5 {
		t.Fatalf("alone, %d admitted at once of a burst of 10 over 2 instances, want 5", admitted)
	}
}

// A store at schema version 10 migrates to 11 and every version after it, the shared rates' table
// made empty beside its rows; the kind opens on it, its row security held.
func TestAPostgresStoreAtSchemaTenMigratesToTheSharedRates(t *testing.T) {
	db := newPgTestDB(t)
	set := pgShippedMigrations()
	if len(set.versions) < 11 || set.versions[10].name != "0011_limit_rates.sql" {
		t.Fatalf("the shipped schema has %d versions: the test names version 11 as the shared rates'", len(set.versions))
	}
	older := pgMigrationSet{versions: set.versions[:10], grants: pgGrantsOfVersion(t, set.grants, 10)}
	if applied, err := migratePostgres(db.migrator, older, db.roles, time.Minute); err != nil || len(applied) != 10 {
		t.Fatalf("schema version 10: %v %v", applied, err)
	}
	if applied, err := migratePostgres(db.migrator, set, db.roles, time.Minute); err != nil || !slices.Equal(applied, pgShippedFrom(11)) {
		t.Fatalf("10 to 11: %v %v", applied, err)
	}
	kind := db.open(t, nil)
	rates := newPgSharedRates(kind)
	defer rates.close()
	row := pgRowScope("scope-a")
	if err := rates.makeRow(row); err != nil {
		t.Fatal(err)
	}
	got, err := rates.lease(row, 3, 100000, 1000000)
	if err != nil || got.took != 3 || got.missing {
		t.Fatalf("a lease of 3 from a full bucket: %+v %v", got, err)
	}
	// another scope's transaction reads no row of scope-a's
	other := newPgSharedRates(kind)
	defer other.close()
	if got, err := other.lease(pgRowScope("scope-b"), 1, 100000, 1000000); err != nil || !got.missing {
		t.Fatalf("scope-b's lease: %+v %v", got, err)
	}
	if n, _ := pgInt8(pgTestQuery(t, db.runtime, `SELECT count(*)::int8 FROM gateway.limit_rates`).rows[0][0]); n != 0 {
		t.Fatalf("a transaction of no scope set reads %d rows", n)
	}
}
