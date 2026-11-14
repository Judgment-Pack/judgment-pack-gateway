package main

// The start lease (store_pg_lease.go): one instance serves a database.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestLeaseHolder(t *testing.T) string {
	t.Helper()
	holder, err := newStartLeaseHolder()
	if err != nil {
		t.Fatal(err)
	}
	return holder
}

// pgWriteOne is a write of the store contract: a blob of its own.
func pgWriteOne(k *pgKind, text string) error {
	_, err := k.artifacts().putBlob([]byte(text))
	return err
}

func pgBlobHeld(t *testing.T, k *pgKind, text string) bool {
	t.Helper()
	names, err := k.artifacts().listBlobs()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(text))
	return contains(names, "sha256:"+hex.EncodeToString(sum[:]))
}

// A second instance is refused the lease, by name and naming the holder,
// while the first's is live; a released lease is taken at once; and the
// instance that released it writes nothing more.
func TestThePostgresStartLeaseAdmitsOneInstanceAtATime(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	first, second := db.open(t, nil), db.open(t, nil)
	one, two := newTestLeaseHolder(t), newTestLeaseHolder(t)
	lease, err := first.takeStartLease(one, pgStartLeasePeriod, pgStartLeaseRenewal)
	if err != nil {
		t.Fatalf("the first take: %v", err)
	}
	if err := pgWriteOne(first, "held"); err != nil {
		t.Fatalf("a write under the lease: %v", err)
	}
	_, err = second.takeStartLease(two, pgStartLeasePeriod, pgStartLeaseRenewal)
	if !errors.Is(err, errStartLeaseHeld) || !strings.Contains(err.Error(), one) || !strings.Contains(err.Error(), "One instance per database") {
		t.Fatalf("a second take while the first's lease lives: %v", err)
	}
	if err := lease.renew(); err != nil {
		t.Fatalf("a renewal of a live lease: %v", err)
	}
	if err := lease.release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, err := second.takeStartLease(two, pgStartLeasePeriod, pgStartLeaseRenewal); err != nil {
		t.Fatalf("a take once the first released its lease: %v", err)
	}
	if err := pgWriteOne(first, "after"); !errors.Is(err, errStartLeaseLost) {
		t.Fatalf("a write of the instance that released its lease: %v", err)
	}
	if pgBlobHeld(t, second, "after") || !pgBlobHeld(t, second, "held") {
		t.Fatal("the fenced write landed, or the one under the lease did not")
	}
	if err := lease.renew(); !errors.Is(err, errStartLeaseLost) {
		t.Fatalf("a renewal of a lease another instance holds: %v", err)
	}
	if err := pgWriteOne(second, "second"); err != nil {
		t.Fatalf("a write of the instance that holds the lease: %v", err)
	}
}

// A crashed instance's lease -- never renewed nor released -- expires by
// the database's clock, and the next instance takes it; the crashed
// instance's writes and renewals are refused from then on.
func TestThePostgresStartLeaseOfACrashedInstanceExpires(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	first, second := db.open(t, nil), db.open(t, nil)
	one, two := newTestLeaseHolder(t), newTestLeaseHolder(t)
	period := 1500 * time.Millisecond
	lease, err := first.takeStartLease(one, period, 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	taken := time.Now()
	if _, err := second.takeStartLease(two, period, 500*time.Millisecond); !errors.Is(err, errStartLeaseHeld) {
		t.Fatalf("a take while the lease lives: %v", err)
	}
	time.Sleep(time.Until(taken.Add(period + 300*time.Millisecond)))
	if _, err := second.takeStartLease(two, pgStartLeasePeriod, pgStartLeaseRenewal); err != nil {
		t.Fatalf("a take once the lease expired: %v", err)
	}
	if err := lease.renew(); !errors.Is(err, errStartLeaseLost) {
		t.Fatalf("a renewal of an expired lease: %v", err)
	}
	if err := pgWriteOne(first, "late"); !errors.Is(err, errStartLeaseLost) {
		t.Fatalf("a write of the instance whose lease expired: %v", err)
	}
	// an expired lease, not yet taken, refuses its holder's writes too
	third := db.open(t, nil)
	db.asOwner(t, "DELETE FROM gateway.start_lease")
	expired, err := third.takeStartLease(newTestLeaseHolder(t), period, 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(period + 300*time.Millisecond)
	if err := pgWriteOne(third, "expired"); !errors.Is(err, errStartLeaseLost) {
		t.Fatalf("a write after the lease expired: %v", err)
	}
	if err := expired.renew(); !errors.Is(err, errStartLeaseLost) {
		t.Fatalf("a renewal after the lease expired: %v", err)
	}
}

// A source fixed to a scope identifier writes through the kind's view of
// its scope, which holds the start lease's fence as the kind does: once
// another instance took the lease, the scoped acquisition is refused and
// writes nothing, no payload and no receipt, in its scope's rows (#447).
func TestThePostgresScopedAcquisitionIsFencedByTheStartLease(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	first, second := db.open(t, nil), db.open(t, nil)
	lease, err := first.takeStartLease(newTestLeaseHolder(t), pgStartLeasePeriod, pgStartLeaseRenewal)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(envSourceHelper, "1")
	scoped := sourceSpec{argv: []string{os.Args[0]}, env: helperEnv, scope: "scope-a"}
	service, err := newGatewayServiceOn(first, testSeed, "gateway:test", map[string]sourceSpec{"screening-a": scoped})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(service.handler())
	t.Cleanup(server.Close)
	if code, body := post(t, server, "/acquire", `{"session":"held-1","source":"screening-a","scope":"scope-a","arguments":{"q":"acme"}}`); code != http.StatusOK {
		t.Fatalf("a scoped acquisition under the lease: %d %v", code, body)
	}
	if err := lease.release(); err != nil {
		t.Fatal(err)
	}
	pgTakeForTest(t, second, pgStartLeasePeriod, pgStartLeaseRenewal)
	a, err := second.inScope("scope-a")
	if err != nil {
		t.Fatal(err)
	}
	blobsBefore, err := a.artifacts().listBlobs()
	if err != nil || len(blobsBefore) == 0 {
		t.Fatalf("the scope's payloads under the lease: %v %v", blobsBefore, err)
	}
	if code, body := post(t, server, "/acquire", `{"session":"fenced-1","source":"screening-a","scope":"scope-a","arguments":{"q":"other"}}`); code == http.StatusOK {
		t.Fatalf("a scoped acquisition of the instance that lost the lease was taken: %v", body)
	}
	series, err := a.receipts().listSeries()
	if err != nil || contains(series, "fenced-1") || !contains(series, "held-1") {
		t.Fatalf("the scope's sessions once the lease was taken: %v %v", series, err)
	}
	blobsAfter, err := a.artifacts().listBlobs()
	if err != nil || len(blobsAfter) != len(blobsBefore) {
		t.Fatalf("the fenced acquisition left payloads: %v, before %v (%v)", blobsAfter, blobsBefore, err)
	}
}

// A loss the lease's keeper reports stops the service, which exits 1.
func TestALostStartLeaseStopsTheService(t *testing.T) {
	service, err := newGatewayServiceOn(newMemoryKind(nil), testSeed, "gateway:test", map[string]sourceSpec{})
	if err != nil {
		t.Fatal(err)
	}
	keep := func(ctx context.Context, lost func(error)) {
		select {
		case <-time.After(200 * time.Millisecond):
			lost(fmt.Errorf("%w: gone", errStartLeaseLost))
		case <-ctx.Done():
		}
	}
	code := make(chan int, 1)
	go func() { code <- serveEngineService(service, engineConfig{listen: "127.0.0.1:0"}, nil, keep) }()
	select {
	case got := <-code:
		if got != 1 {
			t.Fatalf("a service whose lease was lost exits %d", got)
		}
	case <-time.After(10 * time.Second):
		service.cancel()
		<-code
		t.Fatal("a service whose lease was lost keeps serving")
	}
}

// pgTakeForTest takes k's lease and closes the lease's connection when the
// test ends.
func pgTakeForTest(t *testing.T, k *pgKind, period, every time.Duration) *pgStartLease {
	t.Helper()
	lease, err := k.takeStartLease(newTestLeaseHolder(t), period, every)
	if err != nil {
		t.Fatalf("take: %v", err)
	}
	t.Cleanup(lease.closeOwn)
	return lease
}

// pgHeldWrite is a write of k begun by hand as transactOn begins one, its
// blob inserted and its fence held: a write about to send its commit. The
// test sends the commit, or never does.
func pgHeldWrite(t *testing.T, k *pgKind, text string) *pgConn {
	t.Helper()
	c, err := k.pool.acquire(time.Now().Add(5 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.broken = true; k.pool.release(c) })
	c.conn.SetDeadline(time.Now().Add(30 * time.Second))
	sum := sha256.Sum256([]byte(text))
	if _, err := c.exec(pgWriteCommitted.begin()); err != nil {
		t.Fatal(err)
	}
	if err := k.settings(c); err != nil {
		t.Fatal(err)
	}
	if _, err := c.exec(`INSERT INTO gateway.blobs (scope, name, data) VALUES ($1, $2, pg_catalog.convert_to($3, 'UTF8'))`, k.row, "sha256:"+hex.EncodeToString(sum[:]), text); err != nil {
		t.Fatal(err)
	}
	if err := k.holdFence(pgTx{c}); err != nil {
		t.Fatalf("the fence of a write under a live lease: %v", err)
	}
	return c
}

// pgRawHold is a session of the run-time login that holds the lease's row
// in a transaction it never ends by itself, as lock (FOR KEY SHARE, as a
// write's fence does; FOR UPDATE, as a takeover does) says.
func pgRawHold(t *testing.T, db *pgTestDB, lock string) func() {
	t.Helper()
	c, err := pgConnect(db.runtime, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.exec("BEGIN"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.exec("SELECT singleton FROM gateway.start_lease FOR " + lock); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	end := func() {
		once.Do(func() {
			c.exec("ROLLBACK")
			c.close()
		})
	}
	t.Cleanup(end)
	return end
}

// An instance stopped in a write that passed its fence -- paused,
// partitioned -- holds the lease's row only until the server ends its idle
// session, within the idle bound and before the lease runs out: a second
// instance is admitted from the expiry on, and the stopped instance's
// commit, when it resumes, fails and writes nothing.
func TestThePostgresStoppedHolderIsEndedByTheServerAndReplaced(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	first, second := db.open(t, nil), db.open(t, nil)
	first.idle = time.Second // the fence leaves 2 s
	period := 4 * time.Second
	pgTakeForTest(t, first, period, time.Second)
	taken := time.Now()
	held := pgHeldWrite(t, first, "stopped")
	// the instance stops here: no commit, no renewal
	var admitted time.Time
	for deadline := taken.Add(period + 3*time.Second); admitted.IsZero() && time.Now().Before(deadline); {
		lease, err := second.takeStartLease(newTestLeaseHolder(t), pgStartLeasePeriod, pgStartLeaseRenewal)
		switch {
		case err == nil:
			admitted = time.Now()
			t.Cleanup(lease.closeOwn)
		case errors.Is(err, errStartLeaseHeld):
			time.Sleep(100 * time.Millisecond)
		default:
			t.Fatalf("a take: %v", err)
		}
	}
	if admitted.IsZero() {
		t.Fatalf("a second instance is not admitted %s after a lease of %s whose holder stopped", period+3*time.Second, period)
	}
	if admitted.Before(taken.Add(period - 500*time.Millisecond)) {
		t.Fatalf("a second instance is admitted %s into a lease of %s", admitted.Sub(taken), period)
	}
	if admitted.After(taken.Add(period + time.Second)) {
		t.Fatalf("a second instance is admitted %s after the take, past a lease of %s", admitted.Sub(taken), period)
	}
	if done, err := held.exec("COMMIT"); err == nil && done.tag == "COMMIT" {
		t.Fatal("the stopped instance's write committed once it resumed")
	}
	if pgBlobHeld(t, second, "stopped") {
		t.Fatal("the stopped instance's write landed")
	}
	if err := pgWriteOne(first, "resumed"); !errors.Is(err, errStartLeaseLost) {
		t.Fatalf("a write of the resumed instance: %v", err)
	}
}

// The fence is a write's last statement: a write whose statements outlast
// what the fence leaves of the lease fails and writes nothing, as does one
// begun with less than that left, and one that waited for the row reads
// the clock once it holds it.
func TestThePostgresWriteLeavesTheFenceMarginOrFails(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	kind := db.open(t, nil)
	kind.idle = 500 * time.Millisecond // the fence leaves 1.5 s
	insert := func(tx pgTx, text string) error {
		sum := sha256.Sum256([]byte(text))
		_, err := tx.exec(`INSERT INTO gateway.blobs (scope, name, data) VALUES ($1, $2, pg_catalog.convert_to($3, 'UTF8'))`, kind.row, "sha256:"+hex.EncodeToString(sum[:]), text)
		return err
	}
	take := func(t *testing.T, period time.Duration) {
		lease := pgTakeForTest(t, kind, period, time.Second)
		t.Cleanup(func() { lease.release() })
	}
	t.Run("begun with less left", func(t *testing.T) {
		short := pgTakeForTest(t, kind, 1200*time.Millisecond, time.Second)
		if err := pgWriteOne(kind, "short"); !errors.Is(err, errStartLeaseLost) {
			t.Fatalf("a write with 1.2 s of the lease left: %v", err)
		}
		short.release()
		take(t, 4*time.Second)
		if err := pgWriteOne(kind, "room"); err != nil {
			t.Fatalf("a write with 4 s of the lease left: %v", err)
		}
	})
	t.Run("outlasting", func(t *testing.T) {
		take(t, 3*time.Second)
		taken := time.Now()
		err := kind.transact(pgWriteCommitted, func(tx pgTx) error {
			if err := insert(tx, "outlasted"); err != nil {
				return err
			}
			for time.Since(taken) < 2*time.Second {
				if _, err := tx.exec(`SELECT pg_catalog.pg_sleep(0.2)`); err != nil {
					return err
				}
			}
			return nil
		})
		if !errors.Is(err, errStartLeaseLost) || pgBlobHeld(t, kind, "outlasted") {
			t.Fatalf("a write whose statements outlast the lease's margin: %v", err)
		}
	})
	t.Run("waited for the row", func(t *testing.T) {
		take(t, 3*time.Second)
		taken := time.Now()
		end := pgRawHold(t, db, "UPDATE")
		go func() {
			time.Sleep(time.Until(taken.Add(2 * time.Second)))
			end()
		}()
		err := kind.transact(pgWriteCommitted, func(tx pgTx) error { return insert(tx, "waited") })
		if !errors.Is(err, errStartLeaseLost) || pgBlobHeld(t, kind, "waited") {
			t.Fatalf("a write whose fence waited past the lease's margin: %v", err)
		}
	})
}

// A takeover never waits for the row: while a write of the instance whose
// lease ran out still holds it, the take is refused at once, by name, and
// holds nothing; once the write ended it is admitted. A renewal waits for
// none of the instance's own writes.
func TestThePostgresTakeoverIsRefusedAtOnceWhileAWriteHoldsTheRow(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	first, second := db.open(t, nil), db.open(t, nil)
	period := 1500 * time.Millisecond
	lease := pgTakeForTest(t, first, period, 2*time.Second)
	end := pgRawHold(t, db, "KEY SHARE")
	start := time.Now()
	if err := lease.renew(); err != nil || time.Since(start) > time.Second {
		t.Fatalf("a renewal beside a write that holds the row: %v after %s", err, time.Since(start))
	}
	// the renewal moved the expiry: wait it out from there
	time.Sleep(time.Until(start.Add(period + 300*time.Millisecond)))
	start = time.Now()
	_, err := second.takeStartLease(newTestLeaseHolder(t), pgStartLeasePeriod, pgStartLeaseRenewal)
	if !errors.Is(err, errStartLeaseHeld) || !strings.Contains(err.Error(), "start again") || time.Since(start) > time.Second {
		t.Fatalf("a takeover beside a write that holds the row: %v after %s", err, time.Since(start))
	}
	end()
	pgTakeForTest(t, second, pgStartLeasePeriod, pgStartLeaseRenewal)
	if err := pgWriteOne(first, "late"); !errors.Is(err, errStartLeaseLost) {
		t.Fatalf("a write after the takeover: %v", err)
	}
}

// pgCutConn is a connection whose path goes away once a statement on the
// lease's table was sent: what it sends from then on reaches nothing, and
// its close reaches nothing either, so the server keeps the session.
type pgCutConn struct {
	net.Conn
	mu  sync.Mutex
	cut bool
}

func (c *pgCutConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cut {
		return len(p), nil
	}
	n, err := c.Conn.Write(p)
	if bytes.Contains(p, []byte("gateway.start_lease")) {
		c.cut = true
	}
	return n, err
}

func (c *pgCutConn) Close() error { return nil }

// A second instance refused its start whose path goes away between the
// take's statements leaves nothing the first waits for: the first's writes
// and renewals go on at once, while the server still holds the second's
// session.
func TestThePostgresRefusedStartCutMidwayHoldsNothing(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	first, second := db.open(t, nil), db.open(t, nil)
	second.operation = 3 * time.Second
	lease := pgTakeForTest(t, first, pgStartLeasePeriod, pgStartLeaseRenewal)
	dial := pgDial
	var cut []*pgCutConn
	pgDial = func(address string, deadline time.Time) (net.Conn, error) {
		raw, err := dial(address, deadline)
		if err != nil || len(cut) > 0 {
			return raw, err
		}
		c := &pgCutConn{Conn: raw}
		cut = append(cut, c)
		return c, nil
	}
	refused, finished := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(finished)
		_, err := second.takeStartLease(newTestLeaseHolder(t), pgStartLeasePeriod, pgStartLeaseRenewal)
		refused <- err
	}()
	t.Cleanup(func() {
		<-finished
		pgDial = dial
		for _, c := range cut {
			c.Conn.Close()
		}
	})
	time.Sleep(500 * time.Millisecond) // the take's statement is sent, and its path cut
	start := time.Now()
	if err := pgWriteOne(first, "beside"); err != nil || time.Since(start) > time.Second {
		t.Fatalf("a write beside a refused start cut midway: %v after %s", err, time.Since(start))
	}
	start = time.Now()
	if err := lease.renew(); err != nil || time.Since(start) > time.Second {
		t.Fatalf("a renewal beside a refused start cut midway: %v after %s", err, time.Since(start))
	}
	if err := <-refused; err == nil {
		t.Fatal("a start whose path was cut is admitted")
	}
}

// The lease is renewed on its own connection: a renewal goes on while
// requests hold every pooled connection, and a connection that failed is
// opened again by the next renewal.
func TestThePostgresStartLeaseRenewsOnItsOwnConnection(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	kind, err := openPgKind(pgOptions{dsn: db.runtime, connections: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kind.close)
	lease := pgTakeForTest(t, kind, pgStartLeasePeriod, pgStartLeaseRenewal)
	c, err := kind.pool.acquire(time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err = lease.renew()
	kind.pool.release(c)
	if err != nil || time.Since(start) > time.Second {
		t.Fatalf("a renewal while requests hold every pooled connection: %v after %s", err, time.Since(start))
	}
	lease.own.conn.Close() // the connection fails under the lease
	lease.renew()
	if err := lease.renew(); err != nil {
		t.Fatalf("a renewal after the lease's connection failed: %v", err)
	}
}

// The lease's row runs at most ten minutes from its renewal, and never to
// infinity; the run-time login renews and expires it, and never removes it.
func TestThePostgresStartLeaseRowIsBoundedAndKept(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	kind := db.open(t, nil)
	pgTakeForTest(t, kind, pgStartLeasePeriod, pgStartLeaseRenewal)
	for _, set := range []string{
		"expires = 'infinity'",
		"renewed = 'infinity', expires = 'infinity'",
		"expires = renewed + interval '11 minutes'",
		"expires = renewed - interval '1 second'",
	} {
		if _, err := pgTestQueryErr(db.runtime, "UPDATE gateway.start_lease SET "+set); pgCode(err) != pgCheckViolation {
			t.Errorf("a lease row with %s: %v", set, err)
		}
	}
	if _, err := pgTestQueryErr(db.runtime, "DELETE FROM gateway.start_lease"); pgCode(err) != pgInsufficientPriv {
		t.Errorf("the run-time login's removal of the lease's row: %v", err)
	}
}

// The kind is refused a server that keeps other bounds than it sets.
func TestThePostgresKindHoldsTheServerToItsBounds(t *testing.T) {
	kind, _ := pgTestKind(t, "", nil)
	if err := kind.transact(pgRead, func(tx pgTx) error { return kind.boundsHold(tx) }); err != nil {
		t.Fatalf("the bounds the kind set: %v", err)
	}
	other := *kind
	other.idle = 5 * time.Second
	err := kind.transact(pgRead, func(tx pgTx) error { return other.boundsHold(tx) })
	if err == nil || !strings.Contains(err.Error(), "idle_in_transaction_session_timeout") {
		t.Fatalf("a server that holds another idle bound: %v", err)
	}
}

// keep reports a lease another instance took, and a lease it cannot renew
// before less than one interval of it is certainly left, while the database
// still holds it for this instance: a renewal that fails at once and the
// next, which waits to its bound, end with half an interval left.
func TestThePostgresStartLeaseKeepStopsBeforeTheLeaseIsGone(t *testing.T) {
	t.Run("taken by another", func(t *testing.T) {
		db := newPgTestDB(t)
		db.migrate(t)
		kind := db.open(t, nil)
		lease := pgTakeForTest(t, kind, 5*time.Second, 200*time.Millisecond)
		lost := make(chan error, 1)
		go lease.keep(t.Context(), func(err error) { lost <- err })
		time.Sleep(500 * time.Millisecond)
		select {
		case err := <-lost:
			t.Fatalf("a live lease reported lost: %v", err)
		default:
		}
		pgTestQuery(t, db.runtime, "UPDATE gateway.start_lease SET holder = $1", newTestLeaseHolder(t))
		select {
		case err := <-lost:
			if !errors.Is(err, errStartLeaseLost) {
				t.Fatalf("the loss: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("a lease another instance took is not reported")
		}
	})
	// the production ratio: a period of three intervals
	period, every := 3*time.Second, time.Second
	t.Run("not renewed at once", func(t *testing.T) {
		db := newPgTestDB(t)
		db.migrate(t)
		kind := db.open(t, nil)
		lease := pgTakeForTest(t, kind, period, every)
		// every renewal fails at once, as a database refusing it would,
		// while the row is still this instance's
		db.asOwner(t, "REVOKE UPDATE ON gateway.start_lease FROM "+db.roles.runtime)
		lost := make(chan error, 1)
		go lease.keep(t.Context(), func(err error) { lost <- err })
		select {
		case err := <-lost:
			at, until := time.Now(), lease.heldUntil()
			if !errors.Is(err, errStartLeaseLost) || !strings.Contains(err.Error(), "could not be renewed") {
				t.Fatalf("the loss: %v", err)
			}
			if at.Before(until.Add(-every)) || !at.Before(until.Add(-every+300*time.Millisecond)) {
				t.Fatalf("the loss is reported %s before the lease's end; the second renewal that failed is sent one interval before it", until.Sub(at))
			}
		case <-time.After(period + 2*time.Second):
			t.Fatal("a lease that cannot be renewed is not reported")
		}
	})
	t.Run("not renewed", func(t *testing.T) {
		db := newPgTestDB(t)
		db.migrate(t)
		kind := db.open(t, nil)
		lease := pgTakeForTest(t, kind, period, every)
		taken := time.Now()
		// the first renewal fails at once, as a database refusing it would,
		// while the row is still this instance's
		db.asOwner(t, "REVOKE UPDATE ON gateway.start_lease FROM "+db.roles.runtime)
		lost := make(chan error, 1)
		go lease.keep(t.Context(), func(err error) { lost <- err })
		time.Sleep(time.Until(taken.Add(every + every/2)))
		// the second waits for the row to its bound
		db.asOwner(t, "GRANT UPDATE ON gateway.start_lease TO "+db.roles.runtime)
		pgRawHold(t, db, "UPDATE")
		select {
		case err := <-lost:
			at, until := time.Now(), lease.heldUntil()
			if !errors.Is(err, errStartLeaseLost) || !strings.Contains(err.Error(), "could not be renewed") {
				t.Fatalf("the loss: %v", err)
			}
			if at.Before(until.Add(-every)) {
				t.Fatalf("the loss is reported %s before the lease's end, while more than one interval of it is left", until.Sub(at))
			}
			if !at.Before(until.Add(-every/2 + 300*time.Millisecond)) {
				t.Fatalf("the loss is reported %s before the lease's end; a renewal bounded by half an interval leaves %s", until.Sub(at), every/2)
			}
		case <-time.After(period + 2*time.Second):
			t.Fatal("a lease that cannot be renewed is not reported")
		}
	})
}

// pgEngineStart is serve --config's configuration on the PostgreSQL kind,
// the run-time login's connection string in a file.
func pgEngineStart(t *testing.T, db *pgTestDB) engineConfig {
	t.Helper()
	dir := tempDirAt(t, 0o700)
	connection := filepath.Join(dir, "connection")
	if err := os.WriteFile(connection, []byte(pgTestURL(db.runtime)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	records := filepath.Join(dir, "decisions")
	if err := os.Mkdir(records, 0o700); err != nil {
		t.Fatal(err)
	}
	text := `{"engineVersion":"24","authority":"gateway:test","seed":"` + abs(t, dir, "gateway.seed") + `","storage":{"kind":"postgresql","connection":{"file":"` + abs(t, connection) + `"},"connections":2},` +
		`"decisionRecords":"` + abs(t, records) + `","listen":"127.0.0.1:8787","catalog":"` + abs(t, dir, "catalog") + `","platforms":{}}`
	cfg, err := parseEngineConfig([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// serve --config's start on the PostgreSQL kind is refused, by name, while
// another instance serves the database, and is admitted once that instance
// stopped cleanly; neither names the connection string.
func TestThePostgresSecondInstanceIsRefusedItsStartUntilTheFirstStops(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	cfg := pgEngineStart(t, db)
	var said bytes.Buffer
	first, err := startEngineOnKind(cfg, testSeed, map[string]sourceSpec{}, nil, &said)
	if err != nil {
		t.Fatalf("the first start: %v", err)
	}
	if !strings.Contains(said.String(), "holds the start lease, which runs 30s from each renewal by the database's clock and is renewed every 10s") {
		t.Fatalf("the start names no lease: %s", said.String())
	}
	if _, err := startEngineOnKind(cfg, testSeed, map[string]sourceSpec{}, nil, &said); !errors.Is(err, errStartLeaseHeld) {
		first.stop(&said)
		t.Fatalf("a second start while the first serves: %v", err)
	} else {
		said.WriteString(err.Error())
	}
	first.stop(&said)
	again, err := startEngineOnKind(cfg, testSeed, map[string]sourceSpec{}, nil, &said)
	if err != nil {
		t.Fatalf("a start once the first stopped: %v", err)
	}
	again.stop(&said)
	if strings.Contains(said.String(), db.runtime.password) || strings.Contains(said.String(), hex.EncodeToString(testSeed)) {
		t.Fatalf("the start names a secret: %s", said.String())
	}
	if rows := pgTestQuery(t, db.runtime, "SELECT holder FROM gateway.start_lease WHERE expires > renewed"); len(rows.rows) != 0 {
		t.Fatal("a clean stop left its lease live")
	}
}
