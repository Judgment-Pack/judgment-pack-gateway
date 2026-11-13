package main

// The start lease (docs/postgresql-store.md, "One instance per database";
// docs/adr/0032-a-configuration-names-its-storage-kind.md): one gateway
// instance serves a PostgreSQL storage kind's database at a time, and the
// database says which. An instance takes the lease's one row at its start,
// where it is not there or has expired, under an identifier it draws; it
// renews the row while it runs and expires it when it stops cleanly. A
// second instance is refused its start, by name, while the row is live; a
// crashed instance's row expires.
//
// The lease's times are the database's clock, read in the statement
// (clock_timestamp()): instances on different hosts agree on no other.
// These statements, and the fence, are the only ones the kind sends that
// read the database's clock (pgwire_test.go). Receipt and seal times stay
// the gateway's (ADR-0031, decision 9).
//
// The fence. Every write transaction of an instance that holds the lease
// holds the row, as its last statement before its commit, FOR KEY SHARE,
// and only while the row is its own with more than the fence's margin
// (the idle bound and a second) left by the clock read once the row is
// held (pgStartLeaseFence). The server ends a session idle within a
// transaction for the idle bound (pgIdleInTransaction), so the commit is
// sent before the lease runs out or the transaction is gone; and the row
// stays held until the transaction ends. A takeover changes the holder,
// a key, so it would wait for that hold: it takes the row NOWAIT instead
// and is refused at once while a write holds it. So no write of an
// instance commits after another instance took the lease, and a write
// whose statements outlast the lease fails at its fence and writes
// nothing. A renewal changes only the times and waits for none of the
// instance's writes.
//
// The take holds no lock when it is refused: it reads the row first, and
// takes it only where it expired, NOWAIT. A refused start leaves nothing
// the running instance waits for, however its connection ends.
//
// The lease is renewed on its own connection, opened at the take and
// opened again within a renewal's bound when it fails, never one of the
// kind's pool: requests that hold every pooled connection delay no
// renewal.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// The lease's periods, from s, when the last renewal that took effect was
// sent (docs/postgresql-store.md, "The timing"):
//
//   - the database expires the lease pgStartLeasePeriod after the renewal's
//     statement, which ran within pgStartLeaseBound of s: at s+30 s to
//     s+35 s;
//   - renewals are sent every pgStartLeaseRenewal, each bounded by
//     pgStartLeaseBound, so the second in a row to fail ends by s+25 s;
//   - an instance whose renewal failed stops serving once less than one
//     renewal interval of the lease is certainly left, at s+20 s to s+25 s
//     (keep), with 5 s of the lease left at least;
//   - from 11 s before the expiry on (s+19 s at the earliest), every write
//     fails at its fence;
//   - a second instance is admitted from the expiry on, or, when a later
//     renewal stopped between its statement and its commit, once the
//     server ended that session, at most pgIdleInTransaction later: by
//     s+45 s. Before then its start is refused by name, and is started
//     again.
const (
	pgStartLeasePeriod  = 30 * time.Second
	pgStartLeaseRenewal = 10 * time.Second
	pgStartLeaseBound   = pgStartLeaseRenewal / 2
)

// errStartLeaseHeld is a start refused while another instance's lease is
// live, or while a write of the instance whose lease ran out still holds
// the row; errStartLeaseLost is a lease an instance no longer holds.
var (
	errStartLeaseHeld = errors.New("start-lease-held")
	errStartLeaseLost = errors.New("start-lease-lost")
)

// The lease's statements. $1 is the holder; $2 the period as an interval.
const (
	// pgStartLeaseHolder reads the row and holds nothing: its holder, the
	// whole seconds it has left, and whether it is live.
	pgStartLeaseHolder = `SELECT l.holder, pg_catalog.ceil(pg_catalog.date_part('epoch', l.expires - n.now))::int8, l.expires > n.now
		FROM gateway.start_lease l, (SELECT pg_catalog.clock_timestamp() AS now) n`
	// pgStartLeaseTakeOver takes an expired row, NOWAIT: a write of the
	// old holder that still holds the row refuses it at once (55P03).
	pgStartLeaseTakeOver = `WITH old AS MATERIALIZED (SELECT singleton FROM gateway.start_lease
			WHERE expires <= pg_catalog.clock_timestamp() FOR UPDATE NOWAIT)
		UPDATE gateway.start_lease l SET holder = $1, renewed = n.now, expires = n.now + $2::interval
		FROM old, (SELECT pg_catalog.clock_timestamp() AS now) n
		WHERE l.singleton = old.singleton
		RETURNING l.holder`
	// pgStartLeaseTakeFirst takes the row where there is none.
	pgStartLeaseTakeFirst = `INSERT INTO gateway.start_lease (singleton, holder, renewed, expires)
		SELECT true, $1, n.now, n.now + $2::interval FROM (SELECT pg_catalog.clock_timestamp() AS now) n
		ON CONFLICT (singleton) DO NOTHING
		RETURNING holder`
	pgStartLeaseRenew = `UPDATE gateway.start_lease l SET renewed = n.now, expires = n.now + $2::interval
		FROM (SELECT pg_catalog.clock_timestamp() AS now) n
		WHERE l.holder = $1 AND l.expires > n.now
		RETURNING l.holder`
	// pgStartLeaseRelease expires the row; it is never removed.
	pgStartLeaseRelease = `UPDATE gateway.start_lease l SET renewed = n.now, expires = n.now
		FROM (SELECT pg_catalog.clock_timestamp() AS now) n
		WHERE l.holder = $1`
	// pgStartLeaseFence is the last statement of a lease holder's write
	// transaction (pgKind.transactOn); $2 is the fence's margin. The row
	// is held first and the clock read after: a plain subquery's condition
	// is pushed below the hold and reads the clock before a wait for the
	// row, so the hold is a MATERIALIZED query, which nothing is pushed into.
	pgStartLeaseFence = `WITH held AS MATERIALIZED (SELECT holder, expires FROM gateway.start_lease
			WHERE holder = $1 FOR KEY SHARE)
		SELECT holder FROM held WHERE expires > pg_catalog.clock_timestamp() + $2::interval`
)

// pgLockNotAvailable is the SQLSTATE of a NOWAIT lock refused.
const pgLockNotAvailable = "55P03"

// pgInterval is a period as the statements take it.
func pgInterval(d time.Duration) string {
	return strconv.FormatInt(d.Milliseconds(), 10) + " milliseconds"
}

// newStartLeaseHolder draws an instance's identifier.
func newStartLeaseHolder() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "instance-" + hex.EncodeToString(raw), nil
}

// pgStartLease is a lease an instance holds.
type pgStartLease struct {
	kind   *pgKind
	holder string
	period time.Duration
	every  time.Duration
	// bound bounds one renewal, the release, and opening the lease's
	// connection again: half the renewal interval.
	bound time.Duration

	// own is the lease's connection, nil once it failed until it is opened
	// again; one renewal or release at a time uses it.
	ownMu sync.Mutex
	own   *pgConn

	mu sync.Mutex
	// until is this process's clock's time before which the lease is
	// certainly held: the moment a renewal that succeeded was sent, plus the
	// period. The database's expiry is at least as late.
	until time.Time
}

// fenceMargin is what of the lease a write leaves at its fence: the idle
// bound in which its commit is sent, and a second.
func (k *pgKind) fenceMargin() time.Duration { return k.idle + time.Second }

// takeStartLease takes the lease for holder, or refuses with
// errStartLeaseHeld while another instance's lease is live. It is taken
// before the kind's view writes anything, and from then on every write
// transaction of the kind holds it (fence).
func (k *pgKind) takeStartLease(holder string, period, every time.Duration) (*pgStartLease, error) {
	l := &pgStartLease{kind: k, holder: holder, period: period, every: every, bound: every / 2}
	sent := time.Now()
	var other string
	var left int64
	taken := false
	// refusedAtOnce ends the transaction the refused NOWAIT failed
	refusedAtOnce := errors.New("the row is held")
	err := l.onItsConnection(k.operation, func(tx pgTx) error {
		held, err := tx.exec(pgStartLeaseHolder)
		if err != nil {
			return err
		}
		take := pgStartLeaseTakeFirst
		if len(held.rows) == 1 {
			other = string(held.rows[0][0])
			left, _ = pgInt8(held.rows[0][1])
			if live, _ := pgBool(held.rows[0][2]); live {
				return nil
			}
			take = pgStartLeaseTakeOver
		}
		rows, err := tx.exec(take, holder, pgInterval(period))
		if pgCode(err) == pgLockNotAvailable {
			return refusedAtOnce
		}
		if err != nil {
			return err
		}
		if len(rows.rows) == 1 {
			taken = true
			return nil
		}
		// another instance took it between the read and the take
		held, err = tx.exec(pgStartLeaseHolder)
		if err != nil {
			return err
		}
		if len(held.rows) != 1 {
			return errors.New("store: the start lease neither was taken nor is held")
		}
		other = string(held.rows[0][0])
		left, _ = pgInt8(held.rows[0][1])
		return nil
	})
	if err != nil || !taken {
		l.closeOwn()
	}
	if errors.Is(err, refusedAtOnce) {
		return nil, fmt.Errorf("%w: the start lease of gateway instance %s ran out, and a write of that instance still holds it; the server ends that write within %s; start again (docs/postgresql-store.md, \"One instance per database\")", errStartLeaseHeld, other, pgIdleInTransaction)
	}
	if err != nil {
		return nil, err
	}
	if !taken {
		return nil, fmt.Errorf("%w: the database is served by gateway instance %s, whose start lease runs %d s more; one instance serves a database (docs/postgresql-store.md, \"One instance per database\")", errStartLeaseHeld, other, left)
	}
	l.until = sent.Add(period)
	k.fence = holder
	return l, nil
}

// onItsConnection runs fn in a write transaction on the lease's own
// connection, within bound, opening the connection again where it failed.
// The transaction is the kind's (transactOn), with bound for its
// statements, and holds no fence.
func (l *pgStartLease) onItsConnection(bound time.Duration, fn func(pgTx) error) error {
	l.ownMu.Lock()
	defer l.ownMu.Unlock()
	deadline := time.Now().Add(bound)
	if l.own != nil && (l.own.broken || l.own.status != 'I') {
		l.own.close()
		l.own = nil
	}
	if l.own == nil {
		c, err := pgConnect(l.kind.pool.dsn, deadline)
		if err != nil {
			return err
		}
		l.own = c
	}
	view := *l.kind
	view.operation = bound
	view.fence = ""
	return view.transactOn(l.own, deadline, pgWriteCommitted, fn)
}

func (l *pgStartLease) closeOwn() {
	l.ownMu.Lock()
	defer l.ownMu.Unlock()
	if l.own != nil {
		l.own.close()
		l.own = nil
	}
}

// renew renews the lease, each renewal bounded by pgStartLeaseBound. A
// lease no longer held -- expired, or taken by another instance -- is
// errStartLeaseLost; any other failure is the renewal's.
func (l *pgStartLease) renew() error {
	sent := time.Now()
	held := false
	err := l.onItsConnection(l.bound, func(tx pgTx) error {
		rows, err := tx.exec(pgStartLeaseRenew, l.holder, pgInterval(l.period))
		held = len(rows.rows) == 1
		return err
	})
	if err != nil {
		return err
	}
	if !held {
		return fmt.Errorf("%w: gateway instance %s's start lease expired or another instance holds it", errStartLeaseLost, l.holder)
	}
	l.mu.Lock()
	l.until = sent.Add(l.period)
	l.mu.Unlock()
	return nil
}

func (l *pgStartLease) heldUntil() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.until
}

// keep renews the lease every interval until ctx ends. It calls lost, and
// returns, when the lease is gone, or when a renewal has failed and less
// than one interval of the lease is certainly left: each renewal ends
// within its bound, half an interval, so the instance stops serving with
// half an interval of the lease left at least.
func (l *pgStartLease) keep(ctx context.Context, lost func(error)) {
	ticker := time.NewTicker(l.every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		err := l.renew()
		switch {
		case err == nil:
		case errors.Is(err, errStartLeaseLost):
			lost(err)
			return
		case !time.Now().Before(l.heldUntil().Add(-l.every)):
			lost(fmt.Errorf("%w: gateway instance %s's start lease could not be renewed and runs out within %s: %v", errStartLeaseLost, l.holder, l.every, err))
			return
		}
	}
}

// release expires the lease, on a clean stop, so the next instance starts
// at once, and closes the lease's connection. A lease already gone is no
// error.
func (l *pgStartLease) release() error {
	defer l.closeOwn()
	return l.onItsConnection(l.bound, func(tx pgTx) error {
		_, err := tx.exec(pgStartLeaseRelease, l.holder)
		return err
	})
}

// holdFence is the fence of a write transaction of a kind that holds the
// lease: the lease's row, this instance's with more than the fence's
// margin left, held FOR KEY SHARE until the transaction ends.
func (k *pgKind) holdFence(tx pgTx) error {
	if k.fence == "" {
		return nil
	}
	rows, err := tx.exec(pgStartLeaseFence, k.fence, pgInterval(k.fenceMargin()))
	if err != nil {
		return err
	}
	if len(rows.rows) != 1 {
		return fmt.Errorf("%w: gateway instance %s no longer holds the start lease with %s of it to spare; nothing is written", errStartLeaseLost, k.fence, k.fenceMargin())
	}
	return nil
}
