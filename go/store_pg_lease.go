package main

// The start lease (docs/postgresql-store.md, "One instance per database";
// docs/adr/0032-a-configuration-names-its-storage-kind.md): one gateway
// instance serves a PostgreSQL storage kind's database at a time, and the
// database says which. An instance takes the lease's one row at its start,
// where it is not there or has expired, under an identifier it draws; it
// renews the row while it runs and removes it when it stops cleanly. A
// second instance is refused its start, by name, while the row is live; a
// crashed instance's row expires.
//
// The lease's times are the database's clock, read in the statement
// (clock_timestamp()): instances on different hosts agree on no other.
// These statements, and the fence, are the only ones the kind sends that
// read the database's clock (pgwire_test.go). Receipt and seal times stay
// the gateway's (ADR-0031, decision 9).
//
// Every write transaction of an instance that holds the lease first holds
// the row, unexpired and its own, FOR KEY SHARE (pgStartLeaseFence): a
// write that a stopped clock, a pause or a partition delayed past the
// lease's end fails instead of landing beside another instance's. The
// holder is a unique key, so a takeover, which changes it, takes the row
// FOR UPDATE and waits for a write that holds the row to end; a renewal
// changes only the expiry and waits for none of the instance's own writes.

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

// The lease's periods. A lease runs pgStartLeasePeriod from its last
// renewal by the database's clock, and is renewed every
// pgStartLeaseRenewal, each renewal bounded by that interval: two renewals
// in a row may fail and the lease still has a renewal's interval left, in
// which the instance stops serving (keep). An instance that crashed is
// replaced at most pgStartLeasePeriod after its last renewal.
const (
	pgStartLeasePeriod  = 30 * time.Second
	pgStartLeaseRenewal = 10 * time.Second
)

// errStartLeaseHeld is a start refused while another instance's lease is
// live; errStartLeaseLost is a lease an instance no longer holds.
var (
	errStartLeaseHeld = errors.New("start-lease-held")
	errStartLeaseLost = errors.New("start-lease-lost")
)

// The lease's statements. $1 is the holder; $2 the period as an interval.
const (
	pgStartLeaseTake = `INSERT INTO gateway.start_lease AS l (singleton, holder, expires)
		VALUES (true, $1, pg_catalog.clock_timestamp() + $2::interval)
		ON CONFLICT (singleton) DO UPDATE SET holder = excluded.holder, expires = excluded.expires
		WHERE l.expires <= pg_catalog.clock_timestamp()
		RETURNING l.holder`
	pgStartLeaseHolder = `SELECT holder, pg_catalog.ceil(pg_catalog.date_part('epoch', expires - pg_catalog.clock_timestamp()))::int8
		FROM gateway.start_lease`
	pgStartLeaseRenew = `UPDATE gateway.start_lease SET expires = pg_catalog.clock_timestamp() + $2::interval
		WHERE holder = $1 AND expires > pg_catalog.clock_timestamp()
		RETURNING holder`
	pgStartLeaseRelease = `DELETE FROM gateway.start_lease WHERE holder = $1`
	// pgStartLeaseFence is the first statement of a lease holder's write
	// transaction (pgKind.transact).
	pgStartLeaseFence = `SELECT holder FROM gateway.start_lease
		WHERE holder = $1 AND expires > pg_catalog.clock_timestamp()
		FOR KEY SHARE`
)

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

	mu sync.Mutex
	// until is this process's clock's time before which the lease is
	// certainly held: the moment a renewal that succeeded was sent, plus the
	// period. The database's expiry is at least as late.
	until time.Time
}

// takeStartLease takes the lease for holder, or refuses with
// errStartLeaseHeld while another instance's lease is live. It is taken
// before the kind's view writes anything, and from then on every write
// transaction of the kind holds it (fence).
func (k *pgKind) takeStartLease(holder string, period, every time.Duration) (*pgStartLease, error) {
	sent := time.Now()
	var other string
	var left int64
	taken := false
	err := k.transact(pgWriteCommitted, func(tx pgTx) error {
		rows, err := tx.exec(pgStartLeaseTake, holder, pgInterval(period))
		if err != nil {
			return err
		}
		if len(rows.rows) == 1 {
			taken = true
			return nil
		}
		held, err := tx.exec(pgStartLeaseHolder)
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
	if err != nil {
		return nil, err
	}
	if !taken {
		return nil, fmt.Errorf("%w: the database is served by gateway instance %s, whose start lease runs %d s more; one instance serves a database (docs/postgresql-store.md, \"One instance per database\")", errStartLeaseHeld, other, left)
	}
	k.fence = holder
	return &pgStartLease{kind: k, holder: holder, period: period, every: every, until: sent.Add(period)}, nil
}

// renew renews the lease, each renewal bounded by its interval. A lease no
// longer held -- expired, or taken by another instance -- is
// errStartLeaseLost; any other failure is the renewal's.
func (l *pgStartLease) renew() error {
	sent := time.Now()
	view := *l.kind
	view.operation = l.every
	view.fence = ""
	held := false
	err := view.transact(pgWriteCommitted, func(tx pgTx) error {
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
// than one interval of the lease is certainly left: the instance stops
// serving before the database could give the lease to another.
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

// release removes the lease, on a clean stop, so the next instance starts
// at once. A lease already gone is no error.
func (l *pgStartLease) release() error {
	view := *l.kind
	view.operation = l.every
	view.fence = ""
	return view.transact(pgWriteCommitted, func(tx pgTx) error {
		_, err := tx.exec(pgStartLeaseRelease, l.holder)
		return err
	})
}

// holdFence is the fence of a write transaction of a kind that holds the
// lease: the lease's row, unexpired and this instance's, held FOR KEY
// SHARE until the transaction ends.
func (k *pgKind) holdFence(tx pgTx) error {
	if k.fence == "" {
		return nil
	}
	rows, err := tx.exec(pgStartLeaseFence, k.fence)
	if err != nil {
		return err
	}
	if len(rows.rows) != 1 {
		return fmt.Errorf("%w: gateway instance %s no longer holds the start lease; nothing is written", errStartLeaseLost, k.fence)
	}
	return nil
}
