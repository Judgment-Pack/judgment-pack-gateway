package main

// The start lease (docs/postgresql-store.md, "One instance per database" and
// "Several instances on one database";
// docs/adr/0032-a-configuration-names-its-storage-kind.md;
// docs/adr/0035-several-instances-on-one-postgresql-database.md, option C):
// the database says which gateway instances serve it. Each instance takes a
// row of gateway.start_lease at its start under an identifier it draws --
// the row of an instance whose row has expired, or a new one -- and renews
// it while it runs and expires it when it stops cleanly; a crashed
// instance's row expires. The row records the instance's mode, the key id
// it signs under and the authority it names. In the one-instance mode (the
// default) a start is refused, by name, while any row is live, and while one
// is, an instance in either mode is refused beside it; in the
// several-instances mode (storage.instances "several", engineVersion 26) a
// start is admitted beside live instances of that mode alone, each signing
// under the same key id for the same authority. The takes run one at a time,
// under a transaction advisory lock (pgStartLeaseLock), which gateway store
// remove-scope and gateway store migrate hold for their whole transaction.
//
// The lease's times are the database's clock, read in the statement
// (clock_timestamp()): instances on different hosts agree on no other.
// These statements, and the fence, are the only ones the kind sends that
// read the database's clock (pgwire_test.go). Receipt and seal times stay
// the gateway's (ADR-0031, decision 9).
//
// The fence. Every write transaction of an instance that holds the lease
// holds its row, as its last statement before its commit, FOR KEY SHARE,
// and only while the row is its own with more than the fence's margin
// (the idle bound and a second) left by the clock read once the row is
// held (pgStartLeaseFence). The server ends a session idle within a
// transaction for the idle bound (pgIdleInTransaction), so the commit is
// sent before the lease runs out or the transaction is gone; and the row
// stays held until the transaction ends. A takeover of an expired row
// changes its holder, a key, so it would wait for that hold: it takes the
// row NOWAIT instead (in the one-instance mode, refused at once while a
// write holds it), or SKIP LOCKED (in the several-instances mode, which
// takes another row or a new one). What another instance does with the
// sessions of an instance whose row has expired -- takes up one that holds
// no receipt, seals one after the interruption -- it does once it held that
// row FOR UPDATE (pgStartLeaseSettle), which waits for every write of that
// instance that holds it: so no write of an instance commits after another
// instance acted on its row's expiry. A renewal changes only the times and
// waits for none of the instance's writes; it holds the row before it reads
// the clock, as the fence does, so a renewal that waited for a settle's hold
// past the row's expiry fails, and an expired row never lives again.
//
// The take holds no row when it is refused: it reads the rows first, and
// takes one only where it expired. A refused start leaves nothing the
// running instances wait for, however its connection ends.
//
// The lease is renewed on its own connection, opened at the take and
// opened again within a renewal's bound when it fails, never one of the
// kind's pool: requests that hold every pooled connection delay no
// renewal.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
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
// live in a mode that does not admit it, while a write of an instance whose
// lease ran out still holds its row, or while a removal or a migration holds
// the lease's lock; errStartLeaseLost is a lease an instance no longer
// holds; errInstanceMismatch is a start in the several-instances mode whose
// key id or authority is not that of the instances serving.
var (
	errStartLeaseHeld   = errors.New("start-lease-held")
	errStartLeaseLost   = errors.New("start-lease-lost")
	errInstanceMismatch = errors.New("instance-mismatch")
)

// pgStartLeaseLock is the transaction advisory lock every take of a row of
// the lease holds to its commit, and gateway store remove-scope and gateway
// store migrate hold for their whole transaction: takes run one at a time,
// so two starts never each find the other's row not there yet.
const pgStartLeaseLock = 0x6761746577617973 // "gateways" in ASCII, a constant of this schema

// The lease's statements. $1 is the holder; $2 the period as an interval;
// $3 the mode (several); $4 the key id; $5 the authority.
const (
	// pgStartLeaseRows reads every row and holds nothing: its holder, its
	// mode, key id and authority, the whole seconds it has left, and
	// whether it is live.
	pgStartLeaseRows = `SELECT l.holder, l.several, l.key_id, l.authority,
			pg_catalog.ceil(pg_catalog.date_part('epoch', l.expires - n.now))::int8, l.expires > n.now
		FROM gateway.start_lease l, (SELECT pg_catalog.clock_timestamp() AS now) n ORDER BY l.holder`
	// pgStartLeaseHoldExpired holds every expired row, NOWAIT: a write of an
	// instance whose row ran out that still holds it refuses it at once
	// (55P03). The one-instance mode's take makes it first.
	pgStartLeaseHoldExpired = `SELECT holder FROM gateway.start_lease
		WHERE expires <= pg_catalog.clock_timestamp() FOR UPDATE NOWAIT`
	// pgStartLeaseTakeOver takes one expired row that no write holds.
	pgStartLeaseTakeOver = `WITH old AS MATERIALIZED (SELECT holder FROM gateway.start_lease
			WHERE expires <= pg_catalog.clock_timestamp() ORDER BY holder LIMIT 1 FOR UPDATE SKIP LOCKED)
		UPDATE gateway.start_lease l SET holder = $1, several = $3, key_id = $4, authority = $5,
			renewed = n.now, expires = n.now + $2::interval
		FROM old, (SELECT pg_catalog.clock_timestamp() AS now) n
		WHERE l.holder = old.holder
		RETURNING l.holder`
	// pgStartLeaseTakeNew takes a new row, where no expired one is free.
	pgStartLeaseTakeNew = `INSERT INTO gateway.start_lease (holder, several, key_id, authority, renewed, expires)
		SELECT $1, $3, $4, $5, n.now, n.now + $2::interval FROM (SELECT pg_catalog.clock_timestamp() AS now) n
		RETURNING holder`
	// pgStartLeaseRenew renews the holder's row while it is live. As the
	// fence, it holds the row first and reads the clock after: a renewal
	// that waited for the row -- held by a settle (pgStartLeaseSettle) or a
	// takeover's hold -- past the row's expiry finds it expired, and never
	// brings it back to life. Each hold and the clock are MATERIALIZED
	// queries, so nothing reads the clock before the row is held.
	pgStartLeaseRenew = `WITH held AS MATERIALIZED (SELECT holder, expires FROM gateway.start_lease
			WHERE holder = $1 FOR NO KEY UPDATE),
		n AS MATERIALIZED (SELECT holder, expires, pg_catalog.clock_timestamp() AS now FROM held)
		UPDATE gateway.start_lease l SET renewed = n.now, expires = n.now + $2::interval
		FROM n
		WHERE l.holder = n.holder AND n.expires > n.now
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
	// pgStartLeaseLiveCount counts the live rows, in the form of every
	// schema version that has the table (gateway store migrate reads it
	// before it applies a version).
	pgStartLeaseLiveCount = `SELECT pg_catalog.count(*)::int8 FROM gateway.start_lease
		WHERE expires > pg_catalog.clock_timestamp()`
	// pgSeriesHolder reads, in a transaction of the series' scope ($1), the
	// series $2: the instance that holds it -- its last take-up's, or the
	// series' own holder (NULL for none) -- and that turn; whether it holds a
	// receipt; and whether the holder's row of gateway.start_lease is live.
	pgSeriesHolder = `SELECT h.holder, h.turn,
			EXISTS (SELECT 1 FROM gateway.entries e WHERE e.scope = s.scope AND e.series = s.name),
			EXISTS (SELECT 1 FROM gateway.start_lease l WHERE l.holder = h.holder AND l.expires > pg_catalog.clock_timestamp())
		FROM gateway.series s CROSS JOIN LATERAL (
			SELECT t.holder, t.turn FROM gateway.series_holders t WHERE t.scope = s.scope AND t.series = s.name
			UNION ALL SELECT s.holder, 0::int8
			ORDER BY 2 DESC LIMIT 1) h
		WHERE s.scope = $1 AND s.name = $2`
	// pgSeriesHolders lists, in a transaction of the scope $1, each series'
	// name and whether the instance that holds it is live, as pgSeriesHolder
	// reads one.
	pgSeriesHolders = `SELECT s.name, h.holder,
			EXISTS (SELECT 1 FROM gateway.start_lease l WHERE l.holder = h.holder AND l.expires > pg_catalog.clock_timestamp())
		FROM gateway.series s CROSS JOIN LATERAL (
			SELECT t.holder, t.turn FROM gateway.series_holders t WHERE t.scope = s.scope AND t.series = s.name
			UNION ALL SELECT s.holder, 0::int8
			ORDER BY 2 DESC LIMIT 1) h
		WHERE s.scope = $1 ORDER BY s.name`
	// pgStartLeaseSettle holds the row of an instance that is not live FOR
	// UPDATE, to the transaction's end, waiting for every write of that
	// instance that holds it; a write of it that comes later fails at its
	// fence. A row taken over meanwhile is no longer that instance's, and
	// the statement answers no row.
	pgStartLeaseSettle = `SELECT holder FROM gateway.start_lease WHERE holder = $1 FOR UPDATE`
)

// pgLockNotAvailable is the SQLSTATE of a NOWAIT lock refused, and of a
// lock wait past lock_timeout.
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

// pgInstance is what an instance's row records of it: its mode, the key id
// it signs under and the authority it names.
type pgInstance struct {
	several   bool
	keyID     string
	authority string
}

// instanceFor is the row an instance under spec, signing with seed for
// authority, takes: a seed of another length names no key id.
func instanceFor(spec *storageSpec, seed []byte, authority string) pgInstance {
	if len(seed) != seedBytes {
		return pgInstance{several: spec.several, authority: authority}
	}
	return instanceForKey(spec, ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), authority)
}

// instanceForKey is the row an instance signing under public takes: the
// signer's key, the seed's or a key service's key version's (ADR-0050).
func instanceForKey(spec *storageSpec, public ed25519.PublicKey, authority string) pgInstance {
	return pgInstance{several: spec.several, authority: authority, keyID: keyIDFor(public)}
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

// pgLeaseRow is a row of the lease as pgStartLeaseRows reads it.
type pgLeaseRow struct {
	holder, keyID, authority string
	several, live            bool
	left                     int64
}

// takeStartLease takes a row of the lease for holder, as k.instance, or
// refuses: with errStartLeaseHeld while an instance's row is live in a mode
// that does not admit this one beside it, and with errInstanceMismatch
// where the instances serving sign under another key id or name another
// authority. It is taken before the kind's view writes anything, and from
// then on every write transaction of the kind holds it (fence). The take
// reads the schema's version as well, under the lease's lock: a migration
// made since the kind was opened refuses the start.
func (k *pgKind) takeStartLease(holder string, period, every time.Duration) (*pgStartLease, error) {
	as := k.instance
	if as.keyID == "" || as.authority == "" {
		return nil, errors.New("store: an instance takes the start lease under its key id and authority, and this one names neither")
	}
	l := &pgStartLease{kind: k, holder: holder, period: period, every: every, bound: every / 2}
	sent := time.Now()
	var refusal error
	taken := false
	// expired is each instance whose row ran out, named in the refusal a
	// write of one of them that still holds its row makes
	var expired []string
	// refusedAtOnce ends the transaction the refused NOWAIT failed
	refusedAtOnce := errors.New("the row is held")
	err := l.onItsConnection(k.operation, func(tx pgTx) error {
		if _, err := tx.exec(`SELECT pg_catalog.pg_advisory_xact_lock($1)`, int64(pgStartLeaseLock)); err != nil {
			return err
		}
		if k.schema > 0 {
			version, err := tx.exec(`SELECT pg_catalog.max(version)::int8 FROM gateway.schema_migrations`)
			if err != nil {
				return err
			}
			if v, _ := pgInt8(version.rows[0][0]); v != int64(k.schema) {
				refusal = fmt.Errorf("store: the database's schema is at version %d and this gateway's is %d; it was migrated as this instance started (docs/postgresql-store.md)", v, k.schema)
				return nil
			}
		}
		// a store rotated away from starts nothing again: its mark is
		// read before the lease's rows, and refused by name
		mark, err := tx.exec(`SELECT continuation FROM gateway.rotated`)
		if err != nil {
			return err
		}
		if len(mark.rows) > 0 {
			refusal = errStoreRotated(rotatedMarkPrefix + string(mark.rows[0][0]))
			return nil
		}
		read, err := tx.exec(pgStartLeaseRows)
		if err != nil {
			return err
		}
		var live []pgLeaseRow
		for _, row := range read.rows {
			r := pgLeaseRow{holder: string(row[0]), keyID: string(row[2]), authority: string(row[3])}
			r.several, _ = pgBool(row[1])
			r.left, _ = pgInt8(row[4])
			r.live, _ = pgBool(row[5])
			if r.live {
				live = append(live, r)
			} else {
				expired = append(expired, r.holder)
			}
		}
		if refusal = admitBeside(as, live); refusal != nil {
			return nil
		}
		if !as.several {
			// the one instance takes the lease only where no write of an
			// instance whose row ran out holds it still
			if _, err := tx.exec(pgStartLeaseHoldExpired); pgCode(err) == pgLockNotAvailable {
				return refusedAtOnce
			} else if err != nil {
				return err
			}
		}
		args := []any{holder, pgInterval(period), as.several, as.keyID, as.authority}
		rows, err := tx.exec(pgStartLeaseTakeOver, args...)
		if err != nil {
			return err
		}
		if len(rows.rows) == 0 {
			if rows, err = tx.exec(pgStartLeaseTakeNew, args...); err != nil {
				return err
			}
		}
		if len(rows.rows) != 1 {
			return errors.New("store: no row of the start lease was taken")
		}
		taken = true
		return nil
	})
	if err != nil || !taken {
		l.closeOwn()
	}
	switch {
	case errors.Is(err, refusedAtOnce) && len(expired) == 1:
		return nil, fmt.Errorf("%w: the start lease of gateway instance %s ran out, and a write of that instance still holds it; the server ends that write within %s; start again (docs/postgresql-store.md, \"One instance per database\")", errStartLeaseHeld, expired[0], pgIdleInTransaction)
	case errors.Is(err, refusedAtOnce):
		return nil, fmt.Errorf("%w: the start leases of gateway instances %s ran out, and a write of one of them still holds its row; the server ends that write within %s; start again (docs/postgresql-store.md, \"One instance per database\")", errStartLeaseHeld, strings.Join(expired, ", "), pgIdleInTransaction)
	case pgCode(err) == pgLockNotAvailable:
		// the lease's lock, held by gateway store remove-scope or gateway
		// store migrate for its whole transaction
		return nil, fmt.Errorf("%w: a removal of a scope identifier's rows or a migration holds the start lease; start again once it has ended (docs/postgresql-store.md)", errStartLeaseHeld)
	case err != nil:
		return nil, err
	case refusal != nil:
		return nil, refusal
	}
	l.until = sent.Add(period)
	k.fence = holder
	return l, nil
}

// admitBeside is whether an instance as is admitted beside the instances
// whose rows are live: none, in the one-instance mode; in the
// several-instances mode, instances of that mode alone, each under as's key
// id and authority. Its refusal names the instance it found. Rows that ran
// out are not compared (ADR-0035, decision 8): once every instance has
// stopped, a start is compared with none, as in the one-instance mode, and
// its key is held by the start's walk of the registry alone, which refuses
// a seed that is not the chain's current key.
func admitBeside(as pgInstance, live []pgLeaseRow) error {
	for _, r := range live {
		switch {
		case !as.several && !r.several:
			return fmt.Errorf("%w: the database is served by gateway instance %s, whose start lease runs %d s more; one instance serves a database (docs/postgresql-store.md, \"One instance per database\")", errStartLeaseHeld, r.holder, r.left)
		case !as.several:
			return fmt.Errorf("%w: the database is served by gateway instance %s in the several-instances mode (storage.instances \"several\"), whose start lease runs %d s more; an instance in the one-instance mode does not start beside it (docs/postgresql-store.md, \"Several instances on one database\")", errStartLeaseHeld, r.holder, r.left)
		case !r.several:
			return fmt.Errorf("%w: the database is served by gateway instance %s in the one-instance mode, whose start lease runs %d s more; an instance in the several-instances mode does not start beside it (docs/postgresql-store.md, \"Several instances on one database\")", errStartLeaseHeld, r.holder, r.left)
		case r.keyID != as.keyID:
			return fmt.Errorf("%w: gateway instance %s serves the database signing under key id %s, and this instance signs under key id %s; every instance serving one database at once signs with one key: a rolling deploy that moves the instances to another key version, or from the seed to a key service, is not made one instance at a time; stop every instance, rotate with gateway store rotate-key, and start them all under the next key (ADR-0050)", errInstanceMismatch, r.holder, r.keyID, as.keyID)
		case r.authority != as.authority:
			return fmt.Errorf("%w: gateway instance %s serves the database for authority %q, and this instance names %q; every instance serving one database at once names one authority (docs/postgresql-store.md, \"Several instances on one database\")", errInstanceMismatch, r.holder, r.authority, as.authority)
		}
	}
	return nil
}

// pgHoldEveryInstance is what gateway store remove-scope and gateway store
// migrate hold, in the transaction open on c, for the transaction's whole
// time: the lease's lock, so no start takes a row meanwhile, and every row
// of the lease FOR UPDATE, so a write of an instance whose row ran out fails
// at its fence; refused at once while a write still holds a row, and while
// any row is live. what names the command in its refusal.
func pgHoldEveryInstance(c *pgConn, what string) error {
	if _, err := c.exec(`SELECT pg_catalog.pg_advisory_xact_lock($1)`, int64(pgStartLeaseLock)); err != nil {
		return err
	}
	if _, err := c.exec(`SELECT 1 FROM gateway.start_lease FOR UPDATE NOWAIT`); pgCode(err) == pgLockNotAvailable {
		return fmt.Errorf("%w: a gateway instance serves the database, or its start lease ran out and a write of that instance still holds it; stop the gateway, then %s", errStartLeaseHeld, what)
	} else if err != nil {
		return err
	}
	rows, err := c.exec(pgStartLeaseLiveCount)
	if err != nil {
		return err
	}
	if n, _ := pgInt8(rows.rows[0][0]); n > 0 {
		return fmt.Errorf("%w: a gateway instance serves the database by a start lease that is live (%d in all); stop the gateway, then %s", errStartLeaseHeld, n, what)
	}
	return nil
}

// pgRefuseRotated refuses, by name, a database a store rotation marked
// rotated away from (gateway.rotated): a removal appended to its registry
// would break the link the new store's continuation names. The commands
// that hold every row of the lease without taking it (store remove-scope)
// call it after pgHoldEveryInstance, in the same transaction.
func pgRefuseRotated(c *pgConn) error {
	mark, err := c.exec(`SELECT continuation FROM gateway.rotated`)
	if err != nil {
		return err
	}
	if len(mark.rows) > 0 {
		return errStoreRotated(rotatedMarkPrefix + string(mark.rows[0][0]))
	}
	return nil
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
