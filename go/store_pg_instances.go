package main

// The instance that holds each session, where instances serve one PostgreSQL
// database beside one another (storage.instances "several", engineVersion 26;
// docs/adr/0035-several-instances-on-one-postgresql-database.md, option C;
// docs/postgresql-store.md, "Several instances on one database").
//
// A gateway keeps a session's count and chain in memory (open_sessions.go),
// so a session is served by one instance: the one that admitted its first
// call. That instance records itself as the session's holder when it admits
// that call, before the source runs, in the write transaction that makes the
// session's series (claimSeries), fenced on its row of the start lease as
// every write of it is. Another instance answers a call into the session, or
// a seal of it, 409 (refusalHeldElsewhere) while the holder's row is live.
//
// Once the holder's row has expired -- the instance stopped, or crashed and
// its row ran out -- a series that holds no receipt is taken up by the next
// instance a call reaches: it holds the old holder's row FOR UPDATE first
// (pgStartLeaseSettle), so every write of the old holder has ended or will
// fail at its fence, reads again that the series holds no receipt, and
// records itself at the series' next turn (gateway.series_holders). Two
// instances that take one series up at once meet at that turn's key, and
// the one that comes second is answered 409. A series that holds a receipt
// is never taken up: its holder's count is gone with its memory, and it is
// sealed after the interruption (SPEC.md §3c) by gateway seal-open or a
// start, as one an earlier process left open is (seal_open_pg.go).

import (
	"errors"
)

// seriesClaim is what claimSeries and seriesHolding find of a session's
// series.
type seriesClaim int

const (
	// seriesHeldHere: this instance holds the series, made by this call,
	// held already, or taken up by it.
	seriesHeldHere seriesClaim = iota
	// seriesNone: no series of the name (seriesHolding alone).
	seriesNone
	// seriesOfOtherScope: the series is of a scope other than the call's.
	seriesOfOtherScope
	// seriesLeftOpen: the series holds a receipt, and no live instance
	// but this one holds it, which did not mint it in this run.
	seriesLeftOpen
	// seriesHeldElsewhere: another instance whose row of the start lease is
	// live holds the series.
	seriesHeldElsewhere
	// seriesUnclaimed: the series holds no receipt and no live instance
	// holds it (seriesHolding alone).
	seriesUnclaimed
)

// claimsSeries is whether this kind records the instance that holds each
// session: in the several-instances mode, once it holds the start lease.
func (k *pgKind) claimsSeries() bool {
	return k.instance.several && k.fence != ""
}

// pgSeriesHolding is a row of pgSeriesHolder.
type pgSeriesHolding struct {
	holder   string // "" for none
	turn     int64
	receipts bool
	live     bool
}

func pgReadSeriesHolding(tx pgTx, row, name string) (*pgSeriesHolding, error) {
	rows, err := tx.exec(pgSeriesHolder, row, name)
	if err != nil {
		return nil, err
	}
	if len(rows.rows) == 0 {
		return nil, nil
	}
	r := rows.rows[0]
	h := &pgSeriesHolding{}
	if r[0] != nil {
		h.holder = string(r[0])
	}
	var ok1, ok2, ok3 bool
	h.turn, ok1 = pgInt8(r[1])
	h.receipts, ok2 = pgBool(r[2])
	h.live, ok3 = pgBool(r[3])
	if !ok1 || !ok2 || !ok3 {
		return nil, errors.New("store: a series' holder did not read")
	}
	return h, nil
}

// claimSeries makes the series of a session this instance admits a call
// into, of the scope the call's source is fixed to ("" for none), and
// records this instance as its holder; or takes it up from an instance whose
// row has expired, where it holds no receipt; or answers why it does
// neither. It runs in one write transaction, fenced on this instance's row,
// that looks at the call's own scope first and then, where that scope holds
// no series of the name, at every other (ownScopeFirst): a session's name is
// one across scopes.
func (k *pgKind) claimSeries(name, scope string) (seriesClaim, error) {
	if !validStoreName(name) {
		return 0, pgRefused("claim-series", "not a series' name")
	}
	own := k.ofNoScope()
	if scope != "" {
		var err error
		if own, err = k.inScope(scope); err != nil {
			return 0, pgRefused("claim-series", "not a scope identifier")
		}
	}
	me := k.fence
	claim := seriesHeldHere
	err := k.ownScopeFirst(pgWriteCommitted, own, func(tx pgTx, row string) (bool, error) {
		if row != own.row {
			// a series of another scope is never this call's
			rows, err := tx.exec(`SELECT 1 FROM gateway.series WHERE scope = $1 AND name = $2`, row, name)
			if err != nil || len(rows.rows) == 0 {
				return false, err
			}
			claim = seriesOfOtherScope
			return true, nil
		}
		made, err := tx.exec(`INSERT INTO gateway.series (scope, name, holder) VALUES ($1, $2, $3)
			ON CONFLICT DO NOTHING RETURNING name`, row, name, me)
		if err != nil {
			return false, err
		}
		if len(made.rows) == 1 {
			claim = seriesHeldHere
			return true, nil
		}
		h, err := pgReadSeriesHolding(tx, row, name)
		if err != nil || h == nil {
			// not of this scope: another scope's, looked for next
			return false, err
		}
		switch {
		case h.holder == me && h.receipts:
			// a receipt this instance's memory does not hold: one whose write
			// reported a failure although it landed
			claim = seriesLeftOpen
			return true, nil
		case h.holder == me:
			claim = seriesHeldHere
			return true, nil
		case h.live:
			claim = seriesHeldElsewhere
			return true, nil
		case h.receipts:
			claim = seriesLeftOpen
			return true, nil
		}
		// The holder's row has expired: every write of that instance is
		// waited for, and fails at its fence from here, before the series is
		// read again and taken up.
		if h.holder != "" {
			if _, err := tx.exec(pgStartLeaseSettle, h.holder); err != nil {
				return false, err
			}
			again, err := pgReadSeriesHolding(tx, row, name)
			if err != nil {
				return false, err
			}
			if again == nil || again.receipts {
				claim = seriesLeftOpen
				return true, nil
			}
			if again.turn != h.turn || again.live {
				// taken up meanwhile, by an instance that holds it now; or
				// its holder's row is live again (a renewal that committed
				// between the read and the settle): never taken up from a
				// live holder
				claim = seriesHeldElsewhere
				return true, nil
			}
		}
		if _, err := tx.exec(`INSERT INTO gateway.series_holders (scope, series, turn, holder) VALUES ($1, $2, $3, $4)`,
			row, name, h.turn+1, me); err != nil {
			return false, err
		}
		claim = seriesHeldHere
		return true, nil
	})
	if pgCode(err) == pgUniqueViolation {
		// another instance took the series up at the same turn, and holds it
		return seriesHeldElsewhere, nil
	}
	if err != nil {
		return 0, pgFailure("claim-series", true, err)
	}
	return claim, nil
}

// seriesHolding reads, of a session this instance does not hold, who holds
// it and whether it holds a receipt, in every scope (a seal names none); it
// changes nothing.
func (k *pgKind) seriesHolding(name string) (seriesClaim, error) {
	if !validListedSeries(name) {
		return 0, pgRefused("list-entries", "not a series' name")
	}
	me := k.fence
	claim := seriesNone
	err := k.ownScopeFirst(pgReadSnapshot, k.ofNoScope(), func(tx pgTx, row string) (bool, error) {
		h, err := pgReadSeriesHolding(tx, row, name)
		if err != nil || h == nil {
			return false, err
		}
		switch {
		case h.live && h.holder != me:
			claim = seriesHeldElsewhere
		case h.receipts:
			claim = seriesLeftOpen
		default:
			claim = seriesUnclaimed
		}
		return true, nil
	})
	if err != nil {
		return 0, pgFailure("list-entries", false, err)
	}
	return claim, nil
}
