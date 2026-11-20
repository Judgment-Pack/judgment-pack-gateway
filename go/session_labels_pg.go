package main

// Session labels on the PostgreSQL kind (ADR-0051, point 2; migration 0009,
// docs/postgresql-store.md, "Session labels"). A label is a row of
// gateway.session_labels, read and written through the view of its
// namespace's scope alone: each transaction sets gateway.scope to that
// scope and each statement names it, so row security admits no other
// namespace's rows. A label's first use inserts its row ON CONFLICT (scope,
// label) DO NOTHING and, where another request or another instance recorded
// it first, reads the row there in the same transaction: every instance on
// one database agrees on the one id, without the start lease or a lock of
// its own. A write holds the start lease last, as every write of the kind
// does (holdFence).

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

// pgLabels keeps labels in gateway.session_labels through the views of k.
type pgLabels struct{ k *pgKind }

// labelView is the view of the kind whose rows are scope's namespace.
func (l pgLabels) labelView(scope string) (*pgKind, error) {
	if scope == "" {
		return l.k.ofNoScope(), nil
	}
	return l.k.inScope(scope)
}

// pgLabelOf is the series a row read names, held to the minted form.
func pgLabelOf(rows pgRows) (string, error) {
	if len(rows.rows) == 0 {
		return "", nil
	}
	id := string(rows.rows[0][0])
	if len(rows.rows) != 1 || !mintedSessionPattern.MatchString(id) {
		return "", errors.New("store: a session label does not read as one of this gateway's")
	}
	return id, nil
}

func (l pgLabels) labelSession(scope, label string) (string, error) {
	view, err := l.labelView(scope)
	if err != nil {
		return "", err
	}
	var id string
	err = view.transact(pgRead, func(tx pgTx) error {
		rows, err := tx.exec(`SELECT series FROM gateway.session_labels WHERE scope = $1 AND label = $2`, view.row, label)
		if err != nil {
			return err
		}
		id, err = pgLabelOf(rows)
		return err
	})
	if err != nil {
		return "", pgFailure("label", false, err)
	}
	return id, nil
}

func (l pgLabels) recordLabel(scope, label, id string) (string, error) {
	view, err := l.labelView(scope)
	if err != nil {
		return "", err
	}
	var recorded string
	err = view.transact(pgWriteCommitted, func(tx pgTx) error {
		rows, err := tx.exec(`INSERT INTO gateway.session_labels (scope, label, series) VALUES ($1, $2, $3)
			ON CONFLICT (scope, label) DO NOTHING RETURNING series`, view.row, label, id)
		if err != nil {
			return err
		}
		if len(rows.rows) == 0 {
			// recorded first by another request or another instance, whose
			// transaction the insert waited for: its id is the one the
			// label names, and this statement's snapshot holds it
			if rows, err = tx.exec(`SELECT series FROM gateway.session_labels WHERE scope = $1 AND label = $2`, view.row, label); err != nil {
				return err
			}
			if len(rows.rows) == 0 {
				return errors.New("store: a label taken is not there")
			}
		}
		recorded, err = pgLabelOf(rows)
		return err
	})
	if err != nil {
		return "", pgFailure("record-label", true, err)
	}
	return recorded, nil
}

func (l pgLabels) idLabelled(scope, id string) (bool, error) {
	view, err := l.labelView(scope)
	if err != nil {
		return false, err
	}
	var named bool
	err = view.transact(pgRead, func(tx pgTx) error {
		rows, err := tx.exec(`SELECT label FROM gateway.session_labels WHERE scope = $1 AND series = $2`, view.row, id)
		named = len(rows.rows) > 0
		return err
	})
	if err != nil {
		return false, pgFailure("label", false, err)
	}
	return named, nil
}

// pgLabelRows is the labels of one namespace's rows, as a transaction of
// that scope reads them.
func pgLabelRows(tx pgTx, row string) ([]labelEntry, error) {
	rows, err := tx.exec(`SELECT label, series FROM gateway.session_labels WHERE scope = $1 ORDER BY label`, row)
	if err != nil {
		return nil, err
	}
	scope := ""
	if row != pgNoScope {
		scope = strings.TrimPrefix(row, pgScopePrefix)
	}
	entries := make([]labelEntry, 0, len(rows.rows))
	for _, r := range rows.rows {
		label, id := string(r[0]), string(r[1])
		if requireSession(label) != nil || !mintedSessionPattern.MatchString(id) {
			return nil, errors.New("store: a session label does not read as one of this gateway's")
		}
		entries = append(entries, labelEntry{label: label, scope: scope, sessionID: id})
	}
	return entries, nil
}

func (l pgLabels) labelEntries() ([]labelEntry, error) {
	var entries []labelEntry
	err := l.k.everyScope(pgReadSnapshot, func(tx pgTx, row string) error {
		of, err := pgLabelRows(tx, row)
		entries = append(entries, of...)
		return err
	})
	if err != nil {
		return nil, pgFailure("labels", false, err)
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].label < entries[j].label })
	return entries, nil
}

func (l pgLabels) labelsOf(scope string) ([]labelEntry, error) {
	view, err := l.labelView(scope)
	if err != nil {
		return nil, err
	}
	var entries []labelEntry
	err = view.transact(pgRead, func(tx pgTx) error {
		entries, err = pgLabelRows(tx, view.row)
		return err
	})
	if err != nil {
		return nil, pgFailure("labels", false, err)
	}
	return entries, nil
}

// seriesHoldingEntries is every series of no scope and of each scope
// identifier recorded that holds an entry, read one scope at a time in one
// snapshot: the sessions the start at labelsVersion asks whether a label
// names (unlabelledOpen).
func (k *pgKind) seriesHoldingEntries() ([]string, error) {
	var names []string
	err := k.everyScope(pgReadSnapshot, func(tx pgTx, row string) error {
		rows, err := tx.exec(`SELECT s.name FROM gateway.series s WHERE s.scope = $1
			AND EXISTS (SELECT 1 FROM gateway.entries e WHERE e.scope = s.scope AND e.series = s.name) ORDER BY s.name`, row)
		names = append(names, pgNames(rows)...)
		return err
	})
	if err != nil {
		return nil, pgFailure("list-series", false, err)
	}
	return names, nil
}

// pgLabelsFor is the labels of the database a configuration names, read
// through the run-time login with no start lease, and what closes the kind:
// gateway sessions, which writes nothing. The connection file is held as
// export holds it (#444).
func pgLabelsFor(cfg engineConfig) (labelKeeper, func(), error) {
	spec := *cfg.storage
	if spec.file != "" {
		euid := os.Geteuid()
		resolved, err := trustedFile(spec.file, euid, linkOwners{other: euid}, osEngineHost())
		if err != nil {
			return nil, nil, fmt.Errorf("storage.connection.file: %v", err)
		}
		spec.file = resolved
	}
	kind, err := openStorageKind(&spec)
	if err != nil {
		return nil, nil, err
	}
	return pgLabels{k: kind}, kind.close, nil
}
