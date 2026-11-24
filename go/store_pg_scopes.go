package main

// The scope identifiers the PostgreSQL kind keeps rows of
// (docs/adr/0033-a-platform-fixed-to-a-scope-identifier-on-the-postgresql-kind.md,
// docs/postgresql-store.md, "Scope identifiers"). A view of a scope writes
// and reads that scope's rows alone (pgKind.inScope); the gateway opens the
// views of the scopes its platforms are fixed to through scopeViews, which
// records each identifier in gateway.scope_identifiers before the view
// writes anything. What must reach every scope's rows -- an export, the
// start's question whether the store holds a session, a session's name --
// reads that record and then each scope in its turn, within one transaction
// whose every statement sees one scope's rows (everyScope; a session's name
// is asked of its own scope first, ownScopeFirst): no statement is ever
// admitted to the rows of two scopes, or of a scope and of none.

import (
	"bytes"
	"errors"
	"slices"
	"sort"
	"strings"
)

// ofNoScope is the kind's view of no scope, whatever view k is.
func (k *pgKind) ofNoScope() *pgKind {
	view := *k
	view.row = pgNoScope
	return &view
}

// ofRow is the view whose rows hold row, a scope as the scoped tables hold
// it; row is one the database gave back (gateway.scope_identifiers), whose
// form its table's check holds.
func (k *pgKind) ofRow(row string) *pgKind {
	view := *k
	view.row = row
	return &view
}

// scopeViews records each scope identifier in gateway.scope_identifiers, in
// one write transaction of no scope that keeps an identifier recorded
// already as it is, and returns each one's view. A view is a copy of k, so
// it holds the start lease's fence as k does: the views are opened once the
// lease is taken, and every write of each is fenced (holdFence).
func (k *pgKind) scopeViews(scopes []string) (map[string]storeKind, error) {
	views := map[string]storeKind{}
	var rows []string
	for _, scope := range scopes {
		view, err := k.inScope(scope)
		if err != nil {
			return nil, err
		}
		views[scope] = view
		rows = append(rows, view.row)
	}
	if len(rows) == 0 {
		return views, nil
	}
	root := k.ofNoScope()
	err := root.transact(pgWriteCommitted, func(tx pgTx) error {
		for _, row := range rows {
			if _, err := tx.exec(`INSERT INTO gateway.scope_identifiers (scope, identifier) VALUES ($1, $2)
				ON CONFLICT (identifier) DO NOTHING`, root.row, row); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, pgFailure("record-scopes", true, err)
	}
	return views, nil
}

// everyScope runs fn in one transaction of mode, first for the rows of no
// scope and then for those of each scope identifier recorded, in byte
// order, with gateway.scope set to that scope, for the transaction alone,
// before fn is called for it. Each statement fn makes sees the rows of the
// one scope it is called for, and names that scope besides; at REPEATABLE
// READ every scope is read in the transaction's one snapshot.
func (k *pgKind) everyScope(mode pgMode, fn func(tx pgTx, row string) error) error {
	root := k.ofNoScope()
	return root.transact(mode, func(tx pgTx) error {
		recorded, err := tx.exec(`SELECT identifier FROM gateway.scope_identifiers WHERE scope = $1 ORDER BY identifier`, root.row)
		if err != nil {
			return err
		}
		if err := fn(tx, root.row); err != nil {
			return err
		}
		for _, r := range recorded.rows {
			row := string(r[0])
			if _, err := tx.exec(`SELECT pg_catalog.set_config('gateway.scope', $1, true)`, row); err != nil {
				return err
			}
			if err := fn(tx, row); err != nil {
				return err
			}
		}
		return nil
	})
}

// pgGoneSinceTheCut refuses an export that finds a row its cut listed gone
// when it reads the row's bytes. An entry or a blob of this kind goes only
// by gateway store remove-scope, which takes no lock an export holds: a
// removal committed after the cut's snapshot took rows the cut listed, and
// an export that went on would hold the receipts of a removed session
// without their payloads and without the records that name them -- damage
// to a verifier, where the store holds none. The export stops before its
// manifest, so nothing is left as a finished export.
func pgGoneSinceTheCut(op string) error {
	return storeFailure(faultUnreadable, op, errors.New("store: a row the export's cut listed was removed while the export read it (gateway store remove-scope ran during the export); export again once the removal is done"))
}

// holdsAnySeries is whether the kind holds a series of no scope or of any
// scope identifier recorded: the registry's start asks it before it makes
// an empty registry (newGatewayServiceOn).
func (k *pgKind) holdsAnySeries() (bool, error) {
	held := false
	err := k.everyScope(pgReadSnapshot, func(tx pgTx, row string) error {
		if held {
			return nil
		}
		rows, err := tx.exec(`SELECT 1 FROM gateway.series WHERE scope = $1 LIMIT 1`, row)
		held = err == nil && len(rows.rows) > 0
		return err
	})
	if err != nil {
		return false, pgFailure("list-series", false, err)
	}
	return held, nil
}

// ownScopeFirst runs fn in one transaction of mode, first for the rows of
// the scope own, the view's, which the transaction sets as every one of
// that view's does; and then, unless fn answered done for own, for the rows
// of no scope and of each scope identifier recorded but own, in byte order,
// with gateway.scope set to each in its turn for the transaction alone, as
// everyScope does, until fn answers done. Each statement fn makes sees the
// rows of the one scope it is called for.
func (k *pgKind) ownScopeFirst(mode pgMode, own *pgKind, fn func(tx pgTx, row string) (bool, error)) error {
	return own.transact(mode, func(tx pgTx) error {
		if done, err := fn(tx, own.row); done || err != nil {
			return err
		}
		// the record is of no scope, and is read in a setting of no scope
		if _, err := tx.exec(`SELECT pg_catalog.set_config('gateway.scope', $1, true)`, pgNoScope); err != nil {
			return err
		}
		recorded, err := tx.exec(`SELECT identifier FROM gateway.scope_identifiers WHERE scope = $1 ORDER BY identifier`, pgNoScope)
		if err != nil {
			return err
		}
		if own.row != pgNoScope {
			if done, err := fn(tx, pgNoScope); done || err != nil {
				return err
			}
		}
		for _, r := range recorded.rows {
			row := string(r[0])
			if row == own.row {
				continue
			}
			if _, err := tx.exec(`SELECT pg_catalog.set_config('gateway.scope', $1, true)`, row); err != nil {
				return err
			}
			if done, err := fn(tx, row); done || err != nil {
				return err
			}
		}
		return nil
	})
}

// seriesHeld is whether the kind holds a series of the name, of no scope or
// of any scope identifier recorded; whether that series is of scope ("" for
// no scope); and whether it holds an entry. A session's name is one across
// scopes (gateway.series' key), so at most one scope holds it.
//
// The scope asked first is scope's own (ownScopeFirst): a session of that
// scope is answered by one statement, however many identifiers are
// recorded. Only a name that scope does not hold -- every new session's --
// is looked for in no scope and in every other identifier recorded, since
// the answer "held by another scope" needs them all.
func (k *pgKind) seriesHeld(name, scope string) (held, ofScope, entries bool, err error) {
	if !validListedSeries(name) {
		return false, false, false, pgRefused("list-entries", "not a series' name")
	}
	own := k.ofNoScope()
	if scope != "" {
		if own, err = k.inScope(scope); err != nil {
			return false, false, false, pgRefused("list-entries", "not a scope identifier")
		}
	}
	err = k.ownScopeFirst(pgReadSnapshot, own, func(tx pgTx, row string) (bool, error) {
		rows, err := tx.exec(`SELECT EXISTS (SELECT 1 FROM gateway.entries e WHERE e.scope = s.scope AND e.series = s.name)
			FROM gateway.series s WHERE s.scope = $1 AND s.name = $2`, row, name)
		if err != nil || len(rows.rows) == 0 {
			return false, err
		}
		held, ofScope = true, row == own.row
		entries, _ = pgBool(rows.rows[0][0])
		return true, nil
	})
	if err != nil {
		return false, false, false, pgFailure("list-entries", false, err)
	}
	return held, ofScope, entries, nil
}

// seriesScope is whether the kind holds a series of the name, of no scope
// or of any scope identifier recorded, and the scope it is of ("" for none):
// what a seal of a session this instance does not hold is answered by for a
// caller held to scope identifiers (ADR-0037), before anything else of the
// session is read. A session's name is one across scopes, so at most one
// scope holds it.
func (k *pgKind) seriesScope(name string) (held bool, scope string, err error) {
	if !validListedSeries(name) {
		return false, "", pgRefused("list-entries", "not a series' name")
	}
	err = k.ownScopeFirst(pgReadSnapshot, k.ofNoScope(), func(tx pgTx, row string) (bool, error) {
		rows, err := tx.exec(`SELECT 1 FROM gateway.series WHERE scope = $1 AND name = $2`, row, name)
		if err != nil || len(rows.rows) == 0 {
			return false, err
		}
		held = true
		if row != pgNoScope {
			scope = strings.TrimPrefix(row, pgScopePrefix)
		}
		return true, nil
	})
	if err != nil {
		return false, "", pgFailure("list-entries", false, err)
	}
	return held, scope, nil
}

// pgEveryScope is the kind as an export cuts it (exportCut): the rows of no
// scope and of every scope identifier recorded, in one snapshot.
type pgEveryScope struct{ *pgKind }

func (k pgEveryScope) snapshot() (*storeCut, error) { return k.exportCut() }

// exportCut is the cut an export writes: the log, and the series, entries
// and blobs of no scope and of every scope identifier recorded, read in one
// transaction at REPEATABLE READ, one scope at a time (everyScope), so the
// cut is one state the kind was in. A store of the filesystem kind holds
// every scope's receipts in one layout, and so does the cut: a series is
// listed once, since its name is one across scopes; a blob held by several
// scopes, as a payload two scopes' sources returned alike, is listed once
// and read from each scope that holds it, and bytes that differ between
// two are refused rather than one taken for the other. Only the documents of
// no scope are in it: an export writes no document.
func (k *pgKind) exportCut() (*storeCut, error) {
	cut := &storeCut{documents: map[string][]byte{}, revisions: map[string]string{}, entries: map[string][]string{}}
	seriesOf := map[string]string{}
	blobsOf := map[string][]string{}
	var removals []byte
	err := k.everyScope(pgReadSnapshot, func(tx pgTx, row string) error {
		if row == pgNoScope {
			log, present, err := pgLog{k: k, name: "registry"}.readTx(tx, 0)
			if err != nil {
				return err
			}
			cut.log, cut.logPresent = log, present
			// the removal records in the cut's snapshot, as the rows are:
			// gateway store remove-scope commits its records with the
			// removal of the rows, so the records the cut holds name the
			// sessions the cut lacks, and no more
			if removals, _, err = pgRemovalFile(tx); err != nil {
				return err
			}
			// and the operator journal in the same snapshot, so its
			// entries name the records and seals the cut holds
			if cut.refusalJournals, err = pgRefusalJournalFiles(tx); err != nil {
				return err
			}
			if cut.journal, err = pgJournalFile(tx, operatorJournal); err != nil {
				return err
			}
			// a journal this release does not read is refused by its name,
			// never left out, as in a store directory: the copy would
			// verify without it (journal-unknown)
			if err = pgUnknownJournals(tx); err != nil {
				return err
			}
			docs, err := tx.exec(`SELECT name, revision, data FROM gateway.documents WHERE scope = $1`, row)
			if err != nil {
				return err
			}
			for _, d := range docs.rows {
				cut.documents[string(d[0])] = d[2]
				cut.revisions[string(d[0])] = string(d[1])
			}
		}
		series, err := tx.exec(`SELECT name FROM gateway.series WHERE scope = $1`, row)
		if err != nil {
			return err
		}
		for _, s := range series.rows {
			name := string(s[0])
			if _, twice := seriesOf[name]; twice {
				return storeFailure(faultUnreadable, "snapshot", errors.New("store: two scopes hold one series' name"))
			}
			seriesOf[name] = row
			cut.series = append(cut.series, name)
			cut.entries[name] = []string{}
		}
		entries, err := tx.exec(`SELECT series, name FROM gateway.entries WHERE scope = $1`, row)
		if err != nil {
			return err
		}
		for _, e := range entries.rows {
			cut.entries[string(e[0])] = append(cut.entries[string(e[0])], string(e[1]))
		}
		blobs, err := tx.exec(`SELECT name FROM gateway.blobs WHERE scope = $1`, row)
		if err != nil {
			return err
		}
		for _, b := range blobs.rows {
			name := string(b[0])
			if len(blobsOf[name]) == 0 {
				cut.blobs = append(cut.blobs, name)
			}
			blobsOf[name] = append(blobsOf[name], row)
		}
		return nil
	})
	if err != nil {
		return nil, pgFailure("snapshot", false, err)
	}
	sort.Strings(cut.series)
	sort.Strings(cut.blobs)
	for _, names := range cut.entries {
		sort.Strings(names)
	}
	cut.removals = func() ([]byte, bool, error) { return removals, len(removals) > 0, nil }
	// an entry or a blob is never changed once made, so its bytes are read
	// when the cut is asked, by the view of the scope that holds it, in a
	// transaction of its own; one the cut listed and the read finds gone
	// was removed after the snapshot, and refuses the export
	// (pgGoneSinceTheCut)
	cut.entry = func(series, entry string) ([]byte, error) {
		row, listed := seriesOf[series]
		if !listed {
			return nil, pgAbsent("get-entry")
		}
		data, err := pgIndexed{k.ofRow(row)}.getEntry(series, entry)
		if faultOf(err) == faultAbsent && slices.Contains(cut.entries[series], entry) {
			return nil, pgGoneSinceTheCut("get-entry")
		}
		return data, err
	}
	cut.blob = func(name string) ([]byte, error) {
		var held []byte
		found := false
		for _, row := range blobsOf[name] {
			data, err := pgBlobs{k.ofRow(row)}.getBlob(name)
			switch {
			case faultOf(err) == faultAbsent:
				continue
			case err != nil:
				return nil, err
			case found && !bytes.Equal(data, held):
				return nil, storeFailure(faultUnreadable, "get-blob", errors.New("store: two scopes hold different bytes under one blob's name"))
			}
			held, found = data, true
		}
		if !found {
			if len(blobsOf[name]) > 0 {
				return nil, pgGoneSinceTheCut("get-blob")
			}
			return nil, pgAbsent("get-blob")
		}
		return held, nil
	}
	return cut, nil
}
