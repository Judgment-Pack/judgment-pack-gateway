package main

// The refusal journals as the forwarding owner reads them (ADR-0059 section
// 9): refusalEntrySource over the configured scopes' journals, on each kind.
// It reads entries outside every lock, and takes the journal's own lock, the
// one its appends take, only to move the cursor. It takes no lock an answer
// takes, and on the PostgreSQL kind it reads, locks and reads and moves the
// cursors on a connection of its own, outside the pool answers use and apart
// from the writer's.

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// refusalJournalNames are the configured scopes' journal names, sorted.
func refusalJournalNames(j *refusalJournals) []string {
	names := make([]string, 0, len(j.order))
	for _, s := range j.order {
		names = append(names, s.name)
	}
	sort.Strings(names)
	return names
}

// refusalEntrySourceOf is the service's seam: the configured journals on its
// kind, or noRefusalEntries where no journal is configured.
func (g *gatewayService) refusalEntrySourceOf() refusalEntrySource {
	if g.refusals == nil {
		return noRefusalEntries{}
	}
	names := refusalJournalNames(g.refusals)
	if kind, onKind := g.kind.(*pgKind); onKind {
		return newPGRefusalEntries(kind, names)
	}
	return newFSRefusalEntries(g.storeRoot, names)
}

// configuredJournal holds the source to the journals it was made with, so
// that no other path or row is read through it.
func configuredJournal(names []string, journal string) error {
	if i := sort.SearchStrings(names, journal); i < len(names) && names[i] == journal {
		return nil
	}
	return errors.New("not a configured refusal journal")
}

// --- the filesystem kind ----------------------------------------------------

// fsRefusalEntries reads <root>/journals/<name>.jsonl. One process serves a
// store of this kind, so the writer's appends and remove-scope are the
// file's only other users. Its cursors are the files beside the journals
// (fsForwardingCursors), outside the lock and under it alike: the file's
// lock is held across the cursor's compare-and-set.
type fsRefusalEntries struct {
	root        string
	names       []string
	cursorFiles fsForwardingCursors
}

func newFSRefusalEntries(root string, names []string) fsRefusalEntries {
	return fsRefusalEntries{root: root, names: names, cursorFiles: fsForwardingCursors{root: root, mu: &sync.Mutex{}}}
}

func (f fsRefusalEntries) cursors() forwardingCursors { return f.cursorFiles }

func (f fsRefusalEntries) path(journal string) string {
	return filepath.Join(f.root, journalsDir, journal+".jsonl")
}

func (f fsRefusalEntries) journals() ([]string, error) {
	return append([]string(nil), f.names...), nil
}

// entriesAfter reads only what the journal holds durably. It takes the
// file's lock just long enough to read the file's size: the writer syncs a
// line before it lets the lock go, so every byte within that size is on
// disk, and a line still in the page cache is never forwarded. A power loss
// then could write another entry at its ordinal, and the sink would hold two.
// The bytes are read after the lock is let go, so it never holds an append,
// and no further than that size. The writer appends a whole line, its line
// feed last, and only lines that end in one are entries; a torn tail is not
// read. Each entry's at is where its line begins, which locked reads it at
// again. A journal with no file, or an empty one, holds no entry. Where no
// file lock is taken (journalFilesLock false), the bound is the size at the
// read.
func (f fsRefusalEntries) entriesAfter(journal string, ordinal int64, limit int) ([]refusalEntryLine, error) {
	if err := configuredJournal(f.names, journal); err != nil {
		return nil, err
	}
	info, err := os.Lstat(f.path(journal))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errJournalNotRegular
	}
	if info.Size() == 0 {
		return nil, nil
	}
	file, err := os.Open(f.path(journal))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	durable, err := durableSize(file)
	if err != nil {
		return nil, err
	}
	if refusalReadAfterBound != nil {
		refusalReadAfterBound(journal)
	}
	in := bufio.NewReaderSize(io.LimitReader(file, durable), 64<<10)
	var out []refusalEntryLine
	var at int64
	for i := int64(0); len(out) < limit; i++ {
		line, err := in.ReadBytes('\n')
		if err == io.EOF {
			return out, nil // a torn tail, or none
		}
		if err != nil {
			return nil, err
		}
		if i > ordinal {
			out = append(out, refusalEntryLine{ordinal: i, line: line[:len(line)-1], at: at})
		}
		at += int64(len(line))
	}
	return out, nil
}

// refusalReadAfterBound, where not nil, runs once entriesAfter has its bound
// and let the lock go, before it reads: a test seam.
var refusalReadAfterBound func(journal string)

// durableSize is the size of the journal's file under its lock, the one
// each append round takes, which is let go before it returns.
func durableSize(file *os.File) (int64, error) {
	if err := lockJournalFile(file); err != nil {
		return 0, err
	}
	defer unlockJournalFile(file)
	info, err := file.Stat()
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// locked takes the journal file's lock, as each append round does
// (openRound), and runs fn under it only where the path is still the file
// it locked and that file still holds the entry at at its place. Where the
// journal has no file, or another, or the entry is not there, fn is not
// run: the owner reaches locked only after the sink acknowledged at, read
// from the journal, so the journal was removed (remove-scope takes the
// cursor with it, under this lock) or replaced since, and a cursor written
// now would name an entry no journal holds.
func (f fsRefusalEntries) locked(journal string, at refusalEntryLine, fn func(forwardingCursors) error) error {
	if err := configuredJournal(f.names, journal); err != nil {
		return err
	}
	path := f.path(journal)
	if info, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	} else if !info.Mode().IsRegular() {
		return errJournalNotRegular
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	if err := lockJournalFile(file); err != nil {
		return err
	}
	defer unlockJournalFile(file)
	held, err := file.Stat()
	if err != nil {
		return err
	}
	if now, err := os.Lstat(path); err != nil || !os.SameFile(held, now) {
		return nil
	}
	want := append(append([]byte(nil), at.line...), '\n')
	got := make([]byte, len(want))
	if _, err := file.ReadAt(got, at.at); err != nil || !bytes.Equal(got, want) {
		return nil
	}
	return fn(f.cursorFiles)
}

// --- the PostgreSQL kind ----------------------------------------------------

// pgRefusalEntries reads gateway.journal_records, takes each journal's
// advisory lock, and reads and moves the forwarding cursors, on a
// connection of its own: not a slot of the pool answers use, and not the
// writer's, which holds a transaction across a signing. No transaction of
// it spans a delivery: the owner delivers between them.
type pgRefusalEntries struct {
	kind  *pgKind
	names []string
	mu    sync.Mutex
	own   *pgConn
}

func newPGRefusalEntries(kind *pgKind, names []string) *pgRefusalEntries {
	return &pgRefusalEntries{kind: kind.ofNoScope(), names: names}
}

func (p *pgRefusalEntries) journals() ([]string, error) {
	return append([]string(nil), p.names...), nil
}

// onOwn runs fn in one transaction of mode on the source's own connection,
// opening it again where it failed. It holds mu until the transaction
// ends, so fn uses the transaction it is given and never calls onOwn.
func (p *pgRefusalEntries) onOwn(mode pgMode, fn func(pgTx) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	deadline := time.Now().Add(refusalPGBound)
	if p.own != nil && (p.own.broken || p.own.status != 'I') {
		p.own.close()
		p.own = nil
	}
	if p.own == nil {
		c, err := pgConnect(p.kind.pool.dsn, deadline)
		if err != nil {
			return err
		}
		p.own = c
	}
	view := *p.kind
	view.operation = refusalPGBound
	return view.transactOn(p.own, deadline, mode, fn)
}

// cursors reads the cursors on the source's own connection, each read a
// transaction of its own; under the lock, locked gives fn the ones of its
// transaction.
func (p *pgRefusalEntries) cursors() forwardingCursors {
	return pgForwardingCursors{docs: pgDocumentsOn{row: p.kind.row, run: p.onOwn}}
}

func (p *pgRefusalEntries) entriesAfter(journal string, ordinal int64, limit int) ([]refusalEntryLine, error) {
	if err := configuredJournal(p.names, journal); err != nil {
		return nil, err
	}
	var out []refusalEntryLine
	err := p.onOwn(pgRead, func(tx pgTx) error {
		rows, err := tx.exec(`SELECT ordinal, line FROM gateway.journal_records WHERE journal = $1 AND ordinal > $2 ORDER BY ordinal LIMIT $3`, journal, ordinal, int64(limit))
		if err != nil {
			return err
		}
		out = out[:0]
		for _, r := range rows.rows {
			n, ok := pgInt8(r[0])
			if !ok || len(r[1]) == 0 || bytes.IndexByte(r[1], '\n') >= 0 {
				return storeFailure(faultUnreadable, "journal-records", errors.New("store: a journal's row is not one"))
			}
			out = append(out, refusalEntryLine{ordinal: n, line: append([]byte(nil), r[1]...)})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// locked takes the journal's advisory lock, the one its appends and
// remove-scope take (pgRefusalLock), in a write transaction on the source's
// own connection, and runs fn under it only where the journal still holds
// at at its ordinal; otherwise the journal was removed, or begun again,
// since at was read, and fn is not run (as on the filesystem kind). fn is
// given the cursors of that transaction: the cursor's read and its
// compare-and-set are its statements, so they take no slot of the pool, and
// no remove-scope comes between the lock and the put, as one could where
// the put waited for a slot past the idle bound that ends this session and
// lets its lock go. The lock is let go when the transaction ends, after fn
// returns. The owner delivers before it calls locked, never inside it.
func (p *pgRefusalEntries) locked(journal string, at refusalEntryLine, fn func(forwardingCursors) error) error {
	if err := configuredJournal(p.names, journal); err != nil {
		return err
	}
	return p.onOwn(pgWriteCommitted, func(tx pgTx) error {
		if _, err := tx.exec(pgRefusalLock, pgRefusalJournalLockClass, refusalLockKey(journal)); err != nil {
			return err
		}
		rows, err := tx.exec(`SELECT line FROM gateway.journal_records WHERE journal = $1 AND ordinal = $2`, journal, at.ordinal)
		if err != nil {
			return err
		}
		if len(rows.rows) != 1 || !bytes.Equal(rows.rows[0][0], at.line) {
			return nil
		}
		if refusalCursorLockHeld != nil {
			refusalCursorLockHeld(journal)
		}
		return fn(pgForwardingCursors{docs: pgDocumentsOn{row: p.kind.row, run: pgInTransaction(tx)}})
	})
}

// refusalCursorLockHeld, where not nil, runs once locked holds the
// journal's advisory lock and has found the entry there, before fn: a test
// seam.
var refusalCursorLockHeld func(journal string)

func (p *pgRefusalEntries) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.own != nil {
		p.own.close()
		p.own = nil
	}
}
