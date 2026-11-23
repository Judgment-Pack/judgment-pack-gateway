package main

// The operator journal on the PostgreSQL kind (ADR-0056, Amendment A): the
// rows of gateway.journal_records, one for each entry, keyed by (journal,
// ordinal), each the entry's line without its 0x0A. The schema admits a row
// only at its journal's end (migration 0010), and the run-time login may
// read and insert there and nothing else (grants.sql).
//
// The entry is the filesystem kind's, with the same envelope, signer and
// chain, and its lengths are of the bytes an export writes: each removal
// record and its 0x0A, in order, and the registry's bytes. There is no
// staged entry on this kind:
//
//   - gateway store retain and gateway store remove-scope insert their entry
//     in the transaction that inserts the records and removes the rows, as
//     the owner, so the two commit together or not at all;
//   - gateway seal-open, and gateway store rotate in the database rotated
//     from, insert theirs after the last seal, as the run-time login, in a
//     transaction of its own fenced on the start lease as the seals are. A
//     stop between the seals and the entry leaves command seals no entry
//     names, and the next such command names them first;
//   - gateway store rotate writes the store-continued entry of the database
//     rotated to in the migration's transaction that makes its registry and
//     key-history row.
//
// Each insert reads the journal's last row, for its ordinal and previous, in
// the transaction that inserts; two writers racing for one ordinal cannot
// fork the chain, since the primary key refuses the second.

import (
	"bytes"
	"errors"
	"fmt"
)

// journalCutOff, where a test sets it, runs in a removal's transaction on
// this kind after its entry is inserted and before COMMIT: a failure there
// rolls the records and the entry back together.
var journalCutOff func() error

// pgJournalFile is the journal's rows in ordinal order, as an export writes
// them: each line and its 0x0A. Rows that do not run from 0 with no gap, or
// a line holding a 0x0A, are refused, as the schema admits neither.
func pgJournalFile(tx pgTx, journal string) ([]byte, error) {
	rows, err := tx.exec(`SELECT ordinal, line FROM gateway.journal_records WHERE journal = $1 ORDER BY ordinal`, journal)
	if err != nil {
		return nil, err
	}
	var data []byte
	for i, r := range rows.rows {
		ordinal, ok := pgInt8(r[0])
		if !ok || ordinal != int64(i) {
			return nil, storeFailure(faultUnreadable, "journal-records", errors.New("store: the journal's rows do not run from 0 with no gap"))
		}
		if len(r[1]) == 0 || bytes.IndexByte(r[1], '\n') >= 0 {
			return nil, storeFailure(faultUnreadable, "journal-records", errors.New("store: a journal's row is empty or holds a line feed"))
		}
		data = append(append(data, r[1]...), '\n')
	}
	return data, nil
}

// pgOperatorJournalCall is a journaled command's hold on the operator
// journal of a database of the PostgreSQL kind: where its entry goes, as
// read when the call began, and the store's lengths then. A nil call writes
// no entry.
type pgOperatorJournalCall struct {
	key          *signingKey
	stamp        func() string
	ordinal      int64
	previous     string
	unnamed      []commandSeal
	registryFrom int64
	removalFrom  int64
}

// beginPgOperatorJournal is beginOperatorJournal on this kind, in the
// transaction tx that reads the registry's bytes and the removal records:
// whether the call writes an entry -- its configuration of
// operatorJournalVersion or later, or a journal the database holds already
// -- and, if it does, the journal's end and the lengths the call begins
// from.
func beginPgOperatorJournal(tx pgTx, version string, key *signingKey, keys []reachedKey, registry, removal []byte, stamp func() string) (*pgOperatorJournalCall, error) {
	data, err := pgJournalFile(tx, operatorJournal)
	if err != nil {
		return nil, err
	}
	if !journaledStore(len(data) > 0, version) {
		return nil, nil
	}
	j := &pgOperatorJournalCall{key: key, stamp: stamp, registryFrom: int64(len(registry)), removalFrom: int64(len(removal))}
	lines, _ := journalLines(data)
	j.ordinal = int64(len(lines))
	if len(lines) > 0 {
		j.previous = journalDigest(lines[len(lines)-1])
	}
	j.unnamed = judgeOperatorJournal(data, false, keys, registry, removal, true).unnamed
	return j, nil
}

// insert signs the entry of body and inserts it at the journal's end in
// tx, reading the journal's last row there: a journal whose end is not the
// one the call began at is refused, as the seals the call names were read
// against that end.
func (j *pgOperatorJournalCall) insert(tx pgTx, body *vObject) error {
	rows, err := tx.exec(`SELECT ordinal, line FROM gateway.journal_records WHERE journal = $1 ORDER BY ordinal DESC LIMIT 1`, operatorJournal)
	if err != nil {
		return err
	}
	ordinal, previous := int64(0), ""
	if len(rows.rows) == 1 {
		last, ok := pgInt8(rows.rows[0][0])
		if !ok {
			return storeFailure(faultUnreadable, "journal-records", errors.New("store: the journal's last row did not read"))
		}
		ordinal, previous = last+1, journalDigest(rows.rows[0][1])
	}
	if ordinal != j.ordinal || previous != j.previous {
		return errors.New("the operator journal changed while the call ran")
	}
	body.set("registryFrom", vInt(j.registryFrom))
	body.set("removalFrom", vInt(j.removalFrom))
	line, err := signedJournalEntry(j.key, operatorJournal, ordinal, previous, j.stamp(), body)
	if err != nil {
		return err
	}
	return pgInsertJournalRow(tx, ordinal, line)
}

// pgInsertJournalRow inserts the operator journal's row at ordinal holding
// line, its 0x0A taken off.
func pgInsertJournalRow(tx pgTx, ordinal int64, line []byte) error {
	_, err := tx.exec(`INSERT INTO gateway.journal_records (journal, ordinal, line) VALUES ($1, $2, $3)`, operatorJournal, ordinal, bytes.TrimSuffix(line, []byte{'\n'}))
	return err
}

// removalEntry is a removal kind's entry, inserted in the transaction that
// inserts the records lines, each with its 0x0A, as an export writes them.
// A nil call inserts none.
func (j *pgOperatorJournalCall) removalEntry(tx pgTx, lines [][]byte, body *vObject) error {
	if j == nil {
		return nil
	}
	var appended []byte
	for _, line := range lines {
		appended = append(appended, line...)
	}
	body.set("removalBytes", vInt(len(appended)))
	body.set("removalDigest", vString(journalDigest(appended)))
	if err := j.insert(tx, body); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	return nil
}

// sealEntry is a seal kind's entry, inserted after the call's last seal in
// a write transaction of its own of kind, fenced on the start lease as the
// seals are: the command seals no entry names yet, those an interrupted
// call left first, then the call's own. A call that sealed nothing, and
// found nothing to name, inserts none; so does a nil call.
func (j *pgOperatorJournalCall) sealEntry(kind *pgKind, entryKind string, delivered bool) error {
	if j == nil {
		return nil
	}
	err := kind.ofNoScope().transact(pgWriteCommitted, func(tx pgTx) error {
		registry, _, err := pgLog{k: kind, name: "registry"}.readTx(tx, 0)
		if err != nil {
			return err
		}
		named := append([]commandSeal{}, j.unnamed...)
		for _, s := range commandSealsOf(registry) {
			if s.at >= j.registryFrom {
				named = append(named, s)
			}
		}
		if len(named) == 0 {
			return nil
		}
		var sealed []byte
		for _, s := range named {
			sealed = append(sealed, s.line...)
		}
		body := newObject()
		body.set("kind", vString(entryKind))
		body.set("seals", vInt(len(named)))
		body.set("sealDigest", vString(journalDigest(sealed)))
		body.set("delivered", vBool(delivered))
		return j.insert(tx, body)
	})
	if err != nil {
		return pgFailure("journal", false, err)
	}
	return nil
}

// pgBeginSealJournal is beginPgOperatorJournal for a command that seals
// under the start lease: the registry, the removal records and the journal
// read in one transaction of no scope.
func pgBeginSealJournal(kind *pgKind, version string, key *signingKey, stamp func() string) (*pgOperatorJournalCall, error) {
	var j *pgOperatorJournalCall
	err := kind.ofNoScope().transact(pgReadSnapshot, func(tx pgTx) error {
		registry, _, err := pgLog{k: kind, name: "registry"}.readTx(tx, 0)
		if err != nil {
			return err
		}
		walk, err := engineWalk(registry, key.held())
		if err != nil {
			return err
		}
		removal, _, err := pgRemovalFile(tx)
		if err != nil {
			return err
		}
		j, err = beginPgOperatorJournal(tx, version, key, walk.keys, registry, removal, stamp)
		return err
	})
	if err != nil {
		return nil, pgFailure("journal", false, err)
	}
	return j, nil
}

// pgOperatorJournalOf is the operator journal the kind keeps, as an export
// writes it, read in a transaction of no scope.
func pgOperatorJournalOf(kind *pgKind) ([]byte, error) {
	var data []byte
	err := kind.ofNoScope().transact(pgRead, func(tx pgTx) error {
		var err error
		data, err = pgJournalFile(tx, operatorJournal)
		return err
	})
	if err != nil {
		return nil, pgFailure("journal", false, err)
	}
	return data, nil
}

// pgWriteContinuedEntry writes, or on a rerun holds, the store-continued
// entry of the database rotated to, in the migration's transaction that
// makes its registry: a journal there already must be that entry alone,
// naming the continuation and the old journal, or the rotation is refused;
// one not there is written. keys are the new registry's walk's.
func pgWriteContinuedEntry(tx pgTx, key *signingKey, keys []reachedKey, continuation, oldJournal []byte, at string) error {
	there, err := pgJournalFile(tx, operatorJournal)
	if err != nil {
		return err
	}
	if len(there) > 0 {
		if !continuedJournalHolds(there, continuation, oldJournal, keys) {
			return errors.New("its operator journal is not the store-continued entry of this rotation")
		}
		return nil
	}
	line, err := storeContinuedEntry(key, continuation, oldJournal, at)
	if err != nil {
		return err
	}
	return pgInsertJournalRow(tx, 0, line)
}
