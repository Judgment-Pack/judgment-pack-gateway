package main

// The refusal journals on the PostgreSQL kind (ADR-0059 §7): the rows of
// gateway.journal_records under each journal's name, with no migration and
// no grant. The writer inserts on a connection of its own, outside the pool
// answers use, one transaction per entry under the journal's two-int4
// advisory lock (condition C7). K_scope is a row of gateway.secrets, which
// the run-time role may read and insert and never replace (condition C8).

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

// refusalPGBound is one entry's transaction: a key service's signing (up
// to 5 seconds, ADR-0050) and the statements around it.
const refusalPGBound = 15 * time.Second

type refusalPG struct {
	kind *pgKind
	mu   sync.Mutex
	own  *pgConn
	// counted is, for each journal, the ordinal up to which its bytes are
	// summed in the scope's end
	counted map[string]int64
}

func newRefusalPG(kind *pgKind) *refusalPG {
	return &refusalPG{kind: kind, counted: map[string]int64{}}
}

// refusalLockKey is the second key of a journal's lock: the first four
// bytes of SHA-256 over its name, read as a signed integer.
func refusalLockKey(name string) int64 {
	sum := sha256.Sum256([]byte(name))
	return int64(int32(binary.BigEndian.Uint32(sum[:4])))
}

const pgRefusalLock = `SELECT pg_catalog.pg_advisory_xact_lock(($1)::int4, ($2)::int4)`

func (p *refusalPG) key(name string) ([]byte, bool, error) {
	secrets := pgSecrets{p.kind}
	k, err := secrets.getSecret(refusalKeyName(name))
	if err == nil {
		if len(k) != 32 {
			return nil, false, errors.New("the key is not 32 bytes")
		}
		return k, false, nil
	}
	if faultOf(err) != faultAbsent {
		return nil, false, err
	}
	held := false
	err = p.kind.transact(pgRead, func(tx pgTx) error {
		rows, err := tx.exec(`SELECT 1 FROM gateway.journal_records WHERE journal = $1 LIMIT 1`, name)
		held = err == nil && len(rows.rows) == 1
		return err
	})
	if err != nil {
		return nil, false, err
	}
	if held {
		return nil, true, nil
	}
	k = make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, false, err
	}
	if err := secrets.putSecret(refusalKeyName(name), k); err != nil {
		if faultOf(err) != faultTaken {
			return nil, false, err
		}
		// another instance made it first: that one is the key
		if k, err = secrets.getSecret(refusalKeyName(name)); err != nil {
			return nil, false, err
		}
	}
	return k, false, nil
}

// onOwn runs fn in one write transaction on the writer's own connection,
// opening it again where it failed.
func (p *refusalPG) onOwn(fn func(pgTx) error) error {
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
	return view.transactOn(p.own, deadline, pgWriteCommitted, fn)
}

func (p *refusalPG) append(s *refusalScope, entry func(end refusalEnd) ([]byte, error)) error {
	var next refusalEnd
	var counted int64
	err := p.onOwn(func(tx pgTx) error {
		if _, err := tx.exec(pgRefusalLock, pgRefusalJournalLockClass, refusalLockKey(s.name)); err != nil {
			return err
		}
		// The key the entry was made under is the journal's still:
		// remove-scope takes the key and the rows under this lock while an
		// instance serves, and an entry written after it would begin a
		// journal no key opens (ADR-0059 §8).
		held, err := tx.exec(`SELECT value FROM gateway.secrets WHERE name = $1`, refusalKeyName(s.name))
		if err != nil {
			return err
		}
		if len(held.rows) != 1 || !bytes.Equal(held.rows[0][0], s.secret) {
			return errRefusalKeyLost
		}
		end := s.end
		from := p.counted[s.name]
		if from == 0 {
			end.bytes = 0
		}
		rows, err := tx.exec(`SELECT pg_catalog.count(*)::int8, COALESCE(pg_catalog.sum(pg_catalog.octet_length(line) + 1), 0)::int8
			FROM gateway.journal_records WHERE journal = $1 AND ordinal >= $2`, s.name, from)
		if err != nil {
			return err
		}
		n, ok1 := pgInt8(rows.rows[0][0])
		b, ok2 := pgInt8(rows.rows[0][1])
		if !ok1 || !ok2 {
			return errors.New("store: the journal's length did not read")
		}
		end.bytes += b
		counted = from + n
		end.ordinal = counted
		if counted > 0 {
			last, err := tx.exec(`SELECT line FROM gateway.journal_records WHERE journal = $1 AND ordinal = $2`, s.name, counted-1)
			if err != nil {
				return err
			}
			if len(last.rows) != 1 {
				return errors.New("store: the journal's rows do not run from 0 with no gap")
			}
			end.previous = journalDigest(last.rows[0][0])
			end.lastKeyID, end.closed = lastEntryOf(last.rows[0][0])
		} else {
			end.previous, end.lastKeyID, end.closed = "", "", false
		}
		next = end
		line, err := entry(end)
		if err != nil || line == nil {
			return err
		}
		if _, err := tx.exec(`INSERT INTO gateway.journal_records (journal, ordinal, line) VALUES ($1, $2, $3)`, s.name, end.ordinal, line[:len(line)-1]); err != nil {
			return err
		}
		keyID, closed := lastEntryOf(line[:len(line)-1])
		next = refusalEnd{ordinal: end.ordinal + 1, previous: journalDigest(line[:len(line)-1]), bytes: end.bytes + int64(len(line)), lastKeyID: keyID, closed: closed}
		counted++
		return nil
	})
	if err != nil {
		// read the end again, whole, before the next entry
		delete(p.counted, s.name)
		return err
	}
	s.end = next
	p.counted[s.name] = counted
	if next.closed {
		s.closed = true
	}
	return nil
}

func (p *refusalPG) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.own != nil {
		p.own.close()
		p.own = nil
	}
}

// pgRemoveRefusalJournal removes a scope's refusal journal, its key and its
// forwarding cursor in the owner's transaction tx, under the journal's lock,
// and answers the bytes an export would have written of it.
func pgRemoveRefusalJournal(tx pgTx, scopeKey string) ([]byte, error) {
	name := refusalJournalName(scopeKey)
	if _, err := tx.exec(pgRefusalLock, pgRefusalJournalLockClass, refusalLockKey(name)); err != nil {
		return nil, err
	}
	data, err := pgJournalFile(tx, name)
	if err != nil {
		return nil, err
	}
	// the rows go last first, since each names the one before it
	if _, err := tx.exec(`DELETE FROM gateway.journal_records WHERE journal = $1`, name); err != nil {
		return nil, err
	}
	if _, err := tx.exec(`DELETE FROM gateway.secrets WHERE name = $1`, refusalKeyName(name)); err != nil {
		return nil, err
	}
	if _, err := tx.exec(`DELETE FROM gateway.documents WHERE scope = $1 AND name = $2`, pgNoScope, pgForwardingCursorName(name)); err != nil {
		return nil, err
	}
	return data, nil
}
