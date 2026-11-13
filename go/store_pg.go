package main

// The PostgreSQL storage kind (docs/adr/0031-a-second-storage-kind-on-postgresql.md,
// docs/postgresql-store.md): the store contract's spaces (store_contract.go)
// kept in tables of the schema `gateway` that store-migrate makes
// (store_pg/migrations), reached through the client in pgwire.go.
//
// Every operation is one transaction. It sets, for that transaction alone,
// the scope identifier its view of the kind is of (gateway.scope), the
// search path, a statement timeout and synchronous commit, so nothing a
// session, a role or a database set before decides what a transaction
// sees, how long it waits or whether its commit is durable. Row-level
// security keys on the scope setting; the kind also names its scope in
// every statement, so a policy and a filter both hold a transaction to it.
//
// The kind reads no clock of the database: a lease expires by the clock
// the kind is given (store_leases.go), and receipt times are the gateway's.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var _ storeKind = (*pgKind)(nil)

const (
	// pgDefaultConnections bounds the connections a kind holds open at once,
	// unless its configuration says otherwise; pgMaxConnections bounds what
	// a configuration may say.
	pgDefaultConnections = 4
	pgMaxConnections     = 64
	// pgDefaultOperation bounds one operation: waiting for a connection,
	// the transaction's statements and its commit.
	pgDefaultOperation = 30 * time.Second
	// pgAppendAttempts bounds how often an append is tried again when
	// another append took the log's end first.
	pgAppendAttempts = 32
	// pgMinServerVersion is PostgreSQL 16, the major version tested.
	pgMinServerVersion = 160000
)

// pgOptions is how a kind is opened.
type pgOptions struct {
	dsn         pgDSN
	connections int
	operation   time.Duration
	clock       func() time.Time
}

// pgPool holds a bounded number of connections, each used by one operation
// at a time. A connection that failed, or that is not idle when its
// operation ends, is closed and never handed out again.
type pgPool struct {
	dsn   pgDSN
	slots chan struct{}
	mu    sync.Mutex
	idle  []*pgConn
	done  bool
}

func newPgPool(dsn pgDSN, size int) *pgPool {
	return &pgPool{dsn: dsn, slots: make(chan struct{}, size)}
}

var errPgClosed = &pgTransportError{"the store is closed"}

func (p *pgPool) acquire(deadline time.Time) (*pgConn, error) {
	wait := time.NewTimer(time.Until(deadline))
	defer wait.Stop()
	select {
	case p.slots <- struct{}{}:
	case <-wait.C:
		return nil, &pgTransportError{"no connection to the database came free before the operation's deadline"}
	}
	p.mu.Lock()
	if p.done {
		p.mu.Unlock()
		<-p.slots
		return nil, errPgClosed
	}
	if n := len(p.idle); n > 0 {
		c := p.idle[n-1]
		p.idle = p.idle[:n-1]
		p.mu.Unlock()
		return c, nil
	}
	p.mu.Unlock()
	c, err := pgConnect(p.dsn, deadline)
	if err != nil {
		<-p.slots
		return nil, err
	}
	return c, nil
}

func (p *pgPool) release(c *pgConn) {
	defer func() { <-p.slots }()
	if c.broken || c.status != 'I' {
		c.close()
		return
	}
	p.mu.Lock()
	if p.done {
		p.mu.Unlock()
		c.close()
		return
	}
	p.idle = append(p.idle, c)
	p.mu.Unlock()
}

func (p *pgPool) close() {
	p.mu.Lock()
	p.done = true
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()
	for _, c := range idle {
		c.close()
	}
}

// pgKind is the kind, seen as one scope identifier sees it, or as no scope
// does (scope ""): every row it writes carries that scope, and it reads no
// other. Views of one kind share its connections.
type pgKind struct {
	pool      *pgPool
	scope     string
	operation time.Duration
	clock     func() time.Time
}

// openPgKind opens the kind and holds the database to the conditions the
// kind is run under (pgHoldsItsConditions), refusing to open otherwise.
func openPgKind(o pgOptions) (*pgKind, error) {
	if o.connections == 0 {
		o.connections = pgDefaultConnections
	}
	if o.connections < 1 || o.connections > pgMaxConnections {
		return nil, fmt.Errorf("store: a PostgreSQL store holds 1 to %d connections", pgMaxConnections)
	}
	if o.operation == 0 {
		o.operation = pgDefaultOperation
	}
	if o.operation < time.Second || o.operation > 10*time.Minute {
		return nil, errors.New("store: a PostgreSQL operation's deadline is 1 second to 10 minutes")
	}
	if o.clock == nil {
		o.clock = time.Now
	}
	k := &pgKind{pool: newPgPool(o.dsn, o.connections), operation: o.operation, clock: o.clock}
	if err := k.holdsItsConditions(pgShippedMigrations()); err != nil {
		k.close()
		return nil, err
	}
	return k, nil
}

// inScope is the view of the kind a scope identifier has: it writes rows of
// that scope and reads only those.
func (k *pgKind) inScope(scope string) (*pgKind, error) {
	if !isScopeIdentifier(scope) {
		return nil, errors.New("store: a PostgreSQL store's scope is a scope identifier: " + scopeForm)
	}
	view := *k
	view.scope = scope
	return &view, nil
}

func (k *pgKind) close() { k.pool.close() }

// pgTx is one transaction's statements.
type pgTx struct{ c *pgConn }

func (t pgTx) exec(query string, args ...any) (pgRows, error) { return t.c.exec(query, args...) }

// pgMode is a transaction's isolation level and access mode. Only these two
// levels are named, and only from here.
type pgMode struct {
	repeatable bool
	write      bool
}

var (
	pgRead           = pgMode{}
	pgReadSnapshot   = pgMode{repeatable: true}
	pgWriteCommitted = pgMode{write: true}
)

func (m pgMode) begin() string {
	level := "READ COMMITTED"
	if m.repeatable {
		level = "REPEATABLE READ"
	}
	access := "READ ONLY"
	if m.write {
		access = "READ WRITE"
	}
	return "BEGIN ISOLATION LEVEL " + level + " " + access
}

// pgCommitUnknown marks a failure after the commit was sent and before its
// answer came: the transaction may have been made durable or not.
type pgCommitUnknown struct{ error }

func (e pgCommitUnknown) Unwrap() error { return e.error }

// transact runs fn in one transaction of mode, with this view's scope set
// for that transaction alone, and commits it. A failure fn returns rolls it
// back; a commit the server answered other than COMMIT is a failure; a
// commit whose answer never came is pgCommitUnknown.
func (k *pgKind) transact(mode pgMode, fn func(pgTx) error) error {
	deadline := time.Now().Add(k.operation)
	c, err := k.pool.acquire(deadline)
	if err != nil {
		return err
	}
	defer k.pool.release(c)
	if err := c.conn.SetDeadline(deadline); err != nil {
		c.broken = true
		return pgTransport(err)
	}
	defer func() {
		if !c.broken {
			if c.conn.SetDeadline(time.Time{}) != nil {
				c.broken = true
			}
		}
	}()
	if _, err := c.exec(mode.begin()); err != nil {
		c.broken = true
		return err
	}
	timeout := strconv.FormatInt(k.operation.Milliseconds(), 10)
	if _, err := c.exec(`SELECT pg_catalog.set_config('gateway.scope', $1, true),
		pg_catalog.set_config('search_path', 'pg_catalog', true),
		pg_catalog.set_config('statement_timeout', $2, true),
		pg_catalog.set_config('lock_timeout', $2, true),
		pg_catalog.set_config('synchronous_commit', 'on', true)`, k.scope, timeout); err != nil {
		k.rollback(c)
		return err
	}
	if err := fn(pgTx{c}); err != nil {
		k.rollback(c)
		return err
	}
	done, err := c.exec("COMMIT")
	if err != nil {
		var transport *pgTransportError
		if errors.As(err, &transport) {
			return pgCommitUnknown{err}
		}
		k.rollback(c)
		return err
	}
	if done.tag != "COMMIT" {
		// the server answers ROLLBACK to a COMMIT of a transaction that failed
		return &pgTransportError{"the database rolled the transaction back"}
	}
	return nil
}

func (k *pgKind) rollback(c *pgConn) {
	if c.broken {
		return
	}
	if _, err := c.exec("ROLLBACK"); err != nil || c.status != 'I' {
		c.broken = true
	}
}

// pgFailure is a failure of a kind's operation, as a fault: one the kind
// raised itself (a refusal, an absence) as it is; a write that failed
// otherwise is a durability fault, a read an unreadable one.
func pgFailure(op string, write bool, err error) error {
	if faultOf(err) != "" {
		return err
	}
	if write {
		return storeFailure(faultDurability, op, err)
	}
	return storeFailure(faultUnreadable, op, err)
}

func pgRefused(op, what string) error {
	return storeFailure(faultRefused, op, errors.New("store: "+what))
}

func pgAbsent(op string) error { return storeFailure(faultAbsent, op, nil) }

// pgNames reads a statement's first column as names, sorted as the
// contract sorts them (byte order, which COLLATE "C" gives as well).
func pgNames(rows pgRows) []string {
	names := make([]string, 0, len(rows.rows))
	for _, row := range rows.rows {
		names = append(names, string(row[0]))
	}
	sort.Strings(names)
	return names
}

// --- blobs -----------------------------------------------------------------

type pgBlobs struct{ k *pgKind }

func (b pgBlobs) putBlob(data []byte) (string, error) {
	if len(data) > pgMaxValue {
		return "", pgRefused("put-blob", fmt.Sprintf("a blob of %d bytes is past the kind's bound of %d", len(data), pgMaxValue))
	}
	sum := sha256.Sum256(data)
	name := "sha256:" + hex.EncodeToString(sum[:])
	err := b.k.transact(pgWriteCommitted, func(tx pgTx) error {
		_, err := tx.exec(`INSERT INTO gateway.blobs (scope, name, data) VALUES ($1, $2, $3)
			ON CONFLICT (scope, name) DO NOTHING`, b.k.scope, name, data)
		return err
	})
	if err != nil {
		return "", pgFailure("put-blob", true, err)
	}
	return name, nil
}

func (b pgBlobs) getBlob(name string) ([]byte, error) {
	if _, ok := blobHex(name); !ok {
		return nil, pgRefused("get-blob", "not a blob's name")
	}
	var data []byte
	found := false
	err := b.k.transact(pgRead, func(tx pgTx) error {
		rows, err := tx.exec(`SELECT data FROM gateway.blobs WHERE scope = $1 AND name = $2`, b.k.scope, name)
		if err == nil && len(rows.rows) == 1 {
			data, found = rows.rows[0][0], true
		}
		return err
	})
	if err != nil {
		return nil, pgFailure("get-blob", false, err)
	}
	if !found {
		return nil, pgAbsent("get-blob")
	}
	return data, nil
}

func (b pgBlobs) listBlobs() ([]string, error) {
	var names []string
	err := b.k.transact(pgRead, func(tx pgTx) error {
		rows, err := tx.exec(`SELECT name FROM gateway.blobs WHERE scope = $1 ORDER BY name`, b.k.scope)
		names = pgNames(rows)
		return err
	})
	if err != nil {
		return nil, pgFailure("list-blobs", false, err)
	}
	return names, nil
}

// --- indexed entries -------------------------------------------------------

type pgIndexed struct{ k *pgKind }

func (x pgIndexed) makeSeries(series string) (bool, error) {
	if !validStoreName(series) {
		return false, pgRefused("make-series", "not a series' name")
	}
	made := false
	err := x.k.transact(pgWriteCommitted, func(tx pgTx) error {
		// a series of any scope holds its name: a session's name is one
		// across scopes, and one another scope made is never this call's
		rows, err := tx.exec(`INSERT INTO gateway.series (scope, name) VALUES ($1, $2)
			ON CONFLICT DO NOTHING RETURNING name`, x.k.scope, series)
		made = err == nil && len(rows.rows) == 1
		return err
	})
	if err != nil {
		return false, pgFailure("make-series", true, err)
	}
	return made, nil
}

func (x pgIndexed) createIndexed(series string, index int64, data []byte) error {
	if !validStoreName(series) {
		return pgRefused("create", "not a series' name")
	}
	if len(data) > pgMaxValue {
		return pgRefused("create", fmt.Sprintf("an entry of %d bytes is past the kind's bound of %d", len(data), pgMaxValue))
	}
	name := strconv.FormatInt(index, 10)
	made := false
	err := x.k.transact(pgWriteCommitted, func(tx pgTx) error {
		rows, err := tx.exec(`INSERT INTO gateway.entries (scope, series, name, data)
			SELECT s.scope, s.name, $3, $4 FROM gateway.series s WHERE s.scope = $1 AND s.name = $2
			RETURNING name`, x.k.scope, series, name, data)
		made = err == nil && len(rows.rows) == 1
		return err
	})
	switch {
	case pgCode(err) == pgUniqueViolation:
		return storeFailure(faultTaken, "create", fmt.Errorf("store: %s/%s is taken", series, name))
	case pgCode(err) == pgForeignKeyViolation:
		return pgAbsent("create")
	case err != nil:
		return pgFailure("create", true, err)
	case !made:
		// no series of this name in this scope: nothing was written
		return pgAbsent("create")
	}
	return nil
}

func (x pgIndexed) listSeries() ([]string, error) {
	var names []string
	err := x.k.transact(pgRead, func(tx pgTx) error {
		rows, err := tx.exec(`SELECT name FROM gateway.series WHERE scope = $1 ORDER BY name`, x.k.scope)
		names = pgNames(rows)
		return err
	})
	if err != nil {
		return nil, pgFailure("list-series", false, err)
	}
	return names, nil
}

func (x pgIndexed) listEntries(series string) ([]string, error) {
	var names []string
	there := false
	err := x.k.transact(pgRead, func(tx pgTx) error {
		rows, err := tx.exec(`SELECT e.name FROM gateway.series s
			LEFT JOIN gateway.entries e ON e.scope = s.scope AND e.series = s.name
			WHERE s.scope = $1 AND s.name = $2 ORDER BY e.name`, x.k.scope, series)
		if err != nil {
			return err
		}
		there = len(rows.rows) > 0
		for _, row := range rows.rows {
			if row[0] != nil {
				names = append(names, string(row[0]))
			}
		}
		sort.Strings(names)
		return nil
	})
	if err != nil {
		return nil, pgFailure("list-entries", false, err)
	}
	if !there {
		return nil, pgAbsent("list-entries")
	}
	return names, nil
}

func (x pgIndexed) getEntry(series, entry string) ([]byte, error) {
	if entry == "" || strings.ContainsAny(entry, `/\`) {
		return nil, pgRefused("get-entry", fmt.Sprintf("%q is not an entry's name", entry))
	}
	var data []byte
	found := false
	err := x.k.transact(pgRead, func(tx pgTx) error {
		rows, err := tx.exec(`SELECT data FROM gateway.entries WHERE scope = $1 AND series = $2 AND name = $3`, x.k.scope, series, entry)
		if err == nil && len(rows.rows) == 1 {
			data, found = rows.rows[0][0], true
		}
		return err
	})
	if err != nil {
		return nil, pgFailure("get-entry", false, err)
	}
	if !found {
		return nil, pgAbsent("get-entry")
	}
	return data, nil
}

// --- the log ---------------------------------------------------------------

// pgLog is the log named registry: records of no scope, one chain for every
// scope, appended at the offset the log has reached.
type pgLog struct {
	k    *pgKind
	name string
}

func (l pgLog) appendRecord(data []byte) (int, error) {
	if len(data) > pgMaxValue {
		return 0, &storeError{fault: faultRefused, op: "append", err: fmt.Errorf("store: a record of %d bytes is past the kind's bound of %d", len(data), pgMaxValue)}
	}
	for attempt := 0; attempt < pgAppendAttempts; attempt++ {
		made := false
		err := l.k.transact(pgWriteCommitted, func(tx pgTx) error {
			if len(data) == 0 {
				rows, err := tx.exec(`SELECT 1 FROM gateway.logs WHERE name = $1`, l.name)
				made = err == nil && len(rows.rows) == 1
				return err
			}
			// the record starts where the last one stops; two appends that
			// read one end cannot both write there (the primary key), and
			// the one refused tries again from the new end
			rows, err := tx.exec(`INSERT INTO gateway.log_records (log, start, data)
				SELECT g.name, COALESCE((SELECT r.stop FROM gateway.log_records r
					WHERE r.log = g.name ORDER BY r.start DESC LIMIT 1), 0), $2
				FROM gateway.logs g WHERE g.name = $1
				RETURNING start`, l.name, data)
			made = err == nil && len(rows.rows) == 1
			return err
		})
		if pgCode(err) == pgUniqueViolation {
			continue
		}
		var unknown pgCommitUnknown
		switch {
		case errors.As(err, &unknown):
			// written whole; whether it was made durable is not known
			return len(data), &storeError{fault: faultDurability, op: "append", written: len(data), committing: true, err: err}
		case err != nil:
			return 0, &storeError{fault: faultDurability, op: "append", err: err}
		case !made:
			return 0, &storeError{fault: faultAbsent, op: "append"}
		}
		return len(data), nil
	}
	return 0, &storeError{fault: faultDurability, op: "append", err: errors.New("store: the log's end moved under every attempt to append")}
}

// readTx reads the log from a cursor within a transaction already open.
func (l pgLog) readTx(tx pgTx, from int64) ([]byte, bool, error) {
	head, err := tx.exec(`SELECT EXISTS (SELECT 1 FROM gateway.logs WHERE name = $1),
		COALESCE((SELECT r.stop FROM gateway.log_records r WHERE r.log = $1 ORDER BY r.start DESC LIMIT 1), 0)`, l.name)
	if err != nil {
		return nil, false, err
	}
	if len(head.rows) != 1 {
		return nil, false, errors.New("store: the log's head did not read")
	}
	present, ok1 := pgBool(head.rows[0][0])
	end, ok2 := pgInt8(head.rows[0][1])
	if !ok1 || !ok2 {
		return nil, false, errors.New("store: the log's head did not read")
	}
	if !present {
		return nil, false, nil
	}
	if from > end {
		return nil, true, pgRefused("read-log", "the cursor is not within the log")
	}
	rows, err := tx.exec(`SELECT start, data FROM gateway.log_records WHERE log = $1 AND stop > $2 ORDER BY start`, l.name, from)
	if err != nil {
		return nil, true, err
	}
	// the records hold the log whole: each starts where the one before it
	// stops, the first at or before the cursor, the last at the end
	var out []byte
	at := from
	for i, row := range rows.rows {
		start, ok := pgInt8(row[0])
		if !ok {
			return nil, true, errors.New("store: a log record did not read")
		}
		data := row[1]
		if i == 0 {
			if start > from {
				return nil, true, storeFailure(faultUnreadable, "read-log", errors.New("store: the log has a gap"))
			}
			data = data[from-start:]
		} else if start != at {
			return nil, true, storeFailure(faultUnreadable, "read-log", errors.New("store: the log's records do not follow one another"))
		}
		out = append(out, data...)
		at = start + int64(len(row[1]))
	}
	if at != end {
		return nil, true, storeFailure(faultUnreadable, "read-log", errors.New("store: the log's records do not reach its end"))
	}
	return out, true, nil
}

func (l pgLog) readLog(from int64) ([]byte, error) {
	if from < 0 {
		return nil, pgRefused("read-log", "the cursor is not within the log")
	}
	var out []byte
	present := false
	err := l.k.transact(pgReadSnapshot, func(tx pgTx) error {
		var err error
		out, present, err = l.readTx(tx, from)
		return err
	})
	if err != nil {
		return nil, pgFailure("read-log", false, err)
	}
	if !present {
		return nil, pgAbsent("read-log")
	}
	return out, nil
}

func (l pgLog) createLog() error {
	made := false
	err := l.k.transact(pgWriteCommitted, func(tx pgTx) error {
		rows, err := tx.exec(`INSERT INTO gateway.logs (name) VALUES ($1) ON CONFLICT DO NOTHING RETURNING name`, l.name)
		made = err == nil && len(rows.rows) == 1
		return err
	})
	if err != nil {
		return pgFailure("create-log", true, err)
	}
	if !made {
		return storeFailure(faultTaken, "create-log", errors.New("store: the log is there"))
	}
	return nil
}

// --- documents -------------------------------------------------------------

type pgDocuments struct{ k *pgKind }

// newRevision is a document revision: random, so a document deleted and
// made again takes a revision of its own, and counted by no sequence, which
// would be one across scopes.
func newRevision() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func (d pgDocuments) getDocument(name string) ([]byte, string, error) {
	var data []byte
	revision := noRevision
	found := false
	err := d.k.transact(pgRead, func(tx pgTx) error {
		rows, err := tx.exec(`SELECT data, revision FROM gateway.documents WHERE scope = $1 AND name = $2`, d.k.scope, name)
		if err == nil && len(rows.rows) == 1 {
			data, revision, found = rows.rows[0][0], string(rows.rows[0][1]), true
		}
		return err
	})
	if err != nil {
		return nil, noRevision, pgFailure("get-document", false, err)
	}
	if !found {
		return nil, noRevision, pgAbsent("get-document")
	}
	return data, revision, nil
}

func (d pgDocuments) putDocument(name string, data []byte, expected string) (string, error) {
	if !validStoreName(name) {
		return noRevision, pgRefused("put-document", "not a document's name")
	}
	if len(data) > pgMaxValue {
		return noRevision, pgRefused("put-document", fmt.Sprintf("a document of %d bytes is past the kind's bound of %d", len(data), pgMaxValue))
	}
	next, err := newRevision()
	if err != nil {
		return noRevision, storeFailure(faultDurability, "put-document", err)
	}
	put := false
	err = d.k.transact(pgWriteCommitted, func(tx pgTx) error {
		var rows pgRows
		var err error
		if expected == noRevision {
			rows, err = tx.exec(`INSERT INTO gateway.documents (scope, name, revision, data) VALUES ($1, $2, $3, $4)
				ON CONFLICT (scope, name) DO NOTHING RETURNING revision`, d.k.scope, name, next, data)
		} else {
			// the row is locked by the update, and a concurrent writer's
			// update waits and then finds the revision it expected gone
			rows, err = tx.exec(`UPDATE gateway.documents SET revision = $3, data = $4
				WHERE scope = $1 AND name = $2 AND revision = $5 RETURNING revision`, d.k.scope, name, next, data, expected)
		}
		put = err == nil && len(rows.rows) == 1
		return err
	})
	if err != nil {
		return noRevision, pgFailure("put-document", true, err)
	}
	if !put {
		return noRevision, storeFailure(faultConflict, "put-document", fmt.Errorf("store: %s is at another revision", name))
	}
	return next, nil
}

func (d pgDocuments) deleteDocument(name, expected string) error {
	if !validStoreName(name) {
		return pgRefused("delete-document", "not a document's name")
	}
	deleted, there := false, false
	err := d.k.transact(pgWriteCommitted, func(tx pgTx) error {
		if expected != noRevision {
			rows, err := tx.exec(`DELETE FROM gateway.documents WHERE scope = $1 AND name = $2 AND revision = $3 RETURNING name`, d.k.scope, name, expected)
			if err != nil {
				return err
			}
			if deleted = len(rows.rows) == 1; deleted {
				return nil
			}
		}
		rows, err := tx.exec(`SELECT 1 FROM gateway.documents WHERE scope = $1 AND name = $2`, d.k.scope, name)
		there = err == nil && len(rows.rows) == 1
		return err
	})
	switch {
	case err != nil:
		return pgFailure("delete-document", true, err)
	case deleted:
		return nil
	case there:
		return storeFailure(faultConflict, "delete-document", fmt.Errorf("store: %s is at another revision", name))
	}
	return pgAbsent("delete-document")
}

func (d pgDocuments) listDocuments() ([]string, error) {
	var names []string
	err := d.k.transact(pgRead, func(tx pgTx) error {
		rows, err := tx.exec(`SELECT name FROM gateway.documents WHERE scope = $1 ORDER BY name`, d.k.scope)
		names = pgNames(rows)
		return err
	})
	if err != nil {
		return nil, pgFailure("list-documents", false, err)
	}
	return names, nil
}

// --- secrets ---------------------------------------------------------------

type pgSecrets struct{ k *pgKind }

func (s pgSecrets) putSecret(name string, value []byte) error {
	if !validStoreName(name) {
		return pgRefused("put-secret", "not a secret's name")
	}
	made := false
	err := s.k.transact(pgWriteCommitted, func(tx pgTx) error {
		rows, err := tx.exec(`INSERT INTO gateway.secrets (name, value) VALUES ($1, $2) ON CONFLICT DO NOTHING RETURNING name`, name, value)
		made = err == nil && len(rows.rows) == 1
		return err
	})
	if err != nil {
		return pgFailure("put-secret", true, err)
	}
	if !made {
		return storeFailure(faultTaken, "put-secret", errors.New("store: the secret is there"))
	}
	return nil
}

func (s pgSecrets) getSecret(name string) ([]byte, error) {
	var value []byte
	found := false
	err := s.k.transact(pgRead, func(tx pgTx) error {
		rows, err := tx.exec(`SELECT value FROM gateway.secrets WHERE name = $1`, name)
		if err == nil && len(rows.rows) == 1 {
			value, found = rows.rows[0][0], true
		}
		return err
	})
	if err != nil {
		return nil, pgFailure("get-secret", false, err)
	}
	if !found {
		return nil, pgAbsent("get-secret")
	}
	return value, nil
}

// --- the kind --------------------------------------------------------------

func (k *pgKind) artifacts() blobSpace     { return pgBlobs{k} }
func (k *pgKind) receipts() indexedSpace   { return pgIndexed{k} }
func (k *pgKind) registry() appendLog      { return pgLog{k: k, name: "registry"} }
func (k *pgKind) documents() documentSpace { return leaseDocumentsReserved{pgDocuments{k}} }
func (k *pgKind) secrets() secretSpace     { return pgSecrets{k} }

// leases are documents of the view's scope, read and listed through its
// document space as any other document is (store_leases.go).
func (k *pgKind) leases() leaseSpace {
	return documentLeases{docs: pgDocuments{k}, clock: k.clock}
}

// snapshot lists every space in one transaction at REPEATABLE READ: the cut
// is a state the kind was in, as this view sees it. An entry or a blob is
// never changed once made, so its bytes are read when the cut is asked.
func (k *pgKind) snapshot() (*storeCut, error) {
	cut := &storeCut{documents: map[string][]byte{}, revisions: map[string]string{}, entries: map[string][]string{}}
	err := k.transact(pgReadSnapshot, func(tx pgTx) error {
		log, present, err := pgLog{k: k, name: "registry"}.readTx(tx, 0)
		if err != nil {
			return err
		}
		cut.log, cut.logPresent = log, present
		docs, err := tx.exec(`SELECT name, revision, data FROM gateway.documents WHERE scope = $1`, k.scope)
		if err != nil {
			return err
		}
		for _, row := range docs.rows {
			cut.documents[string(row[0])] = row[2]
			cut.revisions[string(row[0])] = string(row[1])
		}
		series, err := tx.exec(`SELECT name FROM gateway.series WHERE scope = $1`, k.scope)
		if err != nil {
			return err
		}
		cut.series = pgNames(series)
		for _, s := range cut.series {
			cut.entries[s] = []string{}
		}
		entries, err := tx.exec(`SELECT series, name FROM gateway.entries WHERE scope = $1`, k.scope)
		if err != nil {
			return err
		}
		for _, row := range entries.rows {
			cut.entries[string(row[0])] = append(cut.entries[string(row[0])], string(row[1]))
		}
		for _, names := range cut.entries {
			sort.Strings(names)
		}
		blobs, err := tx.exec(`SELECT name FROM gateway.blobs WHERE scope = $1`, k.scope)
		if err != nil {
			return err
		}
		cut.blobs = pgNames(blobs)
		return nil
	})
	if err != nil {
		return nil, pgFailure("snapshot", false, err)
	}
	cut.entry = pgIndexed{k}.getEntry
	cut.blob = pgBlobs{k}.getBlob
	return cut, nil
}
