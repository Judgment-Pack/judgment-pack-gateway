package main

// Refusal entries at a sink on delivery "3" (ADR-0059 section 9): the seam
// through which the refusal journal hands its entries to the sink, the
// forwarding owner that decides which instance forwards which entries
// (condition C5), and each journal's forwarding cursor. The refusal journal
// fills the seam (refusal_entry_source.go) where it is configured; where it
// is not, noRefusalEntries names no journal and nothing is forwarded.
// A sink that declines refusal entries (receiptSink.refusalEntries false,
// condition C11) is given no forwarding at all, and no cursor is written.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	// refusalForwardEvery is how often a journal's entries not yet
	// acknowledged are sent again, oldest first: at most once every 5
	// seconds for each journal.
	refusalForwardEvery = 5 * time.Second
	// refusalForwardBatch bounds the entries one pass sends for a journal.
	refusalForwardBatch = 64
	// refusalForwardedSuffix names a journal's cursor on the filesystem
	// kind: <root>/journals/<name>.forwarded.
	refusalForwardedSuffix = ".forwarded"
	// refusalForwardedDocument prefixes a cursor's name among the
	// PostgreSQL kind's documents of no scope, before the SHA-256 of the
	// journal's name.
	refusalForwardedDocument = "refusal-forwarded."
)

// refusalJournalNamePattern is gateway.journal_records' name rule, which a
// refusal journal's name, refusal- and 24 letters, fits.
var refusalJournalNamePattern = regexp.MustCompile(`^[a-z-]{1,32}$`)

// refusalEntryLine is one entry of a refusal journal: its ordinal and its
// line without the line feed; on the filesystem kind, at is the offset in
// the journal's file where the line begins.
type refusalEntryLine struct {
	ordinal int64
	line    []byte
	at      int64
}

// refusalEntrySource is the seam the refusal journal fills (ADR-0059
// section 9; R2 of its build plan): the forwarding owner calls it for the
// entries it forwards, and for nothing else.
type refusalEntrySource interface {
	// journals names the refusal journals there are, sorted.
	journals() ([]string, error)
	// entriesAfter is the journal's entries past ordinal, oldest first, at
	// most limit, whichever instance appended them.
	entriesAfter(journal string, ordinal int64, limit int) ([]refusalEntryLine, error)
	// cursors is the journals' forwarding cursors as a pass reads them
	// first, outside every lock: on the PostgreSQL kind on the source's own
	// connection, never on the pool.
	cursors() forwardingCursors
	// locked runs fn under the journal's lock (ADR-0059 section 7), the one
	// its appends take, so the cursor moves under it; and only where the
	// journal, under that lock, still holds at, the entry the cursor is to
	// name. Where it does not, the journal was removed or begun again since
	// at was read, and fn is not run: the next pass reads again. fn is
	// given the cursors bound to that lock: on the PostgreSQL kind, the
	// cursor's read and its compare-and-set are statements of the
	// transaction that holds the lock, so no remove-scope comes between the
	// lock and the put. fn moves the cursor and nothing else: no delivery,
	// no signing, and on the PostgreSQL kind no other use of the source.
	locked(journal string, at refusalEntryLine, fn func(forwardingCursors) error) error
}

// noRefusalEntries is the seam where no refusal journal is configured: no
// journal, so nothing is forwarded and no cursor is read or written. Its
// cursors are itself: none, and never moved.
type noRefusalEntries struct{}

func (noRefusalEntries) journals() ([]string, error) { return nil, nil }
func (noRefusalEntries) entriesAfter(string, int64, int) ([]refusalEntryLine, error) {
	return nil, nil
}
func (noRefusalEntries) cursors() forwardingCursors { return noRefusalEntries{} }
func (noRefusalEntries) locked(string, refusalEntryLine, func(forwardingCursors) error) error {
	return nil
}
func (noRefusalEntries) read(string) (forwardingCursor, error) {
	return forwardingCursor{ordinal: -1}, nil
}
func (noRefusalEntries) advance(string, int64, forwardingCursor) (bool, error) { return false, nil }

// forwardingCursor is a journal's forwarding progress: the highest ordinal
// the sink acknowledged, and that entry's digest; ordinal -1 for none.
type forwardingCursor struct {
	ordinal int64
	digest  string
}

// errCursorBackwards refuses a cursor moved to an ordinal that is not past
// the one it was read at.
var errCursorBackwards = errors.New("a forwarding cursor moves only to a greater ordinal")

// errCursorDiverged stops the forwarding of a journal whose entry at the
// cursor's ordinal is not the one the sink acknowledged there: a journal
// recreated or rotated under the same name. Nothing more of it is forwarded,
// rather than entries the sink would take for the old journal's.
var errCursorDiverged = errors.New("the refusal journal's entry at its forwarding cursor is not the one the sink acknowledged; nothing more of it is forwarded")

// forwardingCursors keeps each journal's cursor. No verifier reads it and no
// export carries it.
type forwardingCursors interface {
	read(journal string) (forwardingCursor, error)
	// advance is the monotone compare-and-set (condition C5): the cursor is
	// replaced by to only where it still holds the ordinal from, read before
	// the delivery, and only by a greater ordinal. Where another instance
	// moved it first, the greater value stays, and moved is false: the
	// caller reads again.
	advance(journal string, from int64, to forwardingCursor) (moved bool, err error)
}

func encodeForwardingCursor(journal string, c forwardingCursor) []byte {
	return []byte(fmt.Sprintf(`{"digest":%q,"journal":%q,"ordinal":%d}`, c.digest, journal, c.ordinal))
}

// decodeForwardingCursor reads a cursor's bytes, held to its form and to the
// journal it is named for; anything else is an error, never a cursor at -1,
// which would send every entry again under a name the sink may not know.
func decodeForwardingCursor(journal string, data []byte) (forwardingCursor, error) {
	var form struct {
		Digest  string `json:"digest"`
		Journal string `json:"journal"`
		Ordinal *int64 `json:"ordinal"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&form); err != nil || decoder.More() {
		return forwardingCursor{}, fmt.Errorf("the forwarding cursor of %s is not one", journal)
	}
	hexSum, prefixed := strings.CutPrefix(form.Digest, "sha256:")
	if _, err := hex.DecodeString(hexSum); !prefixed || err != nil || len(hexSum) != 64 ||
		form.Journal != journal || form.Ordinal == nil || *form.Ordinal < 0 ||
		!bytes.Equal(data, encodeForwardingCursor(journal, forwardingCursor{*form.Ordinal, form.Digest})) {
		return forwardingCursor{}, fmt.Errorf("the forwarding cursor of %s is not one", journal)
	}
	return forwardingCursor{ordinal: *form.Ordinal, digest: form.Digest}, nil
}

func holdRefusalJournalName(journal string) error {
	if !refusalJournalNamePattern.MatchString(journal) {
		return errors.New("a refusal journal's name is 1 to 32 lowercase letters and hyphens")
	}
	return nil
}

// fsForwardingCursors is the filesystem kind's cursors:
// <root>/journals/<name>.forwarded, staged, synced and renamed into place.
// One process serves a store of this kind, so the compare-and-set is made
// under mu, inside the journal's lock.
type fsForwardingCursors struct {
	root string
	mu   *sync.Mutex
}

// stagedCursorForm is the name fsWriteFile stages a cursor under before it
// renames it into place: the cursor's name, the process's identifier and
// twelve lowercase hexadecimal digits, then .tmp. A process ended between
// the two leaves it in journals/.
var stagedCursorForm = regexp.MustCompile(`^(refusal-[a-p]{24})\.forwarded\.[0-9]{1,10}\.[0-9a-f]{12}\.tmp$`)

// stagedCursorJournal is the refusal journal whose cursor a file so named
// stages, where the name is of that exact form.
func stagedCursorJournal(name string) (string, bool) {
	m := stagedCursorForm.FindStringSubmatch(name)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// removeStaged removes the staging files a process ended mid-write left for
// these journals' cursors, before the owner writes any: only a regular file
// of the exact form for one of them, never a link or anything else, and
// never another journal's.
func (c fsForwardingCursors) removeStaged(journals []string) error {
	dir := filepath.Join(c.root, "journals")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	own := map[string]bool{}
	for _, journal := range journals {
		own[journal] = true
	}
	removed := false
	for _, e := range entries {
		journal, staged := stagedCursorJournal(e.Name())
		if !staged || !own[journal] || !e.Type().IsRegular() {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		removed = true
	}
	if removed {
		syncDir(dir)
	}
	return nil
}

func (c fsForwardingCursors) path(journal string) string {
	return filepath.Join(c.root, "journals", journal+refusalForwardedSuffix)
}

func (c fsForwardingCursors) read(journal string) (forwardingCursor, error) {
	if err := holdRefusalJournalName(journal); err != nil {
		return forwardingCursor{}, err
	}
	data, err := os.ReadFile(c.path(journal))
	if errors.Is(err, fs.ErrNotExist) {
		return forwardingCursor{ordinal: -1}, nil
	}
	if err != nil {
		return forwardingCursor{}, err
	}
	line, whole := bytes.CutSuffix(data, []byte{'\n'})
	if !whole {
		return forwardingCursor{}, fmt.Errorf("the forwarding cursor of %s is not one", journal)
	}
	return decodeForwardingCursor(journal, line)
}

func (c fsForwardingCursors) advance(journal string, from int64, to forwardingCursor) (bool, error) {
	if to.ordinal <= from {
		return false, errCursorBackwards
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now, err := c.read(journal)
	if err != nil {
		return false, err
	}
	if now.ordinal != from {
		return false, nil
	}
	dir := filepath.Join(c.root, "journals")
	if err := os.Mkdir(dir, 0o700); err == nil {
		syncDir(c.root)
	} else if !errors.Is(err, fs.ErrExist) {
		return false, err
	}
	if err := fsWriteFile(c.path(journal), append(encodeForwardingCursor(journal, to), '\n'), false); err != nil {
		return false, err
	}
	return true, nil
}

// pgForwardingCursors is the PostgreSQL kind's cursors: documents of no
// scope, named refusalForwardedDocument and the SHA-256 of the journal's
// name. The compare-and-set is the document's revision: a put at the
// revision read, so of two instances that read one cursor, one moves it and
// the other is told it moved. The owner's are on its source's own
// connection (pgRefusalEntries.cursors), and under the journal's lock on
// the transaction that holds it (pgRefusalEntries.locked).
type pgForwardingCursors struct{ docs cursorDocuments }

// cursorDocuments is what a cursor needs of a document space: its get, and
// its put at a revision.
type cursorDocuments interface {
	getDocument(name string) ([]byte, string, error)
	putDocument(name string, data []byte, expected string) (string, error)
}

func pgForwardingCursorName(journal string) string {
	sum := sha256.Sum256([]byte(journal))
	return refusalForwardedDocument + hex.EncodeToString(sum[:])
}

func (c pgForwardingCursors) load(journal string) (forwardingCursor, string, error) {
	if err := holdRefusalJournalName(journal); err != nil {
		return forwardingCursor{}, "", err
	}
	data, revision, err := c.docs.getDocument(pgForwardingCursorName(journal))
	if faultOf(err) == faultAbsent {
		return forwardingCursor{ordinal: -1}, noRevision, nil
	}
	if err != nil {
		return forwardingCursor{}, "", err
	}
	cursor, err := decodeForwardingCursor(journal, data)
	return cursor, revision, err
}

func (c pgForwardingCursors) read(journal string) (forwardingCursor, error) {
	cursor, _, err := c.load(journal)
	return cursor, err
}

func (c pgForwardingCursors) advance(journal string, from int64, to forwardingCursor) (bool, error) {
	if to.ordinal <= from {
		return false, errCursorBackwards
	}
	now, revision, err := c.load(journal)
	if err != nil {
		return false, err
	}
	if now.ordinal != from {
		return false, nil
	}
	_, err = c.docs.putDocument(pgForwardingCursorName(journal), encodeForwardingCursor(journal, to), revision)
	if faultOf(err) == faultConflict {
		return false, nil
	}
	return err == nil, err
}

// refusalEntryForwarding is the forwarding owner (condition C5). On the
// PostgreSQL kind with several instances, every instance's owner forwards
// every journal from the one cursor, whichever instance appended the
// entries: it delivers the entries after the cursor, oldest first, outside
// the journal's lock, and then moves the cursor under that lock by the
// monotone compare-and-set. Where another instance moved it first, the
// greater value stays, and the next pass reads again: no ordinal is passed
// over, two instances may each send one entry, and the sink deduplicates
// them by digest. It sends through a forwarder, and so an HTTP transport, of
// its own, one delivery in flight gateway-wide, and never holds a request,
// an answer or a receipt's delivery.
type refusalEntryForwarding struct {
	forwarder *receiptForwarder
	// source is the journals, and their cursors with them
	source   refusalEntrySource
	inFlight sync.Mutex
	// stderr is where a journal that stops at a diverged cursor is named,
	// once for each journal (diverged): it is forwarded no more until the
	// maintainer looks at it, and a stop that says nothing is a journal
	// forgotten for good
	stderr     io.Writer
	divergedMu sync.Mutex
	diverged   map[string]bool
}

// newRefusalEntryForwarding is the owner for a sink, or nil: for a sink not
// on "3", and for one that declines refusal entries, nothing is forwarded
// and no cursor is written (condition C11).
func newRefusalEntryForwarding(spec *receiptSinkSpec, source refusalEntrySource) *refusalEntryForwarding {
	if spec == nil || !spec.deliveryV3 || !spec.refusalEntries {
		return nil
	}
	return &refusalEntryForwarding{forwarder: newReceiptForwarder(spec), source: source, stderr: os.Stderr, diverged: map[string]bool{}}
}

// divergedOnce names a journal whose forwarding stopped at a diverged
// cursor, the first time it is met. The line names the journal and nothing
// of its entries: no key, no commitment, no digest.
func (r *refusalEntryForwarding) divergedOnce(journal string) {
	r.divergedMu.Lock()
	defer r.divergedMu.Unlock()
	if r.diverged[journal] {
		return
	}
	r.diverged[journal] = true
	fmt.Fprintf(r.stderr, "refusal entry forwarding: journal %q: %v\n", journal, errCursorDiverged)
}

// forwardJournal is one pass over one journal: the entries after its
// cursor, oldest first, each acknowledged before the next is sent, and the
// cursor moved past the last acknowledged. Every read and every delivery is
// made outside the journal's lock, and outside any transaction: locked
// only checks the entry again and moves the cursor.
func (r *refusalEntryForwarding) forwardJournal(ctx context.Context, journal string) error {
	if r == nil {
		return nil
	}
	from, err := r.source.cursors().read(journal)
	if err != nil {
		return err
	}
	// one read: the entry at the cursor, where there is one, and the batch
	// after it
	after, limit := from.ordinal, refusalForwardBatch
	if from.ordinal >= 0 {
		after, limit = from.ordinal-1, refusalForwardBatch+1
	}
	entries, err := r.source.entriesAfter(journal, after, limit)
	if err != nil {
		return err
	}
	if from.ordinal >= 0 {
		// the entry at the cursor is the one acknowledged there
		if len(entries) == 0 || entries[0].ordinal != from.ordinal {
			return errCursorDiverged
		}
		if held, err := r.forwarder.heldRefusalEntry(journal, entries[0].line); err != nil || held.digest != from.digest {
			return errCursorDiverged
		}
		entries = entries[1:]
	}
	reached := from
	var last refusalEntryLine
	for _, entry := range entries {
		if entry.ordinal != reached.ordinal+1 {
			break // no ordinal is passed over
		}
		held, err := r.forwarder.heldRefusalEntry(journal, entry.line)
		if err != nil || !r.deliver(ctx, held) {
			break
		}
		reached, last = forwardingCursor{ordinal: entry.ordinal, digest: held.digest}, entry
	}
	if reached.ordinal == from.ordinal {
		return nil
	}
	return r.source.locked(journal, last, func(cursors forwardingCursors) error {
		_, err := cursors.advance(journal, from.ordinal, reached)
		return err
	})
}

func (r *refusalEntryForwarding) deliver(ctx context.Context, held heldReceipt) bool {
	r.inFlight.Lock()
	defer r.inFlight.Unlock()
	return r.forwarder.deliverOne(ctx, held)
}

// forwardAll is one pass over every journal the seam names.
func (r *refusalEntryForwarding) forwardAll(ctx context.Context) {
	if r == nil {
		return
	}
	names, err := r.source.journals()
	if err != nil {
		return
	}
	for _, journal := range names {
		if ctx.Err() != nil {
			return
		}
		// a sink that is down is tried again on the next pass; a diverged
		// cursor is not, and is named
		if err := r.forwardJournal(ctx, journal); errors.Is(err, errCursorDiverged) {
			r.divergedOnce(journal)
		}
	}
}

// clearStaged removes, on the filesystem kind and before the first pass, the
// cursor staging files a process ended mid-write left for the owner's own
// journals; each would otherwise be in journals/ until the maintainer took
// it away. A failure is the next start's to try again.
func (r *refusalEntryForwarding) clearStaged() {
	if r == nil {
		return
	}
	c, onFS := r.source.cursors().(fsForwardingCursors)
	if !onFS {
		return
	}
	if names, err := r.source.journals(); err == nil {
		c.removeStaged(names)
	}
}

// run passes over every journal every refusalForwardEvery until ctx ends.
func (r *refusalEntryForwarding) run(ctx context.Context, every time.Duration) {
	if r == nil {
		return
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			r.forwardAll(ctx)
		}
	}
}

// refusalEntryForwardingOf is the service's owner where its sink is on "3"
// and takes refusal entries, over its configured refusal journals
// (refusalEntrySourceOf), or nil; it is not started.
func (g *gatewayService) refusalEntryForwardingOf() *refusalEntryForwarding {
	f := g.forwarder
	if f == nil || !f.v3 || !f.refusalEntries {
		return nil
	}
	return newRefusalEntryForwarding(&receiptSinkSpec{url: f.url, deliveryV3: true, refusalEntries: true}, g.refusalEntrySourceOf())
}

// startRefusalEntryForwarding starts the service's owner, under its
// lifetime, where its sink is on "3" and takes refusal entries. Its source's
// own connection, on the PostgreSQL kind, is closed when the lifetime ends.
func startRefusalEntryForwarding(g *gatewayService) {
	owner := g.refusalEntryForwardingOf()
	if owner == nil {
		return
	}
	g.refusalForwarding = owner
	owner.clearStaged()
	go func() {
		owner.run(g.forwardingContext(), refusalForwardEvery)
		if c, ok := owner.source.(interface{ close() }); ok {
			c.close()
		}
	}()
}
