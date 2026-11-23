package main

// Refusal entries at a sink on delivery "3" (ADR-0059 section 9): the seam
// through which the refusal journal hands its entries to the sink, the
// forwarding owner that decides which instance forwards which entries
// (condition C5), and each journal's forwarding cursor. The refusal journal
// is not part of this change: refusalEntrySource is the seam it fills, and
// until it does, noRefusalEntries names no journal and nothing is forwarded.
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
// line without the line feed.
type refusalEntryLine struct {
	ordinal int64
	line    []byte
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
	// locked runs fn under the journal's lock (ADR-0059 section 7), the one
	// its appends take, so the cursor moves under it.
	locked(journal string, fn func() error) error
}

// noRefusalEntries is the seam as this change leaves it: no journal, so
// nothing is forwarded and no cursor is read or written.
type noRefusalEntries struct{}

func (noRefusalEntries) journals() ([]string, error) { return nil, nil }
func (noRefusalEntries) entriesAfter(string, int64, int) ([]refusalEntryLine, error) {
	return nil, nil
}
func (noRefusalEntries) locked(_ string, fn func() error) error { return fn() }

// forwardingCursor is a journal's forwarding progress: the highest ordinal
// the sink acknowledged, and that entry's digest; ordinal -1 for none.
type forwardingCursor struct {
	ordinal int64
	digest  string
}

// errCursorBackwards refuses a cursor moved to an ordinal that is not past
// the one it was read at.
var errCursorBackwards = errors.New("a forwarding cursor moves only to a greater ordinal")

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
// the other is told it moved.
type pgForwardingCursors struct{ docs documentSpace }

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

// forwardingCursors is the service's cursors, on its kind.
func (g *gatewayService) forwardingCursors() forwardingCursors {
	if kind, onKind := g.kind.(*pgKind); onKind {
		return pgForwardingCursors{kind.ofNoScope().documents()}
	}
	return fsForwardingCursors{root: g.storeRoot, mu: &sync.Mutex{}}
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
	source    refusalEntrySource
	cursors   forwardingCursors
	inFlight  sync.Mutex
}

// newRefusalEntryForwarding is the owner for a sink, or nil: for a sink not
// on "3", and for one that declines refusal entries, nothing is forwarded
// and no cursor is written (condition C11).
func newRefusalEntryForwarding(spec *receiptSinkSpec, source refusalEntrySource, cursors forwardingCursors) *refusalEntryForwarding {
	if spec == nil || !spec.deliveryV3 || !spec.refusalEntries {
		return nil
	}
	return &refusalEntryForwarding{forwarder: newReceiptForwarder(spec), source: source, cursors: cursors}
}

// forwardJournal is one pass over one journal: the entries after its
// cursor, oldest first, each acknowledged before the next is sent, and the
// cursor moved past the last acknowledged.
func (r *refusalEntryForwarding) forwardJournal(ctx context.Context, journal string) error {
	if r == nil {
		return nil
	}
	from, err := r.cursors.read(journal)
	if err != nil {
		return err
	}
	entries, err := r.source.entriesAfter(journal, from.ordinal, refusalForwardBatch)
	if err != nil {
		return err
	}
	reached := from
	for _, entry := range entries {
		if entry.ordinal != reached.ordinal+1 {
			break // no ordinal is passed over
		}
		held, err := r.forwarder.heldRefusalEntry(journal, entry.line)
		if err != nil || !r.deliver(ctx, held) {
			break
		}
		reached = forwardingCursor{ordinal: entry.ordinal, digest: held.digest}
	}
	if reached.ordinal == from.ordinal {
		return nil
	}
	return r.source.locked(journal, func() error {
		_, err := r.cursors.advance(journal, from.ordinal, reached)
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
		_ = r.forwardJournal(ctx, journal)
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

// startRefusalEntryForwarding starts the service's owner, under its
// lifetime, where its sink is on "3" and takes refusal entries; the seam is
// noRefusalEntries until the refusal journal fills it.
func startRefusalEntryForwarding(g *gatewayService) {
	f := g.forwarder
	if f == nil || !f.v3 || !f.refusalEntries {
		return
	}
	owner := newRefusalEntryForwarding(&receiptSinkSpec{url: f.url, deliveryV3: true, refusalEntries: true}, noRefusalEntries{}, g.forwardingCursors())
	go owner.run(g.forwardingContext(), refusalForwardEvery)
}
