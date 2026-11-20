package main

// Seals delivered to the receipt sink (engineVersion 36, receiptSink.seals;
// ADR-0049, amendment of 2026-11-19; SPEC.md §6a): with the member on, each
// seal -- /seal's, and one made after an interruption by the start or by
// gateway seal-open -- is delivered to the sink the receipts go to, after
// every receipt of its session is acknowledged, and acknowledged by its
// digest. /seal answers a seal only once the sink has acknowledged it. One
// not acknowledged is held: in the serving process's memory, after the
// session's receipts, and in the store by a marker, written before the seal
// is appended and removed once it is acknowledged, so that a stop or a
// crash between the two leaves the seal for the next start, or for
// seal-open --config, to deliver. A marker names a session and nothing
// else; it is not read by a verifier, and is no part of the store's
// verified form. The delivery is a form of its own, deliveryVersion "2", so
// a sink that reads receipts never takes a seal for one.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// sealSinkVersion is the engine configuration version that admits
// receiptSink.seals: 36, the version after receiptSinkVersion (35). It is
// spelled here alone; engine.go lists it in engineVersions, so a merge that
// keeps another change's 36 without renumbering one of them does not
// compile.
const sealSinkVersion = "36"

const (
	// sealDeliveryVersion is the seal delivery request's form; a receipt's
	// is receiptDeliveryVersion.
	sealDeliveryVersion = "2"
	// sealIndex is where a seal stands in its session's queue: after every
	// receipt, which redeliver sends up to the index before it.
	sealIndex = math.MaxInt64
	// sealForwardingDir is the filesystem kind's directory of markers, in
	// the store's root beside receipts/ and artifacts/.
	sealForwardingDir = "seal-forwarding"
	// sealForwardingDocument prefixes a marker's name among the PostgreSQL
	// kind's documents of no scope.
	sealForwardingDocument = "seal-forwarding."
)

// sealNotForwarded is the refusal of a seal the sink did not acknowledge,
// whatever went wrong: the seal is in the registry, and is held.
type sealNotForwarded struct{}

func (sealNotForwarded) Error() string {
	return "seal not forwarded: the receipt sink did not acknowledge the session's seal; the session is sealed in the registry, nothing was answered, and the seal is held to be delivered again before the session's next seal, at the next start, or by gateway seal-open"
}

// sealHeldRefusal names, for the start and seal-open, a session whose seal
// is in the registry and not acknowledged.
func sealHeldRefusal(sessionID string) string {
	return fmt.Sprintf("session %s is sealed, and its seal is held: %v", sessionID, sealNotForwarded{})
}

// refusal is the sentence the first thing q holds is refused with; nil for
// nothing held.
func (q *forwardQueue) refusal() error {
	if q == nil {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.held) == 0 {
		return nil
	}
	return q.held[0].refusal()
}

// sealDigestOf is the digest a seal is acknowledged by: SHA-256 over its
// canonical bytes, its registry line without the line feed.
func sealDigestOf(record *vObject) string { return receiptDigestOf(record) }

// heldSeal is a seal ready for the sink: the delivery request
// {"deliveryVersion": "2", "seal", "sealDigest"} in canonical form, at
// sealIndex.
func (f *receiptForwarder) heldSeal(record *vObject) heldReceipt {
	digest := sealDigestOf(record)
	request := newObject()
	request.set("deliveryVersion", vString(sealDeliveryVersion))
	request.set("seal", record)
	request.set("sealDigest", vString(digest))
	return heldReceipt{index: sealIndex, body: canon(request), digest: digest, seal: true}
}

// heldSealOf is the session's seal held for the sink, its marker removed
// once the sink acknowledges it.
func (g *gatewayService) heldSealOf(sessionID string, record *vObject) heldReceipt {
	held := g.forwarder.heldSeal(record)
	marks := g.sealForwarding()
	held.acknowledged = func() { _ = marks.clear(sessionID) }
	return held
}

// sealForwarding keeps the markers of seals pending forwarding, one per
// session: written before the session's seal is appended, and removed once
// the sink acknowledges it. A marker left by a seal never appended names a
// session the registry holds no seal of, and is passed over until it does.
type sealForwarding interface {
	// mark records the session's seal as pending, durably, before it is
	// appended; a marker already there is kept.
	mark(sessionID string) error
	// clear removes the session's marker; one not there is no failure.
	clear(sessionID string) error
	// pending names the sessions marked, sorted.
	pending() ([]string, error)
}

// sealForwarding is the service's markers: the store's directory on the
// filesystem kind, the documents of no scope on the PostgreSQL kind.
func (g *gatewayService) sealForwarding() sealForwarding {
	if kind, onKind := g.kind.(*pgKind); onKind {
		return pgSealForwarding{kind.ofNoScope().documents()}
	}
	return fsSealForwarding{g.storeRoot}
}

// fsSealForwarding is the filesystem kind's markers: one file per session
// under seal-forwarding/ in the store's root, named by the session id and
// holding it and a line feed, written as a receipt is, staged, synced and
// renamed into place. A file of any other name or bytes -- a staging file
// a write left -- is no marker.
type fsSealForwarding struct{ root string }

func (f fsSealForwarding) dir() string { return filepath.Join(f.root, sealForwardingDir) }

func (f fsSealForwarding) mark(sessionID string) error {
	if err := requireSession(sessionID); err != nil {
		return err
	}
	if err := os.Mkdir(f.dir(), 0o700); err == nil {
		syncDir(f.root)
	} else if !errors.Is(err, fs.ErrExist) {
		return err
	}
	return fsWriteFile(filepath.Join(f.dir(), sessionID), []byte(sessionID+"\n"), false)
}

func (f fsSealForwarding) clear(sessionID string) error {
	if err := requireSession(sessionID); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(f.dir(), sessionID)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	syncDir(f.dir())
	return nil
}

func (f fsSealForwarding) pending() ([]string, error) {
	entries, err := os.ReadDir(f.dir())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var marked []string
	for _, entry := range entries {
		name := entry.Name()
		if !entry.Type().IsRegular() || requireSession(name) != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(f.dir(), name))
		if err != nil {
			return nil, err
		}
		if string(data) == name+"\n" {
			marked = append(marked, name)
		}
	}
	return marked, nil
}

// pgSealForwarding is the PostgreSQL kind's markers: documents of no scope,
// each holding a session id and named sealForwardingDocument and the
// lowercase hexadecimal SHA-256 of it, since a document's name is held to a
// session id's form and length; the run-time role's grants on
// gateway.documents already cover them, so no table and no migration is
// added. A document of the prefix whose name is not its bytes' is no marker.
type pgSealForwarding struct{ docs documentSpace }

// pgSealForwardingName is the document the session's marker is.
func pgSealForwardingName(sessionID string) string {
	sum := sha256.Sum256([]byte(sessionID))
	return sealForwardingDocument + hex.EncodeToString(sum[:])
}

func (p pgSealForwarding) mark(sessionID string) error {
	if err := requireSession(sessionID); err != nil {
		return err
	}
	_, err := p.docs.putDocument(pgSealForwardingName(sessionID), []byte(sessionID), noRevision)
	if faultOf(err) == faultConflict {
		return nil
	}
	return err
}

func (p pgSealForwarding) clear(sessionID string) error {
	name := pgSealForwardingName(sessionID)
	_, revision, err := p.docs.getDocument(name)
	if faultOf(err) == faultAbsent {
		return nil
	}
	if err != nil {
		return err
	}
	if err := p.docs.deleteDocument(name, revision); err != nil && faultOf(err) != faultAbsent && faultOf(err) != faultConflict {
		return err
	}
	return nil
}

func (p pgSealForwarding) pending() ([]string, error) {
	names, err := p.docs.listDocuments()
	if err != nil {
		return nil, err
	}
	var marked []string
	for _, name := range names {
		if !strings.HasPrefix(name, sealForwardingDocument) {
			continue
		}
		data, _, err := p.docs.getDocument(name)
		if faultOf(err) == faultAbsent {
			continue
		}
		if err != nil {
			return nil, err
		}
		if id := string(data); requireSession(id) == nil && pgSealForwardingName(id) == name {
			marked = append(marked, id)
		}
	}
	sort.Strings(marked)
	return marked, nil
}

// sealRecordIn is the registry line, parsed, of the seal the walk loaded
// for the session: the line naming the session and the seal's signature.
func sealRecordIn(data []byte, sessionID string, loaded seal) *vObject {
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		parsed, err := parseJSON(line)
		if err != nil {
			continue
		}
		record, ok := parsed.(*vObject)
		if !ok {
			continue
		}
		id, _ := memberString(record, "sessionId")
		signature, _ := memberString(record, "signature")
		if id == sessionID && signature == loaded.signature {
			return record
		}
	}
	return nil
}

// deliverSeal sends one seal, alone in a queue of its own, and removes its
// marker once the sink acknowledges it.
func (s *sealOpenSink) deliverSeal(marks sealForwarding, record *vObject) bool {
	sessionID, _ := memberString(record, "sessionId")
	held := s.forwarder.heldSeal(record)
	held.acknowledged = func() { _ = marks.clear(sessionID) }
	queue := newForwardQueue()
	queue.add(held)
	return s.forwarder.deliver(s.ctx, queue, sealIndex) == nil
}

// deliverPending delivers each seal pending forwarding that the registry,
// as walked, holds, in the order the markers sort, and answers the sessions
// whose seal is still held, named, and whether the sink acknowledged every
// one. A marker is written only once every receipt of its session is
// acknowledged, so a pending seal is sent alone. Once one delivery fails the
// sink is not asked for the seals after it, which are named as well. A
// marker of a session the registry holds no seal of is passed over, as it
// is. An error is markers that cannot be read.
func (s *sealOpenSink) deliverPending(marks sealForwarding, data []byte, walk *registryWalk) ([]string, bool, error) {
	marked, err := marks.pending()
	if err != nil {
		return nil, false, err
	}
	var held []string
	down := false
	for _, sessionID := range marked {
		loaded, sealed := walk.seals[sessionID]
		if !sealed {
			continue
		}
		record := sealRecordIn(data, sessionID, loaded)
		if record == nil {
			continue
		}
		if down || !s.deliverSeal(marks, record) {
			down = true
			held = append(held, sealHeldRefusal(sessionID))
		}
	}
	return held, !down, nil
}

// sealsAtStart is what the start does before it serves: with the switch on,
// sealOpenAtStart, which delivers the seals pending forwarding before it
// seals; with it off and seals forwarded, those seals alone.
func sealsAtStart(service *gatewayService, stderr io.Writer, stamp func() string, sealOpen bool) error {
	if sealOpen {
		return sealOpenAtStart(service, stderr, stamp)
	}
	return forwardPendingSealsAtStart(service, stderr)
}

// forwardPendingSealsAtStart delivers, with seals forwarded, each seal
// pending forwarding before anything is served, and names on stderr each
// one the sink does not acknowledge, which stays held by its marker. The
// start goes on: the seal is in the registry, and no caller is answered
// it. Markers or a registry that cannot be read stop the start.
func forwardPendingSealsAtStart(service *gatewayService, stderr io.Writer) error {
	if service.forwarder == nil || !service.forwarder.seals {
		return nil
	}
	var data []byte
	var err error
	if _, onKind := service.kind.(*pgKind); onKind {
		data, err = service.registry.log.readLog(0)
	} else {
		data, _, err = readRegistryBytes(service.regPath)
	}
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	walk, err := engineWalk(data, service.registry.priv.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}
	sink := &sealOpenSink{forwarder: service.forwarder, ctx: service.forwardingContext()}
	held, _, err := sink.deliverPending(service.sealForwarding(), data, walk)
	for _, refusal := range held {
		fmt.Fprintf(stderr, "start: %s\n", refusal)
	}
	if err != nil {
		return fmt.Errorf("the seals pending forwarding could not be read: %w; the gateway does not start", err)
	}
	return nil
}
