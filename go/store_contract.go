package main

// The store contract (docs/design/store-contract.md): the primitives the
// gateway's durable state is kept through, whatever kind of storage keeps
// it, and the faults a kind reports. The filesystem kind (store_fs.go) is
// the one that ships; every kind answers to the conformance suite
// (store_conformance_test.go). Nothing here names a path: where a kind
// keeps its bytes, and how it judges what it finds there, is the kind's.
//
// The receipt format, the registry's lines and every check verification
// makes are SPEC.md's and not this file's: a kind keeps bytes, and the
// gateway decides what they are.

import (
	"errors"
	"fmt"
	"time"
)

// storeFault is the kind of failure a storage operation met. A caller
// branches on it; the error's text stays its cause's own, so a message the
// gateway gave before a kind stood behind it reads as it did.
type storeFault string

const (
	// faultAbsent: what was asked for is not there.
	faultAbsent storeFault = "absent"
	// faultTaken: a create-once name or index is held already.
	faultTaken storeFault = "taken"
	// faultConflict: a compare-and-set found the document at another
	// revision than the one expected.
	faultConflict storeFault = "conflict"
	// faultLeaseHeld: another holder's lease on the name has not expired.
	faultLeaseHeld storeFault = "lease-held"
	// faultStaleFence: a fencing token is not the current lease's.
	faultStaleFence storeFault = "stale-fence"
	// faultDurability: a write was not made durable. Its bytes may or may
	// not be kept; the caller is told, and never takes it for a success.
	faultDurability storeFault = "durability"
	// faultUnreadable: something is there and cannot be read as what it is.
	faultUnreadable storeFault = "unreadable"
	// faultRefused: a name or an argument outside the contract, refused
	// before anything is touched.
	faultRefused storeFault = "refused"
)

// storeError is every failure a kind reports.
type storeError struct {
	fault storeFault
	op    string
	// written is, for an append that failed, how many of its bytes may be
	// in the log: none when the log was never reached.
	written int
	// committing is true when an append's bytes were written whole and
	// making them durable is what failed.
	committing bool
	err        error
}

func (e *storeError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	return fmt.Sprintf("store: %s: %s", e.op, e.fault)
}

func (e *storeError) Unwrap() error { return e.err }

// storeFailure is a fault met by an operation, with its cause.
func storeFailure(fault storeFault, op string, err error) error {
	return &storeError{fault: fault, op: op, err: err}
}

// faultOf is the fault an error carries, or "" for an error no kind made.
func faultOf(err error) storeFault {
	var e *storeError
	if errors.As(err, &e) {
		return e.fault
	}
	return ""
}

// blobSpace keeps immutable blobs, each named by the SHA-256 of its bytes:
// the retained artifacts, the descriptor snapshots.
type blobSpace interface {
	// putBlob keeps data and returns its name, "sha256:" and 64 lowercase
	// hexadecimal characters. Bytes held already are a put that succeeds.
	putBlob(data []byte) (string, error)
	// getBlob returns the bytes held under name as they are held, or
	// faultAbsent. A kind does not re-digest what it returns: a reader that
	// relies on the bytes re-digests them, as verification does.
	getBlob(name string) ([]byte, error)
	// listBlobs names every blob the space holds, sorted.
	listBlobs() ([]string, error)
}

// indexedSpace keeps entries made once at an index within a series: a
// receipt at its callIndex within its session.
type indexedSpace interface {
	// makeSeries makes the series where it is not there, and reports
	// whether this call made it: a series another call made, at any moment
	// before, is never this call's.
	makeSeries(series string) (made bool, err error)
	// createIndexed makes the entry at index, or refuses with faultTaken
	// when one is there: an entry is never replaced. Into a series never
	// made it writes nothing and answers faultAbsent.
	createIndexed(series string, index int64, data []byte) error
	// listSeries names every series, sorted.
	listSeries() ([]string, error)
	// listEntries names a series' entries, sorted; createIndexed names the
	// entry it makes by its index in decimal.
	listEntries(series string) ([]string, error)
	// getEntry returns an entry's bytes as they are held, or faultAbsent.
	getEntry(series, entry string) ([]byte, error)
}

// appendLog is a durable append-only log of bytes, read in order from a
// cursor: the seal registry, the witness's files. A record's framing is
// its writer's (SPEC.md §3 frames a seal as a line); the log keeps bytes.
type appendLog interface {
	// appendRecord appends data whole and makes it durable. On a failure
	// the *storeError says how many of its bytes may be in the log
	// (written) and whether they were written whole and making them
	// durable failed (committing). Onto a log never made it writes
	// nothing and answers faultAbsent, written 0.
	appendRecord(data []byte) (int, error)
	// readLog returns the log's bytes from the cursor from to its end; the
	// next cursor is from plus their length. faultAbsent when there is no
	// log, faultRefused for a cursor past its end.
	readLog(from int64) ([]byte, error)
	// createLog makes the log, empty, where none is; faultTaken where one is.
	createLog() error
}

// noRevision is the revision of a document that is not there.
const noRevision = ""

// documentSpace keeps versioned documents, each replaced only by a
// compare-and-set against the revision its writer read.
type documentSpace interface {
	// getDocument returns a document and its revision, or faultAbsent.
	getDocument(name string) ([]byte, string, error)
	// putDocument writes data as the document's next revision if the
	// document is at revision expected now -- noRevision for one that is
	// not there -- and returns the new revision; faultConflict otherwise.
	putDocument(name string, data []byte, expected string) (string, error)
	// deleteDocument removes the document if it is at revision expected;
	// faultConflict otherwise, faultAbsent when it is not there.
	deleteDocument(name, expected string) error
	// listDocuments names every document there, sorted.
	listDocuments() ([]string, error)
}

// secretSpace keeps secret values, each made once and never replaced: the
// signing seed. A secret never leaves through a cut.
type secretSpace interface {
	// putSecret makes the secret, or refuses with faultTaken.
	putSecret(name string, value []byte) error
	// getSecret returns the secret's value, or faultAbsent.
	getSecret(name string) ([]byte, error)
}

// lease is a holder's claim on a name until it expires. Its fencing token
// grows with every grant of the name, and never starts again, so a holder
// whose lease expired and was granted to another carries a token the name
// no longer has.
type lease struct {
	name    string
	holder  string
	token   int64
	expires time.Time
}

// leaseSpace grants leases with fencing tokens.
type leaseSpace interface {
	// acquireLease grants the name to holder for ttl, or refuses with
	// faultLeaseHeld while another grant of it has not expired.
	acquireLease(name, holder string, ttl time.Duration) (lease, error)
	// renewLease extends a lease still current, or refuses with
	// faultStaleFence.
	renewLease(l lease, ttl time.Duration) (lease, error)
	// releaseLease gives a current lease up, or refuses with
	// faultStaleFence.
	releaseLease(l lease) error
	// checkFence answers nil only for the token of the name's current,
	// unexpired lease; faultStaleFence otherwise.
	checkFence(name string, token int64) error
}

// storeCut is a consistent cut of a kind's spaces, read-only. A writer
// that makes its writes durable in the order the contract states -- a
// blob before an entry that names it, an entry before a document or a log
// record that counts it -- finds in a cut, for everything the cut holds,
// everything it wrote before. Names are listed at the cut; an entry or a
// blob is never rewritten once made, so its bytes are read when asked.
type storeCut struct {
	// log is the log's bytes at the cut, when logPresent.
	log        []byte
	logPresent bool
	// documents are the documents at the cut, with their revisions.
	documents map[string][]byte
	revisions map[string]string
	// series, and each series' entries, as listed at the cut.
	series  []string
	entries map[string][]string
	// blobs, as listed at the cut.
	blobs []string
	// entry and blob read what the cut listed.
	entry func(series, entry string) ([]byte, error)
	blob  func(name string) ([]byte, error)
}

// storeKind is one kind of storage: the spaces the gateway keeps its state
// in, and the cut across them.
type storeKind interface {
	artifacts() blobSpace
	receipts() indexedSpace
	registry() appendLog
	// documents is the kind's documents as every caller but its leases is
	// given them: a put or a delete of a lease's document is refused
	// (leaseDocumentsReserved), so a fencing token never restarts.
	documents() documentSpace
	secrets() secretSpace
	leases() leaseSpace
	snapshot() (*storeCut, error)
}
