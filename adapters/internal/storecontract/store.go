// Package storecontract is the store contract (docs/design/store-contract.md) as
// the connection custody keeps its state through it: versioned documents,
// replaced by compare-and-set, with explicit faults. The core module holds
// the contract whole and this module may never import it (ADR-0001), so
// the primitives the custody uses are stated here again, held to the same
// conformance cases, and kept in files by the custody's filesystem kind
// (Files) as they were kept before the contract stood in front of them.
package storecontract

import (
	"errors"
	"fmt"
)

// Fault is the kind of failure a storage operation met. A caller branches
// on it; the error's text stays its cause's own.
type Fault string

const (
	// Absent: what was asked for is not there.
	Absent Fault = "absent"
	// Conflict: a compare-and-set found the document at another revision
	// than the one expected.
	Conflict Fault = "conflict"
	// Durability: a write was not made durable. Its bytes may or may not
	// be kept; the caller is told, and never takes it for a success.
	Durability Fault = "durability"
	// Unreadable: something is there and cannot be read as what it is.
	Unreadable Fault = "unreadable"
	// Refused: a name or an argument outside the contract, refused before
	// anything is touched.
	Refused Fault = "refused"
)

// Error is every failure a kind reports.
type Error struct {
	Fault Fault
	Op    string
	Err   error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("store: %s: %s", e.Op, e.Fault)
}

func (e *Error) Unwrap() error { return e.Err }

func failure(fault Fault, op string, err error) error {
	return &Error{Fault: fault, Op: op, Err: err}
}

// FaultOf is the fault an error carries, or "" for an error no kind made.
func FaultOf(err error) Fault {
	var e *Error
	if errors.As(err, &e) {
		return e.Fault
	}
	return ""
}

// NoRevision is the revision of a document that is not there.
const NoRevision = ""

// AnyRevision is the revision a put or a delete gives when it compares
// nothing: its caller holds the space's lock (the custody lock), under
// which it read what it writes.
const AnyRevision = "*"

// Documents keeps versioned documents.
type Documents interface {
	// Get returns a document and its revision, or Absent.
	Get(name string) ([]byte, string, error)
	// Put writes data as the document if the document is at revision
	// expected now -- NoRevision for one that is not there, AnyRevision
	// for any -- and returns its new revision; Conflict otherwise.
	Put(name string, data []byte, expected string) (string, error)
	// Delete removes the document if it is at revision expected;
	// Conflict otherwise, Absent when it is not there.
	Delete(name, expected string) error
	// List names at most limit names the space holds, in no stated
	// order. A kind may hold names that are no document of a caller's --
	// the filesystem kind's lock files -- and the caller says which it
	// reads.
	List(limit int) ([]string, error)
}
