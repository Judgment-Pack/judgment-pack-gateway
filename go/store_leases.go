package main

// Leases with fencing tokens, kept as documents of a space
// (docs/design/store-contract.md, "Leases"): any kind whose documents
// compare and set gives leases through them, and a kind that grants them
// natively answers to the same conformance cases.

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// documentLeases keeps each lease as the document "lease-<name>": its
// holder, its fencing token and when it expires. A grant is a
// compare-and-set against the revision the granter read, so two granters
// cannot both take a name; the token is the last grant's plus one, so it
// grows with every grant, whoever held the name before. Its documents are
// its own: the kind's document space, as every other caller is given it
// (leaseDocumentsReserved), refuses to write or delete one, so no record
// a grant counts from is ever removed or rewound.
type documentLeases struct {
	docs  documentSpace
	clock func() time.Time
}

const leaseDocumentPrefix = "lease-"

// leaseDocumentsReserved is a kind's document space as every caller but
// its leases is given it: a document named "lease-..." is read and listed
// as any other, and a put or a delete of one is refused before anything
// is touched. The prefix is compared without regard to case: on a
// filesystem that folds case, "LEASE-job" is the lease's own document. A lease's record carries the last grant's token; were it
// deleted, the next grant would count from nothing and give a token the
// name had given before, which a holder from before the delete would
// still carry.
type leaseDocumentsReserved struct{ documentSpace }

func leaseDocumentRefused(op, name string) error {
	if len(name) >= len(leaseDocumentPrefix) && strings.EqualFold(name[:len(leaseDocumentPrefix)], leaseDocumentPrefix) {
		return storeFailure(faultRefused, op, fmt.Errorf("store: %s is a lease's document, kept by the leases alone", name))
	}
	return nil
}

func (r leaseDocumentsReserved) putDocument(name string, data []byte, expected string) (string, error) {
	if err := leaseDocumentRefused("put-document", name); err != nil {
		return noRevision, err
	}
	return r.documentSpace.putDocument(name, data, expected)
}

func (r leaseDocumentsReserved) deleteDocument(name, expected string) error {
	if err := leaseDocumentRefused("delete-document", name); err != nil {
		return err
	}
	return r.documentSpace.deleteDocument(name, expected)
}

func (l documentLeases) key(op, name string) (string, error) {
	key := leaseDocumentPrefix + name
	if name == "" || !validStoreName(key) {
		return "", storeFailure(faultRefused, op, fmt.Errorf("store: %q is not a lease's name", name))
	}
	return key, nil
}

// leaseRecord is a lease document's content: canonical JSON of the
// holder, the token and the expiry in Unix milliseconds; an expiry of 0 is
// a lease given up.
func leaseRecord(holder string, token int64, expires time.Time) []byte {
	record := newObject()
	record.set("expires", vInt(expires.UnixMilli()))
	record.set("holder", vString(holder))
	record.set("token", vInt(token))
	return canon(record)
}

func parseLeaseRecord(name string, data []byte) (lease, error) {
	v, err := parseJSON(data)
	if err != nil {
		return lease{}, err
	}
	obj, ok := v.(*vObject)
	if !ok {
		return lease{}, errors.New("store: a lease record is not an object")
	}
	if err := exactlyMembers(obj, map[string]bool{"expires": true, "holder": true, "token": true}, "lease record"); err != nil {
		return lease{}, err
	}
	holder, hok := memberString(obj, "holder")
	token, tok := obj.get("token")
	expires, eok := obj.get("expires")
	t, tIsInt := token.(vInt)
	e, eIsInt := expires.(vInt)
	if !hok || !tok || !eok || !tIsInt || !eIsInt || t < 1 || e < 0 {
		return lease{}, errors.New("store: a lease record is not one this space writes")
	}
	return lease{name: name, holder: holder, token: int64(t), expires: time.UnixMilli(int64(e))}, nil
}

// current reads the name's lease record and the revision it is at; a name
// never granted has none.
func (l documentLeases) current(op, key, name string) (lease, string, bool, error) {
	data, revision, err := l.docs.getDocument(key)
	switch faultOf(err) {
	case "":
	case faultAbsent:
		return lease{}, noRevision, false, nil
	default:
		return lease{}, noRevision, false, err
	}
	held, err := parseLeaseRecord(name, data)
	if err != nil {
		return lease{}, noRevision, false, storeFailure(faultUnreadable, op, err)
	}
	return held, revision, true, nil
}

// live reports whether a lease has not expired at now.
func live(held lease, now time.Time) bool { return now.Before(held.expires) }

func (l documentLeases) acquireLease(name, holder string, ttl time.Duration) (lease, error) {
	key, err := l.key("acquire-lease", name)
	if err != nil {
		return lease{}, err
	}
	if holder == "" || ttl < time.Millisecond {
		return lease{}, storeFailure(faultRefused, "acquire-lease", errors.New("store: a lease needs a holder and a time to live of a millisecond or more"))
	}
	held, revision, found, err := l.current("acquire-lease", key, name)
	if err != nil {
		return lease{}, err
	}
	now := l.clock()
	if found && live(held, now) {
		return lease{}, storeFailure(faultLeaseHeld, "acquire-lease", fmt.Errorf("store: %s is leased until %s", name, held.expires.UTC().Format(time.RFC3339Nano)))
	}
	granted := lease{name: name, holder: holder, token: held.token + 1, expires: time.UnixMilli(now.Add(ttl).UnixMilli())}
	if _, err := l.docs.putDocument(key, leaseRecord(holder, granted.token, granted.expires), revision); err != nil {
		if faultOf(err) == faultConflict {
			return lease{}, storeFailure(faultLeaseHeld, "acquire-lease", fmt.Errorf("store: %s was granted to another meanwhile", name))
		}
		return lease{}, err
	}
	return granted, nil
}

// holding is the revision of the name's lease record when that record is
// the lease given, still live; faultStaleFence otherwise.
func (l documentLeases) holding(op string, given lease) (string, string, error) {
	key, err := l.key(op, given.name)
	if err != nil {
		return "", noRevision, err
	}
	held, revision, found, err := l.current(op, key, given.name)
	if err != nil {
		return "", noRevision, err
	}
	if !found || held.token != given.token || held.holder != given.holder || !live(held, l.clock()) {
		return "", noRevision, storeFailure(faultStaleFence, op, fmt.Errorf("store: token %d is not the current lease of %s", given.token, given.name))
	}
	return key, revision, nil
}

func (l documentLeases) renewLease(given lease, ttl time.Duration) (lease, error) {
	if ttl < time.Millisecond {
		return lease{}, storeFailure(faultRefused, "renew-lease", errors.New("store: a lease needs a time to live of a millisecond or more"))
	}
	key, revision, err := l.holding("renew-lease", given)
	if err != nil {
		return lease{}, err
	}
	renewed := given
	renewed.expires = time.UnixMilli(l.clock().Add(ttl).UnixMilli())
	if _, err := l.docs.putDocument(key, leaseRecord(given.holder, given.token, renewed.expires), revision); err != nil {
		if faultOf(err) == faultConflict {
			return lease{}, storeFailure(faultStaleFence, "renew-lease", fmt.Errorf("store: %s changed hands meanwhile", given.name))
		}
		return lease{}, err
	}
	return renewed, nil
}

func (l documentLeases) releaseLease(given lease) error {
	key, revision, err := l.holding("release-lease", given)
	if err != nil {
		return err
	}
	if _, err := l.docs.putDocument(key, leaseRecord(given.holder, given.token, time.UnixMilli(0)), revision); err != nil {
		if faultOf(err) == faultConflict {
			return storeFailure(faultStaleFence, "release-lease", fmt.Errorf("store: %s changed hands meanwhile", given.name))
		}
		return err
	}
	return nil
}

func (l documentLeases) checkFence(name string, token int64) error {
	key, err := l.key("check-fence", name)
	if err != nil {
		return err
	}
	held, _, found, err := l.current("check-fence", key, name)
	if err != nil {
		return err
	}
	if !found || held.token != token || !live(held, l.clock()) {
		return storeFailure(faultStaleFence, "check-fence", fmt.Errorf("store: token %d is not the current lease of %s", token, name))
	}
	return nil
}
