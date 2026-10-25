package main

// The in-memory kind: the store contract kept in maps, for tests. It is
// the second kind the conformance suite holds to the contract, so the
// suite says what the contract asks of a kind and not what one kind
// happens to do. Every space is under one lock, and a snapshot copies
// every space under it: a cut of this kind is a state it was in.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"
)

var _ storeKind = (*memoryKind)(nil)

type memoryDocument struct {
	data     []byte
	revision int64
	deleted  bool
}

type memoryKind struct {
	mu        sync.Mutex
	clock     func() time.Time
	blobData  map[string][]byte
	series    map[string]map[string][]byte
	log       []byte
	logMade   bool
	docs      map[string]*memoryDocument
	secretSet map[string][]byte
	// broken, when set, is a disk that keeps nothing more: every write
	// after it fails as not made durable
	broken bool
}

func newMemoryKind(clock func() time.Time) *memoryKind {
	if clock == nil {
		clock = time.Now
	}
	return &memoryKind{
		clock:     clock,
		blobData:  map[string][]byte{},
		series:    map[string]map[string][]byte{},
		docs:      map[string]*memoryDocument{},
		secretSet: map[string][]byte{},
	}
}

func (k *memoryKind) brokenWrite(op string) error {
	if k.broken {
		return storeFailure(faultDurability, op, errors.New("memory: the stand-in disk keeps nothing more"))
	}
	return nil
}

type memoryBlobs struct{ k *memoryKind }
type memoryIndexed struct{ k *memoryKind }
type memoryLog struct{ k *memoryKind }
type memoryDocuments struct{ k *memoryKind }
type memorySecrets struct{ k *memoryKind }

func (k *memoryKind) artifacts() blobSpace     { return memoryBlobs{k} }
func (k *memoryKind) receipts() indexedSpace   { return memoryIndexed{k} }
func (k *memoryKind) registry() appendLog      { return memoryLog{k} }
func (k *memoryKind) documents() documentSpace { return memoryDocuments{k} }
func (k *memoryKind) secrets() secretSpace     { return memorySecrets{k} }
func (k *memoryKind) leases() leaseSpace {
	return documentLeases{docs: memoryDocuments{k}, clock: k.clock}
}
func copyBytes(b []byte) []byte           { return append([]byte(nil), b...) }
func memoryAbsent(op string) error        { return storeFailure(faultAbsent, op, nil) }
func memoryRefused(op, what string) error { return storeFailure(faultRefused, op, errors.New(what)) }
func memoryConflict(op string, name string) error {
	return storeFailure(faultConflict, op, fmt.Errorf("memory: %s is at another revision", name))
}

func (b memoryBlobs) putBlob(data []byte) (string, error) {
	b.k.mu.Lock()
	defer b.k.mu.Unlock()
	if err := b.k.brokenWrite("put-blob"); err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	name := "sha256:" + hex.EncodeToString(sum[:])
	if _, held := b.k.blobData[name]; !held {
		b.k.blobData[name] = copyBytes(data)
	}
	return name, nil
}

func (b memoryBlobs) getBlob(name string) ([]byte, error) {
	if _, ok := blobHex(name); !ok {
		return nil, memoryRefused("get-blob", "memory: not a blob's name")
	}
	b.k.mu.Lock()
	defer b.k.mu.Unlock()
	data, held := b.k.blobData[name]
	if !held {
		return nil, memoryAbsent("get-blob")
	}
	return copyBytes(data), nil
}

func (b memoryBlobs) listBlobs() ([]string, error) {
	b.k.mu.Lock()
	defer b.k.mu.Unlock()
	return memoryNames(b.k.blobData), nil
}

func memoryNames[V any](m map[string]V) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (x memoryIndexed) makeSeries(series string) (bool, error) {
	if !validStoreName(series) {
		return false, memoryRefused("make-series", "memory: not a series' name")
	}
	x.k.mu.Lock()
	defer x.k.mu.Unlock()
	if _, there := x.k.series[series]; there {
		return false, nil
	}
	if err := x.k.brokenWrite("make-series"); err != nil {
		return false, err
	}
	x.k.series[series] = map[string][]byte{}
	return true, nil
}

func (x memoryIndexed) createIndexed(series string, index int64, data []byte) error {
	if !validStoreName(series) {
		return memoryRefused("create", "memory: not a series' name")
	}
	x.k.mu.Lock()
	defer x.k.mu.Unlock()
	entries, there := x.k.series[series]
	if !there {
		return memoryAbsent("create")
	}
	name := strconv.FormatInt(index, 10)
	if _, taken := entries[name]; taken {
		return storeFailure(faultTaken, "create", fmt.Errorf("memory: %s/%s is taken", series, name))
	}
	if err := x.k.brokenWrite("create"); err != nil {
		return err
	}
	entries[name] = copyBytes(data)
	return nil
}

func (x memoryIndexed) listSeries() ([]string, error) {
	x.k.mu.Lock()
	defer x.k.mu.Unlock()
	return memoryNames(x.k.series), nil
}

func (x memoryIndexed) listEntries(series string) ([]string, error) {
	x.k.mu.Lock()
	defer x.k.mu.Unlock()
	entries, there := x.k.series[series]
	if !there {
		return nil, memoryAbsent("list-entries")
	}
	return memoryNames(entries), nil
}

func (x memoryIndexed) getEntry(series, entry string) ([]byte, error) {
	x.k.mu.Lock()
	defer x.k.mu.Unlock()
	data, held := x.k.series[series][entry]
	if !held {
		return nil, memoryAbsent("get-entry")
	}
	return copyBytes(data), nil
}

func (l memoryLog) appendRecord(data []byte) (int, error) {
	l.k.mu.Lock()
	defer l.k.mu.Unlock()
	if !l.k.logMade {
		return 0, &storeError{fault: faultAbsent, op: "append"}
	}
	if err := l.k.brokenWrite("append"); err != nil {
		return 0, &storeError{fault: faultDurability, op: "append", err: err}
	}
	l.k.log = append(l.k.log, data...)
	return len(data), nil
}

func (l memoryLog) readLog(from int64) ([]byte, error) {
	l.k.mu.Lock()
	defer l.k.mu.Unlock()
	if !l.k.logMade {
		return nil, memoryAbsent("read-log")
	}
	if from < 0 || from > int64(len(l.k.log)) {
		return nil, memoryRefused("read-log", "memory: the cursor is not within the log")
	}
	return copyBytes(l.k.log[from:]), nil
}

func (l memoryLog) createLog() error {
	l.k.mu.Lock()
	defer l.k.mu.Unlock()
	if l.k.logMade {
		return storeFailure(faultTaken, "create-log", errors.New("memory: the log is there"))
	}
	if err := l.k.brokenWrite("create-log"); err != nil {
		return err
	}
	l.k.logMade = true
	return nil
}

func (d memoryDocuments) getDocument(name string) ([]byte, string, error) {
	d.k.mu.Lock()
	defer d.k.mu.Unlock()
	doc, there := d.k.docs[name]
	if !there || doc.deleted {
		return nil, noRevision, memoryAbsent("get-document")
	}
	return copyBytes(doc.data), strconv.FormatInt(doc.revision, 10), nil
}

func (d memoryDocuments) write(op, name string, data []byte, expected string, deleting bool) (string, error) {
	if !validStoreName(name) {
		return noRevision, memoryRefused(op, "memory: not a document's name")
	}
	d.k.mu.Lock()
	defer d.k.mu.Unlock()
	doc := d.k.docs[name]
	current := noRevision
	if doc != nil && !doc.deleted {
		current = strconv.FormatInt(doc.revision, 10)
	}
	if deleting && current == noRevision {
		return noRevision, memoryAbsent(op)
	}
	if expected != current {
		return noRevision, memoryConflict(op, name)
	}
	if err := d.k.brokenWrite(op); err != nil {
		return noRevision, err
	}
	next := int64(1)
	if doc != nil {
		next = doc.revision + 1
	}
	d.k.docs[name] = &memoryDocument{data: copyBytes(data), revision: next, deleted: deleting}
	return strconv.FormatInt(next, 10), nil
}

func (d memoryDocuments) putDocument(name string, data []byte, expected string) (string, error) {
	return d.write("put-document", name, data, expected, false)
}

func (d memoryDocuments) deleteDocument(name, expected string) error {
	_, err := d.write("delete-document", name, nil, expected, true)
	return err
}

func (d memoryDocuments) listDocuments() ([]string, error) {
	d.k.mu.Lock()
	defer d.k.mu.Unlock()
	var names []string
	for name, doc := range d.k.docs {
		if !doc.deleted {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func (s memorySecrets) putSecret(name string, value []byte) error {
	if !validStoreName(name) {
		return memoryRefused("put-secret", "memory: not a secret's name")
	}
	s.k.mu.Lock()
	defer s.k.mu.Unlock()
	if _, taken := s.k.secretSet[name]; taken {
		return storeFailure(faultTaken, "put-secret", errors.New("memory: the secret is there"))
	}
	if err := s.k.brokenWrite("put-secret"); err != nil {
		return err
	}
	s.k.secretSet[name] = copyBytes(value)
	return nil
}

func (s memorySecrets) getSecret(name string) ([]byte, error) {
	s.k.mu.Lock()
	defer s.k.mu.Unlock()
	value, there := s.k.secretSet[name]
	if !there {
		return nil, memoryAbsent("get-secret")
	}
	return copyBytes(value), nil
}

// snapshot copies every space under the one lock: the cut is a state the
// kind was in.
func (k *memoryKind) snapshot() (*storeCut, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	cut := &storeCut{
		log: copyBytes(k.log), logPresent: k.logMade,
		documents: map[string][]byte{}, revisions: map[string]string{},
		entries: map[string][]string{},
	}
	for name, doc := range k.docs {
		if !doc.deleted {
			cut.documents[name] = copyBytes(doc.data)
			cut.revisions[name] = strconv.FormatInt(doc.revision, 10)
		}
	}
	held := map[string]map[string][]byte{}
	for series, entries := range k.series {
		copied := map[string][]byte{}
		for name, data := range entries {
			copied[name] = copyBytes(data)
		}
		held[series] = copied
		cut.series = append(cut.series, series)
		cut.entries[series] = memoryNames(entries)
	}
	sort.Strings(cut.series)
	blobs := map[string][]byte{}
	for name, data := range k.blobData {
		blobs[name] = copyBytes(data)
	}
	cut.blobs = memoryNames(blobs)
	cut.entry = func(series, entry string) ([]byte, error) {
		data, ok := held[series][entry]
		if !ok {
			return nil, memoryAbsent("get-entry")
		}
		return copyBytes(data), nil
	}
	cut.blob = func(name string) ([]byte, error) {
		data, ok := blobs[name]
		if !ok {
			return nil, memoryAbsent("get-blob")
		}
		return copyBytes(data), nil
	}
	return cut, nil
}
