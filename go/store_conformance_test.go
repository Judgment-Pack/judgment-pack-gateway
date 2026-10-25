package main

// The store contract's conformance suite (docs/design/store-contract.md,
// "What a kind must pass"): every kind runs every case. A kind is added
// to the gateway by adding it to storeKindsUnderTest and passing.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// handClock is a clock a test moves by hand.
type handClock struct {
	mu  sync.Mutex
	now time.Time
}

func newHandClock() *handClock {
	return &handClock{now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *handClock) read() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *handClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// kindUnderTest opens a fresh kind, and gives a way to break its blob
// space: a disk that keeps nothing more.
type kindUnderTest struct {
	name string
	open func(t *testing.T, clock func() time.Time) (storeKind, func())
}

func storeKindsUnderTest() []kindUnderTest {
	return []kindUnderTest{
		{"filesystem", func(t *testing.T, clock func() time.Time) (storeKind, func()) {
			root := t.TempDir()
			kind := newFsKind(fsLayout{
				store:     filepath.Join(root, "store"),
				registry:  filepath.Join(root, "registry.jsonl"),
				documents: filepath.Join(root, "documents"),
				secrets:   filepath.Join(root, "secrets"),
				clock:     clock,
			})
			if err := kind.makeStore(); err != nil {
				t.Fatal(err)
			}
			broken := func() {
				artifacts := filepath.Join(root, "store", "artifacts")
				if err := os.RemoveAll(artifacts); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(artifacts, []byte("no directory"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			return kind, broken
		}},
		{"memory", func(t *testing.T, clock func() time.Time) (storeKind, func()) {
			kind := newMemoryKind(clock)
			return kind, func() {
				kind.mu.Lock()
				kind.broken = true
				kind.mu.Unlock()
			}
		}},
	}
}

func requireFault(t *testing.T, what string, err error, want storeFault) {
	t.Helper()
	if got := faultOf(err); got != want {
		t.Fatalf("%s: fault %q (%v), want %q", what, got, err, want)
	}
}

func TestStoreKindsConform(t *testing.T) {
	for _, k := range storeKindsUnderTest() {
		t.Run(k.name, func(t *testing.T) {
			t.Run("blobs are named by their digest and kept once", func(t *testing.T) {
				kind, _ := k.open(t, nil)
				conformBlobs(t, kind.artifacts())
			})
			t.Run("an indexed entry is created once", func(t *testing.T) {
				kind, _ := k.open(t, nil)
				conformCreateOnce(t, kind.receipts())
			})
			t.Run("a document is replaced only at the revision read", func(t *testing.T) {
				kind, _ := k.open(t, nil)
				conformCompareAndSet(t, kind.documents())
			})
			t.Run("concurrent compare-and-set loses no write", func(t *testing.T) {
				kind, _ := k.open(t, nil)
				conformConcurrentCompareAndSet(t, kind.documents())
			})
			t.Run("a log appends in order and reads from a cursor", func(t *testing.T) {
				kind, _ := k.open(t, nil)
				conformAppendLog(t, kind.registry())
			})
			t.Run("a secret is made once", func(t *testing.T) {
				kind, _ := k.open(t, nil)
				conformSecrets(t, kind.secrets())
			})
			t.Run("a lease expires and a stale fencing token is refused", func(t *testing.T) {
				clock := newHandClock()
				kind, _ := k.open(t, clock.read)
				conformLeases(t, kind.leases(), clock)
			})
			t.Run("a snapshot is a consistent cut under concurrent writes", func(t *testing.T) {
				kind, _ := k.open(t, nil)
				conformSnapshot(t, kind)
			})
			t.Run("a write that is not kept is an error, never a success", func(t *testing.T) {
				kind, broken := k.open(t, nil)
				conformDurability(t, kind, broken)
			})
		})
	}
}

func conformBlobs(t *testing.T, blobs blobSpace) {
	data := []byte("the bytes a receipt names")
	sum := sha256.Sum256(data)
	want := "sha256:" + hex.EncodeToString(sum[:])
	name, err := blobs.putBlob(data)
	if err != nil || name != want {
		t.Fatalf("put: %q %v, want %q", name, err, want)
	}
	if again, err := blobs.putBlob(data); err != nil || again != want {
		t.Fatalf("a second put of the same bytes: %q %v", again, err)
	}
	if got, err := blobs.getBlob(name); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("get: %q %v", got, err)
	}
	other := sha256.Sum256([]byte("never put"))
	_, err = blobs.getBlob("sha256:" + hex.EncodeToString(other[:]))
	requireFault(t, "a blob never put", err, faultAbsent)
	_, err = blobs.getBlob("sha256:../" + strings.Repeat("0", 61))
	requireFault(t, "a name no blob has", err, faultRefused)
	if names, err := blobs.listBlobs(); err != nil || len(names) != 1 || names[0] != want {
		t.Fatalf("list: %v %v", names, err)
	}
}

func conformCreateOnce(t *testing.T, receipts indexedSpace) {
	made, err := receipts.makeSeries("session-a")
	if err != nil || !made {
		t.Fatalf("the first make of a series: %v %v", made, err)
	}
	if made, err := receipts.makeSeries("session-a"); err != nil || made {
		t.Fatalf("a series made already is never this call's: %v %v", made, err)
	}
	first := []byte(`{"callIndex":0}` + "\n")
	if err := receipts.createIndexed("session-a", 0, first); err != nil {
		t.Fatal(err)
	}
	err = receipts.createIndexed("session-a", 0, []byte(`{"callIndex":0,"other":true}`+"\n"))
	requireFault(t, "a second create at one index", err, faultTaken)
	if got, err := receipts.getEntry("session-a", "0"); err != nil || !bytes.Equal(got, first) {
		t.Fatalf("the refused create changed the entry: %q %v", got, err)
	}
	if err := receipts.createIndexed("session-a", 1, []byte("next\n")); err != nil {
		t.Fatalf("the next index: %v", err)
	}
	if entries, err := receipts.listEntries("session-a"); err != nil || strings.Join(entries, ",") != "0,1" {
		t.Fatalf("entries: %v %v", entries, err)
	}
	if series, err := receipts.listSeries(); err != nil || strings.Join(series, ",") != "session-a" {
		t.Fatalf("series: %v %v", series, err)
	}
	_, err = receipts.getEntry("session-a", "7")
	requireFault(t, "an entry never made", err, faultAbsent)
}

func conformCompareAndSet(t *testing.T, docs documentSpace) {
	_, _, err := docs.getDocument("head")
	requireFault(t, "a document never put", err, faultAbsent)
	first, err := docs.putDocument("head", []byte("one"), noRevision)
	if err != nil {
		t.Fatal(err)
	}
	_, err = docs.putDocument("head", []byte("again"), noRevision)
	requireFault(t, "a create of a document that is there", err, faultConflict)
	second, err := docs.putDocument("head", []byte("two"), first)
	if err != nil || second == first {
		t.Fatalf("a put at the revision read: %q %v", second, err)
	}
	_, err = docs.putDocument("head", []byte("stale"), first)
	requireFault(t, "a put at a revision no longer current", err, faultConflict)
	if data, revision, err := docs.getDocument("head"); err != nil || string(data) != "two" || revision != second {
		t.Fatalf("the document after a refused put: %q %q %v", data, revision, err)
	}
	requireFault(t, "a delete at a stale revision", docs.deleteDocument("head", first), faultConflict)
	if err := docs.deleteDocument("head", second); err != nil {
		t.Fatal(err)
	}
	_, _, err = docs.getDocument("head")
	requireFault(t, "a deleted document", err, faultAbsent)
	requireFault(t, "a delete of a document not there", docs.deleteDocument("head", second), faultAbsent)
	third, err := docs.putDocument("head", []byte("three"), noRevision)
	if err != nil || third == first || third == second {
		t.Fatalf("a document made again takes a revision of its own: %q %v", third, err)
	}
	if names, err := docs.listDocuments(); err != nil || strings.Join(names, ",") != "head" {
		t.Fatalf("documents: %v %v", names, err)
	}
	_, err = docs.putDocument("../escape", []byte("x"), noRevision)
	requireFault(t, "a name no document has", err, faultRefused)
}

// conformConcurrentCompareAndSet has writers count together through
// compare-and-set loops: a count short of every increment is a write two
// writers both made from one revision.
func conformConcurrentCompareAndSet(t *testing.T, docs documentSpace) {
	const writers, each = 4, 12
	var wg sync.WaitGroup
	failures := make(chan error, writers)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for done := 0; done < each; {
				data, revision, err := docs.getDocument("counter")
				count := 0
				switch faultOf(err) {
				case "":
					if count, err = strconv.Atoi(string(data)); err != nil {
						failures <- err
						return
					}
				case faultAbsent:
				default:
					failures <- err
					return
				}
				_, err = docs.putDocument("counter", []byte(strconv.Itoa(count+1)), revision)
				switch faultOf(err) {
				case "":
					done++
				case faultConflict:
				default:
					failures <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	data, _, err := docs.getDocument("counter")
	if err != nil || string(data) != strconv.Itoa(writers*each) {
		t.Fatalf("the count after %d increments: %q %v", writers*each, data, err)
	}
}

func conformAppendLog(t *testing.T, log appendLog) {
	_, err := log.readLog(0)
	requireFault(t, "a log never made", err, faultAbsent)
	if n, err := log.appendRecord([]byte("lost\n")); err == nil || n != 0 {
		t.Fatalf("an append to a log never made: %d %v", n, err)
	}
	if _, err := log.readLog(0); faultOf(err) != faultAbsent {
		t.Fatalf("a refused append made the log: %v", err)
	}
	if err := log.createLog(); err != nil {
		t.Fatal(err)
	}
	requireFault(t, "a second make of the log", log.createLog(), faultTaken)
	first, second := []byte("first record\n"), []byte("second record\n")
	for _, record := range [][]byte{first, second} {
		if n, err := log.appendRecord(record); err != nil || n != len(record) {
			t.Fatalf("append: %d %v", n, err)
		}
	}
	whole := append(append([]byte(nil), first...), second...)
	for _, c := range []struct {
		from int64
		want []byte
	}{{0, whole}, {int64(len(first)), second}, {int64(len(whole)), nil}} {
		got, err := log.readLog(c.from)
		if err != nil || !bytes.Equal(got, c.want) {
			t.Fatalf("read from %d: %q %v, want %q", c.from, got, err, c.want)
		}
	}
	_, err = log.readLog(int64(len(whole)) + 1)
	requireFault(t, "a cursor past the log's end", err, faultRefused)
}

func conformSecrets(t *testing.T, secrets secretSpace) {
	_, err := secrets.getSecret("signing")
	requireFault(t, "a secret never made", err, faultAbsent)
	if err := secrets.putSecret("signing", []byte("first value\n")); err != nil {
		t.Fatal(err)
	}
	requireFault(t, "a second make of a secret", secrets.putSecret("signing", []byte("another value\n")), faultTaken)
	if got, err := secrets.getSecret("signing"); err != nil || string(got) != "first value\n" {
		t.Fatalf("the secret after a refused make: %q %v", got, err)
	}
}

func conformLeases(t *testing.T, leases leaseSpace, clock *handClock) {
	first, err := leases.acquireLease("writer", "one", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = leases.acquireLease("writer", "two", 10*time.Second)
	requireFault(t, "a grant while another is live", err, faultLeaseHeld)
	if err := leases.checkFence("writer", first.token); err != nil {
		t.Fatalf("the live lease's token: %v", err)
	}
	clock.advance(11 * time.Second)
	requireFault(t, "an expired lease's token", leases.checkFence("writer", first.token), faultStaleFence)
	second, err := leases.acquireLease("writer", "two", 10*time.Second)
	if err != nil {
		t.Fatalf("a grant after expiry: %v", err)
	}
	if second.token <= first.token {
		t.Fatalf("the second grant's token %d does not exceed the first's %d", second.token, first.token)
	}
	_, err = leases.renewLease(first, 10*time.Second)
	requireFault(t, "a renewal by the expired holder", err, faultStaleFence)
	requireFault(t, "a release by the expired holder", leases.releaseLease(first), faultStaleFence)
	requireFault(t, "the expired holder's token, the name granted again", leases.checkFence("writer", first.token), faultStaleFence)
	clock.advance(5 * time.Second)
	renewed, err := leases.renewLease(second, 10*time.Second)
	if err != nil || renewed.token != second.token {
		t.Fatalf("a renewal by the current holder: %+v %v", renewed, err)
	}
	clock.advance(8 * time.Second)
	if err := leases.checkFence("writer", second.token); err != nil {
		t.Fatalf("a renewed lease past its first expiry: %v", err)
	}
	if err := leases.releaseLease(renewed); err != nil {
		t.Fatal(err)
	}
	requireFault(t, "a released lease's token", leases.checkFence("writer", second.token), faultStaleFence)
	third, err := leases.acquireLease("writer", "three", 10*time.Second)
	if err != nil || third.token <= second.token {
		t.Fatalf("a grant after a release: %+v %v", third, err)
	}
}

// conformSnapshot cuts a kind while a writer makes, in the contract's
// order, a blob, the entry naming it, a document counting the entry and a
// log record counting it, and holds every cut to that order: a record the
// cut holds counts entries the cut holds, and so does the document; every
// entry the cut holds names a blob it holds, whose bytes digest to it.
func conformSnapshot(t *testing.T, kind storeKind) {
	if _, err := kind.receipts().makeSeries("live"); err != nil {
		t.Fatal(err)
	}
	if err := kind.registry().createLog(); err != nil {
		t.Fatal(err)
	}
	const writes = 40
	done := make(chan error, 1)
	go func() {
		revision := noRevision
		for i := 0; i < writes; i++ {
			name, err := kind.artifacts().putBlob([]byte(fmt.Sprintf("artifact %d", i)))
			if err == nil {
				err = kind.receipts().createIndexed("live", int64(i), []byte(name))
			}
			if err == nil {
				revision, err = kind.documents().putDocument("head", []byte(strconv.Itoa(i)), revision)
			}
			if err == nil {
				_, err = kind.registry().appendRecord([]byte(strconv.Itoa(i+1) + "\n"))
			}
			if err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for finished := false; !finished; {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			finished = true
		default:
		}
		cut, err := kind.snapshot()
		if err != nil {
			t.Fatal(err)
		}
		holdCutToItsOrder(t, cut)
	}
	final, err := kind.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if n := holdCutToItsOrder(t, final); n != writes {
		t.Fatalf("the cut after the writer finished counts %d records, want %d", n, writes)
	}
}

// holdCutToItsOrder checks one cut and returns the count its log holds.
func holdCutToItsOrder(t *testing.T, cut *storeCut) int {
	t.Helper()
	if !cut.logPresent {
		t.Fatal("the cut lost the log")
	}
	records := 0
	for _, line := range strings.Split(string(cut.log), "\n") {
		if line == "" {
			continue
		}
		n, err := strconv.Atoi(line)
		if err != nil || n != records+1 {
			t.Fatalf("the cut's log holds %q after %d records", line, records)
		}
		records = n
	}
	entries := map[string]bool{}
	for _, e := range cut.entries["live"] {
		entries[e] = true
	}
	head := -1
	if data, ok := cut.documents["head"]; ok {
		var err error
		if head, err = strconv.Atoi(string(data)); err != nil {
			t.Fatal(err)
		}
	}
	if records > 0 && head < records-1 {
		t.Fatalf("the cut holds %d records and the document counts %d: the document was read before the log", records, head+1)
	}
	for i := 0; i <= head; i++ {
		if !entries[strconv.Itoa(i)] {
			t.Fatalf("the cut's document counts entry %d, which the cut does not hold", i)
		}
	}
	blobs := map[string]bool{}
	for _, b := range cut.blobs {
		blobs[b] = true
	}
	for e := range entries {
		named, err := cut.entry("live", e)
		if err != nil {
			t.Fatal(err)
		}
		if !blobs[string(named)] {
			t.Fatalf("entry %s names a blob the cut does not hold", e)
		}
		data, err := cut.blob(string(named))
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(data); "sha256:"+hex.EncodeToString(sum[:]) != string(named) {
			t.Fatalf("blob %s does not digest to its name", named)
		}
	}
	return records
}

// conformDurability breaks the kind's blob space and holds a put to an
// error that says so: never a success, and nothing listed for it.
func conformDurability(t *testing.T, kind storeKind, broken func()) {
	broken()
	name, err := kind.artifacts().putBlob([]byte("bytes the disk will not keep"))
	if err == nil {
		t.Fatalf("a put to a space that keeps nothing succeeded as %q", name)
	}
	requireFault(t, "a put the space did not keep", err, faultDurability)
	if names, _ := kind.artifacts().listBlobs(); len(names) != 0 {
		t.Fatalf("a refused put is listed: %v", names)
	}
}
