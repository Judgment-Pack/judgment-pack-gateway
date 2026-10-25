package storecontract

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// The conformance cases of the store contract's documents
// (docs/design/store-contract.md, "What a kind must pass"), as the core's
// suite states them (go/store_conformance_test.go), for the kinds this
// module keeps documents in. A kind whose compare-and-set is atomic on its
// own (lockFree) is held to the core's concurrent case: writers that share
// no lock, each retrying a refused write, lose no write. The custody's
// filesystem kind compares and then renames, which is atomic only among
// writers that hold the custody lock, as every custody writer does; it is
// held instead to a lock-discipline case (spaceLock).
type kindUnderTest struct {
	name     string
	open     func(t *testing.T) Documents
	lockFree bool
}

// spaceLock is the space's lock, as the custody lock serializes its
// writers: one holder at a time.
func spaceLock() func(func()) {
	var held sync.Mutex
	return func(f func()) {
		held.Lock()
		defer held.Unlock()
		f()
	}
}

func kindsUnderTest(t *testing.T) []kindUnderTest {
	kinds := []kindUnderTest{{name: "memory", lockFree: true, open: func(t *testing.T) Documents { return newMemory() }}}
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		kinds = append(kinds, kindUnderTest{name: "filesystem", open: func(t *testing.T) Documents {
			root, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { root.Close() })
			return NewFiles(root, Policy{Limit: 64 << 10, Staging: ".tmp-"}, nil)
		}})
	}
	return kinds
}

func requireFault(t *testing.T, what string, err error, want Fault) {
	t.Helper()
	if got := FaultOf(err); got != want {
		t.Fatalf("%s: fault %q (%v), want %q", what, got, err, want)
	}
}

func TestDocumentKindsConform(t *testing.T) {
	for _, k := range kindsUnderTest(t) {
		t.Run(k.name, func(t *testing.T) {
			t.Run("a document is made once and replaced only at the revision read", func(t *testing.T) {
				docs := k.open(t)
				_, _, err := docs.Get("state.json")
				requireFault(t, "a document never put", err, Absent)
				first, err := docs.Put("state.json", []byte(`{"n":1}`), NoRevision)
				if err != nil {
					t.Fatal(err)
				}
				_, err = docs.Put("state.json", []byte(`{"n":0}`), NoRevision)
				requireFault(t, "a second create", err, Conflict)
				second, err := docs.Put("state.json", []byte(`{"n":2}`), first)
				if err != nil || second == first {
					t.Fatalf("a put at the revision read: %q %v", second, err)
				}
				_, err = docs.Put("state.json", []byte(`{"n":3}`), first)
				requireFault(t, "a put at a stale revision", err, Conflict)
				if data, revision, err := docs.Get("state.json"); err != nil || string(data) != `{"n":2}` || revision != second {
					t.Fatalf("after a refused put: %q %q %v", data, revision, err)
				}
				requireFault(t, "a delete at a stale revision", docs.Delete("state.json", first), Conflict)
				if err := docs.Delete("state.json", second); err != nil {
					t.Fatal(err)
				}
				_, _, err = docs.Get("state.json")
				requireFault(t, "a deleted document", err, Absent)
				requireFault(t, "a delete of a document not there", docs.Delete("state.json", AnyRevision), Absent)
			})
			t.Run("a write under the lock replaces whatever is there", func(t *testing.T) {
				docs := k.open(t)
				for _, text := range []string{"one", "two"} {
					if _, err := docs.Put("consent.json", []byte(text), AnyRevision); err != nil {
						t.Fatal(err)
					}
				}
				if data, _, err := docs.Get("consent.json"); err != nil || string(data) != "two" {
					t.Fatalf("%q %v", data, err)
				}
			})
			t.Run("names outside the contract are refused", func(t *testing.T) {
				docs := k.open(t)
				for _, name := range []string{"", ".", "..", "a/b", `a\b`, AnyRevision} {
					_, err := docs.Put(name, []byte("x"), AnyRevision)
					requireFault(t, "a put to "+strconv.Quote(name), err, Refused)
				}
			})
			t.Run("a listing names what is there", func(t *testing.T) {
				docs := k.open(t)
				for _, name := range []string{"grant-a", "grant-b", "state.json"} {
					if _, err := docs.Put(name, []byte("{}"), NoRevision); err != nil {
						t.Fatal(err)
					}
				}
				names, err := docs.List(129)
				sort.Strings(names)
				if err != nil || strings.Join(names, ",") != "grant-a,grant-b,state.json" {
					t.Fatalf("%v %v", names, err)
				}
			})
			if k.lockFree {
				t.Run("concurrent compare-and-set loses no write", func(t *testing.T) {
					docs := k.open(t)
					const writers, each = 4, 12
					var wg sync.WaitGroup
					failed := make(chan error, writers)
					for w := 0; w < writers; w++ {
						wg.Add(1)
						go func() {
							defer wg.Done()
							for done := 0; done < each; {
								data, revision, err := docs.Get("counter")
								n := 0
								switch FaultOf(err) {
								case "":
									n, _ = strconv.Atoi(string(data))
								case Absent:
								default:
									failed <- err
									return
								}
								_, err = docs.Put("counter", []byte(strconv.Itoa(n+1)), revision)
								switch FaultOf(err) {
								case "":
									done++
								case Conflict:
									// another writer's put came first: read again
								default:
									failed <- err
									return
								}
							}
						}()
					}
					wg.Wait()
					close(failed)
					for err := range failed {
						t.Fatal(err)
					}
					if data, _, err := docs.Get("counter"); err != nil || string(data) != strconv.Itoa(writers*each) {
						t.Fatalf("the count after %d increments: %q %v", writers*each, data, err)
					}
				})
			} else {
				t.Run("under the space's lock a compare-and-set sees the last holder's revision", func(t *testing.T) {
					docs, serialize := k.open(t), spaceLock()
					const writers, each = 4, 10
					var wg sync.WaitGroup
					failed := make(chan error, writers*each)
					for w := 0; w < writers; w++ {
						wg.Add(1)
						go func() {
							defer wg.Done()
							for i := 0; i < each; i++ {
								serialize(func() {
									data, revision, err := docs.Get("counter")
									n := 0
									if FaultOf(err) == "" {
										n, _ = strconv.Atoi(string(data))
									} else if FaultOf(err) != Absent {
										failed <- err
										return
									}
									if _, err := docs.Put("counter", []byte(strconv.Itoa(n+1)), revision); err != nil {
										failed <- err
										return
									}
									// the revision this holder read is stale now
									if _, err := docs.Put("counter", []byte("stale"), revision); FaultOf(err) != Conflict {
										failed <- fmt.Errorf("a put at the revision before the holder's own: %v", err)
									}
								})
							}
						}()
					}
					wg.Wait()
					close(failed)
					for err := range failed {
						t.Fatal(err)
					}
					if data, _, err := docs.Get("counter"); err != nil || string(data) != strconv.Itoa(writers*each) {
						t.Fatalf("the count: %q %v", data, err)
					}
				})
			}
		})
	}
}
