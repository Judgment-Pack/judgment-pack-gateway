//go:build unix

package main

// gateway journal compact (#359): the procedure of
// docs/design/action-reconciliation.md ("Compaction") as a command. It is
// refused while a gateway serves the store and a gateway is refused while it
// runs; it retires only an entry that never sent and an answered one past the
// retention period, the action.json alone of an indexed one, each with its
// record, by a move into the archive; it refuses a journal it cannot read; and
// a compaction stopped anywhere is finished by running it again.

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

// farFuture is a clock every receipt of these tests is past the retention of.
var farFuture = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)

const handIntent = `{"journalVersion":"2","identityVersion":"2","fingerprint":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}`

// compactRun runs gateway journal compact with args, and gives its exit code
// and what it wrote.
func compactRun(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := cmdJournal(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// compactAt compacts store into archive at now, and gives what it wrote.
func compactAt(store, archive string, retention time.Duration, now time.Time) (string, error) {
	var out bytes.Buffer
	err := compactJournal(store, archive, retention, func() time.Time { return now }, &out)
	return out.String(), err
}

// treeOf is every name under dir, with its mode and what it holds, for telling
// a tree unchanged. A dir that is not there is an empty tree.
func treeOf(t *testing.T, dir string) map[string]string {
	t.Helper()
	tree := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		held := info.Mode().String()
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			link, _ := os.Readlink(path)
			held += " -> " + link
		case info.Mode().IsRegular():
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			held += fmt.Sprintf(" %x", sha256.Sum256(raw))
		}
		tree[rel] = held
		return nil
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return tree
}

func sameTree(t *testing.T, what string, got, want map[string]string) {
	t.Helper()
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	if string(g) != string(w) {
		t.Fatalf("%s changed:\n got %s\nwant %s", what, g, w)
	}
}

// handEntry writes a journal entry by hand: a private directory under actions,
// its files private.
func handEntry(t *testing.T, actions, name string, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(actions, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for file, raw := range files {
		if err := os.WriteFile(filepath.Join(dir, file), []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// handStore is a store with a journal of one entry that never sent, and no
// gateway: what the command reads of a store is its journal.
func handStore(t *testing.T) (dir, store, entry string) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(tempDirAt(t, 0o700))
	if err != nil {
		t.Fatal(err)
	}
	store = filepath.Join(dir, "store")
	if err := os.MkdirAll(filepath.Join(store, "actions"), 0o700); err != nil {
		t.Fatal(err)
	}
	entry = fmt.Sprintf("%064x", 0xbeef)
	handEntry(t, filepath.Join(store, "actions"), entry, map[string]string{"intent.json": handIntent})
	return dir, store, entry
}

// servedOf is what an action.json's receipt says of itself.
func servedOf(t *testing.T, path string) (session string, callIndex int64, servedAt string, served time.Time) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var retained struct {
		Receipt struct {
			SessionID string `json:"sessionId"`
			CallIndex int64  `json:"callIndex"`
			ServedAt  string `json:"servedAt"`
		} `json:"receipt"`
	}
	if err := json.Unmarshal(raw, &retained); err != nil {
		t.Fatal(err)
	}
	served, err = time.Parse("2006-01-02T15:04:05Z", retained.Receipt.ServedAt)
	if err != nil {
		t.Fatal(err)
	}
	return retained.Receipt.SessionID, retained.Receipt.CallIndex, retained.Receipt.ServedAt, served
}

// retirementOf is the record a retirement of these tests is expected to hold,
// written out by hand.
func retirementOf(store, namespace, class, moved, session string, callIndex int64, servedAt string, retention int, at time.Time) string {
	receipt, outcome, served := "null", "null", "null"
	if session != "" {
		receipt = fmt.Sprintf(`{"callIndex":%d,"sessionId":%q}`, callIndex, session)
		outcome, served = `"response"`, `"`+servedAt+`"`
	}
	return fmt.Sprintf(`{"archivedAt":%q,"class":%q,"moved":%q,"namespace":%q,"outcome":%s,"receipt":%s,"recordVersion":"1","retentionSeconds":%d,"servedAt":%s,"store":%q}`,
		at.Format("2006-01-02T15:04:05Z"), class, moved, namespace, outcome, receipt, retention, served, store)
}

func wantFile(t *testing.T, path, want string, mode os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != want || info.Mode() != mode {
		t.Fatalf("%s holds %s at %v, want %s at %v", path, raw, info.Mode(), want, mode)
	}
}

func archiveNames(t *testing.T, archive string) []string {
	t.Helper()
	entries, err := os.ReadDir(archive)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// A compaction is refused while a gateway serves the store, by either serve
// command, and changes nothing; a gateway is refused its start while a
// compaction runs; once the gateway has stopped the compaction runs, and the
// gateway starts again after it.
func TestJournalCompactExcludesServe(t *testing.T) {
	for _, sc := range serveCommands {
		t.Run(sc.name, func(t *testing.T) {
			args, f := sc.start(t)
			g := serveInProcess(t, args)
			if g.exited {
				t.Fatalf("the gateway did not start: %d %s", g.code, g.stderr())
			}
			actions := filepath.Join(f.store, "actions")
			if err := os.MkdirAll(actions, 0o700); err != nil {
				t.Fatal(err)
			}
			entry := fmt.Sprintf("%064x", 0xcafe)
			handEntry(t, actions, entry, map[string]string{"intent.json": handIntent})
			store, err := filepath.EvalSymlinks(f.store)
			if err != nil {
				t.Fatal(err)
			}
			archive := filepath.Join(filepath.Dir(store), "archive")
			before := treeOf(t, store)
			code, stdout, stderr := compactRun("compact", "--store", f.store, "--archive", archive, "--retention", "1h")
			want := "journal compact: action-journal-held: a gateway process is serving the store " + store + ", or another compaction holds it: stop every gateway process that serves it, then compact again\n"
			if code != 1 || stdout != "" || stderr != want {
				t.Fatalf("while served: %d %q %q", code, stdout, stderr)
			}
			sameTree(t, "the store", treeOf(t, store), before)
			if _, err := os.Lstat(archive); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a refused compaction made the archive: %v", err)
			}
			if code := g.stop(); code != 0 {
				t.Fatalf("the gateway stopped with %d", code)
			}

			// While the compaction runs, between its record and its move, a gateway
			// does not start.
			started := 0
			compactStep = func(point string) error {
				if point == "record "+entry {
					started++
					refused := serveInProcess(t, args)
					want := "start: action-journal-held: a journal compaction holds the store " + f.store + "; start the gateway once it has finished\n"
					if !refused.exited || refused.code != 1 || !strings.Contains(refused.stderr(), want) {
						t.Errorf("a gateway started during a compaction: exited %v, code %d, %q", refused.exited, refused.code, refused.stderr())
					}
				}
				return nil
			}
			t.Cleanup(func() { compactStep = nil })
			code, stdout, stderr = compactRun("compact", "--store", f.store, "--archive", archive, "--retention", "1h")
			compactStep = nil
			wantOut := "retired " + entry + ": never sent; archived as " + entry + ".1\n" +
				"compacted " + filepath.Join(store, "actions") + ": 1 retired, 0 kept, 0 finished; the archive is " + archive + "\n"
			if code != 0 || stdout != wantOut || stderr != "" || started != 1 {
				t.Fatalf("once stopped: %d %q %q, started %d", code, stdout, stderr, started)
			}
			again := serveInProcess(t, args)
			if again.exited {
				t.Fatalf("the gateway did not start after the compaction: %d %s", again.code, again.stderr())
			}
			again.stop()
		})
	}
}

// A key in flight is never compacted: under the lock a gateway holds while it
// serves, the compaction is refused; without it, the entry of a write in flight
// reads as begun, and stays. The write is sent once and its record lands.
func TestJournalCompactNeverTakesAKeyInFlight(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	actionKeysMode(t, root, "write", "rendezvous")
	key := fmt.Sprintf("%064x", 0xf1)
	namespace := g.actionNamespace(actionKeysWho, key)
	done := make(chan error, 1)
	go func() {
		_, err := actionKeysAct(g, c, "in-flight", key)
		done <- err
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(root, "rendezvous", key)); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the write was never in flight")
		}
		time.Sleep(5 * time.Millisecond)
	}
	store := g.storeRoot
	archive := filepath.Join(root, "archive")
	hold, err := holdServedStore(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compactAt(store, archive, time.Hour, farFuture); err == nil || !strings.HasPrefix(err.Error(), "action-journal-held: ") {
		t.Fatalf("a compaction ran while a gateway held the store: %v", err)
	}
	hold.Close()
	journal := filepath.Join(store, "actions")
	before := treeOf(t, journal)
	out, err := compactAt(store, archive, time.Hour, farFuture)
	want := "kept " + namespace + ": begun without a record: the next request records uncertainty and reads back\n" +
		"compacted " + journal + ": 0 retired, 1 kept, 0 finished; the archive is " + archive + "\n"
	if err != nil || out != want {
		t.Fatalf("in flight: %v %q", err, out)
	}
	sameTree(t, "the journal", treeOf(t, journal), before)
	if err := os.WriteFile(filepath.Join(root, "rendezvous", "release"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(journal, namespace, "action.json")); err != nil {
		t.Fatalf("the write's record did not land: %v", err)
	}
	wantSent(t, root, key, 1)
	if names := archiveNames(t, archive); len(names) != 0 {
		t.Fatalf("the archive holds %v", names)
	}
}

// Every class of the procedure, with the gateway's own entries and with entries
// written by hand: what it prints, what it moves and records, and what it
// leaves, byte for byte. No receipt and nothing else in the store is touched.
// Run again, it retires nothing more. A key with a first scope whose action.json
// went sends nothing again; one that never sent dispatches.
func TestJournalCompactClasses(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	store := g.storeRoot
	actions := filepath.Join(store, "actions")
	archive := filepath.Join(root, "archive")
	k := func(n int) string { return fmt.Sprintf("%064x", 0xa000+n) }
	answered, dropped, missingKey, closedKey, indexedKey := k(1), k(2), k(3), k(4), k(5)
	ns := func(key string) string { return g.actionNamespace(actionKeysWho, key) }
	if _, err := actionKeysAct(g, c, "answered", answered); err != nil {
		t.Fatal(err)
	}
	actionKeysMode(t, root, "write", "drop")
	actionKeysAct(g, c, "dropped", dropped)
	actionKeysMode(t, root, "write", "respond")
	missing := actionKeysService(t, root, actionKeysSources(t, root, filepath.Join(root, "not-installed", "adapter-mcp")))
	if _, err := actionKeysAct(missing, c, "missing", missingKey); err == nil || !strings.Contains(err.Error(), "action-not-dispatched") {
		t.Fatalf("not dispatched: %v", err)
	}
	if _, err := scopedAct(g, c, "closing", closedKey, actionKeysWho, true, true); keyRefusal(err) != refusalKeyNotDispatched {
		t.Fatalf("closing: %v", err)
	}
	if _, err := scopedAct(g, c, "indexed", indexedKey, actionKeysWho, true, false); err != nil {
		t.Fatal(err)
	}
	foreign, err := os.ReadFile(filepath.Join(actions, ns(answered), "action.json"))
	if err != nil {
		t.Fatal(err)
	}
	h := func(n int) string { return fmt.Sprintf("%064x", n) }
	bare, begun, broken, later, odd, gap, orphan, foreignEntry, subject, plainFile, noIntent, spent := h(1), h(2), h(3), h(4), h(5), h(6), h(7), h(8), h(9), h(10), h(11), h(12)
	handEntry(t, actions, bare, map[string]string{"intent.json": handIntent})
	handEntry(t, actions, begun, map[string]string{"intent.json": handIntent, "dispatch-1.json": `{"attempt":1}`})
	handEntry(t, actions, broken, map[string]string{"intent.json": `{"journalVersion":"2"`})
	handEntry(t, actions, later, map[string]string{"intent.json": `{"journalVersion":"2","identityVersion":"3","fingerprint":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}`})
	handEntry(t, actions, odd, map[string]string{"intent.json": handIntent, "notes.txt": `{}`})
	handEntry(t, actions, gap, map[string]string{"intent.json": handIntent, "dispatch-2.json": `{"attempt":2}`, "not-dispatched-2.json": `{"attempt":2}`})
	handEntry(t, actions, orphan, map[string]string{"intent.json": handIntent, "not-dispatched-1.json": `{"attempt":1}`})
	handEntry(t, actions, foreignEntry, map[string]string{"intent.json": handIntent, "action.json": string(foreign)})
	handEntry(t, actions, subject, map[string]string{"scope.json": `{"host":"desk","rootActor":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","sub":{"issuer":"https://issuer.test","kind":"person","subject":"s"}}`})
	if err := os.WriteFile(filepath.Join(actions, plainFile), []byte(handIntent), 0o600); err != nil {
		t.Fatal(err)
	}
	handEntry(t, actions, noIntent, map[string]string{"dispatch-1.json": `{"attempt":1}`, "not-dispatched-1.json": `{"attempt":1}`})
	exhausted := map[string]string{"intent.json": handIntent}
	for n := 1; n <= actionDispatchAttempts; n++ {
		exhausted[actionDispatchName(n)] = fmt.Sprintf(`{"attempt":%d}`, n)
		exhausted[actionNotDispatchedName(n)] = fmt.Sprintf(`{"attempt":%d}`, n)
	}
	handEntry(t, actions, spent, exhausted)
	handEntry(t, actions, "notes", nil)
	handEntry(t, actions, ".staging-00000000000000ff", nil)

	entryBefore := map[string]map[string]string{}
	entries, err := os.ReadDir(actions)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		entryBefore[e.Name()] = treeOf(t, filepath.Join(actions, e.Name()))
	}
	indexedRecord, err := os.ReadFile(filepath.Join(actions, ns(indexedKey), "action.json"))
	if err != nil {
		t.Fatal(err)
	}
	outside := func() map[string]string {
		tree := treeOf(t, store)
		for name := range tree {
			if name == "actions" || strings.HasPrefix(name, "actions"+string(filepath.Separator)) {
				delete(tree, name)
			}
		}
		return tree
	}
	storeBefore := outside()
	if _, err := os.Stat(filepath.Join(store, "receipts", "answered")); err != nil {
		t.Fatalf("no receipts to keep: %v", err)
	}

	const damaged = "; follow the procedure for a damaged entry"
	aSession, aIndex, aServed, _ := servedOf(t, filepath.Join(actions, ns(answered), "action.json"))
	iSession, iIndex, iServed, _ := servedOf(t, filepath.Join(actions, ns(indexedKey), "action.json"))
	lines := map[string]string{
		ns(answered):                fmt.Sprintf("retired %s: answered, receipt %s/%d served %s; archived as %s.1", ns(answered), aSession, aIndex, aServed, ns(answered)),
		ns(dropped):                 "kept " + ns(dropped) + ": uncertain: the target is the operator's to check",
		ns(missingKey):              "retired " + ns(missingKey) + ": never sent; archived as " + ns(missingKey) + ".1",
		ns(closedKey):               "kept " + ns(closedKey) + ": closed",
		ns(indexedKey):              fmt.Sprintf("retired %s action.json: indexed, answered, receipt %s/%d served %s; archived as %s.1", ns(indexedKey), iSession, iIndex, iServed, ns(indexedKey)),
		bare:                        "retired " + bare + ": never sent; archived as " + bare + ".1",
		begun:                       "kept " + begun + ": begun without a record: the next request records uncertainty and reads back",
		broken:                      "kept " + broken + ": does not read: intent.json does not read" + damaged,
		later:                       "kept " + later + ": does not read: intent.json records an identity version this release does not read: upgrade rather than remove it" + damaged,
		odd:                         "kept " + odd + ": does not read: it holds notes.txt, which the gateway does not write" + damaged,
		gap:                         "kept " + gap + ": does not read: dispatch-2.json stands above a missing dispatch-1.json" + damaged,
		orphan:                      "kept " + orphan + ": does not read: not-dispatched-1.json answers no marker" + damaged,
		foreignEntry:                "kept " + foreignEntry + ": does not read: action.json is not this entry's key's" + damaged,
		subject:                     "kept " + subject + ": subject record",
		plainFile:                   "kept " + plainFile + ": does not read: the entry is not a private directory" + damaged,
		noIntent:                    "kept " + noIntent + ": does not read: intent.json is missing" + damaged,
		spent:                       "retired " + spent + ": never sent; archived as " + spent + ".1",
		"notes":                     "kept notes: not a journal entry",
		".staging-00000000000000ff": "kept .staging-00000000000000ff: a staging directory a crash left, no entry",
	}
	if len(lines) != len(entries)-1 {
		t.Fatalf("the journal holds %d entries beside its index, the test names %d", len(entries)-1, len(lines))
	}
	expect := func(lines map[string]string, retired, kept int) string {
		names := make([]string, 0, len(lines))
		for name := range lines {
			names = append(names, name)
		}
		sort.Strings(names)
		var b strings.Builder
		for _, name := range names {
			b.WriteString(lines[name] + "\n")
		}
		fmt.Fprintf(&b, "compacted %s: %d retired, %d kept, 0 finished; the archive is %s\n", actions, retired, kept, archive)
		return b.String()
	}
	out, err := compactAt(store, archive, time.Hour, farFuture)
	if err != nil || out != expect(lines, 5, 14) {
		t.Fatalf("the first pass: %v\n got %q\nwant %q", err, out, expect(lines, 5, 14))
	}

	retired := map[string]string{
		ns(answered):   retirementOf(store, ns(answered), "answered", "entry", aSession, aIndex, aServed, 3600, farFuture),
		ns(missingKey): retirementOf(store, ns(missingKey), "never-sent", "entry", "", 0, "", 3600, farFuture),
		bare:           retirementOf(store, bare, "never-sent", "entry", "", 0, "", 3600, farFuture),
		spent:          retirementOf(store, spent, "never-sent", "entry", "", 0, "", 3600, farFuture),
		ns(indexedKey): retirementOf(store, ns(indexedKey), "indexed", "action.json", iSession, iIndex, iServed, 3600, farFuture),
	}
	var wantNames []string
	for name, record := range retired {
		wantNames = append(wantNames, name+".1")
		dir := filepath.Join(archive, name+".1")
		info, err := os.Lstat(dir)
		if err != nil || info.Mode() != os.ModeDir|0o700 {
			t.Fatalf("%s: %v %v", dir, info, err)
		}
		wantFile(t, filepath.Join(dir, "retirement.json"), record, 0o600)
		if name == ns(indexedKey) {
			wantFile(t, filepath.Join(dir, "action.json"), string(indexedRecord), 0o600)
			kept := entryBefore[name]
			delete(kept, "action.json")
			sameTree(t, "the indexed entry", treeOf(t, filepath.Join(actions, name)), kept)
			continue
		}
		sameTree(t, "the archived "+name, treeOf(t, filepath.Join(dir, "entry")), entryBefore[name])
		if _, err := os.Lstat(filepath.Join(actions, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s is still in the journal: %v", name, err)
		}
	}
	sort.Strings(wantNames)
	if got := archiveNames(t, archive); strings.Join(got, " ") != strings.Join(wantNames, " ") {
		t.Fatalf("the archive holds %v, want %v", got, wantNames)
	}
	for name, before := range entryBefore {
		if _, moved := retired[name]; !moved {
			sameTree(t, "the kept "+name, treeOf(t, filepath.Join(actions, name)), before)
		}
	}
	sameTree(t, "the store outside the journal", outside(), storeBefore)

	// Again: nothing more is retired, and the indexed entry, its action.json gone,
	// is kept as indexed.
	archived := treeOf(t, archive)
	for name := range retired {
		delete(lines, name)
	}
	lines[ns(indexedKey)] = "kept " + ns(indexedKey) + ": indexed"
	if out, err := compactAt(store, archive, time.Hour, farFuture); err != nil || out != expect(lines, 0, 15) {
		t.Fatalf("the second pass: %v\n got %q\nwant %q", err, out, expect(lines, 0, 15))
	}
	sameTree(t, "the archive", treeOf(t, archive), archived)

	if out, err := scopedAct(g, c, "indexed-again", indexedKey, actionKeysWho, true, false); err != nil || out["reconciliation"] == nil {
		t.Fatalf("an indexed key after compaction: %v %v", out, err)
	}
	wantSent(t, root, indexedKey, 1)
	if _, err := actionKeysAct(g, c, "missing-again", missingKey); err != nil {
		t.Fatal(err)
	}
	wantSent(t, root, missingKey, 1)
}

// The retention period, on both ends: a receipt served the period ago to the
// second is kept, one a second more is retired; one served after the clock's
// now is kept. The same for an indexed entry's action.json.
func TestJournalCompactRetentionBoundary(t *testing.T) {
	for _, indexed := range []bool{false, true} {
		t.Run(fmt.Sprintf("indexed %v", indexed), func(t *testing.T) {
			root, g, c := actionKeysSetup(t)
			key := fmt.Sprintf("%064x", 0xb1)
			namespace := g.actionNamespace(actionKeysWho, key)
			if _, err := scopedAct(g, c, "served", key, actionKeysWho, indexed, false); err != nil {
				t.Fatal(err)
			}
			store, archive := g.storeRoot, filepath.Join(root, "archive")
			journal := filepath.Join(store, "actions")
			session, index, servedAt, served := servedOf(t, filepath.Join(journal, namespace, "action.json"))
			kind, subject := "answered", namespace
			if indexed {
				kind, subject = "indexed, answered", namespace+" action.json"
			}
			for _, at := range []time.Time{served.Add(-time.Second), served, served.Add(time.Hour)} {
				out, err := compactAt(store, archive, time.Hour, at)
				want := "kept " + namespace + ": " + kind + ", served " + servedAt + ", within the retention period\n" +
					"compacted " + journal + ": 0 retired, 1 kept, 0 finished; the archive is " + archive + "\n"
				if err != nil || out != want {
					t.Fatalf("at %v: %v %q", at, err, out)
				}
			}
			out, err := compactAt(store, archive, time.Hour, served.Add(time.Hour+time.Second))
			want := fmt.Sprintf("retired %s: %s, receipt %s/%d served %s; archived as %s.1\n", subject, kind, session, index, servedAt, namespace) +
				"compacted " + journal + ": 1 retired, 0 kept, 0 finished; the archive is " + archive + "\n"
			if err != nil || out != want {
				t.Fatalf("a second past: %v %q", err, out)
			}
		})
	}
}

// A journal the command cannot read refuses the whole compaction, before
// anything moves: it is never taken as empty. So does a first-scope record that
// does not read, since an entry it names would be taken as no key's.
func TestJournalCompactRefusesAJournalItCannotRead(t *testing.T) {
	keyRecord := func(key, reservation string) (string, string) {
		name := newObject()
		name.set("key", vString(key))
		return actionHash("action-key-index", name) + ".json",
			`{"authority":"gateway:test","indexVersion":"1","key":"` + key + `","reservation":"` + reservation + `","scope":{"authority":"gateway:test"}}`
	}
	key := fmt.Sprintf("%064x", 0xd1)
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, store, entry string) string
		want    func(store string) string
		root    bool
	}{
		{"no store", func(t *testing.T, store, entry string) string {
			return filepath.Join(filepath.Dir(store), "absent")
		}, func(store string) string {
			return "action-journal-unavailable: the store " + filepath.Join(filepath.Dir(store), "absent") + " is not a directory: nothing was compacted"
		}, false},
		{"no journal", func(t *testing.T, store, entry string) string {
			if err := os.RemoveAll(filepath.Join(store, "actions")); err != nil {
				t.Fatal(err)
			}
			return store
		}, func(store string) string {
			return "action-journal-unavailable: the store " + store + " holds no journal: nothing was compacted"
		}, false},
		{"a journal others can read", func(t *testing.T, store, entry string) string {
			chmod(t, filepath.Join(store, "actions"), 0o755)
			return store
		}, func(store string) string {
			return "action-journal-invalid: the journal " + filepath.Join(store, "actions") + " is not a private directory: nothing was compacted"
		}, false},
		{"a journal that is a link", func(t *testing.T, store, entry string) string {
			elsewhere := filepath.Join(filepath.Dir(store), "elsewhere")
			if err := os.Rename(filepath.Join(store, "actions"), elsewhere); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(elsewhere, filepath.Join(store, "actions")); err != nil {
				t.Fatal(err)
			}
			return store
		}, func(store string) string {
			return "action-journal-invalid: the journal " + filepath.Join(store, "actions") + " is not a private directory: nothing was compacted"
		}, false},
		{"a journal that cannot be listed", func(t *testing.T, store, entry string) string {
			chmod(t, filepath.Join(store, "actions"), 0o300)
			return store
		}, func(store string) string {
			return "action-journal-unavailable: the journal " + filepath.Join(store, "actions") + " cannot be read: nothing was compacted"
		}, true},
		{"an index others can read", func(t *testing.T, store, entry string) string {
			mkdir(t, filepath.Join(store, "actions", actionIndexDirectory), 0o755)
			return store
		}, func(store string) string {
			return "action-journal-invalid: the first-scope index " + filepath.Join(store, "actions", actionIndexDirectory) + " is not a private directory: nothing was compacted"
		}, false},
		{"an index that cannot be listed", func(t *testing.T, store, entry string) string {
			mkdir(t, filepath.Join(store, "actions", actionIndexDirectory), 0o300)
			return store
		}, func(store string) string {
			return "action-journal-unavailable: the first-scope index " + filepath.Join(store, "actions", actionIndexDirectory) + " cannot be read: nothing was compacted"
		}, true},
		{"a record that is not JSON", func(t *testing.T, store, entry string) string {
			name, _ := keyRecord(key, entry)
			indexFile(t, store, name, `{"authority":`, 0o600)
			return store
		}, func(store string) string {
			name, _ := keyRecord(key, "")
			return "action-journal-invalid: the first-scope record " + filepath.Join(store, "actions", actionIndexDirectory, name) + " does not read: nothing was compacted"
		}, false},
		{"a record others can read", func(t *testing.T, store, entry string) string {
			name, record := keyRecord(key, entry)
			indexFile(t, store, name, record, 0o644)
			return store
		}, func(store string) string {
			name, _ := keyRecord(key, "")
			return "action-journal-invalid: the first-scope record " + filepath.Join(store, "actions", actionIndexDirectory, name) + " does not read: nothing was compacted"
		}, false},
		{"a record under another key's name", func(t *testing.T, store, entry string) string {
			_, record := keyRecord(key, entry)
			indexFile(t, store, fmt.Sprintf("%064x.json", 7), record, 0o600)
			return store
		}, func(store string) string {
			return "action-journal-invalid: the first-scope record " + filepath.Join(store, "actions", actionIndexDirectory, fmt.Sprintf("%064x.json", 7)) + " does not read: nothing was compacted"
		}, false},
		{"a record of another version", func(t *testing.T, store, entry string) string {
			name, record := keyRecord(key, entry)
			indexFile(t, store, name, strings.Replace(record, `"indexVersion":"1"`, `"indexVersion":"2"`, 1), 0o600)
			return store
		}, func(store string) string {
			name, _ := keyRecord(key, "")
			return "action-journal-invalid: the first-scope record " + filepath.Join(store, "actions", actionIndexDirectory, name) + " does not read: nothing was compacted"
		}, false},
		{"a file the index does not hold", func(t *testing.T, store, entry string) string {
			indexFile(t, store, "notes.json", `{}`, 0o600)
			return store
		}, func(store string) string {
			return "action-journal-invalid: " + filepath.Join(store, "actions", actionIndexDirectory, "notes.json") + " is not a first-scope record: nothing was compacted"
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.root && os.Geteuid() == 0 {
				t.Skip("root reads a directory its mode refuses")
			}
			dir, store, entry := handStore(t)
			target := tc.prepare(t, store, entry)
			archive := filepath.Join(dir, "archive")
			code, stdout, stderr := compactRun("compact", "--store", target, "--archive", archive, "--retention", "1h")
			if code != 1 || stdout != "" || stderr != "journal compact: "+tc.want(store)+"\n" {
				t.Fatalf("%d %q\n got %q\nwant %q", code, stdout, stderr, "journal compact: "+tc.want(store)+"\n")
			}
			if _, err := os.Lstat(archive); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a refused compaction made the archive: %v", err)
			}
			chmod(t, filepath.Join(store, "actions"), 0o700)
			if _, err := os.Lstat(filepath.Join(store, "actions")); err == nil {
				if _, err := os.Stat(filepath.Join(store, "actions", entry, "intent.json")); err != nil && tc.name != "a journal that is a link" {
					t.Fatalf("the entry moved: %v", err)
				}
			}
		})
	}
	// A record that reads keeps the entry it names, which would be retired
	// without it.
	t.Run("a record that reads", func(t *testing.T) {
		dir, store, entry := handStore(t)
		name, record := keyRecord(key, entry)
		indexFile(t, store, name, record, 0o600)
		archive := filepath.Join(dir, "archive")
		code, stdout, stderr := compactRun("compact", "--store", store, "--archive", archive, "--retention", "1h")
		want := "kept " + entry + ": indexed\ncompacted " + filepath.Join(store, "actions") + ": 0 retired, 1 kept, 0 finished; the archive is " + archive + "\n"
		if code != 0 || stdout != want || stderr != "" {
			t.Fatalf("%d %q %q", code, stdout, stderr)
		}
	})
}

func chmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func mkdir(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	chmod(t, path, mode)
	t.Cleanup(func() { os.Chmod(path, 0o700) })
}

func indexFile(t *testing.T, store, name, raw string, mode os.FileMode) {
	t.Helper()
	index := filepath.Join(store, "actions", actionIndexDirectory)
	if err := os.MkdirAll(index, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(index, name)
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	chmod(t, path, mode)
}

// The archive is a private directory outside the store, on the journal's
// filesystem, that no other compaction holds; it is made, private, when it is
// not there. Anything else refuses before anything moves.
func TestJournalCompactArchive(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, dir, store string) string
		want    func(dir, store, archive string) string
	}{
		{"inside the store, not there", func(t *testing.T, dir, store string) string {
			return filepath.Join(store, "archive")
		}, func(dir, store, archive string) string {
			return "action-journal-archive: the archive " + archive + " is inside the store " + store + ", and it must be outside it: nothing was compacted"
		}},
		{"the journal itself", func(t *testing.T, dir, store string) string {
			return filepath.Join(store, "actions")
		}, func(dir, store, archive string) string {
			return "action-journal-archive: the archive " + archive + " is inside the store " + store + ", and it must be outside it: nothing was compacted"
		}},
		{"inside the store through a link", func(t *testing.T, dir, store string) string {
			mkdir(t, filepath.Join(store, "kept"), 0o700)
			link := filepath.Join(dir, "to-store")
			if err := os.Symlink(store, link); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(link, "kept")
		}, func(dir, store, archive string) string {
			return "action-journal-archive: the archive " + archive + " is inside the store " + store + ", and it must be outside it: nothing was compacted"
		}},
		{"others can read it", func(t *testing.T, dir, store string) string {
			archive := filepath.Join(dir, "archive")
			mkdir(t, archive, 0o755)
			return archive
		}, func(dir, store, archive string) string {
			return "action-journal-archive: the archive " + archive + " is not a private directory: nothing was compacted"
		}},
		{"a link", func(t *testing.T, dir, store string) string {
			mkdir(t, filepath.Join(dir, "real"), 0o700)
			archive := filepath.Join(dir, "archive")
			if err := os.Symlink(filepath.Join(dir, "real"), archive); err != nil {
				t.Fatal(err)
			}
			return archive
		}, func(dir, store, archive string) string {
			return "action-journal-archive: the archive " + archive + " is not a private directory: nothing was compacted"
		}},
		{"a file", func(t *testing.T, dir, store string) string {
			archive := filepath.Join(dir, "archive")
			if err := os.WriteFile(archive, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return archive
		}, func(dir, store, archive string) string {
			return "action-journal-archive: the archive " + archive + " is not a private directory: nothing was compacted"
		}},
		{"its directory not there", func(t *testing.T, dir, store string) string {
			return filepath.Join(dir, "none", "archive")
		}, func(dir, store, archive string) string {
			return "action-journal-archive: the directory " + filepath.Join(dir, "none") + " to make the archive in is not there: nothing was compacted"
		}},
		{"another compaction holds it", func(t *testing.T, dir, store string) string {
			archive := filepath.Join(dir, "archive")
			mkdir(t, archive, 0o700)
			held, err := lockDirectory(archive, true)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { held.Close() })
			return archive
		}, func(dir, store, archive string) string {
			return "action-journal-archive: another compaction holds the archive " + archive + ": nothing was compacted"
		}},
		{"another compaction holds the store", func(t *testing.T, dir, store string) string {
			held, err := lockDirectory(store, true)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { held.Close() })
			return filepath.Join(dir, "archive")
		}, func(dir, store, archive string) string {
			return "action-journal-held: a gateway process is serving the store " + store + ", or another compaction holds it: stop every gateway process that serves it, then compact again"
		}},
		{"on another filesystem", func(t *testing.T, dir, store string) string {
			shm, err := os.MkdirTemp("/dev/shm", "journal-archive-")
			if err != nil {
				t.Skipf("no /dev/shm: %v", err)
			}
			t.Cleanup(func() { os.RemoveAll(shm) })
			chmod(t, shm, 0o700)
			var a, b syscall.Stat_t
			if syscall.Stat(shm, &a) != nil || syscall.Stat(store, &b) != nil || a.Dev == b.Dev {
				t.Skip("/dev/shm is on the store's device here")
			}
			return shm
		}, func(dir, store, archive string) string {
			resolved, _ := filepath.EvalSymlinks(archive)
			return "action-journal-archive: the archive " + resolved + " is on another filesystem than the journal, and a move there would be a copy and a removal: nothing was compacted"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, store, entry := handStore(t)
			archive := tc.prepare(t, dir, store)
			before := treeOf(t, store)
			_, existed := os.Lstat(archive)
			var archiveBefore map[string]string
			if info, err := os.Stat(archive); err == nil && info.IsDir() && !strings.HasPrefix(archive, store) {
				archiveBefore = treeOf(t, archive)
			}
			code, stdout, stderr := compactRun("compact", "--store", store, "--archive", archive, "--retention", "1h")
			want := "journal compact: " + tc.want(dir, store, archive) + "\n"
			if code != 1 || stdout != "" || stderr != want {
				t.Fatalf("%d %q\n got %q\nwant %q", code, stdout, stderr, want)
			}
			sameTree(t, "the store", treeOf(t, store), before)
			if archiveBefore != nil {
				sameTree(t, "the archive", treeOf(t, archive), archiveBefore)
			}
			if _, err := os.Lstat(archive); (err == nil) != (existed == nil) {
				t.Fatalf("a refused compaction made the archive: %v", err)
			}
			if _, err := os.Stat(filepath.Join(store, "actions", entry, "intent.json")); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("made when not there", func(t *testing.T) {
		dir, store, entry := handStore(t)
		archive := filepath.Join(dir, "archive")
		code, stdout, stderr := compactRun("compact", "--store", store, "--archive", archive, "--retention", "1h")
		want := "retired " + entry + ": never sent; archived as " + entry + ".1\ncompacted " + filepath.Join(store, "actions") + ": 1 retired, 0 kept, 0 finished; the archive is " + archive + "\n"
		if code != 0 || stdout != want || stderr != "" {
			t.Fatalf("%d %q %q", code, stdout, stderr)
		}
		if info, err := os.Lstat(archive); err != nil || info.Mode() != os.ModeDir|0o700 {
			t.Fatalf("the archive: %v %v", info, err)
		}
	})
}

// A compaction that stops at any point of a retirement, as a crash would stop
// it, leaves the journal and the archive so that running it again ends where a
// run that never stopped ends: the same records, the same moves, the same names.
// A staging directory that moved nothing stays in the archive, inert.
func TestJournalCompactStoppedAnywhereIsFinishedByARerun(t *testing.T) {
	crashed := errors.New("crashed")
	for _, point := range []string{"stage", "record", "move", "publish"} {
		for _, indexed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, indexed %v", point, indexed), func(t *testing.T) {
				root, g, c := actionKeysSetup(t)
				plain, flagged := fmt.Sprintf("%064x", 0xc1), fmt.Sprintf("%064x", 0xc2)
				for key, scoped := range map[string]bool{plain: false, flagged: true} {
					if _, err := scopedAct(g, c, "s-"+key[60:], key, actionKeysWho, scoped, false); err != nil {
						t.Fatal(err)
					}
				}
				store, archive := g.storeRoot, filepath.Join(root, "archive")
				journal := filepath.Join(store, "actions")
				nsPlain, nsFlagged := g.actionNamespace(actionKeysWho, plain), g.actionNamespace(actionKeysWho, flagged)
				target := nsPlain
				if indexed {
					target = nsFlagged
				}
				pSession, pIndex, pServed, _ := servedOf(t, filepath.Join(journal, nsPlain, "action.json"))
				fSession, fIndex, fServed, _ := servedOf(t, filepath.Join(journal, nsFlagged, "action.json"))
				plainBefore := treeOf(t, filepath.Join(journal, nsPlain))
				flaggedRecord, _ := os.ReadFile(filepath.Join(journal, nsFlagged, "action.json"))
				line := map[string]string{
					nsPlain:   fmt.Sprintf("retired %s: answered, receipt %s/%d served %s; archived as %s.1\n", nsPlain, pSession, pIndex, pServed, nsPlain),
					nsFlagged: fmt.Sprintf("retired %s action.json: indexed, answered, receipt %s/%d served %s; archived as %s.1\n", nsFlagged, fSession, fIndex, fServed, nsFlagged),
				}
				order := []string{nsPlain, nsFlagged}
				sort.Strings(order)

				compactStep = func(at string) error {
					if at == point+" "+target {
						return crashed
					}
					return nil
				}
				t.Cleanup(func() { compactStep = nil })
				first, err := compactAt(store, archive, time.Hour, farFuture)
				compactStep = nil
				if !errors.Is(err, crashed) {
					t.Fatalf("the compaction did not stop: %v %q", err, first)
				}
				// Before the point, in the order of the journal, the first run retired; at
				// it, a move made is finished and a name given is done; after it, the rerun
				// retires. The indexed entry, its action.json gone, then reads as indexed.
				wantFirst, wantFinished, wantRerun := "", "", ""
				retired, kept, finished, reached := 0, 0, 0, false
				for _, name := range order {
					done := !reached && name != target
					switch {
					case name == target:
						reached = true
						if point == "move" {
							wantFinished = "finished " + name + ".1: the retirement of " + name + " an interrupted compaction had moved\n"
							finished++
						}
						if point == "move" || point == "publish" {
							done = true
						} else {
							wantRerun += line[name]
							retired++
						}
					case reached:
						wantRerun += line[name]
						retired++
					default:
						wantFirst += line[name]
					}
					if done && name == nsFlagged {
						wantRerun += "kept " + nsFlagged + ": indexed\n"
						kept++
					}
				}
				if first != wantFirst {
					t.Fatalf("before it stopped: %q, want %q", first, wantFirst)
				}
				wantRerun = wantFinished + wantRerun + fmt.Sprintf("compacted %s: %d retired, %d kept, %d finished; the archive is %s\n", journal, retired, kept, finished, archive)
				rerun, err := compactAt(store, archive, time.Hour, farFuture)
				if err != nil || rerun != wantRerun {
					t.Fatalf("the rerun: %v\n got %q\nwant %q", err, rerun, wantRerun)
				}

				// Where a run that never stopped ends.
				wantFile(t, filepath.Join(archive, nsPlain+".1", "retirement.json"), retirementOf(store, nsPlain, "answered", "entry", pSession, pIndex, pServed, 3600, farFuture), 0o600)
				sameTree(t, "the archived entry", treeOf(t, filepath.Join(archive, nsPlain+".1", "entry")), plainBefore)
				wantFile(t, filepath.Join(archive, nsFlagged+".1", "retirement.json"), retirementOf(store, nsFlagged, "indexed", "action.json", fSession, fIndex, fServed, 3600, farFuture), 0o600)
				wantFile(t, filepath.Join(archive, nsFlagged+".1", "action.json"), string(flaggedRecord), 0o600)
				if _, err := os.Lstat(filepath.Join(journal, nsPlain)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("the plain entry is in the journal: %v", err)
				}
				if _, err := os.Lstat(filepath.Join(journal, nsFlagged, "action.json")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("the indexed action.json is in the journal: %v", err)
				}
				names := archiveNames(t, archive)
				var stages []string
				for _, name := range names {
					if strings.HasPrefix(name, ".staging-") {
						stages = append(stages, name)
					}
				}
				wantStages := 0
				if point == "stage" || point == "record" {
					wantStages = 1
				}
				if len(names) != 2+wantStages || len(stages) != wantStages {
					t.Fatalf("the archive holds %v", names)
				}
				for _, stage := range stages {
					held := archiveNames(t, filepath.Join(archive, stage))
					if (point == "stage" && len(held) != 0) || (point == "record" && strings.Join(held, " ") != "retirement.json") {
						t.Fatalf("the inert stage holds %v", held)
					}
				}
				// Once more: nothing.
				if again, err := compactAt(store, archive, time.Hour, farFuture); err != nil || !strings.HasSuffix(again, ": 0 retired, 1 kept, 0 finished; the archive is "+archive+"\n") {
					t.Fatalf("a third run: %v %q", err, again)
				}
			})
		}
	}
}

// A gateway that serves between a stopped compaction and its rerun is answered
// as the journal then stands. Stopped before its move, the entry is still the
// key's, and a write under it lands there; the rerun keeps it, and the staging
// directory, which moved nothing, is named nothing. Stopped after its move, the
// key never sent, so a write under it dispatches into a new entry; the rerun
// names the moved one, keeps the new one, and a later compaction archives it
// under the next number.
func TestJournalCompactRerunAfterAGatewayServed(t *testing.T) {
	for _, point := range []string{"record", "move"} {
		t.Run(point, func(t *testing.T) {
			root, _, c := actionKeysSetup(t)
			key := fmt.Sprintf("%064x", 0xe1)
			missing := actionKeysService(t, root, actionKeysSources(t, root, filepath.Join(root, "not-installed", "adapter-mcp")))
			if _, err := actionKeysAct(missing, c, "missing", key); err == nil {
				t.Fatal("dispatched without a program")
			}
			store, archive := missing.storeRoot, filepath.Join(root, "archive")
			journal := filepath.Join(store, "actions")
			namespace := missing.actionNamespace(actionKeysWho, key)
			compactStep = func(at string) error {
				if at == point+" "+namespace {
					return errors.New("crashed")
				}
				return nil
			}
			t.Cleanup(func() { compactStep = nil })
			if _, err := compactAt(store, archive, time.Hour, farFuture); err == nil {
				t.Fatal("the compaction did not stop")
			}
			compactStep = nil
			installed := actionKeysService(t, root, actionKeysSources(t, root, os.Args[0]))
			if _, err := actionKeysAct(installed, c, "installed", key); err != nil {
				t.Fatal(err)
			}
			wantSent(t, root, key, 1)
			session, index, servedAt, served := servedOf(t, filepath.Join(journal, namespace, "action.json"))
			want := "kept " + namespace + ": answered, served " + servedAt + ", within the retention period\n" +
				"compacted " + journal + ": 0 retired, 1 kept, 0 finished; the archive is " + archive + "\n"
			if point == "move" {
				want = "finished " + namespace + ".1: the retirement of " + namespace + " an interrupted compaction had moved\n" +
					"kept " + namespace + ": answered, served " + servedAt + ", within the retention period\n" +
					"compacted " + journal + ": 0 retired, 1 kept, 1 finished; the archive is " + archive + "\n"
			}
			if out, err := compactAt(store, archive, time.Hour, served); err != nil || out != want {
				t.Fatalf("the rerun: %v\n got %q\nwant %q", err, out, want)
			}
			names := archiveNames(t, archive)
			if point == "record" {
				if len(names) != 1 || !strings.HasPrefix(names[0], ".staging-") {
					t.Fatalf("the archive holds %v", names)
				}
				wantFile(t, filepath.Join(archive, names[0], "retirement.json"), retirementOf(store, namespace, "never-sent", "entry", "", 0, "", 3600, farFuture), 0o600)
				return
			}
			if strings.Join(names, " ") != namespace+".1" {
				t.Fatalf("the archive holds %v", names)
			}
			out, err := compactAt(store, archive, time.Hour, farFuture)
			want = fmt.Sprintf("retired %s: answered, receipt %s/%d served %s; archived as %s.2\n", namespace, session, index, servedAt, namespace) +
				"compacted " + journal + ": 1 retired, 0 kept, 0 finished; the archive is " + archive + "\n"
			if err != nil || out != want {
				t.Fatalf("the next compaction: %v %q", err, out)
			}
			wantFile(t, filepath.Join(archive, namespace+".1", "retirement.json"), retirementOf(store, namespace, "never-sent", "entry", "", 0, "", 3600, farFuture), 0o600)
			wantFile(t, filepath.Join(archive, namespace+".2", "retirement.json"), retirementOf(store, namespace, "answered", "entry", session, index, servedAt, 3600, farFuture), 0o600)
		})
	}
}

// What is moved is what was read: an entry replaced after it was classified is
// not moved, and the compaction stops; the replacement is read on the rerun.
func TestJournalCompactMovesOnlyWhatItRead(t *testing.T) {
	dir, store, entry := handStore(t)
	archive := filepath.Join(dir, "archive")
	path := filepath.Join(store, "actions", entry)
	compactStep = func(at string) error {
		if at == "record "+entry {
			if err := os.Rename(path, filepath.Join(dir, "read")); err != nil {
				return err
			}
			handEntry(t, filepath.Join(store, "actions"), entry, map[string]string{"intent.json": handIntent, "dispatch-1.json": `{"attempt":1}`})
		}
		return nil
	}
	t.Cleanup(func() { compactStep = nil })
	out, err := compactAt(store, archive, time.Hour, farFuture)
	compactStep = nil
	if err == nil || err.Error() != "action-journal-invalid: "+entry+" changed after it was read, and was not moved: the compaction stopped there" || out != "" {
		t.Fatalf("%v %q", err, out)
	}
	if _, err := os.Stat(filepath.Join(path, "dispatch-1.json")); err != nil {
		t.Fatalf("the replacement moved: %v", err)
	}
	out, err = compactAt(store, archive, time.Hour, farFuture)
	want := "kept " + entry + ": begun without a record: the next request records uncertainty and reads back\n" +
		"compacted " + filepath.Join(store, "actions") + ": 0 retired, 1 kept, 0 finished; the archive is " + archive + "\n"
	if err != nil || out != want {
		t.Fatalf("the rerun: %v %q", err, out)
	}
}

// A retirement whose durability is not established stops the compaction there,
// with what it would move still in the journal.
func TestJournalCompactStopsWhereDurabilityFails(t *testing.T) {
	dir, store, entry := handStore(t)
	archive := filepath.Join(dir, "archive")
	if err := os.Mkdir(archive, 0o700); err != nil {
		t.Fatal(err)
	}
	failing := syncActionFile
	syncActionFile = func(*os.File) error { return errors.New("no durability") }
	t.Cleanup(func() { syncActionFile = failing })
	out, err := compactAt(store, archive, time.Hour, farFuture)
	syncActionFile = failing
	if err == nil || err.Error() != "action-journal-archive: a staging directory's durability in the archive "+archive+" was not established: the compaction stopped there" || out != "" {
		t.Fatalf("%v %q", err, out)
	}
	if _, err := os.Stat(filepath.Join(store, "actions", entry, "intent.json")); err != nil {
		t.Fatal(err)
	}
}

// The command line, byte for byte: each flag once, a retention period of whole
// seconds, at least one.
func TestJournalCommandLine(t *testing.T) {
	usage := journalUsage + "\n"
	for _, tc := range []struct {
		args   []string
		stderr string
	}{
		{nil, usage},
		{[]string{"prune"}, usage},
		{[]string{"compact"}, usage},
		{[]string{"compact", "--store", "s", "--archive", "a"}, usage},
		{[]string{"compact", "--store", "s", "--archive", "a", "--retention"}, usage},
		{[]string{"compact", "--store", "", "--archive", "a", "--retention", "1h"}, usage},
		{[]string{"compact", "--store", "s", "--archive", "a", "--retention", "1h", "--force", "x"}, usage},
		{[]string{"compact", "--store", "s", "--store", "t", "--archive", "a", "--retention", "1h"}, "--store is given twice\n" + usage},
		{[]string{"compact", "--store", "s", "--archive", "a", "--retention", "0s"}, "--retention \"0s\" is not a whole number of seconds, at least one, written as a duration such as 720h\n" + usage},
		{[]string{"compact", "--store", "s", "--archive", "a", "--retention", "999ms"}, "--retention \"999ms\" is not a whole number of seconds, at least one, written as a duration such as 720h\n" + usage},
		{[]string{"compact", "--store", "s", "--archive", "a", "--retention", "1500ms"}, "--retention \"1500ms\" is not a whole number of seconds, at least one, written as a duration such as 720h\n" + usage},
		{[]string{"compact", "--store", "s", "--archive", "a", "--retention", "-1h"}, "--retention \"-1h\" is not a whole number of seconds, at least one, written as a duration such as 720h\n" + usage},
		{[]string{"compact", "--store", "s", "--archive", "a", "--retention", "30"}, "--retention \"30\" is not a whole number of seconds, at least one, written as a duration such as 720h\n" + usage},
	} {
		code, stdout, stderr := compactRun(tc.args...)
		if code != 2 || stdout != "" || stderr != tc.stderr {
			t.Fatalf("%q: %d %q %q", tc.args, code, stdout, stderr)
		}
	}
	if d, err := parseRetention("1s"); err != nil || d != time.Second {
		t.Fatalf("one second: %v %v", d, err)
	}
	if d, err := parseRetention("720h"); err != nil || d != 720*time.Hour {
		t.Fatalf("720h: %v %v", d, err)
	}
}

// The procedure of TestCompactionFollowedLiterally, done by the command with
// the retention period passed: an uncertain entry is kept, where the operator
// there took the target as checked. Afterwards nothing is called not
// dispatched that was sent, no key with a first scope sends again, another
// root actor stays refused, and an unflagged answered key past retention sends
// again, as the text says.
func TestJournalCompactFollowsTheProcedure(t *testing.T) {
	h := newDelegationHarness(t, false)
	actor := h.credential(t, statement(t, nil))
	other := h.credential(t, statement(t, map[string]any{"id": strings.Repeat("66", 16), "act": map[string]any{"agent": otherAgent, "software": testSoftware}}))
	bearer := func() map[string]string {
		return map[string]string{"Authorization": "Bearer " + h.token(t, "alice")}
	}
	session := 0
	next := func() string { session++; return fmt.Sprintf("compact-%d", session) }
	asAlice := func(key, extra string) (int, map[string]any) {
		return h.post(t, "/act", h.actBody(next(), key, extra), bearer())
	}
	asActor := func(key, extra string) (int, map[string]any) {
		return h.present(t, "/act", h.actBody(next(), key, extra), actor)
	}
	k := func(n int) string { return fmt.Sprintf("%064x", 0xf000+n) }
	drop := func(do func()) {
		actionKeysMode(t, h.root, "write", "drop")
		do()
		actionKeysMode(t, h.root, "write", "respond")
	}
	flaggedAnswered, flaggedDropped, flaggedClosed := k(1), k(2), k(3)
	asAlice(flaggedAnswered, withKeyScope)
	drop(func() { asAlice(flaggedDropped, withKeyScope) })
	asAlice(flaggedClosed, withKeyScope+withReconcile)
	unflaggedAnswered, unflaggedDropped := k(4), k(5)
	asAlice(unflaggedAnswered, "")
	drop(func() { asAlice(unflaggedDropped, "") })
	delegatedAnswered, delegatedDropped, delegatedClosed := k(6), k(7), k(8)
	asActor(delegatedAnswered, "")
	drop(func() { asActor(delegatedDropped, "") })
	asActor(delegatedClosed, withReconcile)
	sentKeys := map[string]int{flaggedAnswered: 1, flaggedDropped: 1, flaggedClosed: 0, unflaggedAnswered: 1, unflaggedDropped: 1, delegatedAnswered: 1, delegatedDropped: 1, delegatedClosed: 0}
	for key, want := range sentKeys {
		if h.sent(key) != want {
			t.Fatalf("before: key %s sent %d", key[60:], h.sent(key))
		}
	}

	archive := filepath.Join(h.root, "archive")
	out, err := compactAt(h.g.storeRoot, archive, time.Hour, time.Now().Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	classes := map[string]int{}
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		verb, rest, _ := strings.Cut(line, " ")
		_, class, _ := strings.Cut(rest, ": ")
		if verb == "compacted" {
			continue
		}
		class, _, _ = strings.Cut(class, ", receipt")
		class, _, _ = strings.Cut(class, ": the target")
		classes[verb+" "+class]++
	}
	want := map[string]int{"kept closed": 2, "kept subject record": 3, "kept indexed, uncertain": 2, "retired indexed, answered": 2, "retired answered": 1, "kept uncertain": 1}
	g, _ := json.Marshal(classes)
	w, _ := json.Marshal(want)
	if string(g) != string(w) || !strings.Contains(out, ": 3 retired, 8 kept, 0 finished;") {
		t.Fatalf("the classes: %s, want %s\n%s", g, w, out)
	}

	for _, tc := range []struct {
		name, key string
		ask       func(key, extra string) (int, map[string]any)
		reconcile string
		closed    bool
	}{
		{"flagged answered", flaggedAnswered, asAlice, withKeyScope + withReconcile, false},
		{"flagged dropped", flaggedDropped, asAlice, withKeyScope + withReconcile, false},
		{"flagged closed", flaggedClosed, asAlice, withKeyScope + withReconcile, true},
		{"delegated answered", delegatedAnswered, asActor, withReconcile, false},
		{"delegated dropped", delegatedDropped, asActor, withReconcile, false},
		{"delegated closed", delegatedClosed, asActor, withReconcile, true},
	} {
		status, out := tc.ask(tc.key, tc.reconcile)
		if tc.closed {
			if status != http.StatusConflict || refusalOf(out) != refusalKeyNotDispatched {
				t.Fatalf("%s, reconcile: %d %v", tc.name, status, out)
			}
		} else if status != http.StatusOK || out["reconciliation"] == nil {
			t.Fatalf("%s, reconcile: %d %v", tc.name, status, out)
		}
		if h.sent(tc.key) != sentKeys[tc.key] {
			t.Fatalf("%s: sent %d", tc.name, h.sent(tc.key))
		}
	}
	if status, out := h.present(t, "/act", h.actBody(next(), delegatedAnswered, ""), other); status != http.StatusForbidden || refusalOf(out) != refusalKeyScopeConflict {
		t.Fatalf("another root actor: %d %v", status, out)
	}
	if status, _ := asAlice(unflaggedDropped, ""); status != http.StatusOK || h.sent(unflaggedDropped) != 1 {
		t.Fatalf("a kept uncertain key: %d, sent %d", status, h.sent(unflaggedDropped))
	}
	if status, out := asAlice(unflaggedAnswered, ""); status != http.StatusOK || h.sent(unflaggedAnswered) != 2 {
		t.Fatalf("an unflagged key past retention: %d %v, sent %d", status, out, h.sent(unflaggedAnswered))
	}
}

// A staging directory of the archive the command would finish, but that does
// not hold what it stages, refuses the compaction there, before anything is
// named or moved: a moved entry with no record that reads, one recorded as
// another move, or a name it does not stage.
func TestJournalCompactRefusesAStageItDidNotFinish(t *testing.T) {
	record := retirementOf("/store", fmt.Sprintf("%064x", 0xbeef), "never-sent", "action.json", "", 0, "", 3600, farFuture)
	for _, tc := range []struct {
		name  string
		files map[string]string
		dirs  []string
		want  string
	}{
		{"no record", nil, []string{"entry"}, "holds a moved entry whose retirement record does not read"},
		{"a record that is not JSON", map[string]string{"retirement.json": `{"recordVersion":`}, []string{"entry"}, "holds a moved entry whose retirement record does not read"},
		{"a record of another move", map[string]string{"retirement.json": record}, []string{"entry"}, "holds a moved entry whose retirement record does not read"},
		{"a name it does not stage", map[string]string{"notes": `{}`}, nil, "holds what this command does not stage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, store, _ := handStore(t)
			archive := filepath.Join(dir, "archive")
			stage := filepath.Join(archive, ".staging-0000000000000001")
			if err := os.MkdirAll(stage, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(archive, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, d := range tc.dirs {
				if err := os.Mkdir(filepath.Join(stage, d), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for name, raw := range tc.files {
				if err := os.WriteFile(filepath.Join(stage, name), []byte(raw), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			before, archived := treeOf(t, store), treeOf(t, archive)
			out, err := compactAt(store, archive, time.Hour, farFuture)
			want := "action-journal-archive: " + stage + " " + tc.want + ": the compaction stopped there"
			if err == nil || err.Error() != want || out != "" {
				t.Fatalf("%v %q\nwant %q", err, out, want)
			}
			sameTree(t, "the store", treeOf(t, store), before)
			sameTree(t, "the archive", treeOf(t, archive), archived)
		})
	}
}
