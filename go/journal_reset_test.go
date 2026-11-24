package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// unscopedLockLine is the reset's line where the platform locks no registry.
func unscopedLockLine() string {
	if registryLocked {
		return ""
	}
	return "journal reset: this platform locks no registry, so a gateway still running was not looked for; the gateway was to be stopped\n"
}

func runJournalReset(config string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := cmdJournalResetAt([]string{"--config", config, "--unscoped", "--by", "operator-2"}, &stdout, &stderr, fixedStamp(removalStamp))
	return code, stdout.String(), stderr.String()
}

// gateway journal reset --unscoped removes the refusal journal of the
// sources of no scope, its key and its cursor, after a refusal-journal-reset
// entry naming the journal's bytes, written before the key goes; the entry
// verifies, and nothing else in the store changes, a scope's journal, key
// and cursor byte for byte. A second run removes nothing and writes no
// entry, and the next start draws a new key and journals the sources of no
// scope again (gateway #611). A reset that takes a scope's journal, or
// writes its entry after the removal, fails it.
func TestJournalResetTakesTheUnscopedRefusalJournalAlone(t *testing.T) {
	g, config := journalStore(t)
	refusedOnlyJournal(t, g, config, refusedOnly)
	data := refusedOnlyJournal(t, g, config, unscopedMarker)
	dir := filepath.Join(g.storeRoot, journalsDir)
	name := refusalJournalName(unscopedMarker)
	oldKey := readFile(t, filepath.Join(dir, name+".key"))
	before := storeTree(t, g.storeRoot)
	entries := 0
	if _, err := os.Lstat(journalFile(g)); err == nil {
		entries = len(journalEntries(t, g))
	}
	// the entry is in the journal before the first file goes
	atKey := -1
	refusalRemovalStep = func(step string) {
		if step == ".key" {
			atKey = len(journalEntries(t, g))
		}
	}
	t.Cleanup(func() { refusalRemovalStep = nil })

	code, stdout, stderr := runJournalReset(config)
	refusalRemovalStep = nil
	if code != 0 || stdout != "journal reset: the refusal journal of the sources of no scope, "+strconv.Itoa(len(data))+" bytes, its key and its cursor are removed\n" || stderr != unscopedLockLine() {
		t.Fatalf("journal reset: exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	if atKey != entries+1 {
		t.Fatalf("%d entries as the key went, %d before the call", atKey, entries)
	}
	after := storeTree(t, g.storeRoot)
	for _, suffix := range []string{".jsonl", ".key", ".forwarded"} {
		if _, left := after[filepath.Join(journalsDir, name+suffix)]; left {
			t.Errorf("%s stands", suffix)
		}
		delete(before, filepath.Join(journalsDir, name+suffix))
	}
	operator := filepath.Join(journalsDir, operatorJournal+".jsonl")
	if !strings.HasPrefix(after[operator], before[operator]) {
		t.Fatal("the operator journal's earlier entries changed")
	}
	delete(before, operator)
	delete(after, operator)
	if len(after) != len(before) {
		t.Fatalf("%d files after, %d before", len(after), len(before))
	}
	for path, was := range before {
		if after[path] != was {
			t.Errorf("%s changed", path)
		}
	}
	got := journalEntries(t, g)
	if len(got) != entries+1 {
		t.Fatalf("%d entries, %d before", len(got), entries)
	}
	body, _ := got[len(got)-1]["body"].(map[string]any)
	if body["kind"] != refusalJournalResetKind || body["by"] != "operator-2" ||
		body["refusalJournalBytes"] != float64(len(data)) || body["refusalJournalDigest"] != journalDigest(data) ||
		body["removalFrom"] != float64(len(before[removalsFile])) || len(body) != 6 {
		t.Fatalf("the entry: %v", body)
	}
	// the operator journal and the scope's refusal journal each load whole
	if _, said := journalVerdict(t, g, operatorJournal); strings.Join(said, ",") != "journal-from,journal-from" {
		t.Fatalf("the journal's verdict: %v", said)
	}

	// a second run finds no journal: nothing removed, no entry
	journal := readFile(t, journalFile(g))
	code, stdout, stderr = runJournalReset(config)
	if code != 0 || stdout != "journal reset: the refusal journal of the sources of no scope is absent or holds no entry; nothing was removed, and no entry was written\n" || stderr != unscopedLockLine() {
		t.Fatalf("the second run: exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	if readFile(t, journalFile(g)) != journal {
		t.Fatal("a run that removed nothing wrote an entry")
	}

	// the next start draws a new key and journals the sources of no scope
	again := refusedOnlyJournal(t, g, config, unscopedMarker)
	if lines, _ := journalLines(again); len(lines) != 1 {
		t.Fatalf("%d entries in the new journal", len(lines))
	}
	if readFile(t, filepath.Join(dir, name+".key")) == oldKey {
		t.Fatal("the start kept the old key")
	}
}

// The command takes no scope: --scope, a scope argument, or anything but
// its flags, is a usage error before anything is read, on both kinds.
func TestJournalResetOfEitherKindRefusesAnyScopeArgument(t *testing.T) {
	g, config := journalStore(t)
	data := refusedOnlyJournal(t, g, config, unscopedMarker)
	name := refusalJournalName(unscopedMarker)
	missing := filepath.Join(t.TempDir(), "not-read.json")
	for _, args := range [][]string{
		{"--config", missing, "--unscoped", "--by", "operator-2", "--scope", refusedOnly},
		{"--config", missing, "--scope", unscopedMarker, "--by", "operator-2"},
		{"--config", missing, "--unscoped", "--by", "operator-2", refusedOnly},
		{"--config", missing, "--unscoped", unscopedMarker, "--by", "operator-2"},
		{"--config", missing, "--by", "operator-2"},
		{"--config", missing, "--unscoped", "--unscoped", "--by", "operator-2"},
	} {
		var stdout, stderr bytes.Buffer
		if code := cmdJournalResetAt(args, &stdout, &stderr, fixedStamp(removalStamp)); code != 2 || stdout.Len() != 0 ||
			!strings.HasSuffix(stderr.String(), journalResetUsage+"\n") || strings.Contains(stderr.String(), "engine configuration") {
			t.Errorf("journal reset %q: exit %d, %q", args, code, stderr.String())
		}
		stdout.Reset()
		stderr.Reset()
		store := append([]string{"--connection-file", missing, "--owner", "owner-role", "--runtime", "runtime-role"}, args...)
		if code := cmdStoreJournalResetAt(store, &stdout, &stderr, fixedStamp(removalStamp)); code != 2 || stdout.Len() != 0 ||
			!strings.HasSuffix(stderr.String(), storeJournalResetUsage+"\n") || strings.Contains(stderr.String(), "connection-file:") {
			t.Errorf("store journal-reset %q: exit %d, %q", args, code, stderr.String())
		}
	}
	if now := readFile(t, filepath.Join(g.storeRoot, journalsDir, name+".jsonl")); now != string(data) {
		t.Fatal("the journal changed")
	}
}

// A run cut off after its entry and before the journal went is completed
// by the next start where a source of no scope is configured, with one
// stderr line, or by a second run, with no second entry. The journal here
// is one whose key was lost, as after a restore: the start says it is
// write-failed until the reset.
func TestJournalResetCutOffIsCompletedByTheNextStartOrASecondRun(t *testing.T) {
	for _, by := range []string{"start", "second run"} {
		t.Run(by, func(t *testing.T) {
			g, config := journalStore(t)
			refusedOnlyJournal(t, g, config, unscopedMarker)
			dir := filepath.Join(g.storeRoot, journalsDir)
			name := refusalJournalName(unscopedMarker)
			if err := os.Remove(filepath.Join(dir, name+".key")); err != nil {
				t.Fatal(err)
			}
			var said bytes.Buffer
			key := testSigningKey(t, config)
			if _, err := newRefusalJournals(&refusalJournalConfig{maxBytes: refusalDefaultCap}, map[string]bool{unscopedMarker: true}, refusalFS{root: g.storeRoot},
				func() *signingKey { return key }, g.reachedKeys, &said); err != nil || !strings.Contains(said.String(), "holds entries and no key") {
				t.Fatalf("the start before the reset: %v %q", err, said.String())
			}
			// the run cut off: its entry appended, nothing removed
			keys, err := g.reachedKeys()
			if err != nil {
				t.Fatal(err)
			}
			j, err := beginOperatorJournal(g.storeRoot, g.regPath, operatorJournalVersion, key, keys, fixedStamp(removalStamp))
			if err != nil {
				t.Fatal(err)
			}
			r, err := holdRefusalRemoval(g.storeRoot, unscopedMarker)
			if err != nil {
				t.Fatal(err)
			}
			if err := j.refusalResetEntry(refusalResetBody("operator-2", r.data)); err != nil {
				t.Fatal(err)
			}
			r.release()
			entries := len(journalEntries(t, g))

			if by == "start" {
				g.sources = map[string]sourceSpec{"plain": {}}
				var stderr bytes.Buffer
				if err := g.completeCutOffRefusalRemovals(&stderr); err != nil ||
					stderr.String() != "refusal journal: journal "+name+": a journal reset run was cut off; "+refusalResetCompletedNote+"\n" {
					t.Fatalf("the start: %v %q", err, stderr.String())
				}
			} else if code, stdout, stderr := runJournalReset(config); code != 0 || stdout != "journal reset: "+refusalResetCompletedNote+"\n" || stderr != unscopedLockLine() {
				t.Fatalf("the second run: exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
			}
			if n := len(journalEntries(t, g)); n != entries {
				t.Fatalf("%d entries after the completion, %d before", n, entries)
			}
			for _, suffix := range []string{".jsonl", ".forwarded"} {
				if _, err := os.Lstat(filepath.Join(dir, name+suffix)); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("%s stands: %v", suffix, err)
				}
			}
			said.Reset()
			if _, err := newRefusalJournals(&refusalJournalConfig{maxBytes: refusalDefaultCap}, map[string]bool{unscopedMarker: true}, refusalFS{root: g.storeRoot},
				func() *signingKey { return key }, g.reachedKeys, &said); err != nil || said.Len() != 0 {
				t.Fatalf("the start after the reset: %v %q", err, said.String())
			}
		})
	}
}

// A gateway process serving the store holds its directory shared
// (holdServedStore), under its own registry, which need not be the one a
// command's configuration names. remove-scope and journal reset each take
// the store exclusive and refuse while one serves, before anything is
// read or removed; once it stops, the same call removes. Where the platform
// keeps no such lock, nothing is held, as remove-scope's registry check.
func TestRemoveScopeAndJournalResetRefuseAStoreAGatewayServes(t *testing.T) {
	if !actionJournalSupported {
		t.Skip("this platform keeps no store lock")
	}
	g, config := journalStore(t)
	refusedOnlyJournal(t, g, config, refusedOnly)
	refusedOnlyJournal(t, g, config, unscopedMarker)
	before := storeTree(t, g.storeRoot)
	serving, err := holdServedStore(g.storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := cmdRemoveScopeAt([]string{"--config", config, "--scope", refusedOnly, "--by", "operator-2"}, &stdout, &stderr, fixedStamp(removalStamp)); code != 1 ||
		!strings.Contains(stderr.String(), "store-served: a gateway process is serving the store") {
		t.Errorf("remove-scope while a gateway serves the store: exit %d, %q", code, stderr.String())
	}
	if code, _, stderr := runJournalReset(config); code != 1 || !strings.Contains(stderr, "store-served: a gateway process is serving the store") {
		t.Errorf("journal reset while a gateway serves the store: exit %d, %q", code, stderr)
	}
	if after := storeTree(t, g.storeRoot); !reflect.DeepEqual(after, before) {
		t.Fatal("a refused call changed the store")
	}
	serving.Close()
	stdout.Reset()
	stderr.Reset()
	if code := cmdRemoveScopeAt([]string{"--config", config, "--scope", refusedOnly, "--by", "operator-2"}, &stdout, &stderr, fixedStamp(removalStamp)); code != 0 {
		t.Fatalf("remove-scope once the gateway stopped: exit %d, %q", code, stderr.String())
	}
	if code, _, stderr := runJournalReset(config); code != 0 {
		t.Fatalf("journal reset once the gateway stopped: exit %d, %q", code, stderr)
	}
}
