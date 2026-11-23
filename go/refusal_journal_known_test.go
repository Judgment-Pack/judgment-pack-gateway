package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// refusalNearMisses are names a refusal journal's file is not: a wrong
// length, a letter out of a..p, upper case, another suffix or a suffix
// added, and the prefix alone. Each is journal-unknown, as a file planted
// under the prefix is (ADR-0059 §1; SPEC.md §4 step 9).
func refusalNearMisses(name string) []string {
	stem := strings.TrimPrefix(name, refusalJournalPrefix)
	return []string{
		refusalJournalPrefix + stem[:23] + ".jsonl",
		refusalJournalPrefix + stem + "a.jsonl",
		refusalJournalPrefix + strings.Repeat("q", 24) + ".jsonl",
		refusalJournalPrefix + strings.ToUpper(stem) + ".jsonl",
		name + ".jsonl.bak",
		name + ".KEY",
		name + ".pending",
		name,
		refusalJournalPrefix + "anything.jsonl",
		refusalJournalPrefix + ".jsonl",
	}
}

// Only a refusal journal's exact name, with .jsonl or .key, is a file this
// release reads; every near miss is named journal-unknown, and the files
// of the exact name are not.
func TestOnlyARefusalJournalsExactNameIsKnown(t *testing.T) {
	name := refusalJournalName(callerScopeA)
	root := t.TempDir()
	dir := filepath.Join(root, journalsDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	misses := refusalNearMisses(name)
	for _, file := range append([]string{name + ".jsonl", name + ".key"}, misses...) {
		if err := os.WriteFile(filepath.Join(dir, file), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	names, err := unknownJournalFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	want := slices.Clone(misses)
	slices.Sort(want)
	if !slices.Equal(names, want) {
		t.Fatalf("journal-unknown:\n got %q\nwant %q", names, want)
	}
	for _, file := range []string{name + ".jsonl", name + ".key"} {
		if !isKnownJournalFile(file) {
			t.Errorf("%s is not known", file)
		}
	}
	// an export carries the journal by its exact name, and never its key
	// nor a near miss
	if !exportPathWritten("store/journals/" + name + ".jsonl") {
		t.Error("an export reader refuses a refusal journal")
	}
	for _, file := range append([]string{name + ".key"}, misses...) {
		if exportPathWritten("store/journals/" + file) {
			t.Errorf("an export reader takes %s", file)
		}
	}
}

// On the PostgreSQL kind the same form holds: a refusal journal's rows of its
// exact name are exported, and a near miss is refused by its name.
func TestAPostgresExportRefusesANearMissOfARefusalJournalsName(t *testing.T) {
	kind, db := pgTestKind(t, "", nil)
	name := refusalJournalName(callerScopeA)
	c := db.runtimeConn(t)
	insert := func(journal string) {
		t.Helper()
		if _, err := c.exec(`INSERT INTO gateway.journal_records (journal, ordinal, line) VALUES ($1, 0, '\x7b7d'::bytea)`, journal); err != nil {
			t.Fatal(err)
		}
	}
	insert(name)
	if _, err := (pgEveryScope{kind}).snapshot(); errors.Is(err, errUnknownJournal) {
		t.Fatalf("a refusal journal's exact name: %v", err)
	}
	// the schema admits these two (upper case it refuses itself)
	short := name[:len(name)-1]
	outside := refusalJournalPrefix + strings.Repeat("q", 24)
	insert(short)
	insert(outside)
	_, err := (pgEveryScope{kind}).snapshot()
	if !errors.Is(err, errUnknownJournal) || !strings.HasSuffix(err.Error(), ": "+short+", "+outside) {
		t.Fatalf("a near miss: %v", err)
	}
}
