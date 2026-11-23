package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A journal delete that fails part way does not block the second run: the
// journal is renamed before it is deleted, so nothing under the live name
// reads as pending, and the second run finishes the delete.
func TestRemoveScopeFinishesAJournalDeleteThatFailedPartWay(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a directory's permissions do not stop the superuser's delete")
	}
	store := t.TempDir()
	journal, err := openScopedActionJournal(store, callerScopeB)
	if err != nil {
		t.Fatal(err)
	}
	journal.close()
	path := scopedActionJournalPath(store, callerScopeB)
	removing := filepath.Join(filepath.Dir(path), scopedJournalRemoving(callerScopeB))
	entry := strings.Repeat("a", 64)
	// an entry dispatched without an answer: pending while the journal is live
	if err := os.MkdirAll(filepath.Join(path, entry, "held"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, entry, actionDispatchName(1)), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, entry, "held", "x"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if refused, err := pendingScopedKeys(store, callerScopeB, nil); err != nil || len(refused) != 1 || !strings.Contains(refused[0], "does not read") {
		t.Fatalf("the live entry is pending, naming an unreadable record as one cause: %v %v", refused, err)
	}
	if err := os.Chmod(filepath.Join(path, entry, "held"), 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(removing, entry, "held"), 0700) })
	var first removalOutcome
	if err := removeScopedActionJournal(store, callerScopeB, &first); err == nil {
		t.Fatal("the delete through an unwritable directory succeeded")
	}
	if refused, err := pendingScopedKeys(store, callerScopeB, nil); err != nil || len(refused) != 0 {
		t.Fatalf("after the failed delete, a second run is refused: %v %v", refused, err)
	}
	if err := os.Chmod(filepath.Join(removing, entry, "held"), 0700); err != nil {
		t.Fatal(err)
	}
	var second removalOutcome
	if err := removeScopedActionJournal(store, callerScopeB, &second); err != nil || len(second.notes) != 1 {
		t.Fatalf("the second run: %v %v", err, second.notes)
	}
	for _, p := range []string{path, removing} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("%s is still there: %v", p, err)
		}
	}
}
