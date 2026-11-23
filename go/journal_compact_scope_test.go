package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Journal compaction compacts each scope identifier's journal by the journal
// of none's rule (ADR-0054): a scoped action's entry and a scoped entry that
// never sent are retired; a name in the scopes directory that is no scope's
// journal is kept. A scope's index that does not read refuses the whole
// compaction before anything moves, in any journal.
func TestJournalCompactWalksEachScopeJournal(t *testing.T) {
	h := actScopeSetup(t)
	key := strings.Repeat("a", 64)
	if code, out := authed(t, h.server, "/act", h.body("act-b", "tickets-b", scopeB, key, h.decisionB, h.cite("b-read", h.scopedSig)), h.tokenB); code != http.StatusOK {
		t.Fatalf("the scoped action: %d %v", code, out)
	}
	store := realPath(t, h.g.storeRoot)
	journal := scopedActionJournalPath(store, callerScopeB)
	bare, topBare := strings.Repeat("1", 64), strings.Repeat("2", 64)
	handEntry(t, journal, bare, map[string]string{"intent.json": handIntent})
	handEntry(t, filepath.Join(store, "actions"), topBare, map[string]string{"intent.json": handIntent})
	if err := os.WriteFile(filepath.Join(store, "actions", scopedActionJournals, "notes"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(realPath(t, h.root), "archive")

	// an index record of the scope's journal that does not read: nothing moves
	index := filepath.Join(journal, actionIndexDirectory)
	if err := os.MkdirAll(index, 0o700); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(index, strings.Repeat("3", 64)+".json")
	if err := os.WriteFile(stray, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := compactAt(store, archive, time.Hour, farFuture); err == nil || !strings.Contains(err.Error(), "does not read: nothing was compacted") {
		t.Fatalf("a scope's index that does not read: %v", err)
	}
	for _, path := range []string{filepath.Join(journal, bare), filepath.Join(store, "actions", topBare)} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("the refused compaction moved %s: %v", path, err)
		}
	}
	if err := os.Remove(stray); err != nil {
		t.Fatal(err)
	}

	who := &caller{issuer: h.g.identity.issuer, subject: subjectB}
	ns := h.g.actionNamespaceIn(who, key, callerScopeB)
	out, err := compactAt(store, archive, time.Hour, farFuture)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"retired " + bare + ": never sent; archived as " + bare + ".1\n",
		"retired " + topBare + ": never sent; archived as " + topBare + ".1\n",
		"kept " + filepath.Join(scopedActionJournals, "notes") + ": not a scope identifier's journal\n",
		"retired " + ns,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the compaction does not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "kept "+scopedActionJournals+":") {
		t.Fatalf("the scopes directory is kept as an entry:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(journal, bare)); !os.IsNotExist(err) {
		t.Fatalf("the scoped entry that never sent is still in its journal: %v", err)
	}
	if _, err := os.Stat(filepath.Join(journal, ns, "action.json")); !os.IsNotExist(err) {
		t.Fatalf("the scoped action's record is still in its journal: %v", err)
	}
}
