package main

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// A forwarding cursor and a cursor's staging file left beside a refusal
// journal are passed over by verify, never read, and never carried by an
// export (ADR-0059 §9): the store's verdict, the export's files and the
// restored export's verdict are those of the store without them.
func TestALeftoverCursorStagingFileIsPassedOverAndNeverExported(t *testing.T) {
	corpus := filepath.Join("..", "corpus")
	publicKey, err := corpusPublicKey(corpus)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(corpus, "v3", "stores", "v3-journal-refusal-holds.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector storeVector
	if err := decodeVectorFile(raw, &vector, false); err != nil {
		t.Fatal(err)
	}
	root, storeRoot, registryPath, records, err := materializeVector(vector)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	dir := filepath.Join(storeRoot, journalsDir)
	var journal string
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if stem, ok := strings.CutSuffix(e.Name(), ".jsonl"); ok && isRefusalJournalName(stem) {
			journal = stem
		}
	}
	if journal == "" {
		t.Fatal("the vector holds no refusal journal: the test tests nothing")
	}
	before := verdictBytes(t, storeRoot, registryPath, vector.Authority, records, publicKey)
	// bytes no reader takes: a read of either would be a finding
	for _, file := range []string{journal + ".forwarded", journal + ".forwarded.4242.0123456789ab.tmp"} {
		if err := os.WriteFile(filepath.Join(dir, file), []byte("not a cursor"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if names, err := unknownJournalFiles(storeRoot); err != nil || len(names) != 0 {
		t.Fatalf("journal-unknown: %q %v", names, err)
	}
	if got := verdictBytes(t, storeRoot, registryPath, vector.Authority, records, publicKey); !bytes.Equal(got, before) {
		t.Fatalf("the leftovers changed the verdict:\nwithout: %s\nwith:    %s", before, got)
	}
	out := filepath.Join(t.TempDir(), "export")
	kind := newFsKind(fsLayout{store: storeRoot, registry: registryPath})
	if _, err := writeExport(exportInputs{authority: vector.Authority, keyID: keyIDFor(publicKey), kind: kind, storeRoot: storeRoot, decisionRecords: records}, out); err != nil {
		t.Fatalf("export: %v", err)
	}
	var carried []string
	if err := filepath.WalkDir(out, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.Contains(d.Name(), ".forwarded") {
			carried = append(carried, d.Name())
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(carried) != 0 {
		t.Fatalf("the export carries %q", carried)
	}
	restored := filepath.Join(t.TempDir(), "restored")
	restoreTree(t, out, restored)
	requireExportChecks(t, restored)
	if got := restoredVerdict(t, restored, vector.Authority, publicKey); !bytes.Equal(got, before) {
		t.Fatalf("the restored export's verdict differs:\nstore:    %s\nrestored: %s", before, got)
	}
}

// The forwarder's start removes the cursor staging files left for its own
// journals alone: a regular file of the exact form. Another journal's, a
// near miss, the cursor itself and a link of the form are left as they are.
func TestTheForwardersStartRemovesItsOwnJournalsStagingFilesAlone(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, journalsDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	own, other := refusalJournalName(callerScopeA), refusalJournalName(callerScopeB)
	write := func(file string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, file), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	gone := []string{own + ".forwarded.4242.0123456789ab.tmp", own + ".forwarded.7.ffffffffffff.tmp"}
	kept := []string{
		own + ".jsonl", own + ".forwarded",
		other + ".forwarded.4242.0123456789ab.tmp",
		own + ".forwarded.4242.0123456789ab",
		own + ".forwarded.4242.0123456789abc.tmp",
	}
	for _, file := range append(slices.Clone(gone), kept...) {
		write(file)
	}
	// a link of the exact form is not a regular file: it stays, and what it
	// names is untouched
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := own + ".forwarded.99.aaaaaaaaaaaa.tmp"
	linked := os.Symlink(target, filepath.Join(dir, link)) == nil
	if linked {
		kept = append(kept, link)
	}
	owner := newRefusalEntryForwarding(&receiptSinkSpec{url: "http://127.0.0.1:9/", deliveryV3: true, refusalEntries: true}, withCursors{standInJournals{own}, fsForwardingCursors{root: root, mu: &sync.Mutex{}}})
	owner.clearStaged()
	for _, file := range gone {
		if _, err := os.Lstat(filepath.Join(dir, file)); !os.IsNotExist(err) {
			t.Errorf("%s is left: %v", file, err)
		}
	}
	for _, file := range kept {
		if _, err := os.Lstat(filepath.Join(dir, file)); err != nil {
			t.Errorf("%s went: %v", file, err)
		}
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != "kept" {
		t.Errorf("the link's target: %q %v", b, err)
	}
}

// standInJournals is a refusal entry source naming these journals and
// holding no entries.
type standInJournals []string

func (s standInJournals) journals() ([]string, error) { return s, nil }
func (standInJournals) entriesAfter(string, int64, int) ([]refusalEntryLine, error) {
	return nil, nil
}
func (standInJournals) cursors() forwardingCursors { return nil }
func (standInJournals) locked(_ string, _ refusalEntryLine, fn func(forwardingCursors) error) error {
	return fn(nil)
}
