package main

// The filesystem kind's own safeguards, which no conformance case can see
// from outside a kind: the sync of a staging file before its name is put in
// place, and a series that would be made outside the receipts root.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A receipt and an artifact are each written to a staging file beside
// their name, and that file is synced, with every byte in it, before the
// name is put in place; a sync that fails is a durability fault, and
// nothing is kept under the name.
func TestTheStagingFileIsSyncedBeforeItsNameIsPut(t *testing.T) {
	root := t.TempDir()
	kind := newFsKind(fsLayout{store: filepath.Join(root, "store"), registry: filepath.Join(root, "registry.jsonl")})
	if err := kind.makeStore(); err != nil {
		t.Fatal(err)
	}
	if _, err := kind.receipts().makeSeries("session"); err != nil {
		t.Fatal(err)
	}
	artifact := []byte("the bytes a receipt names")
	sum := sha256.Sum256(artifact)
	receipt := []byte("{\"callIndex\":0}\n")
	writes := []struct {
		what  string
		near  string
		data  []byte
		write func() error
	}{
		{"an artifact", filepath.Join(root, "store", "artifacts", hex.EncodeToString(sum[:])), artifact, func() error {
			_, err := kind.artifacts().putBlob(artifact)
			return err
		}},
		{"a receipt", filepath.Join(root, "store", "receipts", "session", "0.json"), receipt, func() error {
			return kind.receipts().createIndexed("session", 0, receipt)
		}},
	}
	defer func() { stagedSync = nil }()

	for _, w := range writes {
		// a failed sync: a durability fault, the name never put in place
		// and the staging file gone
		stagedSync = func(file *os.File) error { return errors.New("the disk keeps nothing more") }
		requireFault(t, w.what+" whose staging file could not be synced", w.write(), faultDurability)
		if _, err := os.Lstat(w.near); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s whose staging file could not be synced is kept: %v", w.what, err)
		}
		requireNoStagingFile(t, filepath.Dir(w.near))

		// a sync that succeeds: once, of the staging file beside the
		// name, holding every byte, before the name is there
		var synced []string
		stagedSync = func(file *os.File) error {
			synced = append(synced, file.Name())
			if filepath.Dir(file.Name()) != filepath.Dir(w.near) || !strings.HasSuffix(file.Name(), ".tmp") {
				t.Errorf("%s: the file synced is %s, not a staging file beside %s", w.what, file.Name(), w.near)
			}
			if held, err := os.ReadFile(file.Name()); err != nil || !bytes.Equal(held, w.data) {
				t.Errorf("%s: the staging file holds %q at its sync (%v), not every byte", w.what, held, err)
			}
			if _, err := os.Lstat(w.near); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s: the name is in place before its staging file is synced: %v", w.what, err)
			}
			return file.Sync()
		}
		if err := w.write(); err != nil {
			t.Fatalf("%s: %v", w.what, err)
		}
		if len(synced) != 1 {
			t.Fatalf("%s: %d staging files synced, want 1", w.what, len(synced))
		}
		if kept, err := os.ReadFile(w.near); err != nil || !bytes.Equal(kept, w.data) {
			t.Fatalf("%s kept as %q (%v)", w.what, kept, err)
		}
		requireNoStagingFile(t, filepath.Dir(w.near))
	}
}

func requireNoStagingFile(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("a staging file is left behind: %s", e.Name())
		}
	}
}

// A series is a directory directly under the receipts root, or nothing:
// a name that would put it anywhere else is refused by every operation
// before anything is made, whatever rule the caller's names were held to.
func TestASeriesNeverEscapesTheReceiptsRoot(t *testing.T) {
	top := t.TempDir()
	receipts := fsIndexed{root: filepath.Join(top, "store", "receipts")}
	for _, series := range []string{"..", "../outside", "../../outside", ".", "", "a/../../outside", "nested/deeper"} {
		made, err := receipts.makeSeries(series)
		requireFault(t, "a series made at "+series, err, faultRefused)
		if made {
			t.Fatalf("a series made at %q is this call's", series)
		}
		requireFault(t, "an entry created in "+series, receipts.createIndexed(series, 0, []byte("{}\n")), faultRefused)
		_, err = receipts.listEntries(series)
		requireFault(t, "the entries listed in "+series, err, faultRefused)
		_, err = receipts.getEntry(series, "0")
		requireFault(t, "an entry read in "+series, err, faultRefused)
	}
	if entries, err := os.ReadDir(top); err != nil || len(entries) != 0 {
		t.Fatalf("refused series made something: %v %v", entries, err)
	}
	// a series directly under the root is made
	if made, err := receipts.makeSeries("session"); err != nil || !made {
		t.Fatalf("a series under the root: %v %v", made, err)
	}
}
