//go:build linux || darwin

package storecontract

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// What the custody's filesystem kind keeps of each document's policy, as
// the custody kept it before the contract.
func TestFilesKeepEachDocumentsPolicy(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	journal := Policy{Limit: 16, ConfirmAbsence: true, SyncDirectory: true, Staging: ".storage-"}
	files := NewFiles(root, Policy{Limit: 8, Staging: ".tmp-"}, map[string]Policy{"intent.json": journal})

	// a link that leads nowhere is no absence where the policy confirms one
	if err := os.Symlink(filepath.Join(dir, "nowhere"), filepath.Join(dir, "intent.json")); err != nil {
		t.Fatal(err)
	}
	_, _, err = files.Get("intent.json")
	requireFault(t, "a link that leads nowhere, confirmed", err, Unreadable)
	if err := os.Remove(filepath.Join(dir, "intent.json")); err != nil {
		t.Fatal(err)
	}
	_, _, err = files.Get("intent.json")
	requireFault(t, "an entry that is not there", err, Absent)

	// each document's bound
	if _, err := files.Put("intent.json", bytes.Repeat([]byte("j"), 16), NoRevision); err != nil {
		t.Fatal(err)
	}
	if _, _, err := files.Get("intent.json"); err != nil {
		t.Fatalf("a document at its bound: %v", err)
	}
	if _, err := files.Put("state.json", bytes.Repeat([]byte("s"), 9), NoRevision); err != nil {
		t.Fatal(err)
	}
	_, _, err = files.Get("state.json")
	requireFault(t, "a document past its bound", err, Unreadable)

	// a file open to others, or one that is no file, is unreadable
	if err := os.WriteFile(filepath.Join(dir, "open.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "open.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err = files.Get("open.json")
	requireFault(t, "a document others may read", err, Unreadable)
	if err := os.Mkdir(filepath.Join(dir, "folder.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, _, err = files.Get("folder.json")
	requireFault(t, "a directory", err, Unreadable)

	// a write leaves no staging file behind, and makes its file private
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Fatalf("a staging file is left: %s", e.Name())
		}
	}
	info, err := os.Stat(filepath.Join(dir, "intent.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the written document: %v %v", info, err)
	}
}

// A document whose policy syncs its directory -- the custody's storage
// intent -- has the held directory synced once its rename is made, and a
// put whose sync fails is a durability fault; a document whose policy
// does not is renamed into place with no directory sync, as before.
func TestFilesSyncTheDirectoryWhereThePolicySaysSo(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	journal := Policy{Limit: 64, ConfirmAbsence: true, SyncDirectory: true, Staging: ".storage-"}
	files := NewFiles(root, Policy{Limit: 64, Staging: ".tmp-"}, map[string]Policy{"intent.json": journal})
	var synced []string
	files.dirSync = func(d *os.File) error {
		held, err := os.ReadFile(filepath.Join(dir, "intent.json"))
		synced = append(synced, string(held))
		if err != nil {
			t.Errorf("the directory is synced before the rename: %v", err)
		}
		if info, err := d.Stat(); err != nil || !info.IsDir() || !os.SameFile(info, mustStat(t, dir)) {
			t.Errorf("what is synced is not the held directory: %v", err)
		}
		return d.Sync()
	}
	if _, err := files.Put("intent.json", []byte("one"), NoRevision); err != nil {
		t.Fatal(err)
	}
	if len(synced) != 1 || synced[0] != "one" {
		t.Fatalf("the directory synced %d times after the storage intent's put, holding %q; want once, after its rename", len(synced), synced)
	}
	if _, err := files.Put("state.json", []byte("{}"), NoRevision); err != nil {
		t.Fatal(err)
	}
	if len(synced) != 1 {
		t.Fatalf("a document whose policy does not sync its directory synced it")
	}
	files.dirSync = func(*os.File) error { return errors.New("the disk keeps nothing more") }
	_, err = files.Put("intent.json", []byte("two"), AnyRevision)
	requireFault(t, "a put whose directory sync fails", err, Durability)
}

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}
