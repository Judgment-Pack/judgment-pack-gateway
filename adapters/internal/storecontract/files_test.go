//go:build linux || darwin

package storecontract

import (
	"bytes"
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
