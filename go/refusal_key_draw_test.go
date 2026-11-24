package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// A draw ended after its staged file and before the link leaves no key, so
// the next start draws one whole; a staged file a start left in the store's
// root is removed at the next, only its own journals' and only a regular
// file.
func TestAKeyDrawEndedPartWayLeavesNoShortKey(t *testing.T) {
	root := t.TempDir()
	f := refusalFS{root: root}
	name := refusalJournalName(callerScopeA)
	path := filepath.Join(f.dir(), name+".key")
	keyDrawCut = func() error { return errors.New("ended mid-draw") }
	t.Cleanup(func() { keyDrawCut = nil })
	if _, _, err := f.key(name); err == nil {
		t.Fatal("the cut draw answered a key")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a cut draw left a key file: %v", err)
	}
	keyDrawCut = nil
	k, missing, err := f.key(name)
	if err != nil || missing || len(k) != 32 {
		t.Fatalf("the next draw: %v %v %d", err, missing, len(k))
	}
	if again, _, err := f.key(name); err != nil || !bytes.Equal(again, k) {
		t.Fatalf("the key read back: %v", err)
	}

	other := refusalJournalName("another-scope")
	leftover := "." + name + ".key.4242.0123456789ab.tmp"
	kept := []string{"." + other + ".key.4242.0123456789ab.tmp", name + ".key.4242.0123456789ab.tmp"}
	for _, n := range append([]string{leftover}, kept...) {
		if err := os.WriteFile(filepath.Join(root, n), []byte("ab"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// uppercase hexadecimal is not the exact form; where the filesystem
	// folds case (as on Windows and macOS by default) that name is the
	// leftover itself, so the case is made only where the two are two files
	upper := "." + name + ".key.4242.0123456789AB.tmp"
	if err := os.WriteFile(filepath.Join(root, upper), []byte("AB"), 0o600); err != nil {
		t.Fatal(err)
	}
	if a, err := os.Stat(filepath.Join(root, leftover)); err != nil {
		t.Fatal(err)
	} else if b, err := os.Stat(filepath.Join(root, upper)); err != nil {
		t.Fatal(err)
	} else if !os.SameFile(a, b) {
		kept = append(kept, upper)
	} else if err := os.WriteFile(filepath.Join(root, leftover), []byte("ab"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := "." + name + ".key.4243.0123456789ab.tmp"
	if err := os.Symlink(filepath.Join(root, kept[0]), filepath.Join(root, linked)); err != nil {
		t.Skipf("no symbolic link here: %v", err)
	}
	if _, err := newRefusalJournals(&refusalJournalConfig{maxBytes: refusalDefaultCap}, map[string]bool{callerScopeA: true}, f, nil, nil, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, leftover)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the start's own staged file stands: %v", err)
	}
	for _, n := range append(kept, linked) {
		if _, err := os.Lstat(filepath.Join(root, n)); err != nil {
			t.Errorf("%s went: %v", n, err)
		}
	}
}
