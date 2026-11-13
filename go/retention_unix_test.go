//go:build unix

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A FIFO at the removal file's path is not read, and nothing waits on it:
// the removed receipt is artifact-missing (SPEC.md §1.3a, §4.1). A regular
// file there that cannot be read is no verdict: the records are there and
// unreadable, not absent.
func TestARemovalFileThatIsAFIFOOrCannotBeRead(t *testing.T) {
	t.Run("a FIFO", func(t *testing.T) {
		s := materializeRetention(t, "v3-artifact-removed")
		file := filepath.Join(s.root, removalsFile)
		if err := os.Remove(file); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(file, 0o600); err != nil {
			t.Fatal(err)
		}
		if status, _ := statusOf(t, s.verdict(t, ""), 0); status != "artifact-missing" {
			t.Fatalf("a FIFO at the removal file's path: %s, want artifact-missing", status)
		}
	})
	t.Run("a file that cannot be read", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads a file of any mode")
		}
		s := materializeRetention(t, "v3-artifact-removed")
		if err := os.Chmod(filepath.Join(s.root, removalsFile), 0); err != nil {
			t.Fatal(err)
		}
		if rep, err := s.verify(t, ""); err == nil {
			t.Fatalf("a removal file that cannot be read gave a verdict: %+v", rep)
		}
	})
}
