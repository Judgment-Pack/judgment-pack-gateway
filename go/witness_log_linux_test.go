//go:build linux

package main

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

// The one line through which the witness asks the system to make bytes
// durable asks the kernel: fsync(2) of a pipe answers EINVAL, an answer no
// other call made here gives for a pipe -- a stat succeeds, and a sync
// that was never asked answers nothing -- and of a file it answers nothing.
// That the kernel and its disk then keep the bytes is beyond this test.
func TestWitnessSyncAsksTheKernel(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if err := syncToSystem(w); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("a sync of a pipe answered %v, not EINVAL: the kernel was not asked", err)
	}
	f, err := os.CreateTemp(t.TempDir(), "sync")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syncToSystem(f); err != nil {
		t.Fatalf("a sync of a file: %v", err)
	}
}
