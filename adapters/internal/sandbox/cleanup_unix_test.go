//go:build !windows

package sandbox

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// dupFd is a new descriptor on f's file, for a reader that closes it.
func dupFd(t *testing.T, f *os.File) int {
	t.Helper()
	fd, err := syscall.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	return fd
}

// What a server leaves in its private temporary directory -- a directory it
// made unwritable or unsearchable, with files in it -- never keeps the
// directory from being removed.
func TestPrivateTempRemovedWhateverTheServerLeft(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root removes regardless of modes")
	}
	tmp, err := os.MkdirTemp("", "gateway-source-")
	if err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(tmp, "d")
	hidden := filepath.Join(tmp, "e")
	for _, dir := range []string{locked, hidden} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	os.Chmod(locked, 0o500)
	os.Chmod(hidden, 0)
	if err := removePrivateTemp(tmp); err != nil {
		os.Chmod(locked, 0o700)
		os.Chmod(hidden, 0o700)
		os.RemoveAll(tmp)
		t.Fatalf("removal failed: %v", err)
	}
	if _, err := os.Lstat(tmp); !os.IsNotExist(err) {
		t.Fatal("the private temporary directory remains")
	}
}
