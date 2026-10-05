//go:build unix

package main

import (
	"fmt"
	"os"
	"syscall"
)

// openNoFollowAppend opens a witness file in its held directory to read and
// to append, following no link and blocking on nothing, so what is opened
// is judged by the descriptor (openEntryBy).
func openNoFollowAppend(dir *os.Root, name string) (*os.File, error) {
	return dir.OpenFile(name, os.O_RDWR|os.O_APPEND|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// witnessFilePrivate is why a witness file, as its descriptor reports it,
// is not the witness's own, or nil: owned by root or by this process, and
// neither readable nor writable by its group or by others. The witness makes
// its files 0600; one with a wider mode was put there by someone else, or
// opened to them since.
func witnessFilePrivate(info os.FileInfo) error {
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("has mode %04o, open to its group or to others; the witness keeps its files 0600", perm)
	}
	if owner := ownerIDsOf(info); owner.known && owner.uid != 0 && owner.uid != os.Geteuid() {
		return fmt.Errorf("is owned by uid %d, neither root nor this process", owner.uid)
	}
	return nil
}
