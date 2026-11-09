//go:build unix

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// lockDirectory takes a lock on the directory at path through a descriptor of
// its own, with flock(2), as the registry is locked (lockRegistry): shared, as a
// gateway process holds its store while it serves, or exclusive, as a journal
// compaction holds the store and its archive. It is held until the file
// returned is closed, or the process ends, and refused at once when another
// holds it in a way this one excludes (errDirectoryHeld), and for any other
// reason it cannot be had, rather than waited for or gone on without. The lock
// is advisory: it keeps out the processes that take it, and stops no write.
func lockDirectory(path string, exclusive bool) (*os.File, error) {
	dir, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := dir.Stat()
	if err != nil || !info.IsDir() {
		dir.Close()
		return nil, errors.New("it is not a directory")
	}
	conn, err := dir.SyscallConn()
	if err != nil {
		dir.Close()
		return nil, err
	}
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	var lockErr error
	if err := conn.Control(func(fd uintptr) {
		lockErr = syscall.Flock(int(fd), how|syscall.LOCK_NB)
	}); err != nil {
		dir.Close()
		return nil, err
	}
	if errors.Is(lockErr, syscall.EWOULDBLOCK) {
		dir.Close()
		return nil, errDirectoryHeld
	}
	if lockErr != nil {
		dir.Close()
		return nil, fmt.Errorf("flock: %v", lockErr)
	}
	return dir, nil
}

// sameDevice reports whether two files are on one filesystem, where a rename
// between them is a move.
func sameDevice(a, b os.FileInfo) bool {
	sa, okA := a.Sys().(*syscall.Stat_t)
	sb, okB := b.Sys().(*syscall.Stat_t)
	return okA && okB && sa.Dev == sb.Dev
}

// crossDevice is a rename refused because its two names are on different
// filesystems, or mounts.
func crossDevice(err error) bool { return errors.Is(err, syscall.EXDEV) }
