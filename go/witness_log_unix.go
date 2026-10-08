//go:build unix

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// witnessFilesKept: on Unix a witness keeps its files, each locked by what
// it is and its names counted.
const witnessFilesKept = true

// witnessFileFlags is how a witness file is opened: to read, and to append.
const witnessFileFlags = os.O_RDWR | os.O_APPEND

// openNoFollowAppend opens a witness file in its held directory to read and
// to append, following no link and blocking on nothing, so what is opened
// is judged by the descriptor (openEntryBy).
func openNoFollowAppend(dir *os.Root, name string) (*os.File, error) {
	return dir.OpenFile(name, witnessFileFlags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// witnessFileHeld is why a witness file, as its descriptor reports it, is
// not the witness's own, or nil: owned by root or by this process, neither
// readable nor writable by its group or by others, and with exactly one
// name. The witness makes its files 0600 and links none of them; a wider
// mode was put there by someone else, and a second name is a way to reach
// the file this witness never looked at.
func witnessFileHeld(info os.FileInfo) error {
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("has mode %04o, open to its group or to others; the witness keeps its files 0600", perm)
	}
	if owner := ownerIDsOf(info); owner.known && owner.uid != 0 && owner.uid != os.Geteuid() {
		return fmt.Errorf("is owned by uid %d, neither root nor this process", owner.uid)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("has names that cannot be counted")
	}
	if uint64(st.Nlink) != 1 {
		return fmt.Errorf("has %d names (hard links); a witness file has exactly one, so that no other name reaches it", st.Nlink)
	}
	return nil
}

// openWitnessDir opens a held directory itself, read-only, following no
// link: the descriptor its syncs go through.
func openWitnessDir(dir *os.Root) (*os.File, error) {
	return dir.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
}

// lockWitnessFileOS is lockWitnessFile with the system's flock(2).
func lockWitnessFileOS(file *os.File) error { return lockWitnessFile(file, syscall.Flock) }

// lockWitnessFile takes an exclusive lock on the file itself, through its
// descriptor: flock(2) locks the open file, whatever name -- a hard link, a
// linked directory -- it was opened by, so a second witness, or a second
// open in this one, that reaches it by any name is refused. The lock is
// held until the descriptor is closed. A witness that cannot take it, for
// any reason -- held by another, or no lock to be had -- refuses rather
// than waits or goes on without it.
func lockWitnessFile(file *os.File, flock func(fd int, how int) error) error {
	conn, err := file.SyscallConn()
	if err != nil {
		return err
	}
	var lockErr error
	if err := conn.Control(func(fd uintptr) {
		lockErr = flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB)
	}); err != nil {
		return err
	}
	if errors.Is(lockErr, syscall.EWOULDBLOCK) {
		return errWitnessHeld
	}
	if lockErr != nil {
		return fmt.Errorf("could not be locked: %v", lockErr)
	}
	return nil
}
