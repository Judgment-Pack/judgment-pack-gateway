//go:build unix

package main

import (
	"errors"
	"os"
	"syscall"
)

// fileOwnerIDs is a file's owner, as the kernel reports it.
type fileOwnerIDs struct {
	uid, gid int
	known    bool
}

func ownerIDsOf(info os.FileInfo) fileOwnerIDs {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return fileOwnerIDs{uid: int(st.Uid), gid: int(st.Gid), known: true}
	}
	return fileOwnerIDs{}
}

// keepOwner gives the file the owner the replaced file had, when that is
// not this process's own: a root connect over a file the signer owns
// leaves it the signer's.
func keepOwner(dir *os.Root, name string, owner fileOwnerIDs) error {
	if !owner.known || (owner.uid == os.Geteuid() && owner.gid == os.Getegid()) {
		return nil
	}
	if err := dir.Chown(name, owner.uid, owner.gid); err != nil {
		return errors.New("the file's owner could not be kept: " + err.Error())
	}
	return nil
}

// lockBeside takes an advisory lock on <name>.lock in the directory, held
// until the returned function is called, so that one connect at a time
// writes the file; a connect that finds it held refuses rather than waits,
// since the holder may be running checks for minutes.
func lockBeside(dir *os.Root, name string) (func(), error) {
	lock, err := dir.OpenFile(name+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.New("another connect holds " + name + ".lock; wait for it")
		}
		return nil, err
	}
	return func() { lock.Close() }, nil
}
