//go:build unix

package main

import (
	"errors"
	"fmt"
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

// parentHeld is why another user could replace an entry of the
// configuration's directory, or nil: the rule the credentials' directories
// are held to (holdDirectory), on the directory as the kernel reports it.
func parentHeld(info os.FileInfo) error {
	owner := ownerIDsOf(info)
	if owner.known && owner.uid != 0 && owner.uid != os.Geteuid() {
		return fmt.Errorf("is owned by uid %d, neither root nor this process, so its owner could replace what is in it", owner.uid)
	}
	perm := info.Mode().Perm()
	if perm&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("is writable beyond its owner (mode %04o) without the sticky bit, so another user could replace what is in it", perm)
	}
	return nil
}

// lockOpened, when set, runs between opening an existing lock and judging
// it: a test's way of putting another file in its place at that moment.
var lockOpened func()

// lockHeld is why an existing lock file cannot be trusted, or nil.
func lockHeld(dir *os.Root, lockName string, lock *os.File, owner fileOwnerIDs) error {
	info, err := lock.Stat()
	if err != nil {
		return err
	}
	entry, err := dir.Lstat(lockName)
	if err != nil {
		return err
	}
	if entry.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !os.SameFile(entry, info) {
		return errors.New(lockName + " is not the regular file it names; remove it")
	}
	holder := ownerIDsOf(info)
	if holder.known && holder.uid != 0 && holder.uid != os.Geteuid() && !(owner.known && holder.uid == owner.uid) {
		return fmt.Errorf("%s is owned by uid %d, neither root, this process nor the configuration's owner, who could replace it; remove it", lockName, holder.uid)
	}
	return nil
}

// keepOwner gives the open file the owner the replaced file had, whenever
// the file written does not have it already -- a directory with the setgid
// bit gives a new file its group, whoever made it -- through the
// descriptor: a root connect over a file the signer owns leaves it the
// signer's, and a connect that cannot keep the owner does not replace.
func keepOwner(file *os.File, owner fileOwnerIDs) error {
	if !owner.known {
		return nil
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	actual := ownerIDsOf(info)
	if actual.known && actual.uid == owner.uid && actual.gid == owner.gid {
		return nil
	}
	if err := file.Chown(owner.uid, owner.gid); err != nil {
		return errors.New("the file's owner could not be kept: " + err.Error())
	}
	return nil
}

// openConfigForRead opens the file in the held directory without blocking
// on what is not a file, so what is opened is judged by the descriptor and
// never waited on; whether it is the entry's own file is judged by the
// caller, since the held directory follows a link within itself.
func openConfigForRead(dir *os.Root, name string) (*os.File, error) {
	return dir.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

// lockBeside takes an advisory lock on <name>.lock in the directory, held
// until the returned function is called, so that one connect at a time
// writes the file; a connect that finds it held refuses rather than waits,
// since the holder may be running checks for minutes. A lock file this
// connect creates is given the configuration's owner, so a later connect by
// that owner can take it after one by root.
func lockBeside(dir *os.Root, name string, owner fileOwnerIDs) (func(), error) {
	lockName := name + ".lock"
	lock, err := dir.OpenFile(lockName, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		if owner.known {
			if err := lock.Chown(owner.uid, owner.gid); err != nil {
				lock.Close()
				return nil, errors.New("the lock file could not be given the configuration's owner: " + err.Error())
			}
		}
	} else {
		// A lock that is already there is trusted only when nobody else
		// could replace it: a regular file, owned by root, by this
		// process or by the configuration's owner, and the entry named is
		// the file opened -- in a sticky directory another user's file
		// can be unlinked by that user and a fresh one put in its place,
		// which a later connect would lock instead of this one's.
		if lock, err = dir.OpenFile(lockName, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0); err != nil {
			return nil, errors.New("cannot open " + lockName + ": " + err.Error())
		}
		if lockOpened != nil {
			lockOpened()
		}
		if err := lockHeld(dir, lockName, lock, owner); err != nil {
			lock.Close()
			return nil, err
		}
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.New("another connect holds " + lockName + "; wait for it")
		}
		return nil, err
	}
	return func() { lock.Close() }, nil
}
