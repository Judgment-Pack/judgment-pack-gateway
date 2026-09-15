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

// The access(2) modes, which the syscall package does not name.
const (
	accessWrite   = 2 // W_OK
	accessExecute = 1 // X_OK
)

// canWrite reports whether this process may write at the path -- and
// pass through it, for a directory -- as the kernel judges it for the
// process's real ids, which are its effective ones: the gateway is not
// a set-user-id program and never switches itself. Nothing is written.
func canWrite(path string) bool {
	mode := uint32(accessWrite)
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		mode |= accessExecute
	}
	return syscall.Access(path, mode) == nil
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

// syncDirectory makes a directory's entries durable: what was made, linked
// or renamed in it survives a crash once this returns.
func syncDirectory(dir *os.Root, name string) error {
	d, err := dir.OpenFile(name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// openNoFollow opens a file in the held directory following no link and
// blocking on nothing, so what is opened is judged by the descriptor.
func openNoFollow(dir *os.Root, name string) (*os.File, error) {
	return dir.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// snapshotHeld is why a snapshot, or the snapshots' directory, is not what
// the frontend will verify at start and can read, or nil: of its kind,
// owned by root or by the configuration's owner, belonging to neither the
// MCP server's user nor its group, writable by neither group nor others, a
// directory others may pass through -- the MCP server is neither its owner
// nor in its group -- and a snapshot of exactly its mode.
func snapshotHeld(info os.FileInfo, owner fileOwnerIDs, dir bool) error {
	switch {
	case dir && !info.IsDir():
		return errors.New("is not a directory")
	case !dir && !info.Mode().IsRegular():
		return errors.New("is not a regular file")
	case !dir && info.Mode().Perm() != snapshotMode:
		return fmt.Errorf("has mode %04o, not %04o", info.Mode().Perm(), snapshotMode)
	case info.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("is writable beyond its owner (mode %04o)", info.Mode().Perm())
	case dir && info.Mode().Perm()&0o001 == 0:
		return fmt.Errorf("cannot be passed through by the MCP server (mode %04o)", info.Mode().Perm())
	}
	holder := ownerIDsOf(info)
	if !holder.known {
		return nil
	}
	if holder.uid != 0 && !(owner.known && holder.uid == owner.uid) {
		return fmt.Errorf("is owned by uid %d, neither root nor the configuration's owner", holder.uid)
	}
	if holder.uid == frontendUID || holder.gid == frontendUID {
		return fmt.Errorf("belongs to the MCP server's own user or group (%d)", frontendUID)
	}
	return nil
}

// frontendOwns reports whether an owner is the MCP server's own user or
// group.
func frontendOwns(owner fileOwnerIDs) bool {
	return owner.known && (owner.uid == frontendUID || owner.gid == frontendUID)
}
