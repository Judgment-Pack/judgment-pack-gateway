//go:build !unix

package main

import "os"

// Elsewhere than Unix a file's owner is not read and no lock is taken;
// the configuration form is refused on such hosts by the isolation
// refusals before anything is written.
type fileOwnerIDs struct{ known bool }

func ownerIDsOf(info os.FileInfo) fileOwnerIDs { return fileOwnerIDs{} }

func parentHeld(info os.FileInfo) error { return nil }

// Elsewhere than Unix, whether this process may write is not judged.
func canWrite(path string) bool { return true }

func keepOwner(file *os.File, owner fileOwnerIDs) error { return nil }

func openConfigForRead(dir *os.Root, name string) (*os.File, error) {
	return dir.OpenFile(name, os.O_RDONLY, 0)
}

func lockBeside(dir *os.Root, name string, owner fileOwnerIDs) (func(), error) { return func() {}, nil }

// Elsewhere than Unix a directory is not synced, a link is not refused by
// the open, and a snapshot's mode and owner are not judged: connect writes
// nothing on such hosts.
func syncDirectory(dir *os.Root, name string) error { return nil }

func openNoFollow(dir *os.Root, name string) (*os.File, error) {
	return dir.OpenFile(name, os.O_RDONLY, 0)
}

func snapshotHeld(info os.FileInfo, owner fileOwnerIDs, dir bool) error { return nil }

func frontendOwns(owner fileOwnerIDs) bool { return false }

// Elsewhere than Unix a file opened for reading cannot be synced, and
// connect writes nothing on such hosts.
func syncFound(file *os.File) error { return nil }

// Elsewhere than Unix a snapshot's owner and mode are not judged: the
// frontend runs on Unix.
func servedInvariant(info os.FileInfo, owner fileOwnerIDs) error { return nil }

func openServedSnapshot(dir *os.Root, name string) (*os.File, error) { return dir.Open(name) }
