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
