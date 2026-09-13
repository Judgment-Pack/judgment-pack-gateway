//go:build !unix

package main

import "os"

// Elsewhere than Unix a file's owner is not read and no lock is taken;
// the configuration form is refused on such hosts by the isolation
// refusals before anything is written.
type fileOwnerIDs struct{ known bool }

func ownerIDsOf(info os.FileInfo) fileOwnerIDs { return fileOwnerIDs{} }

func keepOwner(dir *os.Root, name string, owner fileOwnerIDs) error { return nil }

func lockBeside(dir *os.Root, name string) (func(), error) { return func() {}, nil }
