//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package main

import "os"

// lockJournalFile takes no lock where the platform gives no flock: the
// serving writer is the file's one writer, and remove-scope runs with the
// gateway stopped there.
// journalFilesLock is whether lockJournalFile takes a lock here.
const journalFilesLock = false

func lockJournalFile(*os.File) error { return nil }

func unlockJournalFile(*os.File) {}
