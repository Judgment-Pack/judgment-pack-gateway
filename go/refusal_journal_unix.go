//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"os"
	"syscall"
)

// lockJournalFile takes the refusal journal file's own lock (ADR-0059 §1):
// the serving writer and remove-scope take it, and nothing else writes the
// file.
// journalFilesLock is whether lockJournalFile takes a lock here.
const journalFilesLock = true

func lockJournalFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX) }

func unlockJournalFile(f *os.File) { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
