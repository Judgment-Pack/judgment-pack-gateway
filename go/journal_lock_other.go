//go:build !unix

package main

import (
	"errors"
	"os"
)

// The action journal is kept only on Unix (action_journal_other.go): nothing
// here is locked, and gateway journal compact refuses before it would lock.
func lockDirectory(path string, exclusive bool) (*os.File, error) {
	return nil, errors.New("this platform keeps no action journal")
}

func sameDevice(a, b os.FileInfo) bool { return false }

func crossDevice(err error) bool { return false }
