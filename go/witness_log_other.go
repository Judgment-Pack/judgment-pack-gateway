//go:build !unix

package main

import "os"

// Elsewhere than Unix a witness keeps no files: nothing there locks a file
// by what it is, through this module's standard library alone, or counts
// its names, so no witness file is opened (holdWitnessFiles refuses with
// errWitnessFilesNotKept), and there is no fallback. The witness runs in
// the signer, which the engine runs on Unix only
// (docs/design/engine-config.md). `gateway witness verify` reads a log on
// any platform.
const witnessFilesKept = false

const witnessFileFlags = os.O_RDWR

func openNoFollowAppend(dir *os.Root, name string) (*os.File, error) {
	return nil, errWitnessFilesNotKept
}

func witnessFileHeld(info os.FileInfo) error { return errWitnessFilesNotKept }

func lockWitnessFileOS(file *os.File) error { return errWitnessFilesNotKept }

func openWitnessDir(dir *os.Root) (*os.File, error) { return nil, errWitnessFilesNotKept }
