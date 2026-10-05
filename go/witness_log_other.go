//go:build !unix

package main

import "os"

// witnessFileFlags is how a witness file is opened elsewhere than Unix: to
// read and write, without the append mode, whose handle on Windows cannot
// cut the file as repair must. The witness writes only at the end it seeks
// to, under its writer lock (osWitnessIO).
const witnessFileFlags = os.O_RDWR

// Elsewhere than Unix a link is not refused by the open, and a file's mode
// and owner are not judged: the witness runs in the signer, which the
// engine runs on Unix only (docs/design/engine-config.md).
func openNoFollowAppend(dir *os.Root, name string) (*os.File, error) {
	return dir.OpenFile(name, witnessFileFlags, 0)
}

func witnessFilePrivate(info os.FileInfo) error { return nil }
