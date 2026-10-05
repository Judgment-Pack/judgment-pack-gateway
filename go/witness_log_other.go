//go:build !unix

package main

import "os"

// Elsewhere than Unix a link is not refused by the open, and a file's mode
// and owner are not judged: the witness runs in the signer, which the
// engine runs on Unix only (docs/design/engine-config.md).
func openNoFollowAppend(dir *os.Root, name string) (*os.File, error) {
	return dir.OpenFile(name, os.O_RDWR|os.O_APPEND, 0)
}

func witnessFilePrivate(info os.FileInfo) error { return nil }
