//go:build !(linux && (amd64 || arm64))

package sandbox

import (
	"errors"
	"os"
)

var errNoSealedCopy = errors.New("sandbox: this platform has no sealed anonymous memory file")

// SealedCopy is unavailable here: the caller executes the file by its path
// and digests it again immediately before the start.
func SealedCopy(*os.File, string) (*os.File, error) { return nil, errNoSealedCopy }

func sealedData(string, []byte) (*os.File, error) { return nil, errNoSealedCopy }

// Sealed is false here: no file is sealed.
func Sealed(*os.File) bool { return false }
