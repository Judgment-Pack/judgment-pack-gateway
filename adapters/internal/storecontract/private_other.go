//go:build !linux && !darwin

package storecontract

import (
	"errors"
	"os"
)

// NoFollow and NonBlock are no flags here: the custody is kept on Linux and
// macOS alone, and Private refuses everything elsewhere.
const (
	NoFollow = 0
	NonBlock = 0
)

// Private refuses every file: this platform keeps no custody.
func Private(os.FileInfo) error {
	return errors.New("store: this platform keeps no custody")
}
