//go:build linux || darwin

package storecontract

import (
	"errors"
	"os"
	"syscall"
)

// NoFollow and NonBlock are the flags every custody open is given: no link
// is followed and nothing is waited on, so what is opened is judged by the
// descriptor.
const (
	NoFollow = syscall.O_NOFOLLOW
	NonBlock = syscall.O_NONBLOCK
)

// Private is why a custody file or directory is not private to the
// custody's owner, or nil: owned by this process's effective user, and
// open to nobody else.
func Private(info os.FileInfo) error {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 {
		return errors.New("store: not private to the custody's owner")
	}
	return nil
}
