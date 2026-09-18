//go:build linux || darwin

package connections

import (
	"os"
	"syscall"
)

const noFollow = syscall.O_NOFOLLOW
const nonBlock = syscall.O_NONBLOCK

func private(info os.FileInfo, dir bool) error {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 {
		return ErrStorage
	}
	return nil
}
func lock(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) }
func unlock(f *os.File)     { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
