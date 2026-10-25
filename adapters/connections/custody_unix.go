//go:build linux || darwin

package connections

import (
	"os"
	"syscall"
)

func lock(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) }
func unlock(f *os.File)     { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
