//go:build linux || darwin

package connections

import "syscall"

func mkfifo(name string) error { return syscall.Mkfifo(name, 0600) }
