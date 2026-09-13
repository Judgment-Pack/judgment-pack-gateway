//go:build unix

package fakemcp

import "syscall"

func processGroup() int { return syscall.Getpgrp() }
