//go:build unix

package main

import (
	"os"
	"syscall"
)

// approvalOpenFlags opens an approval record without following a link at
// it and without waiting on a file that is not a regular one.
const approvalOpenFlags = os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
