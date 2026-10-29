//go:build !windows

package mcp

import "syscall"

// nonBlocking opens a FIFO without waiting for a writer.
const nonBlocking = syscall.O_NONBLOCK
