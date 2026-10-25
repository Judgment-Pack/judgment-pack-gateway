//go:build unix

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// registryLocked is whether this platform locks the registry: a running
// gateway holds it, and gateway rotate-key refuses while it is held
// (SPEC.md §3b, "Rotating").
const registryLocked = true

// lockRegistry takes an exclusive lock on the registry file through a
// descriptor of its own, with flock(2), as a witness locks its files
// (lockWitnessFile): held until the file returned is closed, refused at once
// when another holds it -- a running gateway, or a rotation under way -- and
// refused for any other reason it cannot be had, rather than waited for or
// gone on without. The lock is advisory: it keeps out a gateway and
// rotate-key, which take it, and stops no write.
func lockRegistry(path string) (*os.File, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	conn, err := file.SyscallConn()
	if err != nil {
		file.Close()
		return nil, err
	}
	var lockErr error
	if err := conn.Control(func(fd uintptr) {
		lockErr = syscall.Flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB)
	}); err != nil {
		file.Close()
		return nil, err
	}
	if errors.Is(lockErr, syscall.EWOULDBLOCK) {
		file.Close()
		return nil, errRegistryHeld
	}
	if lockErr != nil {
		file.Close()
		return nil, fmt.Errorf("the registry could not be locked: %v", lockErr)
	}
	return file, nil
}
