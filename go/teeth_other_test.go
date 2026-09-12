//go:build !unix

package main

import "os/exec"

// Process groups are a Unix notion; elsewhere the helper's grandchild has
// nothing to escape from.
func detachFromProcessGroup(cmd *exec.Cmd) {}

// Without a portable liveness probe, a process the cleanup has killed and
// waited for is taken as gone.
func processGone(pid int) bool { return true }
