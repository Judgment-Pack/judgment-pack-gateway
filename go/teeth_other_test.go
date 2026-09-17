//go:build !unix

package main

import "os/exec"

// exitStatusTellsAKill is whether an exit status distinguishes a source
// killed from one that exited on its own (exitedOnItsOwn): here it does not,
// and the cancellation's own outcome is what tells them apart.
const exitStatusTellsAKill = false

// Process groups are a Unix notion; elsewhere the helper's grandchild has
// nothing to escape from.
func detachFromProcessGroup(cmd *exec.Cmd) {}

// Without a portable liveness probe, a process the cleanup has killed and
// waited for is taken as gone.
func processGone(pid int) bool { return true }
