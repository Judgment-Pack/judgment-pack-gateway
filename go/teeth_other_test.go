//go:build !unix

package main

import "os/exec"

// Process groups are a Unix notion; elsewhere the helper's grandchild has
// nothing to escape from.
func detachFromProcessGroup(cmd *exec.Cmd) {}
