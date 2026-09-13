//go:build !unix

package mcp

import "os/exec"

// Process groups are a Unix notion; elsewhere a command's descendants are
// not reached, and --image is the shape that keeps the lifecycle under a
// name.
func ownGroup(cmd *exec.Cmd) {}

func killGroup(cmd *exec.Cmd) {}
