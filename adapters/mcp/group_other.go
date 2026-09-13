//go:build !linux

package mcp

// Elsewhere than Linux a command server's descendants are not reached
// when it is stopped: --image is the shape that keeps the lifecycle under
// a name, and under the gateway the source group's kill reaches what
// stayed in the group.
func adoptOrphans() error { return nil }

func killDescendants() error { return nil }
