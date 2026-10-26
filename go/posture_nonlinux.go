//go:build !linux

package main

// Elsewhere than Linux a source's descendants and the engine image's
// custody are stated, not checked: adapter-mcp reaps a command server's
// descendants on Linux alone (adapters/mcp/group_other.go), a platform
// without process groups kills the direct child alone (spawn_other.go),
// and the engine image is a Linux image.

func descendantPosture() postureLine {
	return postureStatements[postureFamily][protectionDescendants]
}

func custodyPosture(bool) postureLine {
	return postureStatements[postureFamily][protectionContainerCustody]
}
