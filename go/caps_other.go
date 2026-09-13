//go:build !linux

package main

// Capabilities are a Linux notion; elsewhere only root switches users, and
// nothing ambient exists to clear.
func processCapabilities() (effective, ambient uint64, known bool) { return 0, 0, false }

func clearAmbientCapabilities() bool { return true }
