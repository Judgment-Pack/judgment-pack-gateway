//go:build !linux

package main

// Capabilities are a Linux notion; elsewhere only root switches users.
type capabilitySets struct {
	effective, permitted, inheritable, ambient uint64
	known                                      bool
}

func processCapabilities() capabilitySets { return capabilitySets{} }
