//go:build !linux

package main

// Capabilities are a Linux notion; elsewhere only root switches users.
type capabilitySets struct {
	effective, permitted, inheritable, ambient uint64
	known                                      bool
}

func processCapabilities() capabilitySets { return capabilitySets{} }

// no_new_privs is a Linux boundary. Elsewhere only root switches users,
// and root's binary carries no file capability for a source to take up.
func denyNewPrivilegesHere() error { return nil }

// Elsewhere than Linux a binary carries no file capabilities, and there is
// nothing about it the engine refuses on.
func executableFacts() (exeFacts, error) { return exeFacts{}, nil }
