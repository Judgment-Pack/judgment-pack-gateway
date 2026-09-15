//go:build linux

package main

import "fmt"

// capabilitySetsEmpty reads this process's capability sets and says whether
// every one of them is empty.
func capabilitySetsEmpty() (bool, string) {
	sets := processCapabilities()
	if !sets.known {
		return false, "the sets could not be read from /proc/self/status"
	}
	if sets.effective != 0 || sets.permitted != 0 || sets.inheritable != 0 || sets.ambient != 0 {
		return false, fmt.Sprintf("effective %#x permitted %#x inheritable %#x ambient %#x", sets.effective, sets.permitted, sets.inheritable, sets.ambient)
	}
	return true, ""
}
