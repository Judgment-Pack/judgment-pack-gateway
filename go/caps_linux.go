//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

// processCapabilities reads this process's effective and ambient
// capability sets from the kernel.
func processCapabilities() (effective, ambient uint64, known bool) {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, 0, false
	}
	return capabilitiesIn(string(status))
}

func capabilitiesIn(status string) (effective, ambient uint64, known bool) {
	for _, line := range strings.Split(status, "\n") {
		if value, ok := strings.CutPrefix(line, "CapEff:"); ok {
			effective, _ = strconv.ParseUint(strings.TrimSpace(value), 16, 64)
			known = true
		}
		if value, ok := strings.CutPrefix(line, "CapAmb:"); ok {
			ambient, _ = strconv.ParseUint(strings.TrimSpace(value), 16, 64)
		}
	}
	return effective, ambient, known
}

const (
	prCapAmbient         = 47
	prCapAmbientClearAll = 4
)

// clearAmbientCapabilities empties this process's ambient set, so that an
// adapter it switches to another user and executes starts with no
// capability of the signer's: the effective set stays, and the switch
// still works, but nothing crosses the exec. It reports whether the set is
// empty afterwards.
func clearAmbientCapabilities() bool {
	syscall.Syscall(syscall.SYS_PRCTL, prCapAmbient, prCapAmbientClearAll, 0)
	_, ambient, known := processCapabilities()
	return !known || ambient == 0
}
