//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
)

// capabilitySets are a process's capability sets as the kernel reports
// them: effective, permitted, inheritable and ambient.
type capabilitySets struct {
	effective, permitted, inheritable, ambient uint64
	known                                      bool
}

// processCapabilities reads this process's sets from the kernel, as the
// thread-group leader's; every thread inherits its creator's sets, so a
// set that is empty on the leader at startup is empty on every thread
// spawned since.
func processCapabilities() capabilitySets {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return capabilitySets{}
	}
	return capabilitiesIn(string(status))
}

func capabilitiesIn(status string) capabilitySets {
	var sets capabilitySets
	for _, line := range strings.Split(status, "\n") {
		field, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		parsed, err := strconv.ParseUint(strings.TrimSpace(value), 16, 64)
		if err != nil {
			continue
		}
		switch field {
		case "CapEff":
			sets.effective, sets.known = parsed, true
		case "CapPrm":
			sets.permitted = parsed
		case "CapInh":
			sets.inheritable = parsed
		case "CapAmb":
			sets.ambient = parsed
		}
	}
	return sets
}
