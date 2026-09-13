//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
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

// prSetNoNewPrivs is prctl's PR_SET_NO_NEW_PRIVS.
const prSetNoNewPrivs = 38

// denyNewPrivilegesHere holds the calling thread, and every process it
// forks from here on, to no_new_privs: an execve then grants no privilege
// the caller lacked -- no set-user-id bit, no file capability -- so a
// source switched to its platform's user cannot take up the gateway's own
// file capabilities by executing the gateway binary, nor any other
// privileged file (Documentation/userspace-api/no_new_privs). The flag is
// per thread, inherited across fork and exec, and never cleared; it is
// read back from the kernel before it is relied on.
func denyNewPrivilegesHere() error {
	if _, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %v", errno)
	}
	status, err := os.ReadFile("/proc/thread-self/status")
	if err != nil {
		return fmt.Errorf("no_new_privs could not be read back: %v", err)
	}
	if noNewPrivilegesIn(string(status)) != "1" {
		return errors.New("no_new_privs was set and the kernel does not report it")
	}
	return nil
}

// noNewPrivilegesIn is the NoNewPrivs value in a status file the kernel
// wrote, or "" where there is none.
func noNewPrivilegesIn(status string) string {
	for _, line := range strings.Split(status, "\n") {
		if field, value, ok := strings.Cut(line, ":"); ok && field == "NoNewPrivs" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// executableFacts is what the engine asks about its own binary: where it
// is, its permission bits, and whether it carries file capabilities -- the
// kernel's security.capability attribute, which any user may read.
func executableFacts() (exeFacts, error) {
	path, err := os.Executable()
	if err != nil {
		return exeFacts{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return exeFacts{}, err
	}
	facts := exeFacts{path: path, mode: info.Mode().Perm()}
	var buf [64]byte
	n, err := syscall.Getxattr(path, "security.capability", buf[:])
	facts.capabilities = (err == nil && n > 0) || err == syscall.ERANGE
	return facts, nil
}
