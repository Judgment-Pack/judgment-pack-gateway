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

// executableFacts is what the engine asks about its own binary: the
// running image, opened once through /proc/self/exe -- which names the
// image even after the file at its path was replaced -- and read for its
// mode and its capability attribute through that one descriptor
// (factsOf), so what is judged is what is running and not what now sits
// at its path.
func executableFacts() (exeFacts, error) {
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		return exeFacts{}, err
	}
	defer f.Close()
	facts, err := factsOf(f, "security.capability")
	if err != nil {
		return exeFacts{}, err
	}
	if path, err := os.Readlink("/proc/self/exe"); err == nil {
		facts.path = path
	}
	return facts, nil
}

// factsOf reads an open file's mode and whether it carries the named
// attribute, both through its descriptor: the mode by fstat, the
// attribute by the descriptor's own link under /proc, which names the
// open file whatever became of its path.
func factsOf(f *os.File, attribute string) (exeFacts, error) {
	info, err := f.Stat()
	if err != nil {
		return exeFacts{}, err
	}
	facts := exeFacts{path: f.Name(), mode: info.Mode().Perm()}
	var buf [64]byte
	n, err := syscall.Getxattr("/proc/self/fd/"+strconv.Itoa(int(f.Fd())), attribute, buf[:])
	facts.capabilities, err = attributePresent(n, err)
	if err != nil {
		return exeFacts{}, fmt.Errorf("reading %s of %s: %v", attribute, f.Name(), err)
	}
	return facts, nil
}

// attributePresent is whether an extended attribute is there, from what
// getxattr returned: a length is presence, and so is a buffer too small
// for the value; no data, or a filesystem that holds no such attributes,
// is confirmed absence; anything else is not known, and is not taken for
// absence.
func attributePresent(n int, err error) (bool, error) {
	switch {
	case err == nil:
		return n > 0, nil
	case errors.Is(err, syscall.ERANGE):
		return true, nil
	case errors.Is(err, syscall.ENODATA), errors.Is(err, syscall.ENOTSUP):
		return false, nil
	}
	return false, err
}
