//go:build unix

package main

// The parts of source isolation that exist only where the platform provides
// them: running a source as another OS user, and refusing a seed file that
// anyone but its owner can read (ADR-0001, determination 2).

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

// applySourceUser makes cmd run as the named OS user. An empty name leaves the
// gateway's own identity in place. The user was already resolved once at
// startup by requireUserSwitching, so a failure here is a change to the
// system since then, and it fails the acquisition rather than running the
// source as the signer.
func applySourceUser(cmd *exec.Cmd, name string) error {
	if name == "" {
		return nil
	}
	uid, gid, err := lookupCredential(name)
	if err != nil {
		return err
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: gid, NoSetGroups: true},
	}
	return nil
}

func lookupCredential(name string) (uint32, uint32, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return 0, 0, fmt.Errorf("user %q: %w", name, err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("user %q has a non-numeric uid %q", name, account.Uid)
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("user %q has a non-numeric gid %q", name, account.Gid)
	}
	if uid == uint64(os.Geteuid()) {
		return 0, 0, fmt.Errorf("user %q is the gateway's own identity; a source user must be a different one", name)
	}
	return uint32(uid), uint32(gid), nil
}

// requireUserSwitching refuses to start when any source names a user and this
// process cannot switch to it. Refusing at startup is the point: a source that
// silently ran as the signer because the switch failed would be exactly the
// configuration the operator asked not to have.
func requireUserSwitching(sources map[string]sourceSpec) error {
	for name, spec := range sources {
		if spec.user == "" {
			continue
		}
		if os.Geteuid() != 0 {
			return fmt.Errorf("--source-user %s=%s: switching to another user requires the gateway to run as root", name, spec.user)
		}
		if _, _, err := lookupCredential(spec.user); err != nil {
			return fmt.Errorf("--source-user %s: %w", name, err)
		}
	}
	return nil
}

// checkSeedPermissions refuses a seed file that group or other can read. keygen
// writes 0600; a seed anyone else can read is not a seed the signer alone
// holds, and a source running as another user on the same host is exactly the
// reader the mode bits are there to exclude.
func checkSeedPermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("seed must be a regular file")
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("seed file is readable by group or other (mode %04o); run: chmod 0600 %s", perm, path)
	}
	return nil
}
