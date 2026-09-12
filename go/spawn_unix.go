//go:build unix

package main

// The parts of source isolation that exist only where the platform provides
// them (ADR-0001, determination 2): a source's process group and, when a user
// is named, its identity; the seed file's ownership and mode; and the
// descriptors a launcher may have left open.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

// prepareSourceProcess sets what a source process starts with. Every source
// gets its own process group, so cancelling it kills the source and every
// descendant it left holding a pipe rather than the direct child alone. A
// source with a named user gets that user's uid, gid and supplementary groups
// in place of the gateway's. The groups are replaced, never kept: a gateway
// that is a member of a group with authority -- a container runtime's, say --
// must not pass that membership to a source.
func prepareSourceProcess(cmd *exec.Cmd, name string) error {
	attr := &syscall.SysProcAttr{Setpgid: true}
	if name != "" {
		credential, err := lookupCredential(name)
		if err != nil {
			return err
		}
		attr.Credential = credential
	}
	cmd.SysProcAttr = attr
	cmd.Cancel = func() error {
		// A negative pid addresses the whole group. If that fails, the direct
		// child is still killed, which is what the default did.
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
	return nil
}

func lookupCredential(name string) (*syscall.Credential, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return nil, fmt.Errorf("user %q: %w", name, err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("user %q has a non-numeric uid %q", name, account.Uid)
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("user %q has a non-numeric gid %q", name, account.Gid)
	}
	if uid == uint64(os.Geteuid()) {
		return nil, fmt.Errorf("user %q is the gateway's own identity; a source user must be a different one", name)
	}
	groupIDs, err := account.GroupIds()
	if err != nil {
		return nil, fmt.Errorf("user %q: supplementary groups: %w", name, err)
	}
	groups := make([]uint32, 0, len(groupIDs))
	for _, id := range groupIDs {
		g, err := strconv.ParseUint(id, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("user %q has a non-numeric group id %q", name, id)
		}
		groups = append(groups, uint32(g))
	}
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: groups}, nil
}

// requireUserSwitching refuses to start when any source names a user and this
// process cannot switch to it. Refusing at startup is the point: a source that
// silently ran as the signer because the switch failed would be exactly the
// configuration the operator asked not to have. The check is the effective
// uid; a root process stripped of CAP_SETUID passes it and fails at the first
// acquisition instead, where the start error is reported in full.
func requireUserSwitching(sources map[string]sourceSpec) error {
	for name, spec := range sources {
		if spec.user == "" {
			continue
		}
		if os.Geteuid() != 0 {
			return fmt.Errorf("--source-user %s=%s: switching to another user requires the gateway to run as root", name, spec.user)
		}
		if _, err := lookupCredential(spec.user); err != nil {
			return fmt.Errorf("--source-user %s: %w", name, err)
		}
	}
	return nil
}

var (
	errSeedNotRegular  = errors.New("seed must be a regular file")
	errSeedOwner       = errors.New("seed file is not owned by the gateway's own user")
	errSeedPermissions = errors.New("seed file is readable by group or other")
)

// verifySeedInfo judges an opened seed file: regular, owned by the identity
// the gateway runs as, readable by nobody else. Ownership matters as much as
// mode: a 0600 seed owned by the very user a source runs as is a seed that
// source can read.
func verifySeedInfo(info os.FileInfo, euid int) error {
	if !info.Mode().IsRegular() {
		return errSeedNotRegular
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("seed file ownership could not be determined")
	}
	if int(st.Uid) != euid {
		return fmt.Errorf("%w (owner uid %d, gateway uid %d)", errSeedOwner, st.Uid, euid)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%w (mode %04o)", errSeedPermissions, perm)
	}
	return nil
}

// openSeed opens the seed once and judges the file it opened before reading
// from that same descriptor. Checking a path and then reading the path would
// let the two name different files; a FIFO at the path is refused as not
// regular rather than blocking the open. What is read is bounded: a seed is
// sixty-five bytes, and a file that is not one is refused by the decoder.
func openSeed(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if err := verifySeedInfo(info, os.Geteuid()); err != nil {
		if errors.Is(err, errSeedPermissions) {
			return nil, fmt.Errorf("%w; run: chmod 0600 %s", err, path)
		}
		return nil, err
	}
	return io.ReadAll(io.LimitReader(file, 4096))
}

// markInheritedCloseOnExec marks every descriptor above the standard three
// close-on-exec. Descriptors the gateway opens itself already are; ones its
// launcher left open -- a seed passed as `3<gateway.seed`, say -- are not, and
// without this they would reach every source regardless of user or mode.
func markInheritedCloseOnExec() {
	limit := uint64(65536)
	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err == nil && rlimit.Cur < limit {
		limit = rlimit.Cur
	}
	for fd := 3; uint64(fd) < limit; fd++ {
		syscall.CloseOnExec(fd)
	}
}
