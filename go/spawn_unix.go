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
	"strings"
	"syscall"
)

// The anchor mode of this executable: selected by the marker variable AND the
// argument together (serve.go), before main or any test runs. Its stdin must
// be a pipe -- the one startAnchor holds -- or it exits at once with a
// failure: an anchor is never started any other way, and a process that
// merely inherited the marker must not sit consuming a terminal.
func init() {
	if os.Getenv(envGroupAnchor) != "1" || len(os.Args) < 2 || os.Args[1] != anchorArg {
		return
	}
	info, err := os.Stdin.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		os.Exit(2)
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

// sourceGroup is the process group a source runs in. Its leader is not the
// source but an anchor process the gateway starts first and reaps last: a
// group is addressed by its leader's pid, and once a leader has been reaped
// that pid can be reused by an unrelated process, which a later kill of the
// group would then reach. The anchor exists so that no kill is ever sent to
// a group whose leader is gone.
type sourceGroup struct {
	anchor *exec.Cmd
	stdin  io.Closer
}

// startAnchor runs this executable's own image where the kernel exposes it
// (/proc/self/exe names the running image even after the file was replaced
// or removed); elsewhere the executable's path is re-opened, so replacing or
// removing the binary while the gateway runs breaks the next acquisition or
// runs the replacement, and SECURITY.md says to restart the gateway instead.
func startAnchor() (*sourceGroup, error) {
	self := "/proc/self/exe"
	if _, err := os.Stat(self); err != nil {
		self, err = os.Executable()
		if err != nil {
			return nil, err
		}
	}
	anchor := exec.Command(self, anchorArg)
	anchor.Env = []string{envGroupAnchor + "=1"}
	anchor.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, err := anchor.StdinPipe()
	if err != nil {
		return nil, err
	}
	if err := anchor.Start(); err != nil {
		return nil, err
	}
	return &sourceGroup{anchor: anchor, stdin: stdin}, nil
}

func (g *sourceGroup) pgid() int { return g.anchor.Process.Pid }

// kill sends SIGKILL to the whole group: the source, every descendant still
// in it, and the anchor. The anchor then exists as a zombie until reap, and
// the group id stays held.
func (g *sourceGroup) kill() { _ = syscall.Kill(-g.pgid(), syscall.SIGKILL) }

// reap kills whatever remains of the group and only then reaps the anchor.
func (g *sourceGroup) reap() {
	g.kill()
	_ = g.stdin.Close()
	_ = g.anchor.Wait()
}

// prepareSourceProcess sets what a source process starts with. Every source
// joins an anchor-led process group, so cancelling it kills the source and
// every descendant it left holding a pipe rather than the direct child alone.
// A source with a named user gets that user's uid, gid and supplementary
// groups in place of the gateway's. The groups are replaced, never kept: a
// gateway that is a member of a group with authority -- a container
// runtime's, say -- must not pass that membership to a source.
func prepareSourceProcess(cmd *exec.Cmd, name string) (*sourceGroup, error) {
	group, err := startAnchor()
	if err != nil {
		return nil, fmt.Errorf("process group anchor: %w", err)
	}
	attr := &syscall.SysProcAttr{Setpgid: true, Pgid: group.pgid()}
	if name != "" {
		credential, err := lookupCredential(name)
		if err != nil {
			group.reap()
			return nil, err
		}
		attr.Credential = credential
	}
	cmd.SysProcAttr = attr
	cmd.Cancel = func() error {
		group.kill()
		return nil
	}
	return group, nil
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
		// Root may switch; so may a process that is not root but holds the
		// three capabilities, which is how the engine runs its signer as a
		// user of its own beside per-platform users. Where capabilities
		// cannot be read (not Linux), only root may.
		if err := switchingRefusal(os.Geteuid(), processCapabilities()); err != nil {
			return fmt.Errorf("--source-user %s=%s: %v", name, spec.user, err)
		}
		if _, err := lookupCredential(spec.user); err != nil {
			return fmt.Errorf("--source-user %s: %w", name, err)
		}
	}
	return nil
}

// The Linux capabilities a gateway needs to run a source as another user and
// to stop it afterwards. Root ordinarily holds all three; a container that
// drops them leaves a root process that can switch but cannot kill, or the
// reverse, and a kill of the group that reaches the anchor alone reports
// success while the source survives. Where /proc/self/status is absent the
// effective uid is the only check there is.
var requiredCapabilities = []struct {
	bit  uint
	name string
}{
	{5, "CAP_KILL"},
	{6, "CAP_SETGID"},
	{7, "CAP_SETUID"},
}

func missingCapabilities() []string {
	return missingCapabilitiesInSets(processCapabilities())
}

// switchingRefusal is why this process may not switch a source to another
// user, or nil: root may; a process that is not root may where the kernel
// reports capabilities, holding the three it needs and none that would
// cross into the source (capabilityRefusal); elsewhere only root may.
func switchingRefusal(euid int, sets capabilitySets) error {
	if euid != 0 && !sets.known {
		return errors.New("switching to another user requires the gateway to run as root")
	}
	if missing := missingCapabilitiesInSets(sets); len(missing) > 0 {
		return fmt.Errorf("this process lacks %s; it could start the source as that user but not stop it, or not start it at all", strings.Join(missing, ", "))
	}
	if euid != 0 {
		return capabilityRefusal(sets)
	}
	return nil
}

func missingCapabilitiesInSets(sets capabilitySets) []string {
	if !sets.known {
		return nil
	}
	var missing []string
	for _, capability := range requiredCapabilities {
		if sets.effective&(1<<capability.bit) == 0 {
			missing = append(missing, capability.name)
		}
	}
	return missing
}

func missingCapabilitiesIn(status string) []string {
	var effective uint64
	found := false
	for _, line := range strings.Split(status, "\n") {
		if value, ok := strings.CutPrefix(line, "CapEff:"); ok {
			parsed, err := strconv.ParseUint(strings.TrimSpace(value), 16, 64)
			if err != nil {
				return nil
			}
			effective, found = parsed, true
			break
		}
	}
	if !found {
		return nil
	}
	var missing []string
	for _, capability := range requiredCapabilities {
		if effective&(1<<capability.bit) == 0 {
			missing = append(missing, capability.name)
		}
	}
	return missing
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
	return io.ReadAll(io.LimitReader(file, maxSeedFileBytes+1))
}

// markInheritedCloseOnExec marks every descriptor above the standard three
// close-on-exec. Descriptors the gateway opens itself already are; ones its
// launcher left open -- a seed passed as `3<gateway.seed`, say -- are not, and
// without this they would reach every source regardless of user or mode.
//
// Where the kernel lists the open descriptors (/proc/self/fd on Linux,
// /dev/fd on the BSDs and macOS) they are marked exactly. Where it does not,
// every number up to the hard limit is tried, capped so an unlimited one does
// not become a million system calls at startup; that last resort misses a
// descriptor opened above a limit that was lowered afterwards, and
// SECURITY.md says so.
func markInheritedCloseOnExec() {
	for _, dir := range []string{"/proc/self/fd", "/dev/fd"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if fd, err := strconv.Atoi(entry.Name()); err == nil && fd > 2 {
				syscall.CloseOnExec(fd)
			}
		}
		return
	}
	limit := uint64(1 << 20)
	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err == nil {
		highest := rlimit.Max
		if rlimit.Cur > highest {
			highest = rlimit.Cur
		}
		if highest < limit {
			limit = highest
		}
	}
	for fd := 3; uint64(fd) < limit; fd++ {
		syscall.CloseOnExec(fd)
	}
}
