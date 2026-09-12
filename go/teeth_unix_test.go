//go:build unix

package main

// Attacks on the Unix half of source isolation: an inherited descriptor, a
// seed another user owns, and the user switch itself.

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A descriptor the gateway's launcher left open -- `3<gateway.seed` -- reaches
// a source unless it is marked close-on-exec. The test first shows the hazard
// (the probe sees the descriptor open) and then that the startup marking
// closes it, so a regression in either direction is visible.
func TestInheritedDescriptorDoesNotReachASource(t *testing.T) {
	file, err := os.Create(filepath.Join(t.TempDir(), "launcher-opened"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	fd := int(file.Fd())
	// os opens with close-on-exec; clear it, as a shell redirection would
	// have left it.
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFD, 0); errno != 0 {
		t.Fatal(errno)
	}
	service, _ := testService(t)
	t.Setenv(envSourceFdProbe, strconv.Itoa(fd))

	out, err := service.acquire("fd-1", "screening", vString("x"))
	if err != nil {
		t.Fatal(err)
	}
	if open, _ := out["result"].(map[string]any)["open"].(bool); !open {
		t.Fatal("the hazard did not reproduce: a launcher-opened descriptor should reach the source until marked")
	}

	markInheritedCloseOnExec()
	out, err = service.acquire("fd-2", "screening", vString("x"))
	if err != nil {
		t.Fatal(err)
	}
	if open, _ := out["result"].(map[string]any)["open"].(bool); open {
		t.Fatal("a launcher-opened descriptor reached the source after startup marking")
	}
}

// fakeSeedInfo lets ownership and mode be stated directly: a test running as
// one user cannot create a file owned by another.
type fakeSeedInfo struct {
	os.FileInfo
	mode os.FileMode
	uid  uint32
}

func (f fakeSeedInfo) Mode() os.FileMode { return f.mode }
func (f fakeSeedInfo) Sys() any          { return &syscall.Stat_t{Uid: f.uid} }

func TestSeedJudgedByOwnerModeAndKind(t *testing.T) {
	real, err := os.Stat(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	const euid = 1000
	cases := []struct {
		name string
		info fakeSeedInfo
		want error
	}{
		{"owned and private", fakeSeedInfo{real, 0o600, euid}, nil},
		{"owned, group readable", fakeSeedInfo{real, 0o640, euid}, errSeedPermissions},
		{"owned, world readable", fakeSeedInfo{real, 0o644, euid}, errSeedPermissions},
		{"another user's, private", fakeSeedInfo{real, 0o600, euid + 1}, errSeedOwner},
		{"a fifo", fakeSeedInfo{real, os.ModeNamedPipe | 0o600, euid}, errSeedNotRegular},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifySeedInfo(tc.info, euid)
			switch {
			case tc.want == nil && err != nil:
				t.Fatalf("refused a good seed: %v", err)
			case tc.want != nil && err == nil:
				t.Fatalf("accepted a seed it must refuse")
			case tc.want != nil && !strings.Contains(err.Error(), tc.want.Error()):
				t.Fatalf("refused for the wrong reason: %v", err)
			}
		})
	}
}

// A named user is applied to the child as its uid, gid and its own
// supplementary groups -- never the gateway's -- in its own process group.
func TestPrepareSourceProcessAppliesTheNamedUser(t *testing.T) {
	account, err := user.Lookup("nobody")
	if err != nil {
		t.Skip("no 'nobody' account on this host")
	}
	if account.Uid == strconv.Itoa(os.Geteuid()) {
		t.Skip("running as nobody")
	}
	cmd := exec.Command("true")
	group, err := prepareSourceProcess(cmd, "nobody")
	if err != nil {
		t.Fatal(err)
	}
	defer group.reap()
	attr := cmd.SysProcAttr
	if attr == nil || !attr.Setpgid || attr.Pgid != group.pgid() {
		t.Fatal("a source must start in the anchor's process group")
	}
	if attr.Credential == nil {
		t.Fatal("the named user was not applied")
	}
	if strconv.Itoa(int(attr.Credential.Uid)) != account.Uid || strconv.Itoa(int(attr.Credential.Gid)) != account.Gid {
		t.Fatalf("credential %d:%d does not match %s:%s", attr.Credential.Uid, attr.Credential.Gid, account.Uid, account.Gid)
	}
	if attr.Credential.NoSetGroups {
		t.Fatal("supplementary groups must be replaced, not kept")
	}
	groups, err := account.GroupIds()
	if err != nil {
		t.Fatal(err)
	}
	if len(attr.Credential.Groups) != len(groups) {
		t.Fatalf("groups %v do not match the account's %v", attr.Credential.Groups, groups)
	}
	if cmd.Cancel == nil {
		t.Fatal("cancellation must address the process group")
	}
}

// The credential is really applied at start: an unprivileged gateway that
// names a user cannot start the source, and says so, rather than running it
// as itself. Removing the credential would make this acquisition succeed.
func TestNamedUserIsAppliedAtStart(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: the switch would succeed")
	}
	if _, err := user.Lookup("nobody"); err != nil {
		t.Skip("no 'nobody' account on this host")
	}
	service, _ := testService(t)
	spec := service.sources["screening"]
	spec.user = "nobody"
	service.sources["screening"] = spec
	started := time.Now()
	_, err := service.acquire("user-1", "screening", vString("x"))
	if err == nil {
		t.Fatal("an unprivileged gateway must not be able to start a source as another user")
	}
	if !strings.Contains(err.Error(), "could not be started") {
		t.Fatalf("the failure must say the source could not be started: %v", err)
	}
	if time.Since(started) > 10*time.Second {
		t.Fatal("the refusal must be immediate, not a timeout")
	}
}

// detachFromProcessGroup gives the helper's grandchild its own process group,
// so a group kill cannot reach it -- the case only the bounded pipe wait
// handles.
func detachFromProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// A descendant that has left the source's process group survives the group
// kill; the bounded pipe wait is then the only thing that ends the
// acquisition, and it must.
func TestEscapedDescendantCannotStrandTheAcquisition(t *testing.T) {
	service, _ := testService(t)
	holderPid := expectHolder(t)
	service.maxSourceOutput = 1024
	t.Setenv(envSourceBig, "4096")
	t.Setenv(envSourceHolder, "1")
	t.Setenv(envSourceEscape, "1")
	started := time.Now()
	_, err := service.acquire("escape-1", "screening", vString("x"))
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("an overflowing source must fail the acquisition")
	}
	holderPid()
	if elapsed > service.waitDelay+10*time.Second {
		t.Fatalf("an escaped descendant stranded the acquisition; acquire took %s", elapsed)
	}
}

// processGone reports whether pid names no running process. A zombie is a
// process that has terminated and not yet been reaped by whoever inherited
// it; it counts as gone here, since the question is whether the source is
// still executing, not whether init has got round to it.
func processGone(pid int) bool {
	if syscall.Kill(pid, 0) == syscall.ESRCH {
		return true
	}
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false // no /proc: only ESRCH can say gone
	}
	// The state follows the parenthesised command name.
	if i := strings.LastIndexByte(string(stat), ')'); i >= 0 && i+2 < len(stat) {
		return stat[i+2] == 'Z' || stat[i+2] == 'X'
	}
	return false
}

// The anchor exists while the group may still be killed, and not after. Its
// pid leads the group the source joins, so the group id cannot be reused by
// anything else until reap has finished with it.
func TestSourceGroupAnchorLivesUntilReap(t *testing.T) {
	cmd := exec.Command("true")
	group, err := prepareSourceProcess(cmd, "")
	if err != nil {
		t.Fatal(err)
	}
	anchor := group.pgid()
	if processGone(anchor) {
		t.Fatal("the anchor must be running while the group is open")
	}
	if attr := cmd.SysProcAttr; attr == nil || !attr.Setpgid || attr.Pgid != anchor {
		t.Fatalf("the source must join the anchor's group; got %+v", cmd.SysProcAttr)
	}
	group.reap()
	if !awaitGone(anchor, 10*time.Second) {
		t.Fatal("the anchor survived reap")
	}
}

// After an acquisition nothing of its group remains: not the anchor, not the
// source, not a descendant.
func TestAcquisitionLeavesNoAnchorBehind(t *testing.T) {
	if _, err := os.Stat("/proc/self"); err != nil {
		t.Skip("counting children needs /proc")
	}
	children := func() int {
		entries, _ := os.ReadDir("/proc")
		count := 0
		for _, entry := range entries {
			pid, err := strconv.Atoi(entry.Name())
			if err != nil {
				continue
			}
			environ, err := os.ReadFile("/proc/" + entry.Name() + "/environ")
			if err != nil {
				continue
			}
			if strings.Contains(string(environ), envGroupAnchor+"=1") && !processGone(pid) {
				count++
			}
		}
		return count
	}
	before := children()
	service, _ := testService(t)
	if _, err := service.acquire("anchor-1", "screening", vString("x")); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envSourceFail, "1")
	if _, err := service.acquire("anchor-2", "screening", vString("x")); err == nil {
		t.Fatal("a failing source must fail the acquisition")
	}
	deadline := time.Now().Add(10 * time.Second)
	for children() > before && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if after := children(); after > before {
		t.Fatalf("%d anchor process(es) survived their acquisitions", after-before)
	}
}

// An overflow that arrives after the direct child has exited cancels a
// context os/exec no longer watches, so nothing kills the descendant that
// wrote it. The bounded wait returns the acquisition; reaping the group after
// Wait is what kills the descendant, and this is the test that would fail
// without it.
func TestOverflowAfterTheChildExitedStillKillsTheGroup(t *testing.T) {
	service, _ := testService(t)
	holderPid := expectHolder(t)
	service.maxSourceOutput = 1024
	service.waitDelay = 3 * time.Second
	t.Setenv(envSourceBig, "4096")
	t.Setenv(envSourceHolder, "1")
	t.Setenv(envSourceQuiet, "1")
	t.Setenv(envSourceDelay, "500")
	_, err := service.acquire("late-1", "screening", vString("x"))
	if err == nil {
		t.Fatal("a late overflow from a descendant must fail the acquisition")
	}
	pid := holderPid()
	if !awaitGone(pid, 10*time.Second) {
		t.Fatalf("descendant %d survived the acquisition; the group was not reaped", pid)
	}
}

// A descriptor numbered high -- above the old fixed sweep, where the soft
// limit allows -- is marked too.
func TestHighInheritedDescriptorDoesNotReachASource(t *testing.T) {
	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err != nil {
		t.Fatal(err)
	}
	high := uint64(70000)
	if rlimit.Cur <= high {
		high = rlimit.Cur - 1
	}
	if high < 1000 {
		t.Skip("descriptor limit too low to place a high descriptor")
	}
	file, err := os.Create(filepath.Join(t.TempDir(), "launcher-opened"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	dup, _, errno := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), syscall.F_DUPFD, uintptr(high))
	if errno != 0 {
		t.Fatal(errno)
	}
	defer syscall.Close(int(dup))
	// F_DUPFD leaves close-on-exec clear, as a launcher's descriptor would be.
	service, _ := testService(t)
	t.Setenv(envSourceFdProbe, strconv.Itoa(int(dup)))
	out, err := service.acquire("fd-high-1", "screening", vString("x"))
	if err != nil {
		t.Fatal(err)
	}
	if open, _ := out["result"].(map[string]any)["open"].(bool); !open {
		t.Fatalf("the hazard did not reproduce for descriptor %d", dup)
	}
	markInheritedCloseOnExec()
	out, err = service.acquire("fd-high-2", "screening", vString("x"))
	if err != nil {
		t.Fatal(err)
	}
	if open, _ := out["result"].(map[string]any)["open"].(bool); open {
		t.Fatalf("descriptor %d reached the source after startup marking", dup)
	}
}

// A FIFO at the seed path is refused, and refused promptly: the open must
// not block waiting for a writer that never comes.
func TestFIFOSeedIsRefusedWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seed.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := loadSeed(path)
		result <- err
	}()
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("a FIFO must be refused as not a regular file: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("opening a FIFO seed blocked")
	}
}
