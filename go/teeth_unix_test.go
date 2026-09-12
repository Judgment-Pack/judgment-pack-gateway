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
	if err := prepareSourceProcess(cmd, "nobody"); err != nil {
		t.Fatal(err)
	}
	attr := cmd.SysProcAttr
	if attr == nil || !attr.Setpgid {
		t.Fatal("a source must start in its own process group")
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
	expectHolder(t)
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
	if elapsed > sourceWaitDelay+10*time.Second {
		t.Fatalf("an escaped descendant stranded the acquisition; acquire took %s", elapsed)
	}
}
