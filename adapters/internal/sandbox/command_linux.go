//go:build linux && (amd64 || arm64)

package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

const helperArg = "_gateway_sandbox_exec_v1"

// The helper never returns to the application. Landlock attaches to the
// calling thread; exec must run on that same locked thread. Its restrictions
// then apply to the new program and its descendants.
func init() {
	if len(os.Args) < 2 || os.Args[1] != helperArg {
		return
	}
	if len(os.Args) < 7 || !ValidMode(os.Args[2]) || os.Args[2] == FullAccess {
		fmt.Fprintln(os.Stderr, "sandbox-policy-invalid: invalid helper invocation")
		os.Exit(125)
	}
	runtime.LockOSThread()
	if err := restrictLandlock(os.Args[2], os.Args[3], os.Args[4]); err != nil {
		fmt.Fprintln(os.Stderr, "sandbox-not-enforced: Landlock setup failed:", err)
		os.Exit(125)
	}
	if err := syscall.Exec(os.Args[5], os.Args[6:], os.Environ()); err != nil {
		fmt.Fprintln(os.Stderr, "server-exec-failed:", err)
		os.Exit(126)
	}
	panic("exec returned without an error")
}

func platformCommand(ctx context.Context, executable string, args []string, mode, workspace, tmp string) (*exec.Cmd, Report, error) {
	report := Report{Mode: mode, Backend: "none", State: "not-enforced", Reason: "no usable filesystem sandbox backend"}
	if path, err := exec.LookPath("bwrap"); err == nil {
		flags := []string{"--die-with-parent", "--new-session", "--unshare-user", "--unshare-pid", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"}
		if mode == WorkspaceWrite {
			flags = append(flags, "--bind", workspace, workspace, "--bind", tmp, tmp)
		}
		flags = append(flags, "--chdir", workspace)
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		probe := exec.CommandContext(probeCtx, path, append(append([]string{}, flags...), "--", "/bin/true")...)
		err := probe.Run()
		cancel()
		if err == nil {
			report.Backend, report.State = "bubblewrap", "enforced"
			report.Reason = "filesystem mounts are read-only outside the declared writable directories; network access is unchanged"
			return exec.CommandContext(ctx, path, append(append(flags, "--", executable), args...)...), report, nil
		}
	}
	if ctx.Err() != nil {
		return nil, report, ctx.Err()
	}
	abi, _, errno := syscall.Syscall(444, 0, 0, 1) // landlock_create_ruleset: query ABI
	if errno != 0 || abi < 3 {
		return nil, report, fmt.Errorf("sandbox-not-enforced: bubblewrap unavailable and Landlock ABI 3 or newer is required")
	}
	self, err := os.Executable()
	if err != nil {
		return nil, report, err
	}
	report.Backend, report.State = "landlock", "partial"
	report.Reason = "file-content writes, truncation and directory mutations are restricted; metadata changes and network access are not restricted"
	argv := append([]string{helperArg, mode, workspace, tmp, executable, executable}, args...)
	return exec.CommandContext(ctx, self, argv...), report, nil
}

func restrictLandlock(mode, workspace, tmp string) error {
	// Handle write, removal, creation, cross-directory rename/link and truncate.
	// Read/execute are left to the process's ordinary credentials. Landlock
	// does not restrict chmod/chown: the report therefore says partial.
	const writes uint64 = (1 << 1) | (0x7ff << 4)
	attr := struct{ FS uint64 }{writes}
	fd, _, errno := syscall.Syscall(444, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return errno
	}
	defer syscall.Close(int(fd))
	if mode == WorkspaceWrite {
		for _, path := range []string{workspace, tmp} {
			parent, err := syscall.Open(path, 0x200000|syscall.O_CLOEXEC|syscall.O_DIRECTORY, 0) // O_PATH
			if err != nil {
				return err
			}
			// The kernel struct is packed: uint64 allowed_access, int32 parent_fd.
			rule := struct {
				Access uint64
				Parent int32
			}{writes, int32(parent)}
			_, _, errno = syscall.Syscall6(445, fd, 1, uintptr(unsafe.Pointer(&rule)), 0, 0, 0)
			syscall.Close(parent)
			if errno != 0 {
				return errno
			}
		}
	}
	if _, _, errno = syscall.Syscall6(syscall.SYS_PRCTL, 38, 1, 0, 0, 0, 0); errno != 0 {
		return errno
	} // PR_SET_NO_NEW_PRIVS
	if _, _, errno = syscall.Syscall(446, fd, 0, 0); errno != 0 {
		return errno
	}
	return nil
}
