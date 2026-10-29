//go:build linux && (amd64 || arm64)

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const helperArg = "_gateway_sandbox_exec_v2"

// The helper never returns to the application. It starts with the fixed
// launcher environment, reads the server's environment from descriptor 3,
// then confines itself. Landlock attaches to the calling thread; exec must
// run on that same locked thread. Its restrictions then apply to the new
// program and its descendants.
func init() {
	if len(os.Args) < 2 || os.Args[1] != helperArg {
		return
	}
	if len(os.Args) < 7 || !ValidMode(os.Args[2]) || os.Args[2] == FullAccess {
		fmt.Fprintln(os.Stderr, "sandbox-policy-invalid: invalid helper invocation")
		os.Exit(125)
	}
	env, err := readEnv(3)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandbox-policy-invalid: the server environment could not be read:", err)
		os.Exit(125)
	}
	runtime.LockOSThread()
	if err := restrictLandlock(os.Args[2], os.Args[3], os.Args[4]); err != nil {
		fmt.Fprintln(os.Stderr, "sandbox-not-enforced: Landlock setup failed:", err)
		os.Exit(125)
	}
	if err := syscall.Exec(os.Args[5], os.Args[6:], env); err != nil {
		fmt.Fprintln(os.Stderr, "server-exec-failed:", err)
		os.Exit(126)
	}
	panic("exec returned without an error")
}

// platformCommand starts a launcher with the fixed launcher environment
// (launcherEnv), never the server's: a loader variable among the server's
// variables would otherwise act on the launcher before anything is confined.
// The server's environment reaches the server through descriptor 3, read by
// bubblewrap (--clearenv, then --args) or by the Landlock helper. Neither
// sees it on a command line.
func platformCommand(ctx context.Context, launch Launch, mode, workspace, tmp string) (*exec.Cmd, Report, error) {
	report := Report{Mode: mode, Backend: "none", State: "not-enforced", Reason: "no usable filesystem sandbox backend"}
	if launch.Backend != "" && launch.Backend != "bubblewrap" && launch.Backend != "landlock" {
		err := fmt.Errorf("sandbox-not-enforced: the launch was bound to backend %s, which this platform does not provide", launch.Backend)
		report.Reason = err.Error()
		return nil, report, err
	}
	// Bound to Landlock (what a probe reported), bubblewrap is not tried.
	if launch.Backend != "landlock" {
		// bubblewrap only from a fixed, verified location (launcher_unix.go);
		// one there that fails verification refuses rather than falling back.
		path, found, err := trustedLauncher(bwrapLocations)
		if err != nil {
			report.Reason = err.Error()
			return nil, report, err
		}
		if !found && launch.Backend == "bubblewrap" {
			err := fmt.Errorf("sandbox-not-enforced: the launch was bound to bubblewrap, and none is at a trusted location (%s); no other backend is used", strings.Join(bwrapLocations, ", "))
			report.Reason = err.Error()
			return nil, report, err
		}
		if found {
			cmd, err := bubblewrapCommand(ctx, path, launch, mode, workspace, tmp, &report)
			if cmd != nil || err != nil {
				return cmd, report, err
			}
			if launch.Backend == "bubblewrap" {
				err := errors.New("sandbox-not-enforced: the launch was bound to bubblewrap, which failed its start check; no other backend is used")
				report.Reason = err.Error()
				return nil, report, err
			}
		}
	}
	if ctx.Err() != nil {
		return nil, report, ctx.Err()
	}
	abi, _, errno := syscall.Syscall(444, 0, 0, 1) // landlock_create_ruleset: query ABI
	if errno != 0 || abi < 3 {
		return nil, report, fmt.Errorf("sandbox-not-enforced: no usable bubblewrap at a trusted location (%s) and Landlock ABI 3 or newer is required", strings.Join(bwrapLocations, ", "))
	}
	self, err := os.Executable()
	if err != nil {
		return nil, report, err
	}
	env, err := envFile(tmp, launch.Env)
	if err != nil {
		return nil, report, err
	}
	report.Backend, report.State = "landlock", "partial"
	report.Reason = "file-content writes, truncation and directory mutations are restricted; metadata changes and network access are not restricted"
	if launch.Backend == "" {
		report.Reason += "; no usable bubblewrap at a trusted location (" + strings.Join(bwrapLocations, ", ") + "), and a bwrap on PATH is never used"
	}
	if note := runtimeSocketNote(launch, reachableRuntimeSockets(launch.Env)); note != "" {
		report.Reason += "; " + note
	}
	report.cleanup = func() error { env.Close(); return nil }
	extra, target := []*os.File{env}, launch.Path
	if launch.File != nil && !isScript(launch.File) {
		extra, target = append(extra, launch.File), descriptorPath(4)
		report.exactFile = true
	}
	argv := append([]string{helperArg, mode, workspace, tmp, target, launch.Argv0}, launch.Args...)
	cmd := exec.CommandContext(ctx, self, argv...)
	cmd.Env = launcherEnv()
	cmd.ExtraFiles = extra
	return cmd, report, nil
}

// bubblewrapCommand prepares the launch under bubblewrap at path. It returns
// no command and no error when bubblewrap fails its start check here.
// Unless launch.RuntimeSockets, the per-user runtime directories are replaced
// by empty ones and every other known runtime socket by /dev/null, so neither
// a container runtime nor the user's service manager can act for the server.
func bubblewrapCommand(ctx context.Context, path string, launch Launch, mode, workspace, tmp string, report *Report) (*exec.Cmd, error) {
	flags, masked := bubblewrapFlags(launch, mode, workspace, tmp)
	// A binary is executed inside the sandbox through the descriptor that
	// was digested (descriptor 4, which bubblewrap passes through), with its
	// argv[0] kept by --argv0; a bubblewrap without --argv0, or a "#!"
	// script, runs the path and the caller re-checks the digest.
	type attempt struct {
		flags  []string
		target string
		files  []*os.File
	}
	attempts := []attempt{}
	if launch.File != nil && !isScript(launch.File) {
		attempts = append(attempts, attempt{append(append([]string{}, flags...), "--argv0", launch.Argv0), descriptorPath(4), []*os.File{launch.File}})
	}
	attempts = append(attempts, attempt{flags, launch.Path, nil})
	for _, a := range attempts {
		probeArgs, err := os.Open(os.DevNull)
		if err != nil {
			return nil, err
		}
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		probe := exec.CommandContext(probeCtx, path, append(append([]string{}, a.flags...), "--", "/bin/true")...)
		probe.Env = launcherEnv()
		probe.ExtraFiles = []*os.File{probeArgs}
		err = probe.Run()
		cancel()
		probeArgs.Close()
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		var items []string
		for _, pair := range launch.Env {
			name, value, _ := strings.Cut(pair, "=")
			items = append(items, "--setenv", name, value)
		}
		args, err := envFile(tmp, items)
		if err != nil {
			return nil, err
		}
		report.Backend, report.State = "bubblewrap", "enforced"
		report.Reason = "filesystem mounts are read-only outside the declared writable directories (launcher " + path + "); network access is unchanged"
		if len(masked) > 0 {
			report.Reason += "; masked inside the sandbox: " + strings.Join(masked, ", ")
		}
		if launch.RuntimeSockets {
			report.State = "partial"
			report.Reason += "; " + runtimeSocketNote(launch, nil)
		}
		report.exactFile = a.files != nil
		report.cleanup = func() error { args.Close(); return nil }
		cmd := exec.CommandContext(ctx, path, append(append(a.flags, "--", a.target), launch.Args...)...)
		cmd.Env = launcherEnv()
		cmd.ExtraFiles = append([]*os.File{args}, a.files...)
		return cmd, nil
	}
	return nil, nil
}

// bubblewrapFlags are the launcher's options up to the command, and what they
// mask: unless launch.RuntimeSockets, each per-user runtime directory becomes
// an empty tmpfs and each other known runtime socket /dev/null. The masks
// precede the writable binds, so a workspace below a masked directory stays.
func bubblewrapFlags(launch Launch, mode, workspace, tmp string) (flags, masked []string) {
	flags = []string{"--die-with-parent", "--new-session", "--unshare-user", "--unshare-pid", "--ro-bind", "/", "/"}
	if !launch.RuntimeSockets {
		dirs := userRuntimeDirs(launch.Env)
		for _, dir := range dirs {
			flags = append(flags, "--tmpfs", dir)
			masked = append(masked, dir)
		}
		for _, socket := range reachableRuntimeSockets(launch.Env) {
			inside := false
			for _, dir := range dirs {
				inside = inside || within(socket, dir)
			}
			if !inside {
				flags = append(flags, "--ro-bind", "/dev/null", socket)
				masked = append(masked, socket)
			}
		}
	}
	flags = append(flags, "--dev", "/dev", "--proc", "/proc")
	if mode == WorkspaceWrite {
		flags = append(flags, "--bind", workspace, workspace, "--bind", tmp, tmp)
	}
	flags = append(flags, "--chdir", workspace, "--clearenv", "--args", "3")
	return flags, masked
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
