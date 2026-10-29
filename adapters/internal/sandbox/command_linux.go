//go:build linux && (amd64 || arm64)

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
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
		if err == syscall.EACCES && os.Args[5] == descriptorPath(4) {
			fmt.Fprintln(os.Stderr, "sandbox-sealed-exec-refused: this host refused to execute the sealed in-memory copy of the approved bytes; nothing was started")
			os.Exit(126)
		}
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
	report.Reason = "file-content writes, truncation and directory mutations are restricted; metadata changes, connections to local sockets and network access are not restricted"
	if launch.Backend == "" {
		report.Reason += "; no usable bubblewrap at a trusted location (" + strings.Join(bwrapLocations, ", ") + "), and a bwrap on PATH is never used"
	}
	if note := runtimeSocketNote(launch, reachableRuntimeSockets(launch.Env)); note != "" {
		report.Reason += "; " + note
	}
	report.cleanup = func() error { env.Close(); return nil }
	extra, target := []*os.File{env}, launch.Path
	if executesDescriptor(launch) {
		extra, target = append(extra, launch.File), descriptorPath(4)
		report.exactFile = Sealed(launch.File)
	}
	argv := append([]string{helperArg, mode, workspace, tmp, target, launch.Argv0}, launch.Args...)
	cmd := exec.CommandContext(ctx, self, argv...)
	cmd.Env = launcherEnv()
	cmd.ExtraFiles = extra
	return cmd, report, nil
}

// bubblewrapCommand prepares the launch under bubblewrap at path. It returns
// no command and no error when bubblewrap fails its start check here.
// Unless launch.RuntimeSockets, every listening Unix socket the server could
// reach is hidden (bubblewrapFlags), and the report is partial when one
// stays reachable.
func bubblewrapCommand(ctx context.Context, path string, launch Launch, mode, workspace, tmp string, report *Report) (*exec.Cmd, error) {
	// A binary is not executed through its descriptor inside bubblewrap: a
	// security module may refuse to execute a memory file there (Ubuntu's
	// bubblewrap profile does, with EACCES). bubblewrap instead copies the
	// digested descriptor (descriptor 4) into a read-only file of its own
	// tmpfs, over a directory of the private temporary directory, and runs
	// that file with argv[0] kept by --argv0. The copy is made from the
	// sealed descriptor before the server starts, and neither the server
	// nor anyone outside its mount namespace can reach it, so what runs is
	// exactly the digested bytes. A bubblewrap that lacks those options, or
	// a "#!" script, runs the path and the caller re-checks the digest.
	type attempt struct {
		copied bool
		target string
	}
	execDir := filepath.Join(tmp, ".gateway-exec")
	attempts := []attempt{}
	if executesDescriptor(launch) {
		if err := os.Mkdir(execDir, 0o700); err != nil {
			return nil, err
		}
		attempts = append(attempts, attempt{true, filepath.Join(execDir, filepath.Base(launch.Path))})
	}
	attempts = append(attempts, attempt{false, launch.Path})
	for _, a := range attempts {
		// The sockets are listed afresh for each start check: one that goes
		// away between the listing and the check fails it once.
		for try := 0; try < 2; try++ {
			flags, masked, open := bubblewrapFlags(launch, mode, workspace, tmp)
			if a.copied {
				flags = append(flags, "--tmpfs", execDir, "--perms", "0555", "--ro-bind-data", "4", a.target, "--argv0", launch.Argv0)
			}
			probeArgs, err := os.Open(os.DevNull)
			if err != nil {
				return nil, err
			}
			probeFiles := []*os.File{probeArgs}
			if a.copied {
				// Its own open file description: bubblewrap reads to the end.
				data, err := reopen(launch.File)
				if err != nil {
					probeArgs.Close()
					return nil, err
				}
				probeFiles = append(probeFiles, data)
			}
			probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			probe := exec.CommandContext(probeCtx, path, append(append([]string{}, flags...), "--", "/bin/true")...)
			probe.Env = launcherEnv()
			probe.ExtraFiles = probeFiles
			err = probe.Run()
			cancel()
			for _, f := range probeFiles {
				f.Close()
			}
			if err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				continue
			}
			var files []*os.File
			if a.copied {
				data, err := reopen(launch.File)
				if err != nil {
					return nil, err
				}
				files = append(files, data)
			}
			var items []string
			for _, pair := range launch.Env {
				name, value, _ := strings.Cut(pair, "=")
				items = append(items, "--setenv", name, value)
			}
			args, err := envFile(tmp, items)
			if err != nil {
				for _, f := range files {
					f.Close()
				}
				return nil, err
			}
			report.Backend, report.State = "bubblewrap", "enforced"
			report.Reason = "filesystem mounts are read-only outside the declared writable directories (launcher " + path + "); network access is unchanged"
			if len(masked) > 0 {
				report.Reason += "; masked inside the sandbox: " + strings.Join(masked, ", ")
			}
			if open != "" {
				report.State = "partial"
				report.Reason += "; " + open
			}
			if launch.RuntimeSockets {
				report.State = "partial"
				report.Reason += "; " + runtimeSocketNote(launch, nil)
			}
			report.exactFile = a.copied && Sealed(launch.File)
			report.cleanup = func() error {
				args.Close()
				for _, f := range files {
					f.Close()
				}
				return nil
			}
			cmd := exec.CommandContext(ctx, path, append(append(flags, "--", a.target), launch.Args...)...)
			cmd.Env = launcherEnv()
			cmd.ExtraFiles = append([]*os.File{args}, files...)
			return cmd, nil
		}
	}
	return nil, nil
}

// reopen is a new open file description, read-only at its first byte, of
// the file f is open on: a memory file or a regular one alike.
func reopen(f *os.File) (*os.File, error) {
	return os.Open(descriptorPath(int(f.Fd())))
}

// bubblewrapFlags are the launcher's options up to the command; what they
// mask, for the report: each runtime directory and known runtime socket by
// name, and the other listening sockets by count, which keeps the report
// within its bound on a host with many; and, when something stays
// reachable, what (open; "" otherwise).
//
// Unless launch.RuntimeSockets, each per-user runtime directory becomes an
// empty tmpfs, and every other socket the server could connect to -- each
// listening socket bound to a path, each known runtime socket and the one a
// runtime host variable names -- becomes /dev/null. Masks come after the
// writable binds, so a socket inside the workspace is hidden too; only a
// runtime directory that holds the workspace or the private temporary
// directory is masked before them, so they stay, and its sockets inside them
// are masked after. A listening socket with an abstract name has no path to
// hide and stays reachable while the network namespace is shared, which every
// mode does: the report is then partial, as it is when the socket list
// cannot be read.
func bubblewrapFlags(launch Launch, mode, workspace, tmp string) (flags, masked []string, open string) {
	flags = []string{"--die-with-parent", "--new-session", "--unshare-user", "--unshare-pid", "--ro-bind", "/", "/"}
	writable := []string{}
	if mode == WorkspaceWrite {
		writable = []string{workspace, tmp}
	}
	inWritable := func(path string) bool {
		for _, dir := range writable {
			if within(path, dir) {
				return true
			}
		}
		return false
	}
	var before, after, sockets []string
	if !launch.RuntimeSockets {
		for _, dir := range userRuntimeDirs(launch.Env) {
			holds := false
			for _, w := range writable {
				holds = holds || within(w, dir)
			}
			if holds {
				before = append(before, dir)
			} else {
				after = append(after, dir)
			}
			masked = append(masked, dir)
		}
		listening, abstract, ok := listeningSockets()
		known := reachableRuntimeSockets(launch.Env)
		others := 0
		for _, socket := range existingSockets(append(append([]string{}, known...), listening...)) {
			hidden := within(socket, "/dev") || within(socket, "/proc")
			for _, dir := range after {
				hidden = hidden || within(socket, dir)
			}
			for _, dir := range before {
				hidden = hidden || (within(socket, dir) && !inWritable(socket))
			}
			// A socket this user may not connect to needs no mask.
			if hidden || syscall.Access(socket, 2) != nil {
				continue
			}
			sockets = append(sockets, socket)
			if slices.Contains(known, socket) {
				masked = append(masked, socket)
			} else {
				others++
			}
		}
		if others > 0 {
			masked = append(masked, strconv.Itoa(others)+" other listening sockets")
		}
		switch {
		case !ok:
			open = "the host's listening Unix sockets could not be listed, so a reachable one may remain"
		case abstract > 0:
			open = strconv.Itoa(abstract) + " listening Unix sockets with an abstract name stay reachable (the network namespace is shared), and their programs are not confined by this boundary"
		}
	}
	for _, dir := range before {
		flags = append(flags, "--tmpfs", dir)
	}
	flags = append(flags, "--dev", "/dev", "--proc", "/proc")
	for _, dir := range writable {
		flags = append(flags, "--bind", dir, dir)
	}
	for _, dir := range after {
		flags = append(flags, "--tmpfs", dir)
	}
	for _, socket := range sockets {
		flags = append(flags, "--ro-bind", "/dev/null", socket)
	}
	flags = append(flags, "--chdir", workspace, "--clearenv", "--args", "3")
	return flags, masked, open
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
	// Writing to /dev/null changes nothing, and programs expect to: its
	// file rights (write, truncate) are granted beneath the device itself.
	if err := landlockRule(fd, os.DevNull, (1<<1)|(1<<14)); err != nil {
		return err
	}
	if mode == WorkspaceWrite {
		for _, path := range []string{workspace, tmp} {
			if err := landlockRule(fd, path, writes); err != nil {
				return err
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

// landlockRule allows access beneath path (a directory, or a file for file
// rights only) in the ruleset fd.
func landlockRule(fd uintptr, path string, access uint64) error {
	parent, err := syscall.Open(path, 0x200000|syscall.O_CLOEXEC, 0) // O_PATH
	if err != nil {
		return err
	}
	defer syscall.Close(parent)
	// The kernel struct is packed: uint64 allowed_access, int32 parent_fd.
	rule := struct {
		Access uint64
		Parent int32
	}{access, int32(parent)}
	if _, _, errno := syscall.Syscall6(445, fd, 1, uintptr(unsafe.Pointer(&rule)), 0, 0, 0); errno != 0 {
		return errno
	}
	return nil
}
