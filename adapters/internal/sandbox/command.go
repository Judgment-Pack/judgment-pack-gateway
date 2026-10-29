package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Launch is a server command as it is to run. Path is the absolute file the
// command resolved to, links resolved. File, when present, is that file
// opened once and digested from this descriptor; a backend that can execute
// or mount the descriptor itself does so, and Report.ExecutesDigestedFile
// then says so. Env is the server's complete environment: it reaches the
// server and never the launcher that confines it.
//
// Backend, when set, is the only backend this launch may use: the one a
// posture probe reported for it. A launch that cannot use exactly that backend
// refuses; nothing falls back to another. Empty selects the platform's usual
// order, and the returned report says which backend was used.
//
// RuntimeSockets keeps known container-runtime sockets reachable inside the
// sandbox, for a container runtime client; the report is then partial,
// because the runtime's daemon is not confined. Otherwise bubblewrap masks
// them (runtimeSocketPaths) and the per-user runtime directory.
type Launch struct {
	Path           string
	File           *os.File
	Argv0          string
	Args           []string
	Env            []string
	Backend        string
	RuntimeSockets bool
}

// LoaderVariable reports whether an environment variable is one a dynamic
// loader honours when a program starts: LD_* (glibc and musl), DYLD_* (macOS)
// and GCONV_PATH, which makes the C library load code. Such a name in a
// customer command's configured environment or credentials is refused: it
// would choose code before any policy applies.
func LoaderVariable(name string) bool {
	upper := strings.ToUpper(name)
	return strings.HasPrefix(upper, "LD_") || strings.HasPrefix(upper, "DYLD_") || upper == "GCONV_PATH"
}

// launcherEnv is the fixed environment a sandbox launcher starts with:
// nothing. The server's own environment is handed to it inside the sandbox.
func launcherEnv() []string { return []string{} }

// Command prepares a command and a private temporary directory. The caller
// removes the directory only after the complete process tree has stopped.
// The returned command's environment is final: the caller must not change it.
func Command(ctx context.Context, launch Launch, mode, workspace string) (*exec.Cmd, Report, func() error, error) {
	report := Report{Mode: mode, Backend: "none", State: "not-enforced"}
	noop := func() error { return nil }
	if !ValidMode(mode) {
		return nil, report, noop, errors.New("sandbox-policy-invalid: unsupported mode")
	}
	if launch.Path == "" || !filepath.IsAbs(launch.Path) {
		return nil, report, noop, errors.New("sandbox-policy-invalid: the command must be resolved to an absolute path")
	}
	if launch.Argv0 == "" {
		launch.Argv0 = launch.Path
	}
	if mode == FullAccess {
		if launch.Backend != "" && launch.Backend != "none" {
			return nil, report, noop, fmt.Errorf("sandbox-not-enforced: the launch was bound to backend %s, but unrestricted access uses none", launch.Backend)
		}
		report.Reason = "the operator explicitly selected unrestricted filesystem access"
		cmd, exact := directCommand(ctx, launch)
		report.exactFile = exact
		cmd.Dir = workspace
		cmd.Env = dedupEnv(launch.Env)
		return cmd, report, noop, nil
	}
	if workspace == "" || !filepath.IsAbs(workspace) {
		return nil, report, noop, errors.New("sandbox-policy-invalid: restricted commands require an absolute workspace directory")
	}
	if launch.Backend == "none" {
		return nil, report, noop, errors.New("sandbox-not-enforced: the launch was bound to no backend, and a restricted mode needs one")
	}
	resolved, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		return nil, report, noop, errors.New("sandbox-policy-invalid: workspace is unavailable")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() || resolved == filepath.VolumeName(resolved)+string(filepath.Separator) {
		return nil, report, noop, errors.New("sandbox-policy-invalid: workspace must be a directory below the filesystem root")
	}
	tmp, err := os.MkdirTemp("", "gateway-source-")
	if err != nil {
		return nil, report, noop, err
	}
	cleanup := func() error { return os.RemoveAll(tmp) }
	// The private temporary-directory variables come last, so neither the
	// platform environment nor a credential replaces them.
	launch.Env = dedupEnv(append(append([]string{}, launch.Env...), "TMPDIR="+tmp, "TMP="+tmp, "TEMP="+tmp))
	cmd, report, err := platformCommand(ctx, launch, mode, resolved, tmp)
	if err == nil && launch.Backend != "" && report.Backend != launch.Backend {
		// platformCommand honours the binding; this keeps any backend from
		// ever starting under a report that names another.
		err = fmt.Errorf("sandbox-not-enforced: the launch was bound to backend %s, but %s was selected", launch.Backend, report.Backend)
		cmd = nil
	}
	if err != nil {
		if report.cleanup != nil {
			if cleanupErr := report.cleanup(); cleanupErr != nil {
				return nil, report, noop, errors.Join(err, cleanupErr)
			}
		}
		err = errors.Join(err, cleanup())
		return nil, report, noop, err
	}
	cmd.Dir = resolved
	if platformCleanup := report.cleanup; platformCleanup != nil {
		removeTemp := cleanup
		cleanup = func() error {
			if err := platformCleanup(); err != nil {
				return err
			}
			return removeTemp()
		}
	}
	return cmd, report, cleanup, nil
}

// ExecutesDigestedFile reports whether the backend runs the descriptor that
// was digested (Launch.File) rather than reopening the path. When it does
// not, the caller re-checks the digest immediately before the start.
func (r Report) ExecutesDigestedFile() bool { return r.exactFile }

// dedupEnv keeps the last value of each name, in first-seen order, so a
// reader that takes the first match and one that takes the last agree.
func dedupEnv(env []string) []string {
	last := map[string]int{}
	for i, pair := range env {
		name, _, _ := strings.Cut(pair, "=")
		last[envKey(name)] = i
	}
	out := make([]string, 0, len(last))
	for i, pair := range env {
		name, _, _ := strings.Cut(pair, "=")
		if last[envKey(name)] == i {
			out = append(out, pair)
		}
	}
	return out
}

// envFile holds the server's environment in an unlinked file in the private
// temporary directory, so no secret travels on a command line. Each item is
// followed by a NUL byte.
func envFile(tmp string, items []string) (*os.File, error) {
	f, err := os.CreateTemp(tmp, "env-")
	if err != nil {
		return nil, err
	}
	if err := os.Remove(f.Name()); err != nil {
		f.Close()
		return nil, err
	}
	var data []byte
	for _, item := range items {
		if strings.IndexByte(item, 0) >= 0 {
			f.Close()
			return nil, errors.New("sandbox-policy-invalid: an environment value contains a NUL byte")
		}
		data = append(append(data, item...), 0)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, 0); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// isScript reports whether the file begins with "#!": the kernel then runs
// the interpreter it names, which opens the script again by its path.
func isScript(f *os.File) bool {
	var head [2]byte
	n, _ := f.ReadAt(head[:], 0)
	return n == 2 && head[0] == '#' && head[1] == '!'
}
