package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Launch is a server command as it is to run. Path is the absolute file the
// command resolved to, links resolved. File, when present, holds the bytes
// that were digested: a sealed in-memory copy (SealedCopy) where the platform
// has one, else that file opened once. A backend that can execute the
// descriptor itself does so; Report.ExecutesDigestedFile says whether what
// runs is exactly the digested bytes, which holds only for a sealed copy.
// Argv0 is the configured word, which a multi-call program dispatches on.
// Env is the server's complete environment: it reaches the server and never
// the launcher that confines it.
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
	created := tmp
	cleanup := func() error { return removePrivateTemp(created) }
	// Resolved, as the workspace is: Seatbelt matches resolved paths, and a
	// temporary directory below a link (/var on macOS) would match nothing.
	if tmp, err = filepath.EvalSymlinks(tmp); err != nil {
		return nil, report, noop, errors.Join(err, cleanup())
	}
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

// ExecutesDigestedFile reports whether what runs is exactly the bytes that
// were digested: the backend executes Launch.File itself, and that file is a
// sealed copy no one can change. When it is not, the caller re-checks the
// digest immediately before the start.
func (r Report) ExecutesDigestedFile() bool { return r.exactFile }

// executesDescriptor reports whether a backend executes launch.File itself
// rather than the path: a binary does; a "#!" script does not, because its
// interpreter reopens the path it is given.
func executesDescriptor(launch Launch) bool { return launch.File != nil && !isScript(launch.File) }

// removePrivateTemp removes a private temporary directory the server could
// fill. The server runs as this process's user, so whatever it left there is
// this user's: a directory it made unwritable or unsearchable is given back
// its owner's permissions first, then the whole tree is removed.
func removePrivateTemp(dir string) error {
	if err := os.RemoveAll(dir); err == nil {
		return nil
	}
	// WalkDir visits a directory before it reads it, so each is made
	// readable and searchable before its entries are needed.
	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			os.Chmod(path, 0o700)
		}
		return nil
	})
	return os.RemoveAll(dir)
}

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

// envFile holds the server's environment, credentials included, so no secret
// travels on a command line: on Linux in a sealed anonymous memory file,
// which never reaches a disk; where there is none (macOS), in an unlinked
// file in the private temporary directory. Each item is followed by a NUL
// byte.
func envFile(tmp string, items []string) (*os.File, error) {
	var data []byte
	for _, item := range items {
		if strings.IndexByte(item, 0) >= 0 {
			return nil, errors.New("sandbox-policy-invalid: an environment value contains a NUL byte")
		}
		data = append(append(data, item...), 0)
	}
	if f, err := sealedData("env", data); err == nil {
		return f, nil
	}
	f, err := os.CreateTemp(tmp, "env-")
	if err != nil {
		return nil, err
	}
	if err := os.Remove(f.Name()); err != nil {
		f.Close()
		return nil, err
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
