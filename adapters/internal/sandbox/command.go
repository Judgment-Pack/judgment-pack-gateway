package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
)

// Command prepares a command and a private temporary directory. The caller
// removes the directory only after the complete process tree has stopped.
func Command(ctx context.Context, executable string, args []string, mode, workspace string) (*exec.Cmd, Report, func(), error) {
	report := Report{Mode: mode, Backend: "none", State: "not-enforced"}
	noop := func() {}
	if !ValidMode(mode) {
		return nil, report, noop, errors.New("sandbox-policy-invalid: unsupported mode")
	}
	if mode == FullAccess {
		report.Reason = "the operator explicitly selected unrestricted filesystem access"
		cmd := exec.CommandContext(ctx, executable, args...)
		cmd.Dir = workspace
		return cmd, report, noop, nil
	}
	if workspace == "" || !filepath.IsAbs(workspace) {
		return nil, report, noop, errors.New("sandbox-policy-invalid: restricted commands require an absolute workspace directory")
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
	cleanup := func() { _ = os.RemoveAll(tmp) }
	cmd, report, err := platformCommand(ctx, executable, args, mode, resolved, tmp)
	if err != nil {
		if report.cleanup == nil || report.cleanup() {
			cleanup()
		}
		return nil, report, noop, err
	}
	cmd.Dir = resolved
	cmd.Env = append(os.Environ(), "TMPDIR="+tmp, "TMP="+tmp, "TEMP="+tmp)
	if platformCleanup := report.cleanup; platformCleanup != nil {
		removeTemp := cleanup
		cleanup = func() {
			if platformCleanup() {
				removeTemp()
			}
		}
	}
	return cmd, report, cleanup, nil
}
