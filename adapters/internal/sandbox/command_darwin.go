package sandbox

import (
	"context"
	"errors"
	"os/exec"
)

func platformCommand(ctx context.Context, executable string, args []string, mode, workspace, tmp string) (*exec.Cmd, Report, error) {
	report := Report{Mode: mode, Backend: "seatbelt", State: "not-enforced", Reason: "Seatbelt launcher is unavailable"}
	launcher, err := exec.LookPath("sandbox-exec")
	if err != nil {
		return nil, report, errors.New("sandbox-not-enforced: Seatbelt launcher is unavailable")
	}
	profile := "(version 1) (allow default) (deny file-write*)"
	if mode == WorkspaceWrite {
		profile += " (allow file-write* (subpath (param \"WORKSPACE\")) (subpath (param \"PRIVATE_TMP\")))"
	}
	argv := []string{"-D", "WORKSPACE=" + workspace, "-D", "PRIVATE_TMP=" + tmp, "-p", profile, executable}
	report.State, report.Reason = "enforced", "Seatbelt denies file writes outside the declared writable directories; network access is unchanged"
	return exec.CommandContext(ctx, launcher, append(argv, args...)...), report, nil
}
