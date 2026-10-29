package sandbox

import (
	"context"
	"errors"
	"os/exec"
)

// Restricted commands fail before execution. Full access is handled only by the
// common path after the operator has explicitly selected that mode.
func platformCommand(_ context.Context, _ string, _ []string, mode, _, _ string) (*exec.Cmd, Report, error) {
	reason := "restricted local commands are unavailable on Windows"
	report := Report{Mode: mode, Backend: "none", State: "not-enforced", Reason: reason}
	return nil, report, errors.New("sandbox-not-enforced: " + reason)
}
