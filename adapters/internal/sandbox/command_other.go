//go:build !windows && !darwin && (!linux || (!amd64 && !arm64))

package sandbox

import (
	"context"
	"errors"
	"os/exec"
)

func platformCommand(_ context.Context, _ string, _ []string, mode, _, _ string) (*exec.Cmd, Report, error) {
	report := Report{Mode: mode, Backend: "none", State: "not-enforced", Reason: "no filesystem sandbox backend is implemented on this platform"}
	return nil, report, errors.New("sandbox-not-enforced: no filesystem sandbox backend is implemented on this platform")
}
