package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"
)

const probeArgument = "_gateway_sandbox_write_probe_v1"

func init() {
	if len(os.Args) != 4 || os.Args[1] != probeArgument {
		return
	}
	// Fixed local behavior: no customer program or network is invoked. The
	// parent owns both files and holds their original content until cleanup.
	writes := []bool{
		os.WriteFile(os.Args[2], []byte("probe"), 0600) == nil,
		os.WriteFile(os.Args[3], []byte("probe"), 0600) == nil,
	}
	if json.NewEncoder(os.Stdout).Encode(writes) != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

// Probe actually executes a fixed write test under the selected backend and
// this process's operating-system identity. It reports only a current filesystem
// check, never read/network isolation or the safety of a customer program.
func Probe(ctx context.Context, mode, workspace string) Report {
	report := Report{Mode: mode, Backend: "none", State: "not-enforced"}
	fail := func(reason string) Report { report.State, report.Reason = "not-enforced", reason; return report }
	if !ValidMode(mode) {
		return fail("sandbox-policy-invalid: unsupported mode")
	}
	if mode == FullAccess {
		return fail("the operator explicitly selected unrestricted filesystem access")
	}
	inside, err := os.CreateTemp(workspace, ".gateway-sandbox-probe-")
	if err != nil {
		return fail("sandbox-probe-failed: cannot prepare workspace probe")
	}
	inside.Close()
	defer os.Remove(inside.Name())
	outside, err := os.CreateTemp("", "gateway-sandbox-probe-")
	if err != nil {
		return fail("sandbox-probe-failed: cannot prepare outside probe")
	}
	outside.Close()
	defer os.Remove(outside.Name())
	self, err := os.Executable()
	if err != nil {
		return fail("sandbox-probe-failed: cannot resolve probe executable")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd, prepared, cleanup, err := Command(ctx, Launch{Path: self, Args: []string{probeArgument, inside.Name(), outside.Name()}}, mode, workspace)
	report = prepared
	if err != nil {
		if report.Reason != "" {
			return fail("sandbox-not-enforced: " + report.Reason)
		}
		return fail("sandbox-not-enforced: backend preparation failed")
	}
	cmd.WaitDelay = time.Second
	raw, runErr := cmd.Output()
	cleanupErr := cleanup()
	if cleanupErr != nil {
		return fail("sandbox-cleanup-failed: probe cleanup did not establish restoration")
	}
	if runErr != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fail("sandbox-probe-failed: backend check timed out")
		}
		return fail("sandbox-not-enforced: restricted probe could not execute")
	}
	var writes []bool
	if json.Unmarshal(raw, &writes) != nil || len(writes) != 2 || writes[0] != (mode == WorkspaceWrite) || writes[1] {
		return fail("sandbox-not-enforced: observed writes do not match the selected mode")
	}
	return report
}
