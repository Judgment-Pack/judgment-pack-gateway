package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

const envHelperArg = "_gateway_sandbox_env_v1"

// The helper runs inside the Seatbelt profile, started with the fixed
// launcher environment. It reads the server's environment from descriptor 3
// and executes the server with it, so no DYLD_* variable of the server's
// reaches sandbox-exec or this helper.
func init() {
	if len(os.Args) < 2 || os.Args[1] != envHelperArg {
		return
	}
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "sandbox-policy-invalid: invalid helper invocation")
		os.Exit(125)
	}
	env, err := readEnv(3)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandbox-policy-invalid: the server environment could not be read:", err)
		os.Exit(125)
	}
	if err := syscall.Exec(os.Args[2], os.Args[3:], env); err != nil {
		fmt.Fprintln(os.Stderr, "server-exec-failed:", err)
		os.Exit(126)
	}
	panic("exec returned without an error")
}

// platformCommand starts sandbox-exec with the fixed launcher environment.
// The server's environment reaches the server through this adapter's helper
// inside the profile. macOS cannot execute an open descriptor, so the file is
// executed by path and the caller re-checks its digest just before the start.
func platformCommand(ctx context.Context, launch Launch, mode, workspace, tmp string) (*exec.Cmd, Report, error) {
	report := Report{Mode: mode, Backend: "seatbelt", State: "not-enforced", Reason: "Seatbelt launcher is unavailable"}
	launcher, err := exec.LookPath("sandbox-exec")
	if err != nil {
		return nil, report, errors.New("sandbox-not-enforced: Seatbelt launcher is unavailable")
	}
	self, err := os.Executable()
	if err != nil {
		return nil, report, err
	}
	env, err := envFile(tmp, launch.Env)
	if err != nil {
		return nil, report, err
	}
	profile := "(version 1) (allow default) (deny file-write*)"
	if mode == WorkspaceWrite {
		profile += " (allow file-write* (subpath (param \"WORKSPACE\")) (subpath (param \"PRIVATE_TMP\")))"
	}
	argv := []string{"-D", "WORKSPACE=" + workspace, "-D", "PRIVATE_TMP=" + tmp, "-p", profile, self, envHelperArg, launch.Path, launch.Argv0}
	report.State, report.Reason = "enforced", "Seatbelt denies file writes outside the declared writable directories; network access is unchanged"
	report.cleanup = func() error { env.Close(); return nil }
	cmd := exec.CommandContext(ctx, launcher, append(argv, launch.Args...)...)
	cmd.Env = launcherEnv()
	cmd.ExtraFiles = []*os.File{env}
	return cmd, report, nil
}
