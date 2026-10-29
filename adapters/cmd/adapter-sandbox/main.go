// adapter-sandbox is the process boundary between the standard-library-only
// gateway core and the adapter module's native sandbox implementations.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"adapters/internal/canon"
	"adapters/internal/descendants"
	"adapters/internal/sandbox"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 2 && args[0] == "preset" {
		raw, err := sandbox.ExpandPreset(args[1])
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		fmt.Fprintln(stdout, string(raw))
		return 0
	}
	if len(args) == 0 || (args[0] != "probe" && args[0] != "run") {
		fmt.Fprintln(stderr, "usage: adapter-sandbox preset review|work|full | probe|run --policy FILE --source NAME --workspace DIR [--container-runtime] [run: --expect-mode MODE --expect-backend NAME --expect-policy DIGEST] [-- COMMAND ARGS...]")
		return 2
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	policy := fs.String("policy", "", "operator sandbox policy file")
	source := fs.String("source", "", "exact source identity")
	workspace := fs.String("workspace", "", "absolute source workspace")
	runtimeSockets := fs.Bool("container-runtime", false, "keep container-runtime sockets reachable for a runtime client (reported as partial)")
	var expectMode, expectBackend, expectPolicy *string
	if args[0] == "run" {
		// What a probe reported for this source: the launch uses exactly
		// that mode, policy and backend, or refuses.
		expectMode = fs.String("expect-mode", "", "the mode the posture probe reported")
		expectBackend = fs.String("expect-backend", "", "the backend the posture probe reported")
		expectPolicy = fs.String("expect-policy", "", "the policy digest the posture probe reported")
	}
	if fs.Parse(args[1:]) != nil {
		return 2
	}
	if (args[0] == "probe" && fs.NArg() != 0) || (args[0] == "run" && fs.NArg() == 0) || *source == "" {
		fmt.Fprintln(stderr, "sandbox-policy-invalid: an exact source and the selected command shape are required")
		return 2
	}
	// A loader variable would choose code for whatever runs under this
	// helper; the launcher starts with an empty environment regardless.
	for _, pair := range os.Environ() {
		if name, _, _ := strings.Cut(pair, "="); sandbox.LoaderVariable(name) {
			fmt.Fprintf(stderr, "sandbox-loader-variable-refused: %s is a dynamic-loader variable (LD_*, DYLD_* or GCONV_PATH), which a wrapped source may not carry\n", name)
			return 125
		}
	}
	removeWorkspace := false
	if *workspace == "" {
		var err error
		*workspace, err = os.MkdirTemp("", "gateway-workspace-")
		if err != nil {
			fmt.Fprintln(stderr, "sandbox-policy-invalid: cannot create private workspace")
			return 125
		}
		removeWorkspace = true
	}
	defer func() {
		if removeWorkspace {
			os.RemoveAll(*workspace)
		}
	}()
	settings, digest, err := sandbox.SelectionForWorkspace(*policy, *source, *workspace)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if args[0] == "run" {
		for _, expected := range []struct{ name, want, got string }{{"policy", *expectPolicy, digest}, {"mode", *expectMode, settings.Mode}} {
			if expected.want != "" && expected.want != expected.got {
				fmt.Fprintf(stderr, "sandbox-not-enforced: the %s is now %s, not the %s posture reported for this source; restart the engine to measure it again\n", expected.name, expected.got, expected.want)
				return 125
			}
		}
		code := runProgram(sandbox.Launch{Backend: *expectBackend, RuntimeSockets: *runtimeSockets}, settings.Mode, *workspace, fs.Args(), stdout, stderr)
		if code == 125 {
			removeWorkspace = false
		}
		return code
	}
	out := struct {
		Settings     sandbox.Settings `json:"settings"`
		Preset       string           `json:"preset"`
		PolicyDigest string           `json:"policyDigest"`
		Protection   sandbox.Report   `json:"protection"`
	}{settings, settings.Preset(), digest, sandbox.Probe(context.Background(), settings.Mode, *workspace, *runtimeSockets)}
	if strings.HasPrefix(out.Protection.Reason, "sandbox-cleanup-failed:") {
		removeWorkspace = false
	}
	raw, err := json.Marshal(out)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	raw, err = canon.Canonicalize(raw, canon.RefuseNumbers)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, string(raw))
	return 0
}

// runProgram runs argv under launch's backend binding and socket choice.
func runProgram(launch sandbox.Launch, mode, workspace string, argv []string, stdout, stderr io.Writer) int {
	path, err := exec.LookPath(argv[0])
	if err == nil {
		path, err = filepath.Abs(path)
	}
	if err != nil {
		fmt.Fprintln(stderr, "sandbox-command-unavailable:", err)
		return 126
	}
	if err := descendants.Adopt(); err != nil {
		fmt.Fprintln(stderr, "sandbox-not-enforced:", err)
		return 125
	}
	launch.Path, launch.Argv0, launch.Args, launch.Env = path, argv[0], argv[1:], os.Environ()
	cmd, _, cleanup, err := sandbox.Command(context.Background(), launch, mode, workspace)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 125
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, stdout, stderr
	cmd.WaitDelay = 2 * time.Second
	runErr := cmd.Run()
	// Reuse the MCP lifecycle implementation: on Linux, descendants adopted
	// here are ended; elsewhere there is no adoption, and a full-access
	// Windows launch has no job containment. Failure overrides even a
	// successful child result and leaves temporary resources for recovery.
	if err := descendants.Kill(); err != nil {
		fmt.Fprintln(stderr, "sandbox-cleanup-failed:", err)
		return 125
	}
	if err := cleanup(); err != nil {
		fmt.Fprintln(stderr, err)
		return 125
	}
	if runErr == nil {
		return 0
	}
	var exit *exec.ExitError
	if errors.As(runErr, &exit) && exit.ExitCode() > 0 {
		return exit.ExitCode()
	}
	fmt.Fprintln(stderr, "sandbox-command-failed:", runErr)
	return 126
}
