package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func init() {
	if len(os.Args) < 2 {
		return
	}
	switch os.Args[1] {
	case "_sandbox_cli_test":
		os.Exit(run(os.Args[2:], os.Stdout, os.Stderr))
	case "_sandbox_cli_descendant":
		cmd := exec.Command(os.Args[0], append([]string{"_sandbox_cli_writer"}, os.Args[2:]...)...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	case "_sandbox_cli_writer":
		json.NewEncoder(os.Stdout).Encode(map[string]any{
			"inside":   os.WriteFile(os.Args[2], []byte("inside"), 0600) == nil,
			"outside":  os.WriteFile(os.Args[3], []byte("outside"), 0600) == nil,
			"argument": os.Args[4],
		})
		os.Exit(0)
	case "_sandbox_cli_failure":
		fmt.Fprintln(os.Stderr, "fixture-child-failure")
		os.Exit(42)
	}
}

func TestWrapperConfinesAdapterAndHelperDescendants(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("native backend platform")
	}
	for _, mode := range []string{"read-only", "workspace-write", "danger-full-access"} {
		t.Run(mode, func(t *testing.T) {
			workspace := t.TempDir()
			policy := filepath.Join(t.TempDir(), "policy.json")
			if err := os.WriteFile(policy, []byte(`{"policyVersion":"1","defaultMode":"`+mode+`","sources":{}}`), 0600); err != nil {
				t.Fatal(err)
			}
			inside, outside := filepath.Join(workspace, "written"), filepath.Join(t.TempDir(), "outside")
			cmd := exec.Command(os.Args[0], "_sandbox_cli_test", "run", "--policy="+policy, "--source=fixture/live", "--workspace="+workspace, "--", os.Args[0], "_sandbox_cli_descendant", inside, outside, "argument with spaces")
			raw, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("wrapper: %v: %s", err, raw)
			}
			var got struct {
				Inside, Outside bool
				Argument        string
			}
			if err = json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err, string(raw))
			}
			if got.Inside != (mode != "read-only") || got.Outside != (mode == "danger-full-access") || got.Argument != "argument with spaces" {
				t.Fatalf("descendant boundary: %+v", got)
			}
		})
	}
}

func TestWrapperKeepsChildFailureDistinct(t *testing.T) {
	policy := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(policy, []byte(`{"policyVersion":"1","defaultMode":"danger-full-access","sources":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "_sandbox_cli_test", "run", "--policy="+policy, "--source=fixture/live", "--", os.Args[0], "_sandbox_cli_failure")
	raw, err := cmd.CombinedOutput()
	if err == nil || cmd.ProcessState.ExitCode() != 42 || string(raw) != "fixture-child-failure\n" {
		t.Fatalf("child failure changed: %v %s", err, raw)
	}
}

func TestWrapperRefusesMalformedSelectionBeforeLaunch(t *testing.T) {
	for _, args := range [][]string{{}, {"run"}, {"probe", "--source="}, {"probe", "--source=fixture/live", "extra"}, {"preset", "unknown"}} {
		var out, diagnostic bytes.Buffer
		if code := run(args, &out, &diagnostic); code != 2 || out.Len() != 0 {
			t.Fatalf("malformed command: %v: %d %s", args, code, out.String())
		}
	}
	var out, diagnostic bytes.Buffer
	if code := run([]string{"preset", "review"}, &out, &diagnostic); code != 0 || !strings.Contains(out.String(), `"mode":"read-only"`) {
		t.Fatalf("preset: %d %s %s", code, out.String(), diagnostic.String())
	}
}

// probeSelection runs the helper's probe and returns what a launch is bound to.
func probeSelection(t *testing.T, env []string, args ...string) (mode, backend, digest string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], append([]string{"_sandbox_cli_test", "probe"}, args...)...)
	cmd.Env = env
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("probe: %v: %s", err, raw)
	}
	var got struct {
		PolicyDigest string `json:"policyDigest"`
		Protection   struct{ Mode, Backend string }
	}
	if err := json.Unmarshal(raw, &got); err != nil || got.PolicyDigest == "" {
		t.Fatalf("probe output: %s", raw)
	}
	return got.Protection.Mode, got.Protection.Backend, got.PolicyDigest
}

func nativeBackend(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("no restricted backend on this platform")
	}
}

// A launch runs only under the mode, policy and backend its probe reported:
// a policy rewritten after the probe, or another backend, refuses before the
// program starts; the probe's own selection runs, confined.
func TestWrapperLaunchIsBoundToProbe(t *testing.T) {
	nativeBackend(t)
	workspace := t.TempDir()
	policy := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(policy, []byte(`{"policyVersion":"1","defaultMode":"workspace-write","sources":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	selection := []string{"--policy=" + policy, "--source=fixture/live", "--workspace=" + workspace}
	mode, backend, digest := probeSelection(t, os.Environ(), selection...)
	if mode != "workspace-write" || !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("probe: %s %s %s", mode, backend, digest)
	}
	launch := func(expect ...string) (int, map[string]any, string) {
		inside, outside := filepath.Join(workspace, "written"), filepath.Join(t.TempDir(), "outside")
		args := append(append([]string{"_sandbox_cli_test", "run"}, selection...), expect...)
		cmd := exec.Command(os.Args[0], append(args, "--", os.Args[0], "_sandbox_cli_writer", inside, outside, "x")...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		cmd.Run()
		var got map[string]any
		json.Unmarshal(stdout.Bytes(), &got)
		if _, err := os.Stat(outside); err == nil {
			t.Fatalf("written outside the workspace: %v", expect)
		}
		return cmd.ProcessState.ExitCode(), got, stderr.String()
	}
	bound := []string{"--expect-mode=" + mode, "--expect-backend=" + backend, "--expect-policy=" + digest}
	if code, got, stderr := launch(bound...); code != 0 || got["inside"] != true || got["outside"] != false {
		t.Fatalf("the probe's own selection: %d %v %s", code, got, stderr)
	}
	other := map[string]string{"linux": "seatbelt", "darwin": "bubblewrap"}[runtime.GOOS]
	for name, expect := range map[string][]string{
		"another backend": {"--expect-mode=" + mode, "--expect-backend=" + other, "--expect-policy=" + digest},
		"another mode":    {"--expect-mode=read-only", "--expect-backend=" + backend, "--expect-policy=" + digest},
	} {
		if code, got, stderr := launch(expect...); code != 125 || got != nil || !strings.Contains(stderr, "sandbox-not-enforced:") {
			t.Fatalf("%s: %d %v %s", name, code, got, stderr)
		}
	}
	// The policy changes after posture was measured: full access now, which
	// would write outside. The launch refuses and nothing runs.
	if err := os.WriteFile(policy, []byte(`{"policyVersion":"1","defaultMode":"danger-full-access","sources":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if code, got, stderr := launch(bound...); code != 125 || got != nil || !strings.Contains(stderr, "not the "+digest+" posture reported") {
		t.Fatalf("policy changed after the probe: %d %v %s", code, got, stderr)
	}
}

// Neither the probe nor the launch uses a launcher found on PATH: a stand-in
// planted first on PATH never runs.
func TestWrapperNeverUsesALauncherOnPath(t *testing.T) {
	nativeBackend(t)
	dir, marker := t.TempDir(), filepath.Join(t.TempDir(), "stand-in-ran")
	for _, name := range []string{"bwrap", "sandbox-exec"} {
		// The stand-in runs whatever it is handed, unconfined.
		script := "#!/bin/sh\necho ran >> '" + marker + "'\nwhile [ \"$#\" -gt 0 ] && [ \"$1\" != \"--\" ]; do shift; done\nshift\nexec \"$@\"\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	env := append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	workspace := t.TempDir()
	selection := []string{"--source=fixture/live", "--workspace=" + workspace}
	mode, backend, digest := probeSelection(t, env, selection...)
	outside := filepath.Join(t.TempDir(), "outside")
	args := append(append([]string{"_sandbox_cli_test", "run"}, selection...), "--expect-mode="+mode, "--expect-backend="+backend, "--expect-policy="+digest, "--", os.Args[0], "_sandbox_cli_writer", filepath.Join(workspace, "in"), outside, "x")
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = env
	raw, err := cmd.CombinedOutput()
	t.Logf("backend %s: %v %s", backend, err, raw)
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("a launcher found on PATH was run")
	}
	if _, statErr := os.Stat(outside); statErr == nil {
		t.Fatal("written outside the workspace")
	}
}

// The wrapper refuses a loader variable in its environment for any wrapped
// program, not only a customer command, before anything starts.
func TestWrapperRefusesLoaderVariables(t *testing.T) {
	for _, name := range []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "GCONV_PATH"} {
		for _, verb := range []string{"probe", "run"} {
			marker := filepath.Join(t.TempDir(), "ran")
			args := []string{"_sandbox_cli_test", verb, "--source=fixture/history"}
			if verb == "run" {
				args = append(args, "--", os.Args[0], "_sandbox_cli_writer", marker, marker, "x")
			}
			cmd := exec.Command(os.Args[0], args...)
			cmd.Env = append(os.Environ(), name+"=/nonexistent/library.so")
			raw, err := cmd.CombinedOutput()
			if err == nil || cmd.ProcessState.ExitCode() != 125 || !strings.Contains(string(raw), "sandbox-loader-variable-refused:") {
				t.Fatalf("%s %s: %v %s", verb, name, err, raw)
			}
			if _, statErr := os.Stat(marker); statErr == nil {
				t.Fatalf("%s %s: the program ran", verb, name)
			}
		}
	}
}
