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
