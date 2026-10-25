//go:build linux || darwin

package main

import (
	"adapters/connections"
	"errors"
	"os"
	"os/exec"
	"testing"
)

// The journal export runs alone, and of Drive's custody: the journal to
// stdout where the custody is there; a custody that is not there, or any
// other mode beside it, is refused, with nothing written and nothing made.
func TestExportObservationsRunsAlone(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	run := func(flags ...string) ([]byte, int) {
		cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestPipeHelper$", "--"}, flags...)...)
		cmd.Env = append(os.Environ(), "GATEWAY_PIPE_HELPER=1")
		out, err := cmd.Output()
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return out, exit.ExitCode()
		}
		if err != nil {
			t.Fatal(err)
		}
		return out, 0
	}
	if out, code := run("--export-observations", "--state-dir", dir, "--principal", "owner"); code != 1 || len(out) != 0 {
		t.Fatalf("a custody that is not there: exit %d, %q", code, out)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("the refused export made %v", entries)
	}
	s, err := connections.OpenStore(dir, "owner")
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if out, code := run("--export-observations", "--state-dir", dir, "--principal", "owner"); code != 0 || string(out) != `{"version":"1","operations":[]}` {
		t.Fatalf("the journal of a custody that keeps none: exit %d, %q", code, out)
	}
	for _, extra := range [][]string{{"--provider", "gmail"}, {"--catalog"}, {"--disabled"}, {"--local-plan"}} {
		flags := append([]string{"--export-observations", "--state-dir", dir, "--principal", "owner"}, extra...)
		if out, code := run(flags...); code != 2 || len(out) != 0 {
			t.Fatalf("%v: exit %d, %q", extra, code, out)
		}
	}
}
