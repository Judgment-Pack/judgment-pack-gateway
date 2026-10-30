//go:build linux || darwin

package main

import (
	"adapters/connections"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The grants mode runs alone: the report reads no input and makes no
// custody; a change reads one request from stdin; a refusal is its code on
// stderr; a mode beside it, or an operation it does not know, is refused.
func TestGrantsRunAlone(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	run := func(stdin string, flags ...string) (string, string, int) {
		cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestPipeHelper$", "--"}, flags...)...)
		cmd.Env = append(os.Environ(), "GATEWAY_PIPE_HELPER=1")
		cmd.Stdin = strings.NewReader(stdin)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return string(out), stderr.String(), exit.ExitCode()
		}
		if err != nil {
			t.Fatal(err)
		}
		return string(out), stderr.String(), 0
	}
	if out, _, code := run("", "--grants", "report", "--state-dir", dir, "--principal", "owner"); code != 0 || out != `{"connections":[],"version":1}`+"\n" {
		t.Fatalf("an empty custody's report: exit %d, %q", code, out)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("the report made %v", entries)
	}
	s, err := connections.OpenDatabricksStore(dir, "owner")
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if out, stderr, code := run(`{"provider":"databricks","connection":"absent","owner":{"kind":"person","issuer":"i","subject":"s"},"ownerHost":"desk"}`, "--grants", "set-owner", "--state-dir", dir, "--principal", "owner"); code != 1 || out != "" || stderr != "grants: grant-unknown\n" {
		t.Fatalf("an owner for an absent connection: exit %d, %q, %q", code, out, stderr)
	}
	if out, _, code := run(`{}`, "--grants", "sweep", "--state-dir", dir, "--principal", "owner", "--provider", "databricks"); code != 0 || out != `{"results":[],"version":1}`+"\n" {
		t.Fatalf("a sweep: exit %d, %q", code, out)
	}
	for _, flags := range [][]string{
		{"--grants", "report", "--catalog"},
		{"--grants", "report", "--disabled"},
		{"--grants", "report", "--export-observations"},
		{"--grants", "rotate"},
	} {
		if out, _, code := run("", append(flags, "--state-dir", dir, "--principal", "owner")...); code != 2 || out != "" {
			t.Fatalf("%v: exit %d, %q", flags, code, out)
		}
	}
}
