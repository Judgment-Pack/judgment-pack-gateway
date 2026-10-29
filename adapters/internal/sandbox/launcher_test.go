//go:build !windows

package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// plantLaunchers puts stand-ins named bwrap and sandbox-exec in a new
// directory; each records that it ran and fails.
func plantLaunchers(t *testing.T) (dir, marker string) {
	t.Helper()
	dir, marker = t.TempDir(), filepath.Join(t.TempDir(), "stand-in-ran")
	for _, name := range []string{"bwrap", "sandbox-exec"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\necho ran >> '"+marker+"'\nexit 1\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir, marker
}

// A launcher first on PATH is never run: launchers come only from fixed,
// verified locations.
func TestPlantedPathLauncherIsNeverUsed(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("no backend implemented on this platform")
	}
	dir, marker := plantLaunchers(t)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, mode := range []string{ReadOnly, WorkspaceWrite} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd, report, cleanup, err := Command(ctx, Launch{Path: os.Args[0], Args: []string{"_sandbox_test_env"}, Env: os.Environ()}, mode, t.TempDir())
		if err == nil {
			_, err = cmd.Output()
		}
		cleanup()
		cancel()
		t.Logf("%s: backend %s, %v", mode, report.Backend, err)
		if _, statErr := os.Stat(marker); statErr == nil {
			t.Fatal("a launcher found on PATH was run")
		}
	}
}

// A launcher at a fixed location that is not root's refuses: no later
// location, no PATH and no other backend is tried.
func TestUntrustedLauncherRefusesWithoutFallback(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("no backend implemented on this platform")
	}
	if os.Geteuid() == 0 {
		t.Skip("a file this test plants would be root's")
	}
	dir, marker := plantLaunchers(t)
	savedB, savedS := bwrapLocations, sandboxExecLocations
	t.Cleanup(func() { bwrapLocations, sandboxExecLocations = savedB, savedS })
	bwrapLocations = []string{filepath.Join(dir, "bwrap"), "/usr/bin/bwrap"}
	sandboxExecLocations = []string{filepath.Join(dir, "sandbox-exec")}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd, report, cleanup, err := Command(ctx, Launch{Path: os.Args[0], Args: []string{"_sandbox_test_env"}, Env: os.Environ()}, WorkspaceWrite, t.TempDir())
	defer cleanup()
	if cmd != nil || err == nil || !strings.Contains(err.Error(), "sandbox-launcher-untrusted:") || report.State != "not-enforced" {
		t.Fatalf("untrusted launcher: cmd=%v report=%+v err=%v", cmd, report, err)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("the untrusted launcher was run")
	}
}
