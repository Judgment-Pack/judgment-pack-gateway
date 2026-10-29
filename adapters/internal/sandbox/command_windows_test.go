package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsRestrictedCommandsRefuseBeforeExecution(t *testing.T) {
	temporary, workspace := t.TempDir(), t.TempDir()
	t.Setenv("TMP", temporary)
	t.Setenv("TEMP", temporary)
	marker := filepath.Join(workspace, "started")
	for _, mode := range []string{ReadOnly, WorkspaceWrite} {
		cmd, report, cleanup, err := Command(context.Background(), Launch{Path: os.Args[0], Args: []string{"_sandbox_test_write", marker}, Env: os.Environ()}, mode, workspace)
		if cmd != nil || err == nil || !strings.Contains(err.Error(), "sandbox-not-enforced:") {
			t.Fatalf("restricted command did not refuse: command=%v error=%v", cmd, err)
		}
		if report.Mode != mode || report.Backend != "none" || report.State != "not-enforced" || !strings.Contains(report.Reason, "Windows") {
			t.Fatalf("false enforcement report: %+v", report)
		}
		if err := cleanup(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatal("refused executable started", err)
		}
		entries, err := os.ReadDir(temporary)
		if err != nil || len(entries) != 0 {
			t.Fatalf("temporary directory leaked: %v %v", entries, err)
		}
	}
}

func TestWindowsExplicitFullAccessRemainsUnrestricted(t *testing.T) {
	workspace := t.TempDir()
	outside := filepath.Join(t.TempDir(), "written")
	cmd, report, cleanup, err := Command(context.Background(), Launch{Path: os.Args[0], Args: []string{"_sandbox_test_write", outside}, Env: os.Environ()}, FullAccess, workspace)
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	if report.Mode != FullAccess || report.Backend != "none" || report.State != "not-enforced" {
		t.Fatalf("false protection: %+v", report)
	}
	if raw, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("explicit full access: %v %s", err, raw)
	}
	if raw, err := os.ReadFile(outside); err != nil || string(raw) != "changed" {
		t.Fatalf("explicit full access did not run: %q %v", raw, err)
	}
}
