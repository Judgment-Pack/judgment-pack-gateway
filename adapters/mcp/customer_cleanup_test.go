package mcp

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"adapters/internal/sandbox"
)

func TestCustomerCleanupFailureRefusesRegistrationAndAcquisition(t *testing.T) {
	cfg := fake(t)
	cfg.Customer = true
	cfg.SandboxWorkspace = t.TempDir()
	cfg.Tools = []string{"query"}
	cfg.ToolTaxonomies = map[string]ToolTaxonomy{"query": {Operation: "read", Effect: "read-external"}}
	cfg.Descriptors = &DescriptorTarget{Platform: "tickets", Binding: testBinding, Operation: "live"}

	// Inject only the sandbox launcher and cleanup result. The actual MCP
	// conversation, capture, snapshot approval and acquisition still execute.
	saved := sandboxCommand
	t.Cleanup(func() { sandboxCommand = saved })
	var cleanupErr error
	cleanups := 0
	sandboxCommand = func(ctx context.Context, executable string, args []string, mode, workspace string) (*exec.Cmd, sandbox.Report, func() error, error) {
		return exec.CommandContext(ctx, executable, args...), sandbox.Report{Mode: mode, Backend: "test", State: "partial"}, func() error {
			cleanups++
			return cleanupErr
		}, nil
	}

	cleanupErr = errors.New("sandbox-cleanup-failed: injected restoration failure")
	out, err := Check(within(t), cfg)
	if err == nil || !strings.Contains(err.Error(), "sandbox-cleanup-failed:") || out != nil || cleanups != 1 {
		t.Fatalf("registration ignored cleanup failure: output=%s error=%v cleanups=%d", out, err, cleanups)
	}
	cleanupErr = nil
	out, err = Check(within(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw := readReport(t, out).Descriptors
	cfg.Descriptors = nil
	cfg.DescriptorSnapshot = filepath.Join(t.TempDir(), "approved.json")
	cfg.ApprovedPlatform, cfg.ApprovedBinding, cfg.ApprovedOperation = "tickets", testBinding, "live"
	writeApproval(t, &cfg, raw)
	cleanupErr = errors.New("sandbox-cleanup-failed: injected job termination failure")
	out, err = Acquire(within(t), cfg, query("select 1"))
	if err == nil || !strings.Contains(err.Error(), "sandbox-cleanup-failed:") || out != nil || cleanups != 3 {
		t.Fatalf("acquisition ignored cleanup failure: output=%s error=%v cleanups=%d", out, err, cleanups)
	}
	if !strings.Contains(strings.Join(methods(trace(t)), ","), "tools/call") {
		t.Fatal("failure did not follow an actual tool call")
	}
}
