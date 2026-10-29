package mcp

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"adapters/internal/fakemcp"
)

func TestWindowsCustomerSandboxUnavailable(t *testing.T) {
	cfg := fake(t)
	cfg.Customer = true
	cfg.SandboxWorkspace = t.TempDir()
	cfg.Tools = []string{"query"}
	cfg.ToolTaxonomies = map[string]ToolTaxonomy{"query": {Operation: "read", Effect: "read-external"}}
	cfg.Descriptors = &DescriptorTarget{Platform: "tickets", Binding: testBinding, Operation: "live"}
	// A refused registration returns no descriptor snapshot and starts no server.
	out, err := Check(within(t), cfg)
	if out != nil || err == nil || !strings.Contains(err.Error(), "sandbox-not-enforced:") {
		t.Fatalf("registration: %s %v", out, err)
	}
	if _, err := os.Stat(os.Getenv(fakemcp.EnvTrace)); !os.IsNotExist(err) {
		t.Fatal("refused registration started the executable", err)
	}

	// Establish an actual existing approval with explicitly selected full access.
	cfg.SandboxPolicy = filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(cfg.SandboxPolicy, []byte(`{"policyVersion":"1","defaultMode":"danger-full-access","sources":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	out, err = Check(within(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw := readReport(t, out).Descriptors
	if len(raw) == 0 {
		t.Fatal("explicit full access did not capture a snapshot")
	}
	cfg.Descriptors = nil
	cfg.DescriptorSnapshot = filepath.Join(t.TempDir(), "approved.json")
	cfg.ApprovedPlatform, cfg.ApprovedBinding, cfg.ApprovedOperation = "tickets", testBinding, "live"
	writeApproval(t, &cfg, raw)
	before, err := os.ReadFile(os.Getenv(fakemcp.EnvTrace))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"read-only", "workspace-write"} {
		if err := os.WriteFile(cfg.SandboxPolicy, []byte(`{"policyVersion":"1","defaultMode":"`+mode+`","sources":{}}`), 0600); err != nil {
			t.Fatal(err)
		}
		out, err = Acquire(within(t), cfg, query("select 1"))
		if out != nil || err == nil || !strings.Contains(err.Error(), "sandbox-not-enforced:") {
			t.Fatalf("approved acquisition %s: %s %v", mode, out, err)
		}
		after, err := os.ReadFile(os.Getenv(fakemcp.EnvTrace))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("refused acquisition started the executable", err)
		}
		kept, err := os.ReadFile(cfg.DescriptorSnapshot)
		if err != nil || !bytes.Equal(raw, kept) {
			t.Fatal("refusal modified existing approval", err)
		}
	}
}
