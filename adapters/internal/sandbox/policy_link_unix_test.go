//go:build !windows

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A policy path that runs through a link the confined source could re-point
// refuses, even while the link leads outside the workspace: at the policy's
// own name inside the workspace, or as a directory on the way.
func TestPolicyPathThroughAWorkspaceLinkRefuses(t *testing.T) {
	workspace, outside := t.TempDir(), t.TempDir()
	policy := filepath.Join(outside, "policy.json")
	if err := os.WriteFile(policy, []byte(`{"policyVersion":"1","defaultMode":"read-only","sources":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if mode, err := ModeForWorkspace(policy, "source/live", workspace); err != nil || mode != ReadOnly {
		t.Fatalf("a policy outside: %q %v", mode, err)
	}
	// The policy's own name is a link in the workspace (P2).
	inside := filepath.Join(workspace, "policy.json")
	if err := os.Symlink(policy, inside); err != nil {
		t.Fatal(err)
	}
	// A directory on the way is a link in the workspace.
	if err := os.Symlink(outside, filepath.Join(workspace, "etc")); err != nil {
		t.Fatal(err)
	}
	hop := filepath.Join(t.TempDir(), "conf")
	if err := os.Symlink(filepath.Join(workspace, "etc"), hop); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{inside, filepath.Join(hop, "policy.json")} {
		if _, err := ModeForWorkspace(path, "source/live", workspace); err == nil || !strings.Contains(err.Error(), "passes through a link inside the source workspace") {
			t.Fatalf("%s: %v", path, err)
		}
	}
}
