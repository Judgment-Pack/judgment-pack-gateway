//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The source sandbox policy chooses every source's filesystem mode, so it is
// held as an adapter is: owned by root or the signer and writable by nobody
// else, on a way only they hold.
func TestSandboxPolicyFileIsHeld(t *testing.T) {
	host := engineHost{euid: os.Geteuid(), fileOwner: fileOwnerOf, readLink: os.Readlink}
	base, err := filepath.EvalSymlinks(tempDirAt(t, 0o755))
	if err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(base, "policy.json")
	if err := os.WriteFile(policy, []byte(`{"policyVersion":"1","defaultMode":"read-only","sources":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := holdSandboxPolicy(policy, host); err != nil {
		t.Fatalf("the signer's policy: %v", err)
	}
	if err := holdSandboxPolicy(filepath.Join(base, "absent.json"), host); err != nil {
		t.Fatalf("a policy not there is the helper's to refuse: %v", err)
	}
	if err := os.Chmod(policy, 0o620); err != nil {
		t.Fatal(err)
	}
	if err := holdSandboxPolicy(policy, host); err == nil || !strings.Contains(err.Error(), "is writable beyond its owner") {
		t.Fatalf("a group-writable policy: %v", err)
	}
	if err := os.Chmod(policy, 0o600); err != nil {
		t.Fatal(err)
	}
	other := host
	other.euid = os.Geteuid() + 1
	if os.Geteuid() != 0 {
		// Refused on its way or at the file: either is another user's.
		if err := holdSandboxPolicy(policy, other); err == nil || !strings.Contains(err.Error(), "neither root nor") {
			t.Fatalf("a policy another user owns: %v", err)
		}
	}
	// Through the start-up hold, beside the helper.
	spec := sourceSpec{argv: []string{hostAdapter(t)}, sandbox: &sourceSandbox{helper: hostAdapter(t), policy: policy}}
	if err := os.Chmod(policy, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := holdAdapterSources(map[string]sourceSpec{"a/live": spec}, host); err == nil || !strings.Contains(err.Error(), "sandbox policy:") {
		t.Fatalf("start-up accepted a writable policy: %v", err)
	}
}

// hostAdapter is an executable this host runs, in a directory only the
// signer may write, for the adapter hold.
func hostAdapter(t *testing.T) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(tempDirAt(t, 0o755))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, "adapter")
	if err := os.WriteFile(path, hostExecutable(), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}
