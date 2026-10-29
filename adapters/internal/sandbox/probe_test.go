package sandbox

import (
	"context"
	"runtime"
	"testing"
)

func TestPostureProbeExecutesRestrictedChild(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("no native backend")
	}
	for _, mode := range []string{ReadOnly, WorkspaceWrite} {
		r := Probe(context.Background(), mode, t.TempDir())
		if r.Mode != mode || (r.State != "enforced" && r.State != "partial") || r.Backend == "none" {
			t.Fatalf("native probe: %+v", r)
		}
	}
}

func TestPostureProbeDoesNotClaimUnrestrictedOrUnavailableProtection(t *testing.T) {
	for _, mode := range []string{FullAccess, "invalid", ReadOnly} {
		r := Probe(context.Background(), mode, "")
		if r.State != "not-enforced" || r.Reason == "" {
			t.Fatalf("false enforcement: %+v", r)
		}
	}
}
