package sandbox

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

func TestPostureProbeReportsActualBackend(t *testing.T) {
	for _, mode := range []string{ReadOnly, WorkspaceWrite} {
		r := Probe(context.Background(), mode, t.TempDir(), false)
		if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
			if r.Mode != mode || r.State != "not-enforced" || r.Backend != "none" || r.Reason == "" {
				t.Fatalf("unavailable backend claims protection: %+v", r)
			}
			if runtime.GOOS == "windows" && !strings.Contains(r.Reason, "Windows") {
				t.Fatalf("missing platform-specific refusal reason: %+v", r)
			}
			continue
		}
		if r.Mode != mode || (r.State != "enforced" && r.State != "partial") || r.Backend == "none" {
			t.Fatalf("native probe: %+v", r)
		}
	}
}

func TestPostureProbeDoesNotClaimUnrestrictedOrUnavailableProtection(t *testing.T) {
	for _, mode := range []string{FullAccess, "invalid", ReadOnly} {
		r := Probe(context.Background(), mode, "", false)
		if r.State != "not-enforced" || r.Reason == "" {
			t.Fatalf("false enforcement: %+v", r)
		}
	}
}
