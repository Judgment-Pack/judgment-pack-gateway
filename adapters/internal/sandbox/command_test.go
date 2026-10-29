package sandbox

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "_sandbox_test_write" {
		results := []bool{}
		for _, path := range os.Args[2:] {
			results = append(results, os.WriteFile(path, []byte("changed"), 0600) == nil)
		}
		json.NewEncoder(os.Stdout).Encode(results)
		os.Exit(0)
	}
	if len(os.Args) > 1 && os.Args[1] == "_sandbox_test_env" {
		json.NewEncoder(os.Stdout).Encode(map[string]string{"program": "test binary", "sentinel": os.Getenv("SANDBOX_TEST_SENTINEL"), "tmpdir": os.Getenv("TMPDIR")})
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestFilesystemPolicyAtTheChildProcess(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("no backend implemented on this platform")
	}
	for _, mode := range []string{ReadOnly, WorkspaceWrite, FullAccess} {
		t.Run(mode, func(t *testing.T) {
			workspace, outside := t.TempDir(), t.TempDir()
			out := filepath.Join(outside, "existing")
			if err := os.WriteFile(out, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(workspace, "escape")
			if err := os.Symlink(out, link); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd, report, cleanup, err := Command(ctx, Launch{Path: os.Args[0], Args: []string{"_sandbox_test_write", filepath.Join(workspace, "new"), out, link}, Env: os.Environ()}, mode, workspace)
			defer cleanup()
			if err != nil {
				t.Fatalf("sandbox setup: %v (%+v)", err, report)
			}
			raw, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("sandbox child: %v: %s", err, raw)
			}
			var got []bool
			if json.Unmarshal(raw, &got) != nil || len(got) != 3 {
				t.Fatalf("child results: %s", raw)
			}
			wantInside, wantOutside := mode != ReadOnly, mode == FullAccess
			if got[0] != wantInside || got[1] != wantOutside || got[2] != wantOutside {
				t.Fatalf("write permissions: %v; want inside=%v outside=%v symlink=%v", got, wantInside, wantOutside, wantOutside)
			}
			if mode != FullAccess {
				kept, _ := os.ReadFile(out)
				if string(kept) != "original" {
					t.Fatal("sandbox changed an existing outside file")
				}
			}
			if report.Backend == "landlock" && report.State != "partial" {
				t.Fatal("Landlock metadata limitation must be reported")
			}
		})
	}
}

func TestPolicyDefaultsAndStrictOverrides(t *testing.T) {
	if mode, err := Mode("", "customer/live"); err != nil || mode != WorkspaceWrite {
		t.Fatal(mode, err)
	}
	for _, tc := range []struct{ raw, want string }{
		{`{"policyVersion":"1","defaultMode":"read-only","sources":{"customer/live":"workspace-write"}}`, WorkspaceWrite},
		{`{"policyVersion":"1","defaultMode":"danger-full-access","sources":{}}`, FullAccess},
		{`{"policyVersion":"1","defaultMode":"read-only","sources":{}}`, ReadOnly},
		{`{"policyVersion":"1","defaultMode":"work","sources":{}}`, ""},
		{`{"policyVersion":"1","defaultMode":"read-only","defaultMode":"danger-full-access"}`, ""},
		{`{"policyVersion":"1","defaultMode":"read-only","SOURCES":{}}`, ""},
		{`{"policyVersion":"1","defaultMode":"read-only","sources":{"other":"bad"}}`, ""},
	} {
		file := filepath.Join(t.TempDir(), "policy.json")
		if err := os.WriteFile(file, []byte(tc.raw), 0600); err != nil {
			t.Fatal(err)
		}
		mode, err := Mode(file, "customer/live")
		if (err == nil) != (tc.want != "") || mode != tc.want {
			t.Fatalf("policy %s: %q %v", tc.raw, mode, err)
		}
	}
}

func TestPolicyHomeCannotBeInSourceWorkspace(t *testing.T) {
	workspace := t.TempDir()
	policy := filepath.Join(workspace, "policy.json")
	if err := os.WriteFile(policy, []byte(`{"policyVersion":"1","defaultMode":"danger-full-access","sources":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ModeForWorkspace(policy, "source/live", workspace); err == nil {
		t.Fatal("source-writable policy accepted")
	}
	outside := t.TempDir()
	link := filepath.Join(outside, "policy.json")
	if err := os.Symlink(policy, link); err != nil {
		t.Skip("symlink unavailable")
	}
	if _, err := ModeForWorkspace(link, "source/live", workspace); err == nil {
		t.Fatal("policy symlink into source workspace accepted")
	}
	if mode, err := ModeForWorkspace(policy, "source/live", outside); err != nil || mode != FullAccess {
		t.Fatal(mode, err)
	}
}
