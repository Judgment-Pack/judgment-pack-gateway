package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The launcher -- bubblewrap or the Landlock helper on Linux, sandbox-exec
// on macOS -- starts with the fixed launcher environment, so a loader
// variable among the server's variables cannot act on it before anything is
// confined; the server still receives its whole environment, with the
// private temporary directory last.
func TestLoaderVariableCannotReachTheLauncher(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("no backend implemented on this platform")
	}
	for _, mode := range []string{ReadOnly, WorkspaceWrite} {
		t.Run(mode, func(t *testing.T) {
			workspace, outside := t.TempDir(), t.TempDir()
			// A dynamically linked launcher that honoured these would write
			// its loader trace outside the workspace before confinement; a
			// confined server cannot write there.
			trace := filepath.Join(outside, "loader-trace")
			env := append(os.Environ(), "SANDBOX_TEST_SENTINEL=delivered", "TMPDIR=/replaced",
				"LD_DEBUG=files", "LD_DEBUG_OUTPUT="+trace, "DYLD_PRINT_LIBRARIES=1", "DYLD_PRINT_TO_FILE="+trace)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd, report, cleanup, err := Command(ctx, Launch{Path: os.Args[0], Args: []string{"_sandbox_test_env"}, Env: env}, mode, workspace)
			defer cleanup()
			if err != nil {
				t.Fatalf("sandbox setup: %v (%+v)", err, report)
			}
			t.Logf("backend %s", report.Backend)
			if cmd.Env == nil || len(cmd.Env) != 0 {
				t.Fatalf("the launcher inherits an environment of %d variables", len(cmd.Env))
			}
			raw, err := cmd.Output()
			if err != nil {
				t.Fatalf("sandbox child: %v: %s", err, raw)
			}
			var got map[string]string
			if json.Unmarshal(raw, &got) != nil {
				t.Fatalf("child output: %s", raw)
			}
			if got["sentinel"] != "delivered" {
				t.Fatal("the server's environment did not reach the server")
			}
			if got["tmpdir"] == "/replaced" || !strings.HasPrefix(filepath.Base(got["tmpdir"]), "gateway-source-") {
				t.Fatalf("the private temporary directory was replaced: %q", got["tmpdir"])
			}
			if matches, _ := filepath.Glob(trace + "*"); len(matches) != 0 {
				t.Fatalf("a loader variable acted outside the sandbox: %v", matches)
			}
		})
	}
}

// On Linux what runs is the sealed copy of the bytes that were digested: a
// file put in place at the path after the digest, or the same file rewritten
// in place (same inode), is not what runs, under every mode and backend. An
// unsealed descriptor is executed too, but is not reported as the digested
// bytes, so the caller re-checks it.
func TestDigestedDescriptorIsWhatRuns(t *testing.T) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("a sealed copy is Linux's; elsewhere the caller re-checks the digest")
	}
	replacement := []byte("#!/bin/sh\necho '{\"program\":\"replacement\"}'\n")
	for _, mode := range []string{ReadOnly, WorkspaceWrite, FullAccess} {
		for _, inPlace := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/in-place=%v", mode, inPlace), func(t *testing.T) {
				dir, workspace := t.TempDir(), t.TempDir()
				path := filepath.Join(dir, "server")
				copyFile(t, os.Args[0], path)
				original, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer original.Close()
				file, err := SealedCopy(original, "server")
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				// After the digest: another program at the same path, put
				// in place or written over the same file.
				if inPlace {
					w, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
					if err != nil {
						t.Fatal(err)
					}
					w.Write(replacement)
					w.Close()
				} else {
					next := path + ".next"
					if err := os.WriteFile(next, replacement, 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(next, path); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				cmd, report, cleanup, err := Command(ctx, Launch{Path: path, File: file, Args: []string{"_sandbox_test_env"}, Env: os.Environ()}, mode, workspace)
				defer cleanup()
				if err != nil {
					t.Fatalf("sandbox setup: %v (%+v)", err, report)
				}
				t.Logf("backend %s", report.Backend)
				raw, err := cmd.Output()
				if err != nil {
					t.Fatalf("sandbox child: %v: %s", err, raw)
				}
				var got map[string]string
				if json.Unmarshal(raw, &got) != nil || got["program"] != "test binary" || !report.ExecutesDigestedFile() {
					t.Fatalf("the digested bytes did not run: %s (exact: %v)", raw, report.ExecutesDigestedFile())
				}
			})
		}
	}
	// An unsealed descriptor names an inode, whose bytes a writer can change.
	path := filepath.Join(t.TempDir(), "server")
	copyFile(t, os.Args[0], path)
	plain, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	_, report, cleanup, err := Command(context.Background(), Launch{Path: path, File: plain, Args: []string{"_sandbox_test_env"}, Env: os.Environ()}, FullAccess, t.TempDir())
	cleanup()
	if err != nil || report.ExecutesDigestedFile() {
		t.Fatalf("an unsealed descriptor was reported as the digested bytes: %v", err)
	}
}

// A sealed copy holds exactly what was copied and refuses every change.
func TestSealedCopyRefusesChange(t *testing.T) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("a sealed copy is Linux's")
	}
	src := filepath.Join(t.TempDir(), "src")
	if err := os.WriteFile(src, []byte("approved bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sealed, err := SealedCopy(f, "src")
	if err != nil {
		t.Fatal(err)
	}
	defer sealed.Close()
	if !Sealed(sealed) || Sealed(f) {
		t.Fatal("seals misreported")
	}
	if w, err := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", sealed.Fd()), os.O_WRONLY, 0); err == nil {
		_, werr := w.Write([]byte("other"))
		w.Close()
		if werr == nil {
			t.Fatal("a sealed copy was written")
		}
	}
	data, err := io.ReadAll(sealed)
	if err != nil || string(data) != "approved bytes" {
		t.Fatalf("copy holds %q, %v", data, err)
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o755); err != nil {
		t.Fatal(err)
	}
}
