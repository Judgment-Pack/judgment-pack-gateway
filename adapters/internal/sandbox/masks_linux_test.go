//go:build linux && (amd64 || arm64)

package sandbox

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeSocketList replaces the kernel's socket list with lines naming the
// given listening paths and abstract names.
func fakeSocketList(t *testing.T, names ...string) {
	t.Helper()
	list := "Num       RefCount Protocol Flags    Type St Inode Path\n"
	for _, name := range names {
		list += "0000000000000000: 00000002 00000000 00010000 0001 01 1234 " + name + "\n"
	}
	// A connected (not listening) socket is no daemon's.
	list += "0000000000000000: 00000003 00000000 00000000 0001 03 1235 /not/listening.sock\n"
	path := filepath.Join(t.TempDir(), "unix")
	if err := os.WriteFile(path, []byte(list), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := procNetUnix
	t.Cleanup(func() { procNetUnix = saved })
	procNetUnix = path
}

// Every listening socket the server could reach is masked after the
// writable binds, a socket inside the workspace included, as is the socket
// a runtime host variable names; an abstract one, which no mask hides, or a
// list that cannot be read, leaves the launch partial.
func TestSocketMasksCoverListeningSocketsAfterBinds(t *testing.T) {
	saved := runtimeSocketPaths
	t.Cleanup(func() { runtimeSocketPaths = saved })
	runtimeSocketPaths = nil
	workspace := listenSocket(t)
	ws := filepath.Dir(workspace) // a listening socket inside the workspace
	daemon := listenSocket(t)     // another daemon's, at its own path
	hosted := listenSocket(t)     // the one DOCKER_HOST names, not in the list
	fakeSocketList(t, workspace, daemon)
	env := []string{"HOME=/nonexistent", "DOCKER_HOST=unix://" + hosted}
	flags, masked, open := bubblewrapFlags(Launch{Env: env}, WorkspaceWrite, ws, "/t")
	joined := strings.Join(flags, " ")
	// The socket a runtime host variable names is reported by name, the
	// others by count.
	if !slices.Contains(masked, hosted) || !slices.Contains(masked, "2 other listening sockets") {
		t.Fatalf("report of what was masked: %v", masked)
	}
	for _, socket := range []string{workspace, daemon, hosted} {
		if !strings.Contains(joined, "--ro-bind /dev/null "+socket) {
			t.Fatalf("%s not masked: %v", socket, flags)
		}
		if i, j := strings.Index(joined, "/dev/null "+socket), strings.Index(joined, "--bind "+ws); j < 0 || i < j {
			t.Fatalf("the mask of %s precedes the workspace bind: %v", socket, flags)
		}
	}
	if strings.Contains(joined, "/not/listening.sock") {
		t.Fatal("a socket that is not listening was masked")
	}
	if open != "" {
		t.Fatalf("nothing stays reachable, yet: %s", open)
	}
	fakeSocketList(t, workspace, "@abstract-daemon")
	if _, _, open := bubblewrapFlags(Launch{Env: env}, WorkspaceWrite, ws, "/t"); !strings.Contains(open, "abstract") {
		t.Fatalf("an abstract socket was not reported: %q", open)
	}
	procNetUnix = filepath.Join(t.TempDir(), "absent")
	if _, _, open := bubblewrapFlags(Launch{Env: env}, WorkspaceWrite, ws, "/t"); open == "" {
		t.Fatal("an unreadable socket list was taken for none")
	}
}

// What stays reachable makes a bubblewrap launch partial, never enforced.
func TestBubblewrapReportIsPartialWhileASocketStaysReachable(t *testing.T) {
	standInBubblewrap(t, "0")
	saved := runtimeSocketPaths
	t.Cleanup(func() { runtimeSocketPaths = saved })
	runtimeSocketPaths = nil
	for _, c := range []struct {
		list  []string
		state string
	}{{nil, "enforced"}, {[]string{"@abstract-daemon"}, "partial"}} {
		fakeSocketList(t, c.list...)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, report, cleanup, err := Command(ctx, Launch{Path: os.Args[0], Args: []string{"_sandbox_test_env"}, Env: []string{"HOME=/nonexistent"}, Backend: "bubblewrap"}, WorkspaceWrite, t.TempDir())
		cleanup()
		cancel()
		if err != nil || report.Backend != "bubblewrap" || report.State != c.state {
			t.Fatalf("sockets %v: %+v %v", c.list, report, err)
		}
		// Enforced is the filesystem write boundary; what stays reachable
		// over a socket is a stated limit, whatever the state.
		if !strings.Contains(report.Reason, SocketLimit) {
			t.Fatalf("the socket limit is not stated: %s", report.Reason)
		}
	}
}

// With a usable bubblewrap at a trusted location, a listening socket inside
// the workspace is unreachable too.
func TestWorkspaceSocketUnreachableUnderBubblewrap(t *testing.T) {
	if _, found, err := trustedLauncher(bwrapLocations); err != nil || !found {
		t.Skip("no bubblewrap at a trusted location")
	}
	socket := listenSocket(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd, report, cleanup, err := Command(ctx, Launch{Path: os.Args[0], Args: []string{"_sandbox_test_connect", socket}, Env: os.Environ(), Backend: "bubblewrap"}, WorkspaceWrite, filepath.Dir(socket))
	defer cleanup()
	if err != nil {
		t.Skipf("bubblewrap is not usable here: %v", err)
	}
	raw, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(raw)) != "refused" {
		t.Fatalf("a workspace socket inside bubblewrap: %s %v (%+v)", raw, err, report)
	}
}

// Under Landlock a confined program may write to /dev/null, and its private
// temporary directory is named by its resolved path.
func TestLandlockAllowsDevNullAndResolvesTemp(t *testing.T) {
	if !landlockAvailable() {
		t.Skip("Landlock unavailable")
	}
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "tmp-link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", link)
	for _, mode := range []string{ReadOnly, WorkspaceWrite} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd, report, cleanup, err := Command(ctx, Launch{Path: os.Args[0], Args: []string{"_sandbox_test_write", os.DevNull}, Env: os.Environ(), Backend: "landlock"}, mode, t.TempDir())
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		raw, err := cmd.Output()
		cleanup()
		cancel()
		var got []bool
		if err != nil || json.Unmarshal(raw, &got) != nil || len(got) != 1 || !got[0] {
			t.Fatalf("%s: /dev/null write under %s: %s %v", mode, report.Backend, raw, err)
		}
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		cmd, _, cleanup, err = Command(ctx, Launch{Path: os.Args[0], Args: []string{"_sandbox_test_env"}, Env: os.Environ(), Backend: "landlock"}, mode, t.TempDir())
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		raw, err = cmd.Output()
		cleanup()
		cancel()
		var env map[string]string
		if err != nil || json.Unmarshal(raw, &env) != nil || !strings.HasPrefix(env["tmpdir"], real+string(filepath.Separator)) {
			t.Fatalf("%s: TMPDIR %q is not below the resolved %s: %v", mode, env["tmpdir"], real, err)
		}
	}
}

// The server's environment, credentials included, travels in a sealed
// memory file, never a file on a disk.
func TestServerEnvironmentIsASealedMemoryFile(t *testing.T) {
	f, err := envFile(t.TempDir(), []string{"SECRET=value"})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	target, _ := os.Readlink(descriptorPath(int(f.Fd())))
	if !Sealed(f) || !strings.HasPrefix(target, "/memfd:") {
		t.Fatalf("the environment is in %q (sealed: %v)", target, Sealed(f))
	}
	env, err := readEnv(dupFd(t, f))
	if err != nil || len(env) != 1 || env[0] != "SECRET=value" {
		t.Fatalf("read back %v %v", env, err)
	}
}

// With a usable bubblewrap at a trusted location, a binary runs as the
// sealed bytes that were digested, from bubblewrap's read-only copy of them,
// never through the memory file itself and never by its path.
func TestSealedCopyRunsUnderBubblewrap(t *testing.T) {
	if _, found, err := trustedLauncher(bwrapLocations); err != nil || !found {
		t.Skip("no bubblewrap at a trusted location")
	}
	for _, mode := range []string{ReadOnly, WorkspaceWrite} {
		path := filepath.Join(t.TempDir(), "server")
		copyFile(t, os.Args[0], path)
		original, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := SealedCopy(original, "server")
		original.Close()
		if err != nil {
			t.Fatal(err)
		}
		// Another program written over the same file after the digest.
		if err := os.WriteFile(path, []byte("#!/bin/sh\necho '{\"program\":\"replacement\"}'\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd, report, cleanup, err := Command(ctx, Launch{Path: path, File: sealed, Argv0: "configured", Args: []string{"_sandbox_test_env"}, Env: os.Environ(), Backend: "bubblewrap"}, mode, t.TempDir())
		if err != nil {
			cancel()
			t.Skipf("bubblewrap is not usable here: %v", err)
		}
		if slices.Contains(cmd.Args, path) || slices.Contains(cmd.Args, descriptorPath(4)) {
			t.Fatalf("bubblewrap is told to run the path or the memory file: %v", cmd.Args)
		}
		raw, err := cmd.CombinedOutput()
		cleanup()
		cancel()
		sealed.Close()
		var got map[string]string
		if err != nil || json.Unmarshal(raw, &got) != nil || got["program"] != "test binary" || !report.ExecutesDigestedFile() {
			t.Fatalf("%s: the sealed bytes did not run under bubblewrap: %s %v (exact %v)", mode, raw, err, report.ExecutesDigestedFile())
		}
	}
}
