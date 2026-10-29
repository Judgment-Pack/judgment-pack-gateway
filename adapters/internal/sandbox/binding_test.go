//go:build linux && (amd64 || arm64)

package sandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The child that reports whether it could connect to a Unix socket. No net
// package: it would link the C library into this test binary, and the
// loader-variable test needs a static one.
func init() {
	if len(os.Args) > 2 && os.Args[1] == "_sandbox_test_connect" {
		fmt.Println(dialUnix(os.Args[2]))
		os.Exit(0)
	}
}

// standInBubblewrap stands a launcher at the only fixed bubblewrap location
// and accepts it as trusted. It records each run in marker; exit is its status.
func standInBubblewrap(t *testing.T, exit string) (marker string) {
	t.Helper()
	dir := t.TempDir()
	marker = filepath.Join(t.TempDir(), "bwrap-ran")
	path := filepath.Join(dir, "bwrap")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho ran >> '"+marker+"'\nexit "+exit+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	savedL, savedT := bwrapLocations, launcherTrusted
	t.Cleanup(func() { bwrapLocations, launcherTrusted = savedL, savedT })
	bwrapLocations = []string{path}
	launcherTrusted = func(string) error { return nil }
	return marker
}

func landlockAvailable() bool {
	abi, _, errno := syscall.Syscall(444, 0, 0, 1) // landlock_create_ruleset: query ABI
	return errno == 0 && abi >= 3
}

// A launch bound to bubblewrap, the backend its posture reported, refuses
// when bubblewrap fails its start check at launch: it never falls back to
// Landlock, which restricts less.
func TestBubblewrapFailureAtLaunchRefusesWithoutFallback(t *testing.T) {
	marker := standInBubblewrap(t, "1")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd, report, cleanup, err := Command(ctx, Launch{Path: os.Args[0], Args: []string{"_sandbox_test_env"}, Env: os.Environ(), Backend: "bubblewrap"}, WorkspaceWrite, t.TempDir())
	cleanup()
	if cmd != nil || err == nil || !strings.Contains(err.Error(), "failed its start check; no other backend is used") || report.Backend == "landlock" {
		t.Fatalf("bound launch fell back: cmd=%v report=%+v err=%v", cmd, report, err)
	}
	if _, statErr := os.Stat(marker); statErr != nil {
		t.Fatal("the bound launcher was not tried")
	}
	// Unbound (a standalone run), the same failure selects Landlock, and the
	// report says so.
	if !landlockAvailable() {
		return
	}
	cmd, report, cleanup, err = Command(ctx, Launch{Path: os.Args[0], Args: []string{"_sandbox_test_env"}, Env: os.Environ()}, WorkspaceWrite, t.TempDir())
	defer cleanup()
	if err != nil || cmd == nil || report.Backend != "landlock" || report.State != "partial" {
		t.Fatalf("unbound launch: %+v %v", report, err)
	}
}

// A launch bound to Landlock does not try bubblewrap, even a usable one, and
// a launch bound to a backend this platform lacks refuses.
func TestBoundBackendIsTheOnlyOneUsed(t *testing.T) {
	marker := standInBubblewrap(t, "0")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if landlockAvailable() {
		cmd, report, cleanup, err := Command(ctx, Launch{Path: os.Args[0], Args: []string{"_sandbox_test_env"}, Env: os.Environ(), Backend: "landlock"}, WorkspaceWrite, t.TempDir())
		cleanup()
		if err != nil || cmd == nil || report.Backend != "landlock" {
			t.Fatalf("bound to landlock: %+v %v", report, err)
		}
		if _, statErr := os.Stat(marker); statErr == nil {
			t.Fatal("bubblewrap was tried for a launch bound to Landlock")
		}
	}
	for _, c := range []struct{ backend, mode string }{{"seatbelt", WorkspaceWrite}, {"none", ReadOnly}, {"bubblewrap", FullAccess}} {
		cmd, _, cleanup, err := Command(ctx, Launch{Path: os.Args[0], Args: []string{"_sandbox_test_env"}, Env: os.Environ(), Backend: c.backend}, c.mode, t.TempDir())
		cleanup()
		if cmd != nil || err == nil || !strings.Contains(err.Error(), "sandbox-not-enforced:") {
			t.Fatalf("bound to %s under %s: %v", c.backend, c.mode, err)
		}
	}
}

// listenSocket makes a listening Unix socket in a new short directory.
func listenSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "rs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "runtime.sock")
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: path}); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Listen(fd, 1); err != nil {
		t.Fatal(err)
	}
	resolved, _ := filepath.EvalSymlinks(path)
	return resolved
}

// dialUnix answers "connected" or "refused" for a Unix socket path.
func dialUnix(path string) string {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return "refused"
	}
	defer syscall.Close(fd)
	if syscall.Connect(fd, &syscall.SockaddrUnix{Name: path}) != nil {
		return "refused"
	}
	return "connected"
}

// Known container-runtime sockets are masked inside bubblewrap, unless the
// source is a runtime client; Landlock cannot mask them and its report names
// them.
func TestRuntimeSocketsMaskedOrReported(t *testing.T) {
	socket := listenSocket(t)
	saved := runtimeSocketPaths
	t.Cleanup(func() { runtimeSocketPaths = saved })
	runtimeSocketPaths = []string{socket}
	flags, masked, _ := bubblewrapFlags(Launch{Env: []string{"HOME=/nonexistent"}}, WorkspaceWrite, "/w", "/t")
	if !slices.Contains(masked, socket) || !strings.Contains(strings.Join(flags, " "), "--ro-bind /dev/null "+socket) {
		t.Fatalf("socket not masked: %v", flags)
	}
	if i, j := slices.Index(flags, socket), slices.Index(flags, "--bind"); i < 0 || j < 0 || i < j {
		t.Fatalf("socket masks must follow the writable binds: %v", flags)
	}
	flags, masked, _ = bubblewrapFlags(Launch{Env: []string{"HOME=/nonexistent"}, RuntimeSockets: true}, WorkspaceWrite, "/w", "/t")
	if len(masked) != 0 || slices.Contains(flags, socket) {
		t.Fatalf("a runtime client's socket was masked: %v", flags)
	}
	if !landlockAvailable() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, report, cleanup, err := Command(ctx, Launch{Path: os.Args[0], Args: []string{"_sandbox_test_env"}, Env: os.Environ(), Backend: "landlock"}, WorkspaceWrite, t.TempDir())
	cleanup()
	if err != nil || report.State != "partial" || !strings.Contains(report.Reason, socket) {
		t.Fatalf("landlock report hides a reachable runtime socket: %+v %v", report, err)
	}
}

// With a usable bubblewrap at a trusted location, a confined program cannot
// connect to a known runtime socket.
func TestRuntimeSocketUnreachableUnderBubblewrap(t *testing.T) {
	path, found, err := trustedLauncher(bwrapLocations)
	if err != nil || !found {
		t.Skip("no bubblewrap at a trusted location")
	}
	socket := listenSocket(t)
	saved := runtimeSocketPaths
	t.Cleanup(func() { runtimeSocketPaths = saved })
	runtimeSocketPaths = []string{socket}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd, report, cleanup, err := Command(ctx, Launch{Path: os.Args[0], Args: []string{"_sandbox_test_connect", socket}, Env: os.Environ(), Backend: "bubblewrap"}, WorkspaceWrite, t.TempDir())
	defer cleanup()
	if err != nil {
		t.Skipf("bubblewrap at %s is not usable here: %v", path, err)
	}
	raw, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(raw)) != "refused" || !strings.Contains(report.Reason, socket) {
		t.Fatalf("runtime socket inside bubblewrap: %s %v (%+v)", raw, err, report)
	}
}
