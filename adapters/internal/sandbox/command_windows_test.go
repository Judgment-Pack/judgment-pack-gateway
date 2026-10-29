package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func init() {
	if len(os.Args) > 1 && os.Args[1] == "_sandbox_windows_sleep" {
		time.Sleep(90 * time.Second)
		os.Exit(0)
	}
	if len(os.Args) > 1 && os.Args[1] == "_sandbox_windows_descendant" {
		child := exec.Command(os.Args[0], "_sandbox_windows_sleep")
		if err := child.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(child.Process.Pid)
		os.Exit(0)
	}
	if len(os.Args) < 2 || os.Args[1] != "_sandbox_windows_probe" {
		return
	}
	parent, _ := strconv.ParseUint(os.Args[4], 10, 32)
	results := map[string]bool{}
	station, _, _ := winUser.NewProc("GetProcessWindowStation").Call()
	thread, _, _ := winKernel.NewProc("GetCurrentThreadId").Call()
	desktop, _, _ := winUser.NewProc("GetThreadDesktop").Call(thread)
	objectName := func(handle uintptr) string {
		var buffer [256]uint16
		var needed uint32
		if err := winBool(winUser.NewProc("GetUserObjectInformationW"), handle, 2, uintptr(unsafe.Pointer(&buffer[0])), unsafe.Sizeof(buffer), uintptr(unsafe.Pointer(&needed))); err != nil {
			return ""
		}
		return syscall.UTF16ToString(buffer[:])
	}
	results["private-station"] = strings.HasPrefix(objectName(station), "gateway-S-1-5-21-")
	results["private-desktop"] = objectName(desktop) == "source"
	results["inside"] = os.WriteFile(filepath.Join(os.Args[2], "new"), []byte("changed"), 0600) == nil
	results["existing"] = os.WriteFile(filepath.Join(os.Args[2], "existing"), []byte("changed"), 0600) == nil
	results["move-outside"] = os.Rename(filepath.Join(os.Args[2], "existing"), filepath.Join(filepath.Dir(os.Args[3]), "escaped")) == nil
	results["rename-inside"] = os.Rename(filepath.Join(os.Args[2], "existing"), filepath.Join(os.Args[2], "renamed")) == nil
	results["outside"] = os.WriteFile(os.Args[3], []byte("changed"), 0600) == nil
	name, _ := syscall.UTF16PtrFromString(os.Args[3])
	h, err := syscall.CreateFile(name, 0x40000, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, 0, 0)
	results["outside-acl"] = err == nil
	if err == nil {
		syscall.CloseHandle(h)
	}
	process, err := syscall.OpenProcess(0x40, false, uint32(parent))
	results["parent-handles"] = err == nil
	if err == nil {
		syscall.CloseHandle(process)
	}
	process, err = syscall.OpenProcess(0x1000, false, uint32(parent))
	if err == nil {
		var token syscall.Token
		err = syscall.OpenProcessToken(process, syscall.TOKEN_DUPLICATE, &token)
		results["parent-token"] = err == nil
		if err == nil {
			token.Close()
		}
		syscall.CloseHandle(process)
	}
	json.NewEncoder(os.Stdout).Encode(results)
	os.Exit(0)
}

func aclString(t *testing.T, path string) string {
	t.Helper()
	a, err := holdWindowsACL(path)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(a.handle)
	defer winFree(a.original)
	state, err := windowsSecurityState(a.original)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// Distinguish a native handle failure from token and job failures, without
// changing the ACL or relying on a path-based reopen in production.
func TestWindowsSecurityHandleReopen(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ kind, path string }{{"directory", dir}, {"file", file}} {
		t.Run(item.kind, func(t *testing.T) {
			a, err := holdWindowsFile(item.path)
			if err != nil {
				t.Fatal(err)
			}
			defer syscall.CloseHandle(a.handle)
			for _, access := range []uintptr{0x020e0080, 0x02000000, 0xe0080} {
				for _, flags := range []uintptr{0x02200000, 0x02000000} {
					h, _, callErr := winReopenFile.Call(uintptr(a.handle), access, 7, flags)
					if syscall.Handle(h) != syscall.InvalidHandle {
						syscall.CloseHandle(syscall.Handle(h))
						t.Logf("access=%x flags=%x: success", access, flags)
					} else {
						t.Logf("access=%x flags=%x: %v", access, flags, callErr)
						if access == 0x020e0080 && flags == 0x02200000 {
							t.Error("production security handle cannot be reopened")
						}
					}
				}
			}
		})
	}
}

func TestWindowsRestrictedTokenBoundary(t *testing.T) {
	for _, mode := range []string{ReadOnly, WorkspaceWrite} {
		t.Run(mode, func(t *testing.T) {
			workspace, outside := t.TempDir(), filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(workspace, "existing"), []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			fileBefore := aclString(t, filepath.Join(workspace, "existing"))
			before := aclString(t, workspace)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd, report, cleanup, err := Command(ctx, os.Args[0], []string{"_sandbox_windows_probe", workspace, outside, strconv.Itoa(os.Getpid())}, mode, workspace)
			defer cleanup()
			if err != nil {
				t.Fatalf("prepare: %v", err)
			}
			if report.Backend != "windows-restricted-token" || report.State != "partial" {
				t.Fatalf("report: %+v", report)
			}
			raw, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("restricted child: %v: %s", err, raw)
			}
			var got map[string]bool
			if err = json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err, string(raw))
			}
			if !got["private-station"] || !got["private-desktop"] {
				t.Fatalf("restricted child did not inherit private desktop: %v", got)
			}
			if got["inside"] != (mode == WorkspaceWrite) || got["existing"] != (mode == WorkspaceWrite) || got["rename-inside"] != (mode == WorkspaceWrite) {
				t.Fatalf("workspace permission: %v", got)
			}
			for _, name := range []string{"outside", "outside-acl", "parent-handles", "parent-token", "move-outside"} {
				if got[name] {
					t.Fatalf("boundary crossed: %s: %v", name, got)
				}
			}
			kept, err := os.ReadFile(outside)
			if err != nil || string(kept) != "original" {
				t.Fatal("outside file changed", err)
			}
			if err := cleanup(); err != nil {
				t.Fatal(err)
			}
			fileName := "existing"
			if mode == WorkspaceWrite {
				fileName = "renamed"
			}
			if after := aclString(t, filepath.Join(workspace, fileName)); after != fileBefore {
				t.Fatalf("held file ACL not restored: before %s; after %s", fileBefore, after)
			}
			if after := aclString(t, workspace); after != before {
				t.Fatalf("workspace ACL not restored:\nbefore %s\nafter %s", before, after)
			}
		})
	}
}

func TestWindowsRejectsMultiplyLinkedWorkspaceFile(t *testing.T) {
	workspace := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(workspace, "link")); err != nil {
		t.Fatal(err)
	}
	before := aclString(t, workspace)
	_, _, cleanup, err := Command(context.Background(), os.Args[0], nil, WorkspaceWrite, workspace)
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	if err == nil || !strings.Contains(err.Error(), "multiply-linked") {
		t.Fatalf("expected named refusal, got %v", err)
	}
	if after := aclString(t, workspace); after != before {
		t.Fatal("refused tree's ACL changed")
	}
}

func TestWindowsJobKillsDescendantsBeforeCleanup(t *testing.T) {
	workspace := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd, _, cleanup, err := Command(ctx, os.Args[0], []string{"_sandbox_windows_descendant"}, WorkspaceWrite, workspace)
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("start descendant: %v: %s", err, raw)
	}
	pid, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 32)
	if err != nil {
		t.Fatal(err, string(raw))
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	process, err := syscall.OpenProcess(syscall.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return
	}
	defer syscall.CloseHandle(process)
	state, err := syscall.WaitForSingleObject(process, 0)
	if err != nil || state != 0 {
		t.Fatal(fmt.Sprintf("descendant survives: pid=%d state=%d error=%v", pid, state, err))
	}
}

func TestWindowsOverlappingWorkspacePreparationRefuses(t *testing.T) {
	workspace := t.TempDir()
	_, _, cleanup, err := Command(context.Background(), os.Args[0], nil, WorkspaceWrite, workspace)
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	_, _, secondCleanup, err := Command(context.Background(), os.Args[0], nil, WorkspaceWrite, workspace)
	if err := secondCleanup(); err != nil {
		t.Fatal(err)
	}
	if err == nil || !strings.Contains(err.Error(), "workspace already in use") {
		t.Fatalf("overlapping ACL mutations: %v", err)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	_, _, thirdCleanup, err := Command(context.Background(), os.Args[0], nil, WorkspaceWrite, workspace)
	if err := thirdCleanup(); err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatalf("workspace lock not released: %v", err)
	}
}

// Complete the first run precisely while the second is acquiring exclusion.
// Capturing the first run's temporary descriptor before this point would restore
// that stale descriptor after the second run and fail the final comparison.
func TestWindowsWorkspaceSnapshotFollowsExclusion(t *testing.T) {
	workspace := t.TempDir()
	before := aclString(t, workspace)
	_, _, firstCleanup, err := Command(context.Background(), os.Args[0], nil, WorkspaceWrite, workspace)
	defer firstCleanup()
	if err != nil {
		t.Fatal(err)
	}
	saved := lockWindowsWorkspace
	t.Cleanup(func() { lockWindowsWorkspace = saved })
	lockWindowsWorkspace = func(handle syscall.Handle) (syscall.Handle, error) {
		if err := firstCleanup(); err != nil {
			return 0, err
		}
		return saved(handle)
	}
	_, _, secondCleanup, err := Command(context.Background(), os.Args[0], nil, WorkspaceWrite, workspace)
	defer secondCleanup()
	if err != nil {
		t.Fatal(err)
	}
	if err = secondCleanup(); err != nil {
		t.Fatal(err)
	}
	if after := aclString(t, workspace); after != before {
		t.Fatalf("stale workspace ACL restored: before %s; after %s", before, after)
	}
}

func TestWindowsCleanupFailureIsReturnedAndStable(t *testing.T) {
	// An invalid job handle deterministically fails before restoration. No real
	// process is started; the failure must stay visible to repeated callers.
	r := &winResources{job: syscall.InvalidHandle}
	for i := 0; i < 2; i++ {
		if err := r.cleanup(); err == nil || !strings.Contains(err.Error(), "sandbox-cleanup-failed:") {
			t.Fatalf("cleanup failure lost: %v", err)
		}
	}
}

func TestWindowsDifferentWorkspaceWritersAlsoExclude(t *testing.T) {
	_, _, cleanup, err := Command(context.Background(), os.Args[0], nil, WorkspaceWrite, t.TempDir())
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	_, _, secondCleanup, err := Command(context.Background(), os.Args[0], nil, WorkspaceWrite, t.TempDir())
	defer secondCleanup()
	if err == nil || !strings.Contains(err.Error(), "workspace already in use") {
		t.Fatalf("overlapping restricted writers: %v", err)
	}
}
