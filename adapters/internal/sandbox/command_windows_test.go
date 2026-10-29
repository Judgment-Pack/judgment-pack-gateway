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
	results["inside"] = os.WriteFile(filepath.Join(os.Args[2], "new"), []byte("changed"), 0600) == nil
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
	var text *uint16
	if err = winBool(winSDString, a.original, 1, winSecurityParts, uintptr(unsafe.Pointer(&text)), 0); err != nil {
		t.Fatal(err)
	}
	defer winFree(uintptr(unsafe.Pointer(text)))
	var units []uint16
	for i := uintptr(0); i < 65536; i++ {
		u := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(text)) + 2*i))
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	return syscall.UTF16ToString(units)
}

func TestWindowsRestrictedTokenBoundary(t *testing.T) {
	for _, mode := range []string{ReadOnly, WorkspaceWrite} {
		t.Run(mode, func(t *testing.T) {
			workspace, outside := t.TempDir(), filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
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
			if got["inside"] != (mode == WorkspaceWrite) {
				t.Fatalf("workspace permission: %v", got)
			}
			for _, name := range []string{"outside", "outside-acl", "parent-handles", "parent-token"} {
				if got[name] {
					t.Fatalf("boundary crossed: %s: %v", name, got)
				}
			}
			kept, err := os.ReadFile(outside)
			if err != nil || string(kept) != "original" {
				t.Fatal("outside file changed", err)
			}
			cleanup()
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
	cleanup()
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
	cleanup()
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
	secondCleanup()
	if err == nil || !strings.Contains(err.Error(), "workspace already in use") {
		t.Fatalf("overlapping ACL mutations: %v", err)
	}
	cleanup()
	_, _, thirdCleanup, err := Command(context.Background(), os.Args[0], nil, WorkspaceWrite, workspace)
	thirdCleanup()
	if err != nil {
		t.Fatalf("workspace lock not released: %v", err)
	}
}
