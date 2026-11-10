//go:build linux

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// envSecondMount names, to the copy of this test that runs in a namespace of
// its own, the directory that holds the store.
const envSecondMount = "JOURNAL_COMPACT_SECOND_MOUNT"

// secondMountUnavailable is what that copy prints where the host does not let
// it mount.
const secondMountUnavailable = "journal compact: no second mount here"

// A second mount of the store gives it another name that no link resolves: an
// archive inside the store under that name is still inside it. The mount is
// made in a user and mount namespace of the test's own, where the host allows
// one, so it is seen by nothing else and ends with the test.
func TestJournalCompactArchiveUnderASecondMount(t *testing.T) {
	if dir := os.Getenv(envSecondMount); dir != "" {
		store, other := filepath.Join(dir, "store"), filepath.Join(dir, "other")
		if err := syscall.Mount(store, other, "", syscall.MS_BIND, ""); err != nil {
			t.Log(secondMountUnavailable, err)
			return
		}
		archive := filepath.Join(other, "kept")
		code, stdout, stderr := compactRun("compact", "--store", store, "--archive", archive, "--retention", "1h")
		want := "journal compact: action-journal-archive: the archive " + archive + " is inside the store " + store + ", and it must be outside it: nothing was compacted\n"
		if code != 1 || stdout != "" || stderr != want {
			t.Fatalf("%d %q\n got %q\nwant %q", code, stdout, stderr, want)
		}
		return
	}
	dir, store, entry := handStore(t)
	mkdir(t, filepath.Join(dir, "other"), 0o700)
	mkdir(t, filepath.Join(store, "kept"), 0o700)
	before := treeOf(t, store)
	run := exec.Command(os.Args[0], "-test.run=^TestJournalCompactArchiveUnderASecondMount$", "-test.count=1", "-test.v")
	run.Env = append(os.Environ(), envSecondMount+"="+dir)
	run.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	out, err := run.CombinedOutput()
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOSPC) {
		t.Skipf("no user namespace here: %v", err)
	}
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(string(out), secondMountUnavailable) {
		t.Skipf("no second mount here:\n%s", out)
	}
	if !strings.Contains(string(out), "--- PASS: TestJournalCompactArchiveUnderASecondMount") {
		t.Fatalf("the copy in its namespace did not run the test:\n%s", out)
	}
	sameTree(t, "the store", treeOf(t, store), before)
	if _, err := os.Stat(filepath.Join(store, "actions", entry, "intent.json")); err != nil {
		t.Fatal(err)
	}
}
