//go:build unix

package program

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// startedChild writes a stand-in program that starts a child of its own,
// which writes its PID and waits; the program reads its stdin, waits until
// that PID is written, and then does what rest says. The child is ended at
// the test's end whatever happened.
func startedChild(t *testing.T, rest string) (program, pidFile string) {
	t.Helper()
	dir := t.TempDir()
	pidFile = filepath.Join(dir, "child")
	program = filepath.Join(dir, "spawns")
	body := "#!/bin/sh\n/bin/sh -c 'echo $$ > " + pidFile + "; exec /bin/sleep 300' </dev/null >/dev/null 2>&1 &\n/bin/cat >/dev/null\nwhile [ ! -s " + pidFile + " ]; do :; done\n" + rest
	if err := os.WriteFile(program, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if pid := childPID(pidFile); pid > 0 {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	return program, pidFile
}

func childPID(pidFile string) int {
	raw, _ := os.ReadFile(pidFile)
	pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	return pid
}

// childEnded waits a little for the child to have been started and then
// reports whether it has ended.
func childEnded(t *testing.T, pidFile string) bool {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for childPID(pidFile) == 0 && time.Now().Before(until) {
		time.Sleep(10 * time.Millisecond)
	}
	pid := childPID(pidFile)
	if pid == 0 {
		t.Fatal("the stand-in's child did not start")
	}
	for time.Now().Before(until) {
		if syscall.Kill(pid, 0) != nil {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// A group run ends what the program started, whether the program is ended at
// the deadline or finishes on its own.
func TestAGroupRunEndsWhatTheProgramStarted(t *testing.T) {
	program, pidFile := startedChild(t, "exec /bin/sleep 300\n")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, _, err := (Run{Program: program, Stdin: []byte("doc"), MaxOutput: 1024, Group: true}).Do(ctx); err != ErrTimeout {
		t.Fatal("the run did not end at its deadline", err)
	}
	if !childEnded(t, pidFile) {
		t.Fatal("a child of a program ended at its deadline outlived the run")
	}
	finished, finishedPID := startedChild(t, "printf done\n")
	if out, _, err := (Run{Program: finished, Stdin: []byte("doc"), MaxOutput: 1024, Group: true}).Do(context.Background()); err != nil || string(out) != "done" {
		t.Fatal(string(out), err)
	}
	if !childEnded(t, finishedPID) {
		t.Fatal("a child of a program that finished outlived the run")
	}
}
