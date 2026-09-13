//go:build linux

package mcp

import (
	"context"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"adapters/internal/fakemcp"
)

// A command server that leaves a descendant behind -- holding the
// credentials in its environment -- does not keep it past the check: the
// server's whole process group is killed when it is stopped.
func TestStoppingACommandReachesItsDescendants(t *testing.T) {
	cfg := fake(t)
	t.Setenv(fakemcp.EnvHoldStdin, "1")
	if _, err := Check(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(os.Getenv(fakemcp.EnvHolderPid))
	if err != nil {
		t.Fatalf("the stand-in left no descendant to reach: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	// Gone, and reaped: the stop rescans until no descendant is alive
	// and reaps the ones it adopted, so nothing of it is left in /proc.
	if stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); err == nil {
		t.Fatalf("the descendant %d survived the check with the credentials, or was left unreaped: %s", pid, stat)
	}
	_ = time.Second
}

// A command server stays in the adapter's own process group -- under the
// gateway, the source group's kill reaches it -- and what it leaves behind
// is reached at stop through the adapter's adoption of orphans.
func TestACommandServerStaysInTheAdaptersGroup(t *testing.T) {
	cfg := fake(t)
	if _, err := Check(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	own := syscall.Getpgrp()
	found := false
	for _, m := range trace(t) {
		if pgid, ok := m["pgid"].(float64); ok {
			found = true
			if int(pgid) != own {
				t.Fatalf("the server ran in group %d, not the adapter's %d", int(pgid), own)
			}
		}
	}
	if !found {
		t.Fatal("the stand-in recorded no process group")
	}
}

// A descendant that forks and exits at once leaves a grandchild whose
// parent is gone: adopted here, it is found and reached all the same.
func TestStoppingACommandReachesAGrandchildWhoseParentIsGone(t *testing.T) {
	cfg := fake(t)
	t.Setenv(fakemcp.EnvHoldStdin, "1")
	t.Setenv(fakemcp.EnvHoldFork, "1")
	if _, err := Check(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(os.Getenv(fakemcp.EnvHolderPid))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("a holder and its child were started: %q", lines)
	}
	for _, line := range lines {
		pid, err := strconv.Atoi(line)
		if err != nil {
			t.Fatal(err)
		}
		if stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); err == nil {
			t.Fatalf("%d survived the check with the credentials, or was left unreaped: %s", pid, stat)
		}
	}
}

// The stop is done only after two quiet scans in a row: a scan that
// reaped something, or found something alive, starts the count over.
func TestStoppingWaitsForTwoQuietScans(t *testing.T) {
	sequence := []struct {
		live   []int
		reaped int
	}{
		{nil, 0},       // quiet once
		{nil, 1},       // a zombie reaped: not quiet
		{[]int{42}, 0}, // a descendant revealed
		{nil, 0},       // quiet once
		{nil, 0},       // quiet twice: done
		{[]int{43}, 0}, // never reached
	}
	scans := 0
	var killed []int
	scan := func() ([]int, int, error) {
		step := sequence[scans]
		scans++
		return step.live, step.reaped, nil
	}
	if err := stopDescendants(scan, func(pid int) { killed = append(killed, pid) }, time.Second); err != nil {
		t.Fatal(err)
	}
	if scans != 5 || len(killed) != 1 || killed[0] != 42 {
		t.Fatalf("scans %d, killed %v", scans, killed)
	}
	// A descendant that stays alive past the deadline fails the stop.
	err := stopDescendants(func() ([]int, int, error) { return []int{7}, 0, nil }, func(int) {}, 50*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "1 process(es) the server left behind survived") {
		t.Fatalf("survivors fail the stop: %v", err)
	}
}
