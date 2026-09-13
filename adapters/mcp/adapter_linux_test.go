//go:build linux

package mcp

import (
	"context"
	"os"
	"strconv"
	"strings"
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
	deadline := time.Now().Add(3 * time.Second)
	for {
		stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if err != nil || strings.Contains(string(stat), ") Z ") {
			return // gone, or a zombie its parent has yet to reap
		}
		if time.Now().After(deadline) {
			t.Fatalf("the descendant %d survived the check with the credentials: %s", pid, stat)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
