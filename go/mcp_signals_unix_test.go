//go:build unix

package main

import (
	"context"
	"os"
	"syscall"
	"testing"
)

// The operator's control: SIGUSR1 closes admission, SIGUSR2 reopens it.
func TestMCPOperatorSignals(t *testing.T) {
	f := newMCPFixture(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.server.operatorControls(ctx)
	closed := func() bool { c, _, _ := f.server.admission(); return c }
	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "admission to close on SIGUSR1", closed)
	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR2); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "admission to open on SIGUSR2", func() bool { return !closed() })
}
