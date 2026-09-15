//go:build unix

package main

import (
	"context"
	"os"
	"syscall"
	"testing"
)

// The signer's operator controls: SIGUSR1 closes its gate, SIGUSR2
// reopens it.
func TestSignerOperatorSignals(t *testing.T) {
	f := newMCPFixture(t, false)
	f.service.reportsOut = &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	installOperatorControls(ctx, f.service)
	closed := func() bool {
		f.service.mu.Lock()
		defer f.service.mu.Unlock()
		return f.service.gate.closed
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the signer's gate to close on SIGUSR1", closed)
	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR2); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the signer's gate to open on SIGUSR2", func() bool { return !closed() })
}
