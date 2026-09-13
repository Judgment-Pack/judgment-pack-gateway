//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Whether this process may switch a source to another user, from what it
// is and what it holds: root may; a non-root process may with the three
// capabilities and nothing an adapter could take up; without capability
// reporting, only root.
func TestSwitchingRefusal(t *testing.T) {
	three := uint64(1<<capSetuid | 1<<capSetgid | 1<<capKill)
	if err := switchingRefusal(0, capabilitySets{}); err != nil {
		t.Fatalf("root switches where capabilities are unknown: %v", err)
	}
	if err := switchingRefusal(1000, capabilitySets{}); err == nil || !strings.Contains(err.Error(), "requires the gateway to run as root") {
		t.Fatalf("without capability reporting only root switches: %v", err)
	}
	if err := switchingRefusal(1000, capabilitySets{known: true, effective: three, permitted: three}); err != nil {
		t.Fatalf("the three as file capabilities suffice: %v", err)
	}
	if err := switchingRefusal(1000, capabilitySets{known: true, effective: 1 << capSetuid}); err == nil || !strings.Contains(err.Error(), "lacks CAP_KILL, CAP_SETGID") {
		t.Fatalf("missing capabilities are named: %v", err)
	}
	if err := switchingRefusal(1000, capabilitySets{known: true, effective: three, ambient: 1 << capSetuid}); err == nil || !strings.Contains(err.Error(), "ambient") {
		t.Fatalf("an ambient capability is refused: %v", err)
	}
	if err := switchingRefusal(1000, capabilitySets{known: true, effective: three, inheritable: 1 << capSetuid}); err == nil || !strings.Contains(err.Error(), "inheritable") {
		t.Fatalf("an inheritable capability is refused: %v", err)
	}
	if err := switchingRefusal(1000, capabilitySets{known: true, effective: three, permitted: three | 1<<capDacReadSearch}); err == nil || !strings.Contains(err.Error(), "CAP_DAC_OVERRIDE or CAP_DAC_READ_SEARCH") {
		t.Fatalf("a permitted DAC capability is refused: %v", err)
	}
	if err := switchingRefusal(0, capabilitySets{known: true, effective: three | 1<<capDacOverride, ambient: three}); err != nil {
		t.Fatalf("root is root; the capability rules are the non-root signer's: %v", err)
	}
}

// A FIFO put in a configuration's place is refused without being waited
// on: the open does not block.
func TestReadBoundedDoesNotBlockOnAFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "engine.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readBounded(fifo, 16)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("a FIFO is refused as not a regular file: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the read blocked on opening the FIFO")
	}
	_ = os.Remove(fifo)
}
