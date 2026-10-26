//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The seed line, flipped one fact at a time: the seed serve accepts is
// enforced, and a seed readable by group or other, owned by another user,
// not a regular file or not there is not.
func TestPostureSeedFlips(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "gateway.seed")
	if err := os.WriteFile(seed, []byte(strings.Repeat("ab", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	euid := os.Geteuid()
	judge := func(path string, owner int) postureLine { return judgeSeed(path, os.Stat, owner) }
	if line := judge(seed, euid); line.name != protectionSeedFile || line.state != postureEnforced {
		t.Fatalf("a 0600 seed of the signer's own: %+v", line)
	}
	if line := seedPosture(postureInput{configured: true, seed: seed}); line.state != postureEnforced {
		t.Fatalf("the seed line as the report makes it: %+v", line)
	}
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o620} {
		if err := os.Chmod(seed, mode); err != nil {
			t.Fatal(err)
		}
		if line := judge(seed, euid); line.state != postureNotEnforced || !strings.Contains(line.reason, "readable by group or other") {
			t.Fatalf("mode %04o: %+v", mode, line)
		}
	}
	if err := os.Chmod(seed, 0o400); err != nil {
		t.Fatal(err)
	}
	if line := judge(seed, euid); line.state != postureEnforced {
		t.Fatalf("a 0400 seed is stricter than 0600: %+v", line)
	}
	if line := judge(seed, euid+1); line.state != postureNotEnforced || !strings.Contains(line.reason, "not owned by the gateway's own user") {
		t.Fatalf("a seed another user owns: %+v", line)
	}
	if line := judge(dir, euid); line.state != postureNotEnforced || !strings.Contains(line.reason, "regular file") {
		t.Fatalf("a directory at the seed's path: %+v", line)
	}
	fifo := filepath.Join(dir, "fifo.seed")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if line := judge(fifo, euid); line.state != postureNotEnforced || !strings.Contains(line.reason, "regular file") {
		t.Fatalf("a FIFO at the seed's path is judged without blocking: %+v", line)
	}
	if line := judge(filepath.Join(dir, "absent.seed"), euid); line.state != postureNotEnforced || !strings.Contains(line.reason, "could not be examined") {
		t.Fatalf("no seed at the path: %+v", line)
	}
}
