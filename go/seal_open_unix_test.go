//go:build unix

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A gateway serving the registry holds it, and the command is refused while
// it does: nothing is sealed. Once the gateway lets go, the session seals.
func TestSealOpenIsRefusedWhileAGatewayHoldsTheRegistry(t *testing.T) {
	g := leftOpenStore(t)
	seedPath := writeSeedFile(t, t.TempDir(), testSeed)
	hold, err := holdEngineRegistry([]string{seedPath}, g.regPath, testSeed)
	if err != nil {
		t.Fatal(err)
	}
	registry := readFile(t, g.regPath)
	code, stdout, stderr := sealOpenOn(t, g, seedPath, "2026-11-10T00:00:01Z", "--session", "left")
	want := "seal-open: the registry is held by a running gateway, or by a rotation under way: " + g.regPath + "; stop the gateway, then seal\n"
	if code != 1 || stdout != "" || stderr != want || readFile(t, g.regPath) != registry {
		t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	hold.Close()
	if code, _, stderr := sealOpenOn(t, g, seedPath, "2026-11-10T00:00:01Z", "--session", "left"); code != 0 || stderr != "" {
		t.Fatalf("after the gateway let go: exit %d: %s", code, stderr)
	}
}

// A session that cannot be read is no answer: with --all, nothing is sealed,
// the whole sessions beside it among them.
func TestSealOpenSealsNothingWhenASessionCannotBeRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a directory's mode does not keep the superuser out")
	}
	g := leftOpenStore(t)
	locked := filepath.Join(g.storeRoot, "receipts", "locked")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "0.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o755) })
	seedPath := writeSeedFile(t, t.TempDir(), testSeed)
	registry := readFile(t, g.regPath)
	code, stdout, stderr := sealOpenOn(t, g, seedPath, "2026-11-10T00:00:01Z", "--all")
	want := "seal-open: session locked could not be read, and nothing was sealed: open " + locked + ": permission denied\n"
	if code != 1 || stdout != "" || stderr != want || readFile(t, g.regPath) != registry {
		t.Fatalf("exit %d\nstdout %q\nstderr %q\nwant   %q", code, stdout, stderr, want)
	}
}
