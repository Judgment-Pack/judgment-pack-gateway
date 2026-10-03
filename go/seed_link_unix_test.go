//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// On a real filesystem: a seed mounted as a projected secret, its name a
// link to ..data/gateway.seed and ..data a link to a dated directory, both
// the signer's own here, resolves to the dated file, which loadSeed then
// opens and judges through one descriptor. The same layout with the dated
// directory writable by others is refused before anything is opened.
func TestAMountedSeedResolvesToTheFileLoadSeedOpens(t *testing.T) {
	host := engineHost{euid: os.Geteuid(), fileOwner: fileOwnerOf, readLink: os.Readlink}
	mount := func(t *testing.T, datedMode os.FileMode) (string, string) {
		t.Helper()
		base, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		secret := filepath.Join(base, "secret")
		dated := filepath.Join(secret, "..2026_10_03")
		if err := os.MkdirAll(dated, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dated, "gateway.seed"), testSeed, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dated, datedMode); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("..2026_10_03", filepath.Join(secret, "..data")); err != nil {
			t.Fatal(err)
		}
		seed := filepath.Join(secret, "gateway.seed")
		if err := os.Symlink(filepath.Join("..data", "gateway.seed"), seed); err != nil {
			t.Fatal(err)
		}
		return seed, filepath.Join(dated, "gateway.seed")
	}
	seed, file := mount(t, 0o700)
	resolved, err := trustedFile(seed, host.euid, linkOwners{other: host.euid}, host)
	if err != nil || resolved != file {
		t.Fatalf("the mounted seed resolves to its dated file: %q %v", resolved, err)
	}
	if loaded, err := loadSeed(resolved); err != nil || len(loaded) != seedBytes {
		t.Fatalf("loadSeed opens the resolved file: %v", err)
	}
	open, _ := mount(t, 0o777)
	if _, err := trustedFile(open, host.euid, linkOwners{other: host.euid}, host); err == nil || !strings.Contains(err.Error(), "without the sticky bit") {
		t.Fatalf("a dated directory others may write: %v", err)
	}
}
