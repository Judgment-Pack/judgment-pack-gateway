//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The custody program a delegated write is admitted through is held at start
// as an adapter is (gateway #368): a link is launched by its target, and a
// program that is not there, or that others may write, refuses the start.
func TestGrantCustodyProgramIsHeldAtStart(t *testing.T) {
	host := engineHost{euid: os.Geteuid(), fileOwner: fileOwnerOf, readLink: os.Readlink, executableFormat: readNativeExecutable}
	tree := func(t *testing.T, custodyMode os.FileMode) string {
		t.Helper()
		base, err := filepath.EvalSymlinks(tempDirAt(t, 0o755))
		if err != nil {
			t.Fatal(err)
		}
		bin := filepath.Join(base, "bin")
		if err := os.Mkdir(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, mode := range map[string]os.FileMode{"adapter-mcp": 0o755, "gateway-connections": custodyMode} {
			if err := os.WriteFile(filepath.Join(bin, name), hostExecutable(), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(bin, name), mode); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chmod(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		return bin
	}
	sources := func(adapter, custody string) map[string]sourceSpec {
		return map[string]sourceSpec{"warehouse/write": {
			argv:  []string{adapter},
			grant: &grantGate{argv: []string{custody, "--state-dir=/var/lib/custody", "--principal=operator", "--provider=notion"}, env: []string{}, provider: "notion", connection: "notion"},
		}}
	}
	bin := tree(t, 0o755)
	linked := filepath.Join(filepath.Dir(bin), "linked")
	if err := os.Mkdir(linked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(bin, "gateway-connections"), filepath.Join(linked, "gateway-connections")); err != nil {
		t.Fatal(err)
	}
	held := sources(filepath.Join(bin, "adapter-mcp"), filepath.Join(linked, "gateway-connections"))
	if err := holdAdapterSources(held, host); err != nil {
		t.Fatalf("the signer's custody program: %v", err)
	}
	if got := held["warehouse/write"].grant.argv; got[0] != filepath.Join(bin, "gateway-connections") || strings.Join(got[1:], " ") != "--state-dir=/var/lib/custody --principal=operator --provider=notion" {
		t.Fatalf("the custody program is launched by its held target: %v", got)
	}
	for name, c := range map[string]struct {
		custody string
		want    string
	}{
		"a custody program that is not there":   {filepath.Join(bin, "absent"), "grant custody"},
		"a custody program its group may write": {filepath.Join(tree(t, 0o775), "gateway-connections"), "is writable beyond its owner (mode 0775)"},
		"a custody program anyone may write":    {filepath.Join(tree(t, 0o757), "gateway-connections"), "is writable beyond its owner (mode 0757)"},
	} {
		err := holdAdapterSources(sources(filepath.Join(bin, "adapter-mcp"), c.custody), host)
		if err == nil || !strings.Contains(err.Error(), "grant custody") || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: want %q, got %v", name, c.want, err)
		}
	}
}
