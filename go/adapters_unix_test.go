//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// On a real filesystem, as serve's host sees it: an adapter directory of the
// signer's own holding executables only it may write is accepted, and a link
// to one is launched by its target. A FIFO where an adapter should be, a
// directory others may write, and an executable its group may write are
// refused.
func TestAdapterExecutablesAreHeldOnARealFilesystem(t *testing.T) {
	host := engineHost{euid: os.Geteuid(), fileOwner: fileOwnerOf, readLink: os.Readlink, executableHead: readExecutableHead}
	tree := func(t *testing.T, dirMode, fileMode os.FileMode) string {
		t.Helper()
		base, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		bin := filepath.Join(base, "bin")
		if err := os.Mkdir(bin, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"adapter-airbyte", "adapter-mcp"} {
			if err := os.WriteFile(filepath.Join(bin, name), append(nativeHead(), make([]byte, 60)...), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(bin, name), fileMode); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chmod(bin, dirMode); err != nil {
			t.Fatal(err)
		}
		return bin
	}
	sources := func(bin string) map[string]sourceSpec {
		return map[string]sourceSpec{
			"warehouse/history": {argv: []string{filepath.Join(bin, "adapter-airbyte")}},
			"warehouse/live":    {argv: []string{filepath.Join(bin, "adapter-mcp")}},
		}
	}
	bin := tree(t, 0o755, 0o755)
	if err := holdAdapterSources(sources(bin), host); err != nil {
		t.Fatalf("the signer's adapters: %v", err)
	}
	linked := filepath.Join(filepath.Dir(bin), "linked")
	if err := os.Mkdir(linked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(bin, "adapter-mcp"), filepath.Join(linked, "adapter-mcp")); err != nil {
		t.Fatal(err)
	}
	launched := map[string]sourceSpec{"warehouse/live": {argv: []string{filepath.Join(linked, "adapter-mcp")}}}
	if err := holdAdapterSources(launched, host); err != nil || launched["warehouse/live"].argv[0] != filepath.Join(bin, "adapter-mcp") {
		t.Fatalf("a link of the signer's own is launched by its target: %v %v", err, launched["warehouse/live"].argv)
	}
	fifo := tree(t, 0o755, 0o755)
	if err := os.Remove(filepath.Join(fifo, "adapter-mcp")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(fifo, "adapter-mcp"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A script, whatever protects it, names an interpreter this check does
	// not hold: one in a directory others may write, or whichever sh env
	// would find on a PATH.
	script := func(text string) string {
		bin := tree(t, 0o755, 0o755)
		if err := os.WriteFile(filepath.Join(bin, "adapter-mcp"), []byte(text), 0o755); err != nil {
			t.Fatal(err)
		}
		return bin
	}
	open := filepath.Join(filepath.Dir(bin), "open")
	if err := os.Mkdir(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		bin  string
		want string
	}{
		"a script whose interpreter others may replace": {script("#!" + filepath.Join(open, "sh") + "\n"), "is a script (it starts with #!)"},
		"a script through env":                          {script("#!/usr/bin/env sh\n"), "is a script (it starts with #!)"},
		"a text file":                                   {script("adapter\n"), "is not a native executable"},
		"a FIFO where an adapter should be":             {fifo, "neither a regular file nor a directory"},
		"a directory others may write":                  {tree(t, 0o777, 0o755), "is writable beyond its owner (mode 0777) without the sticky bit"},
		"an executable its group may write":             {tree(t, 0o755, 0o775), "is writable beyond its owner (mode 0775)"},
	} {
		if err := holdAdapterSources(sources(c.bin), host); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: want %q, got %v", name, c.want, err)
		}
	}
	// An adapter the signer cannot read cannot be told from a script.
	if os.Geteuid() != 0 {
		unreadable := tree(t, 0o755, 0o111)
		if err := holdAdapterSources(sources(unreadable), host); err == nil || !strings.Contains(err.Error(), "could not be read to tell whether it is a native executable") {
			t.Fatalf("an adapter the signer cannot read: %v", err)
		}
	}
}
