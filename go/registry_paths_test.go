package main

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// errorPrivilegeNotHeld is ERROR_PRIVILEGE_NOT_HELD: what Windows answers a
// symbolic link made by an account without the privilege (no Developer
// Mode). It is the one failure to make a link that skips a test here.
const errorPrivilegeNotHeld = syscall.Errno(1314)

// linkOrSkip makes link point at target, or skips the test where the
// platform will not make a link without a privilege the test does not
// hold. Any other failure fails.
func linkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" && errors.Is(err, errorPrivilegeNotHeld) {
			t.Skipf("links need a privilege here: %v", err)
		}
		t.Fatal(err)
	}
}

// dirLinkToNowhere makes link a directory link whose target is gone. The
// target is made first and removed after, so that Windows, which decides a
// link's kind when it is made, makes a directory link and not a file link.
func dirLinkToNowhere(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	linkOrSkip(t, target, link)
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
}

// junctionToNowhere makes link a Windows junction whose target directory is
// gone. A junction needs no privilege, so a failure to make one fails.
func junctionToNowhere(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
}

// The directories above an input are judged as the platform resolves the path
// as given, never as its spelling cleans it. On Linux and macOS a ".." after a
// link is resolved through the link, so a parent cleaned by its spelling can
// be another directory than the one the reader and the writer open: a
// registry that is absent would be refused, and one under a link to nothing
// taken for absent. Windows removes ".." by its spelling before it resolves
// anything, so there the cleaned path is the one it opens, and each row says
// what Windows makes of it. The paths are spelled as strings: filepath.Join
// would clean the case away.
func TestRegistryPathsAreJudgedAsThePlatformResolvesThem(t *testing.T) {
	spell := func(parts ...string) string { return strings.Join(parts, string(filepath.Separator)) }
	windows := runtime.GOOS == "windows"

	t.Run("a file the path steps back over", func(t *testing.T) {
		a := filepath.Join(t.TempDir(), "a")
		if err := os.Mkdir(a, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(a, "file"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(a, "registry.jsonl"), []byte("\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, present, err := readRegistryBytes(spell(a, "file", "..", "registry.jsonl"))
		if windows {
			// Windows opens a\registry.jsonl, which is there
			if err != nil || !present {
				t.Fatalf("present=%v err=%v", present, err)
			}
			return
		}
		// Linux and macOS cannot pass through the file
		if want := "registry parent path component is not a directory: " + spell(a, "file"); err == nil || err.Error() != want {
			t.Fatalf("got %v, want %q", err, want)
		}
	})

	t.Run("a link the path steps back through", func(t *testing.T) {
		dir := t.TempDir()
		for _, d := range []string{filepath.Join(dir, "a"), filepath.Join(dir, "b", "dir")} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		linkOrSkip(t, filepath.Join(dir, "b", "dir"), filepath.Join(dir, "a", "jump"))
		dirLinkToNowhere(t, filepath.Join(dir, "nowhere"), filepath.Join(dir, "a", "broken"))
		_, present, err := readRegistryBytes(spell(dir, "a", "jump", "..", "broken", "registry.jsonl"))
		if windows {
			// Windows opens a\broken\registry.jsonl, under the link to nothing
			if want := "registry parent path component is a link that leads nowhere: " + spell(dir, "a", "broken"); err == nil || err.Error() != want {
				t.Fatalf("got %v, want %q", err, want)
			}
			return
		}
		// Linux and macOS step back from b/dir to b, where broken is not there
		if err != nil || present {
			t.Fatalf("an absent registry: present=%v err=%v", present, err)
		}
	})

	t.Run("a link to nothing the path steps back over", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "a"), 0o755); err != nil {
			t.Fatal(err)
		}
		dirLinkToNowhere(t, filepath.Join(dir, "nowhere"), filepath.Join(dir, "a", "dangling"))
		_, present, err := readRegistryBytes(spell(dir, "a", "dangling", "..", "registry.jsonl"))
		if windows {
			// Windows opens a\registry.jsonl, which is not there
			if err != nil || present {
				t.Fatalf("an absent registry: present=%v err=%v", present, err)
			}
			return
		}
		// Linux and macOS must pass through the link, which leads nowhere
		if want := "registry parent path component is a link that leads nowhere: " + spell(dir, "a", "dangling"); err == nil || err.Error() != want {
			t.Fatalf("got %v, want %q", err, want)
		}
	})

	t.Run("a path Windows takes literally", func(t *testing.T) {
		if !windows {
			t.Skip(`the \\?\ prefix is Windows' own`)
		}
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "a"), 0o755); err != nil {
			t.Fatal(err)
		}
		dirLinkToNowhere(t, filepath.Join(dir, "nowhere"), filepath.Join(dir, "a", "dangling"))
		// given with the \\?\ prefix, a path keeps its "..": Windows must
		// pass through the link, which leads nowhere
		literal := `\\?\` + dir
		_, _, err := readRegistryBytes(spell(literal, "a", "dangling", "..", "registry.jsonl"))
		if want := "registry parent path component is a link that leads nowhere: " + spell(literal, "a", "dangling"); err == nil || err.Error() != want {
			t.Fatalf("got %v, want %q", err, want)
		}
	})
}

// A second look that fails is not absence. When the stat that follows links
// finds an input not there, only a look at the path itself that confirms it
// makes the input absent: that look failing -- the filesystem changing between
// the two, a device error -- establishes nothing, and is a refusal wherever the
// look is taken.
func TestASecondLookThatFailsIsNotAbsence(t *testing.T) {
	failed := errors.New("the second look failed")
	lookFails := func(t *testing.T, at string) {
		t.Helper()
		lstat = func(name string) (fs.FileInfo, error) {
			if name == at {
				return nil, &fs.PathError{Op: "lstat", Path: name, Err: failed}
			}
			return os.Lstat(name)
		}
		t.Cleanup(func() { lstat = os.Lstat })
	}
	dir := t.TempDir()
	for _, tt := range []struct{ name, path, at string }{
		{"at a directory above the registry", filepath.Join(dir, "missing", "registry.jsonl"), filepath.Join(dir, "missing")},
		{"at the registry", filepath.Join(dir, "registry.jsonl"), filepath.Join(dir, "registry.jsonl")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, present, err := readRegistryBytes(tt.path); err != nil || present {
				t.Fatalf("control: an absent registry is absent: present=%v err=%v", present, err)
			}
			lookFails(t, tt.at)
			if _, _, err := readRegistryBytes(tt.path); !errors.Is(err, failed) {
				t.Fatalf("a failed second look was taken for absence: %v", err)
			}
		})
	}
	t.Run("at the decision-record directory", func(t *testing.T) {
		decisions := filepath.Join(dir, "decisions")
		if _, present, err := decisionCandidates(decisions, nil, nil); err != nil || present {
			t.Fatalf("control: an absent directory is absent: present=%v err=%v", present, err)
		}
		lookFails(t, decisions)
		if _, _, err := decisionCandidates(decisions, nil, nil); !errors.Is(err, failed) {
			t.Fatalf("a failed second look was taken for absence: %v", err)
		}
	})
}

// The decision-record directory is judged as the registry is (SPEC.md §4.1):
// a link that leads nowhere, at the directory or at a directory above it, is
// there and cannot be read -- no verdict -- never the absent directory a stat
// that follows it would make of it.
func TestADecisionDirectoryUnderALinkToNothingIsNoVerdict(t *testing.T) {
	dir := t.TempDir()
	leaf := filepath.Join(dir, "decisions")
	dirLinkToNowhere(t, filepath.Join(dir, "nowhere"), leaf)
	if _, _, err := decisionCandidates(leaf, nil, nil); err == nil || err.Error() != "the decision-record directory is a link that leads nowhere: "+leaf {
		t.Fatalf("the directory a link to nothing: %v", err)
	}
	above := filepath.Join(dir, "above")
	dirLinkToNowhere(t, filepath.Join(dir, "nowhere-too"), above)
	want := "decision-record directory: registry parent path component is a link that leads nowhere: " + above
	if _, _, err := decisionCandidates(filepath.Join(above, "decisions"), nil, nil); err == nil || err.Error() != want {
		t.Fatalf("a directory above it a link to nothing: got %v, want %q", err, want)
	}
}
