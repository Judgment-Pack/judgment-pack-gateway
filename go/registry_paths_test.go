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

// An input path is taken by its spelling, so a spelling the platform could
// resolve to another file than the spelling names is refused before anything
// is read or made (SPEC.md §4.1): by the verifier's reader, by the
// decision-record walk, by the registry writer and by the engine's start
// alike. A spelling that names the same file either way is taken. The paths
// are spelled as strings: filepath.Join would clean the cases away.
func TestAPathSpelledToResolveOtherwiseIsRefused(t *testing.T) {
	spell := func(parts ...string) string { return strings.Join(parts, string(filepath.Separator)) }
	dir := t.TempDir()
	refused := []struct{ name, path string }{
		{"a .. after a named component", spell(dir, "a", "..", "registry.jsonl")},
		{"a .. under a directory not yet made", spell(dir, "new", "deeper", "..", "registry.jsonl")},
		{"a .. after a . and a named component", spell(dir, ".", "a", "..", "..", "registry.jsonl")},
		{"a trailing separator", spell(dir, "registry.jsonl") + string(filepath.Separator)},
		{"a trailing separator after a directory", spell(dir, "decisions") + string(filepath.Separator)},
	}
	if runtime.GOOS == "windows" {
		refused = append(refused, []struct{ name, path string }{
			{"the literal namespace", `\\?\` + spell(dir, "registry.jsonl")},
			{"the literal namespace in forward slashes", `//?/` + spell(dir, "registry.jsonl")},
			{"the device namespace", `\\.\` + spell(dir, "registry.jsonl")},
			{"a component ending in a space", spell(dir, "anchor ", "registry.jsonl")},
			{"a component ending in a period", spell(dir, "anchor.", "registry.jsonl")},
			{"a last component ending in a period", spell(dir, "registry.jsonl.")},
		}...)
	}
	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			spelled := func(err error) bool { return err != nil && strings.Contains(err.Error(), "path spelling refused") }
			if _, _, err := readRegistryBytes(tt.path); !spelled(err) {
				t.Errorf("the reader: %v", err)
			}
			if _, _, err := decisionCandidates(tt.path, nil, nil); !spelled(err) {
				t.Errorf("the decision-record walk: %v", err)
			}
			if _, err := newRegistryWriter(tt.path, testSeed); !spelled(err) {
				t.Errorf("the registry writer: %v", err)
			}
			if err := preflightPaths(filepath.Join(dir, "store"), tt.path, filepath.Join(dir, "records")); !spelled(err) {
				t.Errorf("the engine's start, for the registry: %v", err)
			}
			if err := preflightPaths(filepath.Join(dir, "store"), filepath.Join(dir, "registry.jsonl"), tt.path); !spelled(err) {
				t.Errorf("the engine's start, for the decision records: %v", err)
			}
			// refused before anything was made
			if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
				t.Fatalf("a refused spelling made %v (%v)", entries, err)
			}
		})
	}

	taken := []struct{ name, path string }{
		{"a leading ..", spell("..", "no-registry-here-"+filepath.Base(dir), "registry.jsonl")},
		{"a . before a leading ..", spell(".", "..", "no-registry-here-"+filepath.Base(dir), "registry.jsonl")},
		{"a . component", spell(dir, ".", "registry.jsonl")},
		{"a repeated separator", dir + string(filepath.Separator) + string(filepath.Separator) + "registry.jsonl"},
	}
	if runtime.GOOS != "windows" {
		// a name like any other off Windows, which trims nothing
		taken = append(taken, struct{ name, path string }{"a component ending in a space", spell(dir, "anchor ", "registry.jsonl")})
	}
	for _, tt := range taken {
		t.Run(tt.name, func(t *testing.T) {
			if _, present, err := readRegistryBytes(tt.path); err != nil || present {
				t.Fatalf("an absent registry so spelled: present=%v err=%v", present, err)
			}
			if _, present, err := decisionCandidates(tt.path, nil, nil); err != nil || present {
				t.Fatalf("an absent directory so spelled: present=%v err=%v", present, err)
			}
		})
	}
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
