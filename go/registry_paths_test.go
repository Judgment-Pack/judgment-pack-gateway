package main

import (
	"crypto/ed25519"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
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
	sep := string(filepath.Separator)
	spell := func(parts ...string) string { return strings.Join(parts, sep) }
	windows := runtime.GOOS == "windows"
	dir := t.TempDir()
	spelled := func(err error) bool { return err != nil && strings.Contains(err.Error(), "path spelling refused") }
	nothingMade := func(t *testing.T) {
		t.Helper()
		if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
			t.Fatalf("a refused spelling made %v (%v)", entries, err)
		}
	}
	type row struct{ name, path string }

	// refused as the registry and as the decision-record directory
	refused := []row{
		{"a .. after a named component", spell(dir, "a", "..", "registry.jsonl")},
		{"a .. under a directory not yet made", spell(dir, "new", "deeper", "..", "registry.jsonl")},
		{"a .. after a . and a named component", spell(dir, ".", "a", "..", "..", "registry.jsonl")},
	}
	if windows {
		refused = append(refused, []row{
			{"the literal namespace", `\\?\` + spell(dir, "registry.jsonl")},
			{"the literal namespace in forward slashes", `//?/` + spell(dir, "registry.jsonl")},
			{"the device namespace", `\\.\` + spell(dir, "registry.jsonl")},
			{"the object manager's namespace", `\??\` + spell(dir, "registry.jsonl")},
			{"the object manager's namespace for a share", `\??\UNC\server\share\registry.jsonl`},
			{"a component ending in a space", spell(dir, "anchor ", "registry.jsonl")},
			{"a component ending in a period", spell(dir, "anchor.", "registry.jsonl")},
			{"a last component ending in a period", spell(dir, "registry.jsonl.")},
			{"a component holding a colon", spell(dir, "registry.jsonl:stream")},
			{"a reserved device name", spell(dir, "NUL", "registry.jsonl")},
			{"a reserved device name with an extension", spell(dir, "com1.jsonl")},
			{"a reserved device name with a superscript digit", spell(dir, "LPT²", "registry.jsonl")},
			{"a console device name", spell(dir, "conin$")},
			{"a share's server ending in a period", `\\server.\share\registry.jsonl`},
			{"a share ending in a space", `\\server\share \registry.jsonl`},
		}...)
	}
	for _, tt := range refused {
		t.Run("refused: "+tt.name, func(t *testing.T) {
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
			nothingMade(t)
		})
	}

	// a file's path cannot end in a separator; a directory's may
	for _, tt := range []row{
		{"a trailing separator", spell(dir, "registry.jsonl") + sep},
		{"the root", filepath.VolumeName(dir) + sep},
	} {
		t.Run("refused as the registry, taken as the directory: "+tt.name, func(t *testing.T) {
			if _, _, err := readRegistryBytes(tt.path); !spelled(err) {
				t.Errorf("the reader: %v", err)
			}
			if _, err := newRegistryWriter(tt.path, testSeed); !spelled(err) {
				t.Errorf("the registry writer: %v", err)
			}
			if err := requirePlainSpelling(tt.path, false); err != nil {
				t.Errorf("as the decision-record directory: %v", err)
			}
			nothingMade(t)
		})
	}
	t.Run("a decision-record directory with a trailing separator is read", func(t *testing.T) {
		records := filepath.Join(t.TempDir(), "records")
		if err := os.Mkdir(records, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(records, "a.json"), []byte(`{"a":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
		want := hexOf([]byte(`{"a":1}`))
		found, present, err := decisionCandidates(records+sep, map[string]bool{want: true}, nil)
		if err != nil || !present || !found[want] {
			t.Fatalf("present=%v found=%v err=%v", present, found, err)
		}
	})

	// taken as either, and absent when nothing is there
	taken := []row{
		{"a plain absolute path", spell(dir, "registry.jsonl")},
		{"a leading ..", spell("..", "no-registry-here-"+filepath.Base(dir), "registry.jsonl")},
		{"a . before a leading ..", spell(".", "..", "no-registry-here-"+filepath.Base(dir), "registry.jsonl")},
		{"a . component", spell(dir, ".", "registry.jsonl")},
		{"a repeated separator", dir + sep + sep + "registry.jsonl"},
	}
	if windows {
		// a drive's volume holds a colon that names the drive, not a stream
		taken = append(taken, row{"a drive-relative path", filepath.VolumeName(dir) + "no-registry-here-" + filepath.Base(dir) + sep + "registry.jsonl"})
	} else {
		// a name like any other off Windows, which trims nothing
		taken = append(taken, row{"a component ending in a space", spell(dir, "anchor ", "registry.jsonl")})
	}
	for _, tt := range taken {
		t.Run("taken: "+tt.name, func(t *testing.T) {
			if _, present, err := readRegistryBytes(tt.path); err != nil || present {
				t.Fatalf("an absent registry so spelled: present=%v err=%v", present, err)
			}
			if _, present, err := decisionCandidates(tt.path, nil, nil); err != nil || present {
				t.Fatalf("an absent directory so spelled: present=%v err=%v", present, err)
			}
		})
	}
}

// The directories above a path are its prefixes as spelled, cut before each
// separator, so that each resolves as that part of the whole path does -- a
// repeated separator after a drive or a share root included, which
// filepath.Dir on Windows reads as the start of a UNC path, and stops
// climbing. An obstructing file above such a path is found.
func TestTheDirectoriesAboveAPathAreItsPrefixes(t *testing.T) {
	type row struct {
		path string
		want []string
	}
	rows := []row{
		{"/a/b/registry.jsonl", []string{"/a", "/a/b"}},
		{"a//b/registry.jsonl", []string{"a", "a//b"}},
		{"../x/registry.jsonl", []string{"..", "../x"}},
		{"registry.jsonl", nil},
	}
	if runtime.GOOS == "windows" {
		rows = []row{
			{`C:\a\b\registry.jsonl`, []string{`C:\a`, `C:\a\b`}},
			{`C:\\anchor\missing\registry.jsonl`, []string{`C:\\anchor`, `C:\\anchor\missing`}},
			{`C:a\registry.jsonl`, []string{`C:a`}},
			{`\a\registry.jsonl`, []string{`\a`}},
			{`\\server\share\\anchor\missing\registry.jsonl`, []string{`\\server\share\\anchor`, `\\server\share\\anchor\missing`}},
			{`C:/a/b/registry.jsonl`, []string{`C:/a`, `C:/a/b`}},
		}
	}
	for _, tt := range rows {
		if got := pathAncestors(tt.path); !slices.Equal(got, tt.want) {
			t.Errorf("pathAncestors(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
	if runtime.GOOS == "windows" {
		// a repeated separator after the drive root, above a file
		dir := t.TempDir()
		file := filepath.Join(dir, "file")
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		volume := filepath.VolumeName(dir)
		doubled := volume + `\\` + file[len(volume)+1:]
		_, _, err := readRegistryBytes(doubled + `\missing\registry.jsonl`)
		if want := "registry parent path component is not a directory: " + doubled; err == nil || err.Error() != want {
			t.Fatalf("got %v, want %q", err, want)
		}
	}
}

// A name under the decision-record directory that Windows would not read as
// spelled -- one ending in a space, made through the literal namespace -- is
// read by its path as another file: it cannot be read, and is no verdict.
func TestADecisionRecordNamedAsWindowsWouldNotReadIt(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("a name ending in a space is read as spelled off Windows")
	}
	records := t.TempDir()
	if err := os.WriteFile(filepath.Join(records, "record"), []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(`\\?\`+filepath.Join(records, "record")+" ", []byte(`{"b":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := decisionCandidates(records, nil, nil); err == nil || !strings.Contains(err.Error(), "would not read as spelled") {
		t.Fatalf("a record Windows reads as another: %v", err)
	}
}

func testPublicKey(t *testing.T) []byte {
	t.Helper()
	return ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)
}

// The spellings are judged where each process takes them, before anything
// is made or read: a start makes no store for a registry it refuses, and a
// verification refuses before it reads the store -- here a store that is a
// file, whose own refusal would come first otherwise.
func TestSpellingsAreJudgedBeforeAnythingIsMadeOrRead(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "new-store")
	refusedRegistry := strings.Join([]string{store, "..", "registry.jsonl"}, string(filepath.Separator))
	if _, err := newGatewayService(store, testSeed, "gateway:test", refusedRegistry, nil); err == nil || !strings.Contains(err.Error(), "path spelling refused") {
		t.Fatalf("a start on a refused registry spelling: %v", err)
	}
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("the refused start made the store: %v", err)
	}
	file := filepath.Join(dir, "store-file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyWithRegistryAndRecords(file, refusedRegistry, "gateway:test", "", testPublicKey(t)); err == nil || !strings.Contains(err.Error(), "path spelling refused") {
		t.Fatalf("a verification with a refused registry spelling: %v", err)
	}
	refusedRecords := strings.Join([]string{dir, "a", "..", "records"}, string(filepath.Separator))
	if _, err := verifyWithRegistryAndRecords(file, filepath.Join(dir, "registry.jsonl"), "gateway:test", refusedRecords, testPublicKey(t)); err == nil || !strings.Contains(err.Error(), "path spelling refused") {
		t.Fatalf("a verification with a refused decision-record spelling: %v", err)
	}
}

// Absence is the plain answer for a missing name, and only that: on Windows
// os.IsNotExist also answers true for a path, a drive or a network share that
// cannot be reached, which is not the absence of what lies beyond it.
func TestAbsenceIsThePlainAnswerForAMissingName(t *testing.T) {
	if _, err := os.Stat(filepath.Join(t.TempDir(), "missing")); !absent(err) {
		t.Fatalf("a missing name in a directory is not absent: %v", err)
	}
	if absent(nil) {
		t.Fatal("no error is not absence")
	}
	rows := map[syscall.Errno]bool{syscall.ENOENT: true, syscall.ENOTDIR: false, syscall.EACCES: false}
	if runtime.GOOS == "windows" {
		// ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_BAD_NETPATH,
		// ERROR_ACCESS_DENIED
		rows = map[syscall.Errno]bool{2: true, 3: false, 53: false, 5: false}
	}
	for errno, want := range rows {
		if got := absent(&fs.PathError{Op: "stat", Path: "p", Err: errno}); got != want {
			t.Errorf("absent(%v) = %v, want %v", errno, got, want)
		}
	}
}

// A registry on a network share that has gone away is there and cannot be
// read -- never the absence that would load no seals and let a read into a
// session sealed on the share, which is what this change exists to stop.
// Windows reports such a share as ERROR_BAD_NETPATH, which os.IsNotExist takes
// for absence. At the registry and at the directory above it, the reader, the
// /registry endpoint and an acquisition all refuse, and no source starts. Off
// Windows every not-exist answer is the plain one, and there is nothing to
// stand in.
func TestAShareThatHasGoneAwayIsNotAbsence(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("every not-exist answer is the plain one off Windows")
	}
	service, _ := testService(t)
	badNetpath := syscall.Errno(53)
	for name, at := range map[string]string{"at the registry": service.regPath, "at the directory above it": filepath.Dir(service.regPath)} {
		t.Run(name, func(t *testing.T) {
			stat = func(path string) (fs.FileInfo, error) {
				if path == at {
					return nil, &fs.PathError{Op: "stat", Path: path, Err: badNetpath}
				}
				return os.Stat(path)
			}
			lstat = func(path string) (fs.FileInfo, error) {
				if path == at {
					return nil, &fs.PathError{Op: "lstat", Path: path, Err: badNetpath}
				}
				return os.Lstat(path)
			}
			t.Cleanup(func() { stat, lstat = os.Stat, os.Lstat })
			if _, _, err := readRegistryBytes(service.regPath); !errors.Is(err, badNetpath) {
				t.Fatalf("the reader took an unreachable share for absence: %v", err)
			}
			rec := httptest.NewRecorder()
			service.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/registry", nil))
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("/registry answered %d for an unreachable share: %q", rec.Code, rec.Body.String())
			}
			started := filepath.Join(t.TempDir(), "source-started")
			t.Setenv(envSourceReady, started)
			if _, err := service.acquire("share-unknown", "screening", vString("x"), nil); err == nil || !strings.Contains(err.Error(), "registry could not be read") {
				t.Fatalf("an acquisition with the share gone: %v", err)
			}
			if _, err := os.Stat(started); err == nil {
				t.Fatal("a source started with the share gone")
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
