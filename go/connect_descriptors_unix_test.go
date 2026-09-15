//go:build unix

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The snapshot and the configuration are given their final modes before
// they are synced, and the snapshots' directory its mode, whatever the
// umask narrowed them to at creation.
func TestConnectSetsModesBeforeItSyncs(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, ``)
	f.captured = capturedQuery
	if err := os.Chmod(f.config, 0o664); err != nil {
		t.Fatal(err)
	}
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	var modes []os.FileMode
	fileSyncing = func(file *os.File) {
		info, err := file.Stat()
		if err != nil {
			t.Fatal(err)
		}
		modes = append(modes, info.Mode().Perm())
	}
	defer func() { fileSyncing = nil }()
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err != nil {
		t.Fatal(err)
	}
	if len(modes) != 2 || modes[0] != snapshotMode || modes[1] != 0o664 {
		t.Fatalf("the snapshot, then the configuration, each synced at its final mode: %v", modes)
	}
	info, err := os.Stat(f.config + ".descriptors")
	if err != nil || info.Mode().Perm() != snapshotDirMode {
		t.Fatalf("the snapshots' directory is %v: %v", info.Mode().Perm(), err)
	}
}

// What is already there is used only as the frontend would verify it: a
// snapshots' directory that is a link or that others could write, and a
// snapshot's name taken by a link or by a file of another mode, refuse the
// connect before any configuration names a snapshot.
func TestConnectUsesWhatIsThereOnlyWhenItHolds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		after func(t *testing.T, f *connectFixture, snapshotPath string)
		want  string
	}{
		{"a snapshot of another mode", func(t *testing.T, f *connectFixture, path string) {
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
		}, "has mode 0600, not 0644"},
		{"a link in a snapshot's place", func(t *testing.T, f *connectFixture, path string) {
			// To a file of the same bytes and mode inside the
			// configuration's directory, which the held directory would
			// follow: only the open's refusal of links keeps it out.
			data, _ := os.ReadFile(path)
			if err := os.WriteFile(filepath.Join(filepath.Dir(f.config), "copy.json"), data, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("../copy.json", path); err != nil {
				t.Fatal(err)
			}
		}, "is taken, and is not a file this connect can reuse: is a symbolic link"},
		{"a link put in a snapshot's place once its name is judged", func(t *testing.T, f *connectFixture, path string) {
			data, _ := os.ReadFile(path)
			if err := os.WriteFile(filepath.Join(filepath.Dir(f.config), "copy.json"), data, 0o644); err != nil {
				t.Fatal(err)
			}
			entryJudged = func(name string) {
				entryJudged = nil
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("../copy.json", path); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { entryJudged = nil })
		}, "is not the file its name held a moment ago"},
		{"a directory others could write", func(t *testing.T, f *connectFixture, path string) {
			if err := os.Chmod(filepath.Dir(path), 0o775); err != nil {
				t.Fatal(err)
			}
		}, "is writable beyond its owner"},
		{"a link in the directory's place", func(t *testing.T, f *connectFixture, path string) {
			dir := filepath.Dir(path)
			elsewhere := filepath.Join(t.TempDir(), "descriptors")
			if err := os.Rename(dir, elsewhere); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(elsewhere, dir); err != nil {
				t.Fatal(err)
			}
		}, "is a symbolic link"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newConnectFixture(t, restrictedBinding, ``)
			f.captured = capturedQuery
			if _, err := connect(context.Background(), f.request(), f.host, f.check); err != nil {
				t.Fatal(err)
			}
			_, pin, _ := pinnedSnapshot(t, f)
			tc.after(t, f, filepath.Join(f.config+".descriptors", strings.TrimPrefix(pin, "sha256:")+".json"))
			before := f.fileText(t)
			req := f.request()
			req.replace = true
			if _, err := connect(context.Background(), req, f.host, f.check); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q: %v", tc.want, err)
			}
			if f.fileText(t) != before {
				t.Fatal("the configuration is left as it was")
			}
		})
	}
}
