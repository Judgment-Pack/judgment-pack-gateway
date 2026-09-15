//go:build unix

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
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
			// To a copy beside it, which the held directory would follow.
			data, _ := os.ReadFile(path)
			if err := os.WriteFile(filepath.Join(filepath.Dir(path), "copy.json"), data, 0o644); err != nil {
				t.Fatal(err)
			}
			entryJudged = func(name string) {
				if !strings.HasSuffix(name, ".json") {
					return
				}
				entryJudged = nil
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("copy.json", path); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { entryJudged = nil })
		}, "is not the file its name held a moment ago"},
		{"a link to the same file, put in its place once its name is judged", func(t *testing.T, f *connectFixture, path string) {
			entryJudged = func(name string) {
				if !strings.HasSuffix(name, ".json") {
					return
				}
				entryJudged = nil
				// The snapshot itself renamed, and a link to it where it
				// stood: the file opened through the link is the file
				// judged, and only its name has become a link.
				if err := os.Rename(path, path+".moved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Base(path)+".moved", path); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { entryJudged = nil })
		}, "is not the file its name held a moment ago"},
		{"a directory the MCP server cannot pass through", func(t *testing.T, f *connectFixture, path string) {
			if err := os.Chmod(filepath.Dir(path), 0o750); err != nil {
				t.Fatal(err)
			}
		}, "cannot be passed through by the MCP server"},
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

// What belongs to the MCP server's own user or group is refused: a
// snapshot or directory found so, and a configuration whose owner would
// give it to a snapshot made.
func TestNothingOfTheMCPServersOwnIsUsed(t *testing.T) {
	// Even were the configuration the MCP server's user's, and a root file
	// the MCP server's group's.
	for _, tc := range []struct {
		st    syscall.Stat_t
		owner fileOwnerIDs
	}{
		{syscall.Stat_t{Uid: frontendUID}, fileOwnerIDs{uid: frontendUID, known: true}},
		{syscall.Stat_t{Uid: 0, Gid: frontendUID}, fileOwnerIDs{uid: 1000, known: true}},
	} {
		st := tc.st
		if err := snapshotHeld(fakeInfo{mode: 0o644, sys: &st}, tc.owner, false); err == nil || !strings.Contains(err.Error(), "belongs to the MCP server's own user or group") {
			t.Errorf("%+v: %v", tc.st, err)
		}
	}
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	f := &configFile{dir: root, base: "engine.json", mode: 0o640, owner: fileOwnerIDs{uid: 1000, gid: frontendUID, known: true}}
	if _, _, err := f.publishSnapshot([]byte("{}")); err == nil || !strings.Contains(err.Error(), "would be refused at the server's start") {
		t.Fatalf("%v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "engine.json.descriptors")); !os.IsNotExist(err) {
		t.Fatalf("nothing is made for it: %v", err)
	}
}

// fakeInfo is a file's state as a test states it.
type fakeInfo struct {
	mode os.FileMode
	sys  any
}

func (i fakeInfo) Name() string       { return "x" }
func (i fakeInfo) Size() int64        { return 0 }
func (i fakeInfo) Mode() os.FileMode  { return i.mode }
func (i fakeInfo) ModTime() time.Time { return time.Time{} }
func (i fakeInfo) IsDir() bool        { return i.mode.IsDir() }
func (i fakeInfo) Sys() any           { return i.sys }

// A snapshot's name already taken by the same bytes is reused, and synced
// before the configuration names it: a file found may never have reached
// the disk.
func TestConnectSyncsASnapshotItReuses(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, ``)
	f.captured = capturedQuery
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err != nil {
		t.Fatal(err)
	}
	_, pin, _ := pinnedSnapshot(t, f)
	var synced []string
	fileSyncing = func(file *os.File) { synced = append(synced, filepath.Base(file.Name())) }
	defer func() { fileSyncing = nil }()
	req := f.request()
	req.replace = true
	if _, err := connect(context.Background(), req, f.host, f.check); err != nil {
		t.Fatal(err)
	}
	name := strings.TrimPrefix(pin, "sha256:") + ".json"
	if len(synced) != 3 || !strings.HasSuffix(synced[0], ".staged") || synced[1] != name || synced[2] != "new" {
		t.Fatalf("the staged snapshot, the one reused, then the configuration: %q", synced)
	}
}

// The snapshots' directory is held while the snapshot is kept, and its
// name judged again before the configuration is put in place: a link to
// the same directory put in its place, when it is judged or once the
// snapshot is kept, refuses the connect.
func TestTheSnapshotsDirectoryIsHeld(t *testing.T) {
	for _, when := range []string{"judged", "kept"} {
		t.Run(when, func(t *testing.T) {
			f := newConnectFixture(t, restrictedBinding, ``)
			f.captured = capturedQuery
			if _, err := connect(context.Background(), f.request(), f.host, f.check); err != nil {
				t.Fatal(err)
			}
			dir := f.config + ".descriptors"
			swap := func() {
				if err := os.Rename(dir, dir+".moved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Base(dir)+".moved", dir); err != nil {
					t.Fatal(err)
				}
			}
			if when == "judged" {
				entryJudged = func(name string) {
					if strings.HasSuffix(name, ".descriptors") {
						entryJudged = nil
						swap()
					}
				}
			} else {
				beforeCommit = func() { beforeCommit = nil; swap() }
			}
			t.Cleanup(func() { entryJudged, beforeCommit = nil, nil })
			before := f.fileText(t)
			req := f.request()
			req.replace = true
			f.captured = `{"query":{"description":"Run a query now"}}`
			if _, err := connect(context.Background(), req, f.host, f.check); err == nil || !strings.Contains(err.Error(), "is not the directory its name held a moment ago") {
				t.Fatalf("%v", err)
			}
			if f.fileText(t) != before {
				t.Fatal("the configuration is left as it was")
			}
			// Found when it is judged, nothing is written in the directory
			// the link leads to.
			if entries, _ := os.ReadDir(dir + ".moved"); when == "judged" && len(entries) != 1 {
				t.Fatalf("a snapshot was kept in a directory swapped in: %v", entries)
			}
		})
	}
}

// A failure to sync the snapshots' directory refuses the connect before
// any configuration names what is in it.
func TestASnapshotsDirectoryThatWillNotSyncRefusesTheConnect(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, ``)
	f.captured = capturedQuery
	directorySynced = func(name string) error {
		if strings.HasSuffix(name, ".descriptors") {
			return os.ErrPermission
		}
		return nil
	}
	defer func() { directorySynced = nil }()
	before := f.fileText(t)
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err == nil || !strings.Contains(err.Error(), "could not be synced") {
		t.Fatalf("%v", err)
	}
	if f.fileText(t) != before {
		t.Fatal("the configuration is left as it was")
	}
}

// The snapshots' directory is judged immediately before the rename, after
// the configuration is written and synced: a link to the same directory
// put in its place while the configuration syncs refuses the connect.
func TestTheSnapshotsDirectoryIsJudgedLast(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, ``)
	f.captured = capturedQuery
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err != nil {
		t.Fatal(err)
	}
	dir := f.config + ".descriptors"
	fileSyncing = func(file *os.File) {
		if filepath.Base(file.Name()) != "new" {
			return
		}
		fileSyncing = nil
		if err := os.Rename(dir, dir+".moved"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Base(dir)+".moved", dir); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { fileSyncing = nil })
	before := f.fileText(t)
	req := f.request()
	req.replace = true
	f.captured = `{"query":{"description":"Run a query now"}}`
	if _, err := connect(context.Background(), req, f.host, f.check); err == nil || !strings.Contains(err.Error(), "is not the directory its name held a moment ago") {
		t.Fatalf("%v", err)
	}
	if f.fileText(t) != before {
		t.Fatal("the configuration is left as it was")
	}
}
