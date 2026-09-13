//go:build unix

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// One connect at a time holds the file: a second one, while the first is
// still running its checks, refuses rather than waits.
func TestOneConnectAtATimeHoldsTheFile(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, ``)
	inChecks := make(chan struct{})
	release := make(chan struct{})
	first := make(chan error, 1)
	var once sync.Once
	go func() {
		_, err := connect(context.Background(), f.request(), f.host, func(ctx context.Context, spec sourceSpec) ([]byte, error) {
			once.Do(func() { close(inChecks) })
			<-release
			return f.check(ctx, spec)
		})
		first <- err
	}()
	<-inChecks
	second := f.request()
	second.platform = "replica"
	second.user = "engine-docs"
	_, err := connect(context.Background(), second, f.host, f.check)
	if err == nil || !strings.Contains(err.Error(), "another connect holds engine.json.lock") {
		t.Fatalf("the second connect is refused while the first holds the file: %v", err)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatalf("the first connect completes: %v", err)
	}
	if _, err := os.Stat(f.config + ".lock"); err != nil {
		t.Fatalf("the lock file stays beside the configuration: %v", err)
	}
}

// The replaced file keeps its mode whatever the umask narrows creation to.
func TestReplaceKeepsTheFilesModeUnderAUmask(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, ``)
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(f.config)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v, want 0640 as it was", info.Mode().Perm())
	}
}

// A file put in the configuration's place that is not a file is judged by
// the descriptor opened and never waited on: a FIFO does not block a
// connect that holds the lock.
func TestReadingTheConfigurationDoesNotFollowOrBlock(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, ``)
	file, err := openConfigFile(f.config)
	if err != nil {
		t.Fatal(err)
	}
	defer file.close()
	os.Remove(f.config)
	if err := syscall.Mkfifo(f.config, 0o600); err != nil {
		t.Skipf("no FIFO here: %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := file.read(); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "is not a regular file") {
			t.Fatalf("refused as not a file: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a FIFO blocked")
	}
	os.Remove(f.config)
	// A relative link, which the held directory would otherwise follow.
	if err := os.Symlink("elsewhere.json", f.config); err != nil {
		t.Skipf("no symbolic links here: %v", err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "elsewhere.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := file.read(); err == nil {
		t.Fatal("a link in the file's place is not followed")
	}
}

// A directory with the setgid bit gives a new file its group, whoever
// made it; the replaced file keeps the group the old one had.
func TestReplaceKeepsTheGroupUnderASetgidDirectory(t *testing.T) {
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	other := -1
	for _, g := range groups {
		if g != os.Getegid() {
			other = g
			break
		}
	}
	if other < 0 {
		t.Skip("this user has no second group to give the directory")
	}
	f := newConnectFixture(t, restrictedBinding, ``)
	if err := os.Chown(f.dir, -1, other); err != nil {
		t.Skipf("cannot give the directory the group: %v", err)
	}
	// The directory is group-owned by the other group with the setgid bit,
	// and writable by that group only under the sticky bit, which the
	// held-parent rule requires.
	if err := os.Chmod(f.dir, os.ModeSetgid|os.ModeSticky|0o770); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(f.dir); err != nil || info.Mode()&os.ModeSetgid == 0 {
		t.Skipf("the filesystem does not keep the setgid bit: %v", err)
	}
	// The directory gives a new file its group: shown before the replace.
	if probe, err := os.CreateTemp(f.dir, "probe"); err == nil {
		info, _ := probe.Stat()
		probe.Close()
		os.Remove(probe.Name())
		if ownerIDsOf(info).gid != other {
			t.Skip("the directory does not give a new file its group here")
		}
	}
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(f.config)
	if err != nil {
		t.Fatal(err)
	}
	if got := ownerIDsOf(info); got.gid != os.Getegid() {
		t.Fatalf("the file's group is %d, the directory's; it was %d", got.gid, os.Getegid())
	}
}

// A directory another user could write is refused before anything is
// read: the private directory the new file is written in could be
// swapped there. With the sticky bit, it could not.
func TestConnectRefusesADirectoryAnotherUserCouldWrite(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, ``)
	if err := os.Chmod(f.dir, 0o777); err != nil {
		t.Fatal(err)
	}
	_, err := connect(context.Background(), f.request(), f.host, f.check)
	if err == nil || !strings.Contains(err.Error(), "is writable beyond its owner (mode 0777) without the sticky bit") || len(f.asked) != 0 {
		t.Fatalf("refused before any check: %v (asked %d)", err, len(f.asked))
	}
	if err := os.Chmod(f.dir, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err != nil {
		t.Fatalf("with the sticky bit, another user cannot replace what is there: %v", err)
	}
}

// The file read is the entry's own: a regular file put in the entry's
// place between the open and the judgment is not read.
func TestReadingTheConfigurationJudgesTheEntryItOpened(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, ``)
	file, err := openConfigFile(f.config)
	if err != nil {
		t.Fatal(err)
	}
	defer file.close()
	other := filepath.Join(f.dir, "other.json")
	if err := os.WriteFile(other, []byte(`{"engineVersion":"1"}`), 0o640); err != nil {
		t.Fatal(err)
	}
	file.afterOpen = func() {
		if err := os.Rename(other, f.config); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := file.read(); err == nil || !strings.Contains(err.Error(), "is not the regular file it was") {
		t.Fatalf("the descriptor and the entry differ: %v", err)
	}
}

// A lock already there is trusted only as the regular file it names: a
// link, or a file put in its place between the open and the judgment, is
// refused. (A lock owned by another user is refused by the same rule and
// cannot be made without root.)
func TestAnExistingLockIsJudged(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, ``)
	lock := f.config + ".lock"
	if err := os.WriteFile(filepath.Join(f.dir, "elsewhere.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere.lock", lock); err != nil {
		t.Skipf("no symbolic links here: %v", err)
	}
	_, err := connect(context.Background(), f.request(), f.host, f.check)
	if err == nil || !strings.Contains(err.Error(), "engine.json.lock is not the regular file it names") || len(f.asked) != 0 {
		t.Fatalf("a link is not a lock: %v", err)
	}
	os.Remove(lock)
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	lockOpened = func() {
		lockOpened = nil
		os.Remove(lock)
		os.WriteFile(lock, nil, 0o600) // another inode in its place
	}
	defer func() { lockOpened = nil }()
	_, err = connect(context.Background(), f.request(), f.host, f.check)
	if err == nil || !strings.Contains(err.Error(), "engine.json.lock is not the regular file it names") {
		t.Fatalf("a lock replaced under the open is not held: %v", err)
	}
	// The lock as it should be, left by an earlier connect, is taken.
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err != nil {
		t.Fatalf("an existing lock of this user's is taken: %v", err)
	}
}

// Where serve must make or write something, this process must be
// allowed to: a store it may not write in, or a registry it may not
// write, ends the connect before any check; a store, registry or
// decision-record directory to be made in a directory this process may
// not write in is refused the same.
func TestConnectJudgesWhatServeMayWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may write anything")
	}
	f := newConnectFixture(t, restrictedBinding, ``)
	store := storeOf(t, f)
	if err := os.MkdirAll(store, 0o500); err != nil {
		t.Fatal(err)
	}
	before := f.fileText(t)
	_, err := connect(context.Background(), f.request(), f.host, f.check)
	if err == nil || !strings.Contains(err.Error(), "store "+store+": artifacts cannot be made: this process may not write in the store") || len(f.asked) != 0 || f.fileText(t) != before {
		t.Fatalf("a store this process may not write in: %v (asked %d)", err, len(f.asked))
	}
	os.Chmod(store, 0o700)
	// A store directory that is there but not writable.
	if err := os.Mkdir(filepath.Join(store, "artifacts"), 0o500); err != nil {
		t.Fatal(err)
	}
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err == nil || !strings.Contains(err.Error(), "store "+store+": this process may not write in artifacts") || len(f.asked) != 0 {
		t.Fatalf("an artifacts directory this process may not write in: %v", err)
	}
	os.Chmod(filepath.Join(store, "artifacts"), 0o700)
	os.RemoveAll(store)
	registry := strings.TrimSuffix(store, "store") + "registry.jsonl"
	if err := os.WriteFile(registry, nil, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err == nil || !strings.Contains(err.Error(), "registry "+registry+": this process may not write it") || len(f.asked) != 0 {
		t.Fatalf("a registry this process may not write: %v", err)
	}
	os.Remove(registry)
	// Absent, to be made in a directory this process may not write in.
	held := filepath.Join(t.TempDir(), "held")
	if err := os.Mkdir(held, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(held, 0o700)
	decisions := strings.TrimSuffix(store, "store") + "decisions"
	for name, args := range map[string][3]string{
		"store":           {filepath.Join(held, "store"), registry, decisions},
		"registry":        {store, filepath.Join(held, "registry.jsonl"), decisions},
		"decisionRecords": {store, registry, filepath.Join(held, "decisions")},
	} {
		err := preflightPaths(args[0], args[1], args[2])
		if err == nil || !strings.Contains(err.Error(), name+" "+filepath.Join(held, filepath.Base(args[map[string]int{"store": 0, "registry": 1, "decisionRecords": 2}[name]]))+" cannot be made: this process may not write in its directory") {
			t.Fatalf("%s to be made where this process may not write: %v", name, err)
		}
	}
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err != nil || len(f.asked) != 2 {
		t.Fatalf("with everything to be made or written: %v (asked %d)", err, len(f.asked))
	}
}

// A lookup that fails for another reason than absence -- a path under a
// regular file -- is not absence: it is reported as it failed, not taken
// for a path to be made.
func TestPreflightReportsALookupThatFails(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(file, "store")
	err := preflightPaths(store, filepath.Join(dir, "registry.jsonl"), filepath.Join(dir, "decisions"))
	if err == nil || !strings.HasPrefix(err.Error(), "store "+store+": ") || !strings.Contains(err.Error(), "not a directory") || strings.Contains(err.Error(), "cannot be made") {
		t.Fatalf("a lookup under a file: %v", err)
	}
}
