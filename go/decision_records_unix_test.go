//go:build unix

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
)

// recordsHost is the host as serve sees it, with the owners of some paths
// stood in for, since a test cannot make a file another user owns.
func recordsHost(owners map[string]int) engineHost {
	return engineHost{euid: os.Geteuid(), readLink: os.Readlink, fileOwner: func(path string) (fileOwnership, error) {
		owner, err := fileOwnerOf(path)
		if uid, ok := owners[path]; ok && err == nil {
			owner.uid = uid
		}
		return owner, err
	}}
}

// recordsTree makes the given paths under a directory of its own, at the
// given modes whatever the umask, and returns that directory.
func recordsTree(t *testing.T, modes map[string]os.FileMode) string {
	t.Helper()
	// The directory's real path, since the walk resolves a link on the way
	// (macOS's /var) and the owners stood in for are named by real paths.
	base, err := filepath.EvalSymlinks(tempDirAt(t, 0o755))
	if err != nil {
		t.Fatal(err)
	}
	// Made shallowest first, so a file's directory is there; the modes are
	// set deepest first, so a directory made private does not stop a chmod
	// beneath it.
	paths := make([]string, 0, len(modes))
	for rel := range modes {
		paths = append(paths, rel)
	}
	sort.Slice(paths, func(i, j int) bool { return strings.Count(paths[i], "/") < strings.Count(paths[j], "/") })
	for _, rel := range paths {
		path := filepath.Join(base, filepath.FromSlash(rel))
		if modes[rel].IsDir() {
			if err := os.MkdirAll(path, 0o700); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for i := len(paths) - 1; i >= 0; i-- {
		if err := os.Chmod(filepath.Join(base, filepath.FromSlash(paths[i])), modes[paths[i]]&(os.ModePerm|os.ModeSticky)); err != nil {
			t.Fatal(err)
		}
	}
	return base
}

func expectRecordsRefused(t *testing.T, name, dir string, host engineHost, want string) {
	t.Helper()
	if err := holdDecisionRecords(dir, host); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("%s: want %q, got %v", name, want, err)
	}
}

// The decision-record directory, and everything the walk reads beneath it,
// must be writable by its owner alone, and so must every directory on the
// way to it unless the sticky bit keeps others from replacing what they do
// not own. An ordinary private directory, under a sticky /tmp-like parent
// or not, is accepted.
func TestTheDecisionRecordDirectoryIsWritableByItsOwnerAlone(t *testing.T) {
	host := recordsHost(nil)
	dir := os.ModeDir
	base := recordsTree(t, map[string]os.FileMode{"records": dir | 0o700, "records/evaluations.jsonl": 0o600, "records/a": dir | 0o750, "records/a/b.jsonl": 0o644})
	if err := holdDecisionRecords(filepath.Join(base, "records"), host); err != nil {
		t.Fatalf("a private directory: %v", err)
	}
	for name, modes := range map[string]map[string]os.FileMode{
		"group-writable":            {"records": dir | 0o770},
		"other-writable":            {"records": dir | 0o702},
		"sticky and other-writable": {"records": dir | os.ModeSticky | 0o777},
	} {
		base := recordsTree(t, modes)
		expectRecordsRefused(t, name, filepath.Join(base, "records"), host, "is writable beyond its owner")
	}
	ancestor := recordsTree(t, map[string]os.FileMode{"shared": dir | 0o777, "shared/records": dir | 0o700})
	expectRecordsRefused(t, "a writable ancestor", filepath.Join(ancestor, "shared", "records"), host, filepath.Join(ancestor, "shared")+" is writable beyond its owner (mode 0777) without the sticky bit")
	sticky := recordsTree(t, map[string]os.FileMode{"tmp": dir | os.ModeSticky | 0o777, "tmp/records": dir | 0o700})
	if err := holdDecisionRecords(filepath.Join(sticky, "tmp", "records"), host); err != nil {
		t.Fatalf("a private directory under a sticky parent: %v", err)
	}
	for name, modes := range map[string]map[string]os.FileMode{
		"a group-writable directory beneath": {"records": dir | 0o700, "records/a": dir | 0o770},
		"an other-writable file beneath":     {"records": dir | 0o700, "records/evaluations.jsonl": 0o606},
		"a group-writable file two deep":     {"records": dir | 0o700, "records/a": dir | 0o700, "records/a/b": dir | 0o700, "records/a/b/c.jsonl": 0o660},
	} {
		base := recordsTree(t, modes)
		expectRecordsRefused(t, name, filepath.Join(base, "records"), host, "so another user could write a record there")
	}
	// What the walk passes over is passed over here: a link, to however
	// open a directory, and a FIFO.
	passed := recordsTree(t, map[string]os.FileMode{"records": dir | 0o700, "open": dir | 0o777})
	if err := os.Symlink(filepath.Join(passed, "open"), filepath.Join(passed, "records", "link")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(passed, "records", "fifo"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := holdDecisionRecords(filepath.Join(passed, "records"), host); err != nil {
		t.Fatalf("a link and a FIFO beneath: %v", err)
	}
}

// A directory not there yet is made by whoever writes there first, so its
// parent must be writable by its owner alone, sticky or not, and held on
// the way as the directory would be; a parent that is a link is refused.
func TestADecisionRecordDirectoryNotThereIsHeldThroughItsParent(t *testing.T) {
	host := recordsHost(nil)
	dir := os.ModeDir
	private := recordsTree(t, map[string]os.FileMode{"parent": dir | 0o700})
	if err := holdDecisionRecords(filepath.Join(private, "parent", "records"), host); err != nil {
		t.Fatalf("under a private parent: %v", err)
	}
	sticky := recordsTree(t, map[string]os.FileMode{"tmp": dir | os.ModeSticky | 0o777})
	expectRecordsRefused(t, "under a sticky parent", filepath.Join(sticky, "tmp", "records"), host, "another user could make it first")
	open := recordsTree(t, map[string]os.FileMode{"shared": dir | 0o777, "shared/parent": dir | 0o700})
	expectRecordsRefused(t, "under a writable grandparent", filepath.Join(open, "shared", "parent", "records"), host, filepath.Join(open, "shared")+" is writable beyond its owner")
	linked := recordsTree(t, map[string]os.FileMode{"real": dir | 0o700})
	if err := os.Symlink(filepath.Join(linked, "real"), filepath.Join(linked, "link")); err != nil {
		t.Fatal(err)
	}
	expectRecordsRefused(t, "under a parent that is a link", filepath.Join(linked, "link", "records"), host, "is a symbolic link; name the directory where it is")
	// What preflightPaths refuses is left to it: no parent, or a file
	// where the directory should be.
	if err := holdDecisionRecords(filepath.Join(private, "absent", "records"), host); err != nil {
		t.Fatalf("no parent is preflightPaths' to refuse: %v", err)
	}
	file := recordsTree(t, map[string]os.FileMode{"records": 0o666})
	if err := holdDecisionRecords(filepath.Join(file, "records"), host); err != nil {
		t.Fatalf("a file is preflightPaths' to refuse: %v", err)
	}
}

// Who may own what: root, the signer and the directory's owner, whom the
// runtime writes as, and nobody else, on the way to the directory and
// beneath it.
func TestOnlyRootTheSignerAndTheOwnerMayOwnTheDecisionRecords(t *testing.T) {
	dir := os.ModeDir
	base := recordsTree(t, map[string]os.FileMode{"by-signer": dir | 0o755, "by-signer/records": dir | 0o700, "by-signer/records/mine.jsonl": 0o600, "by-signer/records/root.jsonl": 0o600, "by-signer/records/runtime.jsonl": 0o600})
	parent := filepath.Join(base, "by-signer")
	records := filepath.Join(parent, "records")
	const runtimeUser, stranger = 4242, 5151
	owners := map[string]int{records: runtimeUser, filepath.Join(records, "root.jsonl"): 0, filepath.Join(records, "runtime.jsonl"): runtimeUser}
	if err := holdDecisionRecords(records, recordsHost(owners)); err != nil {
		t.Fatalf("a directory the runtime owns, under one the signer owns, holding files of root, the signer and the runtime: %v", err)
	}
	strangerFile := map[string]int{records: runtimeUser, filepath.Join(records, "mine.jsonl"): stranger}
	expectRecordsRefused(t, "a file another user owns", records, recordsHost(strangerFile), "mine.jsonl is owned by uid 5151, neither root, the signer")
	strangerParent := map[string]int{records: runtimeUser, parent: stranger}
	expectRecordsRefused(t, "an ancestor another user owns", records, recordsHost(strangerParent), parent+" is owned by uid 5151")
	absent := filepath.Join(parent, "later")
	if err := holdDecisionRecords(absent, recordsHost(map[string]int{parent: runtimeUser})); err != nil {
		t.Fatalf("a directory not there yet, under one the runtime owns: %v", err)
	}
}

// A link at the decision-record path itself: preflightPaths follows it and
// accepts the directory it leads to, so it is not what holds the link, and
// the walk for a record never follows it. holdDecisionRecords, which serve
// and connect apply first, refuses one root does not own, and holds the
// directory a root-owned one is in as it holds the parent of a directory
// not there yet, since whoever may write that directory could put a
// directory of records in the link's place.
func TestALinkAtTheDecisionRecordPathIsHeld(t *testing.T) {
	dir := os.ModeDir
	base := recordsTree(t, map[string]os.FileMode{"open": dir | 0o777, "private": dir | 0o700, "real": dir | 0o700, "real/evaluations.jsonl": 0o600})
	exposed := filepath.Join(base, "open", "records")
	sheltered := filepath.Join(base, "private", "records")
	for _, link := range []string{exposed, sheltered} {
		if err := os.Symlink(filepath.Join(base, "real"), link); err != nil {
			t.Fatal(err)
		}
	}
	store, registry := filepath.Join(base, "private", "store"), filepath.Join(base, "private", "registry.jsonl")
	if err := preflightPaths(store, registry, exposed); err != nil {
		t.Fatalf("preflightPaths follows a link at the path and accepts where it leads: %v", err)
	}
	// start judges the path as serve and connect do: the refusals,
	// holdDecisionRecords among them, and then preflightPaths.
	start := func(records string, host engineHost) error {
		if err := holdDecisionRecords(records, host); err != nil {
			return err
		}
		return preflightPaths(store, registry, records)
	}
	if os.Geteuid() != 0 {
		if err := start(exposed, recordsHost(nil)); err == nil || !strings.Contains(err.Error(), exposed+" is a symbolic link owned by uid") {
			t.Fatalf("a link root does not own: %v", err)
		}
		if err := start(sheltered, recordsHost(nil)); err == nil || !strings.Contains(err.Error(), "not root") {
			t.Fatalf("a link root does not own, in a private directory: %v", err)
		}
	}
	rootLinks := map[string]int{exposed: 0, sheltered: 0}
	if err := start(exposed, recordsHost(rootLinks)); err == nil ||
		!strings.Contains(err.Error(), filepath.Join(base, "open")+", is writable beyond its owner (mode 0777), so another user could put a directory of records in its place") {
		t.Fatalf("a root-owned link in a directory others may write: %v", err)
	}
	if err := start(sheltered, recordsHost(rootLinks)); err != nil {
		t.Fatalf("a root-owned link in a private directory: %v", err)
	}
}

// Root's ownership excuses no mode: a root-owned directory on the way that
// its group may write, a root-owned records directory its group may write
// or that is sticky and anyone may write, and a root-owned file beneath its
// group may write are each refused.
func TestRootOwnershipExcusesNoWritableMode(t *testing.T) {
	dir := os.ModeDir
	base := recordsTree(t, map[string]os.FileMode{"shared": dir | 0o775, "shared/records": dir | 0o700})
	shared := filepath.Join(base, "shared")
	expectRecordsRefused(t, "a root-owned ancestor its group may write", filepath.Join(shared, "records"), recordsHost(map[string]int{shared: 0}), shared+" is writable beyond its owner (mode 0775) without the sticky bit")
	// The records directory's own rule is the one the sticky bit does not
	// excuse, so a sticky one shows it: the walk on the way would pass it.
	for name, mode := range map[string]os.FileMode{"its group may write": dir | 0o770, "sticky, that anyone may write": dir | os.ModeSticky | 0o777} {
		own := recordsTree(t, map[string]os.FileMode{"records": mode})
		records := filepath.Join(own, "records")
		expectRecordsRefused(t, "a root-owned records directory "+name, records, recordsHost(map[string]int{records: 0}), records+" is writable beyond its owner (mode "+fmt.Sprintf("%04o", mode.Perm())+"), so another user could write a record in it")
	}
	beneath := recordsTree(t, map[string]os.FileMode{"records": dir | 0o700, "records/root.jsonl": 0o664})
	file := filepath.Join(beneath, "records", "root.jsonl")
	expectRecordsRefused(t, "a root-owned file its group may write", filepath.Join(beneath, "records"), recordsHost(map[string]int{file: 0}), file+" is writable beyond its owner (mode 0664)")
}
