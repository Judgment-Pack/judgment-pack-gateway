package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

// heldTree is a walk of the decision-record directory by handle, never by
// path. Its root is held first, as the directory the walk was named by
// (holdRoot); every directory beneath it is enumerated through the handle of
// the directory above it and held in turn (holdDir); and every file is
// opened through the handle of its directory (readEntry). Each directory and
// each file is judged as the entry it is -- not a link, and the thing opened
// the entry's own, before the open and again after it -- so a link put in
// place of the root, of a directory or of a file, at any moment, is either
// found and refused, or put where the walk no longer looks: what the walk
// reads is beneath the root it judged. No name the walk judged is ever read
// again by a path.
type heldTree struct {
	base string // the root, as the walk's caller spelled it
	root *os.Root
}

// walkEntryJudged, when set, runs between judging an entry of the walk --
// the root as "", a directory or a file by its slash-separated path under
// the root -- and opening it: a test's way of putting a link in its place
// at that moment.
var walkEntryJudged func(rel string)

// holdRoot holds the directory base names: not a link, and the directory
// opened the one judged, before the open and after it. It returns nil, and
// no error, when base names a link, which the walk never follows.
func holdRoot(base string) (*heldTree, error) {
	entry, err := os.Lstat(base)
	if err != nil {
		return nil, err
	}
	if entry.Mode()&os.ModeSymlink != 0 {
		return nil, nil
	}
	if !entry.IsDir() {
		return nil, fmt.Errorf("decision-record path is not a directory: %s", base)
	}
	if walkEntryJudged != nil {
		walkEntryJudged("")
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err == nil {
		var after os.FileInfo
		after, err = os.Lstat(base)
		if err == nil && (after.Mode()&os.ModeSymlink != 0 || !os.SameFile(entry, opened) || !os.SameFile(after, opened)) {
			err = errors.New("is no longer the directory the walk judged")
		}
	}
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("the decision-record directory %s: %w", base, err)
	}
	return &heldTree{base: base, root: root}, nil
}

func (h *heldTree) close() { h.root.Close() }

// walk hands visit every regular file beneath the root, depth first, the
// entries of each directory in the order of their names: its path, as the
// root's spelling joined with the names on the way, its name, and its
// bytes. A link is passed over, never followed, and so is anything that is
// neither a directory nor a regular file.
func (h *heldTree) walk(visit func(path, name string, data []byte) error) error {
	return h.walkDir(h.root, h.base, "", visit)
}

func (h *heldTree) walkDir(dir *os.Root, path, rel string, visit func(path, name string, data []byte) error) error {
	listed, err := dir.Open(".")
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	entries, err := listed.ReadDir(-1)
	listed.Close()
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		name := e.Name()
		at, atRel := filepath.Join(path, name), name
		if rel != "" {
			atRel = rel + "/" + name
		}
		// a name Windows would not read as spelled is read as another file
		// or none: it cannot be read, and is no verdict (§4.1)
		if runtime.GOOS == "windows" && !windowsReadsAsSpelled(name) {
			return fmt.Errorf("decision-record directory holds a name Windows would not read as spelled: %s", at)
		}
		switch kind := e.Type(); {
		case kind&fs.ModeSymlink != 0:
			// never followed, whatever it points at
		case kind.IsDir():
			held, err := holdDir(dir, name, atRel)
			if err != nil {
				return fmt.Errorf("%s: %w", at, err)
			}
			err = h.walkDir(held, at, atRel, visit)
			held.Close()
			if err != nil {
				return err
			}
		case kind.IsRegular():
			data, err := readEntry(dir, name, atRel)
			if err != nil {
				return fmt.Errorf("%s: %w", at, err)
			}
			if err := visit(at, name, data); err != nil {
				return err
			}
		}
	}
	return nil
}

// holdDir holds the directory name in parent: not a link, and the directory
// opened the one judged, before the open and after it.
func holdDir(parent *os.Root, name, rel string) (*os.Root, error) {
	entry, err := parent.Lstat(name)
	if err != nil {
		return nil, err
	}
	if entry.Mode()&os.ModeSymlink != 0 || !entry.IsDir() {
		return nil, errors.New("is no longer the directory the walk found")
	}
	if walkEntryJudged != nil {
		walkEntryJudged(rel)
	}
	held, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	opened, err := held.Stat(".")
	if err == nil {
		var after os.FileInfo
		after, err = parent.Lstat(name)
		if err == nil && (after.Mode()&os.ModeSymlink != 0 || !os.SameFile(entry, opened) || !os.SameFile(after, opened)) {
			err = errors.New("is no longer the directory the walk found")
		}
	}
	if err != nil {
		held.Close()
		return nil, err
	}
	return held, nil
}

// readEntry reads the regular file name in dir, opened as the entry it is
// (openEntryJudged).
func readEntry(dir *os.Root, name, rel string) ([]byte, error) {
	var judged func(string)
	if walkEntryJudged != nil {
		judged = func(string) { walkEntryJudged(rel) }
	}
	file, info, err := openEntryJudged(dir, name, judged)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if !info.Mode().IsRegular() {
		return nil, errors.New("is no longer the regular file the walk found")
	}
	return io.ReadAll(file)
}
