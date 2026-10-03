package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// heldTree reads the files a walk of the decision-record directory finds as
// the entries the walk found: each through directories held one at a time
// from the walk's root, every directory and the file itself judged as the
// entry it is -- not a link, and the thing opened the entry's own, before
// the open and again after it (openEntryJudged). The walk enumerates by
// path, and a name it judged a regular file, or a directory it passed
// through, can be put back as a link before the read; a read that would
// then pass through a link is refused, so it is no verdict, never a read of
// what the link points at. A held directory is kept for the walk, so a name
// swapped after it is held changes nothing that is read through it.
type heldTree struct {
	base string // the walk's root, as the walk spells its paths
	root *os.Root
	dirs map[string]*os.Root // by slash-separated path under the root; "" is the root
}

// walkEntryJudged, when set, runs between judging an entry of the walk -- a
// directory or a file, by its slash-separated path under the walk's root --
// and opening it: a test's way of putting a link in its place at that
// moment.
var walkEntryJudged func(rel string)

func newHeldTree(base string) *heldTree {
	return &heldTree{base: base, dirs: map[string]*os.Root{}}
}

// close releases every directory the walk held.
func (h *heldTree) close() {
	for _, d := range h.dirs {
		d.Close()
	}
	if h.root != nil {
		h.root.Close()
	}
}

// dir is the held directory at rel, holding each directory on the way.
func (h *heldTree) dir(rel string) (*os.Root, error) {
	if rel == "" {
		if h.root == nil {
			root, err := os.OpenRoot(h.base)
			if err != nil {
				return nil, err
			}
			h.root = root
		}
		return h.root, nil
	}
	if held, ok := h.dirs[rel]; ok {
		return held, nil
	}
	parentRel, name := path.Split(rel)
	parent, err := h.dir(strings.TrimSuffix(parentRel, "/"))
	if err != nil {
		return nil, err
	}
	entry, err := parent.Lstat(name)
	if err != nil {
		return nil, err
	}
	if entry.Mode()&os.ModeSymlink != 0 || !entry.IsDir() {
		return nil, fmt.Errorf("%s is no longer the directory the walk passed through", rel)
	}
	if walkEntryJudged != nil {
		walkEntryJudged(rel)
	}
	held, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	opened, err := held.Stat(".")
	if err != nil {
		held.Close()
		return nil, err
	}
	after, err := parent.Lstat(name)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(entry, opened) || !os.SameFile(after, opened) {
		held.Close()
		return nil, fmt.Errorf("%s is no longer the directory the walk passed through", rel)
	}
	h.dirs[rel] = held
	return held, nil
}

// read is the bytes of the regular file at path, a path the walk spelled
// under its root, read as the entry it is.
func (h *heldTree) read(p string) ([]byte, error) {
	rel, err := filepath.Rel(h.base, p)
	if err != nil {
		return nil, err
	}
	rel = filepath.ToSlash(rel)
	if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return nil, fmt.Errorf("%s is not under the walk's root", p)
	}
	dirRel, name := path.Split(rel)
	held, err := h.dir(strings.TrimSuffix(dirRel, "/"))
	if err != nil {
		return nil, err
	}
	var judged func(string)
	if walkEntryJudged != nil {
		judged = func(string) { walkEntryJudged(rel) }
	}
	file, info, err := openEntryJudged(held, name, judged)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", rel, err)
	}
	defer file.Close()
	if !info.Mode().IsRegular() {
		return nil, errors.New(rel + " is no longer the regular file the walk found")
	}
	return io.ReadAll(file)
}
