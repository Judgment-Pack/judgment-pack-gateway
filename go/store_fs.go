package main

// The filesystem kind (docs/design/store-contract.md): the store contract
// kept in files, as the gateway has always kept them. Each space here is
// the code that wrote and read those files before the contract stood in
// front of it, moved and not changed, so the receipts, the artifacts, the
// registry, the witness's files and the descriptor snapshots are the same
// bytes, made by the same calls in the same order. The checks of paths,
// links and owners stay here and in the holders that open what a space is
// given (the configuration's snapshots' directory, the witness's held
// files); nothing above a space names a path to it.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Every space of the filesystem kind is a space of the contract.
var (
	_ blobSpace     = fsBlobs{}
	_ blobSpace     = fsHeldPins{}
	_ indexedSpace  = fsIndexed{}
	_ appendLog     = (*fsLog)(nil)
	_ appendLog     = fsHeldLog{}
	_ documentSpace = fsDocuments{}
	_ secretSpace   = fsSecrets{}
	_ leaseSpace    = documentLeases{}
	_ storeKind     = (*fsKind)(nil)
)

// validStoreName reports whether a name is one a space may keep: a flat
// token, the session rule of SPEC.md §3a, never "." or "..".
func validStoreName(name string) bool {
	return sessionPattern.MatchString(name) && name != "." && name != ".."
}

// fsWriteFile puts bytes at near: written to a staging file beside it,
// synced, and then renamed over near, or, with exclusive set, linked to it
// -- which refuses a name that is there, and is what makes the receipt log
// append-only. The directory is synced after, as far as the platform can
// (syncDir).
func fsWriteFile(near string, data []byte, exclusive bool) error {
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return storeFailure(faultDurability, "write", err)
	}
	tmp := fmt.Sprintf("%s.%d.%s.tmp", near, os.Getpid(), hex.EncodeToString(suffix[:]))
	handle, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		// a directory that is not there -- a series never made -- took
		// nothing: absent, not a write that may have been kept. Absent
		// only where a look at the directory confirms it (absent(): on
		// Windows a staging open under a file answers "not found" too,
		// and a directory that cannot be reached is not one that is not
		// there)
		if errors.Is(err, fs.ErrNotExist) {
			if _, lookErr := os.Lstat(filepath.Dir(near)); lookErr != nil && absent(lookErr) {
				return storeFailure(faultAbsent, "write", err)
			}
		}
		return storeFailure(faultDurability, "write", err)
	}
	if _, err := handle.Write(data); err != nil {
		handle.Close()
		os.Remove(tmp)
		return storeFailure(faultDurability, "write", err)
	}
	if err := syncStaged(handle); err != nil {
		handle.Close()
		os.Remove(tmp)
		return storeFailure(faultDurability, "write", err)
	}
	if err := handle.Close(); err != nil {
		os.Remove(tmp)
		return storeFailure(faultDurability, "write", err)
	}
	defer os.Remove(tmp)
	if exclusive {
		if err := os.Link(tmp, near); err != nil {
			if errors.Is(err, os.ErrExist) {
				return storeFailure(faultTaken, "create", fmt.Errorf("receipt already exists (append-only): %s", near))
			}
			return storeFailure(faultDurability, "create", err)
		}
	} else if err := os.Rename(tmp, near); err != nil {
		return storeFailure(faultDurability, "write", err)
	}
	syncDir(filepath.Dir(near))
	return nil
}

// stagedSync, when set, stands in for the sync of fsWriteFile's staging
// file: a test's way of seeing that sync, and of failing it.
var stagedSync func(*os.File) error

// syncStaged makes a staging file's bytes durable before its name is put
// in place.
func syncStaged(file *os.File) error {
	if stagedSync != nil {
		return stagedSync(file)
	}
	return file.Sync()
}

// syncDir syncs a directory as far as the platform can: a platform that
// cannot sync a directory (Windows) or a directory that cannot be opened
// leaves the entry's durability to the filesystem, as it always has.
func syncDir(path string) {
	handle, err := os.Open(path)
	if err != nil {
		return
	}
	defer handle.Close()
	_ = handle.Sync()
}

// fsBlobs keeps blobs as files in a directory, each named by its digest's
// hex: the store's artifacts directory (SPEC.md §1.3).
type fsBlobs struct{ dir string }

func blobHex(name string) (string, bool) {
	hexSum, ok := strings.CutPrefix(name, "sha256:")
	return hexSum, ok && isLowerHexOfLen(hexSum, 64)
}

func (b fsBlobs) putBlob(data []byte) (string, error) {
	sum := sha256.Sum256(data)
	hexSum := hex.EncodeToString(sum[:])
	if err := fsWriteFile(filepath.Join(b.dir, hexSum), data, false); err != nil {
		return "", err
	}
	return "sha256:" + hexSum, nil
}

// readOwnFile reads the regular file a name holds, never through a link:
// a link in its place is refused, unless it leads nowhere, which is the
// absence verification finds there; anything else that is no regular
// file is refused before it is opened. The entry is judged before the open
// and again after it, each time as the file opened, so a link put in its
// place meanwhile is found.
func readOwnFile(op, path string) ([]byte, error) {
	entry, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, storeFailure(faultAbsent, op, err)
		}
		return nil, storeFailure(faultUnreadable, op, err)
	}
	if entry.Mode()&os.ModeSymlink != 0 {
		if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
			return nil, storeFailure(faultAbsent, op, err)
		}
		return nil, storeFailure(faultRefused, op, fmt.Errorf("store: %s is a link, and no file is read through one", path))
	}
	if !entry.Mode().IsRegular() {
		return nil, storeFailure(faultRefused, op, fmt.Errorf("store: %s is not a regular file", path))
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, storeFailure(faultUnreadable, op, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, storeFailure(faultUnreadable, op, err)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(entry, opened) || !os.SameFile(after, opened) {
		return nil, storeFailure(faultRefused, op, fmt.Errorf("store: %s is not the file its name held a moment ago", path))
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, storeFailure(faultUnreadable, op, err)
	}
	return data, nil
}

// getBlob reads the blob's own file (readOwnFile): a link in its place is
// refused, and one that leads nowhere is absent, as verification finds
// such an artifact missing.
func (b fsBlobs) getBlob(name string) ([]byte, error) {
	hexSum, ok := blobHex(name)
	if !ok {
		return nil, storeFailure(faultRefused, "get-blob", fmt.Errorf("store: %q is not a blob's name", name))
	}
	return readOwnFile("get-blob", filepath.Join(b.dir, hexSum))
}

// listBlobs names every entry of the directory that is no directory and is
// named as a blob is: a staging file is none.
func (b fsBlobs) listBlobs() ([]string, error) {
	entries, err := os.ReadDir(b.dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, storeFailure(faultUnreadable, "list-blobs", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && isLowerHexOfLen(e.Name(), 64) {
			names = append(names, "sha256:"+e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// fsIndexed keeps each series as a directory under root and each entry as
// <index>.json in it: the store's receipts directory (SPEC.md §1.3, §3a).
type fsIndexed struct{ root string }

// seriesDir is the series' directory, refused when it would not be a
// directory directly under root. The session rule (SPEC.md §3a) already
// keeps a session id from escaping; this is defence in depth, so nothing is
// ever written outside the root a verifier enumerates, even if that rule is
// loosened.
func (x fsIndexed) seriesDir(series string) (string, error) {
	dir := filepath.Join(x.root, series)
	resolved, err := filepath.Abs(dir)
	if err != nil {
		return "", storeFailure(faultRefused, "series", err)
	}
	rootAbs, err := filepath.Abs(x.root)
	if err != nil {
		return "", storeFailure(faultRefused, "series", err)
	}
	if filepath.Dir(resolved) != rootAbs {
		return "", storeFailure(faultRefused, "series", errors.New("session directory escapes the receipt store"))
	}
	return dir, nil
}

// makeSeries makes the series' directory exclusively, so a directory
// another process put there first -- at any moment before this call -- is
// found and never taken for this call's own. The root is made first where
// it is not there.
func (x fsIndexed) makeSeries(series string) (bool, error) {
	dir, err := x.seriesDir(series)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(x.root, 0o755); err != nil {
		return false, storeFailure(faultDurability, "make-series", err)
	}
	switch err := os.Mkdir(dir, 0o755); {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrExist):
		// Something is there already: a series this process or another
		// made, or an entry of another kind, which the create below
		// answers for. Not this call's own either way.
		return false, nil
	default:
		return false, storeFailure(faultDurability, "make-series", err)
	}
}

func (x fsIndexed) createIndexed(series string, index int64, data []byte) error {
	dir, err := x.seriesDir(series)
	if err != nil {
		return err
	}
	return fsWriteFile(filepath.Join(dir, fmt.Sprintf("%d.json", index)), data, true)
}

// listSeries names the directories under root, as verification enumerates
// sessions (listSessions): no root is no series.
func (x fsIndexed) listSeries() ([]string, error) {
	info, err := os.Stat(x.root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, storeFailure(faultUnreadable, "list-series", err)
	}
	if !info.IsDir() {
		return nil, storeFailure(faultUnreadable, "list-series", fmt.Errorf("receipts path is not a directory: %s", x.root))
	}
	entries, err := os.ReadDir(x.root)
	if err != nil {
		return nil, storeFailure(faultUnreadable, "list-series", err)
	}
	var series []string
	for _, e := range entries {
		if e.IsDir() {
			series = append(series, e.Name())
		}
	}
	sort.Strings(series)
	return series, nil
}

// listEntries names the series' .json files by their stems, as
// verification counts them (verifySession): every one, whatever its stem.
func (x fsIndexed) listEntries(series string) ([]string, error) {
	dir, err := x.seriesDir(series)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, storeFailure(faultAbsent, "list-entries", err)
		}
		return nil, storeFailure(faultUnreadable, "list-entries", err)
	}
	var stems []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			stems = append(stems, strings.TrimSuffix(e.Name(), ".json"))
		}
	}
	sort.Strings(stems)
	return stems, nil
}

func (x fsIndexed) getEntry(series, entry string) ([]byte, error) {
	dir, err := x.seriesDir(series)
	if err != nil {
		return nil, err
	}
	if entry == "" || strings.ContainsAny(entry, `/\`) {
		return nil, storeFailure(faultRefused, "get-entry", fmt.Errorf("store: %q is not an entry's name", entry))
	}
	// the entry's own file, as for a blob (readOwnFile)
	return readOwnFile("get-entry", filepath.Join(dir, entry+".json"))
}

// fsLog is the filesystem kind's log in a file of its own: the seal
// registry, read through verification's own classifier (readRegistryBytes,
// SPEC.md §4.1) and appended to at its end.
type fsLog struct {
	path string
	// write appends a record's bytes and sync makes them durable; a test
	// stands in a failure for either
	write func(*os.File, []byte) (int, error)
	sync  func(*os.File) error
}

func newFsLog(path string) *fsLog {
	return &fsLog{
		path:  path,
		write: func(f *os.File, data []byte) (int, error) { return f.Write(data) },
		sync:  func(f *os.File) error { return f.Sync() },
	}
}

// openFsLog is the log a writer appends to: the path is read by its
// spelling, so it is written by its spelling too, and a spelling the
// platform could resolve otherwise is refused before a directory is made
// for it (SPEC.md §4.1). The directory it is in is made where it is not
// there.
func openFsLog(path string) (*fsLog, error) {
	if err := requirePlainSpelling(path, true); err != nil {
		return nil, storeFailure(faultRefused, "open-log", err)
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, storeFailure(faultDurability, "open-log", err)
		}
	}
	return newFsLog(path), nil
}

// readLog reads the log as verification reads the registry: a log that is
// there and cannot be read -- a link to nothing, a directory, a share that
// cannot be reached -- is no empty log.
func (l *fsLog) readLog(from int64) ([]byte, error) {
	data, present, err := readRegistryBytes(l.path)
	if err != nil {
		return nil, storeFailure(faultUnreadable, "read-log", err)
	}
	if !present {
		return nil, storeFailure(faultAbsent, "read-log", nil)
	}
	if from < 0 || from > int64(len(data)) {
		return nil, storeFailure(faultRefused, "read-log", fmt.Errorf("store: cursor %d is not within the log's %d bytes", from, len(data)))
	}
	return data[from:], nil
}

// createLog makes the log, empty, only where nothing is: never through a
// link to nothing, which an exclusive create does not follow.
func (l *fsLog) createLog() error {
	made, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return storeFailure(faultTaken, "create-log", err)
		}
		return storeFailure(faultDurability, "create-log", err)
	}
	if err := made.Close(); err != nil {
		return storeFailure(faultDurability, "create-log", err)
	}
	return nil
}

// appendRecord appends at the log's end. The log is there (a caller read
// it); an open that would create it could only follow a log that went away
// between that read and this open, so none is made here.
func (l *fsLog) appendRecord(data []byte) (int, error) {
	handle, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		// a log that is not there took nothing: absent where a look at
		// the log's own name confirms it (absent(), as the registry's
		// reader confirms an absence); anything else may be a write the
		// platform could not make, and stays durability
		fault := faultDurability
		if errors.Is(err, fs.ErrNotExist) {
			if _, lookErr := os.Lstat(l.path); lookErr != nil && absent(lookErr) {
				fault = faultAbsent
			}
		}
		return 0, &storeError{fault: fault, op: "append", err: err}
	}
	defer handle.Close()
	n, err := l.write(handle, data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return n, &storeError{fault: faultDurability, op: "append", written: n, err: err}
	}
	if err := l.sync(handle); err != nil {
		return n, &storeError{fault: faultDurability, op: "append", written: n, committing: true, err: err}
	}
	return n, nil
}

// fsHeldLog is the filesystem kind's log over a file held open to append,
// by the one who judged and locked it: a witness's log, marks and
// registrations (witness_log.go). Every write and sync goes through the
// witness's I/O seam, so the order its tests and recovery vectors hold is
// the order kept here.
type fsHeldLog struct {
	label string
	file  *os.File
	io    witnessIO
}

// appendRecord writes data whole -- a short write is a failure -- and then
// syncs the file.
func (l fsHeldLog) appendRecord(data []byte) (int, error) {
	n, err := l.io.write(l.label, l.file, data)
	if err == nil && n != len(data) {
		err = errors.New("short write")
	}
	if err != nil {
		return n, &storeError{fault: faultDurability, op: "append", written: n, err: err}
	}
	if err := l.io.sync(l.label, l.file); err != nil {
		return n, &storeError{fault: faultDurability, op: "append", written: n, committing: true, err: err}
	}
	return n, nil
}

// readLog reads the held file from the cursor to the size it has now.
func (l fsHeldLog) readLog(from int64) ([]byte, error) {
	info, err := l.file.Stat()
	if err != nil {
		return nil, storeFailure(faultUnreadable, "read-log", err)
	}
	if from < 0 || from > info.Size() {
		return nil, storeFailure(faultRefused, "read-log", fmt.Errorf("store: cursor %d is not within the log's %d bytes", from, info.Size()))
	}
	data := make([]byte, info.Size()-from)
	if len(data) > 0 {
		if _, err := l.file.ReadAt(data, from); err != nil {
			return nil, storeFailure(faultUnreadable, "read-log", err)
		}
	}
	return data, nil
}

// createLog: a held file is made by its holder (witnessFiles.createHeld),
// as the entry it is, before it is held.
func (l fsHeldLog) createLog() error {
	return storeFailure(faultTaken, "create-log", fmt.Errorf("witness: the %s file is held", l.label))
}

// committed reports whether an append's failure came after its bytes were
// written whole: making them durable is what failed.
func committed(err error) bool {
	var e *storeError
	return errors.As(err, &e) && e.committing
}

// fsHeldPins is the filesystem kind's blob space for descriptor snapshots
// (docs/design/tool-descriptors.md): the snapshots' directory, held open as
// the entry it is by the one who judged it (configFile.holdSnapshotDirectory,
// openServedDirectory), each snapshot a file named by its digest's hex and
// ".json", of the snapshot's mode and an owner the MCP server accepts.
// Every step is in the held directory, so a name swapped for a link to it
// meanwhile changes nothing.
type fsHeldPins struct {
	dir *os.Root
	// name is the directory as a message names it
	name string
	// owner is the owner a snapshot is given, and held to
	owner fileOwnerIDs
	// synced syncs the held directory
	synced func() error
}

func pinFileName(pin string) (string, bool) {
	hexSum, ok := blobHex(pin)
	return hexSum + ".json", ok
}

// putBlob keeps a snapshot, named by its digest: written in the held
// directory under a staging name no snapshot has, given its final mode and
// owner, and synced; then linked to <hex>.json, which never replaces a
// name. A name already taken is reused only when it is a regular file, of
// that mode and owner, that digests to its name, and it is synced. The
// staging name is removed, and the held directory synced.
func (p fsHeldPins) putBlob(data []byte) (string, error) {
	sum := sha256.Sum256(data)
	pin := "sha256:" + hex.EncodeToString(sum[:])
	name := hex.EncodeToString(sum[:]) + ".json"
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", storeFailure(faultDurability, "put-blob", err)
	}
	staged := ".connect-" + hex.EncodeToString(suffix[:]) + ".staged"
	file, err := p.dir.OpenFile(staged, os.O_WRONLY|os.O_CREATE|os.O_EXCL, snapshotMode)
	if err != nil {
		return "", storeFailure(faultDurability, "put-blob", fmt.Errorf("descriptors: %v", err))
	}
	// From here a failure removes the staging name, before the caller lets
	// the held directory go: once it is closed, nothing can be removed in it.
	failStaged := func(fault storeFault, err error) (string, error) {
		p.dir.Remove(staged)
		return "", storeFailure(fault, "put-blob", err)
	}
	written := func() error {
		defer file.Close()
		if _, err := file.Write(data); err != nil {
			return err
		}
		if err := file.Chmod(snapshotMode); err != nil {
			return err
		}
		if err := keepOwner(file, p.owner); err != nil {
			return err
		}
		if err := syncFile(file); err != nil {
			return err
		}
		return file.Close()
	}
	if err := written(); err != nil {
		return failStaged(faultDurability, fmt.Errorf("descriptors: %v", err))
	}
	if err := p.dir.Link(staged, name); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return failStaged(faultDurability, fmt.Errorf("descriptors: %v", err))
		}
		if err := p.taken(name, pin); err != nil {
			return failStaged(faultConflict, err)
		}
	}
	if err := p.dir.Remove(staged); err != nil {
		return "", storeFailure(faultDurability, "put-blob", fmt.Errorf("descriptors: %v", err))
	}
	if err := p.synced(); err != nil {
		return "", storeFailure(faultDurability, "put-blob", fmt.Errorf("descriptors: %s could not be synced: %v", p.name, err))
	}
	return pin, nil
}

// taken judges a snapshot's name already taken in the held directory:
// reused only when what holds it is a regular file, of the snapshot's mode
// and an owner the frontend accepts, that digests to the pin; opened as the
// entry it is (openEntry), judged by what was opened, and synced, since a
// file found may never have reached the disk.
func (p fsHeldPins) taken(name, pin string) error {
	file, info, err := openEntry(p.dir, name)
	if err != nil {
		return fmt.Errorf("descriptors: %s/%s is taken, and is not a file this connect can reuse: %v", p.name, name, err)
	}
	defer file.Close()
	if err := snapshotHeld(info, p.owner, false); err != nil {
		return fmt.Errorf("descriptors: %s/%s is taken by a file that %v", p.name, name, err)
	}
	existing, err := readBoundedFrom(file, name, maxSnapshotBytes)
	if err != nil {
		return fmt.Errorf("descriptors: %v", err)
	}
	sum := sha256.Sum256(existing)
	if "sha256:"+hex.EncodeToString(sum[:]) != pin {
		return fmt.Errorf("descriptors: %s/%s is taken by a file that does not digest to its name", p.name, name)
	}
	if err := syncFound(file); err != nil {
		return fmt.Errorf("descriptors: %s/%s could not be synced: %v", p.name, name, err)
	}
	return nil
}

// getBlob reads the snapshot a pin names, the file opened as the entry it
// is and judged by what was opened -- a regular file of the snapshot's
// mode and an owner the frontend accepts -- and read to the bound. The
// reader digests it before anything parses it.
func (p fsHeldPins) getBlob(pin string) ([]byte, error) {
	name, ok := pinFileName(pin)
	if !ok {
		return nil, storeFailure(faultRefused, "get-blob", errors.New("not a pin"))
	}
	file, info, err := openEntry(p.dir, name)
	if err != nil {
		fault := faultUnreadable
		if errors.Is(err, fs.ErrNotExist) {
			fault = faultAbsent
		}
		return nil, storeFailure(fault, "get-blob", fmt.Errorf("%s/%s %v", p.name, name, err))
	}
	defer file.Close()
	if err := snapshotHeld(info, p.owner, false); err != nil {
		return nil, storeFailure(faultUnreadable, "get-blob", fmt.Errorf("%s/%s %v", p.name, name, err))
	}
	data, err := readBoundedFrom(file, name, maxSnapshotBytes)
	if err != nil {
		return nil, storeFailure(faultUnreadable, "get-blob", err)
	}
	return data, nil
}

// listBlobs names the snapshots the held directory holds.
func (p fsHeldPins) listBlobs() ([]string, error) {
	listed, err := p.dir.Open(".")
	if err != nil {
		return nil, storeFailure(faultUnreadable, "list-blobs", err)
	}
	defer listed.Close()
	names, err := listed.Readdirnames(-1)
	if err != nil {
		return nil, storeFailure(faultUnreadable, "list-blobs", err)
	}
	var pins []string
	for _, name := range names {
		if hexSum, ok := strings.CutSuffix(name, ".json"); ok && isLowerHexOfLen(hexSum, 64) {
			pins = append(pins, "sha256:"+hexSum)
		}
	}
	sort.Strings(pins)
	return pins, nil
}

// fsDocuments keeps each document as a directory of its revisions under
// dir, <name>/<n> for n from 1, each made once by linking a synced staging
// file to its name, so two writers that expect the same revision cannot
// both make the next one. A revision's first byte says whether it holds
// the document ('d', its bytes after) or the document's deletion ('x').
// A revision a newer one stands over is emptied, never removed: its name
// stays taken, so no revision is ever made twice.
type fsDocuments struct{ dir string }

const (
	revisionData    = 'd'
	revisionDeleted = 'x'
)

func (d fsDocuments) docDir(op, name string) (string, error) {
	if d.dir == "" {
		return "", storeFailure(faultRefused, op, errors.New("store: this filesystem kind keeps no documents"))
	}
	if !validStoreName(name) {
		return "", storeFailure(faultRefused, op, fmt.Errorf("store: %q is not a document's name", name))
	}
	return filepath.Join(d.dir, name), nil
}

// revisionNumber reads a revision's file name: a positive decimal, no
// leading zero.
func revisionNumber(name string) (int64, bool) {
	if name == "" || name[0] == '0' || len(name) > 15 {
		return 0, false
	}
	n, err := strconv.ParseInt(name, 10, 64)
	return n, err == nil && n > 0
}

// newest is the highest revision under a document's directory, 0 for none.
func newest(dir string) (int64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	var top int64
	for _, e := range entries {
		if n, ok := revisionNumber(e.Name()); ok && !e.IsDir() && n > top {
			top = n
		}
	}
	return top, nil
}

// state is a document's newest revision, and its bytes when that revision
// holds the document rather than its deletion.
func (d fsDocuments) state(dir string) (int64, []byte, bool, error) {
	for attempt := 0; attempt < 8; attempt++ {
		n, err := newest(dir)
		if err != nil {
			return 0, nil, false, err
		}
		if n == 0 {
			return 0, nil, false, nil
		}
		data, err := os.ReadFile(filepath.Join(dir, strconv.FormatInt(n, 10)))
		if err != nil {
			return 0, nil, false, err
		}
		switch {
		case len(data) == 0:
			// emptied by a write that made a newer revision since the
			// listing: look again
			continue
		case data[0] == revisionData:
			return n, data[1:], true, nil
		case len(data) == 1 && data[0] == revisionDeleted:
			return n, nil, false, nil
		}
		return 0, nil, false, fmt.Errorf("store: revision %d of %s is not one this kind writes", n, filepath.Base(dir))
	}
	return 0, nil, false, fmt.Errorf("store: %s changed under every read", filepath.Base(dir))
}

func (d fsDocuments) getDocument(name string) ([]byte, string, error) {
	dir, err := d.docDir("get-document", name)
	if err != nil {
		return nil, noRevision, err
	}
	n, data, present, err := d.state(dir)
	if err != nil {
		return nil, noRevision, storeFailure(faultUnreadable, "get-document", err)
	}
	if !present {
		return nil, noRevision, storeFailure(faultAbsent, "get-document", nil)
	}
	return data, strconv.FormatInt(n, 10), nil
}

func (d fsDocuments) putDocument(name string, data []byte, expected string) (string, error) {
	return d.write("put-document", name, append([]byte{revisionData}, data...), expected, false)
}

func (d fsDocuments) deleteDocument(name, expected string) error {
	_, err := d.write("delete-document", name, []byte{revisionDeleted}, expected, true)
	return err
}

// write makes the document's next revision, holding body, if the document
// is at revision expected now.
func (d fsDocuments) write(op, name string, body []byte, expected string, deleting bool) (string, error) {
	dir, err := d.docDir(op, name)
	if err != nil {
		return noRevision, err
	}
	n, _, present, err := d.state(dir)
	if err != nil {
		return noRevision, storeFailure(faultUnreadable, op, err)
	}
	current := noRevision
	if present {
		current = strconv.FormatInt(n, 10)
	}
	if deleting && !present {
		return noRevision, storeFailure(faultAbsent, op, nil)
	}
	if expected != current {
		return noRevision, storeFailure(faultConflict, op, fmt.Errorf("store: %s is at revision %q, not %q", name, current, expected))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return noRevision, storeFailure(faultDurability, op, err)
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return noRevision, storeFailure(faultDurability, op, err)
	}
	staged := filepath.Join(dir, ".staged-"+hex.EncodeToString(suffix[:]))
	handle, err := os.OpenFile(staged, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return noRevision, storeFailure(faultDurability, op, err)
	}
	defer os.Remove(staged)
	_, err = handle.Write(body)
	if err == nil {
		err = handle.Sync()
	}
	if closeErr := handle.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return noRevision, storeFailure(faultDurability, op, err)
	}
	next := n + 1
	if err := os.Link(staged, filepath.Join(dir, strconv.FormatInt(next, 10))); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return noRevision, storeFailure(faultConflict, op, fmt.Errorf("store: another writer made revision %d of %s", next, name))
		}
		return noRevision, storeFailure(faultDurability, op, err)
	}
	syncDir(dir)
	// the revisions under this one are emptied, newest first, until one
	// emptied before is reached
	for old := next - 1; old > 0; old-- {
		at := filepath.Join(dir, strconv.FormatInt(old, 10))
		if info, err := os.Stat(at); err != nil || info.Size() == 0 || os.Truncate(at, 0) != nil {
			break
		}
	}
	return strconv.FormatInt(next, 10), nil
}

func (d fsDocuments) listDocuments() ([]string, error) {
	if d.dir == "" {
		return nil, storeFailure(faultRefused, "list-documents", errors.New("store: this filesystem kind keeps no documents"))
	}
	entries, err := os.ReadDir(d.dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, storeFailure(faultUnreadable, "list-documents", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() || !validStoreName(e.Name()) {
			continue
		}
		_, _, present, err := d.state(filepath.Join(d.dir, e.Name()))
		if err != nil {
			return nil, storeFailure(faultUnreadable, "list-documents", err)
		}
		if present {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

// fsSecrets keeps each secret in a file of its own: one named in files at
// the path given for it -- the seed, at the path its configuration names --
// and any other under dir. A secret is read as the seed is (openSeed): the
// file opened once and judged by what was opened before a byte is read.
type fsSecrets struct {
	dir   string
	files map[string]string
}

// seedSecret is the seed at its path, as a secret space keeps it.
func seedSecret(path string) fsSecrets {
	return fsSecrets{files: map[string]string{"seed": path}}
}

func (s fsSecrets) path(op, name string) (string, error) {
	if path, ok := s.files[name]; ok {
		return path, nil
	}
	if s.dir == "" || !validStoreName(name) {
		return "", storeFailure(faultRefused, op, fmt.Errorf("store: no secret %q is kept here", name))
	}
	return filepath.Join(s.dir, name), nil
}

func (s fsSecrets) getSecret(name string) ([]byte, error) {
	path, err := s.path("get-secret", name)
	if err != nil {
		return nil, err
	}
	raw, err := openSeed(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, storeFailure(faultAbsent, "get-secret", err)
		}
		return nil, storeFailure(faultUnreadable, "get-secret", err)
	}
	return raw, nil
}

// putSecret makes the file exclusively, readable by its owner alone: an
// existing path -- a file, a directory, a link -- is left as it is and
// refused (writeNewSeed).
func (s fsSecrets) putSecret(name string, value []byte) error {
	path, err := s.path("put-secret", name)
	if err != nil {
		return err
	}
	if _, mapped := s.files[name]; !mapped {
		if err := os.MkdirAll(s.dir, 0o700); err != nil {
			return storeFailure(faultDurability, "put-secret", err)
		}
	}
	if err := writeNewSeed(path, value); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return storeFailure(faultTaken, "put-secret", err)
		}
		return storeFailure(faultDurability, "put-secret", err)
	}
	return nil
}

// fsLayout is where the filesystem kind keeps each space. The store and
// the registry are an engine's; documents and secrets are kept only where
// a directory is named for them, and no configuration names one today.
type fsLayout struct {
	store     string
	registry  string
	documents string
	secrets   string
	clock     func() time.Time
}

type fsKind struct {
	layout fsLayout
	log    *fsLog
}

func newFsKind(layout fsLayout) *fsKind {
	if layout.clock == nil {
		layout.clock = time.Now
	}
	return &fsKind{layout: layout, log: newFsLog(layout.registry)}
}

// makeStore makes the store's artifacts and receipts directories where
// they are not there (SPEC.md §1.3).
func (k *fsKind) makeStore() error {
	for _, dir := range []string{"artifacts", "receipts"} {
		if err := os.MkdirAll(filepath.Join(k.layout.store, dir), 0o755); err != nil {
			return storeFailure(faultDurability, "make-store", err)
		}
	}
	return nil
}

func (k *fsKind) artifacts() blobSpace {
	return fsBlobs{dir: filepath.Join(k.layout.store, "artifacts")}
}

func (k *fsKind) receipts() indexedSpace {
	return fsIndexed{root: filepath.Join(k.layout.store, "receipts")}
}

func (k *fsKind) registry() appendLog { return k.log }

// documents is the kind's documents as every caller but its leases is
// given them: a lease's document is the leases' own.
func (k *fsKind) documents() documentSpace {
	return leaseDocumentsReserved{fsDocuments{dir: k.layout.documents}}
}

func (k *fsKind) secrets() secretSpace { return fsSecrets{dir: k.layout.secrets} }

func (k *fsKind) leases() leaseSpace {
	return documentLeases{docs: fsDocuments{dir: k.layout.documents}, clock: k.layout.clock}
}

// snapshotRead, when set, runs after each space a snapshot reads, named
// "log", "documents", "entries" or "blobs": a test's way of writing at that
// moment.
var snapshotRead func(space string)

func snapshotStep(space string) {
	if snapshotRead != nil {
		snapshotRead(space)
	}
}

// snapshot cuts the kind by reading its spaces in the reverse of the order
// a writer makes them durable: the log first, so a record in it counts only
// what was made before it; then the documents; then the series and their
// entries, listed; the blobs last, so every blob a listed entry names,
// kept before that entry, is listed too. Nothing is made: a space that is
// not there is an empty one, as verification reads it.
func (k *fsKind) snapshot() (*storeCut, error) {
	cut := &storeCut{documents: map[string][]byte{}, revisions: map[string]string{}, entries: map[string][]string{}}
	data, err := k.log.readLog(0)
	switch faultOf(err) {
	case "":
		cut.log, cut.logPresent = data, true
	case faultAbsent:
	default:
		return nil, err
	}
	snapshotStep("log")
	if k.layout.documents != "" {
		docs := k.documents()
		names, err := docs.listDocuments()
		if err != nil {
			return nil, err
		}
		for _, name := range names {
			data, revision, err := docs.getDocument(name)
			if faultOf(err) == faultAbsent {
				continue
			}
			if err != nil {
				return nil, err
			}
			cut.documents[name], cut.revisions[name] = data, revision
		}
		snapshotStep("documents")
	}
	receipts := k.receipts()
	series, err := receipts.listSeries()
	if err != nil {
		return nil, err
	}
	for _, s := range series {
		entries, err := receipts.listEntries(s)
		if err != nil {
			return nil, err
		}
		cut.series = append(cut.series, s)
		cut.entries[s] = entries
	}
	snapshotStep("entries")
	artifacts := k.artifacts()
	if cut.blobs, err = artifacts.listBlobs(); err != nil {
		return nil, err
	}
	snapshotStep("blobs")
	cut.entry, cut.blob = receipts.getEntry, artifacts.getBlob
	return cut, nil
}
