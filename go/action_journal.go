package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// A reservation binds a key to one approved content (intent.json). Dispatch is
// granted by a second exclusive transition: creating dispatch-<n>.json, synced,
// immediately before the write program is started. A reservation whose every
// dispatch marker is answered by not-dispatched-<n>.json provably sent nothing,
// and its next attempt may be claimed, by exactly one exclusive creator. A
// dispatch marker without its answer means dispatch may have begun, and no
// later open dispatches again. Nothing here is overwritten or removed, and a
// partial or unreadable entry never grants dispatch.
const actionJournalResponseLimit = 16 << 20

// actionJournalVersion is the intent's journal version. Version "1" entries,
// written before dispatch markers existed, are refused: they cannot prove that
// nothing was sent.
const actionJournalVersion = "2"

// actionDispatchAttempts bounds the not-dispatched attempts one key may record.
const actionDispatchAttempts = 16

type actionJournal struct{ root *os.Root }
type actionClaim struct {
	root  *os.Root
	fresh bool
}
type actionIntent struct {
	Version     string `json:"journalVersion"`
	Identity    string `json:"identityVersion"`
	Fingerprint string `json:"fingerprint"`
}

func openActionJournal(storeRoot string) (*actionJournal, error) {
	if !actionJournalSupported || !filepath.IsAbs(storeRoot) {
		return nil, errors.New("action-journal-unavailable: durable keyed actions require a supported filesystem store")
	}
	parent, err := os.OpenRoot(storeRoot)
	if err != nil {
		return nil, errors.New("action-journal-unavailable: cannot hold store directory")
	}
	defer parent.Close()
	if err = syncActionAncestry(storeRoot, parent); err != nil {
		return nil, err
	}

	if err = parent.Mkdir("actions", 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, errors.New("action-journal-unavailable: cannot create private journal")
	}
	// Always sync: another opener may observe a just-created directory before
	// its creator has synced the parent. No dispatch relies on that race.
	if err = syncActionDirectory(parent); err != nil {
		return nil, err
	}
	root, err := openActionDirectory(parent, "actions")
	if err != nil {
		return nil, err
	}
	return &actionJournal{root}, nil
}

// MkdirAll may have just created the store and several parents. Sync every
// entry naming it, through the filesystem root, before any reservation can
// grant dispatch. Resolving symlinks first covers the physical ancestry; each
// held child's identity is checked against its parent's non-link entry.
func syncActionAncestry(path string, held *os.Root) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return errors.New("action-journal-unavailable: cannot resolve store ancestry")
	}
	current := held
	var opened []*os.Root
	defer func() {
		for _, root := range opened {
			root.Close()
		}
	}()
	for {
		before, err := current.Stat(".")
		if err != nil {
			return errors.New("action-journal-unavailable: cannot identify held store ancestry")
		}
		parentPath := filepath.Dir(resolved)
		if parentPath == resolved {
			return syncActionDirectory(current)
		}
		parent, err := os.OpenRoot(parentPath)
		if err != nil {
			return errors.New("action-journal-unavailable: cannot hold store ancestor")
		}
		opened = append(opened, parent)
		named, err := parent.Lstat(filepath.Base(resolved))
		if err != nil || !named.IsDir() || named.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, named) {
			return errors.New("action-journal-invalid: store ancestry changed while opening")
		}
		if err = syncActionDirectory(parent); err != nil {
			return err
		}
		current = parent
		resolved = parentPath
	}
}

func (j *actionJournal) close() { j.root.Close() }
func (c *actionClaim) close()   { c.root.Close() }

func syncActionDirectory(root *os.Root) error {
	f, err := root.Open(".")
	if err != nil {
		return errors.New("action-journal-unavailable: cannot hold directory for durability")
	}
	defer f.Close()
	if err = syncActionFile(f); err != nil {
		return errors.New("action-journal-unavailable: directory durability was not established")
	}
	return nil
}

// Test seam injects a real durability failure before dispatch authorization.
var syncActionFile = func(f *os.File) error { return f.Sync() }

func openActionDirectory(parent *os.Root, name string) (*os.Root, error) {
	before, err := parent.Lstat(name)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0077 != 0 {
		return nil, errors.New("action-journal-invalid: private directory is missing or unsafe")
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		return nil, errors.New("action-journal-invalid: cannot hold private directory")
	}
	after, err := root.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		root.Close()
		return nil, errors.New("action-journal-invalid: directory changed while opening")
	}
	return root, nil
}

// reserve holds the key's reservation to the request's identity. A new
// reservation records identity version 2. A reservation that records no
// identityVersion was made by v0.23.0 under identity version 1, and is held
// to the request's version 1 identity: it is the same approved content if
// that matches (#355). A version this release does not read refuses.
func (j *actionJournal) reserve(namespace string, identity actionIdentity) (*actionClaim, error) {
	fingerprint := identity.fingerprint
	if !isLowerHexOfLen(namespace, 64) || !isLowerHexOfLen(fingerprint, 64) {
		return nil, errors.New("action-key-invalid: invalid journal identity")
	}
	err := j.root.Mkdir(namespace, 0700)
	fresh := err == nil
	if err != nil && !errors.Is(err, os.ErrExist) {
		return nil, errors.New("action-journal-unavailable: cannot reserve action")
	}
	if err = syncActionDirectory(j.root); err != nil {
		return nil, err
	}
	root, err := openActionDirectory(j.root, namespace)
	if err != nil {
		return nil, err
	}
	claim := &actionClaim{root: root, fresh: fresh}
	fail := func(err error) (*actionClaim, error) { root.Close(); return nil, err }
	if fresh {
		raw, _ := json.Marshal(actionIntent{Version: actionJournalVersion, Identity: actionIdentityVersion, Fingerprint: fingerprint})
		if err = claim.put("intent.json", raw, 1024); err != nil {
			return fail(err)
		}
		return claim, nil
	}
	raw, err := claim.read("intent.json", 1024)
	if err != nil {
		return fail(errors.New("action-journal-invalid: existing reservation has no readable intent; dispatch is forbidden"))
	}
	value, err := parseJSON(raw)
	if err != nil {
		return fail(errors.New("action-journal-invalid: malformed intent"))
	}
	object, err := requireObject(value, "action intent")
	if err != nil {
		return fail(err)
	}
	if err = exactlyMembers(object, map[string]bool{"journalVersion": true, "identityVersion": false, "fingerprint": true}, "action intent"); err != nil {
		return fail(err)
	}
	version, _ := memberString(object, "journalVersion")
	stored, _ := memberString(object, "fingerprint")
	if version != actionJournalVersion || !isLowerHexOfLen(stored, 64) {
		return fail(errors.New("action-journal-invalid: invalid intent"))
	}
	want := identity.previous
	if _, present := object.get("identityVersion"); present {
		if recorded, _ := memberString(object, "identityVersion"); recorded != actionIdentityVersion {
			return fail(errors.New("action-journal-invalid: the reservation records an identity version this release does not read"))
		}
		want = fingerprint
	}
	if stored != want {
		return fail(errors.New("action-key-conflict: this key already identifies different approved content"))
	}
	return claim, nil
}

func actionJournalName(name string) bool {
	if name == "intent.json" || name == "action.json" || name == "response.json" {
		return true
	}
	for n := 1; n <= actionDispatchAttempts; n++ {
		if name == actionDispatchName(n) || name == actionNotDispatchedName(n) {
			return true
		}
	}
	return false
}

func actionDispatchName(n int) string      { return fmt.Sprintf("dispatch-%d.json", n) }
func actionNotDispatchedName(n int) string { return fmt.Sprintf("not-dispatched-%d.json", n) }

// errActionDispatchClaimed is a dispatch marker another opener created first:
// that opener may be sending the mutation now.
var errActionDispatchClaimed = errors.New("action-journal: dispatch was claimed by another request")

// attempt is the reservation's dispatch state: the next attempt number to
// claim, or begun when a dispatch marker exists without its not-dispatched
// answer, so the mutation may have been sent. An entry that cannot be read as
// a not-dispatched answer counts as begun; only a complete answer frees the
// next attempt.
func (c *actionClaim) attempt() (n int, begun bool, err error) {
	for n = 1; n <= actionDispatchAttempts; n++ {
		if _, err = c.root.Lstat(actionDispatchName(n)); errors.Is(err, os.ErrNotExist) {
			return n, false, nil
		} else if err != nil {
			return n, true, nil
		}
		if _, err = c.read(actionNotDispatchedName(n), 1024); err != nil {
			return n, true, nil
		}
	}
	return 0, false, errors.New("action-journal-exhausted: this key recorded too many attempts that were never dispatched; choose the request's next step with the operator")
}

// claimDispatch creates attempt n's dispatch marker exclusively and makes it
// durable. Only a nil return permits starting the write program. A marker that
// already exists is errActionDispatchClaimed; any other failure sends nothing,
// and a marker it may have left counts as begun on the next open.
func (c *actionClaim) claimDispatch(n int) error {
	raw, _ := json.Marshal(map[string]int{"attempt": n})
	err := c.put(actionDispatchName(n), raw, 1024)
	if errors.Is(err, errActionRecordExists) {
		return errActionDispatchClaimed
	}
	return err
}

// releaseDispatch answers attempt n's marker: the write program was never
// started, so nothing was sent under it.
func (c *actionClaim) releaseDispatch(n int, reason string) error {
	raw, _ := json.Marshal(map[string]any{"attempt": n, "reason": reason})
	return c.put(actionNotDispatchedName(n), raw, 1024)
}

var errActionRecordExists = errors.New("action-journal-unavailable: cannot exclusively retain record: it already exists")

// put never overwrites or removes a partial file. An existing malformed entry
// means uncertainty and needs operator recovery; it never grants a new dispatch.
func (c *actionClaim) put(name string, raw []byte, limit int) error {
	if !actionJournalName(name) || len(raw) > limit || !json.Valid(raw) {
		return errors.New("action-journal-invalid: invalid or oversized record")
	}
	f, err := c.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return errActionRecordExists
	}
	if err != nil {
		return errors.New("action-journal-unavailable: cannot exclusively retain record")
	}
	_, writeErr := io.Copy(f, bytes.NewReader(raw))
	if writeErr == nil {
		writeErr = syncActionFile(f)
	}
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("action-journal-unavailable: record durability was not established")
	}
	return syncActionDirectory(c.root)
}

func (c *actionClaim) read(name string, limit int) ([]byte, error) {
	if !actionJournalName(name) {
		return nil, errors.New("action-journal-invalid: invalid record name")
	}
	before, err := c.root.Lstat(name)
	if err != nil {
		return nil, err
	} // ENOENT only when the entry itself is absent.
	if !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 || before.Size() > int64(limit) {
		return nil, errors.New("action-journal-invalid: record is not a bounded private file")
	}
	f, err := c.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("action-journal-invalid: record changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil || len(raw) > limit {
		return nil, errors.New("action-journal-invalid: record could not be read within its bound")
	}
	if _, err = parseJSON(raw); err != nil {
		return nil, fmt.Errorf("action-journal-invalid: malformed record: %w", err)
	}
	return raw, nil
}
