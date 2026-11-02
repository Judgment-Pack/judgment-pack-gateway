package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
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
// later open dispatches again. A dispatch marker may instead record a close, by a
// request that answered that nothing was sent (SPEC.md §1.2b): it takes the name
// that attempt's dispatch would, so only one of the two can happen. Nothing here is
// overwritten or removed, and a partial or unreadable entry never grants dispatch.
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

// syncActionEvidence makes durable, strictly, the directory entries that the
// receipt an action record is about to cite rests on: its result's blob in
// artifacts/, the receipt in receipts/<session>/, and that session in
// receipts/. The store links each with a best-effort directory sync, which is
// not enough for a record that is synced strictly and refuses its key for
// good when the receipt it cites is gone (#352 L4). The store directory's own
// entries for artifacts/ and receipts/ were synced when the journal was opened
// (openActionJournal), and each file's bytes before it was linked.
func syncActionEvidence(storeRoot, sessionID string) error {
	if err := requireSession(sessionID); err != nil {
		return errors.New("action-journal-invalid: the receipt's session is not a session name")
	}
	store, err := os.OpenRoot(storeRoot)
	if err != nil {
		return errors.New("action-journal-unavailable: cannot hold the store to make the receipt durable")
	}
	defer store.Close()
	for _, dir := range []string{"artifacts", "receipts/" + sessionID, "receipts"} {
		held, err := store.OpenRoot(dir)
		if err != nil {
			return errors.New("action-journal-unavailable: cannot hold the receipt's directory to make it durable")
		}
		err = syncActionDirectory(held)
		held.Close()
		if err != nil {
			return errors.New("action-journal-unavailable: the durability of the receipt the action record cites was not established")
		}
	}
	return nil
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
	return j.reserveScoped(namespace, identity, nil)
}

// reserveScoped is reserve in a delegated scope (SPEC.md §11.8): the scope is
// recorded as scope.json before the intent, and held to on every later open.
// nil is a reservation made under no delegation, which records none.
func (j *actionJournal) reserveScoped(namespace string, identity actionIdentity, scope *vObject) (*actionClaim, error) {
	fingerprint := identity.fingerprint
	if !isLowerHexOfLen(namespace, 64) || !isLowerHexOfLen(fingerprint, 64) {
		return nil, errors.New("action-key-invalid: invalid journal identity")
	}
	fresh, err := j.publishUnlessPresent(namespace, reservationRecords(identity, scope))
	if err != nil {
		return nil, err
	}
	claim, err := j.holdEntry(namespace, fresh)
	if err != nil || fresh {
		return claim, err
	}
	if err = claim.holdsIdentity(identity, scope); err != nil {
		claim.close()
		return nil, err
	}
	return claim, nil
}

// openReservation holds the reservation already under the namespace to the
// request's identity, making none: what a reconciling request reads. Absence is
// a refusal here, never a reservation.
func (j *actionJournal) openReservation(namespace string, identity actionIdentity, scope *vObject) (*actionClaim, error) {
	if !isLowerHexOfLen(namespace, 64) || !isLowerHexOfLen(identity.fingerprint, 64) {
		return nil, errors.New("action-key-invalid: invalid journal identity")
	}
	claim, err := j.holdEntry(namespace, false)
	if err != nil {
		return nil, err
	}
	if err = claim.holdsIdentity(identity, scope); err != nil {
		claim.close()
		return nil, err
	}
	return claim, nil
}

// reserveClosed publishes a reservation for a key nothing has been seen under,
// whose first attempt is already closed: intent and close together, in one
// rename, so no crash leaves the reservation without its close, and no request
// finds it free. A reservation another request put there first is
// errActionRecordExists: the caller then reads that one.
func (j *actionJournal) reserveClosed(namespace string, identity actionIdentity, scope *vObject) error {
	if !isLowerHexOfLen(namespace, 64) || !isLowerHexOfLen(identity.fingerprint, 64) {
		return errors.New("action-key-invalid: invalid journal identity")
	}
	return j.publishEntry(namespace, append(reservationRecords(identity, scope), actionRecord{actionDispatchName(1), closedMarker(1), 1024}))
}

// reservationRecords is what a new reservation holds: its scope, if it has one,
// and its intent.
func reservationRecords(identity actionIdentity, scope *vObject) []actionRecord {
	var records []actionRecord
	if scope != nil {
		records = append(records, actionRecord{"scope.json", canon(scope), actionScopeLimit})
	}
	raw, _ := json.Marshal(actionIntent{Version: actionJournalVersion, Identity: actionIdentityVersion, Fingerprint: identity.fingerprint})
	return append(records, actionRecord{"intent.json", raw, 1024})
}

// holdsIdentity holds a reservation that was there already to the request.
func (c *actionClaim) holdsIdentity(identity actionIdentity, scope *vObject) error {
	if scope != nil {
		recorded, err := c.read("scope.json", actionScopeLimit)
		if err != nil || string(recorded) != string(canon(scope)) {
			return errors.New("action-journal-invalid: the reservation does not record the request's delegated scope; dispatch is forbidden")
		}
	}
	raw, err := c.read("intent.json", 1024)
	if err != nil {
		return errors.New("action-journal-invalid: existing reservation has no readable intent; dispatch is forbidden")
	}
	value, err := parseJSON(raw)
	if err != nil {
		return errors.New("action-journal-invalid: malformed intent")
	}
	object, err := requireObject(value, "action intent")
	if err != nil {
		return err
	}
	if err = exactlyMembers(object, map[string]bool{"journalVersion": true, "identityVersion": false, "fingerprint": true}, "action intent"); err != nil {
		return err
	}
	version, _ := memberString(object, "journalVersion")
	stored, _ := memberString(object, "fingerprint")
	if version != actionJournalVersion || !isLowerHexOfLen(stored, 64) {
		return errors.New("action-journal-invalid: invalid intent")
	}
	want := identity.previous
	if _, present := object.get("identityVersion"); present {
		if recorded, _ := memberString(object, "identityVersion"); recorded != actionIdentityVersion {
			return errors.New("action-journal-invalid: the reservation records an identity version this release does not read")
		}
		want = identity.fingerprint
	}
	if stored != want {
		return errors.New("action-key-conflict: this key already identifies different approved content")
	}
	return nil
}

// errActionScopeConflict is a delegated key the same subject reserved under
// another root actor (SPEC.md §11.8, RFC 0030 open question 9).
var errActionScopeConflict = errors.New("action-key-scope-conflict: this subject reserved this key under another root actor")

// holdSubjectKey records, under name, the delegated scope a subject first
// reserved a key in, and refuses the key in any other scope of the same
// subject: a takeover by another root actor finds the key taken rather than
// a new reservation to send the write again under. Only the actor's request
// calls it, before its reservation is made. A record that cannot be read
// refuses.
func (j *actionJournal) holdSubjectKey(name string, scope *vObject) error {
	if !isLowerHexOfLen(name, 64) {
		return errors.New("action-key-invalid: invalid journal identity")
	}
	fresh, err := j.publishUnlessPresent(name, []actionRecord{{"scope.json", canon(scope), actionScopeLimit}})
	if err != nil {
		return err
	}
	claim, err := j.holdEntry(name, fresh)
	if err != nil {
		return err
	}
	defer claim.close()
	if fresh {
		return nil
	}
	recorded, err := claim.read("scope.json", actionScopeLimit)
	if err != nil {
		return errors.New("action-journal-invalid: the key's recorded scope cannot be read; dispatch is forbidden")
	}
	if string(recorded) != string(canon(scope)) {
		return errActionScopeConflict
	}
	return nil
}

// publishUnlessPresent publishes an entry unless something is at its name, and
// says whether it did. What is there already is the caller's to read: a link, a
// damaged entry and an empty directory an older release's crash left all stay
// refusals there, and absence is only an entry that is not there. Exclusivity is
// the rename's, not this look's: it refuses any directory at the name, and in a race
// the system refuses one with records in it. The look is why a request that finds
// its entry writes nothing, as it never did, and why a link is refused as invalid.
func (j *actionJournal) publishUnlessPresent(name string, records []actionRecord) (bool, error) {
	_, err := j.root.Lstat(name)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, errors.New("action-journal-unavailable: cannot reserve action")
	}
	if err != nil {
		err = j.publishEntry(name, records)
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, errActionRecordExists) {
			return false, err
		}
	}
	return false, nil
}

// holdEntry opens the entry at name. Always sync the journal directory first:
// another opener may observe a just-published entry before its publisher has
// synced the parent. No dispatch relies on that race.
func (j *actionJournal) holdEntry(name string, fresh bool) (*actionClaim, error) {
	if err := syncActionDirectory(j.root); err != nil {
		return nil, err
	}
	root, err := openActionDirectory(j.root, name)
	if err != nil {
		return nil, err
	}
	return &actionClaim{root: root, fresh: fresh}, nil
}

// actionRecord is one journal file to publish.
type actionRecord struct {
	name  string
	raw   []byte
	limit int
}

// newActionStage makes a private directory under root, named so that nothing
// reads it as a journal entry, in which records are made durable before any
// other request can see them. A crash leaves it behind, inert (see
// docs/design/action-reconciliation.md).
func newActionStage(root *os.Root) (string, error) {
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return "", errors.New("action-journal-unavailable: cannot name a staging directory")
	}
	stage := ".staging-" + hex.EncodeToString(suffix)
	if err := root.Mkdir(stage, 0700); err != nil {
		return "", errors.New("action-journal-unavailable: cannot make a staging directory")
	}
	return stage, nil
}

// writeActionStaged writes one record under the stage and makes its bytes durable.
func writeActionStaged(root *os.Root, stage string, record actionRecord) error {
	if len(record.raw) > record.limit || !json.Valid(record.raw) {
		return errors.New("action-journal-invalid: invalid or oversized record")
	}
	f, err := root.OpenFile(filepath.Join(stage, record.name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("action-journal-unavailable: cannot exclusively retain record")
	}
	_, writeErr := io.Copy(f, bytes.NewReader(record.raw))
	if writeErr == nil {
		writeErr = syncActionFile(f)
	}
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("action-journal-unavailable: record durability was not established")
	}
	return nil
}

// publishEntry makes an entry appear whole or not at all: its records are made
// durable in a staging directory, which is then renamed onto the entry's name.
// So a crash leaves no entry that has no intent, or no recorded scope, for a key
// that would then be refused for good (#352 L4). A rename onto an entry fails, and
// an entry always holds a record, so the system refuses it even in a race: creation
// is exclusive. That is errActionRecordExists, and the caller reads the entry that
// won. The name's own durability is holdEntry's, which every use of an entry goes
// through.
func (j *actionJournal) publishEntry(name string, records []actionRecord) error {
	stage, err := newActionStage(j.root)
	if err != nil {
		return err
	}
	defer func() { _ = j.root.RemoveAll(stage) }()
	for _, record := range records {
		if err = writeActionStaged(j.root, stage, record); err != nil {
			return err
		}
	}
	held, err := j.root.OpenRoot(stage)
	if err != nil {
		return errors.New("action-journal-unavailable: cannot hold a staging directory")
	}
	err = syncActionDirectory(held)
	held.Close()
	if err != nil {
		return err
	}
	if err = j.root.Rename(stage, name); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errActionRecordExists
		}
		return errors.New("action-journal-unavailable: cannot publish a journal entry")
	}
	return nil
}

// publishActionRecord makes one file appear under root whole or not at all, and
// exclusively: its bytes are made durable under a staging directory, then the
// name is linked, which fails if the name is taken. Only then is root synced.
func publishActionRecord(root *os.Root, record actionRecord) error {
	stage, err := newActionStage(root)
	if err != nil {
		return err
	}
	defer func() { _ = root.RemoveAll(stage) }()
	if err = writeActionStaged(root, stage, record); err != nil {
		return err
	}
	if err = root.Link(filepath.Join(stage, record.name), record.name); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errActionRecordExists
		}
		return errors.New("action-journal-unavailable: cannot publish a journal record")
	}
	return syncActionDirectory(root)
}

// has reports whether a reservation exists under the namespace, making none.
func (j *actionJournal) has(namespace string) bool {
	if !isLowerHexOfLen(namespace, 64) {
		return false
	}
	_, err := j.root.Lstat(namespace)
	return err == nil
}

// actionScopeLimit bounds a recorded scope and a delegated dispatch marker.
const actionScopeLimit = 16 << 10

func actionJournalName(name string) bool {
	if name == "intent.json" || name == "action.json" || name == "response.json" || name == "scope.json" {
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
// next attempt. A closed marker is errActionKeyClosed, whatever stands beside it.
func (c *actionClaim) attempt() (n int, begun bool, err error) {
	for n = 1; n <= actionDispatchAttempts; n++ {
		if _, err = c.root.Lstat(actionDispatchName(n)); errors.Is(err, os.ErrNotExist) {
			return n, false, nil
		} else if err != nil {
			return n, true, nil
		}
		if c.closedAt(n) {
			return n, false, errActionKeyClosed
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
	return c.claimDispatchUnder(n, nil, "")
}

// claimDispatchUnder is claimDispatch for a dispatch admitted under a
// delegation, whose marker records the receipt's delegation member and the
// digest of the credential that dispatched (SPEC.md §11.7, §11.8); with nil
// it is claimDispatch, its marker as before.
func (c *actionClaim) claimDispatchUnder(n int, delegation *vObject, tokenDigest string) error {
	var err error
	if delegation == nil {
		raw, _ := json.Marshal(map[string]int{"attempt": n})
		err = c.put(actionDispatchName(n), raw, 1024)
	} else {
		// A receipt of this dispatch is minted from this marker, so one torn by a
		// crash would refuse its key for good (dispatchDelegation), though no program
		// was started. It appears whole or not at all. A marker under no delegation
		// is only read for being there: a torn one counts as begun.
		marker := newObject()
		marker.set("attempt", vInt(n))
		marker.set("delegation", delegation)
		marker.set("tokenDigest", vString(tokenDigest))
		err = publishActionRecord(c.root, actionRecord{actionDispatchName(n), canon(marker), actionScopeLimit})
	}
	if errors.Is(err, errActionRecordExists) {
		if c.closedAt(n) {
			return errActionKeyClosed
		}
		return errActionDispatchClaimed
	}
	return err
}

// errActionKeyClosed is a key a reconciling request closed: it never dispatches.
var errActionKeyClosed = errors.New("action-key-closed: a reconciling request closed this key, and nothing under it was or will be dispatched")

// closedMarker is attempt n's dispatch marker for a key that closes there. It
// takes the name a dispatch would, so the two cannot both happen. A gateway from
// before closes reads it as a dispatch that may have begun, and sends nothing.
func closedMarker(n int) []byte {
	raw, _ := json.Marshal(map[string]any{"attempt": n, "closed": true, "closedAt": nowStamp()})
	return raw
}

// closedAt reports whether attempt n's marker is a complete close. Anything else
// at that name, unreadable or partial, is no close: it counts as a dispatch that
// may have begun.
func (c *actionClaim) closedAt(n int) bool {
	raw, err := c.read(actionDispatchName(n), actionScopeLimit)
	if err != nil {
		return false
	}
	v, err := parseJSON(raw)
	if err != nil {
		return false
	}
	marker, ok := v.(*vObject)
	if !ok {
		return false
	}
	closed, _ := marker.get("closed")
	attempt, _ := marker.get("attempt")
	return closed == vBool(true) && attempt == vInt(n)
}

// closed reports whether any attempt of this reservation is a close. It looks at
// every attempt: a lower marker lost to damage does not reopen a key.
func (c *actionClaim) closed() bool {
	for n := 1; n <= actionDispatchAttempts; n++ {
		if c.closedAt(n) {
			return true
		}
	}
	return false
}

// closeDispatch closes the key at attempt n: its marker is made durable and then
// put at the name a dispatch of that attempt would create exclusively, so either
// this close or that dispatch happens, across processes. It returns nil, or
// errActionKeyClosed for a close already there, both of which mean closed; or
// errActionDispatchClaimed for a marker that may have begun, which is not closed.
func (c *actionClaim) closeDispatch(n int) error {
	// Each marker is durable before the next can exist, so one above a free attempt is
	// damage, and it says a dispatch may have begun. Nothing closes over it.
	for later := n + 1; later <= actionDispatchAttempts; later++ {
		if _, err := c.root.Lstat(actionDispatchName(later)); !errors.Is(err, os.ErrNotExist) {
			return errActionDispatchClaimed
		}
	}
	err := publishActionRecord(c.root, actionRecord{actionDispatchName(n), closedMarker(n), 1024})
	if errors.Is(err, errActionRecordExists) {
		if c.closedAt(n) {
			return errActionKeyClosed
		}
		return errActionDispatchClaimed
	}
	return err
}

// dispatchDelegation is the delegation member attempt n's marker recorded
// when its dispatch was admitted, and the digest of the credential that
// dispatched. A marker that records either not, or cannot be read, refuses: a
// receipt of that dispatch cannot say what it was admitted under, or by whose
// credential.
func (c *actionClaim) dispatchDelegation(n int) (*vObject, string, error) {
	invalid := errors.New("action-journal-invalid: the dispatch marker does not record the delegation it was admitted under")
	raw, err := c.read(actionDispatchName(n), actionScopeLimit)
	if err != nil {
		return nil, "", invalid
	}
	v, err := parseJSON(raw)
	if err != nil {
		return nil, "", invalid
	}
	marker, ok := v.(*vObject)
	if !ok {
		return nil, "", invalid
	}
	member, present := marker.get("delegation")
	obj, isObject := member.(*vObject)
	digest, _ := memberString(marker, "tokenDigest")
	if !present || !isObject || !isDigest(digest) {
		return nil, "", invalid
	}
	return obj, digest, nil
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

// publish is put for a record no crash may leave partial, since one that does not
// read refuses its key for good: it appears whole or not at all.
func (c *actionClaim) publish(name string, raw []byte, limit int) error {
	if !actionJournalName(name) {
		return errors.New("action-journal-invalid: invalid or oversized record")
	}
	return publishActionRecord(c.root, actionRecord{name, raw, limit})
}

func (c *actionClaim) read(name string, limit int) ([]byte, error) {
	if !actionJournalName(name) {
		return nil, errors.New("action-journal-invalid: invalid record name")
	}
	return readActionRecord(c.root, name, limit)
}

// readActionRecord reads one bounded, private, regular journal file under root.
func readActionRecord(root *os.Root, name string, limit int) ([]byte, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	} // ENOENT only when the entry itself is absent.
	if !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 || before.Size() > int64(limit) {
		return nil, errors.New("action-journal-invalid: record is not a bounded private file")
	}
	f, err := root.Open(name)
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
