package main

// `gateway journal compact` (#359): the offline compaction of the action
// journal that docs/design/action-reconciliation.md describes ("Compaction"),
// done by the gateway's own reading of the journal rather than by hand.
//
// It runs only while no gateway process serves the store. A gateway takes a
// shared lock on its store's directory as it starts and holds it while it
// serves (holdServedStore); the command takes that lock exclusive and is
// refused while any serve holds it, and a serve is refused its start while a
// compaction holds it. The per-key lock (actionKeyLocks) holds one process
// only, and the journal's exclusive creation does not guard against a removal
// while a request is in flight: this lock is what does.
//
// What it removes, it moves, whole, into an archive outside the store, on the
// store's filesystem: an entry that never sent, an answered entry whose
// receipt was served longer ago than the retention period, and the action.json
// of an indexed entry under the same rule. Each move goes with a retirement
// record. Every other entry stays as it is: closed, subject records, indexed
// entries otherwise, entries that do not read, uncertain entries and entries
// begun without a record. The first-scope index stays whole. No receipt is
// touched, nothing is deleted, and nothing in the journal is rewritten.
//
// A retirement is made durable in an order that a crash at any point leaves
// safe to run again: a staging directory in the archive holds its record first,
// then what is moved, and only then takes its final name. A rerun finishes a
// staging directory that holds what was moved, and leaves one that holds only
// its record, which retired nothing.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const journalUsage = `usage: gateway journal compact --store <dir> --archive <dir> --retention <duration>
Compacts a store's action journal while no gateway process serves the store
(docs/design/action-reconciliation.md, "Compaction"). An entry that never
sent, and an answered one whose receipt was served longer ago than the
retention period (a duration such as 720h), is moved whole into the archive
with a retirement record; an indexed entry gives up only such an action.json.
Closed, uncertain, begun and unreadable entries, other indexed entries, subject
records and the first-scope index stay. No receipt is touched and nothing is
deleted. The archive is a private directory outside the store, on the store's
filesystem. Refused while a gateway process serves the store.`

// errDirectoryHeld is a directory lock another holds in a way that excludes
// this one: a gateway serving the store, or a compaction.
var errDirectoryHeld = errors.New("the directory is locked by another process")

// servedStoreHold is the lock a gateway process holds on its store's directory
// while it serves: shared, so that gateway processes serving one store do not
// exclude each other, and so that gateway journal compact, which takes it
// exclusive, is refused while any of them runs. Where no journal is kept,
// nothing is locked.
type servedStoreHold struct {
	store string
	lock  io.Closer
}

// holdServedStore takes the hold before the service is built, so that a start
// while a compaction runs is refused before it makes anything in the store. A
// store that is not a directory yet, which no compaction can hold, is held by
// made, once the service has made it; one that cannot be, the service refuses
// as it always has.
func holdServedStore(storeRoot string) (*servedStoreHold, error) {
	h := &servedStoreHold{store: storeRoot}
	if !actionJournalSupported {
		return h, nil
	}
	if info, err := os.Stat(storeRoot); err != nil || !info.IsDir() {
		return h, nil
	}
	return h, h.take()
}

// made holds the store the service has just made, where it was not there when
// the hold was taken.
func (h *servedStoreHold) made() error {
	if h.lock != nil || !actionJournalSupported {
		return nil
	}
	return h.take()
}

func (h *servedStoreHold) take() error {
	lock, err := lockDirectory(h.store, false)
	if errors.Is(err, errDirectoryHeld) {
		return fmt.Errorf("action-journal-held: a journal compaction holds the store %s; start the gateway once it has finished", h.store)
	}
	if err != nil {
		return fmt.Errorf("action-journal-unavailable: the store %s could not be locked against a journal compaction: %v", h.store, err)
	}
	h.lock = lock
	return nil
}

// Close releases the hold.
func (h *servedStoreHold) Close() error {
	if h.lock == nil {
		return nil
	}
	return h.lock.Close()
}

func cmdJournal(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "compact" {
		fmt.Fprintln(stderr, journalUsage)
		return 2
	}
	flags := map[string]string{}
	for rest := args[1:]; len(rest) > 0; rest = rest[2:] {
		name := rest[0]
		if (name != "--store" && name != "--archive" && name != "--retention") || len(rest) < 2 || rest[1] == "" {
			fmt.Fprintln(stderr, journalUsage)
			return 2
		}
		if _, given := flags[name]; given {
			fmt.Fprintf(stderr, "%s is given twice\n%s\n", name, journalUsage)
			return 2
		}
		flags[name] = rest[1]
	}
	if len(flags) != 3 {
		fmt.Fprintln(stderr, journalUsage)
		return 2
	}
	retention, err := parseRetention(flags["--retention"])
	if err != nil {
		fmt.Fprintf(stderr, "%v\n%s\n", err, journalUsage)
		return 2
	}
	if err := compactJournal(flags["--store"], flags["--archive"], retention, time.Now, stdout); err != nil {
		fmt.Fprintln(stderr, "journal compact:", err)
		return 1
	}
	return 0
}

// parseRetention reads the retention period: a duration of whole seconds, at
// least one, since a receipt's servedAt is to the second.
func parseRetention(text string) (time.Duration, error) {
	d, err := time.ParseDuration(text)
	if err != nil || d < time.Second || d%time.Second != 0 {
		return 0, fmt.Errorf("--retention %q is not a whole number of seconds, at least one, written as a duration such as 720h", text)
	}
	return d, nil
}

// compactStep is a test's way of dying, or of a sync failing, at a named point
// of a compaction: an error it returns ends the compaction there, with nothing
// undone, as a crash would.
var compactStep func(point string) error

func compactStepped(point string) error {
	if compactStep != nil {
		return compactStep(point)
	}
	return nil
}

// retirementLimit bounds a retirement record: its members and the store's path.
const retirementLimit = 8 << 10

// retirementNames bounds how many retirements of one namespace an archive holds.
const retirementNames = 1 << 16

type journalCompaction struct {
	store, journal, archive string
	storeInfo               os.FileInfo
	actions, archived       *os.Root
	retention               time.Duration
	now                     time.Time
	out                     io.Writer
	reservations, subjects  map[string]bool
	retired, kept, finished int
}

func compactJournal(storePath, archivePath string, retention time.Duration, clock func() time.Time, out io.Writer) error {
	if !actionJournalSupported {
		return errors.New("action-journal-unavailable: the action journal is kept only on Unix hosts, and this host keeps none")
	}
	store, err := resolvedDirectory(storePath)
	if err != nil {
		return fmt.Errorf("action-journal-unavailable: the store %s is not a directory: nothing was compacted", storePath)
	}
	lock, err := lockDirectory(store, true)
	if errors.Is(err, errDirectoryHeld) {
		return fmt.Errorf("action-journal-held: a gateway process is serving the store %s, or another compaction holds it: stop every gateway process that serves it, then compact again", store)
	}
	if err != nil {
		return fmt.Errorf("action-journal-unavailable: the store %s could not be locked against a gateway process: %v: nothing was compacted", store, err)
	}
	defer lock.Close()
	storeRoot, err := os.OpenRoot(store)
	if err != nil {
		return fmt.Errorf("action-journal-unavailable: the store %s cannot be held: nothing was compacted", store)
	}
	defer storeRoot.Close()
	locked, lockErr := lock.Stat()
	held, heldErr := storeRoot.Stat(".")
	if lockErr != nil || heldErr != nil || !os.SameFile(locked, held) {
		return fmt.Errorf("action-journal-invalid: the store %s changed while it was locked: nothing was compacted", store)
	}
	c := &journalCompaction{
		store: store, storeInfo: held, journal: filepath.Join(store, "actions"), retention: retention,
		now: clock().UTC(), out: out, reservations: map[string]bool{}, subjects: map[string]bool{},
	}
	if info, err := storeRoot.Lstat("actions"); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("action-journal-unavailable: the store %s holds no journal: nothing was compacted", store)
	} else if err != nil {
		return fmt.Errorf("action-journal-unavailable: the journal %s cannot be read: nothing was compacted", c.journal)
	} else if !privateDirectory(info) {
		return fmt.Errorf("action-journal-invalid: the journal %s is not a private directory: nothing was compacted", c.journal)
	}
	if c.actions, err = openActionDirectory(storeRoot, "actions"); err != nil {
		return fmt.Errorf("action-journal-unavailable: the journal %s cannot be read: nothing was compacted", c.journal)
	}
	defer c.actions.Close()
	// Everything the journal says of its keys is read before anything moves: a
	// record that does not read could name an entry that must stay.
	if err := c.readIndex(); err != nil {
		return err
	}
	entries, err := listHeld(c.actions)
	if err != nil {
		return fmt.Errorf("action-journal-unavailable: the journal %s cannot be read: nothing was compacted", c.journal)
	}
	archiveLock, err := c.openArchive(archivePath)
	if err != nil {
		return err
	}
	defer archiveLock.Close()
	defer c.archived.Close()
	if err := c.finishInterrupted(); err != nil {
		return err
	}
	for _, e := range entries {
		if err := c.compactEntry(e); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "compacted %s: %d retired, %d kept, %d finished; the archive is %s\n", c.journal, c.retired, c.kept, c.finished, c.archive)
	return nil
}

// resolvedDirectory is path made absolute, every link followed, and a directory.
func resolvedDirectory(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", errors.New("not a directory")
	}
	return resolved, nil
}

// listHeld is a held directory's entries, by name.
func listHeld(root *os.Root) ([]os.DirEntry, error) {
	f, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

// privateDirectory is a directory, not a link, that only its owner reaches.
func privateDirectory(info os.FileInfo) bool {
	return info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o077 == 0
}

func isStaging(e os.DirEntry) bool {
	return strings.HasPrefix(e.Name(), ".staging-") && e.IsDir()
}

// readIndex reads every first-scope record, for the entries they name: its
// reservation and its subject record. A record that does not read refuses the
// whole compaction: an entry it names would be read as no key's.
func (c *journalCompaction) readIndex() error {
	path := filepath.Join(c.journal, actionIndexDirectory)
	if info, err := c.actions.Lstat(actionIndexDirectory); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("action-journal-unavailable: the first-scope index %s cannot be read: nothing was compacted", path)
	} else if !privateDirectory(info) {
		return fmt.Errorf("action-journal-invalid: the first-scope index %s is not a private directory: nothing was compacted", path)
	}
	index, err := openActionDirectory(c.actions, actionIndexDirectory)
	if err != nil {
		return fmt.Errorf("action-journal-unavailable: the first-scope index %s cannot be read: nothing was compacted", path)
	}
	defer index.Close()
	records, err := listHeld(index)
	if err != nil {
		return fmt.Errorf("action-journal-unavailable: the first-scope index %s cannot be read: nothing was compacted", path)
	}
	for _, e := range records {
		if isStaging(e) {
			continue
		}
		name := e.Name()
		hashed, isRecord := strings.CutSuffix(name, ".json")
		if !isRecord || !isLowerHexOfLen(hashed, 64) {
			return fmt.Errorf("action-journal-invalid: %s is not a first-scope record: nothing was compacted", filepath.Join(path, name))
		}
		raw, err := readActionRecord(index, name, actionIndexLimit)
		if err != nil {
			return fmt.Errorf("action-journal-invalid: the first-scope record %s does not read: nothing was compacted", filepath.Join(path, name))
		}
		reservation, subject, ok := parseFirstScopeRecord(raw, hashed)
		if !ok {
			return fmt.Errorf("action-journal-invalid: the first-scope record %s does not read: nothing was compacted", filepath.Join(path, name))
		}
		c.reservations[reservation] = true
		if subject != "" {
			c.subjects[subject] = true
		}
	}
	return nil
}

// parseFirstScopeRecord reads a first-scope record as the gateway writes it
// (actionFirstScope), held to the name it is kept under: the hash of its key.
func parseFirstScopeRecord(raw []byte, name string) (reservation, subject string, ok bool) {
	v, err := parseJSON(raw)
	record, isObject := v.(*vObject)
	if err != nil || !isObject {
		return "", "", false
	}
	if exactlyMembers(record, map[string]bool{"indexVersion": true, "authority": true, "key": true, "reservation": true, "scope": true, "subjectRecord": false}, "action key index") != nil {
		return "", "", false
	}
	version, _ := memberString(record, "indexVersion")
	key, _ := memberString(record, "key")
	_, authority := memberString(record, "authority")
	reservation, _ = memberString(record, "reservation")
	scope, _ := record.get("scope")
	_, scoped := scope.(*vObject)
	keyName := newObject()
	keyName.set("key", vString(key))
	if version != actionIndexVersion || !isLowerHexOfLen(key, 64) || !authority || !isLowerHexOfLen(reservation, 64) || !scoped || actionHash("action-key-index", keyName) != name {
		return "", "", false
	}
	if _, named := record.get("subjectRecord"); named {
		if subject, _ = memberString(record, "subjectRecord"); !isLowerHexOfLen(subject, 64) {
			return "", "", false
		}
	}
	return reservation, subject, true
}

// openArchive holds the archive: a private directory outside the store, made
// if it is not there, on the journal's filesystem, and locked against another
// compaction. Nothing is made where any of that does not hold.
func (c *journalCompaction) openArchive(archivePath string) (io.Closer, error) {
	notPrivate := fmt.Errorf("action-journal-archive: the archive %s is not a private directory: nothing was compacted", archivePath)
	abs, err := filepath.Abs(archivePath)
	if err != nil {
		return nil, notPrivate
	}
	info, err := os.Lstat(abs)
	made := false
	if errors.Is(err, os.ErrNotExist) {
		parent, err := resolvedDirectory(filepath.Dir(abs))
		if err != nil {
			return nil, fmt.Errorf("action-journal-archive: the directory %s to make the archive in is not there: nothing was compacted", filepath.Dir(abs))
		}
		abs = filepath.Join(parent, filepath.Base(abs))
		if err := c.placeArchive(archivePath, parent, nil); err != nil {
			return nil, err
		}
		if err = os.Mkdir(abs, 0o700); err != nil {
			return nil, fmt.Errorf("action-journal-archive: the archive %s could not be made: nothing was compacted", archivePath)
		}
		made = true
		info, err = os.Lstat(abs)
		if err != nil {
			return nil, notPrivate
		}
	} else if err != nil {
		return nil, notPrivate
	}
	if !privateDirectory(info) {
		return nil, notPrivate
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, notPrivate
	}
	if err := c.placeArchive(archivePath, resolved, info); err != nil {
		return nil, err
	}
	if made {
		if err := syncDirectoryAt(filepath.Dir(resolved)); err != nil {
			return nil, fmt.Errorf("action-journal-archive: the archive %s was made, and its durability was not established: nothing was compacted", archivePath)
		}
	}
	lock, err := lockDirectory(resolved, true)
	if errors.Is(err, errDirectoryHeld) {
		return nil, fmt.Errorf("action-journal-archive: another compaction holds the archive %s: nothing was compacted", resolved)
	} else if err != nil {
		return nil, fmt.Errorf("action-journal-archive: the archive %s could not be locked: nothing was compacted", resolved)
	}
	root, err := os.OpenRoot(resolved)
	if err != nil {
		lock.Close()
		return nil, notPrivate
	}
	locked, lockErr := lock.Stat()
	opened, openErr := root.Stat(".")
	journal, journalErr := c.actions.Stat(".")
	if lockErr != nil || openErr != nil || journalErr != nil || !os.SameFile(locked, opened) || !os.SameFile(info, opened) {
		root.Close()
		lock.Close()
		return nil, fmt.Errorf("action-journal-archive: the archive %s changed while it was opened: nothing was compacted", resolved)
	}
	if !sameDevice(journal, opened) {
		root.Close()
		lock.Close()
		return nil, fmt.Errorf("action-journal-archive: the archive %s is on another filesystem than the journal, and a move there would be a copy and a removal: nothing was compacted", resolved)
	}
	c.archive, c.archived = resolved, root
	return lock, nil
}

// placeArchive refuses an archive that is the store, is inside it, or holds
// it. at is the archive's resolved directory, or, for one not made yet, the
// directory it is to be made in, and archive the archive's own, where it is
// there. Directories are compared as files, along each path's directories, and
// not by their names: a filesystem that ignores case, or a second mount of a
// directory, gives one directory two names.
func (c *journalCompaction) placeArchive(archivePath, at string, archive os.FileInfo) error {
	inside, err := directoryAtOrAbove(at, c.storeInfo)
	if err == nil && !inside && archive != nil {
		var holds bool
		holds, err = directoryAtOrAbove(c.store, archive)
		if err == nil && holds {
			return fmt.Errorf("action-journal-archive: the archive %s holds the store %s, and it must be outside it: nothing was compacted", archivePath, c.store)
		}
	}
	if err != nil {
		return fmt.Errorf("action-journal-archive: whether the archive %s is outside the store %s could not be established: nothing was compacted", archivePath, c.store)
	}
	if inside {
		return fmt.Errorf("action-journal-archive: the archive %s is inside the store %s, and it must be outside it: nothing was compacted", archivePath, c.store)
	}
	return nil
}

// directoryAtOrAbove reports whether the directory at path, or one above it,
// is dir. A directory along the way that cannot be read refuses.
func directoryAtOrAbove(path string, dir os.FileInfo) (bool, error) {
	for {
		info, err := os.Stat(path)
		if err != nil {
			return false, err
		}
		if os.SameFile(info, dir) {
			return true, nil
		}
		parent := filepath.Dir(path)
		if parent == path {
			return false, nil
		}
		path = parent
	}
}

// syncDirectoryAt makes the entries of the directory at path durable.
func syncDirectoryAt(path string) error {
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	return syncActionDirectory(root)
}

// finishInterrupted gives its final name to every retirement a compaction that
// stopped had moved and not yet named. A staging directory that holds only its
// record retired nothing, and is left as it is.
func (c *journalCompaction) finishInterrupted() error {
	entries, err := listHeld(c.archived)
	if err != nil {
		return fmt.Errorf("action-journal-archive: the archive %s cannot be read: nothing was compacted", c.archive)
	}
	for _, e := range entries {
		if !isStaging(e) {
			continue
		}
		path := filepath.Join(c.archive, e.Name())
		stage, err := openActionDirectory(c.archived, e.Name())
		if err != nil {
			return fmt.Errorf("action-journal-archive: %s is not a private directory: the compaction stopped there", path)
		}
		moved, err := stagedMove(stage)
		if err != nil {
			stage.Close()
			return fmt.Errorf("action-journal-archive: %s holds what this command does not stage: the compaction stopped there", path)
		}
		if moved == "" {
			stage.Close()
			continue
		}
		raw, err := readActionRecord(stage, "retirement.json", retirementLimit)
		stage.Close()
		namespace, recorded, ok := parseRetirementRecord(raw)
		if err != nil || !ok || recorded != moved {
			return fmt.Errorf("action-journal-archive: %s holds a moved %s whose retirement record does not read: the compaction stopped there", path, moved)
		}
		final, err := c.publish(e.Name(), namespace)
		if err != nil {
			return err
		}
		c.finished++
		fmt.Fprintf(c.out, "finished %s: the retirement of %s an interrupted compaction had moved\n", final, namespace)
	}
	return nil
}

// stagedMove is what a staging directory holds beside its record: "entry", a
// journal entry moved whole; "action.json", an indexed entry's record moved
// alone; or "" for nothing moved.
func stagedMove(stage *os.Root) (string, error) {
	files, err := listHeld(stage)
	if err != nil {
		return "", err
	}
	moved := ""
	for _, f := range files {
		switch name := f.Name(); {
		case name == "retirement.json":
		case moved == "" && name == "entry" && f.IsDir():
			moved = name
		case moved == "" && name == "action.json" && f.Type().IsRegular():
			moved = name
		default:
			return "", errors.New("unexpected")
		}
	}
	return moved, nil
}

// retirementRecord is what a retirement records, beside what it moved: the
// store and the entry's namespace, its class, what was moved, the receipt it
// cites with its outcome and when it was served (null for an entry that never
// sent), the retention period it was judged under, and when it was archived.
func (c *journalCompaction) retirementRecord(namespace, class, moved string, ev *retainedEvidence) []byte {
	o := newObject()
	o.set("recordVersion", vString("1"))
	o.set("store", vString(c.store))
	o.set("namespace", vString(namespace))
	o.set("class", vString(class))
	o.set("moved", vString(moved))
	if ev == nil {
		o.set("receipt", vNull{})
		o.set("outcome", vNull{})
		o.set("servedAt", vNull{})
	} else {
		r := newObject()
		r.set("sessionId", vString(ev.sessionID))
		r.set("callIndex", vInt(ev.callIndex))
		o.set("receipt", r)
		o.set("outcome", vString(ev.outcome))
		o.set("servedAt", vString(ev.servedAt))
	}
	o.set("retentionSeconds", vInt(int64(c.retention/time.Second)))
	o.set("archivedAt", vString(c.now.Truncate(time.Second).Format("2006-01-02T15:04:05Z")))
	return canon(o)
}

// parseRetirementRecord reads a retirement record, for the namespace it
// retired and what it moved.
func parseRetirementRecord(raw []byte) (namespace, moved string, ok bool) {
	v, err := parseJSON(raw)
	record, isObject := v.(*vObject)
	if err != nil || !isObject {
		return "", "", false
	}
	members := map[string]bool{"recordVersion": true, "store": true, "namespace": true, "class": true, "moved": true, "receipt": true, "outcome": true, "servedAt": true, "retentionSeconds": true, "archivedAt": true}
	if exactlyMembers(record, members, "retirement record") != nil {
		return "", "", false
	}
	version, _ := memberString(record, "recordVersion")
	namespace, _ = memberString(record, "namespace")
	moved, _ = memberString(record, "moved")
	if version != "1" || !isLowerHexOfLen(namespace, 64) || (moved != "entry" && moved != "action.json") {
		return "", "", false
	}
	return namespace, moved, true
}

// publish gives a staging directory of the archive its final name: the
// namespace and the first number no retirement of it holds. A rename onto a
// name that holds a retirement fails, so none is replaced.
func (c *journalCompaction) publish(stage, namespace string) (string, error) {
	for n := 1; n <= retirementNames; n++ {
		name := fmt.Sprintf("%s.%d", namespace, n)
		if _, err := c.archived.Lstat(name); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("action-journal-archive: the archive %s cannot be read: the compaction stopped there", c.archive)
		}
		if err := c.archived.Rename(stage, name); errors.Is(err, os.ErrExist) {
			continue
		} else if err != nil {
			return "", fmt.Errorf("action-journal-archive: %s could not be named %s in the archive: the compaction stopped there", stage, name)
		}
		if err := syncActionDirectory(c.archived); err != nil {
			return "", fmt.Errorf("action-journal-archive: %s was named in the archive, and its durability was not established: the compaction stopped there", name)
		}
		return name, nil
	}
	return "", fmt.Errorf("action-journal-archive: the archive holds %d retirements of %s: the compaction stopped there", retirementNames, namespace)
}

// retainedEvidence is what an action.json says of its receipt.
type retainedEvidence struct {
	sessionID, outcome, servedAt string
	callIndex                    int64
	served                       time.Time
}

// compactJournalFiles are the files the gateway writes in an entry. An entry
// that holds anything else, but a staging directory, is not read as one.
func compactJournalFile(name string) bool {
	return name != "response.json" && actionJournalName(name)
}

// verdict is what becomes of an entry: kept, with why, or retired.
type verdict struct {
	retire, class, why string
	evidence           *retainedEvidence
	held               os.FileInfo
}

func kept(why string) verdict { return verdict{why: why} }

func (c *journalCompaction) compactEntry(e os.DirEntry) error {
	name := e.Name()
	switch {
	case name == actionIndexDirectory:
		return nil
	case isStaging(e):
		c.kept++
		fmt.Fprintf(c.out, "kept %s: a staging directory a crash left, no entry\n", name)
		return nil
	case !isLowerHexOfLen(name, 64):
		c.kept++
		fmt.Fprintf(c.out, "kept %s: not a journal entry\n", name)
		return nil
	}
	v := c.classify(name)
	if v.retire == "" {
		c.kept++
		fmt.Fprintf(c.out, "kept %s: %s\n", name, v.why)
		return nil
	}
	return c.retire(name, v)
}

// classify reads an entry as the procedure does, the first class that fits
// being its class, and with the gateway's own readings of each file. Only an
// entry proven to have never sent, or answered and past the retention period,
// is retired; anything this cannot read stays.
func (c *journalCompaction) classify(namespace string) verdict {
	const damaged = "; follow the procedure for a damaged entry"
	if info, err := c.actions.Lstat(namespace); err != nil || !privateDirectory(info) {
		return kept("does not read: the entry is not a private directory" + damaged)
	}
	entry, err := openActionDirectory(c.actions, namespace)
	if err != nil {
		return kept("does not read: the entry cannot be read" + damaged)
	}
	defer entry.Close()
	held, err := entry.Stat(".")
	files, listErr := listHeld(entry)
	if err != nil || listErr != nil {
		return kept("does not read: the entry cannot be listed" + damaged)
	}
	present, unexpected := map[string]bool{}, ""
	for _, f := range files {
		switch {
		case isStaging(f):
		case compactJournalFile(f.Name()):
			present[f.Name()] = true
		case unexpected == "":
			unexpected = f.Name()
		}
	}
	claim := &actionClaim{root: entry}
	if claim.closed() {
		return kept("closed")
	}
	if c.subjects[namespace] || (present["scope.json"] && !present["intent.json"]) {
		return kept("subject record")
	}
	if c.reservations[namespace] || present["scope.json"] {
		if !present["action.json"] {
			return kept("indexed")
		}
		why, ev, record := c.readsWhole(namespace, claim, present, unexpected)
		switch {
		case why != "":
			return kept("indexed, does not read: " + why + damaged)
		case ev.outcome != "response":
			return kept("indexed, uncertain: the target is the operator's to check")
		case !c.pastRetention(ev):
			return kept(fmt.Sprintf("indexed, answered, served %s, within the retention period", ev.servedAt))
		}
		return verdict{retire: "action.json", class: "indexed", evidence: ev, held: record}
	}
	why, ev, _ := c.readsWhole(namespace, claim, present, unexpected)
	if why != "" {
		return kept("does not read: " + why + damaged)
	}
	if !present["action.json"] {
		for n := 1; n <= actionDispatchAttempts; n++ {
			if !present[actionDispatchName(n)] {
				continue
			}
			if _, err := claim.read(actionNotDispatchedName(n), 1024); err != nil {
				return kept("begun without a record: the next request records uncertainty and reads back")
			}
		}
		return verdict{retire: "entry", class: "never-sent", held: held}
	}
	if ev.outcome != "response" {
		return kept("uncertain: the target is the operator's to check")
	}
	if !c.pastRetention(ev) {
		return kept(fmt.Sprintf("answered, served %s, within the retention period", ev.servedAt))
	}
	return verdict{retire: "entry", class: "answered", evidence: ev, held: held}
}

// readsWhole is why an entry does not read, or "": a file the gateway does not
// write, no intent or one this release does not read, an answer with no
// marker, or an action.json that does not read or is not the entry's key's.
// With an action.json, its evidence and the file's identity.
func (c *journalCompaction) readsWhole(namespace string, claim *actionClaim, present map[string]bool, unexpected string) (string, *retainedEvidence, os.FileInfo) {
	if unexpected != "" {
		return fmt.Sprintf("it holds %s, which the gateway does not write", unexpected), nil, nil
	}
	if !present["intent.json"] {
		return "intent.json is missing", nil, nil
	}
	if why := intentReads(claim); why != "" {
		return why, nil, nil
	}
	// Each marker is durable before the next can exist, so one above a missing
	// marker says the lower one was lost, and what it recorded with it.
	missing := 0
	for n := 1; n <= actionDispatchAttempts; n++ {
		switch marker := present[actionDispatchName(n)]; {
		case present[actionNotDispatchedName(n)] && !marker:
			return actionNotDispatchedName(n) + " answers no marker", nil, nil
		case !marker && missing == 0:
			missing = n
		case marker && missing != 0:
			return fmt.Sprintf("%s stands above a missing %s", actionDispatchName(n), actionDispatchName(missing)), nil, nil
		}
	}
	if !present["action.json"] {
		return "", nil, nil
	}
	return retainedReads(namespace, claim, present["scope.json"])
}

// intentReads is why an intent does not read as the gateway holds one to a
// request (holdsIdentity), or "".
func intentReads(claim *actionClaim) string {
	raw, err := claim.read("intent.json", 1024)
	if err != nil {
		return "intent.json does not read"
	}
	v, err := parseJSON(raw)
	intent, isObject := v.(*vObject)
	if err != nil || !isObject || exactlyMembers(intent, map[string]bool{"journalVersion": true, "identityVersion": false, "fingerprint": true}, "action intent") != nil {
		return "intent.json does not read"
	}
	version, _ := memberString(intent, "journalVersion")
	fingerprint, _ := memberString(intent, "fingerprint")
	if version != actionJournalVersion || !isLowerHexOfLen(fingerprint, 64) {
		return "intent.json does not read"
	}
	if identity, recorded := intent.get("identityVersion"); recorded && identity != vString(actionIdentityVersion) {
		return "intent.json records an identity version this release does not read: upgrade rather than remove it"
	}
	return ""
}

// retainedReads reads an entry's action.json as a retained action: the members
// the gateway retains, an action receipt with a delivery, and a receipt of
// this entry's key, its namespace computed from the receipt as the gateway
// computes it from the request (actionNamespace).
func retainedReads(namespace string, claim *actionClaim, delegated bool) (string, *retainedEvidence, os.FileInfo) {
	const unreadable = "action.json does not read"
	info, err := claim.root.Lstat("action.json")
	if err != nil {
		return unreadable, nil, nil
	}
	raw, err := claim.read("action.json", actionJournalResponseLimit)
	if err != nil {
		return unreadable, nil, nil
	}
	v, err := parseJSON(raw)
	retained, isObject := v.(*vObject)
	if err != nil || !isObject || exactlyMembers(retained, map[string]bool{"result": true, "receipt": true, "salts": true}, "retained action") != nil {
		return unreadable, nil, nil
	}
	rv, _ := retained.get("receipt")
	ro, isObject := rv.(*vObject)
	if !isObject {
		return unreadable, nil, nil
	}
	r, err := receiptFrom(ro)
	if err != nil || r.kind != "action" || r.delivery == nil || !isStamp(r.servedAt) || requireSession(r.sessionID) != nil {
		return unreadable, nil, nil
	}
	scope := newObject()
	scope.set("authority", vString(r.authority))
	scope.set("key", vString(r.delivery.key))
	domain := "action-key"
	if delegated {
		recorded, err := claim.read("scope.json", actionScopeLimit)
		if err != nil {
			return unreadable, nil, nil
		}
		value, err := parseJSON(recorded)
		if err != nil {
			return unreadable, nil, nil
		}
		scope.set("scope", value)
		domain = "delegated-action-key"
	} else {
		av, _ := ro.get("action")
		action, _ := av.(*vObject)
		var requester *vObject
		if action != nil {
			iv, _ := action.get("requester")
			requester, _ = iv.(*vObject)
		}
		if requester == nil {
			return unreadable, nil, nil
		}
		issuer, _ := memberString(requester, "issuer")
		subject, _ := memberString(requester, "subject")
		scope.set("issuer", vString(issuer))
		scope.set("subject", vString(subject))
	}
	if actionHash(domain, scope) != namespace {
		return "action.json is not this entry's key's", nil, nil
	}
	served, _ := time.Parse("2006-01-02T15:04:05Z", r.servedAt)
	return "", &retainedEvidence{sessionID: r.sessionID, callIndex: r.callIndex, outcome: r.delivery.outcome, servedAt: r.servedAt, served: served}, info
}

// pastRetention reports whether a receipt was served longer ago than the
// retention period: at the period's end exactly, it is not.
func (c *journalCompaction) pastRetention(ev *retainedEvidence) bool {
	return ev.served.Add(c.retention).Before(c.now)
}

// retire moves an entry, or an indexed entry's action.json, into the archive
// with its retirement record: a staging directory, durable in the archive, takes
// the record, durable, then what is moved, durable on both sides, and is then
// named. What is moved is the file or directory that was classified, by its
// identity, or nothing is.
func (c *journalCompaction) retire(namespace string, v verdict) error {
	record := c.retirementRecord(namespace, v.class, v.retire, v.evidence)
	stage, err := newActionStage(c.archived)
	if err != nil {
		return fmt.Errorf("action-journal-archive: a staging directory could not be made in the archive %s: the compaction stopped there", c.archive)
	}
	if err = syncActionDirectory(c.archived); err != nil {
		return fmt.Errorf("action-journal-archive: a staging directory's durability in the archive %s was not established: the compaction stopped there", c.archive)
	}
	if err = compactStepped("stage " + namespace); err != nil {
		return err
	}
	if err = writeActionStaged(c.archived, stage, actionRecord{"retirement.json", record, retirementLimit}); err != nil {
		return fmt.Errorf("action-journal-archive: the retirement record of %s could not be made durable: the compaction stopped there", namespace)
	}
	staged, err := c.archived.OpenRoot(stage)
	if err != nil {
		return fmt.Errorf("action-journal-archive: the staging directory %s cannot be held: the compaction stopped there", filepath.Join(c.archive, stage))
	}
	defer staged.Close()
	if err = syncActionDirectory(staged); err != nil {
		return fmt.Errorf("action-journal-archive: the retirement record of %s could not be made durable: the compaction stopped there", namespace)
	}
	if err = compactStepped("record " + namespace); err != nil {
		return err
	}
	from, to := filepath.Join(c.journal, namespace), filepath.Join(c.archive, stage, "entry")
	what := namespace
	if v.retire == "action.json" {
		from, to = filepath.Join(from, "action.json"), filepath.Join(c.archive, stage, "action.json")
		what = namespace + " action.json"
	}
	if now, err := os.Lstat(from); err != nil || !os.SameFile(now, v.held) {
		return fmt.Errorf("action-journal-invalid: %s changed after it was read, and was not moved: the compaction stopped there", what)
	}
	// The move is made by path: the staging directory there must still be
	// the one the record was made durable in.
	if holding, heldErr := staged.Stat("."); heldErr != nil {
		return fmt.Errorf("action-journal-archive: the staging directory %s cannot be held: the compaction stopped there", filepath.Join(c.archive, stage))
	} else if there, err := os.Lstat(filepath.Dir(to)); err != nil || !os.SameFile(there, holding) {
		return fmt.Errorf("action-journal-archive: the staging directory %s was replaced after its record was made, and %s was not moved: the compaction stopped there", filepath.Join(c.archive, stage), what)
	}
	if err = os.Rename(from, to); err != nil {
		if crossDevice(err) {
			return fmt.Errorf("action-journal-archive: %s cannot be moved to the archive %s, which is on another mount than the journal: the compaction stopped there", what, c.archive)
		}
		return fmt.Errorf("action-journal-unavailable: %s could not be moved to the archive: the compaction stopped there", what)
	}
	if after, err := os.Lstat(to); err != nil || !os.SameFile(after, v.held) {
		return fmt.Errorf("action-journal-archive: what was moved of %s is not what was read: the compaction stopped there", what)
	}
	if err = syncActionDirectory(staged); err != nil {
		return fmt.Errorf("action-journal-archive: the move of %s into the archive was not made durable: the compaction stopped there", what)
	}
	if err = c.syncLeft(namespace, v.retire); err != nil {
		return fmt.Errorf("action-journal-unavailable: the move of %s out of the journal was not made durable: the compaction stopped there", what)
	}
	if err = compactStepped("move " + namespace); err != nil {
		return err
	}
	final, err := c.publish(stage, namespace)
	if err != nil {
		return err
	}
	if err = compactStepped("publish " + namespace); err != nil {
		return err
	}
	c.retired++
	switch v.class {
	case "never-sent":
		fmt.Fprintf(c.out, "retired %s: never sent; archived as %s\n", namespace, final)
	case "answered":
		fmt.Fprintf(c.out, "retired %s: answered, receipt %s/%d served %s; archived as %s\n", namespace, v.evidence.sessionID, v.evidence.callIndex, v.evidence.servedAt, final)
	default:
		fmt.Fprintf(c.out, "retired %s action.json: indexed, answered, receipt %s/%d served %s; archived as %s\n", namespace, v.evidence.sessionID, v.evidence.callIndex, v.evidence.servedAt, final)
	}
	return nil
}

// syncLeft makes durable the directory a move took something out of: the
// journal, for an entry, or the entry, for its action.json.
func (c *journalCompaction) syncLeft(namespace, moved string) error {
	if moved != "action.json" {
		return syncActionDirectory(c.actions)
	}
	entry, err := openActionDirectory(c.actions, namespace)
	if err != nil {
		return err
	}
	defer entry.Close()
	return syncActionDirectory(entry)
}
