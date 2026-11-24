package main

// Who reads a refusal journal (ADR-0059 §8): gateway verify, gateway export,
// gateway journal open, and remove-scope, which removes it. No route serves
// one.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// bodyFits holds an entry's body to its journal's kinds: the operator
// kinds in operator, the refusal kinds in a refusal journal, so a body of
// one is never read as the other's.
func (e *journalEntry) bodyFits(body *vObject, journal string) bool {
	if isRefusalJournalName(journal) {
		kind, ok := refusalBodyLoads(body, journal)
		e.kind = kind
		return ok
	}
	return e.bodyLoads(body)
}

func isRefusalScope(s string) bool { return s == unscopedMarker || isScopeIdentifier(s) }

func isSha256Digest(s string) bool {
	rest, ok := strings.CutPrefix(s, "sha256:")
	return ok && isLowerHexOfLen(rest, 64)
}

func isCode(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// countsLoad holds a tally's object of counts: members among names, each
// an integer of at least one; it answers how many it holds.
func countsLoad(v value, names []string) (int, bool) {
	obj, ok := v.(*vObject)
	if !ok {
		return 0, false
	}
	allowed := setOf(names...)
	for _, name := range obj.names {
		n, _ := obj.get(name)
		count, isInt := n.(vInt)
		if !allowed[name] || !isInt || count < 1 {
			return 0, false
		}
	}
	return len(obj.names), true
}

// refusalBodyLoads is section 8's structural check of a refusal journal's
// body: exactly a refusal or a tally, of its form, whose scope gives the
// journal's name.
func refusalBodyLoads(body *vObject, journal string) (string, bool) {
	kind, _ := memberString(body, "kind")
	scope, ok := memberString(body, "scope")
	if !ok || !isRefusalScope(scope) || refusalJournalName(scope) != journal {
		return kind, false
	}
	switch kind {
	case "refusal":
		if !exactMembers(body, map[string]bool{"kind": true, "scope": true, "route": true, "reason": true, "refusal": true,
			"outOfScope": true, "tool": true, "descriptorDigest": true, "status": true, "answeredAt": true, "caller": true, "delegation": true, "nonce": true, "request": true}) {
			return kind, false
		}
		route, _ := memberString(body, "route")
		reason, _ := memberString(body, "reason")
		if !refusalReasons[route][reason] {
			return kind, false
		}
		refusal, hasRefusal := memberString(body, "refusal")
		if _, given := body.get("refusal"); given != (reason == "delegation" || reason == "grant") || (given && (!hasRefusal || !isCode(refusal))) {
			return kind, false
		}
		outOfScope, hasOut := memberString(body, "outOfScope")
		if _, given := body.get("outOfScope"); given != (refusal == refusalOutOfScope) || (given && (!hasOut || outOfScope == "")) {
			return kind, false
		}
		// a descriptor digest is the resolved tool's, never without it
		tool, hasTool := memberString(body, "tool")
		if _, given := body.get("tool"); given && (!hasTool || tool == "") {
			return kind, false
		}
		digest, hasDigest := memberString(body, "descriptorDigest")
		if _, given := body.get("descriptorDigest"); given && (!hasTool || !hasDigest || !isDigest(digest)) {
			return kind, false
		}
		status, _ := body.get("status")
		if n, isInt := status.(vInt); !isInt || n < 400 || n > 499 {
			return kind, false
		}
		at, _ := memberString(body, "answeredAt")
		if _, err := time.Parse("2006-01-02T15:04:05.000Z", at); err != nil || len(at) != 24 {
			return kind, false
		}
		raw, _ := body.get("caller")
		caller, isObject := raw.(*vObject)
		if !isObject || !exactMembers(caller, map[string]bool{"issuer": true, "subject": true, "tokenDigest": true}) || len(caller.names) != 3 {
			return kind, false
		}
		issuer, ok1 := memberString(caller, "issuer")
		subject, ok2 := memberString(caller, "subject")
		digest, ok3 := memberString(caller, "tokenDigest")
		if !ok1 || !ok2 || !ok3 || issuer == "" || subject == "" || !isDigest(digest) {
			return kind, false
		}
		if raw, given := body.get("delegation"); given {
			d, isObject := raw.(*vObject)
			if !isObject || !exactMembers(d, map[string]bool{"id": true, "host": true, "actor": true, "subject": true, "chain": true}) || len(d.names) != 5 {
				return kind, false
			}
			if _, isArray := refusalMember(d, "chain").(vArray); !isArray {
				return kind, false
			}
		}
		nonce, _ := memberString(body, "nonce")
		request, _ := memberString(body, "request")
		if !isLowerHexOfLen(nonce, 64) || !isSha256Digest(request) {
			return kind, false
		}
		return kind, true
	case "tally":
		if !exactMembers(body, map[string]bool{"kind": true, "scope": true, "from": true, "to": true, "limit": true, "dropped": true, "full": true}) {
			return kind, false
		}
		from, _ := memberString(body, "from")
		to, _ := memberString(body, "to")
		f, err1 := time.Parse("2006-01-02T15:04:05Z", from)
		t, err2 := time.Parse("2006-01-02T15:04:05Z", to)
		if err1 != nil || err2 != nil || len(from) != 20 || len(to) != 20 || t.Before(f) {
			return kind, false
		}
		limits, ok1 := countsLoad(refusalMember(body, "limit"), limitCountNames)
		dropped, ok2 := countsLoad(refusalMember(body, "dropped"), dropNames[:])
		if !ok1 || !ok2 || limits+dropped == 0 {
			return kind, false
		}
		if raw, given := body.get("full"); given {
			if b, isBool := raw.(vBool); !isBool || !bool(b) {
				return kind, false
			}
		}
		return kind, true
	}
	return kind, false
}

func refusalMember(obj *vObject, name string) value {
	v, _ := obj.get(name)
	return v
}

// refusalJournalJudgment is step 9 on one refusal journal: at most one
// finding, journal-entry-forged or journal-order, never one against the
// store, since a refusal journal binds nothing in it.
func judgeRefusalJournal(data []byte, name string, keys []reachedKey) (finding, int, int) {
	lines, torn := journalLines(data)
	entries := make([]*journalEntry, 0, len(lines))
	for i, line := range lines {
		e, ok := loadJournalEntry(line, name, keys)
		if !ok {
			return journalFinding("journal-entry-forged", name, i), 0, 0
		}
		entries = append(entries, e)
	}
	// the order, once every entry loads, as for the operator journal
	for i, e := range entries {
		if e.ordinal != int64(i) || (i == 0 && e.hasPrevious) ||
			(i > 0 && (!e.hasPrevious || e.previous != journalDigest(lines[i-1]) || e.keyPos < entries[i-1].keyPos)) {
			return journalFinding("journal-order", name, i), 0, 0
		}
	}
	return nil, len(entries), torn
}

// refusalJournalsIn are the refusal journals' names under a store's
// journals directory, sorted; a name of another form is not one.
func refusalJournalsIn(storeRoot string) ([]string, error) {
	dir := filepath.Join(storeRoot, journalsDir)
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("journal: %w", err)
	}
	var names []string
	for _, e := range entries {
		if name, ok := strings.CutSuffix(e.Name(), ".jsonl"); ok && isRefusalJournalName(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

// judgeRefusalJournals is SPEC.md §4 step 9 on every refusal journal of a
// store's root: a finding, or journal-from and any torn tail observed. A
// verdict by scope reads its own scope's journal alone, as it reports
// no other (ADR-0059 §8): another scope's journal that cannot be read does
// not stop it.
func (r *report) judgeRefusalJournals(storeRoot string, keys []reachedKey, only string) error {
	names, err := refusalJournalsIn(storeRoot)
	if err != nil {
		return err
	}
	for _, name := range names {
		if only != "" && name != only {
			continue
		}
		data, there, err := readJournalPath(storeRoot, name+".jsonl")
		if errors.Is(err, errJournalNotRegular) {
			continue
		}
		if err != nil {
			return err
		}
		if !there || len(data) == 0 {
			continue
		}
		if r.journals == nil {
			r.journals = map[string]bool{}
		}
		r.journals[name] = true
		f, n, torn := judgeRefusalJournal(data, name, keys)
		if f != nil {
			r.Findings = append(r.Findings, f)
			continue
		}
		if n > 0 {
			r.Observations = append(r.Observations, finding{"observation": "journal-from", "journal": name, "entries": int64(n)})
		}
		if torn > 0 {
			r.Observations = append(r.Observations, finding{"observation": "journal-torn-tail", "journal": name, "bytes": int64(torn)})
		}
	}
	return nil
}

// refusalJournalFilesIn are the refusal journals of a store's root, by name,
// whole, as an export writes them.
func refusalJournalFilesIn(storeRoot string) (map[string][]byte, error) {
	names, err := refusalJournalsIn(storeRoot)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, name := range names {
		data, there, err := readJournalPath(storeRoot, name+".jsonl")
		if err != nil {
			return nil, err
		}
		if there && len(data) > 0 {
			out[name] = data
		}
	}
	return out, nil
}

// pgRefusalJournalFiles are the refusal journals' rows, by name, as an
// export writes them.
func pgRefusalJournalFiles(tx pgTx) (map[string][]byte, error) {
	rows, err := tx.exec(`SELECT DISTINCT journal FROM gateway.journal_records WHERE journal LIKE 'refusal-%' ORDER BY journal`)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, row := range rows.rows {
		name := string(row[0])
		if !isRefusalJournalName(name) {
			continue
		}
		data, err := pgJournalFile(tx, name)
		if err != nil {
			return nil, err
		}
		out[name] = data
	}
	return out, nil
}

// putRefusalJournals writes the refusal journals into an export, in name
// order. No key and no cursor is written.
func putRefusalJournals(journals map[string][]byte, put func(path string, data []byte) error) error {
	names := make([]string, 0, len(journals))
	for name := range journals {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := put("store/"+journalsDir+"/"+name+".jsonl", journals[name]); err != nil {
			return err
		}
	}
	return nil
}

// --- remove-scope (ADR-0059 §8) ----------------------------------------------

// refusalRemoval is remove-scope's hold on a scope's refusal journal of the
// filesystem kind: its file locked from the read of its bytes to its
// removal, so a serving writer never interleaves.
type refusalRemoval struct {
	dir, name string
	file      *os.File
	data      []byte
}

func holdRefusalRemoval(storeRoot, scope string) (*refusalRemoval, error) {
	name := refusalJournalName(limitScopeKey(scope))
	r := &refusalRemoval{dir: filepath.Join(storeRoot, journalsDir), name: name}
	path := filepath.Join(r.dir, name+".jsonl")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, fmt.Errorf("the refusal journal: %v", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("the refusal journal: %w", errJournalNotRegular)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("the refusal journal: %v", err)
	}
	if err := lockJournalFile(file); err != nil {
		file.Close()
		return nil, fmt.Errorf("the refusal journal: %v", err)
	}
	if r.data, err = io.ReadAll(file); err != nil {
		unlockJournalFile(file)
		file.Close()
		return nil, fmt.Errorf("the refusal journal: %v", err)
	}
	r.file = file
	return r, nil
}

// describeRefusalRemoval gives the operator entry its two members where a
// refusal journal is removed (ADR-0056 §4, amended).
func describeRefusalRemoval(body *vObject, removed []byte) {
	if len(removed) == 0 {
		return
	}
	body.set("refusalJournalBytes", vInt(int64(len(removed))))
	body.set("refusalJournalDigest", vString(journalDigest(removed)))
}

// remove takes the journal's key and its cursor away, and then the journal:
// a run cut off between them leaves the journal, the bytes its operator
// entry names, which the next run or start completes; so a key beside no
// journal is never a removal's leftover, but one drawn since.
// refusalRemovalStep, where not nil, is told each step of a refusal
// journal's removal: a file's suffix once it is removed, "sync" once the
// directory is synced. A test seam.
var refusalRemovalStep func(step string)

func refusalRemovalStepped(step string) {
	if refusalRemovalStep != nil {
		refusalRemovalStep(step)
	}
}

func (r *refusalRemoval) remove() error {
	if !journalFilesLock {
		// No flock here, so the held handle excludes nothing, and the
		// platform refuses to delete a file a handle holds open: close it
		// first. remove-scope runs with the gateway stopped here.
		r.release()
	}
	// the key and the cursor go first, and their removal is synced before
	// the journal goes: a journal left without its key after a crash is one
	// a completion recognizes by the bytes its entry names, on every
	// filesystem, never a key left without its journal
	for _, suffix := range []string{".key", ".forwarded", ".jsonl"} {
		if suffix == ".jsonl" {
			syncDir(r.dir)
			refusalRemovalStepped("sync")
		}
		if err := os.Remove(filepath.Join(r.dir, r.name+suffix)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("the refusal journal's %s could not be removed: %v; the records stand, and a second run completes the removal", suffix, err)
		}
		refusalRemovalStepped(suffix)
	}
	syncDir(r.dir)
	refusalRemovalStepped("sync")
	return nil
}

func (r *refusalRemoval) release() {
	if r != nil && r.file != nil {
		unlockJournalFile(r.file)
		r.file.Close()
		r.file = nil
	}
}

// --- gateway journal name and gateway journal open ---------------------------

const journalNameUsage = `usage: gateway journal name --scope <key>
Prints the refusal journal's name of a scope key: its scope identifier, or
"unscoped" for the sources of none (ADR-0059 §1).`

const journalOpenUsage = `usage: gateway journal open --config <file> --journal <name> --ordinal <n> --route <route> --body <file> [--reveal-salt]
Answers "match" or "no match": whether the request body in <file>, sent to
<route>, is the one a refusal entry commits to. It opens the store of the
configuration as its own login (on the PostgreSQL kind, the run-time role),
reads the entry and the scope's key, and writes nothing. --reveal-salt also
prints that one entry's salt (ADR-0059 §3).`

func cmdJournalName(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] != "--scope" || !isRefusalScope(args[1]) {
		fmt.Fprintln(stderr, journalNameUsage)
		return 2
	}
	fmt.Fprintln(stdout, refusalJournalName(args[1]))
	return 0
}

func cmdJournalOpen(args []string, stdout, stderr io.Writer) int {
	flags := map[string]string{}
	reveal := false
	for rest := args; len(rest) > 0; {
		name := rest[0]
		if name == "--reveal-salt" {
			reveal, rest = true, rest[1:]
			continue
		}
		switch name {
		case "--config", "--journal", "--ordinal", "--route", "--body":
		default:
			fmt.Fprintln(stderr, journalOpenUsage)
			return 2
		}
		if _, given := flags[name]; given || len(rest) < 2 || rest[1] == "" {
			fmt.Fprintln(stderr, journalOpenUsage)
			return 2
		}
		flags[name], rest = rest[1], rest[2:]
	}
	ordinal, err := strconv.ParseInt(flags["--ordinal"], 10, 64)
	if len(flags) != 5 || err != nil || ordinal < 0 || !isRefusalJournalName(flags["--journal"]) || refusalReasons[flags["--route"]] == nil {
		fmt.Fprintln(stderr, journalOpenUsage)
		return 2
	}
	body, err := os.ReadFile(flags["--body"])
	if err != nil {
		fmt.Fprintln(stderr, "journal open: the body:", err)
		return 1
	}
	cfg, _, err := loadEngineConfig(flags["--config"], osEngineHost().account)
	if err != nil {
		fmt.Fprintln(stderr, "journal open:", err)
		return 1
	}
	matched, salt, err := openRefusalEntry(cfg, flags["--journal"], ordinal, flags["--route"], body)
	if err != nil {
		fmt.Fprintln(stderr, "journal open:", err)
		return 1
	}
	if reveal {
		fmt.Fprintln(stdout, "salt:", hex.EncodeToString(salt))
	}
	if !matched {
		fmt.Fprintln(stdout, "no match")
		return 1
	}
	fmt.Fprintln(stdout, "match")
	return 0
}

// openRefusalEntry reads the entry at ordinal and the journal's key from
// the configuration's store, and answers whether route and body give the
// entry's commitment, with the entry's salt.
func openRefusalEntry(cfg engineConfig, journal string, ordinal int64, route string, body []byte) (bool, []byte, error) {
	var data, key []byte
	if cfg.storage != nil {
		kind, err := openStorageKind(cfg.storage)
		if err != nil {
			return false, nil, err
		}
		defer kind.pool.close()
		if err := kind.transact(pgRead, func(tx pgTx) error {
			var err error
			data, err = pgJournalFile(tx, journal)
			return err
		}); err != nil {
			return false, nil, err
		}
		if key, err = (pgSecrets{kind}).getSecret(refusalKeyName(journal)); err != nil {
			return false, nil, fmt.Errorf("the journal's key could not be read: %v", err)
		}
	} else {
		var err error
		if data, _, err = readJournalPath(cfg.store, journal+".jsonl"); err != nil {
			return false, nil, err
		}
		raw, err := os.ReadFile(filepath.Join(cfg.store, journalsDir, journal+".key"))
		if err != nil {
			return false, nil, fmt.Errorf("the journal's key could not be read: %v", err)
		}
		if key, err = hex.DecodeString(strings.TrimSuffix(string(raw), "\n")); err != nil || len(key) != 32 {
			return false, nil, errors.New("the journal's key is not 32 bytes in hexadecimal")
		}
	}
	lines, _ := journalLines(data)
	if ordinal >= int64(len(lines)) {
		return false, nil, fmt.Errorf("journal %s holds no entry %d", journal, ordinal)
	}
	return matchRefusalEntry(lines[ordinal], key, route, body)
}

// matchRefusalEntry is the opening of one entry's commitment.
func matchRefusalEntry(line, key []byte, route string, body []byte) (bool, []byte, error) {
	v, err := parseRecordJSON(line)
	if err != nil {
		return false, nil, errors.New("the entry is not JSON")
	}
	obj, _ := v.(*vObject)
	if obj == nil {
		return false, nil, errors.New("the entry is not an object")
	}
	inner, _ := obj.get("body")
	b, _ := inner.(*vObject)
	if b == nil {
		return false, nil, errors.New("the entry has no body")
	}
	if kind, _ := memberString(b, "kind"); kind != "refusal" {
		return false, nil, errors.New("the entry is not a refusal")
	}
	nonceHex, _ := memberString(b, "nonce")
	request, _ := memberString(b, "request")
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil || len(nonce) != 32 {
		return false, nil, errors.New("the entry's nonce is not 32 bytes")
	}
	salt := refusalSalt(key, nonce)
	committedRoute, _ := memberString(b, "route")
	return committedRoute == route && bytes.Equal([]byte(refusalCommitment(salt, route, body)), []byte(request)), salt, nil
}
