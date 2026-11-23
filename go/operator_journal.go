package main

// The operator journal (docs/adr/0056-an-operator-journal-of-signed-chained-entries-in-the-store.md):
// one signed, chained entry for each operator command that changed the
// store, kept in the store at journals/<journal>.jsonl, and held by gateway
// verify (SPEC.md §4 step 9) to the removal file's bytes and the registry's
// command seals it names. Sections 1 to 3 of the record -- the placement,
// the envelope, the signing and the load rule -- are every journal's; the
// bodies and the rule against the store are the operator journal's.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

const (
	// journalContext is the prefix every journal entry's signature covers,
	// one for every journal, and no other kind's (ADR-0053, decision 2).
	journalContext = "judgment-pack-gateway/journal-entry/1:"
	// journalEnvelopeVersion is the envelope's form (ADR-0056 §2).
	journalEnvelopeVersion = "1"
	// journalLineBound is an entry's bound, its 0x0A not counted.
	journalLineBound = 4096
	// journalsDir is where a store of the filesystem kind keeps its journals.
	journalsDir = "journals"
	// operatorJournal is the operator journal's name.
	operatorJournal = "operator"
)

// operatorJournalVersion is the first engine configuration version whose
// journaled commands begin the operator journal (ADR-0056 §7). A command of
// an earlier version, or given flags, writes an entry only where the store
// already holds the journal: a journal once begun is never skipped.
const operatorJournalVersion = "41" // placeholder: the maintainer assigns the number in merge order

// errJournalPending is a staged entry the store does not match (ADR-0056 §5).
var errJournalPending = errors.New("an interrupted operator command left a journal entry the store does not match (journal-pending); nothing was changed")

// errJournalNotRegular is something at a journal's name that is not a
// regular file: a verifier reads it as no journal, a writer refuses it.
var errJournalNotRegular = errors.New("a journal's path holds something that is not a regular file")

// journalStepCut, where it is set, runs at a step of a journaled removal
// ("staged", after the entry is staged; "records", after the records are
// appended): a test's way of cutting a run off there.
var journalStepCut func(step string) error

// isJournalName is a journal's name: 1 to 32 characters, each a lowercase
// letter or "-".
func isJournalName(s string) bool {
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c != '-' && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}

func journalDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// --- the envelope (ADR-0056 §2, §3) ------------------------------------------

// signedJournalEntry is an entry of journal, signed through the configured
// signer, as its line with its 0x0A; a line past the bound is refused.
func signedJournalEntry(key *signingKey, journal string, ordinal int64, previous, at string, body *vObject) ([]byte, error) {
	obj := newObject()
	obj.set("journal", vString(journal))
	obj.set("journalVersion", vString(journalEnvelopeVersion))
	obj.set("ordinal", vInt(ordinal))
	if ordinal > 0 {
		obj.set("previous", vString(previous))
	}
	obj.set("at", vString(at))
	obj.set("keyId", vString(key.keyID))
	if key.alg == algES256 {
		obj.set("alg", vString(algES256))
	}
	obj.set("body", body)
	signature, err := key.signVerified(recordSigningInput(journalContext, obj))
	if err != nil {
		return nil, fmt.Errorf("the journal entry could not be signed: %v", err)
	}
	obj.set("signature", vString(hex.EncodeToString(signature)))
	line := canon(obj)
	if len(line) > journalLineBound {
		return nil, fmt.Errorf("the journal entry is %d bytes, past the bound of %d", len(line), journalLineBound)
	}
	return append(line, '\n'), nil
}

// journalEntry is an entry that loaded.
type journalEntry struct {
	line        []byte // without its 0x0A
	ordinal     int64
	previous    string
	hasPrevious bool
	keyPos      int
	kind        string
	// every operator body's
	registryFrom, removalFrom int64
	// a removal kind's
	removal       bool
	removalBytes  int64
	removalDigest string
	// a seal kind's
	sealing    bool
	seals      int64
	sealDigest string
	// store-continued's
	continuation string
}

// operatorBodies are the operator journal's body kinds, each with exactly
// its members beside kind, registryFrom and removalFrom: true where the
// member is required (ADR-0056 §4).
var operatorBodies = map[string]map[string]bool{
	"retain":          {"by": true, "scope": false, "acknowledgments": true, "acknowledgedBy": true, "sessions": true, "removalBytes": true, "removalDigest": true},
	"remove-scope":    {"by": true, "scope": true, "removalBytes": true, "removalDigest": true},
	"remove-artifact": {"by": true, "removalBytes": true, "removalDigest": true},
	"seal-open":       {"seals": true, "sealDigest": true, "delivered": true},
	"store-rotate":    {"seals": true, "sealDigest": true, "delivered": true},
	"store-continued": {"continuation": true, "previousJournalBytes": true, "previousJournalDigest": true},
}

func hexMember(obj *vObject, name string, n int) (string, bool) {
	v, _ := obj.get(name)
	s, ok := v.(vString)
	return string(s), ok && isLowerHexOfLen(string(s), n)
}

func scopeMember(obj *vObject, name string) bool {
	v, _ := obj.get(name)
	s, ok := v.(vString)
	return ok && isScopeIdentifier(string(s))
}

// loadJournalEntry is a complete line of journal as an entry that loads
// (ADR-0056 §6, journal-entry-forged): within the bound, one canonical JSON
// object of exactly the envelope's members, each of its form, a body of a
// kind with exactly that kind's members, the journal's own name, a key the
// walk reached, and a signature that verifies under it.
func loadJournalEntry(line []byte, journal string, keys []reachedKey) (*journalEntry, bool) {
	if len(line) > journalLineBound {
		return nil, false
	}
	v, err := parseRecordJSON(line)
	if err != nil || !bytes.Equal(canon(v), line) {
		return nil, false
	}
	obj, ok := v.(*vObject)
	if !ok || !exactMembers(obj, map[string]bool{"journal": true, "journalVersion": true, "ordinal": true, "previous": true,
		"at": true, "keyId": true, "alg": true, "body": true, "signature": true}) {
		return nil, false
	}
	e := &journalEntry{line: line}
	if name, ok := memberString(obj, "journal"); !ok || name != journal {
		return nil, false
	}
	if version, ok := memberString(obj, "journalVersion"); !ok || version != journalEnvelopeVersion {
		return nil, false
	}
	if e.ordinal, ok = recordCount(obj, "ordinal"); !ok {
		return nil, false
	}
	if _, given := obj.get("previous"); given {
		if e.previous, ok = hexMember(obj, "previous", 64); !ok {
			return nil, false
		}
		e.hasPrevious = true
	}
	at, ok := memberString(obj, "at")
	if !ok || len(at) != 20 {
		return nil, false
	}
	if _, err := time.Parse("2006-01-02T15:04:05Z", at); err != nil {
		return nil, false
	}
	keyID, ok := hexMember(obj, "keyId", 32)
	if !ok {
		return nil, false
	}
	signature, ok := hexMember(obj, "signature", 128)
	if !ok {
		return nil, false
	}
	rawBody, _ := obj.get("body")
	body, ok := rawBody.(*vObject)
	if !ok || !e.bodyLoads(body) {
		return nil, false
	}
	// the key the walk reached, by the algorithm alg names, and the
	// signature over the prefix and canon of the entry without it
	if e.keyPos = signedByReachedKey(obj, journalContext, keyID, signature, keys); e.keyPos < 0 {
		return nil, false
	}
	return e, true
}

// bodyLoads holds a body to its kind's members, each of its form.
func (e *journalEntry) bodyLoads(body *vObject) bool {
	kind, ok := memberString(body, "kind")
	members, known := operatorBodies[kind]
	if !ok || !known {
		return false
	}
	e.kind = kind
	allowed := map[string]bool{"kind": true, "registryFrom": true, "removalFrom": true}
	for name, required := range members {
		allowed[name] = true
		if _, given := body.get(name); required && !given {
			return false
		}
	}
	if !exactMembers(body, allowed) {
		return false
	}
	if e.registryFrom, ok = recordCount(body, "registryFrom"); !ok {
		return false
	}
	if e.removalFrom, ok = recordCount(body, "removalFrom"); !ok {
		return false
	}
	for name := range members {
		if _, given := body.get(name); !given {
			continue
		}
		var holds bool
		switch name {
		case "by", "scope":
			holds = scopeMember(body, name)
		case "acknowledgments", "previousJournalDigest":
			_, holds = hexMember(body, name, 64)
		case "removalDigest":
			e.removalDigest, holds = hexMember(body, name, 64)
		case "sealDigest":
			e.sealDigest, holds = hexMember(body, name, 64)
		case "continuation":
			e.continuation, holds = hexMember(body, name, 64)
		case "acknowledgedBy":
			v, _ := body.get(name)
			ids, isArray := v.(vArray)
			holds = isArray && len(ids) >= 1 && len(ids) <= 4
			for _, id := range ids {
				s, isString := id.(vString)
				holds = holds && isString && isLowerHexOfLen(string(s), 32)
			}
		case "sessions", "previousJournalBytes":
			_, holds = recordCount(body, name)
		case "removalBytes":
			e.removalBytes, holds = recordCount(body, name)
			e.removal = holds
		case "seals":
			e.seals, holds = recordCount(body, name)
			e.sealing = holds
		case "delivered":
			v, _ := body.get(name)
			_, holds = v.(vBool)
		}
		if !holds {
			return false
		}
	}
	return true
}

// --- reading a journal --------------------------------------------------------

// readJournalPath reads <storeRoot>/journals/<file>, following no link:
// there is whether a regular file is at its name. Nothing there, or no
// journals directory, is not there; something there that is not a regular
// file is errJournalNotRegular.
func readJournalPath(storeRoot, file string) (data []byte, there bool, err error) {
	root, err := os.OpenRoot(storeRoot)
	if err != nil {
		if absent(err) || errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("journal: %w", err)
	}
	defer root.Close()
	dir, err := root.Lstat(journalsDir)
	if err != nil {
		if absent(err) || errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("journal: %w", err)
	}
	if !dir.IsDir() {
		// a journals/ that is not a directory holds no journal (SPEC.md §4.1)
		return nil, false, nil
	}
	rel := journalsDir + "/" + file
	info, err := root.Lstat(rel)
	if err != nil {
		if absent(err) || errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("journal: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, false, errJournalNotRegular
	}
	f, err := root.Open(rel)
	if err != nil {
		return nil, false, fmt.Errorf("journal: %w", err)
	}
	defer f.Close()
	data, err = io.ReadAll(f)
	if err != nil {
		return nil, false, fmt.Errorf("journal: %w", err)
	}
	return data, true, nil
}

// readRemovalBytes is the removal file's bytes, whole: none where nothing
// is there, or where what is there is not a regular file (loadRecords).
func readRemovalBytes(storeRoot string) ([]byte, error) {
	file, err := openRemovals(storeRoot)
	if errors.Is(err, errRemovalsNotRegular) {
		return nil, nil
	}
	if err != nil || file == nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("removal records: %w", err)
	}
	return data, nil
}

// journalLines are a journal's complete lines, each without its 0x0A, and
// the length of the torn last piece with no 0x0A after it, which is not an
// entry.
func journalLines(data []byte) (lines [][]byte, torn int) {
	pieces := bytes.Split(data, []byte{'\n'})
	return pieces[:len(pieces)-1], len(pieces[len(pieces)-1])
}

// commandSeal is a registry line §1.1's parser reads as one JSON object of
// kind seal-after-interruption and sealedVia command, whether or not it
// loads: where it starts, and its bytes with its 0x0A.
type commandSeal struct {
	at   int64
	line []byte
}

func commandSealsOf(registry []byte) []commandSeal {
	var out []commandSeal
	at := int64(0)
	for {
		i := bytes.IndexByte(registry[at:], '\n')
		if i < 0 {
			return out
		}
		line := registry[at : at+int64(i)+1]
		if v, err := parseJSON(line[:len(line)-1]); err == nil {
			if obj, ok := v.(*vObject); ok {
				kind, _ := memberString(obj, "kind")
				via, _ := memberString(obj, "sealedVia")
				if kind == "seal-after-interruption" && via == string(sealedViaCommand) {
					out = append(out, commandSeal{at: at, line: line})
				}
			}
		}
		at += int64(i) + 1
	}
}

// journalJudgment is what step 9 finds of one journal against the store:
// the entries that loaded, the finding (nil for none), and where the
// journal's coverage ends.
type journalJudgment struct {
	entries []*journalEntry
	finding finding
	// unnamed are the command seals at or after the first entry's
	// registryFrom that no entry takes: what the next seal entry names first
	unnamed []commandSeal
	// tornAt and torn are the removal file's torn last piece that is no
	// finding (ADR-0056, Amendment B): where it starts and its length, torn
	// 0 for none
	tornAt, torn int64
}

// tornRemovalPiece is the removal file's last piece, the bytes after its
// last 0x0A (the whole file where it holds none), and where it starts.
func tornRemovalPiece(removal []byte) (start int64, piece []byte) {
	i := bytes.LastIndexByte(removal, '\n') + 1
	return int64(i), removal[i:]
}

// pieceLoads is whether a torn piece, read as a line, loads as a removal
// record of any kind under keys (SPEC.md §1.3a, "Loading"): ended by the
// next append's 0x0A, it would be a record no entry names (ADR-0056,
// Amendment B).
func pieceLoads(piece []byte, keys []reachedKey) bool {
	if len(piece) == 0 || len(piece) > removalLineBound {
		return false
	}
	v, err := parseJSON(piece)
	if err != nil {
		return false
	}
	obj, ok := v.(*vObject)
	if !ok {
		return false
	}
	kind, _ := memberString(obj, "kind")
	switch kind {
	case removalKind:
		_, ok = artifactRemovalOf(obj, keys)
	case sessionRemovalKind:
		_, ok = sessionRemovalOf(obj, keys)
	case scopeRemovalKind:
		_, ok = scopeRemovalOf(obj, keys)
	default:
		ok = false
	}
	return ok
}

func journalFinding(status, journal string, ordinal int) finding {
	return finding{"status": status, "journal": journal, "ordinal": int64(ordinal)}
}

// judgeOperatorJournal is SPEC.md §4 step 9 for the operator journal
// (ADR-0056 §6): at most one finding, the first of journal-entry-forged,
// journal-order, journal-entry-mismatch and journal-entry-missing.
func judgeOperatorJournal(data []byte, pending bool, keys []reachedKey, registry, removal []byte, continued bool) *journalJudgment {
	const name = operatorJournal
	j := &journalJudgment{}
	lines, _ := journalLines(data)
	for i, line := range lines {
		e, ok := loadJournalEntry(line, name, keys)
		if !ok {
			j.finding = journalFinding("journal-entry-forged", name, i)
			return j
		}
		j.entries = append(j.entries, e)
	}
	for i, e := range j.entries {
		switch {
		case e.ordinal != int64(i),
			i == 0 && e.hasPrevious,
			i > 0 && (!e.hasPrevious || e.previous != journalDigest(lines[i-1])),
			i > 0 && e.keyPos < j.entries[i-1].keyPos:
			j.finding = journalFinding("journal-order", name, i)
			return j
		}
	}
	seals := commandSealsOf(registry)
	gap := false
	if len(j.entries) > 0 {
		first := j.entries[0]
		cursor, taken, registryAt := first.removalFrom, 0, int64(0)
		for taken < len(seals) && seals[taken].at < first.registryFrom {
			taken++
		}
		for i, e := range j.entries {
			mismatch := e.removalFrom < cursor || e.removalFrom > int64(len(removal)) ||
				e.registryFrom > int64(len(registry)) || e.registryFrom < registryAt
			registryAt = e.registryFrom
			switch {
			case mismatch:
			case e.removal:
				end := e.removalFrom + e.removalBytes
				if end > int64(len(removal)) || journalDigest(removal[e.removalFrom:end]) != e.removalDigest {
					mismatch = true
					break
				}
				gap = gap || e.removalFrom > cursor
				cursor = end
			case e.sealing:
				if int64(len(seals)-taken) < e.seals {
					mismatch = true
					break
				}
				var named []byte
				for _, s := range seals[taken : taken+int(e.seals)] {
					named = append(named, s.line...)
				}
				if journalDigest(named) != e.sealDigest {
					mismatch = true
					break
				}
				taken += int(e.seals)
			case e.kind == "store-continued":
				first, _, _ := bytes.Cut(registry, []byte{'\n'})
				mismatch = i != 0 || !continued || journalDigest(first) != e.continuation
			}
			if mismatch {
				j.finding = journalFinding("journal-entry-mismatch", name, i)
				return j
			}
		}
		// the one uncovered piece that is no finding (Amendment B): the
		// removal file's unterminated last piece, past every range, that
		// loads as no record, with no entry staged
		start, piece := tornRemovalPiece(removal)
		if !gap && !pending && len(piece) > 0 && cursor == start && !pieceLoads(piece, keys) {
			j.tornAt, j.torn = start, int64(len(piece))
		} else {
			gap = gap || cursor < int64(len(removal))
		}
		j.unnamed = seals[taken:]
	}
	if pending || gap || len(j.unnamed) > 0 {
		j.finding = journalFinding("journal-entry-missing", name, len(j.entries))
	}
	return j
}

// judgeJournals is SPEC.md §4 step 9 on a store's root: each journal it
// holds is judged, and a journal with no finding observed as journal-from.
// The operator journal is the one this record names; a journal of another
// name, a later record's, is passed over, as an older verifier passes over
// journals/ whole. held and evidence are what --require-journal reads.
func (r *report) judgeJournals(storeRoot string, registry []byte, walk *registryWalk) error {
	data, there, err := readJournalPath(storeRoot, operatorJournal+".jsonl")
	if errors.Is(err, errJournalNotRegular) {
		data, there, err = nil, false, nil
	}
	if err != nil {
		return err
	}
	_, pending, err := readJournalPath(storeRoot, operatorJournal+".pending")
	if errors.Is(err, errJournalNotRegular) {
		pending, err = true, nil
	}
	if err != nil {
		return err
	}
	removal, err := readRemovalBytes(storeRoot)
	if err != nil {
		return err
	}
	r.journalEvidence = bytes.IndexByte(removal, '\n') >= 0 || len(commandSealsOf(registry)) > 0
	lines, _ := journalLines(data)
	if !there || len(lines) == 0 {
		if !pending {
			return nil
		}
	}
	if r.journals == nil {
		r.journals = map[string]bool{}
	}
	r.journals[operatorJournal] = true
	j := judgeOperatorJournal(data, pending, walk.keys, registry, removal, walk.continuation != nil)
	if j.finding != nil {
		r.Findings = append(r.Findings, j.finding)
		return nil
	}
	first := j.entries[0]
	r.Observations = append(r.Observations, finding{
		"observation": "journal-from", "journal": operatorJournal, "registryFrom": first.registryFrom, "removalFrom": first.removalFrom,
	})
	if j.torn > 0 {
		r.Observations = append(r.Observations, finding{
			"observation": "journal-torn-tail", "journal": operatorJournal, "removalFrom": j.tornAt, "bytes": j.torn,
		})
	}
	return nil
}

// requireJournals is --require-journal (ADR-0056 §6): a journal the store
// does not hold, while it holds a removal record or a command seal, is
// journal-missing, and the verdict fails.
func (r *report) requireJournals(names []string) {
	for _, name := range names {
		if r.journals[name] || !r.journalEvidence {
			continue
		}
		r.Findings = append(r.Findings, finding{"status": "journal-missing", "journal": name})
		r.OK = false
	}
}

// --- writing the operator journal on the filesystem kind (ADR-0056 §5) -------

// operatorJournalCall is a journaled command's hold on the operator journal
// of a store of the filesystem kind: where the next entry goes, and the
// store's lengths when the call began. A nil call writes no entry.
type operatorJournalCall struct {
	storeRoot, registry string
	key                 *signingKey
	stamp               func() string
	ordinal             int64
	previous            string
	unnamed             []commandSeal
	registryFrom        int64
	removalFrom         int64
	// tornPiece is the removal file's torn last piece the call found, which
	// loads as no record: the call's range begins with it (Amendment B).
	// pieceLoads is that piece loading as a record, which a removal call
	// refuses.
	tornPiece  []byte
	pieceLoads bool
}

// stagedJournalNotice is what the start says of a staged entry it finds
// (ADR-0056 §5, "What the start does"): the start serves, and the next
// journaled command settles it. "" where there is none.
func stagedJournalNotice(storeRoot string) string {
	if _, there, err := readJournalPath(storeRoot, operatorJournal+".pending"); there || errors.Is(err, errJournalNotRegular) {
		return "an interrupted operator command left a staged entry in " + filepath.Join(storeRoot, journalsDir, operatorJournal+".pending") +
			"; the gateway serves, the next journaled command settles it, and gateway verify reports journal-entry-missing until then"
	}
	return ""
}

// beginOperatorJournal is a journaled command's first step, under the
// registry's hold and before its own work: whether the call writes an entry
// -- its configuration of operatorJournalVersion or later, or a journal the
// store already holds -- and, if it does, a staged entry settled and the
// lengths it begins from.
func beginOperatorJournal(storeRoot, registryPath, version string, key *signingKey, keys []reachedKey, stamp func() string) (*operatorJournalCall, error) {
	data, there, err := readJournalPath(storeRoot, operatorJournal+".jsonl")
	if err != nil {
		return nil, err
	}
	staged, pending, err := readJournalPath(storeRoot, operatorJournal+".pending")
	if err != nil {
		return nil, err
	}
	if !there && !pending && (version == "" || !versionAtLeast(version, operatorJournalVersion)) {
		return nil, nil
	}
	registry, _, err := readRegistryBytes(registryPath)
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	removal, err := readRemovalBytes(storeRoot)
	if err != nil {
		return nil, err
	}
	// a torn last piece is no entry, and is cut away before an entry
	// follows it, so the entry starts a line of its own
	if _, torn := journalLines(data); torn > 0 {
		if err := truncateJournal(storeRoot, int64(len(data)-torn)); err != nil {
			return nil, err
		}
		data = data[:len(data)-torn]
	}
	j := &operatorJournalCall{storeRoot: storeRoot, registry: registryPath, key: key, stamp: stamp}
	j.follow(data, keys, registry, removal)
	if pending {
		committed, err := j.settle(staged, data, keys, removal)
		if err != nil {
			return nil, err
		}
		if committed {
			data = append(data, staged...)
			j.follow(data, keys, registry, removal)
		}
	}
	j.registryFrom, j.removalFrom = int64(len(registry)), int64(len(removal))
	if start, piece := tornRemovalPiece(removal); len(piece) > 0 {
		if pieceLoads(piece, keys) {
			j.pieceLoads = true
		} else {
			j.removalFrom, j.tornPiece = start, piece
		}
	}
	return j, nil
}

// follow sets where the next entry goes from the journal's bytes.
func (j *operatorJournalCall) follow(data []byte, keys []reachedKey, registry, removal []byte) {
	lines, _ := journalLines(data)
	j.ordinal, j.previous = int64(len(lines)), ""
	if len(lines) > 0 {
		j.previous = journalDigest(lines[len(lines)-1])
	}
	j.unnamed = judgeOperatorJournal(data, false, keys, registry, removal, true).unnamed
}

// settle is a staged entry settled (ADR-0056 §5): committed where the
// removal file's bytes past its removalFrom are exactly the range it names
// and it follows the journal's last entry; removed where the call appended
// no line; and otherwise refused, nothing changed.
func (j *operatorJournalCall) settle(staged, data []byte, keys []reachedKey, removal []byte) (bool, error) {
	line := bytes.TrimSuffix(staged, []byte{'\n'})
	e, ok := loadJournalEntry(line, operatorJournal, keys)
	if !ok || !e.removal || len(staged) != len(line)+1 || e.removalFrom > int64(len(removal)) {
		return false, errJournalPending
	}
	past := removal[e.removalFrom:]
	follows := e.ordinal == j.ordinal && (e.ordinal == 0 && !e.hasPrevious || e.ordinal > 0 && e.hasPrevious && e.previous == j.previous)
	switch {
	case follows && int64(len(past)) == e.removalBytes && journalDigest(past) == e.removalDigest:
		if err := j.appendEntry(staged); err != nil {
			return false, err
		}
		return true, j.removePending()
	case bytes.IndexByte(past, '\n') < 0:
		return false, j.removePending()
	}
	return false, errJournalPending
}

// journalsRoot opens the store's journals directory, made 0700 where it is
// not there.
func (j *operatorJournalCall) journalsRoot() (*os.Root, error) {
	dir := filepath.Join(j.storeRoot, journalsDir)
	if err := os.Mkdir(dir, 0o700); err == nil {
		syncDir(j.storeRoot)
	} else if !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("journal: %w", err)
	}
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() {
		return nil, errJournalNotRegular
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("journal: %w", err)
	}
	return root, nil
}

// appendEntry appends a line and its 0x0A to the journal and syncs it; a
// journal made here is made exclusively, and its directory synced.
func (j *operatorJournalCall) appendEntry(line []byte) error {
	root, err := j.journalsRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	name := operatorJournal + ".jsonl"
	made := false
	file, err := openAppendNoFollow(root, name)
	if err != nil && absent(err) {
		file, err = root.OpenFile(name, os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_EXCL, 0o600)
		made = true
	}
	if err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		return errJournalNotRegular
	}
	if _, err := file.Write(line); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	if made {
		syncDir(filepath.Join(j.storeRoot, journalsDir))
	}
	return nil
}

// truncateJournal cuts the journal to n bytes: only ever its torn last
// piece, which is no entry.
func truncateJournal(storeRoot string, n int64) error {
	root, err := os.OpenRoot(filepath.Join(storeRoot, journalsDir))
	if err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	defer root.Close()
	file, err := openAppendNoFollow(root, operatorJournal+".jsonl")
	if err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	defer file.Close()
	if err := file.Truncate(n); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	return file.Sync()
}

func (j *operatorJournalCall) stage(line []byte) error {
	root, err := j.journalsRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	file, err := root.OpenFile(operatorJournal+".pending", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("journal: the entry could not be staged: %w", err)
	}
	defer file.Close()
	if _, err := file.Write(line); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	syncDir(filepath.Join(j.storeRoot, journalsDir))
	return nil
}

func (j *operatorJournalCall) removePending() error {
	root, err := j.journalsRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.Remove(operatorJournal + ".pending"); err != nil && !absent(err) {
		return fmt.Errorf("journal: %w", err)
	}
	syncDir(filepath.Join(j.storeRoot, journalsDir))
	return nil
}

func (j *operatorJournalCall) entry(body *vObject) ([]byte, error) {
	body.set("registryFrom", vInt(j.registryFrom))
	body.set("removalFrom", vInt(j.removalFrom))
	return signedJournalEntry(j.key, operatorJournal, j.ordinal, j.previous, j.stamp(), body)
}

// journaledAppendRemovals is appendRemovals with the call's entry (ADR-0056
// §5): the entry naming the bytes signed and staged, the records appended
// and synced, and the entry appended and the staged file removed. A nil
// call appends the records alone, as before the journal.
func journaledAppendRemovals(j *operatorJournalCall, storeRoot string, torn bool, lines []byte, body *vObject) error {
	if j == nil {
		return appendRemovals(storeRoot, torn, lines)
	}
	if j.pieceLoads {
		return fmt.Errorf("removal records: %s ends in an unterminated line that loads as a removal record, and this call would end it, making it a record no journal entry names (ADR-0056, Amendment B); nothing is changed. The line is no record while it is unterminated, so cut the file back to the end of its last complete line and run the command again", filepath.Join(storeRoot, removalsFile))
	}
	appended := lines
	if torn {
		appended = append(append(append([]byte{}, j.tornPiece...), '\n'), lines...)
	}
	body.set("removalBytes", vInt(len(appended)))
	body.set("removalDigest", vString(journalDigest(appended)))
	line, err := j.entry(body)
	if err != nil {
		return err
	}
	if err := j.stage(line); err != nil {
		return err
	}
	if journalStepCut != nil {
		if err := journalStepCut("staged"); err != nil {
			return err
		}
	}
	if err := appendRemovals(storeRoot, torn, lines); err != nil {
		return err
	}
	if journalStepCut != nil {
		if err := journalStepCut("records"); err != nil {
			return err
		}
	}
	if err := j.appendEntry(line); err != nil {
		return err
	}
	return j.removePending()
}

// commitSeals is a seal kind's entry, written after the call's last seal is
// appended and synced: the command seals no entry names yet, those an
// interrupted call left first, then the call's own. A call that sealed
// nothing, and found nothing to name, writes none.
func (j *operatorJournalCall) commitSeals(kind string, delivered bool) error {
	if j == nil {
		return nil
	}
	registry, _, err := readRegistryBytes(j.registry)
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	named := append([]commandSeal{}, j.unnamed...)
	for _, s := range commandSealsOf(registry) {
		if s.at >= j.registryFrom {
			named = append(named, s)
		}
	}
	if len(named) == 0 {
		return nil
	}
	var sealed []byte
	for _, s := range named {
		sealed = append(sealed, s.line...)
	}
	body := newObject()
	body.set("kind", vString(kind))
	body.set("seals", vInt(len(named)))
	body.set("sealDigest", vString(journalDigest(sealed)))
	body.set("delivered", vBool(delivered))
	line, err := j.entry(body)
	if err != nil {
		return err
	}
	return j.appendEntry(line)
}

// removalBody is a removal kind's body before its lengths and range.
func removalBody(kind, by, scope string) *vObject {
	body := newObject()
	body.set("kind", vString(kind))
	body.set("by", vString(by))
	if scope != "" {
		body.set("scope", vString(scope))
	}
	return body
}
