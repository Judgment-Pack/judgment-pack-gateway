package main

// The checkpoint witness's own storage (docs/adr/0013-checkpoint-witness.md
// §4, "Endpoints and storage"): the witness log, the marks, the
// registrations, the order in which a statement is signed, made durable,
// marked and published, the start-up checks, and the repair their three
// rules allow. This is the core the witness service is built on; nothing
// here listens, and nothing here is served yet.
//
// The files, each private to the signer (0600):
//
//   - the log, at the path the witness is given: one statement per line, in
//     its canonical form (SPEC.md §8.2), ended by a newline, appended and
//     never rewritten;
//   - the marks, at a path on storage apart from the log's: one line per
//     statement, {"index","signature","trail"}, appended and synced after
//     the statement is durable and before it is published. Never restored
//     from a backup: it is what a log, restored or not, is judged against;
//   - beside the log, <log>.registrations: one line per registration or
//     change, {"issuer","subject","trail"}, appended and synced before
//     anything is signed for the trail, never served;
//   - beside the log, <log>.set-aside: what repair took off the end of a
//     file, one record a line, kept and never served;
//   - <log>.lock and <marks>.lock, held while the files are open, so one
//     process at a time writes them.
//
// Every file is opened through its directory, held open from the start, as
// the entry it is -- never a link, and the descriptor's file the entry's own
// (openEntryBy) -- and read, appended and cut through that one descriptor:
// no name is resolved again after it was judged.

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	registrationsSuffix = ".registrations"
	setAsideSuffix      = ".set-aside"

	// witnessLineLimit bounds a line of any of the witness's files as it is
	// read: a statement is about 609 bytes and a mark about 190, so a longer
	// line is no line the witness wrote. It is read to its end, never kept.
	witnessLineLimit = 4096

	// witnessNameLimit bounds a registration's issuer and subject, in bytes.
	witnessNameLimit = 1024
)

// The outcomes of the start-up checks (§4, "Start-up, and repair"). The
// witness starts on outcomeStart alone. Three more name what `repair` may
// do, each a step the fixed order was about to take or bytes no mark can
// name; outcomeRegistrationSetAside is the same for the registrations,
// which are never served. On outcomeRefused the witness goes on under its
// key only once a copy of the log that passes the checks against the marks
// is put in place; on outcomeNewKey it goes on only under a new key.
const (
	outcomeStart                = "start"
	outcomeMarkCompleted        = "mark-completed"
	outcomeNewlineAndMark       = "newline-and-mark-completed"
	outcomeSetAside             = "set-aside"
	outcomeRegistrationSetAside = "registration-set-aside"
	outcomeRefused              = "refused"
	outcomeNewKey               = "new-key"
)

// The findings of the start-up checks. Those a reader of a chain reports
// keep the reader's names (witness.go); the rest are of the files only the
// witness keeps.
const (
	findingLogTorn                   = "witness-log-torn"
	findingLogUnterminated           = "witness-log-unterminated"
	findingMarksLost                 = "witness-marks-lost"
	findingMarksTorn                 = "witness-marks-torn"
	findingMarksUnterminated         = "witness-marks-unterminated"
	findingMarkMalformed             = "witness-mark-malformed"
	findingMarkUnreached             = "witness-mark-unreached"
	findingUnmarked                  = "witness-unmarked"
	findingRegistrationMalformed     = "witness-registration-malformed"
	findingRegistrationsTorn         = "witness-registrations-torn"
	findingRegistrationsUnterminated = "witness-registrations-unterminated"
	findingUnregistered              = "witness-unregistered"
)

// witnessFinding is one kind of failure in one file: the file, the first
// line it was found at -- a file's last bytes are the line after its last
// newline, and 0 is the file as a whole -- and how many times it was found.
// Findings are counted, never listed one by one, so what the checks report
// of a log of any length is a few lines.
type witnessFinding struct {
	Finding string `json:"finding"`
	File    string `json:"file"`
	Line    int64  `json:"line"`
	Count   int64  `json:"count"`
}

type findingTally map[string]*witnessFinding

func (t findingTally) add(name, file string, line int64) {
	key := file + " " + name
	if f, ok := t[key]; ok {
		f.Count++
		if line < f.Line {
			f.Line = line
		}
		return
	}
	t[key] = &witnessFinding{Finding: name, File: file, Line: line, Count: 1}
}

func (t findingTally) has(name string) bool {
	for _, f := range t {
		if f.Finding == name {
			return true
		}
	}
	return false
}

// list is the findings in the order of their files and names.
func (t findingTally) list() []witnessFinding {
	out := make([]witnessFinding, 0, len(t))
	for _, f := range t {
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Finding < out[j].Finding
	})
	return out
}

// names is the findings' names, each once, in order.
func (t findingTally) names() []string {
	set := map[string]bool{}
	for _, f := range t {
		set[f.Finding] = true
	}
	return sortedKeys(set)
}

// --- the line forms ---------------------------------------------------------

var (
	markMembers         = map[string]bool{"index": true, "signature": true, "trail": true}
	registrationMembers = map[string]bool{"issuer": true, "subject": true, "trail": true}
)

type markKey struct {
	trail string
	index int64
}

// witnessMark is a mark line read: the statement it names, and its line.
type witnessMark struct {
	key       markKey
	signature string
	line      int64
}

// markLine is the mark of a statement, a line.
func markLine(st *witnessStatement) []byte {
	o := newObject()
	o.set("index", vInt(st.index))
	o.set("signature", vString(st.signature))
	o.set("trail", vString(st.trail))
	return append(canon(o), '\n')
}

// parseMark reads a mark line, which the witness writes in its canonical
// form and nothing else: a line of other bytes is damaged.
func parseMark(line []byte) (witnessMark, bool) {
	v, err := parseStatementJSON(line, 8)
	if err != nil {
		return witnessMark{}, false
	}
	obj, ok := v.(*vObject)
	if !ok || exactlyMembers(obj, markMembers, "mark") != nil || string(canon(obj)) != string(line) {
		return witnessMark{}, false
	}
	trail, _ := memberString(obj, "trail")
	signature, _ := memberString(obj, "signature")
	index, ok := witnessInteger(obj, "index", 0)
	if !ok || !isLowerHexOfLen(trail, 32) || !isLowerHexOfLen(signature, 128) {
		return witnessMark{}, false
	}
	return witnessMark{key: markKey{trail, index}, signature: signature}, true
}

// witnessRegistration is a trail registered to the one issuer and subject
// that may submit for it.
type witnessRegistration struct {
	trail, issuer, subject string
}

// check is why a registration cannot be kept, or nil.
func (r witnessRegistration) check() error {
	if !isLowerHexOfLen(r.trail, 32) {
		return errors.New("witness: a trail is 32 lowercase hexadecimal characters")
	}
	for what, name := range map[string]string{"issuer": r.issuer, "subject": r.subject} {
		if name == "" || len(name) > witnessNameLimit || !utf8.ValidString(name) {
			return fmt.Errorf("witness: a registration's %s is UTF-8 of 1 to %d bytes", what, witnessNameLimit)
		}
	}
	return nil
}

func registrationLine(r witnessRegistration) []byte {
	o := newObject()
	o.set("issuer", vString(r.issuer))
	o.set("subject", vString(r.subject))
	o.set("trail", vString(r.trail))
	return append(canon(o), '\n')
}

func parseRegistration(line []byte) (witnessRegistration, bool) {
	v, err := parseStatementJSON(line, 8)
	if err != nil {
		return witnessRegistration{}, false
	}
	obj, ok := v.(*vObject)
	if !ok || exactlyMembers(obj, registrationMembers, "registration") != nil || string(canon(obj)) != string(line) {
		return witnessRegistration{}, false
	}
	var r witnessRegistration
	r.trail, _ = memberString(obj, "trail")
	r.issuer, _ = memberString(obj, "issuer")
	r.subject, _ = memberString(obj, "subject")
	return r, r.check() == nil
}

// witnessCheckpoint is a checkpoint line offered to the witness, held to
// the runtime's shape (SPEC.md §8.1) and to its canonical form: the witness
// signs the line it was given and never re-encodes one.
type witnessCheckpoint struct {
	trail    string
	sequence int64
	line     string
}

func parseCheckpointLine(line []byte) (witnessCheckpoint, bool) {
	v, err := parseStatementJSON(line, 8)
	if err != nil {
		return witnessCheckpoint{}, false
	}
	obj, ok := v.(*vObject)
	if !ok || exactlyMembers(obj, checkpointMembers, "checkpoint") != nil || string(canon(obj)) != string(line) {
		return witnessCheckpoint{}, false
	}
	version, _ := memberString(obj, "checkpointVersion")
	trail, _ := memberString(obj, "trail")
	record, _ := memberString(obj, "recordDigest")
	sequence, ok := witnessInteger(obj, "sequence", 1)
	if !ok || version != "1" || !isLowerHexOfLen(trail, 32) || !isDigest(record) {
		return witnessCheckpoint{}, false
	}
	return witnessCheckpoint{trail: trail, sequence: sequence, line: string(line)}, true
}

// --- reading the files --------------------------------------------------------

// scanLines hands visit each line of r in turn: its bytes without the
// newline, its number from 1, the offsets it begins at and ends after, and
// whether a newline ended it -- the piece after the last newline, when there
// is one, comes last, not ended. A line longer than limit is read to its end
// and handed over empty, with over set. The bytes are valid only during the
// call.
func scanLines(r io.Reader, limit int, visit func(line []byte, number, start, end int64, ended, over bool) error) error {
	br := bufio.NewReaderSize(r, 64<<10)
	var line []byte
	over := false
	var offset, start, number int64
	for {
		chunk, err := br.ReadSlice('\n')
		if err != nil && err != bufio.ErrBufferFull && err != io.EOF {
			return err
		}
		ended := len(chunk) > 0 && chunk[len(chunk)-1] == '\n'
		offset += int64(len(chunk))
		if ended {
			chunk = chunk[:len(chunk)-1]
		}
		if !over {
			if len(line)+len(chunk) > limit {
				over, line = true, line[:0]
			} else {
				line = append(line, chunk...)
			}
		}
		if ended {
			number++
			if err := visit(line, number, start, offset, true, over); err != nil {
				return err
			}
			line, over, start = line[:0], false, offset
			continue
		}
		if err == io.EOF {
			if offset > start {
				number++
				return visit(line, number, start, offset, false, over)
			}
			return nil
		}
	}
}

// witnessInput is what the start-up checks read: each file, or nil when it
// is not there, and which of the checks apply. `gateway witness verify`
// checks a log alone, or with its marks, and never registrations.
type witnessInput struct {
	log, marks, registrations io.Reader
	marksChecked              bool
	registrationsChecked      bool
}

// witnessJudgement is what the start-up checks found: the outcome, the
// findings, and what the witness starts from or repair works on.
type witnessJudgement struct {
	outcome  string
	findings findingTally

	trails        map[string]*witnessTrail
	registrations map[string]witnessRegistration
	statements    int64

	// logEnd and registrationsEnd are each file's length up to and including
	// its last newline; logTail and registrationsTail, whether bytes follow.
	logEnd, registrationsEnd   int64
	logTail, registrationsTail bool
	// complete is the statement whose mark repair completes, for
	// outcomeMarkCompleted and outcomeNewlineAndMark.
	complete *witnessStatement
}

// witnessTrail is one trail's chain as the log holds it.
type witnessTrail struct {
	// offsets and lengths place each statement's line in the log, by index,
	// its newline not counted.
	offsets []int64
	lengths []int
	// last is the chain's last statement and latest its last checkpoint
	// statement, or nil.
	last, latest *witnessStatement
	// checkpoints holds each checkpoint statement by its sequence: its
	// index and its checkpoint's canonical bytes. conflicts holds the index
	// of the first conflict statement at each sequence.
	checkpoints map[int64]heldCheckpoint
	conflicts   map[int64]int64
}

type heldCheckpoint struct {
	index      int64
	checkpoint string
}

func (t *witnessTrail) retired() bool {
	return t != nil && t.last != nil && t.last.kind == "retirement"
}

// admit adds a statement that follows the chain (chainFollows), at its place
// in the log.
func (t *witnessTrail) admit(st *witnessStatement, offset int64, length int) {
	t.offsets = append(t.offsets, offset)
	t.lengths = append(t.lengths, length)
	switch st.kind {
	case "checkpoint":
		t.latest = st
		t.checkpoints[st.sequence] = heldCheckpoint{index: st.index, checkpoint: st.checkpoint}
	case "conflict":
		if _, ok := t.conflicts[st.sequence]; !ok {
			t.conflicts[st.sequence] = st.index
		}
	}
	t.last = st
}

func trailIn(trails map[string]*witnessTrail, trail string) *witnessTrail {
	t, ok := trails[trail]
	if !ok {
		t = &witnessTrail{checkpoints: map[int64]heldCheckpoint{}, conflicts: map[int64]int64{}}
		trails[trail] = t
	}
	return t
}

// statementFault is the first check a log's statement fails, as a finding,
// or "": its form, in the canonical bytes the witness writes; its signature,
// under the witness's key.
func statementFault(line []byte, over bool, key ed25519.PublicKey, keyID string) (*witnessStatement, string) {
	if over {
		return nil, findingWitnessMalformed
	}
	st, ok := parseWitnessStatement(line)
	if !ok || st.whole != string(line) {
		return nil, findingWitnessMalformed
	}
	if st.keyID != keyID || !witnessSignatureValid(key, st) {
		return st, findingWitnessSignatureInvalid
	}
	return st, ""
}

// judgeWitness applies the start-up checks (§4, "Start-up, and repair") and
// the three rules of recovery to the files, in one pass over each.
func judgeWitness(in witnessInput, key ed25519.PublicKey) (*witnessJudgement, error) {
	j := &witnessJudgement{
		findings:      findingTally{},
		trails:        map[string]*witnessTrail{},
		registrations: map[string]witnessRegistration{},
	}
	keyID := keyIDFor(key)

	if in.registrationsChecked && in.registrations != nil {
		err := scanLines(in.registrations, witnessLineLimit, func(line []byte, number, start, end int64, ended, over bool) error {
			if !ended {
				j.registrationsTail = true
				if _, whole := parseRegistration(line); whole && !over {
					j.findings.add(findingRegistrationsUnterminated, "registrations", number)
				} else {
					j.findings.add(findingRegistrationsTorn, "registrations", number)
				}
				return nil
			}
			j.registrationsEnd = end
			r, ok := parseRegistration(line)
			if over || !ok {
				j.findings.add(findingRegistrationMalformed, "registrations", number)
				return nil
			}
			j.registrations[r.trail] = r
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("witness registrations: %w", err)
		}
	}

	marksPresent := in.marksChecked && in.marks != nil
	marks := map[markKey]witnessMark{}
	marksTail := false
	if marksPresent {
		err := scanLines(in.marks, witnessLineLimit, func(line []byte, number, start, end int64, ended, over bool) error {
			m, ok := parseMark(line)
			ok = ok && !over
			if !ended {
				marksTail = true
				if ok {
					j.findings.add(findingMarksUnterminated, "marks", number)
				} else {
					j.findings.add(findingMarksTorn, "marks", number)
				}
				return nil
			}
			if !ok {
				j.findings.add(findingMarkMalformed, "marks", number)
				return nil
			}
			m.line = number
			if earlier, seen := marks[m.key]; seen {
				// a second mark for one index names a statement the log
				// cannot also hold there
				if earlier.signature != m.signature {
					j.findings.add(findingMarkUnreached, "marks", number)
				}
				return nil
			}
			marks[m.key] = m
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("witness marks: %w", err)
		}
	}

	var (
		// walk is whether the chains are still walked: as a reader does
		// (§8.6 step 3), they are not once a statement has failed, since a
		// hole it leaves would break every chain after it.
		walk                   = true
		logBytes               int64
		unmarked, failing      int64
		lastLine, lastUnmarked int64
		lastFails              bool
		lastStatement          *witnessStatement
		tailWhole, tailFails   bool
		tailStatement          *witnessStatement
		reached                = map[markKey]bool{}
		hasStatement           = map[string]bool{}
	)
	if in.log != nil {
		err := scanLines(in.log, witnessLineLimit, func(line []byte, number, start, end int64, ended, over bool) error {
			logBytes = end
			st, fault := statementFault(line, over, key, keyID)
			if !ended {
				// The log's last bytes: torn, or a whole statement missing
				// only its newline, held to the checks as the next of its
				// chain but not yet a part of it.
				j.logTail = true
				if st == nil && fault == findingWitnessMalformed {
					if whole, ok := parseWitnessStatement(line); ok && !over {
						// whole, and not in the bytes the witness writes
						st, tailWhole = whole, true
					}
				} else {
					tailWhole = true
				}
				if !tailWhole {
					j.findings.add(findingLogTorn, "log", number)
					return nil
				}
				j.findings.add(findingLogUnterminated, "log", number)
				tailStatement = st
				hasStatement[st.trail] = true
				if fault == "" && walk {
					var last, latest *witnessStatement
					if t := j.trails[st.trail]; t != nil {
						last, latest = t.last, t.latest
					}
					if !chainFollows(last, latest, st) {
						fault = findingWitnessChainBroken
					}
				}
				if fault != "" {
					j.findings.add(fault, "log", number)
					tailFails = true
				}
				return nil
			}
			j.logEnd = end
			lastLine = number
			if fault != "" {
				walk = false
			} else if walk {
				t := trailIn(j.trails, st.trail)
				if chainFollows(t.last, t.latest, st) {
					t.admit(st, start, len(line))
				} else {
					fault, walk = findingWitnessChainBroken, false
				}
			}
			if fault != "" {
				j.findings.add(fault, "log", number)
				failing++
			}
			lastFails = fault != ""
			marked := false
			if st != nil {
				j.statements++
				hasStatement[st.trail] = true
				// A mark is reached by a statement of its trail, index and
				// signature whose signature verifies: a damaged line that
				// still spells the signature holds no published statement.
				if m, ok := marks[markKey{st.trail, st.index}]; ok && m.signature == st.signature && fault != findingWitnessSignatureInvalid {
					marked = true
					reached[m.key] = true
				}
			}
			if marksPresent && !marked {
				unmarked++
				lastUnmarked = number
				j.findings.add(findingUnmarked, "log", number)
			}
			lastStatement = st
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("witness log: %w", err)
		}
	}

	if marksPresent {
		for key, m := range marks {
			if !reached[key] {
				j.findings.add(findingMarkUnreached, "marks", m.line)
			}
		}
	}
	if in.registrationsChecked {
		for trail := range hasStatement {
			if _, ok := j.registrations[trail]; !ok {
				j.findings.add(findingUnregistered, "registrations", 0)
			}
		}
	}
	if !in.marksChecked {
		return j, nil
	}

	// The outcome, by the three rules: what costs a key first, then what a
	// log copy can answer, then the one release and the one mark repair may
	// make, and last the registrations, which are never evidence.
	logOutcome := outcomeStart
	switch {
	case in.marks == nil && logBytes > 0:
		j.findings.add(findingMarksLost, "marks", 0)
		logOutcome = outcomeNewKey
	case in.marks == nil:
		// a witness with no statement yet: the marks are made at its start
	case marksTail, j.findings.has(findingMarkMalformed):
		logOutcome = outcomeNewKey
	case j.findings.has(findingMarkUnreached):
		logOutcome = outcomeRefused
	case unmarked > 1, unmarked == 1 && (lastUnmarked != lastLine || j.logTail):
		logOutcome = outcomeRefused
	case failing > 1, failing == 1 && !(unmarked == 1 && lastFails):
		// a statement a mark names fails the checks
		logOutcome = outcomeRefused
	case j.logTail && !tailWhole:
		logOutcome = outcomeSetAside
	case j.logTail && tailFails:
		logOutcome = outcomeNewKey
	case j.logTail:
		logOutcome = outcomeNewlineAndMark
		j.complete = tailStatement
	case unmarked == 1 && lastFails:
		logOutcome = outcomeNewKey
	case unmarked == 1:
		logOutcome = outcomeMarkCompleted
		j.complete = lastStatement
	}
	j.outcome = logOutcome
	if logOutcome == outcomeNewKey || logOutcome == outcomeRefused || !in.registrationsChecked {
		return j, nil
	}
	switch {
	case j.findings.has(findingRegistrationMalformed), j.findings.has(findingUnregistered):
		j.outcome = outcomeRefused
	case j.registrationsTail && logOutcome == outcomeStart:
		j.outcome = outcomeRegistrationSetAside
	}
	return j, nil
}

// --- the files held open ------------------------------------------------------

// witnessEntryJudged, when set, runs between judging a witness file's entry
// and opening it: a test's way of putting a link in its place at that
// moment.
var witnessEntryJudged func(name string)

// witnessFiles is the witness's files, held open: their directories, held
// from the start; each file through one descriptor, or nil when it is not
// there; and the two locks.
type witnessFiles struct {
	logDir, marksDir          *os.Root
	logName, marksName        string
	log, marks, registrations *os.File
	unlock                    []func()
}

// witnessPaths is where the witness keeps its log and its marks.
type witnessPaths struct{ log, marks string }

func (p witnessPaths) check() error {
	for what, path := range map[string]string{"log": p.log, "marks": p.marks} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("witness: the %s is named by an absolute, clean path: %q", what, path)
		}
		if base := filepath.Base(path); base == "." || base == ".." || base == string(filepath.Separator) {
			return fmt.Errorf("witness: the %s names no file: %q", what, path)
		}
	}
	for _, beside := range []string{p.log, p.log + registrationsSuffix, p.log + setAsideSuffix, p.log + ".lock"} {
		if p.marks == beside || p.marks+".lock" == beside {
			return fmt.Errorf("witness: the marks %q are the log or a file kept beside it", p.marks)
		}
	}
	return nil
}

// holdWitnessFiles holds the witness's directories and takes its locks,
// then opens each file that is there as the entry it is.
func holdWitnessFiles(p witnessPaths) (*witnessFiles, error) {
	if err := p.check(); err != nil {
		return nil, err
	}
	f := &witnessFiles{logName: filepath.Base(p.log), marksName: filepath.Base(p.marks)}
	fail := func(err error) (*witnessFiles, error) {
		f.close()
		return nil, err
	}
	var err error
	if f.logDir, err = holdWitnessDir(filepath.Dir(p.log)); err != nil {
		return fail(err)
	}
	if f.marksDir, err = holdWitnessDir(filepath.Dir(p.marks)); err != nil {
		return fail(err)
	}
	for _, lock := range []struct {
		dir  *os.Root
		name string
	}{{f.logDir, f.logName}, {f.marksDir, f.marksName}} {
		unlock, err := lockBesideFor(lock.dir, lock.name, fileOwnerIDs{}, "witness")
		if err != nil {
			return fail(fmt.Errorf("witness: %v", err))
		}
		f.unlock = append(f.unlock, unlock)
	}
	if f.log, err = openWitnessFile(f.logDir, f.logName); err != nil {
		return fail(err)
	}
	if f.marks, err = openWitnessFile(f.marksDir, f.marksName); err != nil {
		return fail(err)
	}
	if f.registrations, err = openWitnessFile(f.logDir, f.logName+registrationsSuffix); err != nil {
		return fail(err)
	}
	if err := f.distinct(); err != nil {
		return fail(err)
	}
	return f, nil
}

// holdWitnessDir holds a directory of the witness's: one nobody but root
// and this process could replace an entry of.
func holdWitnessDir(path string) (*os.Root, error) {
	dir, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("witness: %v", err)
	}
	info, err := dir.Stat(".")
	if err == nil {
		err = parentHeld(info)
	}
	if err != nil {
		dir.Close()
		return nil, fmt.Errorf("witness: %s %v", path, err)
	}
	return dir, nil
}

// openWitnessFile opens a file of the witness's to read and append, as the
// entry it is, or gives nil when nothing is there.
func openWitnessFile(dir *os.Root, name string) (*os.File, error) {
	file, info, err := openEntryBy(dir, name, openNoFollowAppend, witnessEntryJudged)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("witness: %s %v", name, err)
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("witness: %s is not a regular file", name)
	}
	if err := witnessFilePrivate(info); err != nil {
		file.Close()
		return nil, fmt.Errorf("witness: %s %v", name, err)
	}
	return file, nil
}

// distinct refuses two of the files that are one file.
func (f *witnessFiles) distinct() error {
	var infos []os.FileInfo
	for _, file := range []*os.File{f.log, f.marks, f.registrations} {
		if file == nil {
			continue
		}
		info, err := file.Stat()
		if err != nil {
			return fmt.Errorf("witness: %v", err)
		}
		for _, other := range infos {
			if os.SameFile(info, other) {
				return errors.New("witness: the log, the marks and the registrations are one file under two names")
			}
		}
		infos = append(infos, info)
	}
	return nil
}

func (f *witnessFiles) close() {
	for _, file := range []*os.File{f.log, f.marks, f.registrations} {
		if file != nil {
			file.Close()
		}
	}
	for i := len(f.unlock) - 1; i >= 0; i-- {
		f.unlock[i]()
	}
	for _, dir := range []*os.Root{f.logDir, f.marksDir} {
		if dir != nil {
			dir.Close()
		}
	}
}

// whole is a file's bytes from its start, as its descriptor reads them, or
// nil when it is not there.
func whole(file *os.File) (io.Reader, error) {
	if file == nil {
		return nil, nil
	}
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	return io.NewSectionReader(file, 0, info.Size()), nil
}

// judge applies the start-up checks to the files as their descriptors read
// them now.
func (f *witnessFiles) judge(key ed25519.PublicKey) (*witnessJudgement, error) {
	in := witnessInput{marksChecked: true, registrationsChecked: true}
	var err error
	if in.log, err = whole(f.log); err != nil {
		return nil, fmt.Errorf("witness log: %w", err)
	}
	if in.marks, err = whole(f.marks); err != nil {
		return nil, fmt.Errorf("witness marks: %w", err)
	}
	if in.registrations, err = whole(f.registrations); err != nil {
		return nil, fmt.Errorf("witness registrations: %w", err)
	}
	return judgeWitness(in, key)
}

// create makes each file that is not there, empty and 0600, exclusively --
// never through a link, nor over a file that came since it was looked for
// -- and syncs its directory, so the file survives a crash once this
// returns. The log is made first and the marks last.
func (f *witnessFiles) create() error {
	for _, c := range []struct {
		file **os.File
		dir  *os.Root
		name string
	}{{&f.log, f.logDir, f.logName}, {&f.registrations, f.logDir, f.logName + registrationsSuffix}, {&f.marks, f.marksDir, f.marksName}} {
		if *c.file != nil {
			continue
		}
		made, err := createWitnessFile(c.dir, c.name)
		if err != nil {
			return err
		}
		*c.file = made
	}
	return nil
}

func createWitnessFile(dir *os.Root, name string) (*os.File, error) {
	made, err := dir.OpenFile(name, os.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("witness: %v", err)
	}
	fail := func(err error) (*os.File, error) {
		made.Close()
		return nil, fmt.Errorf("witness: %s %v", name, err)
	}
	// the mode exactly, whatever the umask made of it, through the
	// descriptor
	if err := made.Chmod(0o600); err != nil {
		return fail(err)
	}
	info, err := made.Stat()
	if err != nil {
		return fail(err)
	}
	if entry, err := dir.Lstat(name); err != nil || !os.SameFile(entry, info) {
		return fail(errors.New("is not the file this witness made"))
	}
	if err := syncDirectory(dir, "."); err != nil {
		return fail(err)
	}
	return made, nil
}

// --- writing ------------------------------------------------------------------

// witnessIO appends to a file, makes it durable and cuts it, through its
// descriptor. A test stands in a failure for any of them, at any step, as it
// does for the seal registry (registryWriter).
type witnessIO struct {
	write    func(file string, f *os.File, data []byte) (int, error)
	sync     func(file string, f *os.File) error
	truncate func(file string, f *os.File, size int64) error
}

func osWitnessIO() witnessIO {
	return witnessIO{
		write:    func(_ string, f *os.File, data []byte) (int, error) { return f.Write(data) },
		sync:     func(_ string, f *os.File) error { return f.Sync() },
		truncate: func(_ string, f *os.File, size int64) error { return f.Truncate(size) },
	}
}

// appendTo appends data whole, or fails: a short write is a failure.
func (x witnessIO) appendTo(file string, f *os.File, data []byte) error {
	n, err := x.write(file, f, data)
	if err == nil && n != len(data) {
		err = errors.New("short write")
	}
	return err
}

// witnessConfig is what a witness log is opened with: where its files are,
// how a trail is registered, its key and how it signs, and its clock.
type witnessConfig struct {
	paths witnessPaths
	// firstSubmission is registration "first-submission": the first
	// submission accepted for a trail registers it to its submitter. False
	// is "operator", the default: a submission for a trail the witness's
	// operator has not registered is refused.
	firstSubmission bool
	publicKey       ed25519.PublicKey
	// sign signs a statement's bytes (SPEC.md §8.3) under the key publicKey
	// verifies: the gateway's own seed (witnessSeedSigner).
	sign  func(message []byte) []byte
	clock func() time.Time
}

// witnessSeedSigner is the gateway's seed as the witness's key (ADR-0013,
// question 6): the seed that signs its receipts and seals, under the
// witness's own prefix, which the statement's bytes begin with.
func witnessSeedSigner(seed []byte) (ed25519.PublicKey, func([]byte) []byte) {
	private := ed25519.NewKeyFromSeed(seed)
	return private.Public().(ed25519.PublicKey), func(message []byte) []byte { return ed25519.Sign(private, message) }
}

// The answers of a submission, a retirement and a registration that are
// not a statement (§4, "POST /witness/checkpoints").
var (
	// errWitnessStopped: a statement or a registration could not be kept
	// earlier, so nothing more is written, for any trail, until the witness
	// restarts and its start-up checks pass. It never signs a second
	// statement at an index whose first may be durable.
	errWitnessStopped        = errors.New("witness: an earlier statement could not be kept; nothing more is signed, for any trail, until the witness restarts")
	errWitnessUnregistered   = errors.New("witness: the trail is not registered")
	errWitnessRegisteredElse = errors.New("witness: the trail is registered to another submitter")
	errWitnessNothingRetired = errors.New("witness: the trail has no checkpoint statement to retire")
	errWitnessIndexBound     = errors.New("witness: the trail's chain is at the largest index a statement holds")
)

// witnessFailure is a write that failed at a step of the fixed order --
// "append", "sync", "mark", "mark-sync" or "publish" for a statement, and
// "register" or "register-sync" for a registration -- after which the
// witness writes nothing more until it restarts.
type witnessFailure struct {
	step string
	err  error
}

func (e witnessFailure) Error() string {
	return fmt.Sprintf("witness: the %s step failed, and nothing more is written until the witness restarts: %v", e.step, e.err)
}

// witnessLineError is a submission out of shape.
type witnessLineError struct{ reason string }

func (e witnessLineError) Error() string { return "witness: " + e.reason }

// witnessNotStarted is a start the checks refused: the judgement says why,
// and what repair, a log copy or a new key can do about it.
type witnessNotStarted struct{ judgement *witnessJudgement }

func (e witnessNotStarted) Error() string {
	var parts []string
	for _, f := range e.judgement.findings.list() {
		parts = append(parts, fmt.Sprintf("%s in the %s at line %d (%d)", f.Finding, f.File, f.Line, f.Count))
	}
	what := map[string]string{
		outcomeMarkCompleted:        "repair completes the mark of the log's last statement",
		outcomeNewlineAndMark:       "repair completes the newline and the mark of the log's last statement",
		outcomeSetAside:             "repair sets the log's torn last bytes aside",
		outcomeRegistrationSetAside: "repair sets the registrations' last bytes aside",
		outcomeRefused:              "only a copy of the log that passes these checks against the marks, put in its place, lets the witness go on under its key; otherwise it goes on only under a new key",
		outcomeNewKey:               "the witness goes on only under a new key, a new witness whose chains begin at index 0; this key signs nothing more",
	}[e.judgement.outcome]
	if e.judgement.outcome == outcomeRefused && e.judgement.registrationsOnly() {
		what = "a trail with statements has no registration, or a registration does not read: restore the registrations, or register the trail with the witness stopped"
	}
	return fmt.Sprintf("witness: the start-up checks found %s: %s", strings.Join(parts, "; "), what)
}

// registrationsOnly reports whether every finding is of the registrations:
// a refusal no log copy answers.
func (j *witnessJudgement) registrationsOnly() bool {
	for _, f := range j.findings {
		if f.File != "registrations" {
			return false
		}
	}
	return true
}

// witnessAnswer is a statement answer: "signed" for a statement made now,
// "held" for one the witness held already, "conflict" with the checkpoint
// statement held and the conflict statement, "below-head" and "retired"
// with the head. Each statement is its exact line, without the newline.
type witnessAnswer struct {
	kind       string
	statements [][]byte
}

// witnessLog is a witness's log, marks and registrations, open: checked at
// its start, and written by one writer.
type witnessLog struct {
	files           *witnessFiles
	publicKey       ed25519.PublicKey
	keyID           string
	sign            func([]byte) []byte
	clock           func() time.Time
	firstSubmission bool
	io              witnessIO
	// published runs once a statement is marked and before it is answered:
	// a test's way of failing at that step.
	published func() error

	// writer is the writer lock: a statement's append and sync and its
	// mark's append and sync, or a registration's append and sync, happen
	// under it, for every trail and every kind, and so does the choice of
	// what to sign. stopped is the failure after which nothing more is
	// written.
	writer  sync.Mutex
	stopped error

	// index guards trails and registrations, which the writer changes and
	// the reads read.
	index         sync.RWMutex
	trails        map[string]*witnessTrail
	registrations map[string]witnessRegistration
	logSize       int64
}

// openWitnessLog opens a witness's files and applies the start-up checks:
// it starts only when they find nothing, makes the files that are not
// there, and repairs nothing by itself.
func openWitnessLog(cfg witnessConfig) (*witnessLog, error) {
	files, err := holdWitnessFiles(cfg.paths)
	if err != nil {
		return nil, err
	}
	j, err := files.judge(cfg.publicKey)
	if err != nil {
		files.close()
		return nil, err
	}
	if j.outcome != outcomeStart {
		files.close()
		return nil, witnessNotStarted{j}
	}
	if err := files.create(); err != nil {
		files.close()
		return nil, err
	}
	clock := cfg.clock
	if clock == nil {
		clock = time.Now
	}
	return &witnessLog{
		files: files, publicKey: cfg.publicKey, keyID: keyIDFor(cfg.publicKey), sign: cfg.sign, clock: clock,
		firstSubmission: cfg.firstSubmission, io: osWitnessIO(), published: func() error { return nil },
		trails: j.trails, registrations: j.registrations, logSize: j.logEnd,
	}, nil
}

// close releases the files and the locks. A witness closed after a failure
// is in the state a crash at that step leaves.
func (w *witnessLog) close() { w.files.close() }

// submit answers a submission of checkpoint lines, all of one trail, their
// sequences strictly increasing, by a submitter: the trail must be
// registered to it, or, under "first-submission", not registered yet. Only
// the last line is signed; the others are compared with what the witness
// holds, for conflicts, and otherwise discarded (§4, question 7).
func (w *witnessLog) submit(issuer, subject string, lines [][]byte) (witnessAnswer, error) {
	if len(lines) == 0 {
		return witnessAnswer{}, witnessLineError{"a submission holds at least one checkpoint line"}
	}
	checkpoints := make([]witnessCheckpoint, len(lines))
	for i, line := range lines {
		cp, ok := parseCheckpointLine(line)
		switch {
		case !ok:
			return witnessAnswer{}, witnessLineError{fmt.Sprintf("line %d is not a checkpoint in its canonical form", i+1)}
		case i > 0 && cp.trail != checkpoints[0].trail:
			return witnessAnswer{}, witnessLineError{"the lines are of more than one trail"}
		case i > 0 && cp.sequence <= checkpoints[i-1].sequence:
			return witnessAnswer{}, witnessLineError{"the lines' sequences do not strictly increase"}
		}
		checkpoints[i] = cp
	}
	trail := checkpoints[0].trail

	w.writer.Lock()
	defer w.writer.Unlock()
	registration, registered := w.registrations[trail]
	switch {
	case registered && (registration.issuer != issuer || registration.subject != subject):
		return witnessAnswer{}, errWitnessRegisteredElse
	case !registered && !w.firstSubmission:
		return witnessAnswer{}, errWitnessUnregistered
	case !registered:
		if err := w.keepRegistration(witnessRegistration{trail: trail, issuer: issuer, subject: subject}); err != nil {
			return witnessAnswer{}, err
		}
	}
	t := w.trails[trail]
	if t.retired() {
		return w.answer("retired", t, t.last.index)
	}
	if t != nil {
		for _, cp := range checkpoints {
			held, ok := t.checkpoints[cp.sequence]
			if !ok || held.checkpoint == cp.line {
				continue
			}
			heldLine, err := w.line(t, held.index)
			if err != nil {
				return witnessAnswer{}, err
			}
			// the first offer for a sequence is its evidence; a later one
			// is answered with it, and nothing is appended
			if first, ok := t.conflicts[cp.sequence]; ok {
				firstLine, err := w.line(t, first)
				if err != nil {
					return witnessAnswer{}, err
				}
				return witnessAnswer{kind: "conflict", statements: [][]byte{heldLine, firstLine}}, nil
			}
			made, err := w.signAndKeep("conflict", cp.line, t)
			if err != nil {
				return witnessAnswer{}, err
			}
			return witnessAnswer{kind: "conflict", statements: [][]byte{heldLine, made}}, nil
		}
		last := checkpoints[len(checkpoints)-1]
		if held, ok := t.checkpoints[last.sequence]; ok {
			return w.answer("held", t, held.index)
		}
		if t.latest != nil && last.sequence < t.latest.sequence {
			return w.answer("below-head", t, t.last.index)
		}
	}
	made, err := w.signAndKeep("checkpoint", checkpoints[len(checkpoints)-1].line, t)
	if err != nil {
		return witnessAnswer{}, err
	}
	return witnessAnswer{kind: "signed", statements: [][]byte{made}}, nil
}

// retire signs a trail's retirement, the last statement of its chain,
// repeating its latest witnessed checkpoint; a trail already retired is
// answered with its retirement.
func (w *witnessLog) retire(trail string) (witnessAnswer, error) {
	w.writer.Lock()
	defer w.writer.Unlock()
	t := w.trails[trail]
	if t == nil || t.latest == nil {
		return witnessAnswer{}, errWitnessNothingRetired
	}
	if t.retired() {
		return w.answer("retired", t, t.last.index)
	}
	made, err := w.signAndKeep("retirement", t.latest.checkpoint, t)
	if err != nil {
		return witnessAnswer{}, err
	}
	return witnessAnswer{kind: "signed", statements: [][]byte{made}}, nil
}

// register registers a trail, or changes its registration: the witness's
// operator's act, appended and synced under the writer lock, recorded and
// never served.
func (w *witnessLog) register(r witnessRegistration) error {
	w.writer.Lock()
	defer w.writer.Unlock()
	return w.keepRegistration(r)
}

func (w *witnessLog) answer(kind string, t *witnessTrail, index int64) (witnessAnswer, error) {
	line, err := w.line(t, index)
	if err != nil {
		return witnessAnswer{}, err
	}
	return witnessAnswer{kind: kind, statements: [][]byte{line}}, nil
}

// keepRegistration appends a registration and syncs it, under the writer
// lock, before anything is signed for its trail.
func (w *witnessLog) keepRegistration(r witnessRegistration) error {
	if w.stopped != nil {
		return errWitnessStopped
	}
	if err := r.check(); err != nil {
		return err
	}
	file := w.files.registrations
	if err := w.io.appendTo("registrations", file, registrationLine(r)); err != nil {
		w.stopped = witnessFailure{"register", err}
		return w.stopped
	}
	if err := w.io.sync("registrations", file); err != nil {
		w.stopped = witnessFailure{"register-sync", err}
		return w.stopped
	}
	w.index.Lock()
	w.registrations[r.trail] = r
	w.index.Unlock()
	return nil
}

// signAndKeep makes the trail's next statement, of a kind, over a
// checkpoint's canonical bytes, and keeps it in the fixed order: signed,
// durable, marked, published. It is called under the writer lock.
func (w *witnessLog) signAndKeep(kind, checkpoint string, t *witnessTrail) ([]byte, error) {
	if w.stopped != nil {
		return nil, errWitnessStopped
	}
	st, line, err := w.statement(kind, checkpoint, t)
	if err != nil {
		return nil, err
	}
	// durable: the line appended to the log, and the log synced
	offset := w.logSize
	if err := w.io.appendTo("log", w.files.log, append(append([]byte(nil), line...), '\n')); err != nil {
		w.stopped = witnessFailure{"append", err}
		return nil, w.stopped
	}
	w.logSize += int64(len(line)) + 1
	if err := w.io.sync("log", w.files.log); err != nil {
		w.stopped = witnessFailure{"sync", err}
		return nil, w.stopped
	}
	// marked: its mark appended to the marks, and the marks synced
	if err := w.io.appendTo("marks", w.files.marks, markLine(st)); err != nil {
		w.stopped = witnessFailure{"mark", err}
		return nil, w.stopped
	}
	if err := w.io.sync("marks", w.files.marks); err != nil {
		w.stopped = witnessFailure{"mark-sync", err}
		return nil, w.stopped
	}
	// published: only now may a read serve it or an answer give it
	w.index.Lock()
	trailIn(w.trails, st.trail).admit(st, offset, len(line))
	w.index.Unlock()
	if err := w.published(); err != nil {
		w.stopped = witnessFailure{"publish", err}
		return nil, w.stopped
	}
	return line, nil
}

// statement makes and signs the trail's next statement, and holds it to
// what its readers will hold it to -- its form, in the bytes it is written
// in, its signature under the witness's key, and the chain rule after the
// trail's last statement -- before a byte of it is written.
func (w *witnessLog) statement(kind, checkpoint string, t *witnessTrail) (*witnessStatement, []byte, error) {
	cp, err := parseStatementJSON([]byte(checkpoint), 8)
	if err != nil {
		return nil, nil, fmt.Errorf("witness: a checkpoint held does not read: %v", err)
	}
	var last, latest *witnessStatement
	if t != nil {
		last, latest = t.last, t.latest
	}
	index, prev := int64(0), value(vNull{})
	at := w.clock().UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
	if last != nil {
		if last.index >= maxWitnessInteger {
			return nil, nil, errWitnessIndexBound
		}
		index, prev = last.index+1, vString(last.signature)
		// never earlier than the previous statement's time for the trail
		if at < last.witnessedAt {
			at = last.witnessedAt
		}
	}
	body := newObject()
	body.set("checkpoint", cp)
	body.set("index", vInt(index))
	body.set("keyId", vString(w.keyID))
	body.set("kind", vString(kind))
	body.set("prevSignature", prev)
	body.set("witnessVersion", vString("1"))
	body.set("witnessedAt", vString(at))
	signature := w.sign(append([]byte(witnessPrefix), canon(body)...))
	body.set("signature", vString(hex.EncodeToString(signature)))
	line := canon(body)
	st, ok := parseWitnessStatement(line)
	if !ok || st.whole != string(line) || st.keyID != w.keyID || !witnessSignatureValid(w.publicKey, st) || !chainFollows(last, latest, st) {
		return nil, nil, fmt.Errorf("witness: the %s statement made at index %d would not read as the next of its chain; nothing was written", kind, index)
	}
	return st, line, nil
}

// line is a statement's exact line, without its newline, read from the log
// through the descriptor held for it.
func (w *witnessLog) line(t *witnessTrail, index int64) ([]byte, error) {
	buf := make([]byte, t.lengths[index])
	if _, err := w.files.log.ReadAt(buf, t.offsets[index]); err != nil {
		return nil, fmt.Errorf("witness log: %w", err)
	}
	return buf, nil
}

// head is a trail's last statement, exactly as logged, or false for a trail
// the witness holds nothing for.
func (w *witnessLog) head(trail string) ([]byte, bool, error) {
	w.index.RLock()
	defer w.index.RUnlock()
	t := w.trails[trail]
	if t == nil || t.last == nil {
		return nil, false, nil
	}
	line, err := w.line(t, t.last.index)
	return line, err == nil, err
}

// statements is a trail's statements from an index, at most limit of them,
// in index order, each exactly as logged.
func (w *witnessLog) statements(trail string, from int64, limit int) ([][]byte, error) {
	w.index.RLock()
	defer w.index.RUnlock()
	t := w.trails[trail]
	var out [][]byte
	if t == nil || from < 0 {
		return out, nil
	}
	for index := from; index < int64(len(t.offsets)) && len(out) < limit; index++ {
		line, err := w.line(t, index)
		if err != nil {
			return nil, err
		}
		out = append(out, line)
	}
	return out, nil
}

// --- repair -------------------------------------------------------------------

// repairWitnessLog applies the start-up checks and does what the three
// rules allow and nothing else (§4, "Recovery, in three rules"): it
// completes the mark of the log's whole last statement that no mark names
// and that passes the checks, with its newline when that is missing; or it
// sets the log's torn last bytes aside, when the marks end cleanly and the
// log without them reaches every mark, releasing their index; and it sets
// the registrations' last bytes aside, a registration never acknowledged.
// On any other outcome it writes nothing. It returns the judgement it acted
// on; after a repair the checks must find nothing.
func repairWitnessLog(cfg witnessConfig, wio witnessIO) (*witnessJudgement, error) {
	files, err := holdWitnessFiles(cfg.paths)
	if err != nil {
		return nil, err
	}
	defer files.close()
	j, err := files.judge(cfg.publicKey)
	if err != nil {
		return nil, err
	}
	switch j.outcome {
	case outcomeStart, outcomeRefused, outcomeNewKey:
		return j, nil
	}
	clock := cfg.clock
	if clock == nil {
		clock = time.Now
	}
	switch j.outcome {
	case outcomeSetAside:
		if err := files.setAside("log", files.log, j.logEnd, clock, wio); err != nil {
			return j, err
		}
	case outcomeNewlineAndMark:
		if err := wio.appendTo("log", files.log, []byte{'\n'}); err != nil {
			return j, fmt.Errorf("witness repair: %w", err)
		}
		if err := wio.sync("log", files.log); err != nil {
			return j, fmt.Errorf("witness repair: %w", err)
		}
		fallthrough
	case outcomeMarkCompleted:
		if err := wio.appendTo("marks", files.marks, markLine(j.complete)); err != nil {
			return j, fmt.Errorf("witness repair: %w", err)
		}
		if err := wio.sync("marks", files.marks); err != nil {
			return j, fmt.Errorf("witness repair: %w", err)
		}
	}
	if j.registrationsTail {
		if err := files.setAside("registrations", files.registrations, j.registrationsEnd, clock, wio); err != nil {
			return j, err
		}
	}
	after, err := files.judge(cfg.publicKey)
	if err != nil {
		return j, err
	}
	if after.outcome != outcomeStart {
		return j, fmt.Errorf("witness repair: after %s the start-up checks found %v", j.outcome, after.findings.names())
	}
	return j, nil
}

// setAside keeps a file's last bytes, from end on, in the set-aside file
// beside the log -- appended and synced, made if it is not there -- and only
// then ends the file at end. A crash between the two leaves the bytes kept
// twice, never lost.
func (f *witnessFiles) setAside(label string, file *os.File, end int64, clock func() time.Time, wio witnessIO) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("witness repair: %w", err)
	}
	last := make([]byte, info.Size()-end)
	if _, err := file.ReadAt(last, end); err != nil {
		return fmt.Errorf("witness repair: %w", err)
	}
	record := newObject()
	record.set("at", vString(clock().UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")))
	record.set("bytes", vString(hex.EncodeToString(last)))
	record.set("file", vString(label))
	record.set("offset", vInt(end))
	kept, err := openWitnessFile(f.logDir, f.logName+setAsideSuffix)
	if err == nil && kept == nil {
		kept, err = createWitnessFile(f.logDir, f.logName+setAsideSuffix)
	}
	if err != nil {
		return fmt.Errorf("witness repair: %w", err)
	}
	defer kept.Close()
	if err := wio.appendTo("set-aside", kept, append(canon(record), '\n')); err != nil {
		return fmt.Errorf("witness repair: %w", err)
	}
	if err := wio.sync("set-aside", kept); err != nil {
		return fmt.Errorf("witness repair: %w", err)
	}
	if err := wio.truncate(label, file, end); err != nil {
		return fmt.Errorf("witness repair: %w", err)
	}
	if err := wio.sync(label, file); err != nil {
		return fmt.Errorf("witness repair: %w", err)
	}
	return nil
}

// registerWitnessTrail registers a trail while the witness is not running:
// under its locks, to registrations that end cleanly, whatever the log
// holds. A registration is harmless to the log: it is how a witness whose
// start-up found a trail with no registration is given one.
func registerWitnessTrail(paths witnessPaths, r witnessRegistration, wio witnessIO) error {
	if err := r.check(); err != nil {
		return err
	}
	files, err := holdWitnessFiles(paths)
	if err != nil {
		return err
	}
	defer files.close()
	if files.registrations == nil {
		if files.registrations, err = createWitnessFile(files.logDir, files.logName+registrationsSuffix); err != nil {
			return err
		}
	}
	info, err := files.registrations.Stat()
	if err != nil {
		return fmt.Errorf("witness registrations: %w", err)
	}
	if size := info.Size(); size > 0 {
		lastByte := make([]byte, 1)
		if _, err := files.registrations.ReadAt(lastByte, size-1); err != nil {
			return fmt.Errorf("witness registrations: %w", err)
		}
		if lastByte[0] != '\n' {
			return errors.New("witness: the registrations do not end cleanly; repair sets their last bytes aside first")
		}
	}
	if err := wio.appendTo("registrations", files.registrations, registrationLine(r)); err != nil {
		return fmt.Errorf("witness registrations: %w", err)
	}
	if err := wio.sync("registrations", files.registrations); err != nil {
		return fmt.Errorf("witness registrations: %w", err)
	}
	return nil
}
