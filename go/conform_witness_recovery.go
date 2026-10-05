package main

// The witness's recovery vectors (corpus/witness-recovery/): a witness's
// files, and what its start-up checks, its repair and its writer do with
// them, by the rules of docs/adr/0013-checkpoint-witness.md §4. They hold
// this reference witness's own storage, which no reader of a chain reads, so
// `gateway conform` runs them against this implementation alone and they
// are not in the process contract (corpus/README.md).
//
// No vector hands the runner a secret. A writer step signs nothing here: the
// vector lists the statements the writer is expected to make, each signed
// under the test seed and checked under corpus/TEST-PUBLIC-KEY before
// anything is run, and the runner's signer gives the writer a statement's
// signature only for exactly the bytes that statement signs. A writer that
// builds any other bytes gets no signature, and the step disagrees.

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// recoveryFamilies are the families of recovery vectors this runner reads.
var recoveryFamilies = map[string]bool{
	"accepted": true, "mark": true, "set-aside": true, "refused": true, "new-key": true,
	"registration": true, "writer": true,
}

// recoveryVector is one vector: the files a witness finds, the clock and the
// registration it runs with, the statements its writer may make, and the
// steps, each with what it is expected to give.
type recoveryVector struct {
	Name         string             `json:"name"`
	Family       string             `json:"family"`
	Note         string             `json:"note"`
	Clock        string             `json:"clock"`
	Registration string             `json:"registration"`
	Statements   []string           `json:"statements"`
	Files        map[string]*string `json:"files"`
	Steps        []recoveryStep     `json:"steps"`
}

// recoveryStep is one step: exactly one of its actions, with its
// expectation.
type recoveryStep struct {
	Open       *recoveryExpect    `json:"open"`
	Repair     *recoveryExpect    `json:"repair"`
	Replace    map[string]*string `json:"replace"`
	Register   *recoveryRegister  `json:"register"`
	Offline    *recoveryRegister  `json:"registerOffline"`
	Submit     *recoverySubmit    `json:"submit"`
	Retire     *string            `json:"retire"`
	Concurrent []recoverySubmit   `json:"concurrent"`
	Fault      *recoveryFault     `json:"fault"`
	Answer     *recoveryAnswer    `json:"answer"`
	Answers    []string           `json:"answers"`
	AtMost     *int               `json:"notEndingCleanlyAtMost"`
	Files      map[string]*string `json:"files"`
}

type recoveryExpect struct {
	Outcome  string   `json:"outcome"`
	Findings []string `json:"findings"`
}

type recoveryRegister struct {
	Trail   string `json:"trail"`
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

type recoverySubmit struct {
	Issuer  string   `json:"issuer"`
	Subject string   `json:"subject"`
	Lines   []string `json:"lines"`
}

// recoveryFault is a write that fails at a step of the fixed order (append,
// sync, mark, mark-sync, publish, register, register-sync), leaving in its
// file nothing of what it wrote, a torn part, all of it but its newline, or
// all of it; a failed sync keeps what was written, or loses it.
type recoveryFault struct {
	Step   string `json:"step"`
	Leaves string `json:"leaves"`
}

type recoveryAnswer struct {
	Kind       string   `json:"kind"`
	Statements []string `json:"statements"`
}

// The files of a vector, by the names it gives them.
var recoveryFileNames = []string{"log", "marks", "registrations", "setAside"}

// readRecoveryVector reads one vector, refusing a member the runner does not
// know, a family it does not read, a step that is not exactly one action,
// and a statement that does not verify under the test key.
func readRecoveryVector(path string, publicKey ed25519.PublicKey) (recoveryVector, error) {
	var v recoveryVector
	raw, err := os.ReadFile(path)
	if err != nil {
		return v, err
	}
	if err := decodeVectorFile(raw, &v, true); err != nil {
		return v, fmt.Errorf("%s: %v", path, err)
	}
	fail := func(format string, args ...any) (recoveryVector, error) {
		return v, fmt.Errorf("%s: %s", path, fmt.Sprintf(format, args...))
	}
	if !recoveryFamilies[v.Family] {
		return fail("family %q is not one this runner reads", v.Family)
	}
	if v.Name != strings.TrimSuffix(filepath.Base(path), ".json") {
		return fail("named %q", v.Name)
	}
	if _, err := time.Parse("2006-01-02T15:04:05Z", v.Clock); err != nil {
		return fail("clock %q is not a time", v.Clock)
	}
	if v.Registration != "operator" && v.Registration != "first-submission" {
		return fail("registration %q is neither operator nor first-submission", v.Registration)
	}
	if len(v.Steps) == 0 {
		return fail("no steps")
	}
	checkFiles := func(files map[string]*string) error {
		for name := range files {
			if !slices.Contains(recoveryFileNames, name) {
				return fmt.Errorf("a file %q no runner compares", name)
			}
		}
		return nil
	}
	if err := checkFiles(v.Files); err != nil {
		return fail("%v", err)
	}
	for i, step := range v.Steps {
		actions := 0
		for _, set := range []bool{step.Open != nil, step.Repair != nil, step.Replace != nil, step.Register != nil, step.Offline != nil, step.Submit != nil, step.Retire != nil, step.Concurrent != nil} {
			if set {
				actions++
			}
		}
		if actions > 1 || (actions == 0 && step.Files == nil) {
			return fail("step %d is not exactly one action", i+1)
		}
		writes := step.Register != nil || step.Submit != nil || step.Retire != nil
		expect := step.Open
		if expect == nil {
			expect = step.Repair
		}
		faults := map[string]bool{"append": true, "sync": true, "mark": true, "mark-sync": true, "publish": true, "register": true, "register-sync": true}
		leaves := map[string]bool{"nothing": true, "torn": true, "unterminated": true, "whole": true}
		switch {
		case expect != nil && (expect.Outcome == "" || expect.Findings == nil):
			return fail("step %d expects no outcome or no findings", i+1)
		case writes && step.Answer == nil:
			return fail("step %d expects no answer", i+1)
		case step.Answer != nil && !writes:
			return fail("step %d expects an answer of nothing that answers", i+1)
		case step.Concurrent != nil && (step.Fault == nil || step.Answers == nil || step.AtMost == nil):
			return fail("step %d is concurrent with no fault, answers or bound", i+1)
		case step.Concurrent == nil && (step.Answers != nil || step.AtMost != nil):
			return fail("step %d expects answers of no concurrent submissions", i+1)
		case step.Fault != nil && !writes && step.Concurrent == nil && step.Repair == nil:
			return fail("step %d has a fault and nothing that writes", i+1)
		case step.Fault != nil && (!faults[step.Fault.Step] || !leaves[step.Fault.Leaves]):
			return fail("step %d has a fault of no step or no state", i+1)
		}
		if err := errors.Join(checkFiles(step.Files), checkFiles(step.Replace)); err != nil {
			return fail("step %d: %v", i+1, err)
		}
	}
	for i, line := range v.Statements {
		st, ok := parseWitnessStatement([]byte(line))
		if !ok || st.whole != line || st.keyID != keyIDFor(publicKey) || !witnessSignatureValid(publicKey, st) {
			return fail("statement %d is no statement the test key signed", i+1)
		}
	}
	return v, nil
}

// recoveryVectorPaths lists the recovery vectors, in a fixed order.
func recoveryVectorPaths(corpusDir string) ([]string, error) {
	paths, err := filepath.Glob(filepath.Join(corpusDir, "witness-recovery", "*.json"))
	sort.Strings(paths)
	return paths, err
}

// runRecoveryVectors reads every recovery vector and, when run is set, holds
// this implementation's witness to it.
func runRecoveryVectors(corpusDir string, run bool) ([]string, int, error) {
	publicKey, err := corpusPublicKey(corpusDir)
	if err != nil {
		return nil, 0, err
	}
	paths, err := recoveryVectorPaths(corpusDir)
	if err != nil {
		return nil, 0, err
	}
	var failures []string
	for _, path := range paths {
		vector, err := readRecoveryVector(path, publicKey)
		if err != nil {
			return nil, 0, err
		}
		if !run {
			continue
		}
		for _, disagreement := range runRecoveryVector(vector, publicKey) {
			failures = append(failures, fmt.Sprintf("witness-recovery %s: %s", vector.Name, disagreement))
		}
	}
	return failures, len(paths), nil
}

// recoveryRun is one vector being run: its directory, the files' paths, the
// witness open, if it is, and what went wrong.
type recoveryRun struct {
	vector    recoveryVector
	publicKey ed25519.PublicKey
	root      string
	paths     witnessPaths
	log       *witnessLog
	signed    map[string][]byte
	unsigned  []string
	failures  []string
	// trace holds every operation of every step to the order of
	// witness_trace.go: a vector whose outcome is right and whose order is
	// not disagrees.
	trace *witnessTrace
}

func (r *recoveryRun) path(name string) string {
	switch name {
	case "log":
		return r.paths.log
	case "marks":
		return r.paths.marks
	case "registrations":
		return r.paths.log + registrationsSuffix
	}
	return r.paths.log + setAsideSuffix
}

func (r *recoveryRun) failf(format string, args ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}

func (r *recoveryRun) config() witnessConfig {
	at, _ := time.Parse("2006-01-02T15:04:05Z", r.vector.Clock)
	return witnessConfig{
		paths:           r.paths,
		firstSubmission: r.vector.Registration == "first-submission",
		publicKey:       r.publicKey,
		sign: func(message []byte) []byte {
			if signature, ok := r.signed[string(message)]; ok {
				return signature
			}
			r.unsigned = append(r.unsigned, fmt.Sprintf("%.120s", message))
			return make([]byte, ed25519.SignatureSize)
		},
		clock: func() time.Time { return at },
		io:    r.trace.wrap(osWitnessIO()),
	}
}

// runRecoveryVector runs one vector's steps in a directory of its own -- the
// log's and the marks' directories apart, as a witness keeps them -- and
// says how each step disagrees with what the vector expects.
func runRecoveryVector(vector recoveryVector, publicKey ed25519.PublicKey) []string {
	root, err := os.MkdirTemp("", "witness-recovery")
	if err != nil {
		return []string{err.Error()}
	}
	defer os.RemoveAll(root)
	r := &recoveryRun{vector: vector, publicKey: publicKey, root: root, signed: map[string][]byte{}, trace: newWitnessTrace()}
	for _, dir := range []string{"log", "marks"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0o700); err != nil {
			return []string{err.Error()}
		}
	}
	r.paths = witnessPaths{log: filepath.Join(root, "log", "witness.log"), marks: filepath.Join(root, "marks", "witness.marks")}
	for _, line := range vector.Statements {
		st, _ := parseWitnessStatement([]byte(line))
		signature, _ := hex.DecodeString(st.signature)
		r.signed[string(st.signed)] = signature
	}
	if err := r.replace(vector.Files); err != nil {
		return []string{err.Error()}
	}
	for i, step := range vector.Steps {
		before := len(r.failures)
		r.step(step)
		for j := before; j < len(r.failures); j++ {
			r.failures[j] = fmt.Sprintf("step %d: %s", i+1, r.failures[j])
		}
		if len(r.unsigned) > 0 {
			r.failf("step %d: the writer built bytes no statement of the vector signs: %q", i+1, r.unsigned[0])
			r.unsigned = nil
		}
		if broken := r.trace.violation(); broken != "" && len(r.failures) == before {
			r.failf("step %d: the order of the witness's operations: %s", i+1, broken)
		}
		if len(r.failures) > 0 {
			break
		}
	}
	if r.log != nil {
		r.log.close()
	}
	return r.failures
}

// replace writes the files given, 0600, and removes those given as null:
// the witness's files as it finds them, or as its operator restores them.
func (r *recoveryRun) replace(files map[string]*string) error {
	for name, text := range files {
		path := r.path(name)
		if text == nil {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			continue
		}
		if err := os.WriteFile(path, []byte(*text), 0o600); err != nil {
			return err
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (r *recoveryRun) closeLog() {
	if r.log != nil {
		r.log.close()
		r.log = nil
	}
}

func (r *recoveryRun) step(step recoveryStep) {
	wio := osWitnessIO()
	var fired *bool
	if step.Fault != nil {
		wio, fired = faultyWitnessIO(wio, step.Fault.Step, step.Fault.Leaves)
	}
	switch {
	case step.Open != nil:
		r.closeLog()
		log, err := openWitnessLog(r.config())
		var refused witnessNotStarted
		switch {
		case err == nil:
			r.log = log
			r.judged("open", step.Open, outcomeStart, nil)
		case errors.As(err, &refused):
			r.judged("open", step.Open, refused.judgement.outcome, refused.judgement.findings.names())
		default:
			r.failf("open: %v", err)
		}
	case step.Repair != nil:
		r.closeLog()
		cfg := r.config()
		cfg.io = r.trace.wrap(wio)
		j, err := repairWitnessLog(cfg)
		if err != nil {
			r.failf("repair: %v", err)
			return
		}
		r.judged("repair", step.Repair, j.outcome, j.findings.names())
	case step.Replace != nil:
		r.closeLog()
		if err := r.replace(step.Replace); err != nil {
			r.failf("replace: %v", err)
		}
		// files the operator put in place are as durable as the operator
		// made them, whatever the witness left unsynced before
		r.trace.reset()
	case step.Offline != nil:
		r.closeLog()
		err := registerWitnessTrail(r.paths, witnessRegistration{trail: step.Offline.Trail, issuer: step.Offline.Issuer, subject: step.Offline.Subject}, r.trace.wrap(wio))
		if err != nil {
			r.failf("registerOffline: %v", err)
		}
	case step.Concurrent != nil:
		r.concurrent(step, wio, fired)
	default:
		if step.Submit != nil || step.Register != nil || step.Retire != nil {
			r.write(step, wio, fired)
		}
	}
	if step.Files != nil {
		r.files(step.Files)
	}
}

// judged compares an outcome and its findings with those expected.
func (r *recoveryRun) judged(what string, expected *recoveryExpect, outcome string, findings []string) {
	want := append([]string(nil), expected.Findings...)
	sort.Strings(want)
	if findings == nil {
		findings = []string{}
	}
	if outcome != expected.Outcome || strings.Join(want, "|") != strings.Join(findings, "|") {
		r.failf("%s: expected %s %v, produced %s %v", what, expected.Outcome, want, outcome, findings)
	}
}

// write runs one submission, registration or retirement against the
// witness open, with the vector's fault in its writes.
func (r *recoveryRun) write(step recoveryStep, wio witnessIO, fired *bool) {
	if r.log == nil {
		r.failf("a write with no witness open")
		return
	}
	r.log.io = r.trace.wrap(wio)
	if step.Fault != nil && step.Fault.Step == "publish" {
		r.log.published = func() error { *fired = true; return errors.New("the process ended after the mark") }
	}
	var answer witnessAnswer
	var err error
	switch {
	case step.Submit != nil:
		answer, err = r.log.submit(step.Submit.Issuer, step.Submit.Subject, stringLines(step.Submit.Lines))
	case step.Retire != nil:
		answer, err = r.log.retire(*step.Retire)
	default:
		err = r.log.register(witnessRegistration{trail: step.Register.Trail, issuer: step.Register.Issuer, subject: step.Register.Subject})
		answer.kind = "registered"
	}
	r.log.io, r.log.published = r.trace.wrap(osWitnessIO()), func() error { return nil }
	if fired != nil && !*fired && step.Fault != nil {
		r.failf("the fault at %s was never reached", step.Fault.Step)
	}
	kind := answerKind(err, answer.kind)
	if kind != step.Answer.Kind {
		r.failf("expected the answer %s, produced %s", step.Answer.Kind, kind)
		return
	}
	if err != nil {
		return
	}
	if len(answer.statements) != len(step.Answer.Statements) {
		r.failf("expected %d statements, produced %d", len(step.Answer.Statements), len(answer.statements))
		return
	}
	for i, line := range answer.statements {
		if string(line) != step.Answer.Statements[i] {
			r.failf("statement %d: %s", i+1, firstDifference(step.Answer.Statements[i], string(line)))
		}
	}
}

// concurrent runs submissions at once, the fault reached by whichever
// writes first: one crash under the writer lock. Every submission is
// answered; then at most the bound of the log and the marks may fail to end
// cleanly.
func (r *recoveryRun) concurrent(step recoveryStep, wio witnessIO, fired *bool) {
	if r.log == nil {
		r.failf("a write with no witness open")
		return
	}
	r.log.io = r.trace.wrap(wio)
	kinds := make([]string, len(step.Concurrent))
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i, submission := range step.Concurrent {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			answer, err := r.log.submit(submission.Issuer, submission.Subject, stringLines(submission.Lines))
			kinds[i] = answerKind(err, answer.kind)
		}()
	}
	close(start)
	wg.Wait()
	r.log.io = r.trace.wrap(osWitnessIO())
	if !*fired {
		r.failf("the fault at %s was never reached", step.Fault.Step)
	}
	want := append([]string(nil), step.Answers...)
	sort.Strings(want)
	sort.Strings(kinds)
	if strings.Join(want, "|") != strings.Join(kinds, "|") {
		r.failf("expected the answers %v, produced %v", want, kinds)
	}
	notClean := 0
	for _, name := range []string{"log", "marks"} {
		data, err := os.ReadFile(r.path(name))
		if err != nil {
			r.failf("%s: %v", name, err)
			return
		}
		if len(data) > 0 && data[len(data)-1] != '\n' {
			notClean++
		}
	}
	if notClean > *step.AtMost {
		r.failf("%d of the log and the marks do not end cleanly, more than %d", notClean, *step.AtMost)
	}
}

// files compares the witness's files, as they are now, with the bytes
// expected, null for a file that is not there.
func (r *recoveryRun) files(expected map[string]*string) {
	for _, name := range recoveryFileNames {
		want, compared := expected[name]
		if !compared {
			continue
		}
		data, err := os.ReadFile(r.path(name))
		switch {
		case want == nil && errors.Is(err, os.ErrNotExist):
		case want == nil:
			r.failf("%s: expected no file, found one of %d bytes", name, len(data))
		case err != nil:
			r.failf("%s: %v", name, err)
		case string(data) != *want:
			r.failf("%s: %s", name, firstDifference(*want, string(data)))
		}
	}
}

// answerKind names what a write answered: the answer's kind, or the error
// it gave instead.
func answerKind(err error, kind string) string {
	var failure witnessFailure
	var lines witnessLineError
	switch {
	case err == nil:
		return kind
	case errors.Is(err, errWitnessStopped):
		return "stopped"
	case errors.As(err, &failure):
		return "failed"
	case errors.Is(err, errWitnessUnregistered):
		return "unregistered"
	case errors.Is(err, errWitnessRegisteredElse):
		return "registered-elsewhere"
	case errors.Is(err, errWitnessNothingRetired):
		return "nothing-to-retire"
	case errors.As(err, &lines):
		return "refused-lines"
	}
	return "error: " + err.Error()
}

func stringLines(lines []string) [][]byte {
	out := make([][]byte, len(lines))
	for i, line := range lines {
		out[i] = []byte(line)
	}
	return out
}

// firstDifference says where two texts first differ, in a few bytes of each,
// never the whole of either.
func firstDifference(want, have string) string {
	i := 0
	for i < len(want) && i < len(have) && want[i] == have[i] {
		i++
	}
	excerpt := func(s string) string {
		end := min(len(s), i+40)
		return fmt.Sprintf("%q", s[max(0, i-20):end])
	}
	return fmt.Sprintf("%d bytes expected, %d produced, first differing at byte %d: expected %s, produced %s", len(want), len(have), i, excerpt(want), excerpt(have))
}

// faultyWitnessIO is the witness's writes with one failure in them: at the
// first write or sync of the step named, it leaves what the vector says and
// fails, and reports through fired that it did. A crash at that step leaves
// the same bytes, and the writer writes nothing after it.
func faultyWitnessIO(base witnessIO, step, leaves string) (witnessIO, *bool) {
	fired := new(bool)
	var mu sync.Mutex
	files := map[string]string{
		"append": "log", "sync": "log", "mark": "marks", "mark-sync": "marks",
		"register": "registrations", "register-sync": "registrations",
	}
	isSync := strings.HasSuffix(step, "sync")
	var lastSize int64
	// written is each file written through this seam: a sync fails only
	// when it is the one that covers a write, as a crash in it would
	written := map[string]bool{}
	out := base
	out.write = func(file string, f *os.File, data []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		if info, err := f.Stat(); err == nil {
			lastSize = info.Size()
		}
		written[file] = true
		if *fired || isSync || files[step] != file {
			return base.write(file, f, data)
		}
		*fired = true
		n := map[string]int{"nothing": 0, "torn": len(data) / 2, "unterminated": len(data) - 1, "whole": len(data)}[leaves]
		written, _ := base.write(file, f, data[:n])
		return written, errors.New("the write failed")
	}
	out.sync = func(file string, f *os.File) error {
		mu.Lock()
		defer mu.Unlock()
		if *fired || !isSync || files[step] != file || !written[file] {
			return base.sync(file, f)
		}
		*fired = true
		if leaves == "nothing" {
			// what was written and never made durable is lost
			_ = f.Truncate(lastSize)
		}
		return errors.New("the sync failed")
	}
	return out, fired
}
