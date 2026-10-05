//go:build unix

package main

// The witness's own storage (witness_log.go; ADR-0013 §4): what it signs,
// under which key and prefix; that every statement it writes reads cleanly
// through the reader of witness.go; its answers; the start-up checks case by
// case; and the writer's fixed order, tested by failing it at every step, for
// every writer, and restarting. The corpus holds the same rules as vectors
// (corpus/witness-recovery/, conformance_test.go); these hold the paths the
// vectors do not reach, and every step of the order for every writer.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	witnessIssuer = "https://issuer.example"
	trailB        = "7d1f3b5a9c2e4f6a8b0d2c4e6f8a1b3c"
	trailC        = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
)

var testClock = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

// newWitnessPaths is a log and its marks in two directories of their own,
// 0700, as a witness keeps them on storage apart.
func newWitnessPaths(t *testing.T) witnessPaths {
	t.Helper()
	root := tempDirAt(t, 0o700)
	for _, dir := range []string{"log", "marks"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return witnessPaths{log: filepath.Join(root, "log", "witness.log"), marks: filepath.Join(root, "marks", "witness.marks")}
}

// testWitness is a witness under the corpus's test seed, its clock the
// test's to move. Every operation its witness, its repairs and its
// registrations make on their files goes through one trace, and the test
// fails, when it ends, if any of them broke the order witness_trace.go
// holds them to.
type testWitness struct {
	paths  witnessPaths
	signer witnessSigner
	now    *time.Time
	first  bool
	trace  *witnessTrace
}

func newTestWitness(t *testing.T, trails ...string) *testWitness {
	t.Helper()
	tw := &testWitness{paths: newWitnessPaths(t), signer: newWitnessSigner(t), now: new(time.Time), trace: newWitnessTrace()}
	t.Cleanup(func() {
		if broken := tw.trace.violation(); broken != "" {
			t.Errorf("the order of the witness's operations: %s; the last of them: %v", broken, tw.trace.last())
		}
	})
	*tw.now = testClock
	for _, trail := range trails {
		tw.register(t, trail)
	}
	return tw
}

func subjectOf(trail string) string { return "deliverer-" + trail[:4] }

func (tw *testWitness) register(t *testing.T, trail string) {
	t.Helper()
	if err := registerWitnessTrail(tw.paths, witnessRegistration{trail: trail, issuer: witnessIssuer, subject: subjectOf(trail)}, tw.io(osWitnessIO())); err != nil {
		t.Fatal(err)
	}
}

func (tw *testWitness) config() witnessConfig {
	public, sign := witnessSeedSigner(tw.signer.seed)
	return witnessConfig{paths: tw.paths, firstSubmission: tw.first, publicKey: public, sign: sign, clock: func() time.Time { return *tw.now }, io: tw.io(osWitnessIO())}
}

// io is base, traced.
func (tw *testWitness) io(base witnessIO) witnessIO { return tw.trace.wrap(base) }

// repair repairs with base in place of the operating system's operations.
func (tw *testWitness) repair(base witnessIO) (*witnessJudgement, error) {
	cfg := tw.config()
	cfg.io = tw.io(base)
	return repairWitnessLog(cfg)
}

func (tw *testWitness) open(t *testing.T) *witnessLog {
	t.Helper()
	w, err := openWitnessLog(tw.config())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return w
}

// judge is the start-up checks' outcome and findings for the files as they
// are, without opening the witness.
func (tw *testWitness) judge(t *testing.T) (string, []string) {
	t.Helper()
	files, err := holdWitnessFiles(tw.paths, osWitnessIO())
	if err != nil {
		t.Fatal(err)
	}
	defer files.close()
	j, err := files.judge(tw.signer.public)
	if err != nil {
		t.Fatal(err)
	}
	return j.outcome, j.findings.names()
}

func (tw *testWitness) read(t *testing.T, name string) string {
	t.Helper()
	path := map[string]string{"log": tw.paths.log, "marks": tw.paths.marks, "registrations": tw.paths.log + registrationsSuffix, "setAside": tw.paths.log + setAsideSuffix}[name]
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "<absent>"
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func (tw *testWitness) write(t *testing.T, name, text string) {
	t.Helper()
	path := map[string]string{"log": tw.paths.log, "marks": tw.paths.marks, "registrations": tw.paths.log + registrationsSuffix, "setAside": tw.paths.log + setAsideSuffix}[name]
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// cpLine is a checkpoint line, in its canonical form, of a record named by
// its trail, sequence and variant.
func cpLine(trail string, sequence int64, variant string) []byte {
	sum := sha256.Sum256([]byte(fmt.Sprintf("witness log test %s record of %s at %d", variant, trail, sequence)))
	return []byte(fmt.Sprintf(`{"checkpointVersion":"1","recordDigest":"sha256:%s","sequence":%d,"trail":"%s"}`, hex.EncodeToString(sum[:]), sequence, trail))
}

func mustSubmit(t *testing.T, w *witnessLog, trail string, lines ...[]byte) witnessAnswer {
	t.Helper()
	answer, err := w.submit(witnessIssuer, subjectOf(trail), lines)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	return answer
}

func mustSign(t *testing.T, w *witnessLog, trail string, sequence int64) []byte {
	t.Helper()
	answer := mustSubmit(t, w, trail, cpLine(trail, sequence, "a"))
	if answer.kind != "signed" || len(answer.statements) != 1 {
		t.Fatalf("expected a statement signed, got %s with %d", answer.kind, len(answer.statements))
	}
	return answer.statements[0]
}

// readChain reads a trail's chain as the witness serves it, to its head,
// through the reader a verifier uses (witness.go).
func readChain(t *testing.T, w *witnessLog, key []byte, trail string) witnessVerdict {
	t.Helper()
	lines, err := w.statements(trail, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	head, ok, err := w.head(trail)
	if err != nil || !ok {
		t.Fatalf("head of %s: %v %v", trail, ok, err)
	}
	var file bytes.Buffer
	for _, line := range lines {
		file.Write(line)
		file.WriteByte('\n')
	}
	return readWitness(witnessReading{trail: trail, keys: [][]byte{key}, files: [][]byte{file.Bytes()}, head: append(head, '\n')})
}

// A statement the witness signs is, byte for byte, what SPEC.md §8.3 says it
// signs, under the gateway's own seed -- the key its receipts and seals are
// signed under, the same keyId -- and under the witness's prefix, so it
// verifies as no receipt and no seal.
func TestWitnessSignsUnderTheGatewaySeedWithTheWitnessPrefix(t *testing.T) {
	tw := newTestWitness(t, testTrail)
	w := tw.open(t)
	defer w.close()
	first := mustSign(t, w, testTrail, 10)
	second := mustSign(t, w, testTrail, 20)

	private := ed25519.NewKeyFromSeed(tw.signer.seed)
	public := private.Public().(ed25519.PublicKey)
	s, err := newStore(t.TempDir(), tw.signer.seed, "gateway:test")
	if err != nil {
		t.Fatal(err)
	}
	if s.keyID != keyIDFor(public) {
		t.Fatalf("the store's keyId %s is not the seed's", s.keyID)
	}
	prev := "null"
	for i, line := range [][]byte{first, second} {
		sequence := []int64{10, 20}[i]
		unsigned := fmt.Sprintf(`{"checkpoint":%s,"index":%d,"keyId":"%s","kind":"checkpoint","prevSignature":%s,"witnessVersion":"1","witnessedAt":"2026-10-05T12:00:00Z"}`,
			cpLine(testTrail, sequence, "a"), i, s.keyID, prev)
		signature := hex.EncodeToString(ed25519.Sign(private, []byte("judgment-pack-gateway/witness/1:"+unsigned)))
		want := strings.Replace(unsigned, `,"witnessVersion"`, `,"signature":"`+signature+`","witnessVersion"`, 1)
		if string(line) != want {
			t.Fatalf("statement %d: %s", i, firstDifference(want, string(line)))
		}
		raw, _ := hex.DecodeString(signature)
		for _, prefix := range []string{receiptContext, receiptContext3, sealContext} {
			if ed25519.Verify(public, []byte(prefix+unsigned), raw) {
				t.Errorf("statement %d verifies under the prefix %q", i, prefix)
			}
		}
		prev = `"` + signature + `"`
	}
}

// Every statement the witness writes reads through the reader with no
// finding, across two trails and every kind -- checkpoints, a conflict, a
// held checkpoint, a checkpoint below the head, a retirement and a
// submission after it -- to the head it serves, before and after a restart;
// and `gateway witness verify` finds nothing in its log and marks.
func TestWitnessRoundTripThroughTheReader(t *testing.T) {
	tw := newTestWitness(t, testTrail, trailB)
	w := tw.open(t)
	mustSign(t, w, testTrail, 10)
	mustSign(t, w, trailB, 5)
	mustSign(t, w, testTrail, 20)
	if a := mustSubmit(t, w, testTrail, cpLine(testTrail, 10, "another")); a.kind != "conflict" {
		t.Fatalf("a conflict was answered %s", a.kind)
	}
	mustSign(t, w, trailB, 9)
	if a := mustSubmit(t, w, testTrail, cpLine(testTrail, 20, "a")); a.kind != "held" {
		t.Fatalf("a held checkpoint was answered %s", a.kind)
	}
	if a := mustSubmit(t, w, testTrail, cpLine(testTrail, 15, "a")); a.kind != "below-head" {
		t.Fatalf("a checkpoint below the head was answered %s", a.kind)
	}
	if a, err := w.retire(testTrail); err != nil || a.kind != "signed" {
		t.Fatalf("retire: %v %v", a.kind, err)
	}
	if a := mustSubmit(t, w, testTrail, cpLine(testTrail, 30, "a")); a.kind != "retired" {
		t.Fatalf("a submission after the retirement was answered %s", a.kind)
	}
	mustSign(t, w, trailB, 12)

	check := func(w *witnessLog) [][]byte {
		a := readChain(t, w, tw.signer.public, testTrail)
		if a.refused != "" || len(a.findings) > 0 || a.reading != "current" || !a.retired || a.highest != 3 ||
			a.latest == nil || a.latest.Sequence != 20 || len(a.conflict) != 1 || a.conflict[0] != 10 {
			t.Fatalf("trail A reads: refused %q, findings %v, reading %s, retired %v, highest %d, conflicts %v", a.refused, a.findings, a.reading, a.retired, a.highest, a.conflict)
		}
		b := readChain(t, w, tw.signer.public, trailB)
		if b.refused != "" || len(b.findings) > 0 || b.retired || b.highest != 2 || b.latest == nil || b.latest.Sequence != 12 {
			t.Fatalf("trail B reads: refused %q, findings %v, retired %v, highest %d", b.refused, b.findings, b.retired, b.highest)
		}
		lines, err := w.statements(testTrail, 0, 1000)
		if err != nil {
			t.Fatal(err)
		}
		return lines
	}
	before := check(w)
	w.close()
	if outcome, findings := tw.judge(t); outcome != outcomeStart || len(findings) > 0 {
		t.Fatalf("after a clean close the checks find %s %v", outcome, findings)
	}
	w = tw.open(t)
	defer w.close()
	after := check(w)
	if !bytes.Equal(bytes.Join(before, []byte{'\n'}), bytes.Join(after, []byte{'\n'})) {
		t.Fatal("a restart serves other bytes for the trail's statements")
	}

	keyFile := filepath.Join(t.TempDir(), "witness.key")
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(tw.signer.public)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := witnessVerify(tw.paths.log, keyFile, tw.paths.marks)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(out, []byte(`{"ok":true,"findings":[],"outcome":"start","statements":7}`)) {
		t.Fatalf("witness verify: %.300s", out)
	}
}

// The witness's answers to a submission, a retirement and a registration.
func TestWitnessSubmissionAnswers(t *testing.T) {
	tw := newTestWitness(t, testTrail)
	w := tw.open(t)
	defer w.close()
	logSize := func() int { return len(tw.read(t, "log")) }

	for _, c := range []struct {
		what    string
		subject string
		lines   [][]byte
		want    error
	}{
		{"a trail not registered", subjectOf(trailB), [][]byte{cpLine(trailB, 1, "a")}, errWitnessUnregistered},
		{"a trail registered to another subject", "someone-else", [][]byte{cpLine(testTrail, 1, "a")}, errWitnessRegisteredElse},
	} {
		if _, err := w.submit(witnessIssuer, c.subject, c.lines); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", c.what, err)
		}
	}
	if _, err := w.submit("https://another.example", subjectOf(testTrail), [][]byte{cpLine(testTrail, 1, "a")}); !errors.Is(err, errWitnessRegisteredElse) {
		t.Errorf("another issuer: %v", err)
	}
	respelled := bytes.Replace(cpLine(testTrail, 1, "a"), []byte(`"sequence":1`), []byte(`"sequence": 1`), 1)
	for what, lines := range map[string][][]byte{
		"no line":                       nil,
		"a line respelled":              {respelled},
		"lines of two trails":           {cpLine(testTrail, 1, "a"), cpLine(trailB, 2, "a")},
		"sequences not increasing":      {cpLine(testTrail, 2, "a"), cpLine(testTrail, 2, "b")},
		"a statement, not a checkpoint": {[]byte(`{"checkpointVersion":"1","recordDigest":"sha256:` + strings.Repeat("0", 64) + `","sequence":1,"trail":"` + testTrail + `","x":1}`)},
	} {
		var lineErr witnessLineError
		if _, err := w.submit(witnessIssuer, subjectOf(testTrail), lines); !errors.As(err, &lineErr) {
			t.Errorf("%s: %v", what, err)
		}
	}
	if logSize() != 0 {
		t.Fatal("a refused submission wrote to the log")
	}

	first := mustSign(t, w, testTrail, 10)
	if a := mustSubmit(t, w, testTrail, cpLine(testTrail, 10, "a")); a.kind != "held" || !bytes.Equal(a.statements[0], first) {
		t.Fatalf("the same checkpoint again: %s", a.kind)
	}
	mustSign(t, w, testTrail, 20)
	size := logSize()
	conflict := mustSubmit(t, w, testTrail, cpLine(testTrail, 10, "another"), cpLine(testTrail, 30, "a"))
	if conflict.kind != "conflict" || !bytes.Equal(conflict.statements[0], first) || logSize() == size {
		t.Fatalf("an earlier line conflicting: %s", conflict.kind)
	}
	size = logSize()
	again := mustSubmit(t, w, testTrail, cpLine(testTrail, 10, "a third"))
	if again.kind != "conflict" || !bytes.Equal(again.statements[1], conflict.statements[1]) || logSize() != size {
		t.Fatalf("a second offer at one sequence: %s, the log grew %v", again.kind, logSize() != size)
	}
	if a := mustSubmit(t, w, testTrail, cpLine(testTrail, 15, "a")); a.kind != "below-head" || !bytes.Equal(a.statements[0], conflict.statements[1]) {
		t.Fatalf("below the latest checkpoint: %s", a.kind)
	}
	if _, err := w.retire(trailB); !errors.Is(err, errWitnessNothingRetired) {
		t.Errorf("retiring a trail with nothing: %v", err)
	}
	retirement, err := w.retire(testTrail)
	if err != nil || retirement.kind != "signed" {
		t.Fatalf("retire: %v", err)
	}
	st, _ := parseWitnessStatement(retirement.statements[0])
	if st.kind != "retirement" || st.sequence != 20 {
		t.Fatalf("the retirement repeats sequence %d as a %s", st.sequence, st.kind)
	}
	for _, again := range []func() (witnessAnswer, error){
		func() (witnessAnswer, error) { return w.retire(testTrail) },
		func() (witnessAnswer, error) {
			return w.submit(witnessIssuer, subjectOf(testTrail), [][]byte{cpLine(testTrail, 40, "a")})
		},
	} {
		if a, err := again(); err != nil || a.kind != "retired" || !bytes.Equal(a.statements[0], retirement.statements[0]) {
			t.Fatalf("after the retirement: %s %v", a.kind, err)
		}
	}
	if err := w.register(witnessRegistration{trail: trailB, issuer: witnessIssuer, subject: ""}); err == nil {
		t.Error("a registration with no subject was kept")
	}
}

// Under "first-submission" the first submission accepted for a trail
// registers it to its submitter, before anything is signed for it, and
// another subject is then refused.
func TestWitnessFirstSubmissionRegisters(t *testing.T) {
	tw := newTestWitness(t)
	tw.first = true
	w := tw.open(t)
	defer w.close()
	mustSign(t, w, trailC, 1)
	if got, want := tw.read(t, "registrations"), string(registrationLine(witnessRegistration{trail: trailC, issuer: witnessIssuer, subject: subjectOf(trailC)})); got != want {
		t.Fatalf("registrations: %s", firstDifference(want, got))
	}
	if _, err := w.submit(witnessIssuer, "a-squatter", [][]byte{cpLine(trailC, 2, "a")}); !errors.Is(err, errWitnessRegisteredElse) {
		t.Fatalf("another subject: %v", err)
	}
}

// A statement's time is never earlier than the previous statement's for the
// trail: the witness takes the later of its clock and that time.
func TestWitnessTimeNeverGoesBack(t *testing.T) {
	tw := newTestWitness(t, testTrail, trailB)
	w := tw.open(t)
	defer w.close()
	mustSign(t, w, testTrail, 1)
	*tw.now = testClock.Add(-time.Hour)
	st, _ := parseWitnessStatement(mustSign(t, w, testTrail, 2))
	if st.witnessedAt != "2026-10-05T12:00:00Z" {
		t.Fatalf("a statement after a clock set back states %s", st.witnessedAt)
	}
	other, _ := parseWitnessStatement(mustSign(t, w, trailB, 1))
	if other.witnessedAt != "2026-10-05T11:00:00Z" {
		t.Fatalf("another trail's statement states %s, not its clock's time", other.witnessedAt)
	}
}

// The witness writes nothing its readers would refuse: a statement made
// under a signer that does not make the key's signatures is refused before
// a byte of it is written, and the witness goes on.
func TestWitnessWritesNothingItsReadersWouldRefuse(t *testing.T) {
	tw := newTestWitness(t, testTrail)
	cfg := tw.config()
	_, otherSign := witnessSeedSigner(bytes.Repeat([]byte{7}, 32))
	cfg.sign = otherSign
	w, err := openWitnessLog(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	if _, err := w.submit(witnessIssuer, subjectOf(testTrail), [][]byte{cpLine(testTrail, 1, "a")}); err == nil {
		t.Fatal("a statement under another key was kept")
	}
	if tw.read(t, "log") != "" || tw.read(t, "marks") != "" || w.stopped != nil {
		t.Fatal("a statement refused before it was written left bytes, or stopped the witness")
	}
}

// startState is a witness's files built from statements signed here.
type startState struct {
	name          string
	log, marks    string
	noMarks       bool
	registrations *string
	want          string
	findings      []string
}

// The start-up checks, case by case: the outcome each state gives and the
// findings that name it, from ADR-0013 §4's checks and three rules.
func TestWitnessStartUpCases(t *testing.T) {
	w := newWitnessSigner(t)
	var sigs []string
	var stmts []string
	prev := ""
	for i, seq := range []int64{10, 20, 30} {
		line, sig := w.line(stmt{sequence: seq, index: int64(i), prev: prev})
		stmts, sigs, prev = append(stmts, line), append(sigs, sig), sig
	}
	retirement, rsig := w.line(stmt{kind: "retirement", index: 3, prev: sigs[2], retires: &stmt{sequence: 30}})
	afterRetirement, asig := w.line(stmt{sequence: 40, index: 4, prev: rsig})
	mark := func(index int, sig string) string {
		return fmt.Sprintf(`{"index":%d,"signature":"%s","trail":"%s"}`, index, sig, testTrail) + "\n"
	}
	marks := func(n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteString(mark(i, sigs[i]))
		}
		return b.String()
	}
	log := func(lines ...string) string { return strings.Join(lines, "\n") + "\n" }
	brokenChain, brokenSig := w.line(stmt{sequence: 30, index: 2, prev: sigs[0]})
	other := witnessSigner{private: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))}
	other.public = other.private.Public().(ed25519.PublicKey)
	otherKey, _ := other.line(stmt{sequence: 30, index: 2, prev: sigs[1]})
	respelled := strings.Replace(stmts[1], `"index":1`, `"index": 1`, 1)
	reg := string(registrationLine(witnessRegistration{trail: testTrail, issuer: witnessIssuer, subject: "d"}))
	p := func(s string) *string { return &s }

	for _, c := range []startState{
		{name: "a witness with nothing yet", want: outcomeStart},
		{name: "every statement marked", log: log(stmts...), marks: marks(3), want: outcomeStart},
		{name: "a retirement, marked", log: log(stmts[0], stmts[1], stmts[2], retirement), marks: marks(3) + mark(3, rsig), want: outcomeStart},
		{name: "a statement after a retirement, marked", log: log(stmts[0], stmts[1], stmts[2], retirement, afterRetirement), marks: marks(3) + mark(3, rsig) + mark(4, asig),
			want: outcomeRefused, findings: []string{findingWitnessChainBroken}},
		{name: "a marked line respelled", log: log(stmts[0], respelled, stmts[2]), marks: marks(3), want: outcomeRefused,
			findings: []string{findingMarkUnreached, findingUnmarked, findingWitnessMalformed}},
		{name: "an unmarked last line under another key", log: log(stmts[0], stmts[1], otherKey), marks: marks(2), want: outcomeNewKey,
			findings: []string{findingUnmarked, findingWitnessSignatureInvalid}},
		{name: "an unmarked last line breaking the chain", log: log(stmts[0], stmts[1], brokenChain), marks: marks(2), want: outcomeNewKey,
			findings: []string{findingUnmarked, findingWitnessChainBroken}},
		{name: "a marked line breaking the chain", log: log(stmts[0], brokenChain), marks: marks(1) + mark(2, brokenSig),
			want: outcomeRefused, findings: []string{findingWitnessChainBroken}},
		{name: "an unterminated last statement that fails the checks", log: log(stmts[0], stmts[1]) + otherKey, marks: marks(2), want: outcomeNewKey,
			findings: []string{findingLogUnterminated, findingWitnessSignatureInvalid}},
		{name: "an unterminated last statement breaking the chain", log: log(stmts[0], stmts[1]) + brokenChain, marks: marks(2), want: outcomeNewKey,
			findings: []string{findingLogUnterminated, findingWitnessChainBroken}},
		{name: "a marked statement missing its newline", log: log(stmts[0], stmts[1]) + stmts[2], marks: marks(3), want: outcomeRefused,
			findings: []string{findingLogUnterminated, findingMarkUnreached}},
		{name: "a torn tail after an unmarked statement", log: log(stmts...) + "{", marks: marks(2), want: outcomeRefused,
			findings: []string{findingLogTorn, findingUnmarked}},
		{name: "a second mark for an index", log: log(stmts...), marks: marks(3) + mark(2, sigs[0]), want: outcomeRefused,
			findings: []string{findingMarkUnreached}},
		{name: "a line longer than any statement", log: log(stmts[0], strings.Repeat("x", witnessLineLimit+1)), marks: marks(1), want: outcomeNewKey,
			findings: []string{findingUnmarked, findingWitnessMalformed}},
		{name: "empty marks behind statements", log: log(stmts[0]), marks: "", want: outcomeMarkCompleted, findings: []string{findingUnmarked}},
		{name: "a lost marks file behind statements", log: log(stmts...), noMarks: true, want: outcomeNewKey, findings: []string{findingMarksLost}},
		{name: "a registration line at the bound", log: log(stmts...), marks: marks(3), registrations: p(reg + string(registrationLine(witnessRegistration{trail: trailB, issuer: witnessIssuer, subject: strings.Repeat("s", witnessLineLimit-(len(registrationLine(witnessRegistration{trail: trailB, issuer: witnessIssuer, subject: ""}))-1))}))),
			want: outcomeStart},
		{name: "a registration line one past the bound", log: log(stmts...), marks: marks(3), registrations: p(reg + string(registrationLine(witnessRegistration{trail: trailB, issuer: witnessIssuer, subject: strings.Repeat("s", 1+witnessLineLimit-(len(registrationLine(witnessRegistration{trail: trailB, issuer: witnessIssuer, subject: ""}))-1))}))),
			want: outcomeRefused, findings: []string{findingRegistrationMalformed}},
		{name: "a lost marks file behind a torn log", log: "{", noMarks: true, want: outcomeNewKey, findings: []string{findingLogTorn, findingMarksLost}},
		{name: "a registration line damaged", log: log(stmts...), marks: marks(3), registrations: p(reg + "{}\n"), want: outcomeRefused,
			findings: []string{findingRegistrationMalformed}},
		{name: "registrations missing only a newline", log: log(stmts...), marks: marks(3), registrations: p(reg + strings.TrimSuffix(string(registrationLine(witnessRegistration{trail: trailB, issuer: witnessIssuer, subject: "b"})), "\n")),
			want: outcomeRegistrationSetAside, findings: []string{findingRegistrationsUnterminated}},
		{name: "a trail's only registration missing its newline", log: log(stmts...), marks: marks(3), registrations: p(strings.TrimSuffix(reg, "\n")), want: outcomeRefused,
			findings: []string{findingRegistrationsUnterminated, findingUnregistered}},
		{name: "registrations torn with a mark to complete", log: log(stmts...), marks: marks(2), registrations: p(reg + reg[:9]), want: outcomeMarkCompleted,
			findings: []string{findingRegistrationsTorn, findingUnmarked}},
	} {
		t.Run(c.name, func(t *testing.T) {
			tw := newTestWitness(t)
			if c.log != "" || c.marks != "" {
				tw.write(t, "log", c.log)
				tw.write(t, "marks", c.marks)
			}
			if c.noMarks {
				if err := os.Remove(tw.paths.marks); err != nil {
					t.Fatal(err)
				}
			}
			registrations := reg
			if c.registrations != nil {
				registrations = *c.registrations
			}
			tw.write(t, "registrations", registrations)
			outcome, findings := tw.judge(t)
			want := append([]string(nil), c.findings...)
			sort.Strings(want)
			if outcome != c.want || strings.Join(findings, " ") != strings.Join(want, " ") {
				t.Fatalf("outcome %s %v, want %s %v", outcome, findings, c.want, c.findings)
			}
			w, err := openWitnessLog(tw.config())
			if err == nil {
				w.close()
			}
			if (err == nil) != (c.want == outcomeStart) {
				t.Fatalf("open: %v, with the outcome %s", err, outcome)
			}
		})
	}
}

// failAt is the witness's writes failing at a step, as faultyWitnessIO
// fails them, and, the moment it fails, the sizes of the log and the marks,
// so that a test can show nothing was written after the failure.
type failAt struct {
	io     witnessIO
	fired  *bool
	sizes  [2]int64
	signal chan struct{}
}

func newFailAt(tw *testWitness, step, leaves string, block <-chan struct{}) *failAt {
	f := &failAt{signal: make(chan struct{})}
	inner, fired := faultyWitnessIO(osWitnessIO(), step, leaves)
	f.fired = fired
	var once sync.Once
	after := func() {
		once.Do(func() {
			for i, path := range []string{tw.paths.log, tw.paths.marks} {
				if info, err := os.Stat(path); err == nil {
					f.sizes[i] = info.Size()
				}
			}
			close(f.signal)
			if block != nil {
				<-block
			}
		})
	}
	f.io = inner
	f.io.write = func(file string, fd *os.File, data []byte) (int, error) {
		n, err := inner.write(file, fd, data)
		if *fired {
			after()
		}
		return n, err
	}
	f.io.sync = func(file string, fd *os.File) error {
		err := inner.sync(file, fd)
		if *fired {
			after()
		}
		return err
	}
	return f
}

// sizes is the log's and the marks' sizes now.
func (tw *testWitness) sizes(t *testing.T) [2]int64 {
	t.Helper()
	var out [2]int64
	for i, path := range []string{tw.paths.log, tw.paths.marks} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = info.Size()
	}
	return out
}

// crashCase is one writer failing at one step, leaving one state.
type crashCase struct {
	writer, step, leaves string
	want                 string
}

// crashOutcome is what the start-up checks find after a crash at a step that
// left its file so (ADR-0013 §4): every case but last bytes in the marks
// file is started again with no key lost.
func crashOutcome(step, leaves string) string {
	switch step + "/" + leaves {
	case "append/nothing", "sync/nothing", "mark/whole", "mark-sync/whole", "publish/whole",
		"register/nothing", "register/whole", "register-sync/nothing", "register-sync/whole":
		return outcomeStart
	case "append/torn":
		return outcomeSetAside
	case "append/unterminated":
		return outcomeNewlineAndMark
	case "append/whole", "sync/whole", "mark/nothing", "mark-sync/nothing":
		return outcomeMarkCompleted
	case "mark/torn", "mark/unterminated":
		return outcomeNewKey
	case "register/torn", "register/unterminated":
		return outcomeRegistrationSetAside
	}
	return ""
}

// crashCases is every writer at every step of its order, leaving every
// state that step can leave: a write nothing, half of its bytes, all but
// the newline, or all; a sync what was written lost, or kept.
func crashCases() []crashCase {
	var out []crashCase
	statementSteps := []string{"append", "sync", "mark", "mark-sync", "publish"}
	for _, writer := range []string{"checkpoint", "conflict", "retirement", "first-submission"} {
		steps := statementSteps
		if writer == "first-submission" {
			steps = append([]string{"register", "register-sync"}, statementSteps...)
		}
		for _, step := range steps {
			leaves := []string{"nothing", "torn", "unterminated", "whole"}
			if strings.HasSuffix(step, "sync") {
				leaves = []string{"nothing", "whole"}
			}
			if step == "publish" {
				leaves = []string{"whole"}
			}
			for _, left := range leaves {
				out = append(out, crashCase{writer, step, left, crashOutcome(step, left)})
			}
		}
	}
	return out
}

// The crash matrix: every writer -- a checkpoint statement, a conflict, a
// retirement, and a first submission that registers its trail -- failing at
// every step of the fixed order, leaving every state the step can. After the
// failure the witness signs nothing for another trail and serves nothing
// unmarked; restarted, the checks give what ADR-0013's rules say for that
// state; repair does what they allow; and then every statement published
// before the crash is served as it was, each chain reads cleanly, and the
// trail goes on.
func TestWitnessCrashMatrix(t *testing.T) {
	for _, c := range crashCases() {
		t.Run(c.writer+"/"+c.step+"/"+c.leaves, func(t *testing.T) {
			tw := newTestWitness(t, testTrail, trailB)
			tw.first = true
			w := tw.open(t)
			mustSign(t, w, testTrail, 10)
			mustSign(t, w, trailB, 5)
			mustSign(t, w, testTrail, 20)
			published := map[string]string{}
			for _, trail := range []string{testTrail, trailB} {
				lines, _ := w.statements(trail, 0, 1000)
				published[trail] = string(bytes.Join(lines, []byte{'\n'}))
			}
			headBefore, _, _ := w.head(testTrail)

			f := newFailAt(tw, c.step, c.leaves, nil)
			w.io = tw.io(f.io)
			if c.step == "publish" {
				w.published = func() error { *f.fired = true; return errors.New("the process ended after the mark") }
			}
			var err error
			switch c.writer {
			case "checkpoint":
				_, err = w.submit(witnessIssuer, subjectOf(testTrail), [][]byte{cpLine(testTrail, 30, "a")})
			case "conflict":
				_, err = w.submit(witnessIssuer, subjectOf(testTrail), [][]byte{cpLine(testTrail, 10, "another")})
			case "retirement":
				_, err = w.retire(testTrail)
			case "first-submission":
				_, err = w.submit(witnessIssuer, subjectOf(trailC), [][]byte{cpLine(trailC, 1, "a")})
			}
			var failure witnessFailure
			if !*f.fired || !errors.As(err, &failure) || failure.step != c.step {
				t.Fatalf("the fault fired %v, and the write answered %v", *f.fired, err)
			}
			if c.step == "publish" {
				f.sizes = tw.sizes(t)
			}
			// stopped: nothing more is signed, for any trail, and nothing
			// unmarked is served
			if _, err := w.submit(witnessIssuer, subjectOf(trailB), [][]byte{cpLine(trailB, 6, "a")}); !errors.Is(err, errWitnessStopped) {
				t.Fatalf("another trail after the failure: %v", err)
			}
			if _, err := w.retire(trailB); !errors.Is(err, errWitnessStopped) {
				t.Fatalf("a retirement after the failure: %v", err)
			}
			if err := w.register(witnessRegistration{trail: trailC[:31] + "1", issuer: witnessIssuer, subject: "x"}); !errors.Is(err, errWitnessStopped) {
				t.Fatalf("a registration after the failure: %v", err)
			}
			if a, err := w.submit(witnessIssuer, subjectOf(trailB), [][]byte{cpLine(trailB, 5, "a")}); err != nil || a.kind != "held" {
				t.Fatalf("a held statement after the failure: %v", err)
			}
			if head, _, _ := w.head(testTrail); c.step != "publish" && !bytes.Equal(head, headBefore) {
				t.Fatal("a statement not yet marked is served")
			}
			if tw.sizes(t) != f.sizes {
				t.Fatalf("written after the failure: sizes %v, at the failure %v", tw.sizes(t), f.sizes)
			}
			w.close()

			outcome, findings := tw.judge(t)
			if outcome != c.want {
				t.Fatalf("restarted, the checks give %s %v, the rules %s", outcome, findings, c.want)
			}
			if c.want == outcomeNewKey {
				log, marks := tw.read(t, "log"), tw.read(t, "marks")
				if j, err := tw.repair(osWitnessIO()); err != nil || j.outcome != outcomeNewKey {
					t.Fatalf("repair: %v", err)
				}
				if tw.read(t, "log") != log || tw.read(t, "marks") != marks || tw.read(t, "setAside") != "<absent>" {
					t.Fatal("a repair that may not act wrote")
				}
				return
			}
			if j, err := tw.repair(osWitnessIO()); err != nil || j.outcome != c.want {
				t.Fatalf("repair: %v", err)
			}
			w = tw.open(t)
			defer w.close()
			for trail, before := range published {
				lines, _ := w.statements(trail, 0, 3)
				if got := string(bytes.Join(lines, []byte{'\n'})); !strings.HasPrefix(got, before) {
					t.Fatalf("trail %s no longer serves what it published", trail[:4])
				}
				if v := readChain(t, w, tw.signer.public, trail); v.refused != "" || len(v.findings) > 0 {
					t.Fatalf("trail %s reads with %v", trail[:4], v.findings)
				}
			}
			// the trail goes on: a new checkpoint signs at the next index
			trail := testTrail
			if c.writer == "first-submission" {
				trail = trailC
			}
			if c.writer == "retirement" && (c.want == outcomeMarkCompleted || c.want == outcomeNewlineAndMark || c.step == "mark" && c.leaves == "whole" || c.step == "mark-sync" && c.leaves == "whole" || c.step == "publish") {
				if a := mustSubmit(t, w, trail, cpLine(trail, 50, "a")); a.kind != "retired" {
					t.Fatalf("a retired trail answered %s", a.kind)
				}
				return
			}
			if c.writer == "first-submission" && c.step == "register" && c.leaves != "whole" || c.writer == "first-submission" && c.step == "register-sync" && c.leaves == "nothing" {
				// the registration was never made: the trail is free, and
				// its first submission registers it now
				if a := mustSubmit(t, w, trailC, cpLine(trailC, 1, "a")); a.kind != "signed" {
					t.Fatalf("after a registration that was not made: %s", a.kind)
				}
				return
			}
			st, _ := parseWitnessStatement(mustSign(t, w, trail, 50))
			if v := readChain(t, w, tw.signer.public, trail); v.refused != "" || len(v.findings) > 0 || v.highest != st.index {
				t.Fatalf("after going on, trail %s reads with %v", trail[:4], v.findings)
			}
		})
	}
}

// One crash under the writer lock with two trails submitting: whichever
// trail reaches the failing step first, the other waits at the lock and is
// refused once it gets it, so nothing is written after the crash, and at
// most one of the log and the marks fails to end cleanly. The failing write
// holds the other submission off for a moment after it fails: without the
// lock the other would write in that moment.
func TestWitnessOneCrashUnderTheLockWithTwoTrails(t *testing.T) {
	for _, step := range []string{"append", "sync", "mark", "mark-sync"} {
		leaves := []string{"nothing", "torn", "unterminated", "whole"}
		if strings.HasSuffix(step, "sync") {
			leaves = []string{"nothing", "whole"}
		}
		for _, left := range leaves {
			t.Run(step+"/"+left, func(t *testing.T) {
				tw := newTestWitness(t, testTrail, trailB)
				w := tw.open(t)
				defer w.close()
				mustSign(t, w, testTrail, 1)
				mustSign(t, w, trailB, 1)
				release := make(chan struct{})
				f := newFailAt(tw, step, left, release)
				w.io = tw.io(f.io)
				var wg sync.WaitGroup
				answers := make([]error, 2)
				for i, trail := range []string{testTrail, trailB} {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for sequence := int64(2); sequence < 6; sequence++ {
							if _, answers[i] = w.submit(witnessIssuer, subjectOf(trail), [][]byte{cpLine(trail, sequence, "a")}); answers[i] != nil {
								return
							}
						}
					}()
				}
				<-f.signal
				time.Sleep(50 * time.Millisecond)
				close(release)
				wg.Wait()
				if tw.sizes(t) != f.sizes {
					t.Fatalf("written after the crash: sizes %v, at the crash %v", tw.sizes(t), f.sizes)
				}
				notClean := 0
				for _, name := range []string{"log", "marks"} {
					if text := tw.read(t, name); text != "" && !strings.HasSuffix(text, "\n") {
						notClean++
					}
				}
				var failure witnessFailure
				failed := errors.As(answers[0], &failure) || errors.As(answers[1], &failure)
				stopped := errors.Is(answers[0], errWitnessStopped) || errors.Is(answers[1], errWitnessStopped)
				if notClean > 1 || !failed || !stopped {
					t.Fatalf("%d files not ending cleanly; answers %v, %v", notClean, answers[0], answers[1])
				}
				w.close()
				if outcome, _ := tw.judge(t); outcome != crashOutcome(step, left) {
					t.Fatalf("restarted, the checks give %s, the rules %s", outcome, crashOutcome(step, left))
				}
			})
		}
	}
}

// A repair interrupted is repaired again: the torn bytes are kept before the
// log is cut, so a crash between the two keeps them twice and loses none,
// and a crash in the middle of completing a mark leaves a state repair
// completes.
func TestWitnessRepairInterruptedIsRepairedAgain(t *testing.T) {
	sign := func(tw *testWitness) []byte {
		w := tw.open(t)
		defer w.close()
		mustSign(t, w, testTrail, 1)
		return mustSign(t, w, testTrail, 2)
	}
	t.Run("set-aside cut short", func(t *testing.T) {
		tw := newTestWitness(t, testTrail)
		second := sign(tw)
		marks := tw.read(t, "marks")
		torn := strings.TrimSuffix(tw.read(t, "log"), string(second)+"\n") + string(second[:40])
		tw.write(t, "log", torn)
		tw.write(t, "marks", strings.SplitAfter(marks, "\n")[0])
		failing := osWitnessIO()
		failing.truncate = func(string, *os.File, int64) error { return errors.New("the process ended") }
		if _, err := tw.repair(failing); err == nil {
			t.Fatal("the repair did not fail")
		}
		if tw.read(t, "log") != torn {
			t.Fatal("the log was cut before its bytes were kept")
		}
		if j, err := tw.repair(osWitnessIO()); err != nil || j.outcome != outcomeSetAside {
			t.Fatalf("repair again: %v", err)
		}
		if kept := tw.read(t, "setAside"); strings.Count(kept, hex.EncodeToString(second[:40])) != 2 {
			t.Fatal("the torn bytes are not kept by each repair")
		}
		tw.open(t).close()
	})
	t.Run("a newline completed and its mark not", func(t *testing.T) {
		tw := newTestWitness(t, testTrail)
		sign(tw)
		tw.write(t, "log", strings.TrimSuffix(tw.read(t, "log"), "\n"))
		tw.write(t, "marks", strings.SplitAfter(tw.read(t, "marks"), "\n")[0])
		failing, _ := faultyWitnessIO(osWitnessIO(), "mark", "nothing")
		if _, err := tw.repair(failing); err == nil {
			t.Fatal("the repair did not fail")
		}
		if outcome, _ := tw.judge(t); outcome != outcomeMarkCompleted {
			t.Fatalf("after the newline, the checks give %s", outcome)
		}
		if j, err := tw.repair(osWitnessIO()); err != nil || j.outcome != outcomeMarkCompleted {
			t.Fatalf("repair again: %v", err)
		}
		tw.open(t).close()
	})
}

// A registration kept with the witness stopped is kept only to
// registrations that end cleanly: last bytes are repair's to set aside.
func TestWitnessRegistersOffline(t *testing.T) {
	tw := newTestWitness(t, testTrail)
	tw.write(t, "registrations", tw.read(t, "registrations")+`{"issu`)
	if err := registerWitnessTrail(tw.paths, witnessRegistration{trail: trailB, issuer: witnessIssuer, subject: "b"}, tw.io(osWitnessIO())); err == nil {
		t.Error("a registration was appended to registrations that do not end cleanly")
	}
}

// `gateway witness verify`: its usage, its exit codes, its verdict in its
// JSON, a key the key rule refuses, and findings counted rather than listed.
func TestWitnessVerifyCommand(t *testing.T) {
	tw := newTestWitness(t, testTrail)
	w := tw.open(t)
	mustSign(t, w, testTrail, 1)
	mustSign(t, w, testTrail, 2)
	w.close()
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	small := filepath.Join(dir, "small")
	os.WriteFile(key, []byte(hex.EncodeToString(tw.signer.public)+"\n"), 0o600)
	os.WriteFile(small, []byte(strings.Repeat("00", 32)+"\n"), 0o600)
	run := func(args ...string) (int, map[string]any) {
		var stdout, stderr bytes.Buffer
		code := cmdWitness(args, &stdout, &stderr)
		var out map[string]any
		if code == 0 {
			if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
				t.Fatalf("%v: %v", args, err)
			}
		}
		return code, out
	}
	for _, args := range [][]string{nil, {"check"}, {"verify"}, {"verify", "--log", tw.paths.log}, {"verify", "--log", tw.paths.log, "--log", tw.paths.log, "--public-key", key}, {"verify", "--log"}, {"verify", "--other", "x"}} {
		if code, _ := run(args...); code != 2 {
			t.Errorf("%v: exit %d, not a usage error", args, code)
		}
	}
	if code, _ := run("verify", "--log", filepath.Join(dir, "none"), "--public-key", key); code != 1 {
		t.Errorf("a log that is not there: exit %d", code)
	}
	if code, out := run("verify", "--log", tw.paths.log, "--public-key", small); code != 0 || out["refused"] != refusalKeySmallOrder {
		t.Errorf("a key of small order: exit %d, %v", code, out)
	}
	if code, out := run("verify", "--log", tw.paths.log, "--public-key", key); code != 0 || out["ok"] != true || out["outcome"] != nil {
		t.Errorf("a clean log: exit %d, %v", code, out)
	}
	tw.write(t, "log", tw.read(t, "log")+`{"checkpoint"`)
	code, out := run("verify", "--log", tw.paths.log, "--public-key", key, "--marks", tw.paths.marks)
	if code != 0 || out["ok"] != false || out["outcome"] != outcomeSetAside {
		t.Errorf("a torn log: exit %d, %v", code, out)
	}
	many := filepath.Join(dir, "many")
	os.WriteFile(many, bytes.Repeat([]byte("x\n"), 100000), 0o600)
	code, out = run("verify", "--log", many, "--public-key", key)
	findings, _ := out["findings"].([]any)
	if code != 0 || len(findings) != 1 || findings[0].(map[string]any)["count"] != float64(100000) {
		t.Errorf("100000 malformed lines: exit %d, %d findings", code, len(findings))
	}
}

// traceOf runs operations through a trace's checks, as the seam would, and
// gives the first that broke an invariant, or "".
func traceOf(ops ...string) string {
	tr := newWitnessTrace()
	for _, op := range ops {
		fields := strings.Fields(op)
		var err error
		if len(fields) == 3 {
			err = errors.New("failed")
		}
		tr.before(fields[0], fields[1])
		tr.after(fields[0], fields[1], err)
	}
	return tr.violation()
}

// The trace's invariants (witness_trace.go), each held to a sequence that
// breaks it and one that keeps it, so that the checks the tests and the
// recovery vectors rely on are themselves checked.
func TestWitnessTraceHoldsTheOrder(t *testing.T) {
	start := []string{"hold -", "lock log", "lock registrations", "lock marks", "read log", "read registrations", "read marks", "sync log", "sync registrations", "sync marks", "syncdir log-dir", "syncdir marks-dir", "start -"}
	for _, c := range []struct {
		name string
		ops  []string
		want string
	}{
		{"a start and a statement in order", append(append([]string{}, start...), "write log", "sync log", "write marks", "sync marks", "publish statement"), ""},
		{"1: a mark before its line is synced", []string{"write log", "write marks"}, "a mark appended before the log line"},
		{"1: a mark after a failed sync", []string{"write log", "sync log failed", "write marks"}, "a mark appended before the log line"},
		{"2: published before the mark is synced", []string{"write log", "sync log", "write marks", "publish statement"}, "the marks held bytes not synced"},
		{"2: started on a log not synced", []string{"write log", "start -"}, "the log held bytes not synced"},
		{"3: a cut with nothing kept", []string{"truncate log"}, "a file cut before"},
		{"3: a cut before the kept bytes are synced", []string{"write set-aside", "truncate log"}, "a file cut before"},
		{"3: a cut before the kept bytes are read back", []string{"write set-aside", "sync set-aside", "truncate log"}, "a file cut before"},
		{"3: a read-back before the sync", []string{"write set-aside", "readback set-aside", "sync set-aside", "truncate log"}, "a file cut before"},
		{"3: a read-back of nothing kept", []string{"readback set-aside", "truncate log"}, "a file cut before"},
		{"3: a cut after them", []string{"write set-aside", "sync set-aside", "readback set-aside", "truncate log", "sync log", "repaired -"}, ""},
		{"3: a second cut on the first read-back", []string{"write set-aside", "sync set-aside", "readback set-aside", "truncate log", "sync log", "truncate registrations"}, "a file cut before"},
		{"8: a read before a lock", []string{"hold -", "read log"}, "a file read before it was locked"},
		{"8: a read on a lock of an earlier hold", []string{"hold -", "lock log", "hold -", "read log"}, "a file read before it was locked"},
		{"8: a lock that failed", []string{"hold -", "lock log failed", "read log"}, "a file read before it was locked"},
		{"4: a write before the directory of a file made is synced", []string{"create log", "write log"}, "the directory of a file made"},
		{"4: a write after it", []string{"create log", "syncdir log-dir", "write log", "sync log"}, ""},
		{"5: a mark built on a line read and not synced", []string{"hold -", "lock log", "read log", "write marks"}, "what was read"},
		{"5: a start on a file synced and its directory not", []string{"hold -", "lock log", "read log", "sync log", "start -"}, "what was read (log-dir)"},
		{"5: a start on the marks' directory not synced", []string{"hold -", "lock marks", "read marks", "sync marks", "syncdir log-dir", "start -"}, "what was read (marks-dir)"},
		{"5: a file made on what was read", []string{"hold -", "lock registrations", "read registrations", "create log"}, "what was read"},
		{"5: a start", start, ""},
		{"6: a registration ending unsynced", []string{"write registrations", "registered -"}, "it ended with registrations not synced"},
		{"6: a repair ending with a directory not synced", []string{"create set-aside", "repaired -"}, "the directory of a file made"},
		{"7: a statement on a registration not synced", []string{"write registrations", "write log"}, "the registration it rests on"},
	} {
		got := traceOf(c.ops...)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// The operations one start and one statement make, in their order: each
// file locked before it is read, and what was read synced, files and
// directories, before the start; a statement's
// line written and synced, then its mark written and synced, then the
// statement published; a first submission's registration written and
// synced before its statement.
func TestWitnessOperationsInOrder(t *testing.T) {
	tw := newTestWitness(t, testTrail)
	tw.first = true
	w := tw.open(t)
	ops := strings.Join(tw.trace.last(), " | ")
	if want := "hold  | lock registrations | read registrations | sync registrations | syncdir log-dir | syncdir marks-dir | create log | lock log | syncdir log-dir | create marks | lock marks | syncdir marks-dir | start "; !strings.HasSuffix(ops, want) {
		t.Fatalf("a first start: %s", ops)
	}
	mustSign(t, w, testTrail, 1)
	ops = strings.Join(tw.trace.last(), " | ")
	if want := " | write log | sync log | write marks | sync marks | publish statement"; !strings.HasSuffix(ops, want) {
		t.Fatalf("a statement: %s", ops)
	}
	mustSign(t, w, trailC, 1)
	ops = strings.Join(tw.trace.last(), " | ")
	if want := " | write registrations | sync registrations | write log | sync log | write marks | sync marks | publish statement"; !strings.HasSuffix(ops, want) {
		t.Fatalf("a first submission: %s", ops)
	}
	w.close()
	tw.open(t).close()
	ops = strings.Join(tw.trace.last(), " | ")
	if want := "hold  | lock log | lock registrations | lock marks | read log | read registrations | read marks | sync log | sync registrations | sync marks | syncdir log-dir | syncdir marks-dir | start "; !strings.HasSuffix(ops, want) {
		t.Fatalf("a start on files there: %s", ops)
	}
}

// The seam's operations reach the system: each, given a file or a
// directory already closed, fails rather than answering for an operation it
// did not make. A sync that did nothing would pass every other test here.
func TestWitnessIOReachesTheSystem(t *testing.T) {
	dir := tempDirAt(t, 0o700)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	file, err := root.OpenFile("f", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	self, err := openWitnessDir(root)
	if err != nil {
		t.Fatal(err)
	}
	x := osWitnessIO()
	if err := x.sync("log", file); err != nil {
		t.Fatalf("a sync of an open file: %v", err)
	}
	if err := x.syncDir("log-dir", self); err != nil {
		t.Fatalf("a sync of an open directory: %v", err)
	}
	if err := x.lock("log", file); err != nil {
		t.Fatalf("a lock of an open file: %v", err)
	}
	file.Close()
	self.Close()
	root.Close()
	if err := x.sync("log", file); err == nil {
		t.Error("a sync of a closed file answered as done")
	}
	if _, err := x.write("log", file, []byte("x")); err == nil {
		t.Error("a write to a closed file answered as done")
	}
	if err := x.truncate("log", file, 0); err == nil {
		t.Error("a cut of a closed file answered as done")
	}
	if err := x.syncDir("log-dir", self); err == nil {
		t.Error("a sync of a closed directory answered as done")
	}
	if err := x.lock("log", file); err == nil {
		t.Error("a lock of a closed file answered as taken")
	}
	if made, err := x.create("log", root, "g"); err == nil {
		made.Close()
		t.Error("a file made in a closed directory")
	}
}

// failingAt is the operating system's operations with the nth of them --
// a write, a sync, a cut, a file made or a directory synced -- failing,
// leaving its file as it was.
func failingAt(n int) (witnessIO, *int) {
	count := new(int)
	base := osWitnessIO()
	out := base
	fail := func() bool { *count++; return *count == n }
	out.write = func(file string, f *os.File, data []byte) (int, error) {
		if fail() {
			return 0, errors.New("the write failed")
		}
		return base.write(file, f, data)
	}
	out.sync = func(file string, f *os.File) error {
		if fail() {
			return errors.New("the sync failed")
		}
		return base.sync(file, f)
	}
	out.truncate = func(file string, f *os.File, size int64) error {
		if fail() {
			return errors.New("the cut failed")
		}
		return base.truncate(file, f, size)
	}
	out.create = func(file string, dir *os.Root, name string) (*os.File, error) {
		if fail() {
			return nil, errors.New("the file could not be made")
		}
		return base.create(file, dir, name)
	}
	out.syncDir = func(dir string, d *os.File) error {
		if fail() {
			return errors.New("the directory sync failed")
		}
		return base.syncDir(dir, d)
	}
	return out, count
}

// A repair of each kind failing at each of its operations, in turn: it
// answers with the failure, the marked statements stay, the bytes it was to
// set aside are never cut before they are kept, and a repair run again
// finishes the work, after which the witness starts. Every run is held to
// the trace's order.
func TestWitnessRepairFailsAtEveryStep(t *testing.T) {
	kinds := []struct {
		name string
		want string
		make func(t *testing.T, tw *testWitness)
	}{
		{"a mark completed", outcomeMarkCompleted, func(t *testing.T, tw *testWitness) {
			tw.write(t, "marks", strings.SplitAfter(tw.read(t, "marks"), "\n")[0])
		}},
		{"a newline and a mark completed", outcomeNewlineAndMark, func(t *testing.T, tw *testWitness) {
			tw.write(t, "marks", strings.SplitAfter(tw.read(t, "marks"), "\n")[0])
			tw.write(t, "log", strings.TrimSuffix(tw.read(t, "log"), "\n"))
		}},
		{"torn bytes set aside", outcomeSetAside, func(t *testing.T, tw *testWitness) {
			tw.write(t, "log", tw.read(t, "log")+`{"checkpoint":`)
		}},
		{"a registration's bytes set aside", outcomeRegistrationSetAside, func(t *testing.T, tw *testWitness) {
			tw.write(t, "registrations", tw.read(t, "registrations")+`{"issuer":`)
		}},
	}
	for _, kind := range kinds {
		// how many operations a clean repair of this kind makes
		steps := 0
		{
			tw := newTestWitness(t, testTrail)
			w := tw.open(t)
			mustSign(t, w, testTrail, 1)
			mustSign(t, w, testTrail, 2)
			w.close()
			kind.make(t, tw)
			counting, count := failingAt(-1)
			if j, err := tw.repair(counting); err != nil || j.outcome != kind.want {
				t.Fatalf("%s: a clean repair: %v", kind.name, err)
			}
			steps = *count
		}
		for n := 1; n <= steps; n++ {
			t.Run(fmt.Sprintf("%s/operation %d of %d", kind.name, n, steps), func(t *testing.T) {
				tw := newTestWitness(t, testTrail)
				w := tw.open(t)
				mustSign(t, w, testTrail, 1)
				mustSign(t, w, testTrail, 2)
				w.close()
				kind.make(t, tw)
				marks, log := tw.read(t, "marks"), tw.read(t, "log")
				failing, _ := failingAt(n)
				if _, err := tw.repair(failing); err == nil {
					t.Fatal("the repair did not answer with its failure")
				}
				if !strings.HasPrefix(tw.read(t, "marks"), marks) {
					t.Fatal("a mark was lost")
				}
				if kind.want == outcomeSetAside && tw.read(t, "log") != log && tw.read(t, "setAside") == "<absent>" {
					t.Fatal("the log was cut and its bytes are kept nowhere")
				}
				if _, err := tw.repair(osWitnessIO()); err != nil {
					t.Fatalf("the repair run again: %v", err)
				}
				tw.open(t).close()
			})
		}
	}
}

// A registration, by a first submission or by the operator, with the
// witness running or stopped, failing at its write or its sync, leaving
// every state that step can: the running witness then signs nothing for any
// trail, and the checks at the next start give what ADR-0013's rules say.
// The order of every run is held to the trace.
func TestWitnessRegistrationFailsAtEveryStep(t *testing.T) {
	for _, mode := range []string{"first-submission", "operator", "offline"} {
		for _, step := range []string{"register", "register-sync"} {
			leaves := []string{"nothing", "torn", "unterminated", "whole"}
			if step == "register-sync" {
				leaves = []string{"nothing", "whole"}
			}
			for _, left := range leaves {
				t.Run(mode+"/"+step+"/"+left, func(t *testing.T) {
					tw := newTestWitness(t, testTrail, trailB)
					tw.first = mode == "first-submission"
					w := tw.open(t)
					mustSign(t, w, testTrail, 1)
					faulty, fired := faultyWitnessIO(osWitnessIO(), step, left)
					r := witnessRegistration{trail: trailC, issuer: witnessIssuer, subject: subjectOf(trailC)}
					var err error
					switch mode {
					case "first-submission":
						w.io = tw.io(faulty)
						_, err = w.submit(witnessIssuer, subjectOf(trailC), [][]byte{cpLine(trailC, 1, "a")})
					case "operator":
						w.io = tw.io(faulty)
						err = w.register(r)
					case "offline":
						w.close()
						err = registerWitnessTrail(tw.paths, r, tw.io(faulty))
					}
					if !*fired || err == nil {
						t.Fatalf("the fault fired %v; the registration answered %v", *fired, err)
					}
					if mode != "offline" {
						if _, err := w.submit(witnessIssuer, subjectOf(trailB), [][]byte{cpLine(trailB, 1, "a")}); !errors.Is(err, errWitnessStopped) {
							t.Fatalf("another trail after the failure: %v", err)
						}
						w.close()
					}
					if outcome, findings := tw.judge(t); outcome != crashOutcome(step, left) {
						t.Fatalf("the checks give %s %v, the rules %s", outcome, findings, crashOutcome(step, left))
					}
				})
			}
		}
	}
}

// Every line the witness writes is one its own start reads back: each kind
// is held, before it is written, to its reader's function and to the
// 4096-byte bound that reader takes. A registration at the bound is kept,
// by the operator with the witness stopped or running, and read back; one
// byte past it is refused, writes nothing and stops nothing. Set-aside
// bytes of any length are kept in records within the bound. The largest
// statement and the largest mark the format allows fit well within it, and
// a line one past it of any kind is refused.
func TestWitnessWritesOnlyLinesItsReaderReads(t *testing.T) {
	registrationOf := func(length int) witnessRegistration {
		r := witnessRegistration{trail: trailC, issuer: witnessIssuer, subject: "s"}
		pad := length - (len(registrationLine(r)) - 1)
		r.subject = strings.Repeat("s", 1+pad)
		return r
	}
	for _, length := range []int{witnessLineLimit, witnessLineLimit + 1} {
		r := registrationOf(length)
		if got := len(registrationLine(r)) - 1; got != length {
			t.Fatalf("a registration line of %d bytes, not %d", got, length)
		}
		for _, running := range []bool{false, true} {
			tw := newTestWitness(t, testTrail)
			before := tw.read(t, "registrations")
			var err error
			if running {
				w := tw.open(t)
				err = w.register(r)
				if w.stopped != nil {
					t.Fatalf("a registration of %d bytes stopped the witness", length)
				}
				w.close()
			} else {
				err = registerWitnessTrail(tw.paths, r, tw.io(osWitnessIO()))
			}
			switch {
			case length <= witnessLineLimit && err != nil:
				t.Fatalf("a registration line at the bound, running %v: %v", running, err)
			case length > witnessLineLimit && (err == nil || !strings.Contains(err.Error(), "longer than")):
				t.Fatalf("a registration line one past the bound, running %v: %v", running, err)
			case length > witnessLineLimit && tw.read(t, "registrations") != before:
				t.Fatal("a registration refused was written")
			}
			if outcome, findings := tw.judge(t); outcome != outcomeStart {
				t.Fatalf("after a registration line of %d bytes the checks give %s %v", length, outcome, findings)
			}
		}
	}

	tw := newTestWitness(t, testTrail)
	w := tw.open(t)
	mustSign(t, w, testTrail, 1)
	w.close()
	tail := strings.Repeat("x", 5000)
	tw.write(t, "log", tw.read(t, "log")+tail)
	if j, err := tw.repair(osWitnessIO()); err != nil || j.outcome != outcomeSetAside {
		t.Fatalf("repair: %v", err)
	}
	var kept []byte
	records := strings.Split(strings.TrimSuffix(tw.read(t, "setAside"), "\n"), "\n")
	for _, record := range records {
		part, ok := parseSetAside([]byte(record))
		if !ok || len(record) > witnessLineLimit {
			t.Fatalf("a set-aside record of %d bytes its reader does not read", len(record))
		}
		kept = append(kept, part.bytes...)
	}
	if len(records) != 5 || string(kept) != tail {
		t.Fatalf("%d records keeping %d bytes; want 5 keeping %d", len(records), len(kept), len(tail))
	}

	// a set-aside record at the bound and one past it
	for _, digits := range []int64{0, 10, 100} {
		at := setAsideLine("2026-10-05T12:00:00Z", nil, "log", digits)
		over := len(at) - 1
		if (witnessLineLimit-over)%2 != 0 {
			continue
		}
		atBound := setAsideLine("2026-10-05T12:00:00Z", []byte(strings.Repeat("y", (witnessLineLimit-over)/2)), "log", digits)
		if err := admitWitnessLine("set-aside", atBound[:len(atBound)-1]); err != nil || len(atBound)-1 != witnessLineLimit {
			t.Fatalf("a set-aside record of %d bytes: %v", len(atBound)-1, err)
		}
		past := setAsideLine("2026-10-05T12:00:00Z", []byte(strings.Repeat("y", (witnessLineLimit-over)/2)), "log", max(10, digits*10))
		if err := admitWitnessLine("set-aside", past[:len(past)-1]); err == nil || len(past)-1 <= witnessLineLimit {
			t.Fatalf("a set-aside record of %d bytes was admitted", len(past)-1)
		}
		break
	}

	// the largest statement and mark, and one past the bound of each kind
	s := newWitnessSigner(t)
	largest, _ := s.line(stmt{kind: "conflict", sequence: maxWitnessInteger, index: maxWitnessInteger, prev: strings.Repeat("f", 128)})
	st, ok := parseWitnessStatement([]byte(largest))
	if !ok || admitWitnessLine("statement", []byte(largest)) != nil || admitWitnessLine("mark", markLine(st)[:len(markLine(st))-1]) != nil {
		t.Fatal("the largest statement or mark is not admitted")
	}
	if len(largest) > witnessLineLimit/4 {
		t.Fatalf("the largest statement is %d bytes, near the bound", len(largest))
	}
	for _, kind := range []string{"statement", "mark", "registration", "set-aside"} {
		if err := admitWitnessLine(kind, bytes.Repeat([]byte(" "), witnessLineLimit+1)); err == nil || !strings.Contains(err.Error(), "longer than") {
			t.Errorf("a %s line one past the bound: %v", kind, err)
		}
	}
}

// setAsideRecords reads the set-aside file as its reader reads it: how many
// lines it holds, and the records among them.
func setAsideRecords(t *testing.T, tw *testWitness) (int, []setAsideRecord) {
	t.Helper()
	text := tw.read(t, "setAside")
	if text == "<absent>" {
		return 0, nil
	}
	if !strings.HasSuffix(text, "\n") {
		t.Fatal("the set-aside file does not end cleanly")
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	var records []setAsideRecord
	for _, line := range lines {
		if r, ok := parseSetAside([]byte(line)); ok {
			records = append(records, r)
		}
	}
	return len(lines), records
}

// A repair interrupted while it appended a set-aside record -- having
// written nothing of it, half of it, or all of it but its newline -- is
// repaired again: the retry settles the set-aside file's own last bytes
// before it appends (ended where they stand, and, unless they are a whole
// record, kept in a record of their own), appends its records, reads them
// back, and only then cuts the log. Afterwards every line of the set-aside
// file is a record its reader reads but the torn half, which stays where it
// was and is kept by one; the log's last bytes are kept in records read
// back in order; and the witness starts. For last bytes of one part and of several, the
// interruption in the last record.
func TestWitnessSetAsideSettlesItsOwnTailFirst(t *testing.T) {
	for _, tail := range []string{`{"checkpoint":`, strings.Repeat("x", 2*setAsideChunk+100)} {
		for _, leaves := range []string{"nothing", "half", "unterminated"} {
			name := fmt.Sprintf("%d parts/%s", (len(tail)+setAsideChunk-1)/setAsideChunk, leaves)
			t.Run(name, func(t *testing.T) {
				tw := newTestWitness(t, testTrail)
				w := tw.open(t)
				mustSign(t, w, testTrail, 1)
				w.close()
				clean := tw.read(t, "log")
				tw.write(t, "log", clean+tail)
				parts := (len(tail) + setAsideChunk - 1) / setAsideChunk
				x := osWitnessIO()
				base := x.write
				written := 0
				x.write = func(file string, f *os.File, data []byte) (int, error) {
					if file != "set-aside" {
						return base(file, f, data)
					}
					written++
					if written < parts {
						return base(file, f, data)
					}
					n := map[string]int{"nothing": 0, "half": len(data) / 2, "unterminated": len(data) - 1}[leaves]
					m, _ := base(file, f, data[:n])
					return m, errors.New("the process ended in the append")
				}
				if _, err := tw.repair(x); err == nil {
					t.Fatal("the interrupted repair did not answer with its failure")
				}
				if tw.read(t, "log") != clean+tail {
					t.Fatal("the log was cut although its bytes were not kept")
				}
				interrupted := tw.read(t, "setAside")
				if j, err := tw.repair(osWitnessIO()); err != nil || j.outcome != outcomeSetAside {
					t.Fatalf("the repair run again: %v", err)
				}
				if tw.read(t, "log") != clean {
					t.Fatal("the log was not ended at its last newline")
				}
				// every line is a record its reader reads, but for the torn
				// half record, ended where it stood and kept by one
				lines, records := setAsideRecords(t, tw)
				if torn := map[string]int{"half": 1}[leaves]; lines != len(records)+torn {
					t.Fatalf("%d lines in the set-aside file, %d of them records", lines, len(records))
				}
				var log, own []byte
				for _, r := range records {
					switch r.file {
					case "log":
						log = append(log, r.bytes...)
					case "set-aside":
						own = append(own, r.bytes...)
					}
				}
				// the earlier, interrupted records keep a prefix of the log's
				// last bytes, perhaps whole; the retry's keep them all
				if !strings.HasSuffix(string(log), tail) {
					t.Fatalf("the records keep %d bytes of the log, not ending in its %d last bytes", len(log), len(tail))
				}
				switch leaves {
				case "half":
					torn := interrupted[strings.LastIndexByte("\n"+interrupted, '\n'):]
					if string(own) != torn {
						t.Fatalf("the interrupted half record is kept as %d bytes, not %d", len(own), len(torn))
					}
				default:
					if len(own) != 0 {
						t.Fatalf("%d bytes kept as the set-aside file's own, with nothing torn", len(own))
					}
				}
				tw.open(t).close()
			})
		}
	}
}

// The records a repair appends to the set-aside file are read back before
// the file they keep is cut: a record written otherwise than it was meant
// while the write reports success -- keeping other bytes, not reading as a
// record at all, lost, or given twice -- refuses the cut, and the log keeps
// its last bytes, here of three parts.
func TestWitnessSetAsideIsReadBackBeforeTheCut(t *testing.T) {
	last := strings.Repeat("y", 2*setAsideChunk+10)
	for what, spoil := range map[string]func([]byte) []byte{
		"other bytes kept": func(data []byte) []byte {
			return bytes.Replace(data, []byte(`"bytes":"79`), []byte(`"bytes":"7a`), 1)
		},
		"no record": func(data []byte) []byte { return append([]byte("not a record "), data...) },
		"a record lost": func(data []byte) []byte {
			if bytes.Contains(data, []byte(hex.EncodeToString([]byte(last[2*setAsideChunk:])))) {
				return nil
			}
			return data
		},
		"a record given twice": func(data []byte) []byte {
			if bytes.Contains(data, []byte(hex.EncodeToString([]byte(last[2*setAsideChunk:])))) {
				return append(append([]byte(nil), data...), data...)
			}
			return data
		},
	} {
		t.Run(what, func(t *testing.T) {
			tw := newTestWitness(t, testTrail)
			w := tw.open(t)
			mustSign(t, w, testTrail, 1)
			w.close()
			torn := tw.read(t, "log") + last
			tw.write(t, "log", torn)
			x := osWitnessIO()
			base := x.write
			x.write = func(file string, f *os.File, data []byte) (int, error) {
				if file == "set-aside" && len(data) > 1 {
					spoiled := spoil(data)
					if _, err := base(file, f, spoiled); err != nil {
						return 0, err
					}
					return len(data), nil
				}
				return base(file, f, data)
			}
			if _, err := tw.repair(x); err == nil || !strings.Contains(err.Error(), "nothing is cut") {
				t.Fatalf("the repair: %v", err)
			}
			if tw.read(t, "log") != torn {
				t.Fatal("the log was cut although its records did not read back")
			}
		})
	}
}

// The read-back holds the set-aside file's own kept bytes to the same rule:
// last bytes an interrupted repair left there, whose keeping record is lost
// while the write reports success, refuse the cut.
func TestWitnessSetAsideOwnBytesAreReadBack(t *testing.T) {
	tw := newTestWitness(t, testTrail)
	w := tw.open(t)
	mustSign(t, w, testTrail, 1)
	w.close()
	torn := tw.read(t, "log") + `{"checkpoint":`
	tw.write(t, "log", torn)
	if err := os.WriteFile(tw.paths.log+setAsideSuffix, []byte(`{"at":"2026-10-05T11:00:00Z","by`), 0o600); err != nil {
		t.Fatal(err)
	}
	x := osWitnessIO()
	base := x.write
	x.write = func(file string, f *os.File, data []byte) (int, error) {
		if file == "set-aside" && bytes.Contains(data, []byte(`"file":"set-aside"`)) {
			return len(data), nil
		}
		return base(file, f, data)
	}
	if _, err := tw.repair(x); err == nil || !strings.Contains(err.Error(), "nothing is cut") {
		t.Fatalf("the repair: %v", err)
	}
	if tw.read(t, "log") != torn {
		t.Fatal("the log was cut although the set-aside file's own bytes were not kept")
	}
}

// A record of the set-aside file's own that no longer keeps the bytes at
// its offset keeps nothing for the read-back either: when the record the
// repair writes in its place is lost while the write reports success, the
// cut is refused.
func TestWitnessSetAsideDamagedRecordKeepsNothing(t *testing.T) {
	tw := newTestWitness(t, testTrail)
	w := tw.open(t)
	mustSign(t, w, testTrail, 1)
	w.close()
	clean := tw.read(t, "log")
	tw.write(t, "log", clean+`{"checkpoint":`)
	if _, err := tw.repair(interruptions("half")); err == nil {
		t.Fatal("the interrupted repair answered no failure")
	}
	if _, err := tw.repair(interruptions("", "", "fail")); err == nil {
		t.Fatal("the second interrupted repair answered no failure")
	}
	text := tw.read(t, "setAside")
	i := strings.Index(text, `"file":"set-aside"`)
	if i < 0 {
		t.Fatal("no record of the set-aside file's own was written")
	}
	j := strings.LastIndex(text[:i], `"bytes":"`) + len(`"bytes":"`)
	if j < len(`"bytes":"`) {
		t.Fatal("no record of the set-aside file's own")
	}
	digit := byte('7')
	if text[j] == '7' {
		digit = '6'
	}
	tw.write(t, "setAside", text[:j]+string(digit)+text[j+1:])
	torn := tw.read(t, "log")
	x := osWitnessIO()
	base := x.write
	x.write = func(file string, f *os.File, data []byte) (int, error) {
		if file == "set-aside" && bytes.Contains(data, []byte(`"file":"set-aside"`)) {
			return len(data), nil
		}
		return base(file, f, data)
	}
	if _, err := tw.repair(x); err == nil || !strings.Contains(err.Error(), "nothing is cut") {
		t.Fatalf("the repair: %v", err)
	}
	if tw.read(t, "log") != torn {
		t.Fatal("the log was cut although a line of the set-aside file is kept by nothing")
	}
}

// Every append the witness makes settles its own file's last bytes first,
// or refuses: a statement's line and its mark, and a registration, by a
// running witness, are refused when the log, the marks or the registrations
// gained last bytes behind its back, and nothing is joined to them; an
// offline registration refuses registrations that do not end cleanly; a
// repair completing a mark refuses marks that gained last bytes after they
// were judged; and the set-aside file's are settled
// (TestWitnessSetAsideSettlesItsOwnTailFirst). A running witness that finds
// one stops, as after any failure.
func TestWitnessEveryAppendSettlesItsTailFirst(t *testing.T) {
	for _, c := range []struct {
		file, step string
		do         func(w *witnessLog) error
	}{
		{"log", "append", func(w *witnessLog) error {
			_, err := w.submit(witnessIssuer, subjectOf(testTrail), [][]byte{cpLine(testTrail, 2, "a")})
			return err
		}},
		{"marks", "mark", func(w *witnessLog) error {
			_, err := w.submit(witnessIssuer, subjectOf(testTrail), [][]byte{cpLine(testTrail, 2, "a")})
			return err
		}},
		{"registrations", "register", func(w *witnessLog) error {
			return w.register(witnessRegistration{trail: trailC, issuer: witnessIssuer, subject: "c"})
		}},
	} {
		t.Run("running/"+c.file, func(t *testing.T) {
			tw := newTestWitness(t, testTrail)
			w := tw.open(t)
			defer w.close()
			mustSign(t, w, testTrail, 1)
			tw.write(t, c.file, tw.read(t, c.file)+`{"torn`)
			before := map[string]string{}
			for _, name := range []string{"log", "marks", "registrations"} {
				before[name] = tw.read(t, name)
			}
			var failure witnessFailure
			if err := c.do(w); !errors.As(err, &failure) || failure.step != c.step || !strings.Contains(err.Error(), "does not end cleanly") {
				t.Fatalf("an append after last bytes in the %s: %v", c.file, err)
			}
			for name, text := range before {
				if tw.read(t, name) != text {
					t.Fatalf("the %s was written", name)
				}
			}
			if _, err := w.submit(witnessIssuer, subjectOf(testTrail), [][]byte{cpLine(testTrail, 3, "a")}); !errors.Is(err, errWitnessStopped) {
				t.Fatalf("after it: %v", err)
			}
		})
	}
	t.Run("offline/registrations", func(t *testing.T) {
		tw := newTestWitness(t, testTrail)
		tw.write(t, "registrations", tw.read(t, "registrations")+`{"torn`)
		before := tw.read(t, "registrations")
		if err := registerWitnessTrail(tw.paths, witnessRegistration{trail: trailB, issuer: witnessIssuer, subject: "b"}, tw.io(osWitnessIO())); err == nil {
			t.Fatal("an offline registration after last bytes")
		}
		if tw.read(t, "registrations") != before {
			t.Fatal("the registrations were written")
		}
	})
	t.Run("repair/marks", func(t *testing.T) {
		tw := newTestWitness(t, testTrail)
		w := tw.open(t)
		mustSign(t, w, testTrail, 1)
		mustSign(t, w, testTrail, 2)
		w.close()
		tw.write(t, "marks", strings.SplitAfter(tw.read(t, "marks"), "\n")[0])
		tw.write(t, "log", strings.TrimSuffix(tw.read(t, "log"), "\n"))
		// last bytes come to the marks after they were judged, while the
		// newline is synced
		x := osWitnessIO()
		base := x.sync
		x.sync = func(file string, f *os.File) error {
			err := base(file, f)
			if file == "log" && strings.HasSuffix(tw.read(t, "log"), "\n") && !strings.HasSuffix(tw.read(t, "marks"), `{"torn`) {
				tw.write(t, "marks", tw.read(t, "marks")+`{"torn`)
			}
			return err
		}
		if _, err := tw.repair(x); err == nil || !strings.Contains(err.Error(), "does not end cleanly") {
			t.Fatalf("a mark completed after last bytes in the marks: %v", err)
		}
		if !strings.HasSuffix(tw.read(t, "marks"), `{"torn`) {
			t.Fatal("a mark was joined to the marks' last bytes")
		}
	})
}

// A file whose length changes while the start-up checks read it -- bytes
// appended by something that ignores the locks, after its size was taken
// -- refuses the start and the repair: what was judged is not the file
// there now. Only the length is compared: other bytes of the same length,
// written by something that ignores the locks, are not found, and the
// locks are what keep every other writer of this program out.
func TestWitnessRefusesAFileWhoseLengthChangesWhileItIsRead(t *testing.T) {
	for _, what := range []string{"open", "repair"} {
		for _, file := range []string{"log", "marks", "registrations"} {
			t.Run(what+"/"+file, func(t *testing.T) {
				tw := newTestWitness(t, testTrail)
				w := tw.open(t)
				mustSign(t, w, testTrail, 1)
				w.close()
				if what == "repair" {
					tw.write(t, "registrations", tw.read(t, "registrations")+`{"torn`)
				}
				cfg := tw.config()
				x := osWitnessIO()
				x.note = func(op, label string) {
					if op == "read" && label == file {
						tw.write(t, file, tw.read(t, file)+`{"checkpoint":1}`+"\n")
					}
				}
				cfg.io = tw.io(x)
				var err error
				if what == "open" {
					var w *witnessLog
					if w, err = openWitnessLog(cfg); err == nil {
						w.close()
					}
				} else {
					_, err = repairWitnessLog(cfg)
				}
				if err == nil || !strings.Contains(err.Error(), "length changed while it was read") {
					t.Fatalf("a %s that grew while it was read: %v", file, err)
				}
			})
		}
	}
}

// A file that comes to a name between the look that found none there and
// the making of it is refused, never taken for the file the witness made.
func TestWitnessRefusesAFileThatAppearsAsItIsMade(t *testing.T) {
	for _, file := range []string{"log", "marks"} {
		t.Run(file, func(t *testing.T) {
			tw := newTestWitness(t, testTrail)
			cfg := tw.config()
			x := osWitnessIO()
			base := x.create
			x.create = func(label string, dir *os.Root, name string) (*os.File, error) {
				if label == file {
					tw.write(t, file, "")
				}
				return base(label, dir, name)
			}
			cfg.io = tw.io(x)
			w, err := openWitnessLog(cfg)
			if err == nil {
				w.close()
			}
			if err == nil || !errors.Is(err, fs.ErrExist) && !strings.Contains(err.Error(), "exists") {
				t.Fatalf("a %s that appeared as it was made: %v", file, err)
			}
		})
	}
}

// A write that reports fewer bytes than it was given, with no error, is a
// failure like any other: the writer stops at that step.
func TestWitnessShortWriteIsAFailure(t *testing.T) {
	for _, c := range []struct{ file, step string }{{"log", "append"}, {"marks", "mark"}, {"registrations", "register"}} {
		t.Run(c.file, func(t *testing.T) {
			tw := newTestWitness(t, testTrail)
			tw.first = true
			w := tw.open(t)
			defer w.close()
			x := osWitnessIO()
			base := x.write
			x.write = func(file string, f *os.File, data []byte) (int, error) {
				if file == c.file {
					return base(file, f, data[:len(data)/2])
				}
				return base(file, f, data)
			}
			w.io = tw.io(x)
			_, err := w.submit(witnessIssuer, subjectOf(trailC), [][]byte{cpLine(trailC, 1, "a")})
			var failure witnessFailure
			if !errors.As(err, &failure) || failure.step != c.step || !strings.Contains(err.Error(), "short write") {
				t.Fatalf("a short write to the %s: %v", c.file, err)
			}
		})
	}
}

// interruptions is the operating system's operations with a repair's
// set-aside writes failing as listed, one entry a write in turn: "" passes
// the write, "fail" writes nothing of it, "half" half of it; each failing
// write answers with its failure.
func interruptions(plan ...string) witnessIO {
	x := osWitnessIO()
	base := x.write
	n := 0
	x.write = func(file string, f *os.File, data []byte) (int, error) {
		if file != "set-aside" {
			return base(file, f, data)
		}
		step := ""
		if n < len(plan) {
			step = plan[n]
		}
		n++
		switch step {
		case "fail":
			return 0, errors.New("the process ended before the write")
		case "half":
			m, _ := base(file, f, data[:len(data)/2])
			return m, errors.New("the process ended in the write")
		}
		return base(file, f, data)
	}
	return x
}

// keptLines checks the rule every repair leaves the set-aside file in:
// every line a record its reader reads, or kept whole by records of the
// set-aside file itself that keep its bytes. It gives the number of lines
// that are no record.
func keptLines(t *testing.T, tw *testWitness) int {
	t.Helper()
	text := tw.read(t, "setAside")
	kept := map[int64]string{}
	type line struct {
		at   int64
		text string
	}
	var others []line
	at := int64(0)
	for _, l := range strings.SplitAfter(text, "\n") {
		if l == "" {
			continue
		}
		body := strings.TrimSuffix(l, "\n")
		if r, ok := parseSetAside([]byte(body)); ok {
			if r.file == "set-aside" && int(r.offset)+len(r.bytes) <= len(text) && text[r.offset:int(r.offset)+len(r.bytes)] == string(r.bytes) {
				kept[r.offset] = string(r.bytes)
			}
		} else if body != "" {
			others = append(others, line{at, body})
		}
		at += int64(len(l))
	}
	for _, o := range others {
		var whole strings.Builder
		for p := o.at; p < o.at+int64(len(o.text)); {
			part, ok := kept[p]
			if !ok {
				t.Fatalf("the line at %d of the set-aside file is no record and no record keeps it", o.at)
			}
			whole.WriteString(part)
			p += int64(len(part))
		}
		if whole.String() != o.text {
			t.Fatalf("the line at %d is kept as other bytes", o.at)
		}
	}
	return len(others)
}

// Every repair leaves the set-aside file holding every line as a record, or
// kept by records of its own: a repair interrupted after it ended the last
// bytes an earlier one left and before it wrote the record keeping them --
// the sequence the second review round found -- leaves the next repair the
// same work, and it does it; so with two such lines from two such
// interruptions; and a record of its own that was damaged keeps nothing, so
// its line is kept again. A set-aside file that already holds to the rule is
// not written to but for the records a repair keeps of the log.
func TestWitnessSetAsideKeepsEveryLineOnEveryRepair(t *testing.T) {
	setUpWith := func(t *testing.T, tail string) (*testWitness, string) {
		tw := newTestWitness(t, testTrail)
		w := tw.open(t)
		mustSign(t, w, testTrail, 1)
		w.close()
		clean := tw.read(t, "log")
		tw.write(t, "log", clean+tail)
		return tw, clean
	}
	setUp := func(t *testing.T) (*testWitness, string) { return setUpWith(t, `{"checkpoint":`) }
	finish := func(t *testing.T, tw *testWitness, clean string, others int) {
		t.Helper()
		if j, err := tw.repair(osWitnessIO()); err != nil || j.outcome != outcomeSetAside {
			t.Fatalf("the last repair: %v", err)
		}
		if tw.read(t, "log") != clean {
			t.Fatal("the log was not ended at its last newline")
		}
		if n := keptLines(t, tw); n != others {
			t.Fatalf("%d lines no record, kept by records; want %d", n, others)
		}
		tw.open(t).close()
	}
	t.Run("the newline written, the keeping record not", func(t *testing.T) {
		tw, clean := setUp(t)
		for _, plan := range [][]string{{"half"}, {"", "fail"}} {
			if _, err := tw.repair(interruptions(plan...)); err == nil {
				t.Fatalf("the interrupted repair %v answered no failure", plan)
			}
		}
		if !strings.HasSuffix(tw.read(t, "setAside"), "\n") || strings.Contains(tw.read(t, "setAside"), `"file":"set-aside"`) {
			t.Fatal("the interruptions did not leave a line ended and kept by nothing")
		}
		finish(t, tw, clean, 1)
	})
	t.Run("two such lines from two such interruptions", func(t *testing.T) {
		tw, clean := setUp(t)
		for _, plan := range [][]string{{"half"}, {"", "fail"}, {"half"}, {"", "fail"}} {
			if _, err := tw.repair(interruptions(plan...)); err == nil {
				t.Fatalf("the interrupted repair %v answered no failure", plan)
			}
		}
		finish(t, tw, clean, 2)
	})
	t.Run("a damaged record of its own keeps nothing", func(t *testing.T) {
		tw, clean := setUp(t)
		if _, err := tw.repair(interruptions("half")); err == nil {
			t.Fatal("the interrupted repair answered no failure")
		}
		if _, err := tw.repair(interruptions("", "", "fail")); err == nil {
			t.Fatal("the second interrupted repair answered no failure")
		}
		// the bytes the record of its own keeps, a hexadecimal digit of
		// them changed: still a record, keeping other bytes than the file's
		var damaged []string
		for _, line := range strings.SplitAfter(tw.read(t, "setAside"), "\n") {
			if r, ok := parseSetAside([]byte(strings.TrimSuffix(line, "\n"))); ok && r.file == "set-aside" {
				i := strings.Index(line, `"bytes":"`) + len(`"bytes":"`)
				digit := byte('7')
				if line[i] == '7' {
					digit = '6'
				}
				line = line[:i] + string(digit) + line[i+1:]
				if _, ok := parseSetAside([]byte(strings.TrimSuffix(line, "\n"))); !ok {
					t.Fatal("the damaged record does not read as a record")
				}
			}
			damaged = append(damaged, line)
		}
		damagedText := strings.Join(damaged, "")
		if damagedText == tw.read(t, "setAside") {
			t.Fatal("no record of the set-aside file's own to damage")
		}
		tw.write(t, "setAside", damagedText)
		finish(t, tw, clean, 1)
	})
	t.Run("a long line kept in part", func(t *testing.T) {
		// half a record of a part: a line longer than one part, so it is
		// kept by two records, the second of which is interrupted
		tw, clean := setUpWith(t, strings.Repeat("x", 2*setAsideChunk+100))
		for _, plan := range [][]string{{"", "half"}, {"", "", "fail"}} {
			if _, err := tw.repair(interruptions(plan...)); err == nil {
				t.Fatalf("the interrupted repair %v answered no failure", plan)
			}
		}
		finish(t, tw, clean, 1)
	})
	t.Run("a file already holding to the rule", func(t *testing.T) {
		tw, clean := setUp(t)
		if _, err := tw.repair(interruptions("half")); err == nil {
			t.Fatal("the interrupted repair answered no failure")
		}
		finish(t, tw, clean, 1)
		before := tw.read(t, "setAside")
		tw.write(t, "log", clean+`{"index":`)
		finish(t, tw, clean, 1)
		after := tw.read(t, "setAside")
		if !strings.HasPrefix(after, before) {
			t.Fatal("the set-aside file was written before its end")
		}
		for _, line := range strings.Split(strings.TrimSuffix(after[len(before):], "\n"), "\n") {
			if r, ok := parseSetAside([]byte(line)); !ok || r.file != "log" {
				t.Fatalf("a file holding to the rule was written a line other than a record of the log: %.80s", line)
			}
		}
	})
}
