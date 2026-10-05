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
// test's to move.
type testWitness struct {
	paths  witnessPaths
	signer witnessSigner
	now    *time.Time
	first  bool
}

func newTestWitness(t *testing.T, trails ...string) *testWitness {
	t.Helper()
	tw := &testWitness{paths: newWitnessPaths(t), signer: newWitnessSigner(t), now: new(time.Time)}
	*tw.now = testClock
	for _, trail := range trails {
		tw.register(t, trail)
	}
	return tw
}

func subjectOf(trail string) string { return "deliverer-" + trail[:4] }

func (tw *testWitness) register(t *testing.T, trail string) {
	t.Helper()
	if err := registerWitnessTrail(tw.paths, witnessRegistration{trail: trail, issuer: witnessIssuer, subject: subjectOf(trail)}, osWitnessIO()); err != nil {
		t.Fatal(err)
	}
}

func (tw *testWitness) config() witnessConfig {
	public, sign := witnessSeedSigner(tw.signer.seed)
	return witnessConfig{paths: tw.paths, firstSubmission: tw.first, publicKey: public, sign: sign, clock: func() time.Time { return *tw.now }}
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
	files, err := holdWitnessFiles(tw.paths)
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
	path := map[string]string{"log": tw.paths.log, "marks": tw.paths.marks, "registrations": tw.paths.log + registrationsSuffix}[name]
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
	f.io = witnessIO{
		write: func(file string, fd *os.File, data []byte) (int, error) {
			n, err := inner.write(file, fd, data)
			if *fired {
				after()
			}
			return n, err
		},
		sync: func(file string, fd *os.File) error {
			err := inner.sync(file, fd)
			if *fired {
				after()
			}
			return err
		},
		truncate: inner.truncate,
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
			w.io = f.io
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
				if j, err := repairWitnessLog(tw.config(), osWitnessIO()); err != nil || j.outcome != outcomeNewKey {
					t.Fatalf("repair: %v", err)
				}
				if tw.read(t, "log") != log || tw.read(t, "marks") != marks || tw.read(t, "setAside") != "<absent>" {
					t.Fatal("a repair that may not act wrote")
				}
				return
			}
			if j, err := repairWitnessLog(tw.config(), osWitnessIO()); err != nil || j.outcome != c.want {
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
				w.io = f.io
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
		if _, err := repairWitnessLog(tw.config(), failing); err == nil {
			t.Fatal("the repair did not fail")
		}
		if tw.read(t, "log") != torn {
			t.Fatal("the log was cut before its bytes were kept")
		}
		if j, err := repairWitnessLog(tw.config(), osWitnessIO()); err != nil || j.outcome != outcomeSetAside {
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
		if _, err := repairWitnessLog(tw.config(), failing); err == nil {
			t.Fatal("the repair did not fail")
		}
		if outcome, _ := tw.judge(t); outcome != outcomeMarkCompleted {
			t.Fatalf("after the newline, the checks give %s", outcome)
		}
		if j, err := repairWitnessLog(tw.config(), osWitnessIO()); err != nil || j.outcome != outcomeMarkCompleted {
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
	if err := registerWitnessTrail(tw.paths, witnessRegistration{trail: trailB, issuer: witnessIssuer, subject: "b"}, osWitnessIO()); err == nil {
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
