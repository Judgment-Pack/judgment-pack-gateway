//go:build unix

package main

// The witness's endpoints (witness_serve.go; ADR-0013 §4; SPEC.md §6,
// "Witness endpoints"), each answer and each bound, through the signer's own
// handler with a recorder: no socket is opened here, so the tests run where
// none may be. A few go through http.Server over an in-memory connection, to
// hold what only a server does -- a write that times out, a whole round
// trip -- and one, at the end, over a real listener.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const witnessAudience = "gateway:witness"

// witnessFixture is a witness open behind a signer's handler, a token issuer
// the signer trusts, and the witness's reports.
type witnessFixture struct {
	tw      *testWitness
	log     *witnessLog
	svc     *witnessService
	gateway *gatewayService
	issuer  *testIssuer
	reports *lockedBuffer
}

// lockedBuffer is a buffer written from handlers and read by the test.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// edIssuer is an issuer of one Ed25519 key, enough for these tests and
// quicker to make than newIssuer's three.
func edIssuer(t *testing.T) (*testIssuer, identityConfig) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := parseKeySet([]byte(`{"keys":[{"kty":"OKP","kid":"ed-1","crv":"Ed25519","x":"` + b64(public) + `"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return &testIssuer{edPub: public, edPriv: private}, identityConfig{issuer: witnessIssuer, audience: witnessAudience, keys: keys}
}

// newWitnessFixture is a witness whose trails are registered as given, its
// configuration's member spec, behind a signer's handler.
func newWitnessFixture(t *testing.T, spec witnessSpec, trails ...string) *witnessFixture {
	t.Helper()
	tw := newTestWitness(t, trails...)
	tw.first = spec.firstSubmission
	if spec.trailsPerSubmitter == 0 {
		spec.trailsPerSubmitter = 100
	}
	if spec.submissionsPerMinute == 0 {
		spec.submissionsPerMinute = 6000
	}
	spec.paths = tw.paths
	cfg := tw.config()
	cfg.trailsPerSubmitter = spec.trailsPerSubmitter
	log, err := openWitnessLog(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(log.close)
	issuer, id := edIssuer(t)
	root := t.TempDir()
	gateway, err := newGatewayService(filepath.Join(root, "store"), tw.signer.seed, "gateway:witness", filepath.Join(root, "registry.jsonl"), nil)
	if err != nil {
		t.Fatal(err)
	}
	gateway.identity = &id
	reports := &lockedBuffer{}
	svc := newWitnessService(log, &spec, reports)
	svc.now = func() time.Time { return *tw.now }
	gateway.witness = svc
	return &witnessFixture{tw: tw, log: log, svc: svc, gateway: gateway, issuer: issuer, reports: reports}
}

// token is a token the fixture's issuer signs for a subject, valid for an
// hour from now.
func (f *witnessFixture) token(t *testing.T, subject string) string {
	t.Helper()
	return f.issuer.mint(t, "ed-1", nil, map[string]any{"iss": witnessIssuer, "sub": subject, "aud": witnessAudience, "exp": time.Now().Add(time.Hour).Unix()})
}

// serve answers one request through the signer's handler.
func (f *witnessFixture) serve(r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	f.gateway.handler().ServeHTTP(rec, r)
	return rec
}

// submission is a request to submit a body, under a token, as
// application/jsonl.
func submission(token string, body io.Reader) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/witness/checkpoints", body)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("Content-Type", "application/jsonl")
	return r
}

// submit submits checkpoint lines for a trail, under its registered
// subject's token.
func (f *witnessFixture) submit(t *testing.T, trail string, lines ...[]byte) *httptest.ResponseRecorder {
	t.Helper()
	return f.serve(submission(f.token(t, subjectOf(trail)), bytes.NewReader(jsonl(lines...))))
}

func jsonl(lines ...[]byte) []byte {
	var body []byte
	for _, line := range lines {
		body = append(append(body, line...), '\n')
	}
	return body
}

// refusal is a refusal's body as read.
type refusal struct {
	Error      string   `json:"error"`
	Reason     string   `json:"reason"`
	Statements []string `json:"statements"`
}

// refusedAs holds an answer to a status and a reason, and returns its body.
func refusedAs(t *testing.T, rec *httptest.ResponseRecorder, status int, reason string) refusal {
	t.Helper()
	var body refusal
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("a refusal that is not JSON (status %d): %.200q", rec.Code, rec.Body.String())
	}
	if rec.Code != status || body.Reason != reason || body.Error == "" {
		t.Fatalf("answered %d %q (%.200s), want %d %q", rec.Code, body.Reason, body.Error, status, reason)
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("a refusal of type %q", rec.Header().Get("Content-Type"))
	}
	return body
}

// statementAnswer holds an answer to 200 with one statement line, and
// returns the line.
func statementAnswer(t *testing.T, rec *httptest.ResponseRecorder) []byte {
	t.Helper()
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/jsonl" {
		t.Fatalf("answered %d %q: %.300s", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
	}
	body := rec.Body.Bytes()
	if bytes.Count(body, []byte{'\n'}) != 1 || body[len(body)-1] != '\n' {
		t.Fatalf("not one statement line: %.300q", body)
	}
	return body[:len(body)-1]
}

// statementOf is a statement line read.
func statementOf(t *testing.T, line []byte) *witnessStatement {
	t.Helper()
	st, ok := parseWitnessStatement(line)
	if !ok || st.whole != string(line) {
		t.Fatalf("not a statement in its canonical form: %.300s", line)
	}
	return st
}

// sentinel is a body that fails the test if more than its first bytes are
// read: what a refusal must decide before reading.
type sentinel struct {
	t     *testing.T
	first []byte
	read  atomic.Int64
}

func (s *sentinel) Read(p []byte) (int, error) {
	if len(s.first) > 0 {
		n := copy(p, s.first)
		s.first = s.first[n:]
		s.read.Add(int64(n))
		return n, nil
	}
	s.read.Add(1)
	return 0, errors.New("the body was read past what the answer needed")
}

// --- the answers -------------------------------------------------------------

// Without a witness configured there is no /witness/ endpoint at all; with
// one, there is.
func TestOnlyAWitnessServesWitnessEndpoints(t *testing.T) {
	f := newWitnessFixture(t, witnessSpec{}, testTrail)
	f.gateway.witness = nil
	if rec := f.serve(httptest.NewRequest(http.MethodGet, "/witness/trails/"+testTrail+"/head", nil)); rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "reason") {
		t.Fatalf("a signer that is no witness answered %d %.100s", rec.Code, rec.Body.String())
	}
	f.gateway.witness = f.svc
	refusedAs(t, f.serve(httptest.NewRequest(http.MethodGet, "/witness/trails/"+testTrail+"/head", nil)), http.StatusNotFound, witnessReasonUnknownTrail)
}

// Every answer a submission can have, as SPEC.md §6 states it: a statement
// signed, the same statement for the same checkpoint again with nothing
// appended, a conflict signed once and given again, a line below the head,
// and a retired trail; only the last line of a submission is signed.
func TestWitnessSubmissionAnswersOverHTTP(t *testing.T) {
	f := newWitnessFixture(t, witnessSpec{}, testTrail)
	logSize := func() int { return len(f.tw.read(t, "log")) }

	// several lines: only the last is signed
	first := statementAnswer(t, f.submit(t, testTrail, cpLine(testTrail, 3, "a"), cpLine(testTrail, 7, "a"), cpLine(testTrail, 10, "a")))
	st := statementOf(t, first)
	if st.kind != "checkpoint" || st.index != 0 || st.checkpoint != string(cpLine(testTrail, 10, "a")) || strings.Count(f.tw.read(t, "log"), "\n") != 1 {
		t.Fatalf("a submission of three lines signed %s at %d over %.80s, the log holding %d lines", st.kind, st.index, st.checkpoint, strings.Count(f.tw.read(t, "log"), "\n"))
	}
	// the same checkpoint again: the same statement, nothing appended
	size := logSize()
	again := statementAnswer(t, f.submit(t, testTrail, cpLine(testTrail, 10, "a")))
	if !bytes.Equal(again, first) || logSize() != size {
		t.Fatalf("an identical resubmission: the same statement %v, the log unchanged %v", bytes.Equal(again, first), logSize() == size)
	}
	second := statementAnswer(t, f.submit(t, testTrail, cpLine(testTrail, 20, "a")))
	if statementOf(t, second).index != 1 {
		t.Fatal("the next checkpoint is not at the next index")
	}
	// a conflict: an earlier line with another digest
	size = logSize()
	conflict := refusedAs(t, f.submit(t, testTrail, cpLine(testTrail, 10, "another"), cpLine(testTrail, 30, "a")), http.StatusConflict, witnessReasonConflict)
	if len(conflict.Statements) != 2 || conflict.Statements[0] != string(first) || statementOf(t, []byte(conflict.Statements[1])).kind != "conflict" || logSize() == size {
		t.Fatalf("a conflict answered %d statements, the log grew %v", len(conflict.Statements), logSize() != size)
	}
	size = logSize()
	once := refusedAs(t, f.submit(t, testTrail, cpLine(testTrail, 10, "a third")), http.StatusConflict, witnessReasonConflict)
	if len(once.Statements) != 2 || once.Statements[1] != conflict.Statements[1] || logSize() != size {
		t.Fatal("a second offer at one sequence is not answered with the first conflict, or appended")
	}
	below := refusedAs(t, f.submit(t, testTrail, cpLine(testTrail, 15, "a")), http.StatusConflict, witnessReasonBelowHead)
	if len(below.Statements) != 1 || below.Statements[0] != conflict.Statements[1] || logSize() != size {
		t.Fatal("a line below the head is not answered with the head, or appended")
	}
	retirement, err := f.log.retire(testTrail)
	if err != nil {
		t.Fatal(err)
	}
	retired := refusedAs(t, f.submit(t, testTrail, cpLine(testTrail, 40, "a")), http.StatusConflict, witnessReasonRetired)
	if len(retired.Statements) != 1 || retired.Statements[0] != string(retirement.statements[0]) {
		t.Fatal("a retired trail is not answered with its retirement")
	}
}

// Every refusal that needs no body is made before a byte of it is read,
// and writes nothing: a method the specification does not name, a query, a
// token absent, from another issuer, for another audience, expired, or
// spelled twice over; a subject the configuration does not allow; another
// media type; a length stated past the bound.
func TestWitnessSubmissionRefusalsBeforeTheBody(t *testing.T) {
	f := newWitnessFixture(t, witnessSpec{submittersGiven: true, submitters: []submitterKey{{witnessIssuer, subjectOf(testTrail)}}}, testTrail)
	good := f.token(t, subjectOf(testTrail))
	claims := func(change func(map[string]any)) string {
		c := map[string]any{"iss": witnessIssuer, "sub": subjectOf(testTrail), "aud": witnessAudience, "exp": time.Now().Add(time.Hour).Unix()}
		change(c)
		return f.issuer.mint(t, "ed-1", nil, c)
	}
	other, _ := edIssuer(t)
	foreign := other.mint(t, "ed-1", nil, map[string]any{"iss": witnessIssuer, "sub": subjectOf(testTrail), "aud": witnessAudience, "exp": time.Now().Add(time.Hour).Unix()})
	for _, c := range []struct {
		name    string
		request func(body io.Reader) *http.Request
		status  int
		reason  string
	}{
		{"GET", func(b io.Reader) *http.Request {
			r := submission(good, b)
			r.Method = http.MethodGet
			return r
		}, http.StatusMethodNotAllowed, witnessReasonMethod},
		{"PUT", func(b io.Reader) *http.Request {
			r := submission(good, b)
			r.Method = http.MethodPut
			return r
		}, http.StatusMethodNotAllowed, witnessReasonMethod},
		{"a query", func(b io.Reader) *http.Request {
			r := submission(good, b)
			r.URL.RawQuery = "trail=" + testTrail
			return r
		}, http.StatusBadRequest, witnessReasonMalformed},
		{"an empty query", func(b io.Reader) *http.Request {
			r := submission(good, b)
			r.URL.ForceQuery = true
			return r
		}, http.StatusBadRequest, witnessReasonMalformed},
		{"no token", func(b io.Reader) *http.Request { return submission("", b) }, http.StatusUnauthorized, witnessReasonToken},
		{"another scheme", func(b io.Reader) *http.Request {
			r := submission("", b)
			r.Header.Set("Authorization", "Basic "+good)
			return r
		}, http.StatusUnauthorized, witnessReasonToken},
		{"a token from another issuer", func(b io.Reader) *http.Request {
			return submission(claims(func(c map[string]any) { c["iss"] = "https://other.example" }), b)
		}, http.StatusUnauthorized, witnessReasonToken},
		{"a token signed by a key not in the file", func(b io.Reader) *http.Request { return submission(foreign, b) }, http.StatusUnauthorized, witnessReasonToken},
		{"a token for another audience", func(b io.Reader) *http.Request {
			return submission(claims(func(c map[string]any) { c["aud"] = "gateway:other" }), b)
		}, http.StatusUnauthorized, witnessReasonToken},
		{"an expired token", func(b io.Reader) *http.Request {
			return submission(claims(func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }), b)
		}, http.StatusUnauthorized, witnessReasonToken},
		{"a subject not allowed", func(b io.Reader) *http.Request {
			return submission(claims(func(c map[string]any) { c["sub"] = "someone-else" }), b)
		}, http.StatusForbidden, witnessReasonNotSubmitter},
		{"another media type", func(b io.Reader) *http.Request {
			r := submission(good, b)
			r.Header.Set("Content-Type", "application/json")
			return r
		}, http.StatusUnsupportedMediaType, witnessReasonMediaType},
		{"no media type", func(b io.Reader) *http.Request {
			r := submission(good, b)
			r.Header.Del("Content-Type")
			return r
		}, http.StatusUnsupportedMediaType, witnessReasonMediaType},
		{"a length past the bound", func(b io.Reader) *http.Request {
			r := submission(good, b)
			r.ContentLength = maxRequestBody + 1
			return r
		}, http.StatusRequestEntityTooLarge, witnessReasonTooLarge},
	} {
		t.Run(c.name, func(t *testing.T) {
			body := &sentinel{t: t}
			rec := f.serve(c.request(body))
			refusedAs(t, rec, c.status, c.reason)
			if body.read.Load() != 0 {
				t.Fatal("the body was read before the refusal")
			}
			if c.status == http.StatusUnauthorized && rec.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatal("a 401 without WWW-Authenticate: Bearer")
			}
			if c.status == http.StatusMethodNotAllowed && rec.Header().Get("Allow") != http.MethodPost {
				t.Fatalf("a 405 allowing %q", rec.Header().Get("Allow"))
			}
			if strings.Contains(rec.Body.String(), good) {
				t.Fatal("a refusal repeats the token")
			}
		})
	}
	if f.tw.read(t, "log") != "" || f.tw.read(t, "registrations") != string(registrationLine(witnessRegistration{trail: testTrail, issuer: witnessIssuer, subject: subjectOf(testTrail)})) {
		t.Fatal("a refused submission wrote")
	}
	// the media type's parameters are not its type
	r := submission(good, bytes.NewReader(jsonl(cpLine(testTrail, 1, "a"))))
	r.Header.Set("Content-Type", "application/jsonl; charset=utf-8")
	statementAnswer(t, f.serve(r))
}

// A body is read through its bound, a line at a time, each line held as it
// arrives: the bound of a submission and of a line at and one past; a body
// with no line, a last line with no newline, an empty line, a line ended by
// CR LF, a line respelled, with a member twice, with a member unknown, of
// another trail, and a sequence not above the line's before; the first line
// that fails ends the read.
func TestWitnessSubmissionBodyBounds(t *testing.T) {
	f := newWitnessFixture(t, witnessSpec{}, testTrail)
	line := string(cpLine(testTrail, 1, "a"))
	for _, c := range []struct {
		name   string
		body   string
		status int
		reason string
	}{
		{"no line", "", http.StatusBadRequest, witnessReasonMalformed},
		{"a last line with no newline", line, http.StatusBadRequest, witnessReasonMalformed},
		{"an empty line", "\n", http.StatusBadRequest, witnessReasonMalformed},
		{"an empty line after one", line + "\n\n", http.StatusBadRequest, witnessReasonMalformed},
		{"CR LF", line + "\r\n", http.StatusBadRequest, witnessReasonMalformed},
		{"respelled", strings.Replace(line, `"sequence":1`, `"sequence": 1`, 1) + "\n", http.StatusBadRequest, witnessReasonMalformed},
		{"a member twice", strings.Replace(line, `"sequence":1`, `"sequence":1,"sequence":1`, 1) + "\n", http.StatusBadRequest, witnessReasonMalformed},
		{"a member unknown", strings.Replace(line, `"trail"`, `"tag":"x","trail"`, 1) + "\n", http.StatusBadRequest, witnessReasonMalformed},
		{"a statement, not a checkpoint", string(jsonl([]byte(`{"checkpoint":` + line + `}`))), http.StatusBadRequest, witnessReasonMalformed},
		{"two trails", string(jsonl(cpLine(testTrail, 1, "a"), cpLine(trailB, 2, "a"))), http.StatusBadRequest, witnessReasonMalformed},
		{"a sequence not above", string(jsonl(cpLine(testTrail, 2, "a"), cpLine(testTrail, 2, "b"))), http.StatusBadRequest, witnessReasonMalformed},
		{"a line at the bound", strings.Repeat("x", witnessLineBound) + "\n", http.StatusBadRequest, witnessReasonMalformed},
		{"a line one past the bound", strings.Repeat("x", witnessLineBound+1) + "\n", http.StatusRequestEntityTooLarge, witnessReasonTooLarge},
		{"a line one past the bound, last", strings.Repeat("x", witnessLineBound+1), http.StatusRequestEntityTooLarge, witnessReasonTooLarge},
	} {
		t.Run(c.name, func(t *testing.T) {
			refusedAs(t, f.serve(submission(f.token(t, subjectOf(testTrail)), strings.NewReader(c.body))), c.status, c.reason)
		})
	}
	// the first line that fails ends the read, whichever check it fails:
	// what follows it is never asked for
	for what, first := range map[string][]byte{
		"not a checkpoint":     []byte("not a checkpoint\n"),
		"of another trail":     jsonl(cpLine(testTrail, 1, "a"), cpLine(trailB, 2, "a")),
		"a sequence not above": jsonl(cpLine(testTrail, 3, "a"), cpLine(testTrail, 2, "a")),
		"respelled":            []byte(strings.Replace(line, `"sequence":1`, `"sequence": 1`, 1) + "\n"),
	} {
		body := &sentinel{t: t, first: first}
		refusedAs(t, f.serve(submission(f.token(t, subjectOf(testTrail)), body)), http.StatusBadRequest, witnessReasonMalformed)
		if body.read.Load() != int64(len(first)) {
			t.Fatalf("%s: the read went on past the line that failed", what)
		}
	}
	// a body of exactly the bound is taken, and one byte more is not; the
	// length is not stated, so the bound on what is read decides
	full := boundBody(t, testTrail, maxRequestBody)
	rec := f.serve(submission(f.token(t, subjectOf(testTrail)), io.MultiReader(bytes.NewReader(full))))
	st := statementOf(t, statementAnswer(t, rec))
	last := full[bytes.LastIndexByte(full[:len(full)-1], '\n')+1 : len(full)-1]
	if st.checkpoint != string(last) {
		t.Fatal("a body at the bound did not sign its last line")
	}
	over := append(boundBody(t, trailB, maxRequestBody), '\n')
	r := submission(f.token(t, subjectOf(trailB)), io.MultiReader(bytes.NewReader(over)))
	r.ContentLength = -1
	refusedAs(t, f.serve(r), http.StatusRequestEntityTooLarge, witnessReasonTooLarge)
	if strings.Count(f.tw.read(t, "log"), "\n") != 1 {
		t.Fatal("a refused body wrote")
	}
}

// boundBody is checkpoint lines of a trail, their sequences increasing, of
// exactly size bytes.
func boundBody(t *testing.T, trail string, size int) []byte {
	t.Helper()
	body := make([]byte, 0, size)
	// the sequences' digits grow with the sequence, so the last lines are
	// chosen to land on the size: lines of a fixed number of digits, from a
	// first sequence of that many digits
	for digits := 4; digits <= 6; digits++ {
		body = body[:0]
		sequence := int64(1)
		for i := 1; i < digits; i++ {
			sequence *= 10
		}
		lineSize := len(cpLine(trail, sequence, "b")) + 1
		count := size / lineSize
		rest := size - count*lineSize
		// rest lines of one more digit, each a byte longer, make up the rest
		if rest > count {
			continue
		}
		for i := 0; i < count-rest; i++ {
			body = append(append(body, cpLine(trail, sequence, "b")...), '\n')
			sequence++
		}
		next := sequence * 10
		for i := 0; i < rest; i++ {
			body = append(append(body, cpLine(trail, next, "b")...), '\n')
			next++
		}
		if len(body) == size {
			return body
		}
	}
	t.Fatalf("no body of %d bytes was made", size)
	return nil
}

// Who may submit for a trail: the subject it is registered to, and no
// other; under "operator", a trail nobody registered is refused; under
// "first-submission", its first submission registers it to its submitter,
// before anything is signed, and another subject is refused after. A
// submitter whose subject no registration can hold registers nothing.
func TestWitnessSubmissionAuthorization(t *testing.T) {
	f := newWitnessFixture(t, witnessSpec{}, testTrail)
	statementAnswer(t, f.submit(t, testTrail, cpLine(testTrail, 1, "a")))
	// a token for another trail: the subject of trail A submitting for B
	refusedAs(t, f.serve(submission(f.token(t, subjectOf(testTrail)), bytes.NewReader(jsonl(cpLine(trailB, 1, "a"))))), http.StatusForbidden, witnessReasonNotRegistered)
	// trail A, by B's subject
	notMine := refusedAs(t, f.serve(submission(f.token(t, subjectOf(trailB)), bytes.NewReader(jsonl(cpLine(testTrail, 2, "a"))))), http.StatusForbidden, witnessReasonNotRegistered)
	unregistered := refusedAs(t, f.submit(t, trailB, cpLine(trailB, 1, "a")), http.StatusForbidden, witnessReasonNotRegistered)
	if notMine.Error != unregistered.Error {
		t.Fatal("a trail registered to another and one registered to nobody are answered apart")
	}

	first := newWitnessFixture(t, witnessSpec{firstSubmission: true})
	statementAnswer(t, first.submit(t, trailC, cpLine(trailC, 1, "a")))
	if got, want := first.tw.read(t, "registrations"), string(registrationLine(witnessRegistration{trail: trailC, issuer: witnessIssuer, subject: subjectOf(trailC)})); got != want {
		t.Fatalf("the first submission's registration: %s", firstDifference(want, got))
	}
	refusedAs(t, first.serve(submission(first.token(t, "a-squatter"), bytes.NewReader(jsonl(cpLine(trailC, 2, "a"))))), http.StatusForbidden, witnessReasonNotRegistered)
	long := strings.Repeat("s", witnessLineLimit)
	refusedAs(t, first.serve(submission(first.token(t, long), bytes.NewReader(jsonl(cpLine(trailB, 1, "a"))))), http.StatusForbidden, witnessReasonNotRegistered)
	if strings.Count(first.tw.read(t, "registrations"), "\n") != 1 || strings.Count(first.tw.read(t, "log"), "\n") != 1 || first.log.stopped != nil {
		t.Fatal("a refused submission registered or signed, or stopped the witness")
	}
}

// A submitter's rate: at most its number of submissions in a minute,
// counted at their arrival whatever becomes of them, the minute's turn
// named in Retry-After; one submitter's count is not another's; the minute
// turning starts every count again; and the submitters one minute counts
// are bounded.
func TestWitnessRateBounds(t *testing.T) {
	f := newWitnessFixture(t, witnessSpec{submissionsPerMinute: 3}, testTrail, trailB)
	*f.tw.now = time.Date(2026, 10, 5, 12, 0, 15, 0, time.UTC)
	for sequence := int64(1); sequence <= 3; sequence++ {
		lines := [][]byte{cpLine(testTrail, sequence, "a")}
		if sequence == 2 {
			lines = [][]byte{[]byte("a line out of shape")}
		}
		f.submit(t, testTrail, lines...)
	}
	body := &sentinel{t: t}
	rec := f.serve(submission(f.token(t, subjectOf(testTrail)), body))
	refusedAs(t, rec, http.StatusTooManyRequests, witnessReasonRate)
	if rec.Header().Get("Retry-After") != "45" || body.read.Load() != 0 {
		t.Fatalf("the fourth submission in a minute: Retry-After %q, the body read %v", rec.Header().Get("Retry-After"), body.read.Load() != 0)
	}
	statementAnswer(t, f.submit(t, trailB, cpLine(trailB, 1, "a")))
	*f.tw.now = time.Date(2026, 10, 5, 12, 1, 0, 0, time.UTC)
	statementAnswer(t, f.submit(t, testTrail, cpLine(testTrail, 4, "a")))

	saved := maxRateSubmitters
	maxRateSubmitters = 2
	t.Cleanup(func() { maxRateSubmitters = saved })
	statementAnswer(t, f.submit(t, trailB, cpLine(trailB, 2, "a")))
	refusedAs(t, f.serve(submission(f.token(t, "a-third-submitter"), strings.NewReader(""))), http.StatusTooManyRequests, witnessReasonRate)
	*f.tw.now = time.Date(2026, 10, 5, 12, 2, 59, 0, time.UTC)
	rec = f.serve(submission(f.token(t, "a-third-submitter"), bytes.NewReader(jsonl(cpLine(trailC, 1, "a")))))
	refusedAs(t, rec, http.StatusForbidden, witnessReasonNotRegistered)
}

// A submitter's trails: a submission for a trail that holds no statement is
// refused when the trails registered to its submitter that hold one are at
// the bound, before it registers anything; a trail it holds already goes
// on; and a trail moved to another submitter is counted as that one's.
func TestWitnessTrailsPerSubmitter(t *testing.T) {
	f := newWitnessFixture(t, witnessSpec{firstSubmission: true, trailsPerSubmitter: 2})
	token := f.token(t, "deliverer")
	post := func(trail string, sequence int64) *httptest.ResponseRecorder {
		return f.serve(submission(token, bytes.NewReader(jsonl(cpLine(trail, sequence, "a")))))
	}
	statementAnswer(t, post(testTrail, 1))
	statementAnswer(t, post(trailB, 1))
	registrations := f.tw.read(t, "registrations")
	refusedAs(t, post(trailC, 1), http.StatusTooManyRequests, witnessReasonTrails)
	if f.tw.read(t, "registrations") != registrations {
		t.Fatal("a submission past the bound registered its trail")
	}
	statementAnswer(t, post(testTrail, 2))
	// another submitter has a count of its own
	statementAnswer(t, f.serve(submission(f.token(t, "another"), bytes.NewReader(jsonl(cpLine(trailC, 1, "a"))))))
	// a trail moved by its operator to another submitter frees a place
	if err := f.log.register(witnessRegistration{trail: trailB, issuer: witnessIssuer, subject: "another"}); err != nil {
		t.Fatal(err)
	}
	fourth := "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	statementAnswer(t, post(fourth, 1))
	refusedAs(t, f.serve(submission(f.token(t, "another"), bytes.NewReader(jsonl(cpLine("ffffffffffffffffffffffffffffffff", 1, "a"))))), http.StatusTooManyRequests, witnessReasonTrails)
	// the counts are the files': a restart counts the same
	f.log.close()
	f.tw.trace.reset()
	cfg := f.tw.config()
	cfg.trailsPerSubmitter = 2
	log, err := openWitnessLog(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer log.close()
	if log.submitterTrails[submitterKey{witnessIssuer, "deliverer"}] != 2 || log.submitterTrails[submitterKey{witnessIssuer, "another"}] != 2 {
		t.Fatalf("after a restart the counts are %d and %d", log.submitterTrails[submitterKey{witnessIssuer, "deliverer"}], log.submitterTrails[submitterKey{witnessIssuer, "another"}])
	}
}

// Submissions in flight are bounded, for the witness and for each
// submitter: with the writer held, the submissions that reach it wait; one
// past a submitter's bound is refused 503 busy, and so is one past the
// witness's, from a submitter with none in flight; the waiting ones are
// answered once the writer is free. Identical submissions in flight at once
// are one statement: the others are answered with the first's.
func TestWitnessSubmissionsInFlight(t *testing.T) {
	savedAll, savedOne := witnessSubmissionsInFlight, witnessSubmitterInFlight
	witnessSubmissionsInFlight, witnessSubmitterInFlight = 4, 2
	t.Cleanup(func() { witnessSubmissionsInFlight, witnessSubmitterInFlight = savedAll, savedOne })
	f := newWitnessFixture(t, witnessSpec{}, testTrail, trailB)
	tokenA, tokenB, tokenC := f.token(t, subjectOf(testTrail)), f.token(t, subjectOf(trailB)), f.token(t, "deliverer-c")
	f.log.writer.Lock()
	answers := make(chan *httptest.ResponseRecorder, 4)
	wait := func(n int) {
		deadline := time.Now().Add(10 * time.Second)
		for len(f.svc.submitting) < n && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
	}
	for i := 0; i < 2; i++ {
		go func() { answers <- f.serve(submission(tokenA, bytes.NewReader(jsonl(cpLine(testTrail, 5, "a"))))) }()
	}
	wait(2)
	ownBound := f.serve(submission(tokenA, bytes.NewReader(jsonl(cpLine(testTrail, 6, "a")))))
	for i := 0; i < 2; i++ {
		go func() { answers <- f.serve(submission(tokenB, bytes.NewReader(jsonl(cpLine(trailB, 5, "a"))))) }()
	}
	wait(4)
	allBound := f.serve(submission(tokenC, bytes.NewReader(jsonl(cpLine(trailC, 1, "a")))))
	f.log.writer.Unlock()
	for _, busy := range []*httptest.ResponseRecorder{ownBound, allBound} {
		refusedAs(t, busy, http.StatusServiceUnavailable, witnessReasonBusy)
		if busy.Header().Get("Retry-After") != "1" {
			t.Fatal("a busy refusal names no Retry-After")
		}
	}
	if !strings.Contains(refusedAs(t, ownBound, http.StatusServiceUnavailable, witnessReasonBusy).Error, "one submitter") {
		t.Fatal("the submitter's own bound is not what refused its third submission")
	}
	byTrail := map[string][][]byte{}
	for i := 0; i < 4; i++ {
		line := statementAnswer(t, <-answers)
		st := statementOf(t, line)
		byTrail[st.trail] = append(byTrail[st.trail], line)
	}
	for trail, lines := range byTrail {
		if len(lines) != 2 || !bytes.Equal(lines[0], lines[1]) {
			t.Fatalf("identical submissions in flight for %s were answered with %d statements, alike %v", trail[:4], len(lines), len(lines) == 2 && bytes.Equal(lines[0], lines[1]))
		}
	}
	if strings.Count(f.tw.read(t, "log"), "\n") != 2 || len(f.svc.submitting) != 0 || len(f.svc.flying) != 0 {
		t.Fatalf("identical submissions in flight signed %d statements; %d places and %d submitters still held", strings.Count(f.tw.read(t, "log"), "\n"), len(f.svc.submitting), len(f.svc.flying))
	}
}

// A failure of the writer on one trail stops signing for all: that
// submission and every one after it is answered 503 -- a statement held
// included -- the operator is told once, and nothing unpublished is read.
func TestWitnessStoppedRefusesEverySubmission(t *testing.T) {
	f := newWitnessFixture(t, witnessSpec{}, testTrail, trailB, trailC)
	held := statementAnswer(t, f.submit(t, trailB, cpLine(trailB, 1, "a")))
	head := statementAnswer(t, f.submit(t, testTrail, cpLine(testTrail, 1, "a")))
	statementAnswer(t, f.submit(t, trailC, cpLine(trailC, 1, "a")))
	if _, err := f.log.retire(trailC); err != nil {
		t.Fatal(err)
	}
	failing, fired := faultyWitnessIO(osWitnessIO(), "mark-sync", "whole")
	f.log.io = f.tw.io(failing)
	refusedAs(t, f.submit(t, testTrail, cpLine(testTrail, 2, "a")), http.StatusServiceUnavailable, witnessReasonStopped)
	if !*fired {
		t.Fatal("the fault did not fire")
	}
	refusedAs(t, f.submit(t, trailB, cpLine(trailB, 2, "a")), http.StatusServiceUnavailable, witnessReasonStopped)
	// not even a statement it holds, nor the head a line falls below
	refusedAs(t, f.submit(t, trailB, cpLine(trailB, 1, "a")), http.StatusServiceUnavailable, witnessReasonStopped)
	refusedAs(t, f.submit(t, testTrail, cpLine(testTrail, 1, "b")), http.StatusServiceUnavailable, witnessReasonStopped)
	// a retired trail too, and its retirement asked for again
	refusedAs(t, f.submit(t, trailC, cpLine(trailC, 2, "a")), http.StatusServiceUnavailable, witnessReasonStopped)
	if _, err := f.log.retire(trailC); !errors.Is(err, errWitnessStopped) {
		t.Fatalf("a retirement asked for again after the failure: %v", err)
	}
	if got := strings.Count(f.reports.String(), "witness: stopped:"); got != 1 || !strings.Contains(f.reports.String(), "mark-sync") {
		t.Fatalf("the operator was told %d times: %.200s", got, f.reports.String())
	}
	// reads serve what was published, and nothing after it
	if got := statementAnswer(t, f.serve(httptest.NewRequest(http.MethodGet, "/witness/trails/"+testTrail+"/head", nil))); !bytes.Equal(got, head) {
		t.Fatal("a read after the failure serves a statement not published")
	}
	if got := statementAnswer(t, f.serve(httptest.NewRequest(http.MethodGet, "/witness/trails/"+trailB+"/head", nil))); !bytes.Equal(got, held) {
		t.Fatal("a read after the failure does not serve what was published")
	}
}

// A statement is answered only once it is published: its line synced, its
// mark appended and synced, and the publication noted -- the order the
// storage's seam records, with the answer written after it.
func TestWitnessAnswersOnlyWhatIsPublished(t *testing.T) {
	f := newWitnessFixture(t, witnessSpec{}, testTrail)
	var mu sync.Mutex
	var ops []string
	note := func(op string) {
		mu.Lock()
		defer mu.Unlock()
		if len(ops) < 64 {
			ops = append(ops, op)
		}
	}
	base := f.log.io
	recorded := base
	recorded.write = func(file string, fd *os.File, data []byte) (int, error) {
		note("write " + file)
		return base.write(file, fd, data)
	}
	recorded.sync = func(file string, fd *os.File) error {
		note("sync " + file)
		return base.sync(file, fd)
	}
	recorded.note = func(op, file string) {
		note(op + " " + file)
		base.note(op, file)
	}
	f.log.io = recorded
	rec := &orderedRecorder{ResponseRecorder: httptest.NewRecorder(), note: note}
	f.gateway.handler().ServeHTTP(rec, submission(f.token(t, subjectOf(testTrail)), bytes.NewReader(jsonl(cpLine(testTrail, 1, "a")))))
	statementAnswer(t, rec.ResponseRecorder)
	want := "write log, sync log, write marks, sync marks, publish statement, answer 200"
	if got := strings.Join(ops, ", "); got != want {
		t.Fatalf("the order was %q, want %q", got, want)
	}
}

// orderedRecorder notes the moment an answer's status is written.
type orderedRecorder struct {
	*httptest.ResponseRecorder
	note func(string)
}

func (o *orderedRecorder) WriteHeader(code int) {
	o.note("answer " + strconv.Itoa(code))
	o.ResponseRecorder.WriteHeader(code)
}

// --- reads ---------------------------------------------------------------------

// The two reads, open to anyone who names a trail: what each serves of a
// trail with statements, a retired one, one registered with none and one
// never named; the path and the query held to one spelling; the method.
func TestWitnessReads(t *testing.T) {
	f := newWitnessFixture(t, witnessSpec{}, testTrail, trailB)
	var signed [][]byte
	for sequence := int64(1); sequence <= 5; sequence++ {
		signed = append(signed, statementAnswer(t, f.submit(t, testTrail, cpLine(testTrail, sequence*10, "a"))))
	}
	get := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "Bearer not-a-token")
		return f.serve(r)
	}
	lines := func(rec *httptest.ResponseRecorder) [][]byte {
		t.Helper()
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/jsonl" || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("answered %d %q: %.200s", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
		}
		body := rec.Body.Bytes()
		if len(body) == 0 {
			return nil
		}
		if body[len(body)-1] != '\n' {
			t.Fatal("a read's last line is not ended by a newline")
		}
		return bytes.Split(body[:len(body)-1], []byte{'\n'})
	}
	join := func(l [][]byte) string { return string(bytes.Join(l, []byte{'\n'})) }
	statements := "/witness/trails/" + testTrail + "/statements"
	if got := lines(get("/witness/trails/" + testTrail + "/head")); len(got) != 1 || !bytes.Equal(got[0], signed[4]) {
		t.Fatal("the head is not the last statement")
	}
	if got := lines(get(statements)); join(got) != join(signed) {
		t.Fatal("the statements read from 0 are not the chain")
	}
	if got := lines(get(statements + "?from=1&limit=2")); join(got) != join(signed[1:3]) {
		t.Fatal("from 1, at most 2")
	}
	if got := lines(get(statements + "?limit=1000&from=4")); join(got) != join(signed[4:]) {
		t.Fatal("limit at its bound, and from given after it")
	}
	if got := lines(get(statements + "?from=5")); got != nil {
		t.Fatal("from past the head serves a statement")
	}
	if got := lines(get(statements + fmt.Sprintf("?from=%d", int64(maxWitnessInteger)))); got != nil {
		t.Fatal("from at the largest index serves a statement")
	}
	// a trail registered and not signed for, and one never named, alike;
	// nothing reveals a registration
	registered := refusedAs(t, get("/witness/trails/"+trailB+"/head"), http.StatusNotFound, witnessReasonUnknownTrail)
	never := refusedAs(t, get("/witness/trails/"+trailC+"/head"), http.StatusNotFound, witnessReasonUnknownTrail)
	if registered.Error != never.Error {
		t.Fatal("a registered trail with no statement reads otherwise than a trail never named")
	}
	refusedAs(t, get("/witness/trails/"+trailB+"/statements"), http.StatusNotFound, witnessReasonUnknownTrail)
	// a retired trail is served as before, its retirement last
	retirement, err := f.log.retire(testTrail)
	if err != nil {
		t.Fatal(err)
	}
	if got := lines(get("/witness/trails/" + testTrail + "/head")); len(got) != 1 || !bytes.Equal(got[0], retirement.statements[0]) {
		t.Fatal("a retired trail's head is not its retirement")
	}
	if got := lines(get(statements)); len(got) != 6 {
		t.Fatalf("a retired trail serves %d statements", len(got))
	}
	for _, c := range []struct {
		path   string
		status int
		reason string
	}{
		{"/witness/trails/" + strings.ToUpper(testTrail) + "/head", http.StatusBadRequest, witnessReasonMalformed},
		{"/witness/trails/" + testTrail[:31] + "/head", http.StatusBadRequest, witnessReasonMalformed},
		{"/witness/trails/" + testTrail + "0/head", http.StatusBadRequest, witnessReasonMalformed},
		{"/witness/trails/%33" + testTrail[1:] + "/head", http.StatusBadRequest, witnessReasonMalformed},
		{"/witness/trails/" + testTrail + "%2Fhead", http.StatusBadRequest, witnessReasonMalformed},
		{"/witness/trails/" + testTrail, http.StatusNotFound, witnessReasonNotFound},
		{"/witness/trails/" + testTrail + "/", http.StatusNotFound, witnessReasonNotFound},
		{"/witness/trails/" + testTrail + "/heads", http.StatusNotFound, witnessReasonNotFound},
		{"/witness/trails/" + testTrail + "/head/x", http.StatusNotFound, witnessReasonNotFound},
		{"/witness/trails/", http.StatusNotFound, witnessReasonNotFound},
		{"/witness/", http.StatusNotFound, witnessReasonNotFound},
		{"/witness/checkpoint", http.StatusNotFound, witnessReasonNotFound},
		{"/witness/trails/" + testTrail + "/head?from=0", http.StatusBadRequest, witnessReasonMalformed},
		{"/witness/trails/" + testTrail + "/head?", http.StatusBadRequest, witnessReasonMalformed},
		{statements + "?", http.StatusBadRequest, witnessReasonMalformed},
		{statements + "?from=", http.StatusBadRequest, witnessReasonMalformed},
		{statements + "?from", http.StatusBadRequest, witnessReasonMalformed},
		{statements + "?from=01", http.StatusBadRequest, witnessReasonMalformed},
		{statements + "?from=-1", http.StatusBadRequest, witnessReasonMalformed},
		{statements + "?from=+1", http.StatusBadRequest, witnessReasonMalformed},
		{statements + "?from=1e3", http.StatusBadRequest, witnessReasonMalformed},
		{statements + "?from=%31", http.StatusBadRequest, witnessReasonMalformed},
		{statements + "?from=1&from=2", http.StatusBadRequest, witnessReasonMalformed},
		{statements + "?from=1&", http.StatusBadRequest, witnessReasonMalformed},
		{statements + "?from=1;limit=2", http.StatusBadRequest, witnessReasonMalformed},
		{statements + "?index=1", http.StatusBadRequest, witnessReasonMalformed},
		{statements + "?limit=0", http.StatusBadRequest, witnessReasonMalformed},
		{statements + "?limit=1001", http.StatusBadRequest, witnessReasonMalformed},
		{statements + fmt.Sprintf("?from=%d", int64(maxWitnessInteger)+1), http.StatusBadRequest, witnessReasonMalformed},
		{statements + "?from=12345678901234567", http.StatusBadRequest, witnessReasonMalformed},
	} {
		t.Run(c.path, func(t *testing.T) {
			refusedAs(t, get(c.path), c.status, c.reason)
		})
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodHead, http.MethodDelete} {
		for _, path := range []string{"/witness/trails/" + testTrail + "/head", statements} {
			rec := f.serve(httptest.NewRequest(method, path, nil))
			if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodGet {
				t.Fatalf("%s %s answered %d, Allow %q", method, path, rec.Code, rec.Header().Get("Allow"))
			}
		}
	}
}

// Reads in flight are bounded: with the statements' index held, the reads
// that reach it wait, the one past the bound is refused 503 busy, and the
// waiting ones are answered once it is free.
func TestWitnessReadsInFlight(t *testing.T) {
	saved := witnessReadsInFlight
	witnessReadsInFlight = 3
	t.Cleanup(func() { witnessReadsInFlight = saved })
	f := newWitnessFixture(t, witnessSpec{}, testTrail)
	statementAnswer(t, f.submit(t, testTrail, cpLine(testTrail, 1, "a")))
	f.log.index.Lock()
	answers := make(chan *httptest.ResponseRecorder, 3)
	for i := 0; i < 3; i++ {
		go func() {
			answers <- f.serve(httptest.NewRequest(http.MethodGet, "/witness/trails/"+testTrail+"/head", nil))
		}()
	}
	deadline := time.Now().Add(10 * time.Second)
	for len(f.svc.reading) < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	busy := f.serve(httptest.NewRequest(http.MethodGet, "/witness/trails/"+testTrail+"/statements", nil))
	f.log.index.Unlock()
	refusedAs(t, busy, http.StatusServiceUnavailable, witnessReasonBusy)
	for i := 0; i < 3; i++ {
		statementAnswer(t, <-answers)
	}
}

// --- over a server ---------------------------------------------------------------

// pipeListener is a listener of in-memory connections: http.Server serves
// on it as on a socket, and nothing is opened.
type pipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error { l.once.Do(func() { close(l.closed) }); return nil }

func (l *pipeListener) Addr() net.Addr { return pipeAddr{} }

// dial is a connection to the listener's server.
func (l *pipeListener) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	server, client := net.Pipe()
	select {
	case l.conns <- server:
		return client, nil
	case <-l.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

// serveOnPipe serves the fixture's signer on an in-memory listener until
// the test ends, and gives a client of it.
func (f *witnessFixture) serveOnPipe(t *testing.T) (*pipeListener, *http.Client) {
	t.Helper()
	listener := newPipeListener()
	ctx, cancel := context.WithCancel(context.Background())
	f.gateway.bindLifetime(ctx)
	done := make(chan error, 1)
	go func() { done <- f.gateway.serveOn(listener) }()
	t.Cleanup(func() {
		cancel()
		listener.Close()
		<-done
	})
	return listener, &http.Client{Transport: &http.Transport{DialContext: listener.dial}, Timeout: 30 * time.Second}
}

// An answer that is not read is not waited on for longer than its bound:
// the read's place is given back, so readers that do not read cannot hold
// every place.
func TestWitnessAnswerTimeIsBounded(t *testing.T) {
	saved := witnessAnswerTime
	witnessAnswerTime = 200 * time.Millisecond
	t.Cleanup(func() { witnessAnswerTime = saved })
	f := newWitnessFixture(t, witnessSpec{}, testTrail)
	statementAnswer(t, f.submit(t, testTrail, cpLine(testTrail, 1, "a")))
	listener, _ := f.serveOnPipe(t)
	conn, err := listener.dial(context.Background(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET /witness/trails/" + testTrail + "/head HTTP/1.1\r\nHost: witness\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	// the request is in, and the answer is never read
	deadline := time.Now().Add(5 * time.Second)
	for len(f.svc.reading) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	for len(f.svc.reading) != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(f.svc.reading) != 0 {
		t.Fatal("an answer nobody reads holds its place past its bound")
	}
	// and the answer was abandoned at its bound, not written afterwards
	// with no bound once its place was given back
	time.Sleep(100 * time.Millisecond)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, err := conn.Read(make([]byte, 64))
	if got != 0 || err == nil {
		t.Fatalf("after its bound the answer was still written: %d bytes read, %v", got, err)
	}
}

// The round trip: statements served over a server, submitted and then read
// back a page at a time to the head, read through the reader a verifier
// uses (witness.go) with no finding -- current, to the head, before and
// after the trail's retirement -- and, when GATEWAY_VERIFY_TS_IMPL names
// the second implementation's command, through it as well.
func TestWitnessServedChainReadsCleanly(t *testing.T) {
	f := newWitnessFixture(t, witnessSpec{}, testTrail, trailB)
	_, client := f.serveOnPipe(t)
	post := func(trail string, lines ...[]byte) *http.Response {
		r, _ := http.NewRequest(http.MethodPost, "http://witness/witness/checkpoints", bytes.NewReader(jsonl(lines...)))
		r.Header.Set("Authorization", "Bearer "+f.token(t, subjectOf(trail)))
		r.Header.Set("Content-Type", "application/jsonl")
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp
	}
	fetch := func(path string) []byte {
		resp, err := client.Get("http://witness" + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: %d %v", path, resp.StatusCode, err)
		}
		return body
	}
	// the chain a reader fetches: pages of two, from the next index, until
	// the head's index is reached
	chain := func(trail string) (statements, head []byte) {
		head = fetch("/witness/trails/" + trail + "/head")
		headIndex := statementOf(t, bytes.TrimSuffix(head, []byte{'\n'})).index
		for from := int64(0); from <= headIndex; from += 2 {
			statements = append(statements, fetch(fmt.Sprintf("/witness/trails/%s/statements?from=%d&limit=2", trail, from))...)
		}
		return statements, head
	}
	for _, step := range []struct {
		trail  string
		lines  [][]byte
		status int
	}{
		{testTrail, [][]byte{cpLine(testTrail, 10, "a")}, 200},
		{trailB, [][]byte{cpLine(trailB, 5, "a")}, 200},
		{testTrail, [][]byte{cpLine(testTrail, 12, "a"), cpLine(testTrail, 20, "a")}, 200},
		{testTrail, [][]byte{cpLine(testTrail, 10, "another")}, 409},
		{testTrail, [][]byte{cpLine(testTrail, 20, "a")}, 200},
		{testTrail, [][]byte{cpLine(testTrail, 15, "a")}, 409},
		{trailB, [][]byte{cpLine(trailB, 9, "a")}, 200},
		{testTrail, [][]byte{cpLine(testTrail, 30, "a")}, 200},
	} {
		if resp := post(step.trail, step.lines...); resp.StatusCode != step.status {
			t.Fatalf("a submission answered %d, want %d", resp.StatusCode, step.status)
		}
	}
	read := func(trail string, wantHighest int64, wantRetired bool) {
		t.Helper()
		statements, head := chain(trail)
		v := readWitness(witnessReading{trail: trail, keys: [][]byte{f.tw.signer.public}, files: [][]byte{statements}, head: head})
		if v.refused != "" || len(v.findings) > 0 || v.reading != "current" || v.highest != wantHighest || v.retired != wantRetired {
			t.Fatalf("trail %s reads: refused %q, findings %v, reading %s, highest %d, retired %v", trail[:4], v.refused, v.findings, v.reading, v.highest, v.retired)
		}
		readInVerifyTS(t, trail, f.tw.signer.public, statements, head, wantHighest, wantRetired)
	}
	read(testTrail, 3, false)
	read(trailB, 1, false)
	if _, err := f.log.retire(testTrail); err != nil {
		t.Fatal(err)
	}
	if resp := post(testTrail, cpLine(testTrail, 40, "a")); resp.StatusCode != http.StatusConflict {
		t.Fatalf("a submission after the retirement answered %d", resp.StatusCode)
	}
	read(testTrail, 4, true)
}

// readInVerifyTS reads a chain through the second implementation, when
// GATEWAY_VERIFY_TS_IMPL names its command (the process contract's
// `witness`, corpus/README.md); CI's verify-ts job names it.
func readInVerifyTS(t *testing.T, trail string, key, statements, head []byte, highest int64, retired bool) {
	t.Helper()
	impl := os.Getenv("GATEWAY_VERIFY_TS_IMPL")
	if impl == "" {
		return
	}
	dir := t.TempDir()
	files := map[string][]byte{"key": []byte(hex.EncodeToString(key) + "\n"), "statements": statements, "head": head}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, impl, "witness", "--trail", trail, "--witness-key", filepath.Join(dir, "key"),
		"--witness", filepath.Join(dir, "statements"), "--witness-head", filepath.Join(dir, "head")).Output()
	if err != nil {
		t.Fatalf("verify-ts: %v", err)
	}
	var answer struct {
		OK       bool     `json:"ok"`
		Findings []string `json:"findings"`
		Reading  string   `json:"reading"`
		Highest  int64    `json:"highestIndex"`
		Retired  bool     `json:"retired"`
	}
	if err := json.Unmarshal(out, &answer); err != nil || !answer.OK || len(answer.Findings) != 0 || answer.Reading != "current" || answer.Highest != highest || answer.Retired != retired {
		t.Fatalf("verify-ts reads trail %s: ok %v, findings %v, reading %s, highest %d, retired %v (%v)", trail[:4], answer.OK, answer.Findings, answer.Reading, answer.Highest, answer.Retired, err)
	}
}

// Over a real listener, once: a submission and a read, as a deliverer and a
// verifier on another host would make them through a front.
func TestWitnessOverARealListener(t *testing.T) {
	f := newWitnessFixture(t, witnessSpec{}, testTrail)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no listener can be opened here: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f.gateway.bindLifetime(ctx)
	done := make(chan error, 1)
	go func() { done <- f.gateway.serveOn(listener) }()
	defer func() {
		cancel()
		<-done
	}()
	base := "http://" + listener.Addr().String()
	r, _ := http.NewRequest(http.MethodPost, base+"/witness/checkpoints", bytes.NewReader(jsonl(cpLine(testTrail, 1, "a"))))
	r.Header.Set("Authorization", "Bearer "+f.token(t, subjectOf(testTrail)))
	r.Header.Set("Content-Type", "application/jsonl")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	signed, _ := io.ReadAll(bufio.NewReader(io.LimitReader(resp.Body, 1<<20)))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the submission answered %d", resp.StatusCode)
	}
	resp, err = client.Get(base + "/witness/trails/" + testTrail + "/head")
	if err != nil {
		t.Fatal(err)
	}
	head, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.Equal(head, signed) {
		t.Fatalf("the head read answered %d, the statement signed %v", resp.StatusCode, bytes.Equal(head, signed))
	}
}
