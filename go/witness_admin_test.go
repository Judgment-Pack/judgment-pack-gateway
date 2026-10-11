//go:build unix

package main

// The witness's operator's two acts on a running witness (witness_admin.go;
// SPEC.md §6, "Administration"; issue #215): a trail registered, its
// registration changed and a trail retired while the witness runs, each
// judged by the next submission; the token boundary, an operator's token
// taken and a submitter's refused; what is kept before an answer, step by
// step and under a crash at each step; the refusals of a witness stopped;
// the place each act takes among the submissions in flight; and the same
// retirement, byte for byte, as the command signs on a stopped witness.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// operatorToken is a token of the fixture's issuer for a subject, naming
// the audience given: the engine's makes it an operator's, unless the
// subject is a listed submitter.
func (f *witnessFixture) operatorToken(t *testing.T, subject string, aud any) string {
	t.Helper()
	return f.issuer.mint(t, "ed-1", nil, map[string]any{"iss": witnessIssuer, "sub": subject, "aud": aud, "exp": time.Now().Add(time.Hour).Unix()})
}

// operator is the fixture's operator's token.
func (f *witnessFixture) operator(t *testing.T) string {
	t.Helper()
	return f.operatorToken(t, "operator-1", witnessEngineAudience)
}

// registrationRequest is a registration, under a token, as application/json.
func registrationRequest(token string, body io.Reader) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/witness/registrations", body)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("Content-Type", "application/json")
	return r
}

// registrationOf is a registration's body.
func registrationOf(trail, issuer, subject string) io.Reader {
	body, _ := json.Marshal(map[string]string{"trail": trail, "issuer": issuer, "subject": subject})
	return bytes.NewReader(body)
}

// retirementRequest is a retirement of a trail, under a token, with no body.
func retirementRequest(token, trail string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/witness/trails/"+trail+"/retirement", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

// registeredAs holds an answer to 200, application/json, its length stated
// and not stored, with exactly the registration's members, and returns it.
func registeredAs(t *testing.T, rec *httptest.ResponseRecorder) (witnessRegistrationAnswer, map[string]json.RawMessage) {
	t.Helper()
	h := rec.Header()
	if rec.Code != http.StatusOK || h.Get("Content-Type") != "application/json" || h.Get("Cache-Control") != "no-store" || h.Get("Content-Length") != strconv.Itoa(rec.Body.Len()) {
		t.Fatalf("answered %d %q, Cache-Control %q, Content-Length %q: %.300s", rec.Code, h.Get("Content-Type"), h.Get("Cache-Control"), h.Get("Content-Length"), rec.Body.String())
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &members); err != nil || len(members) != 4 {
		t.Fatalf("a registration's answer of other members: %.300s", rec.Body.String())
	}
	var answer witnessRegistrationAnswer
	decoder := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&answer); err != nil {
		t.Fatal(err)
	}
	return answer, members
}

// A trail registered on a running witness is judged by the next
// submission: refused before, accepted after; registered again to another
// subject, the answer names the one it had, the first subject is refused and
// the second taken; registered again to the same, nothing is said changed
// and nothing is appended. Each registration is the line the command
// appends, and a restart reads the last.
func TestWitnessRegistersOnARunningWitness(t *testing.T) {
	f := newWitnessFixture(t, witnessSpec{})
	operator := f.operator(t)
	refusedAs(t, f.submit(t, testTrail, cpLine(testTrail, 1, "a")), http.StatusForbidden, witnessReasonNotRegistered)

	rec := f.serve(registrationRequest(operator, registrationOf(testTrail, witnessIssuer, subjectOf(testTrail))))
	registeredAs(t, rec)
	if want := `{"trail":"` + testTrail + `","issuer":"` + witnessIssuer + `","subject":"` + subjectOf(testTrail) + `","changedFrom":null}` + "\n"; rec.Body.String() != want {
		t.Fatalf("the first registration: %s", firstDifference(want, rec.Body.String()))
	}
	first := registrationLine(witnessRegistration{trail: testTrail, issuer: witnessIssuer, subject: subjectOf(testTrail)})
	if got := f.tw.read(t, "registrations"); got != string(first) {
		t.Fatalf("the registration kept: %s", firstDifference(string(first), got))
	}
	statementAnswer(t, f.submit(t, testTrail, cpLine(testTrail, 1, "a")))

	moved, members := registeredAs(t, f.serve(registrationRequest(operator, registrationOf(testTrail, witnessIssuer, "deliverer-new"))))
	if moved.Subject != "deliverer-new" || moved.ChangedFrom == nil || *moved.ChangedFrom != (witnessRegistrant{witnessIssuer, subjectOf(testTrail)}) || string(members["changedFrom"]) != `{"issuer":"`+witnessIssuer+`","subject":"`+subjectOf(testTrail)+`"}` {
		t.Fatalf("a changed registration answered %+v, changedFrom %s", moved, members["changedFrom"])
	}
	refusedAs(t, f.submit(t, testTrail, cpLine(testTrail, 2, "a")), http.StatusForbidden, witnessReasonNotRegistered)
	statementAnswer(t, f.serve(submission(f.token(t, "deliverer-new"), bytes.NewReader(jsonl(cpLine(testTrail, 2, "a"))))))

	second := registrationLine(witnessRegistration{trail: testTrail, issuer: witnessIssuer, subject: "deliverer-new"})
	for i := 0; i < 2; i++ {
		same, _ := registeredAs(t, f.serve(registrationRequest(operator, registrationOf(testTrail, witnessIssuer, "deliverer-new"))))
		if same.ChangedFrom != nil || same.Subject != "deliverer-new" {
			t.Fatalf("the same registration again answered %+v", same)
		}
	}
	// repeated, it appends nothing: neither the file nor the index grows
	if got, want := f.tw.read(t, "registrations"), string(first)+string(second); got != want {
		t.Fatalf("the registrations kept: %s", firstDifference(want, got))
	}
	// a restart reads what was answered
	f.log.close()
	w := f.tw.open(t)
	defer w.close()
	if r := w.registrations[testTrail]; r.subject != "deliverer-new" {
		t.Fatalf("after a restart the trail is registered to %q", r.subject)
	}
}

// A trail retired on a running witness: the answer is the retirement, the
// statement the head then serves, made durable and marked; a submission for
// the trail is refused retired on the next request; a second retirement is
// 409 with the first and signs nothing; a trail with no statement, registered
// or not, is 404; a restart starts on what was written.
func TestWitnessRetiresOnARunningWitness(t *testing.T) {
	f := newWitnessFixture(t, witnessSpec{}, testTrail, trailB)
	operator := f.operator(t)
	statementAnswer(t, f.submit(t, testTrail, cpLine(testTrail, 10, "a")))
	statementAnswer(t, f.submit(t, testTrail, cpLine(testTrail, 20, "a")))

	line := statementAnswer(t, f.serve(retirementRequest(operator, testTrail)))
	st := statementOf(t, line)
	if st.kind != "retirement" || st.index != 2 || st.sequence != 20 || st.trail != testTrail {
		t.Fatalf("retired with a %s at %d over %d", st.kind, st.index, st.sequence)
	}
	if !strings.HasSuffix(f.tw.read(t, "log"), string(line)+"\n") || !strings.HasSuffix(f.tw.read(t, "marks"), string(markLine(st))) {
		t.Fatal("the retirement answered is not the log's last line and the marks' last mark")
	}
	if head := statementAnswer(t, f.serve(httptest.NewRequest(http.MethodGet, "/witness/trails/"+testTrail+"/head", nil))); !bytes.Equal(head, line) {
		t.Fatal("the head is not the retirement answered")
	}
	retired := refusedAs(t, f.submit(t, testTrail, cpLine(testTrail, 30, "a")), http.StatusConflict, witnessReasonRetired)
	if len(retired.Statements) != 1 || retired.Statements[0] != string(line) {
		t.Fatal("a submission after the retirement is not refused with it")
	}
	before := f.tw.files(t)
	again := refusedAs(t, f.serve(retirementRequest(operator, testTrail)), http.StatusConflict, witnessReasonRetired)
	if len(again.Statements) != 1 || again.Statements[0] != string(line) || f.tw.files(t) != before {
		t.Fatal("a second retirement is not answered with the first, or wrote")
	}
	refusedAs(t, f.serve(retirementRequest(operator, trailB)), http.StatusNotFound, witnessReasonUnknownTrail)
	refusedAs(t, f.serve(retirementRequest(operator, trailC)), http.StatusNotFound, witnessReasonUnknownTrail)
	if f.tw.files(t) != before {
		t.Fatal("a retirement of a trail with no statement wrote")
	}
	f.log.close()
	if outcome, findings := f.tw.judge(t); outcome != outcomeStart || len(findings) > 0 {
		t.Fatalf("after a retirement on a running witness the checks find %s %v", outcome, findings)
	}
}

// The retirement a running witness signs is, byte for byte, the one
// `gateway witness retire` signs over the same files: the two are made on
// two copies of one witness, whose last statement's time is past both
// clocks, so each takes that time.
func TestWitnessLiveRetirementIsTheCommandsStatement(t *testing.T) {
	f := newWitnessFixture(t, witnessSpec{}, testTrail)
	*f.tw.now = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	statementAnswer(t, f.submit(t, testTrail, cpLine(testTrail, 10, "a")))
	statementAnswer(t, f.submit(t, testTrail, cpLine(testTrail, 20, "a")))

	stopped := newTestWitness(t)
	for _, name := range []string{"log", "marks", "registrations"} {
		stopped.write(t, name, f.tw.read(t, name))
	}
	code, out, errText := act("retire", "--config", witnessEngineFile(t, stopped, ""), "--trail", testTrail)
	if code != 0 || errText != "" {
		t.Fatalf("retire on the stopped copy: %d %s", code, errText)
	}
	live := statementAnswer(t, f.serve(retirementRequest(f.operator(t), testTrail)))
	if string(live)+"\n" != out {
		t.Fatalf("the live retirement and the command's: %s", firstDifference(out, string(live)+"\n"))
	}
	for _, name := range []string{"log", "marks", "registrations"} {
		if f.tw.read(t, name) != stopped.read(t, name) {
			t.Fatalf("the %s after the two retirements: %s", name, firstDifference(stopped.read(t, name), f.tw.read(t, name)))
		}
	}
}

// The token boundary: both acts are the operator's. An absent token, one of
// another audience, a submitter's -- naming the witness's audience, alone or
// with the engine's -- and a listed submitter's engine token are each
// refused 401, with WWW-Authenticate: Bearer, a submitter's with "a token for
// the witness is refused here", and nothing is written; the operator's
// token is refused by a submission in turn. With no identity configured,
// each is refused 401, as a submission is, after its method.
func TestWitnessAdministrationIsTheOperators(t *testing.T) {
	f := newWitnessFixture(t, witnessSpec{}, testTrail)
	statementAnswer(t, f.submit(t, testTrail, cpLine(testTrail, 1, "a")))
	listed := newWitnessFixture(t, witnessSpec{submittersGiven: true, submitters: []submitterKey{{witnessIssuer, "deliverer-a"}, {witnessIssuer, subjectOf(testTrail)}}}, testTrail)
	statementAnswer(t, listed.submit(t, testTrail, cpLine(testTrail, 1, "a")))
	acts := map[string]func(token string) *http.Request{
		"registration": func(token string) *http.Request {
			return registrationRequest(token, registrationOf(trailB, witnessIssuer, "deliverer-a"))
		},
		"retirement": func(token string) *http.Request { return retirementRequest(token, testTrail) },
	}
	for name, request := range acts {
		for _, c := range []struct {
			name     string
			f        *witnessFixture
			token    string
			sentence string
		}{
			{"no token", f, "", errNoBearerToken.Error()},
			{"a submitter's token", f, f.token(t, subjectOf(testTrail)), errWitnessTokenHere.Error()},
			{"a token of both audiences", f, f.operatorToken(t, "operator-1", []string{witnessEngineAudience, witnessAudience}), errWitnessTokenHere.Error()},
			{"a token of another audience", f, f.operatorToken(t, "operator-1", "gateway:other"), ""},
			{"a listed submitter's engine token", listed, listed.operatorToken(t, "deliverer-a", witnessEngineAudience), errWitnessTokenHere.Error()},
			{"a listed submitter's own token", listed, listed.token(t, "deliverer-a"), errWitnessTokenHere.Error()},
		} {
			t.Run(name+"/"+c.name, func(t *testing.T) {
				before := c.f.tw.files(t)
				rec := c.f.serve(request(c.token))
				refused := refusedAs(t, rec, http.StatusUnauthorized, witnessReasonToken)
				if c.sentence != "" && refused.Error != c.sentence {
					t.Fatalf("refused with %q, want %q", refused.Error, c.sentence)
				}
				if rec.Header().Get("WWW-Authenticate") != "Bearer" || rec.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("a 401 without WWW-Authenticate: Bearer, or stored")
				}
				if c.f.tw.files(t) != before {
					t.Fatal("a refused act wrote")
				}
			})
		}
	}
	// the operator's token of a subject not listed is taken where a
	// listed submitter's is not
	registeredAs(t, listed.serve(registrationRequest(listed.operator(t), registrationOf(trailB, witnessIssuer, "deliverer-a"))))
	// a submission refuses the operator's token
	refusedAs(t, f.serve(submission(f.operator(t), bytes.NewReader(jsonl(cpLine(testTrail, 2, "a"))))), http.StatusUnauthorized, witnessReasonToken)

	// no identity, a state the engine refuses to start in: each act is
	// answered as a submission is, its method first and then 401
	f.gateway.identity = nil
	before := f.tw.files(t)
	refusedAs(t, f.serve(submission(f.token(t, subjectOf(testTrail)), bytes.NewReader(jsonl(cpLine(testTrail, 2, "a"))))), http.StatusUnauthorized, witnessReasonToken)
	for name, request := range acts {
		rec := f.serve(request(f.operator(t)))
		refusedAs(t, rec, http.StatusUnauthorized, witnessReasonToken)
		if rec.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Fatalf("a %s with no identity: a 401 without WWW-Authenticate: Bearer", name)
		}
		get := request(f.operator(t))
		get.Method = http.MethodGet
		refusedAs(t, f.serve(get), http.StatusMethodNotAllowed, witnessReasonMethod)
		if f.tw.files(t) != before {
			t.Fatalf("a %s with no identity wrote", name)
		}
	}
}

// The operators list (#229): where witness.operators is given, both acts
// are a named operator's. A token the engine takes of a caller the list does
// not name is refused 403 not-an-operator, with its sentence, before a byte
// of a body is read, and nothing is written; so is every caller where the
// list is present and empty. A listed submitter's token, and a listed
// operator's naming the witness's audience too, are still 401 with "a token
// for the witness is refused here", and no token 401. A listed operator
// registers and retires, and a submission refuses its token, which names
// the engine's audience alone. With the list absent, any token the engine
// takes administers, as before.
func TestWitnessAdministrationIsTheNamedOperators(t *testing.T) {
	spec := witnessSpec{
		submittersGiven: true, submitters: []submitterKey{{witnessIssuer, "deliverer-a"}, {witnessIssuer, subjectOf(testTrail)}},
		operatorsGiven: true, operators: []submitterKey{{witnessIssuer, "operator-1"}},
	}
	f := newWitnessFixture(t, spec, testTrail)
	statementAnswer(t, f.submit(t, testTrail, cpLine(testTrail, 1, "a")))
	nobody := spec
	nobody.operators = nil
	empty := newWitnessFixture(t, nobody, testTrail)
	statementAnswer(t, empty.submit(t, testTrail, cpLine(testTrail, 1, "a")))
	const notAnOperator = "an operator named by witness.operators is required here"
	acts := map[string]func(token string) (*http.Request, *sentinel){
		"registration": func(token string) (*http.Request, *sentinel) {
			body := &sentinel{t: t}
			return registrationRequest(token, body), body
		},
		"retirement": func(token string) (*http.Request, *sentinel) { return retirementRequest(token, testTrail), nil },
	}
	for name, request := range acts {
		for _, c := range []struct {
			name     string
			f        *witnessFixture
			token    string
			status   int
			reason   string
			sentence string
		}{
			{"an unlisted engine token", f, f.operatorToken(t, "operator-2", witnessEngineAudience), http.StatusForbidden, witnessReasonNotOperator, notAnOperator},
			{"an engine token under an empty list", empty, empty.operator(t), http.StatusForbidden, witnessReasonNotOperator, notAnOperator},
			// a subject is matched exactly: not by case, not as a prefix
			{"a listed subject in another case", f, f.operatorToken(t, "Operator-1", witnessEngineAudience), http.StatusForbidden, witnessReasonNotOperator, notAnOperator},
			{"a listed subject with a suffix", f, f.operatorToken(t, "operator-1x", witnessEngineAudience), http.StatusForbidden, witnessReasonNotOperator, notAnOperator},
			{"a listed submitter's engine token", f, f.operatorToken(t, "deliverer-a", witnessEngineAudience), http.StatusUnauthorized, witnessReasonToken, errWitnessTokenHere.Error()},
			{"a listed submitter's own token", f, f.token(t, "deliverer-a"), http.StatusUnauthorized, witnessReasonToken, errWitnessTokenHere.Error()},
			{"a listed operator's token of both audiences", f, f.operatorToken(t, "operator-1", []string{witnessEngineAudience, witnessAudience}), http.StatusUnauthorized, witnessReasonToken, errWitnessTokenHere.Error()},
			{"no token", f, "", http.StatusUnauthorized, witnessReasonToken, errNoBearerToken.Error()},
		} {
			t.Run(name+"/"+c.name, func(t *testing.T) {
				before := c.f.tw.files(t)
				r, body := request(c.token)
				rec := c.f.serve(r)
				refused := refusedAs(t, rec, c.status, c.reason)
				if refused.Error != c.sentence {
					t.Fatalf("refused with %q, want %q", refused.Error, c.sentence)
				}
				h := rec.Header()
				if h.Get("Content-Length") != strconv.Itoa(rec.Body.Len()) || h.Get("Cache-Control") != "no-store" {
					t.Fatalf("Content-Length %q for %d bytes, Cache-Control %q", h.Get("Content-Length"), rec.Body.Len(), h.Get("Cache-Control"))
				}
				if (h.Get("WWW-Authenticate") == "Bearer") != (c.status == http.StatusUnauthorized) {
					t.Fatalf("a %d with WWW-Authenticate %q", c.status, h.Get("WWW-Authenticate"))
				}
				if body != nil && body.read.Load() != 0 {
					t.Fatal("the body was read before the refusal")
				}
				if c.f.tw.files(t) != before {
					t.Fatal("a refused act wrote")
				}
			})
		}
	}

	// the listed operator registers, and the registration is judged by the
	// next submission
	operator := f.operator(t)
	registeredAs(t, f.serve(registrationRequest(operator, registrationOf(trailB, witnessIssuer, "deliverer-a"))))
	statementAnswer(t, f.serve(submission(f.token(t, "deliverer-a"), bytes.NewReader(jsonl(cpLine(trailB, 1, "a"))))))
	// and retires, the answer's length stated and not stored
	rec := f.serve(retirementRequest(operator, testTrail))
	if st := statementOf(t, statementAnswer(t, rec)); st.kind != "retirement" || st.trail != testTrail {
		t.Fatalf("the listed operator's retirement is a %s of %s", st.kind, st.trail)
	}
	if h := rec.Header(); h.Get("Content-Length") != strconv.Itoa(rec.Body.Len()) || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("a retirement answered with Content-Length %q for %d bytes, Cache-Control %q", h.Get("Content-Length"), rec.Body.Len(), h.Get("Cache-Control"))
	}
	// a submission refuses the listed operator's token, as any operator's
	refusedAs(t, f.serve(submission(operator, bytes.NewReader(jsonl(cpLine(trailB, 2, "a"))))), http.StatusUnauthorized, witnessReasonToken)

	// with the list absent, a token the engine takes of any subject not
	// among the submitters administers, the one refused above included
	absent := spec
	absent.operatorsGiven, absent.operators = false, nil
	open := newWitnessFixture(t, absent, testTrail)
	statementAnswer(t, open.submit(t, testTrail, cpLine(testTrail, 1, "a")))
	anyone := open.operatorToken(t, "operator-2", witnessEngineAudience)
	registeredAs(t, open.serve(registrationRequest(anyone, registrationOf(trailB, witnessIssuer, "deliverer-a"))))
	statementAnswer(t, open.serve(retirementRequest(anyone, testTrail)))
}

// What each act refuses before it writes: a method not named, with Allow; a
// query; a registration of another media type, a length past the bound, a
// body out of shape or one no token could match -- another issuer, a
// subject the configuration does not allow; a retirement of a trail out of
// shape, or with a body. What needs no body is refused before a byte of it
// is read, and nothing is written.
func TestWitnessAdministrationRefusals(t *testing.T) {
	f := newWitnessFixture(t, witnessSpec{submittersGiven: true, submitters: []submitterKey{{witnessIssuer, "deliverer-a"}, {witnessIssuer, subjectOf(testTrail)}}}, testTrail)
	statementAnswer(t, f.submit(t, testTrail, cpLine(testTrail, 1, "a")))
	operator := f.operator(t)
	register := func(body string, change func(*http.Request)) *http.Request {
		r := registrationRequest(operator, strings.NewReader(body))
		if change != nil {
			change(r)
		}
		return r
	}
	good := `{"trail":"` + trailB + `","issuer":"` + witnessIssuer + `","subject":"deliverer-a"}`
	before := f.tw.files(t)
	for _, c := range []struct {
		name    string
		request func(body io.Reader) *http.Request
		status  int
		reason  string
	}{
		{"a registration by GET", func(b io.Reader) *http.Request {
			r := registrationRequest(operator, b)
			r.Method = http.MethodGet
			return r
		}, http.StatusMethodNotAllowed, witnessReasonMethod},
		{"a retirement by GET", func(b io.Reader) *http.Request {
			r := retirementRequest(operator, testTrail)
			r.Method = http.MethodGet
			return r
		}, http.StatusMethodNotAllowed, witnessReasonMethod},
		{"a registration with a query", func(b io.Reader) *http.Request {
			r := registrationRequest(operator, b)
			r.URL.RawQuery = "trail=" + trailB
			return r
		}, http.StatusBadRequest, witnessReasonMalformed},
		{"a retirement with an empty query", func(b io.Reader) *http.Request {
			r := retirementRequest(operator, testTrail)
			r.URL.ForceQuery = true
			return r
		}, http.StatusBadRequest, witnessReasonMalformed},
		{"a registration of another media type", func(b io.Reader) *http.Request {
			r := registrationRequest(operator, b)
			r.Header.Set("Content-Type", "application/jsonl")
			return r
		}, http.StatusUnsupportedMediaType, witnessReasonMediaType},
		{"a registration past the bound", func(b io.Reader) *http.Request {
			r := registrationRequest(operator, b)
			r.ContentLength = maxRequestBody + 1
			return r
		}, http.StatusRequestEntityTooLarge, witnessReasonTooLarge},
		{"a retirement of a trail out of shape", func(b io.Reader) *http.Request {
			return retirementRequest(operator, strings.ToUpper(testTrail))
		}, http.StatusBadRequest, witnessReasonMalformed},
		{"a retirement percent-encoded", func(b io.Reader) *http.Request {
			r := retirementRequest(operator, testTrail)
			r.URL.RawPath = "/witness/trails/" + testTrail + "/retir%65ment"
			return r
		}, http.StatusBadRequest, witnessReasonMalformed},
		{"a registration under a path spelled unclean", func(b io.Reader) *http.Request {
			r := registrationRequest(operator, b)
			r.URL.Path = "/witness/./registrations"
			return r
		}, http.StatusBadRequest, witnessReasonMalformed},
	} {
		t.Run(c.name, func(t *testing.T) {
			body := &sentinel{t: t}
			rec := f.serve(c.request(body))
			refusedAs(t, rec, c.status, c.reason)
			if body.read.Load() != 0 {
				t.Fatal("the body was read before the refusal")
			}
			if c.status == http.StatusMethodNotAllowed && rec.Header().Get("Allow") != http.MethodPost {
				t.Fatalf("a 405 allowing %q", rec.Header().Get("Allow"))
			}
		})
	}
	over := register(`{"trail":"`+strings.Repeat("a", maxRequestBody)+`"}`, func(r *http.Request) { r.ContentLength = -1 })
	refusedAs(t, f.serve(over), http.StatusRequestEntityTooLarge, witnessReasonTooLarge)
	for _, c := range []struct{ name, body string }{
		{"not JSON", "trail"},
		{"an array", "[" + good + "]"},
		{"two values", good + good},
		{"a member unknown", strings.Replace(good, `{`, `{"kind":"operator",`, 1)},
		{"a member twice", strings.Replace(good, `{`, `{"subject":"deliverer-a",`, 1)},
		{"a member missing", `{"trail":"` + trailB + `","issuer":"` + witnessIssuer + `"}`},
		{"a member null", `{"trail":"` + trailB + `","issuer":"` + witnessIssuer + `","subject":null}`},
		{"a member a number", `{"trail":"` + trailB + `","issuer":"` + witnessIssuer + `","subject":7}`},
		{"a trail out of shape", strings.Replace(good, trailB, strings.ToUpper(trailB), 1)},
		{"an empty subject", strings.Replace(good, `"deliverer-a"`, `""`, 1)},
		{"a subject longer than a line holds", strings.Replace(good, `"deliverer-a"`, `"`+strings.Repeat("s", witnessLineLimit)+`"`, 1)},
		{"another issuer", strings.Replace(good, witnessIssuer, "https://other.example", 1)},
		{"a subject not among the submitters", strings.Replace(good, "deliverer-a", "deliverer-b", 1)},
	} {
		t.Run("a registration of "+c.name, func(t *testing.T) {
			refusedAs(t, f.serve(register(c.body, nil)), http.StatusBadRequest, witnessReasonMalformed)
		})
	}
	// a retirement with a body, of a length stated and of one unstated
	// (chunked), is refused unread
	for _, length := range []int64{2, -1} {
		body := &sentinel{t: t, first: []byte("{}")}
		r := httptest.NewRequest(http.MethodPost, "/witness/trails/"+testTrail+"/retirement", body)
		r.ContentLength = length
		r.Header.Set("Authorization", "Bearer "+operator)
		refused := refusedAs(t, f.serve(r), http.StatusBadRequest, witnessReasonMalformed)
		if refused.Error != "a retirement takes no body" || body.read.Load() != 0 {
			t.Fatalf("a retirement with a body of length %d: %q, the body read %v", length, refused.Error, body.read.Load() != 0)
		}
	}
	if f.tw.files(t) != before {
		t.Fatal("a refused act wrote")
	}

	// a string the gateway's parser refuses -- not UTF-8, or a lone
	// surrogate escape -- is refused, never rewritten to U+FFFD and kept,
	// where no submitters list would refuse the subject first; a pair of
	// surrogate escapes is one character, and is kept as it
	open := newWitnessFixture(t, witnessSpec{}, testTrail)
	openBefore := open.tw.files(t)
	for _, subject := range []string{`a\ud800`, `a\udc00b`, "a\xff", "a\xed\xa0\x80"} {
		body := `{"trail":"` + trailB + `","issuer":"` + witnessIssuer + `","subject":"` + subject + `"}`
		refused := refusedAs(t, open.serve(registrationRequest(open.operator(t), strings.NewReader(body))), http.StatusBadRequest, witnessReasonMalformed)
		if !strings.Contains(refused.Error, "UTF-8") {
			t.Fatalf("subject %q refused with %q", subject, refused.Error)
		}
	}
	if open.tw.files(t) != openBefore {
		t.Fatal("a registration of a string not UTF-8 wrote")
	}
	pair := `{"trail":"` + trailB + `","issuer":"` + witnessIssuer + `","subject":"a\ud83d\ude00"}`
	if kept, _ := registeredAs(t, open.serve(registrationRequest(open.operator(t), strings.NewReader(pair)))); kept.Subject != "a\U0001F600" {
		t.Fatalf("a surrogate pair kept as %q", kept.Subject)
	}
	// the media type's parameters are not its type
	r := register(good, func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=utf-8") })
	registeredAs(t, f.serve(r))
}

// A witness stopped by a failure refuses both acts as it refuses a
// submission, 503 stopped, and writes nothing; and a registration whose own
// write fails stops it, the operator told once.
func TestWitnessAdministrationWhileStopped(t *testing.T) {
	f := newWitnessFixture(t, witnessSpec{}, testTrail, trailB)
	statementAnswer(t, f.submit(t, testTrail, cpLine(testTrail, 1, "a")))
	failing, fired := faultyWitnessIO(osWitnessIO(), "mark-sync", "whole")
	f.log.io = f.tw.io(failing)
	refusedAs(t, f.submit(t, trailB, cpLine(trailB, 1, "a")), http.StatusServiceUnavailable, witnessReasonStopped)
	if !*fired {
		t.Fatal("the fault did not fire")
	}
	before := f.tw.files(t)
	refusedAs(t, f.serve(registrationRequest(f.operator(t), registrationOf(trailC, witnessIssuer, "deliverer-c"))), http.StatusServiceUnavailable, witnessReasonStopped)
	refusedAs(t, f.serve(retirementRequest(f.operator(t), testTrail)), http.StatusServiceUnavailable, witnessReasonStopped)
	// the registration the trail holds already, too: a stopped witness
	// answers nothing as if it were not
	refusedAs(t, f.serve(registrationRequest(f.operator(t), registrationOf(testTrail, witnessIssuer, subjectOf(testTrail)))), http.StatusServiceUnavailable, witnessReasonStopped)
	if f.tw.files(t) != before || strings.Count(f.reports.String(), "witness: stopped:") != 1 {
		t.Fatalf("a stopped witness wrote, or told the operator again: %.300s", f.reports.String())
	}

	g := newWitnessFixture(t, witnessSpec{}, testTrail)
	failing, fired = faultyWitnessIO(osWitnessIO(), "register-sync", "whole")
	g.log.io = g.tw.io(failing)
	refusedAs(t, g.serve(registrationRequest(g.operator(t), registrationOf(trailB, witnessIssuer, "deliverer-b"))), http.StatusServiceUnavailable, witnessReasonStopped)
	if !*fired {
		t.Fatal("the fault did not fire")
	}
	refusedAs(t, g.submit(t, testTrail, cpLine(testTrail, 1, "a")), http.StatusServiceUnavailable, witnessReasonStopped)
	if got := strings.Count(g.reports.String(), "witness: stopped:"); got != 1 || !strings.Contains(g.reports.String(), "register-sync") {
		t.Fatalf("the operator was told %d times: %.300s", got, g.reports.String())
	}
}

// What each act keeps before it is answered, in the order the storage's
// seam records it: a registration's line appended and synced; a
// retirement's line appended and synced, its mark appended and synced, and
// the publication noted; the answer written after.
func TestWitnessAdministrationAnswersOnlyWhatIsKept(t *testing.T) {
	f := newWitnessFixture(t, witnessSpec{}, testTrail)
	statementAnswer(t, f.submit(t, testTrail, cpLine(testTrail, 1, "a")))
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
	for _, c := range []struct {
		name    string
		request *http.Request
		want    string
	}{
		{"registration", registrationRequest(f.operator(t), registrationOf(testTrail, witnessIssuer, "deliverer-new")), "write registrations, sync registrations, answer 200"},
		{"retirement", retirementRequest(f.operator(t), testTrail), "write log, sync log, write marks, sync marks, publish statement, answer 200"},
	} {
		mu.Lock()
		ops = nil
		mu.Unlock()
		rec := &orderedRecorder{ResponseRecorder: httptest.NewRecorder(), note: note}
		f.gateway.handler().ServeHTTP(rec, c.request)
		if rec.Code != http.StatusOK {
			t.Fatalf("the %s answered %d: %.200s", c.name, rec.Code, rec.Body.String())
		}
		mu.Lock()
		got := strings.Join(ops, ", ")
		mu.Unlock()
		if got != c.want {
			t.Fatalf("the %s's order was %q, want %q", c.name, got, c.want)
		}
	}
}

// The crash matrix, for the two acts on a running witness: a registration
// changing a trail's subject and a retirement, each failing at every step
// of its order and leaving every state the step can. The act is answered
// 503 stopped, never 200, and nothing is written after; restarted, the
// checks give what ADR-0013's rules say for that state; repaired where they
// allow, the trail is registered to the new subject exactly when its line
// was kept whole, and retired exactly when its retirement was marked, or
// its mark completed by the repair.
func TestWitnessAdministrationCrashMatrix(t *testing.T) {
	type step struct{ act, step, leaves string }
	var steps []step
	for _, s := range []string{"register", "register-sync"} {
		leaves := []string{"nothing", "torn", "unterminated", "whole"}
		if s == "register-sync" {
			leaves = []string{"nothing", "whole"}
		}
		for _, left := range leaves {
			steps = append(steps, step{"registration", s, left})
		}
	}
	for _, c := range crashCases() {
		if c.writer == "retirement" {
			steps = append(steps, step{"retirement", c.step, c.leaves})
		}
	}
	for _, c := range steps {
		t.Run(c.act+"/"+c.step+"/"+c.leaves, func(t *testing.T) {
			f := newWitnessFixture(t, witnessSpec{}, testTrail, trailB)
			statementAnswer(t, f.submit(t, testTrail, cpLine(testTrail, 10, "a")))
			statementAnswer(t, f.submit(t, trailB, cpLine(trailB, 5, "a")))
			headBefore := statementAnswer(t, f.submit(t, testTrail, cpLine(testTrail, 20, "a")))
			fail := newFailAt(f.tw, c.step, c.leaves, nil)
			f.log.io = f.tw.io(fail.io)
			if c.step == "publish" {
				f.log.published = func() error { *fail.fired = true; return errors.New("the process ended after the mark") }
			}
			var rec *httptest.ResponseRecorder
			if c.act == "registration" {
				rec = f.serve(registrationRequest(f.operator(t), registrationOf(testTrail, witnessIssuer, "deliverer-new")))
			} else {
				rec = f.serve(retirementRequest(f.operator(t), testTrail))
			}
			refusedAs(t, rec, http.StatusServiceUnavailable, witnessReasonStopped)
			if !*fail.fired || !strings.Contains(f.reports.String(), "the "+c.step+" step failed") {
				t.Fatalf("the fault fired %v; told %.200s", *fail.fired, f.reports.String())
			}
			if c.step == "publish" {
				fail.sizes = f.tw.sizes(t)
			}
			registrations := f.tw.read(t, "registrations")
			// stopped: neither act nor a submission writes after it
			refusedAs(t, f.serve(registrationRequest(f.operator(t), registrationOf(trailC, witnessIssuer, "deliverer-c"))), http.StatusServiceUnavailable, witnessReasonStopped)
			refusedAs(t, f.serve(retirementRequest(f.operator(t), trailB)), http.StatusServiceUnavailable, witnessReasonStopped)
			refusedAs(t, f.submit(t, trailB, cpLine(trailB, 6, "a")), http.StatusServiceUnavailable, witnessReasonStopped)
			if f.tw.sizes(t) != fail.sizes || f.tw.read(t, "registrations") != registrations {
				t.Fatal("written after the failure")
			}
			f.log.close()

			want := crashOutcome(c.step, c.leaves)
			if outcome, findings := f.tw.judge(t); outcome != want {
				t.Fatalf("restarted, the checks give %s %v, the rules %s", outcome, findings, want)
			}
			if want == outcomeNewKey {
				return
			}
			if j, err := f.tw.repair(osWitnessIO()); err != nil || j.outcome != want {
				t.Fatalf("repair: %v", err)
			}
			w := f.tw.open(t)
			defer w.close()
			if c.act == "registration" {
				kept := c.leaves == "whole"
				if got := w.registrations[testTrail].subject; (got == "deliverer-new") != kept {
					t.Fatalf("after the restart the trail is registered to %q; the line was kept whole %v", got, kept)
				}
				return
			}
			marked := want == outcomeMarkCompleted || want == outcomeNewlineAndMark || c.leaves == "whole" && (c.step == "mark" || c.step == "mark-sync" || c.step == "publish")
			head, _, err := w.head(testTrail)
			if err != nil {
				t.Fatal(err)
			}
			if st := statementOf(t, head); (st.kind == "retirement") != marked || !marked && !bytes.Equal(head, headBefore) {
				t.Fatalf("after the restart the head is a %s; the retirement was marked %v", st.kind, marked)
			}
		})
	}
}

// Each act takes a place among the submissions in flight, held to the
// bounds a submission is: with the writer held, an operator's acts wait in
// their places, one past its own bound is refused 503 busy, and submitters
// still take the places left; once the writer is free, every act and
// submission waiting is answered, and every place given back.
func TestWitnessAdministrationTakesAPlaceInFlight(t *testing.T) {
	savedAll, savedOne := witnessSubmissionsInFlight, witnessSubmitterInFlight
	witnessSubmissionsInFlight, witnessSubmitterInFlight = 4, 2
	t.Cleanup(func() { witnessSubmissionsInFlight, witnessSubmitterInFlight = savedAll, savedOne })
	f := newWitnessFixture(t, witnessSpec{}, testTrail, trailB)
	statementAnswer(t, f.submit(t, testTrail, cpLine(testTrail, 1, "a")))
	operator := f.operator(t)
	wait := func(n int) {
		deadline := time.Now().Add(10 * time.Second)
		for len(f.svc.submitting) < n && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
	}
	submissionB := submission(f.token(t, subjectOf(trailB)), bytes.NewReader(jsonl(cpLine(trailB, 1, "a"))))
	submissionA := submission(f.token(t, subjectOf(testTrail)), bytes.NewReader(jsonl(cpLine(testTrail, 2, "a"))))
	another := f.operatorToken(t, "operator-2", witnessEngineAudience)
	f.log.writer.Lock()
	answers := make(chan *httptest.ResponseRecorder, 4)
	go func() {
		answers <- f.serve(registrationRequest(operator, registrationOf(trailC, witnessIssuer, "deliverer-c")))
	}()
	go func() { answers <- f.serve(retirementRequest(operator, testTrail)) }()
	wait(2)
	ownBound := f.serveWithin(retirementRequest(operator, testTrail), 5*time.Second)
	go func() { answers <- f.serve(submissionB) }()
	go func() { answers <- f.serve(submissionA) }()
	wait(4)
	allBound := f.serveWithin(registrationRequest(another, registrationOf(trailC, witnessIssuer, "deliverer-c")), 5*time.Second)
	f.log.writer.Unlock()
	if ownBound == nil || allBound == nil {
		t.Fatalf("an act past a bound waited instead of being refused: the operator's %v, the witness's %v", ownBound == nil, allBound == nil)
	}
	if !strings.Contains(refusedAs(t, ownBound, http.StatusServiceUnavailable, witnessReasonBusy).Error, "one submitter") ||
		!strings.Contains(refusedAs(t, allBound, http.StatusServiceUnavailable, witnessReasonBusy).Error, "as it takes") {
		t.Fatal("the bounds that refused are not the operator's own and the witness's")
	}
	for i := 0; i < 4; i++ {
		if rec := <-answers; rec.Code != http.StatusOK && rec.Code != http.StatusConflict {
			t.Fatalf("a waiting act or submission answered %d: %.200s", rec.Code, rec.Body.String())
		}
	}
	if len(f.svc.submitting) != 0 || len(f.svc.flying) != 0 {
		t.Fatalf("%d places and %d callers still held", len(f.svc.submitting), len(f.svc.flying))
	}
}
