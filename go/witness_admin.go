package main

// The witness's operator's two acts on a running witness (SPEC.md §6,
// "Administration"; issue #215): registering a trail, or changing its
// registration, and retiring a trail. The commands `gateway witness
// register` and `retire` do the same with the witness stopped
// (witness_cmd.go); a running witness holds its files, so on a running
// witness these endpoints do it, through the writer the submissions go
// through. Repair stays a command, for a stopped witness only.
//
// Both are the operator's: a token is verified as the engine's own
// endpoints verify one (engineCaller), under the engine's audience, so a
// submitter's token -- one naming the witness's audience, or of a subject
// among witness.submitters -- is refused here as it is at /seal. With no
// identity configured each is refused 401, as a submission is. Any token
// the engine takes is an operator's here, so these two paths belong behind
// the operator's side of a front, never beside the submission and the reads
// a front passes to other parties (SPEC.md §6). Each takes a place among
// the submissions in flight, as a submission does, though no rate counts
// it, and is answered only once what it wrote is kept: a registration
// appended and synced, a retirement durable and marked.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"time"
)

// witnessRegistrationMembers are the members a registration's body holds,
// all of them and no others.
var witnessRegistrationMembers = map[string]bool{"trail": true, "issuer": true, "subject": true}

// witnessRegistrant is an issuer and a subject a trail is registered to, as
// a registration's answer names the one it replaced.
type witnessRegistrant struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

// witnessRegistrationAnswer is a registration's answer: the registration
// kept, and the registration it changed, or null when the trail was
// registered to nobody or to the same issuer and subject.
type witnessRegistrationAnswer struct {
	Trail       string             `json:"trail"`
	Issuer      string             `json:"issuer"`
	Subject     string             `json:"subject"`
	ChangedFrom *witnessRegistrant `json:"changedFrom"`
}

// operator is the caller of an operator's act, its token verified as the
// engine's own endpoints verify one, or false once the refusal is written:
// 401 for an absent or invalid token, and for a submitter's, with the
// sentence every endpoint that is not the witness's gives it; 401 too, as a
// submission is answered, where no identity is configured.
func (s *witnessService) operator(w http.ResponseWriter, r *http.Request, id *identityConfig) (*caller, bool) {
	if id == nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		witnessRefuse(w, http.StatusUnauthorized, witnessReasonToken, "an operator's act is authenticated, and this engine has no identity configured")
		return nil, false
	}
	who, err := engineCaller(id, s.spec, r.Header.Get("Authorization"), time.Now())
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		witnessRefuse(w, http.StatusUnauthorized, witnessReasonToken, err.Error())
		return nil, false
	}
	return who, true
}

// actPlace takes a place among the submissions in flight for an operator's
// act, held to the bounds a submission is held to, the operator counted as
// any submitter is by its issuer and subject; it returns what gives the
// place back once the answer is written, or false once the refusal is.
func (s *witnessService) actPlace(w http.ResponseWriter, who *caller) (func(), bool) {
	key := submitterKey{who.issuer, who.subject}
	if !s.enter(key) {
		w.Header().Set("Retry-After", "1")
		witnessRefuse(w, http.StatusServiceUnavailable, witnessReasonBusy, "this submitter has as many submissions in flight as the witness takes from one submitter")
		return nil, false
	}
	select {
	case s.submitting <- struct{}{}:
		return func() { <-s.submitting; s.leave(key) }, true
	default:
		w.Header().Set("Retry-After", "1")
		witnessRefuse(w, http.StatusServiceUnavailable, witnessReasonBusy, "the witness has as many submissions in flight as it takes")
		s.leave(key)
		return nil, false
	}
}

// actRefused answers an operator's act the writer refused: stopped, by a
// failure now or earlier, as a submission is answered; a chain at the
// largest index; anything else, on the signer's standard error.
func (s *witnessService) actRefused(w http.ResponseWriter, act string, err error) {
	var failure witnessFailure
	switch {
	case errors.As(err, &failure):
		// the storage gives the failure once, to the write it stopped
		fmt.Fprintf(s.reports, "witness: stopped: %v\n", failure)
		fallthrough
	case errors.Is(err, errWitnessStopped):
		witnessRefuse(w, http.StatusServiceUnavailable, witnessReasonStopped, witnessStoppedSentence)
	case errors.Is(err, errWitnessIndexBound):
		witnessRefuse(w, http.StatusConflict, witnessReasonIndexBound, "the trail's chain is at the largest index a statement holds")
	default:
		fmt.Fprintf(s.reports, "witness: a %s could not be answered: %v\n", act, err)
		witnessRefuse(w, http.StatusInternalServerError, witnessReasonInternal, "the "+act+" could not be answered")
	}
}

// register answers POST /witness/registrations: the operator registers a
// trail to an issuer and a subject, or changes its registration. The body
// is held as the command holds its flags: the issuer the configured one,
// and, where the configuration names the submitters, the subject one of
// them, since a registration no token could match is refused rather than
// kept. The registration is appended and synced under the writer lock, and
// indexed, before it is answered, so the next submission for the trail is
// judged by it; one the same as the trail's holds already is answered alike
// and appends nothing.
func (s *witnessService) register(w http.ResponseWriter, r *http.Request, id *identityConfig) {
	if r.Method != http.MethodPost {
		refuseMethod(w, http.MethodPost)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		witnessRefuse(w, http.StatusBadRequest, witnessReasonMalformed, "a registration takes no query")
		return
	}
	who, ok := s.operator(w, r, id)
	if !ok {
		return
	}
	if media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || media != "application/json" {
		witnessRefuse(w, http.StatusUnsupportedMediaType, witnessReasonMediaType, "a registration is application/json")
		return
	}
	if r.ContentLength > maxRequestBody {
		witnessRefuse(w, http.StatusRequestEntityTooLarge, witnessReasonTooLarge, fmt.Sprintf("a registration is at most %d bytes", maxRequestBody))
		return
	}
	release, ok := s.actPlace(w, who)
	if !ok {
		return
	}
	defer release()
	limitBodyTo(w, r, maxRequestBody)
	reg, status, why := readRegistration(r, id, s.spec)
	if status != 0 {
		reason := witnessReasonMalformed
		if status == http.StatusRequestEntityTooLarge {
			reason = witnessReasonTooLarge
		}
		witnessRefuse(w, status, reason, why)
		return
	}
	previous, err := s.log.reregister(reg)
	if err != nil {
		s.actRefused(w, "registration", err)
		return
	}
	answer := witnessRegistrationAnswer{Trail: reg.trail, Issuer: reg.issuer, Subject: reg.subject}
	if previous != nil && (previous.issuer != reg.issuer || previous.subject != reg.subject) {
		answer.ChangedFrom = &witnessRegistrant{Issuer: previous.issuer, Subject: previous.subject}
	}
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(answer); err != nil {
		// kept already: the operator is told it was, without the echo
		fmt.Fprintf(s.reports, "witness: a registration kept could not be answered: %v\n", err)
		witnessRefuse(w, http.StatusInternalServerError, witnessReasonInternal, "the registration was kept, and its answer could not be written")
		return
	}
	witnessWrite(w, http.StatusOK, "application/json", body.Bytes())
}

// readRegistration reads a registration's body, a closed object of three
// strings, and holds it as `gateway witness register` holds its flags: a
// registration the storage keeps, of the configured issuer and, where the
// submitters are named, of one of them. Each string is read by the
// gateway's own parser, not encoding/json's, so one that is not UTF-8, or
// holds a lone surrogate escape, is refused as the command refuses it,
// never rewritten to U+FFFD and kept. It answers the registration, or the
// status and the sentence of a refusal.
func readRegistration(r *http.Request, id *identityConfig, spec *witnessSpec) (witnessRegistration, int, string) {
	const shape = "a registration is a JSON object of trail, issuer and subject, each a string of UTF-8 text with no lone surrogate escape, and nothing else"
	members, err := requestMembers(r.Body, witnessRegistrationMembers)
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		return witnessRegistration{}, http.StatusRequestEntityTooLarge, fmt.Sprintf("a registration is at most %d bytes", maxRequestBody)
	case err != nil:
		return witnessRegistration{}, http.StatusBadRequest, shape
	}
	var reg witnessRegistration
	for name, into := range map[string]*string{"trail": &reg.trail, "issuer": &reg.issuer, "subject": &reg.subject} {
		raw, present := members[name]
		if !present {
			return witnessRegistration{}, http.StatusBadRequest, shape
		}
		v, err := parseJSONWithin(raw, 1)
		text, isString := v.(vString)
		if err != nil || !isString {
			return witnessRegistration{}, http.StatusBadRequest, shape
		}
		*into = string(text)
	}
	switch {
	case !isLowerHexOfLen(reg.trail, 32):
		return witnessRegistration{}, http.StatusBadRequest, "a trail is 32 lowercase hexadecimal characters"
	case admitRegistration(reg) != nil:
		return witnessRegistration{}, http.StatusBadRequest, fmt.Sprintf("a registration's issuer and subject are strings of at least one character, its line at most %d bytes", witnessLineLimit)
	case reg.issuer != id.issuer:
		return witnessRegistration{}, http.StatusBadRequest, "the registration names an issuer other than identity.issuer, whose tokens alone this engine takes, so no submission could match it; nothing was changed"
	case spec.submittersGiven && !containsSubmitter(spec.submitters, submitterKey{reg.issuer, reg.subject}):
		return witnessRegistration{}, http.StatusBadRequest, "the registration's subject is not among witness.submitters, so no submission of it is taken; nothing was changed"
	}
	return reg, 0, ""
}

// retire answers POST /witness/trails/{trail}/retirement: the operator
// retires a trail, as `gateway witness retire` does on a stopped witness --
// the same statement over the same files, signed, made durable, marked and
// only then published, in the answer. A trail the witness holds no
// statement for is 404, and one retired already 409 with its retirement,
// nothing signed; a submission for the trail is refused retired from the
// next request on.
func (s *witnessService) retire(w http.ResponseWriter, r *http.Request, id *identityConfig, trail string) {
	if r.Method != http.MethodPost {
		refuseMethod(w, http.MethodPost)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		witnessRefuse(w, http.StatusBadRequest, witnessReasonMalformed, "a retirement takes no query")
		return
	}
	who, ok := s.operator(w, r, id)
	if !ok {
		return
	}
	if !isLowerHexOfLen(trail, 32) {
		witnessRefuse(w, http.StatusBadRequest, witnessReasonMalformed, "a trail is 32 lowercase hexadecimal characters")
		return
	}
	// a body, even one of unstated length, is refused unread: a retirement
	// names its trail in its path and takes nothing else
	if r.ContentLength != 0 {
		witnessRefuse(w, http.StatusBadRequest, witnessReasonMalformed, "a retirement takes no body")
		return
	}
	release, ok := s.actPlace(w, who)
	if !ok {
		return
	}
	defer release()
	answer, err := s.log.retire(trail)
	switch {
	case errors.Is(err, errWitnessNothingRetired):
		witnessRefuse(w, http.StatusNotFound, witnessReasonUnknownTrail, witnessUnknownTrailSentence)
	case err != nil:
		s.actRefused(w, "retirement", err)
	case answer.kind == "retired":
		witnessRefuse(w, http.StatusConflict, witnessReasonRetired, witnessRetiredSentence, answer.statements...)
	case answer.kind == "signed" && len(answer.statements) == 1:
		witnessLines(w, answer.statements)
	default:
		fmt.Fprintf(s.reports, "witness: a retirement was answered %q, which has no answer here\n", answer.kind)
		witnessRefuse(w, http.StatusInternalServerError, witnessReasonInternal, "the retirement could not be answered")
	}
}
