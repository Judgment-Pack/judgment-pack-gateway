package main

// The checkpoint witness's endpoints (docs/adr/0013-checkpoint-witness.md §4;
// SPEC.md §6, "Witness endpoints"): a submission of checkpoint lines, and the
// two open reads of a trail's chain. They are the first surface of this
// gateway meant to be reached from other hosts by other parties, so every
// request is held as one from a party nothing is known about: only the
// method the specification names, a path spelled one way, a query of the
// members named and digits where a number is meant; a body read through its
// bound, line by line, each line held to the checkpoint's canonical form as
// it arrives; a bearer token verified as every other endpoint verifies one,
// before the body is read; and a bound on what each submitter may cost, on
// what is in flight, and on how long an answer may take to be written.
//
// What the witness keeps, and in what order, is the storage's
// (witness_log.go): a statement is answered only once it is published,
// after its line and its mark are synced, and a witness whose writer failed
// answers every submission with a refusal until it restarts.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// witnessLineBound is a checkpoint line's bound, its newline not
	// counted: the runtime's MaxCheckpointBytes, and the storage's line
	// bound (witnessLineLimit), so nothing is taken at the door that the
	// storage would refuse.
	witnessLineBound = witnessLineLimit

	// witnessReadLimit is the most statements one read answers, and the
	// default.
	witnessReadLimit = 1000

	// witnessMediaType is what a submission is, and what a statement is
	// answered as.
	witnessMediaType = "application/jsonl"
)

// The bounds on what is in flight, and on how long an answer may take to be
// written. Variables, so a test can reach them without a thousand requests.
var (
	witnessSubmissionsInFlight = 32
	witnessReadsInFlight       = 64
	witnessAnswerTime          = 30 * time.Second

	// maxRateSubmitters bounds the submitters one minute's window counts:
	// a submitter not yet counted in a minute that has counted this many is
	// refused until the minute turns, so what the windows hold is bounded
	// whatever the issuer names.
	maxRateSubmitters = 65536
)

// witnessService answers the witness's endpoints over a witness log open.
type witnessService struct {
	log *witnessLog
	// allowed are the submitters configured; nil when any subject of the
	// configured issuer may submit.
	allowed   map[submitterKey]bool
	perMinute int
	now       func() time.Time
	reports   io.Writer

	submitting chan struct{}
	reading    chan struct{}

	// the rate windows: one per submitter, all of one minute, cleared when
	// the minute turns (count)
	rate   sync.Mutex
	minute int64
	counts map[[sha256.Size]byte]int

	stopReported sync.Once
}

// newWitnessService is the service of a witness log open under a
// configuration's witness member; what it reports goes to reports.
func newWitnessService(log *witnessLog, spec *witnessSpec, reports io.Writer) *witnessService {
	s := &witnessService{
		log: log, perMinute: spec.submissionsPerMinute, now: time.Now, reports: reports,
		submitting: make(chan struct{}, witnessSubmissionsInFlight),
		reading:    make(chan struct{}, witnessReadsInFlight),
		counts:     map[[sha256.Size]byte]int{},
	}
	if spec.submittersGiven {
		s.allowed = map[submitterKey]bool{}
		for _, key := range spec.submitters {
			s.allowed[key] = true
		}
	}
	return s
}

// The reasons a witness's refusal carries, one word each, beside a sentence.
const (
	witnessReasonMalformed     = "malformed"
	witnessReasonMethod        = "method"
	witnessReasonNotFound      = "not-found"
	witnessReasonToken         = "unauthenticated"
	witnessReasonNotSubmitter  = "not-a-submitter"
	witnessReasonNotRegistered = "not-registered"
	witnessReasonUnknownTrail  = "unknown-trail"
	witnessReasonConflict      = "conflict"
	witnessReasonBelowHead     = "below-head"
	witnessReasonRetired       = "retired"
	witnessReasonIndexBound    = "index-bound"
	witnessReasonTooLarge      = "too-large"
	witnessReasonMediaType     = "media-type"
	witnessReasonRate          = "rate"
	witnessReasonTrails        = "trails"
	witnessReasonBusy          = "busy"
	witnessReasonStopped       = "stopped"
	witnessReasonInternal      = "internal"
)

// handler is the witness's endpoints, under /witness/, for a signer whose
// tokens are verified under id.
func (s *witnessService) handler(id *identityConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer s.answerWithin(w)()
		// One spelling of a path: what is percent-encoded is refused,
		// whatever it decodes to, so no path reaches a trail by another.
		if strings.Contains(r.URL.EscapedPath(), "%") {
			witnessRefuse(w, http.StatusBadRequest, witnessReasonMalformed, "a witness path is spelled without percent-encoding")
			return
		}
		path := r.URL.Path
		if path == "/witness/checkpoints" {
			s.submit(w, r, id)
			return
		}
		rest, under := strings.CutPrefix(path, "/witness/trails/")
		trail, what, two := strings.Cut(rest, "/")
		if !under || !two || (what != "head" && what != "statements") {
			witnessRefuse(w, http.StatusNotFound, witnessReasonNotFound, "no witness endpoint is at this path")
			return
		}
		s.read(w, r, trail, what)
	}
}

// answerWithin bounds how long an answer may take to be written, from the
// moment the request is handled: a reader that does not read is not held
// for longer, and neither is the place among the reads or submissions in
// flight that the answer is written under (witnessWrite flushes it there).
// It returns what ends the bound once the answer is written, so the next
// request on the connection is not held to it.
func (s *witnessService) answerWithin(w http.ResponseWriter) func() {
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(witnessAnswerTime))
	return func() { _ = rc.SetWriteDeadline(time.Time{}) }
}

// refuseMethod answers a method the specification does not name for the
// endpoint, before anything else is read.
func refuseMethod(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	witnessRefuse(w, http.StatusMethodNotAllowed, witnessReasonMethod, "this witness endpoint is "+allow+" only")
}

// witnessRefuse answers a refusal: {"error", "reason"}, and "statements",
// each a statement's exact line as a JSON string, when there are any. The
// sentence is the witness's own, never text a request carried or an
// operating system wrote.
func witnessRefuse(w http.ResponseWriter, status int, reason, sentence string, statements ...[]byte) {
	body := map[string]any{"error": sentence, "reason": reason}
	if len(statements) > 0 {
		lines := make([]string, len(statements))
		for i, st := range statements {
			lines[i] = string(st)
		}
		body["statements"] = lines
	}
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(body); err != nil {
		buf.Reset()
		buf.WriteString(`{"error":"the refusal could not be written","reason":"internal"}` + "\n")
	}
	witnessWrite(w, status, "application/json", buf.Bytes())
}

// witnessWrite writes an answer whole, its length stated, and flushes it
// to the connection: an answer is written, or its bound has passed, before
// the place it was made under is given back.
func witnessWrite(w http.ResponseWriter, status int, contentType string, body []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
	_ = http.NewResponseController(w).Flush()
}

// witnessLines answers 200 with statement lines, each exactly as the
// witness keeps it, ended by a newline.
func witnessLines(w http.ResponseWriter, lines [][]byte) {
	var size int
	for _, line := range lines {
		size += len(line) + 1
	}
	body := make([]byte, 0, size)
	for _, line := range lines {
		body = append(append(body, line...), '\n')
	}
	witnessWrite(w, http.StatusOK, witnessMediaType, body)
}

// --- submission ----------------------------------------------------------------

// submit answers POST /witness/checkpoints. Everything that needs no body
// is decided before a byte of it is read: the method, the query, the token,
// whether its subject may submit, its rate, the media type, the length the
// request states, and a place among the submissions in flight.
func (s *witnessService) submit(w http.ResponseWriter, r *http.Request, id *identityConfig) {
	if r.Method != http.MethodPost {
		refuseMethod(w, http.MethodPost)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		witnessRefuse(w, http.StatusBadRequest, witnessReasonMalformed, "a submission takes no query")
		return
	}
	if id == nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		witnessRefuse(w, http.StatusUnauthorized, witnessReasonToken, "a submission is authenticated, and this engine has no identity configured")
		return
	}
	who, err := bearerCaller(id, r.Header.Get("Authorization"), time.Now())
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		witnessRefuse(w, http.StatusUnauthorized, witnessReasonToken, err.Error())
		return
	}
	key := submitterKey{who.issuer, who.subject}
	if s.allowed != nil && !s.allowed[key] {
		witnessRefuse(w, http.StatusForbidden, witnessReasonNotSubmitter, "the token's subject is not among the submitters this witness allows")
		return
	}
	if wait, ok := s.count(key); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(wait))
		witnessRefuse(w, http.StatusTooManyRequests, witnessReasonRate, fmt.Sprintf("this submitter has made %d submissions in this minute, as many as the witness takes", s.perMinute))
		return
	}
	if media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || media != witnessMediaType {
		witnessRefuse(w, http.StatusUnsupportedMediaType, witnessReasonMediaType, "a submission is "+witnessMediaType)
		return
	}
	if r.ContentLength > maxRequestBody {
		witnessRefuse(w, http.StatusRequestEntityTooLarge, witnessReasonTooLarge, fmt.Sprintf("a submission is at most %d bytes", maxRequestBody))
		return
	}
	select {
	case s.submitting <- struct{}{}:
		defer func() { <-s.submitting }()
	default:
		w.Header().Set("Retry-After", "1")
		witnessRefuse(w, http.StatusServiceUnavailable, witnessReasonBusy, "the witness has as many submissions in flight as it takes")
		return
	}
	limitBodyTo(w, r, maxRequestBody)
	lines, status, why := readCheckpointLines(r.Body)
	if status != 0 {
		reason := witnessReasonMalformed
		if status == http.StatusRequestEntityTooLarge {
			reason = witnessReasonTooLarge
		}
		witnessRefuse(w, status, reason, why)
		return
	}
	answer, err := s.log.submit(who.issuer, who.subject, lines)
	s.answer(w, answer, err)
}

// readCheckpointLines reads a submission's body through its bound, a line
// at a time: each line at most witnessLineBound bytes and ended by a
// newline, and held as it arrives to a checkpoint in its canonical form, of
// the first line's trail, its sequence above the line's before -- the first
// line that fails ends the read, and the rest is never read. It answers the
// lines, or the status and the sentence of a refusal.
func readCheckpointLines(body io.Reader) ([][]byte, int, string) {
	reader := bufio.NewReaderSize(body, witnessLineBound+1)
	var (
		lines    [][]byte
		trail    string
		sequence int64
	)
	for number := 1; ; number++ {
		chunk, err := reader.ReadSlice('\n')
		var tooLarge *http.MaxBytesError
		switch {
		case errors.As(err, &tooLarge):
			return nil, http.StatusRequestEntityTooLarge, fmt.Sprintf("a submission is at most %d bytes", maxRequestBody)
		case errors.Is(err, bufio.ErrBufferFull):
			return nil, http.StatusRequestEntityTooLarge, fmt.Sprintf("line %d is longer than %d bytes, a checkpoint line's bound", number, witnessLineBound)
		case err == io.EOF && len(chunk) == 0:
			if len(lines) == 0 {
				return nil, http.StatusBadRequest, "a submission holds at least one checkpoint line"
			}
			return lines, 0, ""
		case err == io.EOF:
			return nil, http.StatusBadRequest, fmt.Sprintf("line %d is not ended by a newline", number)
		case err != nil:
			return nil, http.StatusBadRequest, "the submission could not be read"
		}
		line := append([]byte(nil), chunk[:len(chunk)-1]...)
		cp, ok := parseCheckpointLine(line)
		switch {
		case !ok:
			return nil, http.StatusBadRequest, fmt.Sprintf("line %d is not a checkpoint in its canonical form", number)
		case number > 1 && cp.trail != trail:
			return nil, http.StatusBadRequest, fmt.Sprintf("line %d is of another trail than line 1", number)
		case number > 1 && cp.sequence <= sequence:
			return nil, http.StatusBadRequest, fmt.Sprintf("line %d's sequence is not above line %d's", number, number-1)
		}
		trail, sequence = cp.trail, cp.sequence
		lines = append(lines, line)
	}
}

// answer is a submission's answer, from what the storage did with it.
func (s *witnessService) answer(w http.ResponseWriter, answer witnessAnswer, err error) {
	var lineErr witnessLineError
	var failure witnessFailure
	switch {
	case err == nil:
	case errors.As(err, &lineErr):
		witnessRefuse(w, http.StatusBadRequest, witnessReasonMalformed, lineErr.reason)
		return
	case errors.Is(err, errWitnessUnregistered), errors.Is(err, errWitnessRegisteredElse), errors.Is(err, errWitnessUnregisterable):
		// one answer for a trail not registered and one registered to
		// another: it tells a submitter nothing of another's registration
		witnessRefuse(w, http.StatusForbidden, witnessReasonNotRegistered, "the trail is not registered to this submitter")
		return
	case errors.Is(err, errWitnessTrailsBound):
		witnessRefuse(w, http.StatusTooManyRequests, witnessReasonTrails, "this submitter submits for as many trails as the witness allows a submitter")
		return
	case errors.As(err, &failure):
		s.stopReported.Do(func() {
			fmt.Fprintf(s.reports, "witness: stopped: %v\n", failure)
		})
		fallthrough
	case errors.Is(err, errWitnessStopped):
		witnessRefuse(w, http.StatusServiceUnavailable, witnessReasonStopped, "a statement this witness signed could not be kept, so it signs nothing more, for any trail, until it has restarted")
		return
	case errors.Is(err, errWitnessIndexBound):
		witnessRefuse(w, http.StatusConflict, witnessReasonIndexBound, "the trail's chain is at the largest index a statement holds")
		return
	default:
		fmt.Fprintf(s.reports, "witness: a submission could not be answered: %v\n", err)
		witnessRefuse(w, http.StatusInternalServerError, witnessReasonInternal, "the submission could not be answered")
		return
	}
	switch answer.kind {
	case "signed", "held":
		witnessLines(w, answer.statements)
	case "conflict":
		witnessRefuse(w, http.StatusConflict, witnessReasonConflict, "the witness holds another record digest for a sequence submitted; the conflict statement it signed is the first offered for that sequence, and acknowledges nothing of the digest just sent", answer.statements...)
	case "below-head":
		witnessRefuse(w, http.StatusConflict, witnessReasonBelowHead, "the last line's sequence is below the latest checkpoint the witness holds for the trail, and not held; the head is given", answer.statements...)
	case "retired":
		witnessRefuse(w, http.StatusConflict, witnessReasonRetired, "the trail is retired, and the witness accepts nothing more for it", answer.statements...)
	default:
		fmt.Fprintf(s.reports, "witness: a submission was answered %q, which has no answer here\n", answer.kind)
		witnessRefuse(w, http.StatusInternalServerError, witnessReasonInternal, "the submission could not be answered")
	}
}

// count counts a submission against its submitter's window, at its arrival,
// whatever becomes of it, and says whether it is within the bound; when it
// is not, how many seconds until the window turns. The windows are one
// minute each, from a whole minute of the witness's clock, for every
// submitter alike, and are forgotten when it turns.
func (s *witnessService) count(key submitterKey) (int, bool) {
	now := s.now()
	minute := now.Unix() / 60
	digest := sha256.Sum256([]byte(key.issuer + "\x00" + key.subject))
	s.rate.Lock()
	defer s.rate.Unlock()
	if minute != s.minute {
		s.minute, s.counts = minute, map[[sha256.Size]byte]int{}
	}
	wait := max(1, int(math.Ceil(time.Unix((minute+1)*60, 0).Sub(now).Seconds())))
	n, known := s.counts[digest]
	if !known && len(s.counts) >= maxRateSubmitters {
		return wait, false
	}
	if n >= s.perMinute {
		return wait, false
	}
	s.counts[digest] = n + 1
	return 0, true
}

// --- reads ---------------------------------------------------------------------

// read answers the two reads of a trail, open to anyone who names it: its
// head, and its statements from an index. A trail the witness holds no
// statement for -- never submitted, or registered and not yet signed for --
// is answered alike, 404, and no registration is ever served.
func (s *witnessService) read(w http.ResponseWriter, r *http.Request, trail, what string) {
	if r.Method != http.MethodGet {
		refuseMethod(w, http.MethodGet)
		return
	}
	if !isLowerHexOfLen(trail, 32) {
		witnessRefuse(w, http.StatusBadRequest, witnessReasonMalformed, "a trail is 32 lowercase hexadecimal characters")
		return
	}
	from, limit := int64(0), witnessReadLimit
	switch {
	case what == "head" && (r.URL.RawQuery != "" || r.URL.ForceQuery):
		witnessRefuse(w, http.StatusBadRequest, witnessReasonMalformed, "a head is read with no query")
		return
	case what == "statements":
		var why string
		if from, limit, why = parseReadQuery(r.URL.RawQuery, r.URL.ForceQuery); why != "" {
			witnessRefuse(w, http.StatusBadRequest, witnessReasonMalformed, why)
			return
		}
	}
	select {
	case s.reading <- struct{}{}:
		defer func() { <-s.reading }()
	default:
		w.Header().Set("Retry-After", "1")
		witnessRefuse(w, http.StatusServiceUnavailable, witnessReasonBusy, "the witness has as many reads in flight as it takes")
		return
	}
	var (
		lines [][]byte
		known bool
		err   error
	)
	if what == "head" {
		var line []byte
		line, known, err = s.log.head(trail)
		lines = [][]byte{line}
	} else {
		lines, known, err = s.log.read(trail, from, limit)
	}
	switch {
	case err != nil:
		fmt.Fprintf(s.reports, "witness: a read could not be answered: %v\n", err)
		witnessRefuse(w, http.StatusInternalServerError, witnessReasonInternal, "the read could not be answered")
	case !known:
		witnessRefuse(w, http.StatusNotFound, witnessReasonUnknownTrail, "the witness holds no statement for this trail")
	default:
		witnessLines(w, lines)
	}
}

// parseReadQuery reads a statements read's query, spelled one way: nothing,
// or from and limit, each at most once, as name=value, each value decimal
// digits with no sign, no leading zero and nothing encoded; from 0 to
// 2^53-2, 0 when absent; limit 1 to 1000, 1000 when absent.
func parseReadQuery(raw string, force bool) (int64, int, string) {
	from, limit := int64(0), witnessReadLimit
	if raw == "" {
		if force {
			return 0, 0, "an empty query is not a query of from and limit"
		}
		return from, limit, ""
	}
	seen := map[string]bool{}
	for _, pair := range strings.Split(raw, "&") {
		name, text, ok := strings.Cut(pair, "=")
		if !ok || (name != "from" && name != "limit") {
			return 0, 0, "a statements read's query names from and limit, each as name=digits, and nothing else"
		}
		if seen[name] {
			return 0, 0, name + " is given twice"
		}
		seen[name] = true
		n, ok := decimalDigits(text)
		switch {
		case !ok:
			return 0, 0, name + " is decimal digits, with no sign and no leading zero"
		case name == "from" && n > maxWitnessInteger:
			return 0, 0, fmt.Sprintf("from is an index, at most %d", int64(maxWitnessInteger))
		case name == "limit" && (n < 1 || n > witnessReadLimit):
			return 0, 0, fmt.Sprintf("limit is 1 to %d", witnessReadLimit)
		case name == "from":
			from = n
		default:
			limit = int(n)
		}
	}
	return from, limit, ""
}

// decimalDigits reads a number spelled in decimal digits alone, with no
// sign and no leading zero, of at most sixteen digits.
func decimalDigits(text string) (int64, bool) {
	if text == "" || len(text) > 16 || (len(text) > 1 && text[0] == '0') {
		return 0, false
	}
	for i := 0; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(text, 10, 64)
	return n, err == nil
}
