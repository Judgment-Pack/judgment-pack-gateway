package main

// `gateway witness fetch`: the reference reader of the witness a receipt
// names (docs/adr/0014-a-receipt-names-the-witness.md, determination 4;
// SPEC.md §6, "Reading the witness a receipt names"). From a decision record
// and its receipts alone -- the record, its trail, the operator's store and
// registry under the operator's gateway key pinned out of band -- it reads
// the witnesses the receipts name for the record's trail from a verdict that
// is ok, finds each one's key (the reader's own pin whose identifier the
// receipt names, or else the key the named origin serves, held to that
// identifier and the key rule), fetches the trail's head and statements with
// no token and no redirect, and runs the runtime's `audit verify --witness`
// over them. The runtime's report is the reading, given verbatim: this
// command reads no statement itself, and credits nothing.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const witnessFetchUsage = `usage:
  gateway witness fetch --store <dir> --registry <file> --authority <label> --public-key <file>
      [--decision-records <dir>] --record <file> --trail <file> --runtime <path> --out <dir>
      [--witness-key <file>]... [--statements <file>]... [--allow-loopback]
      [--require-countersigned-through <sequence>] [--witness-save <dir>] [--witness-resume <dir>]
--public-key is the operator's gateway key, pinned out of band; --witness-key a witness key
the reader pinned; --statements statements the reader kept, read when a witness named cannot
be reached or answers outside its form; --out a new directory the fetched statements, head and
key are written to; --witness-save and --witness-resume directories of continuations, one file
for each witness named, by its trail, origin and key identifier.`

// The reading's bounds: an answer of the witness's taken whole within these,
// and the statements a reading takes (SPEC.md §8.7).
const (
	witnessFetchTimeout     = 30 * time.Second
	witnessFetchPage        = 1000
	maxWitnessSmallAnswer   = 64 << 10
	witnessFetchRuntimeTime = 10 * time.Minute
)

// The fixed sentences of the reading (ADR-0014, determination 4).
const (
	sentenceNoWitness   = "No receipt names a witness for this trail."
	sentenceNamedAt     = "The operator's gateway named this witness for this trail under its own key at %s; that is not a statement of the witness."
	sentenceServedKey   = "The key was served at an origin the operator's gateway named, so this reading is as independent of the operator as the operator's choice of witness."
	sentenceUnreachable = "The witness the receipts name could not be reached."
	sentenceRefused     = "The witness the receipts name holds nothing for this trail."
	sentenceRefusedRead = "The witness the receipts name refused the read; its answer is given as it gave it, and nothing is credited."
	sentenceNotOfForm   = "The witness the receipts name answered outside its form (%s), so nothing it answered was read."
	sentenceNoPin       = "No key the reader pinned is the one the receipts name, so nothing was read."
	sentenceNoneHeld    = "The reader holds no statements of this witness, so nothing was read."
	sentenceKeyNotNamed = "The origin the receipts name serves another key than the one they name, or none the key rule takes, so nothing from it was read."
	sentenceOriginHTTP  = "The origin the receipts name is not https, and is read over http only at a loopback address and only when the reader asks (--allow-loopback), so nothing was read."
)

// The outcomes of reading one witness named.
const (
	fetchRead          = "read"
	fetchUnreachable   = "unreachable"
	fetchNotOfForm     = "answer-not-of-form"
	fetchRefused       = "refused"
	fetchKeyNotNamed   = "witness-key-not-named"
	fetchOriginRefused = "witness-origin-refused"
)

// witnessFetchOptions is the command line.
type witnessFetchOptions struct {
	store, registry, authority, publicKey, decisionRecords string
	record, trail, runtime, out                            string
	witnessKeys, statements                                []string
	allowLoopback                                          bool
	// save and resume are directories of continuations, one file for
	// each witness named (continuationName).
	requireThrough, save, resume string
}

// witnessFetchReport is what the command prints: the record's trail, and a
// reading of each witness the receipts name for it.
type witnessFetchReport struct {
	Trail     string                `json:"trail"`
	Witnesses []witnessFetchReading `json:"witnesses"`
	Sentences []string              `json:"sentences,omitempty"`
}

// witnessFetchReading is one witness named, read or not, and why.
type witnessFetchReading struct {
	Origin  string   `json:"origin"`
	KeyID   string   `json:"keyId"`
	NamedAt []string `json:"namedAt"`
	// Key is where the key came from: "pinned", "served", or null when no
	// key was taken.
	Key     *string `json:"key"`
	Outcome string  `json:"outcome"`
	// Head is whether a head the witness served was handed to the runtime:
	// a reading with one is current, without one historical.
	Head bool `json:"head"`
	// Refusal is the witness's own answer, verbatim, when it refused, and
	// at which read.
	Refusal *witnessFetchRefusal `json:"refusal,omitempty"`
	// Continuation is the name of this witness's continuation file in the
	// directories --witness-resume and --witness-save name, when either is
	// given.
	Continuation string   `json:"continuation,omitempty"`
	Sentences    []string `json:"sentences"`
	// Report is the runtime's report, its bytes as it wrote them, and Exit
	// its exit status; both null when the runtime was not run.
	Report json.RawMessage `json:"report"`
	Exit   *int            `json:"exit"`
}

// witnessFetchRefusal is a witness's refusal as it gave it, and the read it
// refused: "publickey", "head" or "statements".
type witnessFetchRefusal struct {
	At     string `json:"at"`
	Status int    `json:"status"`
	Reason string `json:"reason"`
	Error  string `json:"error"`
}

// witnessRuntime runs the runtime with arguments and gives its standard
// output and exit status; a test stands in another.
var witnessRuntime = func(path string, args []string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), witnessFetchRuntimeTime)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return stdout.Bytes(), exit.ExitCode(), nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("the runtime could not be run: %v", err)
	}
	return stdout.Bytes(), 0, nil
}

// witnessHTTP is the client the reader fetches with: no redirect followed,
// no token sent, each answer within its time.
var witnessHTTP = &http.Client{
	Timeout: witnessFetchTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func parseWitnessFetch(args []string) (witnessFetchOptions, error) {
	var o witnessFetchOptions
	single := map[string]*string{
		"--store": &o.store, "--registry": &o.registry, "--authority": &o.authority, "--public-key": &o.publicKey,
		"--decision-records": &o.decisionRecords, "--record": &o.record, "--trail": &o.trail, "--runtime": &o.runtime,
		"--out": &o.out, "--require-countersigned-through": &o.requireThrough, "--witness-save": &o.save, "--witness-resume": &o.resume,
	}
	repeated := map[string]*[]string{"--witness-key": &o.witnessKeys, "--statements": &o.statements}
	given := map[string]bool{}
	for i := 0; i < len(args); i++ {
		name := args[i]
		if name == "--allow-loopback" {
			if o.allowLoopback {
				return o, errors.New("--allow-loopback is given twice")
			}
			o.allowLoopback = true
			continue
		}
		into, isSingle := single[name]
		list, isRepeated := repeated[name]
		if !isSingle && !isRepeated {
			return o, fmt.Errorf("unknown argument %q", name)
		}
		if i+1 >= len(args) || args[i+1] == "" {
			return o, fmt.Errorf("%s needs a value", name)
		}
		i++
		if isRepeated {
			*list = append(*list, args[i])
			continue
		}
		if given[name] {
			return o, fmt.Errorf("%s is given twice", name)
		}
		given[name] = true
		*into = args[i]
	}
	for _, name := range []string{"--store", "--registry", "--authority", "--public-key", "--record", "--trail", "--runtime", "--out"} {
		if !given[name] {
			return o, fmt.Errorf("%s is required", name)
		}
	}
	// The runtime is named by its path, never found by name on a search
	// path: the program that reads the chain is the one the reader chose.
	if !strings.ContainsRune(o.runtime, filepath.Separator) && !strings.ContainsRune(o.runtime, '/') {
		return o, errors.New("--runtime names the runtime by its path, not by a name to search for")
	}
	if o.requireThrough != "" {
		if n, err := strconv.ParseInt(o.requireThrough, 10, 64); err != nil || n < 1 || strconv.FormatInt(n, 10) != o.requireThrough {
			return o, errors.New("--require-countersigned-through is a sequence, an integer from 1")
		}
	}
	return o, nil
}

// continuationName is the file, in the directories --witness-resume and
// --witness-save name, that holds one witness's continuation: one for each
// {trail, origin, keyId}, so that after a change of witness each reading
// resumes from and saves its own, never another witness's.
func continuationName(named witnessTriple) string {
	sum := sha256.Sum256([]byte(named.Trail + "\n" + named.Origin + "\n" + named.KeyID))
	return hex.EncodeToString(sum[:]) + ".continuation"
}

// continuationDirectories holds --witness-resume to a directory that is
// there and makes --witness-save's when it is not.
func continuationDirectories(o witnessFetchOptions) error {
	if o.resume != "" {
		if info, err := os.Stat(o.resume); err != nil || !info.IsDir() {
			return fmt.Errorf("--witness-resume names a directory of continuations, and %s is not one", o.resume)
		}
	}
	if o.save != "" {
		if err := os.MkdirAll(o.save, 0o700); err != nil {
			return fmt.Errorf("--witness-save: %v", err)
		}
		if info, err := os.Stat(o.save); err != nil || !info.IsDir() {
			return fmt.Errorf("--witness-save names a directory of continuations, and %s is not one", o.save)
		}
	}
	return nil
}

// cmdWitnessFetch is `gateway witness fetch`. It exits 0 whenever it gave a
// report, whatever the report says (SPEC.md §5a.2: the verdict is the
// JSON), 1 when it could not give one, and 2 for its usage.
func cmdWitnessFetch(args []string, stdout, stderr io.Writer) int {
	o, err := parseWitnessFetch(args)
	if err != nil {
		fmt.Fprintf(stderr, "witness fetch: %v\n%s\n", err, witnessFetchUsage)
		return 2
	}
	report, err := witnessFetch(o)
	if err != nil {
		fmt.Fprintln(stderr, "witness fetch:", err)
		return 1
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	// the runtime's report is written as it wrote it, never re-escaped
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(stderr, "witness fetch:", err)
		return 1
	}
	stdout.Write(out.Bytes())
	return 0
}

// witnessFetch is the reading of every witness the receipts name for the
// record's trail.
func witnessFetch(o witnessFetchOptions) (*witnessFetchReport, error) {
	pins, err := readWitnessPins(o.witnessKeys)
	if err != nil {
		return nil, err
	}
	trail, err := witnessFetchTrail(o.record)
	if err != nil {
		return nil, err
	}
	if err := makeFetchOut(o.out); err != nil {
		return nil, err
	}
	if err := continuationDirectories(o); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(o.publicKey)
	if err != nil {
		return nil, fmt.Errorf("--public-key: %v", err)
	}
	gatewayKey, err := readPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("--public-key: %v", err)
	}
	verdict, err := verifyWithRegistryAndRecords(o.store, o.registry, o.authority, o.decisionRecords, gatewayKey)
	if err != nil {
		return nil, fmt.Errorf("the receipts could not be verified: %v", err)
	}
	// A reader takes the witnesses only from a verdict it acts on (SPEC.md
	// §5a.1), store-wide.
	if !verdict.OK {
		return nil, errors.New("the receipts do not verify (ok is false), and a witness is taken only from a verdict a reader acts on (SPEC.md §5a.1); nothing was read")
	}
	report := &witnessFetchReport{Trail: trail, Witnesses: []witnessFetchReading{}}
	for _, named := range verdict.Witnesses {
		if named.Trail != trail {
			continue
		}
		dir := filepath.Join(o.out, strconv.Itoa(len(report.Witnesses)+1))
		if err := os.Mkdir(dir, 0o700); err != nil {
			return nil, err
		}
		reading, err := readNamedWitness(o, named, verdict.namedAt[named], pins, dir)
		if err != nil {
			return nil, err
		}
		report.Witnesses = append(report.Witnesses, reading)
	}
	if len(report.Witnesses) == 0 {
		report.Sentences = []string{sentenceNoWitness}
	}
	return report, nil
}

// readWitnessPins reads the witness keys the reader pinned, each held to the
// key rule (SPEC.md §8.4) before anything is read.
func readWitnessPins(paths []string) ([][]byte, error) {
	var pins [][]byte
	for _, path := range paths {
		key, err := readWitnessKeyFile(path)
		if err != nil {
			return nil, fmt.Errorf("--witness-key %s: %v", path, err)
		}
		if refusal := witnessKeyRefusal(key); refusal != "" {
			return nil, fmt.Errorf("--witness-key %s: the key rule refuses it (%s)", path, refusal)
		}
		pins = append(pins, key)
	}
	return pins, nil
}

// witnessFetchTrail is the trail of the record the reader holds: one line,
// a runtime evaluation record whose trail is 32 lowercase hexadecimal
// characters.
func witnessFetchTrail(path string) (string, error) {
	data, err := readBounded(path, maxWitnessSmallAnswer<<4)
	if err != nil {
		return "", fmt.Errorf("--record: %v", err)
	}
	data = bytes.TrimSuffix(data, []byte{'\n'})
	trail := recordTrail(data)
	if trail == "" {
		return "", errors.New("--record: the record is not a runtime evaluation record of a trail: it names no trail of 32 lowercase hexadecimal characters")
	}
	return trail, nil
}

// makeFetchOut makes the directory the reading writes its files to: a new
// one, or one that is there and empty.
func makeFetchOut(dir string) error {
	if err := os.Mkdir(dir, 0o700); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("--out: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("--out: %v", err)
	}
	if len(entries) > 0 {
		return fmt.Errorf("--out: %s is not empty", dir)
	}
	return nil
}

// readNamedWitness reads one witness named for the trail (ADR-0014,
// determination 4, steps 2 to 5).
func readNamedWitness(o witnessFetchOptions, named witnessTriple, namedAt []string, pins [][]byte, dir string) (witnessFetchReading, error) {
	reading := witnessFetchReading{
		Origin: named.Origin, KeyID: named.KeyID, NamedAt: namedAt,
		Sentences: []string{fmt.Sprintf(sentenceNamedAt, strings.Join(namedAt, ", "))},
	}
	done := func(outcome string, sentences ...string) (witnessFetchReading, error) {
		reading.Outcome = outcome
		reading.Sentences = append(reading.Sentences, sentences...)
		return reading, nil
	}
	// Step 2: https, or http on loopback when the reader asks.
	if !strings.HasPrefix(named.Origin, "https://") && !(o.allowLoopback && strings.HasPrefix(named.Origin, "http://")) {
		return done(fetchOriginRefused, sentenceOriginHTTP)
	}
	// Step 3: the reader's pin whose identifier is the one named; never the
	// receipt's, which names a key and carries none.
	var key []byte
	for _, pin := range pins {
		if keyIDFor(pin) == named.KeyID {
			key = pin
			reading.Key = keySource("pinned")
			break
		}
	}
	if key == nil {
		served, answer := servedWitnessKey(named)
		switch answer.outcome {
		case fetchUnreachable:
			return done(fetchUnreachable, sentenceUnreachable, sentenceNoPin)
		case fetchNotOfForm:
			return done(fetchNotOfForm, fmt.Sprintf(sentenceNotOfForm, answer.why), sentenceNoPin)
		case fetchRefused:
			reading.Refusal = answer.refusal
			return done(fetchRefused, sentenceRefusedRead)
		case fetchKeyNotNamed:
			return done(fetchKeyNotNamed, sentenceKeyNotNamed)
		}
		key = served
		reading.Key = keySource("served")
		reading.Sentences = append(reading.Sentences, sentenceServedKey)
	}
	keyPath := filepath.Join(dir, "witness-key")
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		return reading, err
	}
	// This witness's own continuation, by {trail, origin, keyId}: resumed
	// from when the reader holds one, saved to when it asks.
	var resume, save string
	if o.resume != "" || o.save != "" {
		reading.Continuation = continuationName(named)
	}
	if o.resume != "" {
		if _, err := os.Stat(filepath.Join(o.resume, reading.Continuation)); err == nil {
			resume = filepath.Join(o.resume, reading.Continuation)
		}
	}
	if o.save != "" {
		save = filepath.Join(o.save, reading.Continuation)
	}
	// Step 4: the head, then the statements from index 0 or after the
	// continuation, with no token and no redirect. A refusal of any of these
	// reads ends the reading, quoted, with nothing credited and the runtime
	// not run; no answer, or an answer outside its form, leaves the reader
	// what it holds.
	head := fetchWitnessHead(named)
	answer := head
	var statements witnessFetchAnswer
	if head.outcome == fetchRead {
		from, err := resumeIndex(resume)
		if err != nil {
			return reading, err
		}
		statements = fetchWitnessStatements(named, from)
		answer = statements
	}
	if answer.outcome == fetchRefused {
		reading.Refusal = answer.refusal
		if answer.refusal.Reason == "unknown-trail" {
			return done(fetchRefused, sentenceRefused)
		}
		return done(fetchRefused, sentenceRefusedRead)
	}
	args := []string{"audit", "verify", "--format", "json", "--trail", o.trail, "--witness-key", keyPath}
	if answer.outcome == fetchRead {
		statementsPath, headPath := filepath.Join(dir, "statements.jsonl"), filepath.Join(dir, "head.jsonl")
		if err := os.WriteFile(statementsPath, statements.body, 0o600); err != nil {
			return reading, err
		}
		if err := os.WriteFile(headPath, head.body, 0o600); err != nil {
			return reading, err
		}
		args = append(args, "--witness", statementsPath, "--witness-head", headPath)
		reading.Head = true
	} else {
		// No answer, or an answer outside its form: the statements the
		// reader kept, under its pin, read as far as supplied; with no pin
		// there is no key, and nothing is read.
		if answer.outcome == fetchUnreachable {
			reading.Sentences = append(reading.Sentences, sentenceUnreachable)
		} else {
			reading.Sentences = append(reading.Sentences, fmt.Sprintf(sentenceNotOfForm, answer.why))
		}
		if reading.Key == nil || *reading.Key != "pinned" {
			reading.Key = nil
			os.Remove(keyPath)
			return done(answer.outcome, sentenceNoPin)
		}
		if len(o.statements) == 0 {
			return done(answer.outcome, sentenceNoneHeld)
		}
		for _, held := range o.statements {
			args = append(args, "--witness", held)
		}
		reading.Outcome = answer.outcome
	}
	if o.requireThrough != "" {
		args = append(args, "--require-countersigned-through", o.requireThrough)
	}
	if resume != "" {
		args = append(args, "--witness-resume", resume)
	}
	if save != "" {
		args = append(args, "--witness-save", save)
	}
	// Step 5: the runtime's reading, which is the reading.
	out, exit, err := witnessRuntime(o.runtime, args)
	if err != nil {
		return reading, err
	}
	if exit != 0 && exit != 1 || !json.Valid(out) {
		return reading, fmt.Errorf("the runtime gave no report (exit %d)", exit)
	}
	reading.Report = json.RawMessage(bytes.TrimSpace(out))
	reading.Exit = &exit
	if reading.Outcome == "" {
		reading.Outcome = fetchRead
	}
	return reading, nil
}

func keySource(s string) *string { return &s }

// witnessFetchAnswer is what one read of the witness's came to: read, with
// its body; refused, with the refusal as given; unreachable, when no
// answer came; or an answer outside its form, and why.
type witnessFetchAnswer struct {
	outcome string
	body    []byte
	refusal *witnessFetchRefusal
	why     string
}

// classifyWitnessAnswer is a read's answer: no answer is unreachable; a
// status other than 200 answered as the witness answers a refusal (SPEC.md
// §6, "Answers": application/json, an object whose reason and error are
// strings) is a refusal, its status, reason and sentence kept as given; a
// 200 of the type the read expects is read, its body for the caller to hold
// to its form; anything else -- a redirect, another status or type, a body
// past its bound -- is an answer outside its form.
func classifyWitnessAnswer(at string, status int, contentType string, body []byte, err error, want string) witnessFetchAnswer {
	switch {
	case errors.Is(err, errPastBound):
		return witnessFetchAnswer{outcome: fetchNotOfForm, why: "the " + at + " answer is past its bound"}
	case err != nil:
		return witnessFetchAnswer{outcome: fetchUnreachable}
	case status == http.StatusOK && contentType == want:
		return witnessFetchAnswer{outcome: fetchRead, body: body}
	case status != http.StatusOK && contentType == "application/json":
		var refusal struct {
			Reason *string `json:"reason"`
			Error  *string `json:"error"`
		}
		if json.Unmarshal(body, &refusal) == nil && refusal.Reason != nil && refusal.Error != nil && *refusal.Reason != "" {
			return witnessFetchAnswer{outcome: fetchRefused, refusal: &witnessFetchRefusal{At: at, Status: status, Reason: *refusal.Reason, Error: *refusal.Error}}
		}
	}
	return witnessFetchAnswer{outcome: fetchNotOfForm, why: fmt.Sprintf("the %s answer is status %d of type %q", at, status, contentType)}
}

// servedWitnessKey is the key the named origin serves at /publickey, held to
// the key rule and to the identifier the receipts name: the answer
// classified as every read's is (classifyWitnessAnswer), and
// witness-key-not-named for a key the rule refuses or of another
// identifier.
func servedWitnessKey(named witnessTriple) ([]byte, witnessFetchAnswer) {
	status, contentType, body, err := witnessGet(named.Origin+"/publickey", maxWitnessSmallAnswer)
	answer := classifyWitnessAnswer("publickey", status, contentType, body, err, "application/json")
	if answer.outcome != fetchRead {
		return nil, answer
	}
	var document struct {
		PublicKey string `json:"publicKey"`
	}
	if json.Unmarshal(body, &document) != nil || !isLowerHexOfLen(document.PublicKey, 64) {
		return nil, witnessFetchAnswer{outcome: fetchNotOfForm, why: "the publickey answer names no key of 64 lowercase hexadecimal characters"}
	}
	key, _ := hex.DecodeString(document.PublicKey)
	if witnessKeyRefusal(key) != "" || keyIDFor(key) != named.KeyID {
		return nil, witnessFetchAnswer{outcome: fetchKeyNotNamed}
	}
	return ed25519.PublicKey(key), answer
}

// statementLinesOfForm is whether a body is statement lines as a witness
// serves them (SPEC.md §6): each of §8.2's form, ended by a newline, none
// empty. It holds the form and nothing else: a signature, a key and a trail
// are the runtime's to read, and their findings stay its own.
func statementLinesOfForm(body []byte) bool {
	if len(body) > 0 && body[len(body)-1] != '\n' {
		return false
	}
	for rest := body; len(rest) > 0; {
		i := bytes.IndexByte(rest, '\n')
		if _, ok := parseWitnessStatement(rest[:i]); !ok {
			return false
		}
		rest = rest[i+1:]
	}
	return true
}

// fetchWitnessHead is the trail's head as the witness serves it, held to its
// form: exactly one statement line of §8.2's form.
func fetchWitnessHead(named witnessTriple) witnessFetchAnswer {
	status, contentType, body, err := witnessGet(named.Origin+"/witness/trails/"+named.Trail+"/head", maxWitnessSmallAnswer)
	answer := classifyWitnessAnswer("head", status, contentType, body, err, "application/jsonl")
	if answer.outcome == fetchRead && (bytes.Count(body, []byte{'\n'}) != 1 || !statementLinesOfForm(body)) {
		return witnessFetchAnswer{outcome: fetchNotOfForm, why: "the head is not one statement line of SPEC.md §8.2's form"}
	}
	return answer
}

// fetchWitnessStatements is the trail's statements from index from, a page
// at a time until a page is short, within SPEC.md §8.7's bounds: at most
// the statements and the bytes one reading takes, past which the runtime
// refuses the reading rather than read part of it. A refusal of any page,
// the first or a later one, is the answer, and what the pages before it
// gave is not read.
func fetchWitnessStatements(named witnessTriple, from int64) witnessFetchAnswer {
	var all []byte
	count := 0
	for {
		url := fmt.Sprintf("%s/witness/trails/%s/statements?from=%d&limit=%d", named.Origin, named.Trail, from, witnessFetchPage)
		status, contentType, body, err := witnessGet(url, maxWitnessBytes-len(all))
		answer := classifyWitnessAnswer("statements", status, contentType, body, err, "application/jsonl")
		if answer.outcome != fetchRead {
			return answer
		}
		if !statementLinesOfForm(body) {
			return witnessFetchAnswer{outcome: fetchNotOfForm, why: "a statements page is not statement lines of SPEC.md §8.2's form"}
		}
		lines := bytes.Count(body, []byte{'\n'})
		all = append(all, body...)
		count += lines
		from += int64(lines)
		if lines < witnessFetchPage || count > maxWitnessStatements {
			return witnessFetchAnswer{outcome: fetchRead, body: all}
		}
	}
}

// errPastBound is an answer longer than the read takes.
var errPastBound = errors.New("an answer past its bound")

// witnessGet is one GET of the witness's, with no token, no redirect
// followed, and the body read whole within its bound.
func witnessGet(url string, limit int) (int, string, []byte, error) {
	resp, err := witnessHTTP.Get(url)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return 0, "", nil, err
	}
	if len(body) > limit {
		return 0, "", nil, errPastBound
	}
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	return resp.StatusCode, mediaType, body, nil
}

// resumeIndex is the index after the last statement a continuation the
// reader's own earlier reading saved holds, or 0 with none: the reading
// then fetches only what follows it, as the runtime reads only that. The
// continuation is the runtime's -- {"continuationVersion": "1", "last",
// "latestCheckpoint"}, each a statement as signed -- and this reader takes
// last's index from it and nothing else; the runtime checks the rest.
func resumeIndex(path string) (int64, error) {
	if path == "" {
		return 0, nil
	}
	data, err := readBounded(path, maxWitnessSmallAnswer)
	if err != nil {
		return 0, fmt.Errorf("--witness-resume: %v", err)
	}
	refusal := errors.New("--witness-resume: the continuation is not one this reader can read the last statement's index from")
	v, err := parseJSON(bytes.TrimSpace(data))
	continuation, isObject := v.(*vObject)
	if err != nil || !isObject {
		return 0, refusal
	}
	lastV, _ := continuation.get("last")
	last, isObject := lastV.(*vObject)
	if !isObject {
		return 0, refusal
	}
	index, ok := witnessInteger(last, "index", 0)
	if !ok {
		return 0, refusal
	}
	return index + 1, nil
}
