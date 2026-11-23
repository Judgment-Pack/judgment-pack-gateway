package main

// The refusal journal of each scope (ADR-0059, accepted with conditions).
// The scope identifiers, subjects and tokens are the synthetic ones of
// limits_serve_test.go.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// refusalLimits gives every scope a request rate the tests never reach.
func refusalLimits() *limitsConfig {
	e := limitEntry{scope: limitValues{requestsPerMinute: 60000, burst: 10000}}
	return &limitsConfig{beforeScope: 64, byDefault: &e, scopes: map[string]limitEntry{}}
}

// refusalStderr is a stderr the writer and the test share.
type refusalStderr struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *refusalStderr) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *refusalStderr) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// refusalSetup is limitsSetup with the journals of the filesystem kind on.
func refusalSetup(t *testing.T, cfg *limitsConfig) (*limitsHarness, *refusalJournals, *refusalStderr) {
	t.Helper()
	h := limitsSetup(t, cfg)
	stderr := &refusalStderr{}
	if err := h.g.openRefusalJournals(&refusalJournalConfig{maxBytes: refusalDefaultCap}, stderr); err != nil {
		t.Fatal(err)
	}
	j := h.g.refusals
	j.start()
	t.Cleanup(j.stop)
	return h, j, stderr
}

// wireJournals puts j in front of the harness's limiter and handler.
func wireJournals(h *limitsHarness, j *refusalJournals) {
	for key, s := range j.scopes {
		if held := h.g.limiter.scopes[key]; held != nil {
			held.journal = s
		}
	}
	h.g.refusals = j
}

// refusalBodies are the bodies of a scope's journal on the filesystem kind.
func refusalBodies(t *testing.T, storeRoot, scopeKey string) []*vObject {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(storeRoot, journalsDir, refusalJournalName(scopeKey)+".jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	lines, torn := journalLines(data)
	if torn != 0 {
		t.Fatalf("a torn tail of %d bytes", torn)
	}
	var out []*vObject
	for _, line := range lines {
		v, err := parseRecordJSON(line)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := v.(*vObject).get("body")
		out = append(out, body.(*vObject))
	}
	return out
}

// answerOf is everything a caller reads of an answer: its status, its
// headers but Date, how its length is sent, and its body's bytes.
func answerOf(t *testing.T, h *limitsHarness, path, body, who string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if who != "" {
		req.Header.Set("Authorization", "Bearer "+h.tokens[who])
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var names []string
	for name := range resp.Header {
		if name != "Date" {
			names = append(names, name+": "+strings.Join(resp.Header[name], ", "))
		}
	}
	sort.Strings(names)
	return fmt.Sprintf("%d\n%s\nlength %d %v\n%s", resp.StatusCode, strings.Join(names, "\n"), resp.ContentLength, resp.TransferEncoding, raw)
}

type refusalCase struct {
	path, body, who string
	// scope and reason the entry is journaled under; "" for none
	scope, reason string
}

// refusalCases are refusals of every route, journaled and not.
var refusalCases = []refusalCase{
	{"/acquire", `{"session":"s-1","source":"scoped-a","bogus":true}`, "a", callerScopeA, "body"},
	// a source the caller does not reach and one that is not are one answer
	{"/acquire", acquireBodyFor("s-2", "no-such-source", ""), "a", callerScopeA, "scope"},
	{"/acquire", acquireBodyFor("s-3", "scoped-a", callerScopeB), "a", callerScopeA, "scope"},
	// a caller of A naming B's source: charged to A, never to B
	{"/acquire", acquireBodyFor("s-4", "scoped-b", callerScopeB), "a", callerScopeA, "scope"},
	{"/seal", `{"session":"s-none"}`, "a", callerScopeA, "session"},
	{"/seal", `{"session":"s-1","extra":1}`, "a", callerScopeA, "body"},
	{"/act", `{"session":"s-unknown"}`, "none", unscopedMarker, "platform"},
	{"/acquire", `{"session":"s-5","source":"plain","bogus":true}`, "none", unscopedMarker, "body"},
	// not journaled: no caller, a caller of several scopes whose scope is
	// not established, and a route outside the lists
	{"/acquire", acquireBodyFor("s-6", "scoped-a", callerScopeA), "bad", "", ""},
	{"/acquire", acquireBodyFor("s-7", "no-such-source", ""), "all", "", ""},
	{"/acquire", `{"session":"s-8","source":"scoped-a","bogus":true}`, "ab", "", ""},
	{"/verify", `{}`, "a", "", ""},
	// refused before the charge: a write route this caller does not reach
	{"/act", `{"session":"s-unknown"}`, "a", "", ""},
}

// failingRefusalStore keys every journal and appends nothing.
type failingRefusalStore struct{}

func (failingRefusalStore) key(string) ([]byte, bool, error) { return make([]byte, 32), false, nil }
func (failingRefusalStore) append(*refusalScope, func(refusalEnd) ([]byte, error)) error {
	return errors.New("the disk refused the write")
}
func (failingRefusalStore) close() {}

// Every refusal is answered byte for byte as without the member, with the
// journal on and with its every write failing; each journaled one is one
// entry in the charged scope's journal alone, and the others none
// (ADR-0059 §4, §5, §10; condition C10).
func TestRefusalJournalLeavesEveryAnswerAsItWas(t *testing.T) {
	h, j, stderr := refusalSetup(t, refusalLimits())
	registry, _ := os.ReadFile(filepath.Join(h.root, "registry.jsonl"))
	posture := answerOf(t, h, "/posture", "", "a")

	h.g.refusals = nil
	var off []string
	for _, c := range refusalCases {
		off = append(off, answerOf(t, h, c.path, c.body, c.who))
	}
	h.g.refusals = j
	for i, c := range refusalCases {
		if on := answerOf(t, h, c.path, c.body, c.who); on != off[i] {
			t.Errorf("%s by %s: with the journal\n%s\nwithout\n%s", c.path, c.who, on, off[i])
		}
	}
	failing, err := newRefusalJournals(&refusalJournalConfig{maxBytes: refusalDefaultCap}, limitScopeKeys(h.g.sources), failingRefusalStore{}, h.g.store.signing.key, h.g.provenanceKeys, stderr)
	if err != nil {
		t.Fatal(err)
	}
	failing.start()
	wireJournals(h, failing)
	for i, c := range refusalCases {
		if on := answerOf(t, h, c.path, c.body, c.who); on != off[i] {
			t.Errorf("%s by %s: with every write failing\n%s\nwithout\n%s", c.path, c.who, on, off[i])
		}
	}
	failing.stop()
	j.stop()

	want := map[string][]string{}
	for _, c := range refusalCases {
		if c.scope != "" {
			want[c.scope] = append(want[c.scope], c.path+" "+c.reason)
		}
	}
	for key := range limitScopeKeys(h.g.sources) {
		var got []string
		for _, b := range refusalBodies(t, h.g.storeRoot, key) {
			route, _ := memberString(b, "route")
			reason, _ := memberString(b, "reason")
			if scope, _ := memberString(b, "scope"); scope != key {
				t.Errorf("journal of %s holds an entry of %s", key, scope)
			}
			got = append(got, route+" "+reason)
		}
		if strings.Join(got, "|") != strings.Join(want[key], "|") {
			t.Errorf("journal of %s:\n got %v\nwant %v", key, got, want[key])
		}
	}
	if n := failing.scopes[callerScopeA].tally[dropWriteFailed].Load(); n < 1 {
		t.Errorf("the failing writes counted %d write-failed", n)
	}
	if !strings.Contains(stderr.String(), "records were not written at stop") {
		t.Errorf("stderr: %q", stderr.String())
	}
	// the key is in no stderr line; the registry and posture do not move
	key, _ := os.ReadFile(filepath.Join(h.g.storeRoot, journalsDir, refusalJournalName(callerScopeA)+".key"))
	if len(key) != 65 || strings.Contains(stderr.String(), strings.TrimSpace(string(key))) {
		t.Errorf("the key file %q, or stderr holds it", key)
	}
	if again, _ := os.ReadFile(filepath.Join(h.root, "registry.jsonl")); !bytes.Equal(again, registry) {
		t.Error("a refusal moved the registry")
	}
	// ADR-0057's own count of unauthenticated refusals moves, and nothing else
	unauthenticated := regexp.MustCompile(`"unauthenticatedRefusals":[0-9]+`)
	again := answerOf(t, h, "/posture", "", "a")
	if unauthenticated.ReplaceAllString(again, "") != unauthenticated.ReplaceAllString(posture, "") || !strings.Contains(posture, protectionRefusalJournal) {
		t.Errorf("posture moved or lacks the line:\n%s\n%s", posture, again)
	}
}

// A blocked writer delays no answer of A's or B's, and B's full queue
// refuses B's offer, never A's: asserted by order (ADR-0059 §10).
func TestRefusalJournalAnswersNeverWaitOnTheWriter(t *testing.T) {
	h, j, _ := refusalSetup(t, refusalLimits())
	gate, signing := make(chan struct{}), make(chan struct{}, 1)
	j.beforeSign = func() {
		select {
		case signing <- struct{}{}:
		default:
		}
		<-gate
	}
	if code, _, _ := h.post(t, "/seal", `{"session":"s-none"}`, "a"); code != http.StatusNotFound && code/100 != 4 {
		t.Fatalf("the first refusal: %d", code)
	}
	select {
	case <-signing:
	case <-time.After(10 * time.Second):
		t.Fatal("the writer never signed")
	}
	a, b := j.scopes[callerScopeA], j.scopes[callerScopeB]
	who := &caller{issuer: "issuer", subject: subjectB, tokenDigest: "sha256:" + strings.Repeat("0", 64)}
	for len(b.queue) < refusalQueueBound {
		j.handOff(b, "/seal", refusalNote{reason: "session"}, 404, who, nil, time.Now())
	}
	before := b.tally[dropQueueFull].Load()
	for i := 0; i < 2; i++ {
		answerOf(t, h, "/seal", `{"session":"s-none"}`, "a")
		answerOf(t, h, "/seal", `{"session":"s-none"}`, "b")
	}
	// the hand-off follows the flushed answer, so a caller can read the
	// answer before it is made: wait for it, never for the writer
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline) && (len(a.queue) != 2 || b.tally[dropQueueFull].Load() != before+2); {
		time.Sleep(5 * time.Millisecond)
	}
	if len(a.queue) != 2 || b.tally[dropQueueFull].Load() != before+2 {
		t.Errorf("A's queue %d (want 2), B's queue-full %d (want %d)", len(a.queue), b.tally[dropQueueFull].Load(), before+2)
	}
	close(gate)
	j.stop()
	if n := len(refusalBodies(t, h.g.storeRoot, callerScopeA)); n != 3 {
		t.Errorf("A's journal holds %d entries, want 3", n)
	}
}

// A limit refusal is counted in its scope's tally and journaled alone by
// it, never as an entry of its own (ADR-0059 §4).
func TestRefusalJournalCountsALimitRefusalInTheTally(t *testing.T) {
	cfg := refusalLimits()
	cfg.scopes[callerScopeA] = rateOf(1, 1)
	h, j, _ := refusalSetup(t, cfg)
	answerOf(t, h, "/seal", `{"session":"s-none"}`, "a")
	if code, _, _ := h.post(t, "/seal", `{"session":"s-none"}`, "a"); code != http.StatusTooManyRequests {
		t.Fatalf("the second: %d", code)
	}
	j.stop()
	a := j.scopes[callerScopeA]
	a.since = a.since.Add(-time.Minute)
	j.store = refusalFS{root: h.g.storeRoot}
	// the tally reopens the journal the stop closed: close it again, as a
	// platform without flock deletes no file a handle holds
	t.Cleanup(j.closeFiles)
	j.writeTally(a, time.Now())
	bodies := refusalBodies(t, h.g.storeRoot, callerScopeA)
	if len(bodies) != 2 {
		t.Fatalf("%d entries", len(bodies))
	}
	if kind, _ := memberString(bodies[1], "kind"); kind != "tally" || string(canon(refusalMember(bodies[1], "limit"))) != `{"scope-rate":1}` {
		t.Errorf("the tally: %s", canon(bodies[1]))
	}
}

// refusalUnit is a journal of scope A of the filesystem kind, its writer
// driven by the test.
func refusalUnit(t *testing.T, maxBytes int64) (*limitsHarness, *refusalJournals, *refusalScope) {
	t.Helper()
	h := limitsSetup(t, refusalLimits())
	j, err := newRefusalJournals(&refusalJournalConfig{maxBytes: maxBytes}, map[string]bool{callerScopeA: true}, refusalFS{root: h.g.storeRoot}, h.g.store.signing.key, h.g.provenanceKeys, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(j.closeFiles)
	return h, j, j.scopes[callerScopeA]
}

func unitCaller() *caller {
	return &caller{issuer: "https://issuer.test", subject: subjectA, tokenDigest: "sha256:" + strings.Repeat("ab", 32)}
}

// The cap: refusal entries stop at the cap less its sixteenth, the tallies
// take that room, the closing tally says full, and nothing comes after it;
// the journal stays within its cap and verifies (condition C6).
func TestRefusalJournalHoldsItsCapWithAClosingTally(t *testing.T) {
	const maxBytes = 64 << 10
	h, j, s := refusalUnit(t, maxBytes)
	path := filepath.Join(h.g.storeRoot, journalsDir, s.name+".jsonl")
	for i := 0; !s.refusalsFull; i++ {
		if i > 1000 {
			t.Fatal("the refusals never filled")
		}
		j.handOff(s, "/acquire", refusalNote{reason: "body"}, 400, unitCaller(), []byte(`{"n":`+fmt.Sprint(i)+`}`), time.Now())
		j.round()
	}
	info, _ := os.Stat(path)
	if room := int64(maxBytes - maxBytes/16); info.Size() > room || info.Size() < room-int64(journalLineBound) {
		t.Fatalf("the refusals took %d bytes of %d", info.Size(), room)
	}
	j.handOff(s, "/acquire", refusalNote{reason: "body"}, 400, unitCaller(), nil, time.Now())
	j.round()
	if got := s.tally[dropJournalFull].Load(); got != 2 {
		t.Fatalf("journal-full %d, want 2", got)
	}
	for i := 0; !s.closed; i++ {
		if i > 1000 {
			t.Fatal("the journal never closed")
		}
		s.countLimit(limitScopeRate)
		j.writeTally(s, time.Now())
	}
	data, _ := os.ReadFile(path)
	if int64(len(data)) > maxBytes {
		t.Fatalf("the journal is %d bytes, over its cap", len(data))
	}
	lines, _ := journalLines(data)
	if keyID, closed := lastEntryOf(lines[len(lines)-1]); !closed || keyID == "" {
		t.Fatal("the last entry is not the closing tally")
	}
	s.countLimit(limitScopeRate)
	j.writeTally(s, time.Now())
	j.handOff(s, "/acquire", refusalNote{reason: "body"}, 400, unitCaller(), nil, time.Now())
	j.round()
	if again, _ := os.ReadFile(path); !bytes.Equal(again, data) {
		t.Fatal("an entry came after the closing tally")
	}
	keys, _ := h.g.provenanceKeys()
	if f, n, _ := judgeRefusalJournal(data, s.name, keys); f != nil || n != len(lines) {
		t.Fatalf("verify: %v, %d entries", f, n)
	}
}

// The queue: a full one drops the record and counts it, never waiting.
func TestRefusalJournalDropsAndCountsWhereTheQueueIsFull(t *testing.T) {
	_, j, s := refusalUnit(t, refusalDefaultCap)
	for i := 0; i < refusalQueueBound+3; i++ {
		j.handOff(s, "/seal", refusalNote{reason: "session"}, 404, unitCaller(), nil, time.Now())
	}
	if len(s.queue) != refusalQueueBound || s.tally[dropQueueFull].Load() != 3 {
		t.Fatalf("queue %d, queue-full %d", len(s.queue), s.tally[dropQueueFull].Load())
	}
}

// A journal holding entries and no key takes no entry and says so; a key
// earlier in the key walk than the last entry's signs nothing.
func TestRefusalJournalRefusesAMissingKeyAndAKeyGoneBackwards(t *testing.T) {
	h := limitsSetup(t, refusalLimits())
	dir := filepath.Join(h.g.storeRoot, journalsDir)
	name := refusalJournalName(callerScopeA)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	j, err := newRefusalJournals(&refusalJournalConfig{maxBytes: refusalDefaultCap}, map[string]bool{callerScopeA: true}, refusalFS{root: h.g.storeRoot}, h.g.store.signing.key, h.g.provenanceKeys, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(j.closeFiles)
	s := j.scopes[callerScopeA]
	j.handOff(s, "/seal", refusalNote{reason: "session"}, 404, unitCaller(), nil, time.Now())
	if s.secret != nil || len(s.queue) != 0 || s.tally[dropWriteFailed].Load() != 1 || !strings.Contains(stderr.String(), "holds entries and no key") {
		t.Fatalf("a missing key: %q", stderr.String())
	}
	current := h.g.store.signing.key().keyID
	j.keys = func() ([]reachedKey, error) {
		return []reachedKey{{keyID: current}, {keyID: strings.Repeat("f", 32)}}, nil
	}
	if _, err := j.sign(s, refusalEnd{ordinal: 1, lastKeyID: strings.Repeat("f", 32)}, newObject()); err == nil {
		t.Fatal("a key gone backwards signed")
	}
}

// The commitment: equal requests give unequal commitments, the key opens
// each, another key or another body does not, and no unsalted digest of
// the body is it (ADR-0059 §3).
func TestRefusalJournalCommitmentIsSaltedUnderTheScopesKey(t *testing.T) {
	h, j, s := refusalUnit(t, refusalDefaultCap)
	read := []byte(`{"session":"s-1","source":"scoped-a","bogus":true}`)
	for i := 0; i < 2; i++ {
		j.handOff(s, "/acquire", refusalNote{reason: "body"}, 400, unitCaller(), read, time.Now())
		j.round()
	}
	data, _ := os.ReadFile(filepath.Join(h.g.storeRoot, journalsDir, s.name+".jsonl"))
	lines, _ := journalLines(data)
	bodies := refusalBodies(t, h.g.storeRoot, callerScopeA)
	first, _ := memberString(bodies[0], "request")
	second, _ := memberString(bodies[1], "request")
	unsalted := sha256.Sum256(append([]byte(refusalRequestLabel+"/acquire\n"), read...))
	if first == second || first == "sha256:"+hex.EncodeToString(unsalted[:]) {
		t.Fatalf("the commitments %s %s", first, second)
	}
	for _, line := range lines {
		if ok, salt, err := matchRefusalEntry(line, s.secret, "/acquire", read); !ok || err != nil || len(salt) != 32 {
			t.Fatalf("the key does not open its entry: %v", err)
		}
		if ok, _, _ := matchRefusalEntry(line, make([]byte, 32), "/acquire", read); ok {
			t.Fatal("another key opens the entry")
		}
		if ok, _, _ := matchRefusalEntry(line, s.secret, "/acquire", append(read, ' ')); ok {
			t.Fatal("another body opens the entry")
		}
	}
	files, err := refusalJournalFilesIn(h.g.storeRoot)
	if err != nil || len(files) != 1 || bytes.Contains(files[s.name], []byte(hex.EncodeToString(s.secret))) {
		t.Fatalf("the export's journals: %v", err)
	}
}

// Verify: a forged entry, a body of another scope, an operator body in a
// refusal journal and a refusal body in operator, and an order broken
// (ADR-0059 §8).
func TestRefusalJournalVerifyRefusesForgedEntries(t *testing.T) {
	h, j, s := refusalUnit(t, refusalDefaultCap)
	for i := 0; i < 3; i++ {
		j.handOff(s, "/acquire", refusalNote{reason: "body"}, 400, unitCaller(), nil, time.Now())
		j.round()
	}
	keys, _ := h.g.provenanceKeys()
	data, _ := os.ReadFile(filepath.Join(h.g.storeRoot, journalsDir, s.name+".jsonl"))
	lines, _ := journalLines(data)
	if f, n, _ := judgeRefusalJournal(data, s.name, keys); f != nil || n != 3 {
		t.Fatalf("the journal as written: %v", f)
	}
	join := func(ls ...[]byte) []byte { return append(bytes.Join(ls, []byte("\n")), '\n') }
	resign := func(ordinal int64, previous []byte, body *vObject, journal string) []byte {
		line, err := signedJournalEntry(h.g.store.signing.key(), journal, ordinal, journalDigest(previous), "2026-09-12T00:00:02Z", body)
		if err != nil {
			t.Fatal(err)
		}
		return line[:len(line)-1]
	}
	other := refusalBodies(t, h.g.storeRoot, callerScopeA)[1]
	other.set("scope", vString(callerScopeB))
	operatorBody := newObject()
	operatorBody.set("kind", vString("remove-artifact"))
	operatorBody.set("registryFrom", vInt(0))
	operatorBody.set("removalFrom", vInt(0))
	operatorBody.set("by", vString(callerScopeA))
	operatorBody.set("removalBytes", vInt(1))
	operatorBody.set("removalDigest", vString(strings.Repeat("0", 64)))
	flipped := bytes.Clone(lines[1])
	flipped[len(flipped)-3] ^= 1
	for name, c := range map[string]struct {
		data   []byte
		status string
		at     int
	}{
		"forged":         {join(lines[0], flipped, lines[2]), "journal-entry-forged", 1},
		"scope-mismatch": {join(lines[0], resign(1, lines[0], other, s.name)), "journal-entry-forged", 1},
		"kind-crossed":   {join(lines[0], resign(1, lines[0], operatorBody, s.name)), "journal-entry-forged", 1},
		"order":          {join(lines[0], lines[2], lines[1]), "journal-order", 1},
	} {
		f, _, _ := judgeRefusalJournal(c.data, s.name, keys)
		if f == nil || f["status"] != c.status || f["ordinal"] != int64(c.at) {
			t.Errorf("%s: %v", name, f)
		}
	}
	refusalBody := refusalBodies(t, h.g.storeRoot, callerScopeA)[0]
	if _, ok := loadJournalEntry(resign(0, nil, refusalBody, operatorJournal), operatorJournal, keys); ok {
		t.Error("a refusal body loads in the operator journal")
	}
}

// gateway journal name is the name both verifiers and the writer give.
func TestRefusalJournalNameIsTheDerivedOne(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := cmdJournalName([]string{"--scope", callerScopeA}, &out, &errOut); code != 0 || strings.TrimSpace(out.String()) != refusalJournalName(callerScopeA) {
		t.Fatalf("%d %q %q", code, out.String(), errOut.String())
	}
	if name := refusalJournalName(unscopedMarker); !isRefusalJournalName(name) || len(name) != 32 {
		t.Fatalf("%q", name)
	}
	if code := cmdJournalName([]string{"--scope", ""}, &out, &errOut); code != 2 {
		t.Fatalf("a scope of another form: %d", code)
	}
}

// The load: the member's form, its version, identity, a rate for every
// scope (ADR-0059 §6).
func TestRefusalJournalLoadTimeRefusals(t *testing.T) {
	parse := func(text string) error {
		v, err := parseRecordJSON([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		_, err = parseRefusalJournal(v)
		return err
	}
	for text, want := range map[string]error{
		`{}`:                             nil,
		`{"maxBytesPerScope":1048576}`:   nil,
		`{"maxBytesPerScope":1048575}`:   errRefusalJournalCap,
		`{"maxBytesPerScope":1.5e6}`:     errRefusalJournalCap,
		`{"maxBytesPerScope":"1048576"}`: errRefusalJournalCap,
		`{"other":1}`:                    errRefusalJournalForm,
		`[]`:                             errRefusalJournalForm,
	} {
		if err := parse(text); err != want {
			t.Errorf("%s: %v, want %v", text, err, want)
		}
	}
	rj := &refusalJournalConfig{maxBytes: refusalDefaultCap}
	scopes := map[string]bool{callerScopeA: true, unscopedMarker: true}
	if err := holdRefusalJournal(rj, false, refusalLimits(), scopes); err != errRefusalJournalIdentity {
		t.Errorf("no identity: %v", err)
	}
	if err := holdRefusalJournal(rj, true, nil, scopes); err != errRefusalJournalRate {
		t.Errorf("no limits: %v", err)
	}
	partial := &limitsConfig{beforeScope: 1, scopes: map[string]limitEntry{callerScopeA: rateOf(60, 1)}}
	if err := holdRefusalJournal(rj, true, partial, scopes); err != errRefusalJournalRate {
		t.Errorf("a scope with no rate: %v", err)
	}
	if err := holdRefusalJournal(rj, true, refusalLimits(), scopes); err != nil {
		t.Errorf("held: %v", err)
	}
}

// remove-scope takes the journal, its key and its cursor away, and names
// the journal's bytes in its operator entry (ADR-0059 §8).
func TestRefusalJournalRemovalTakesTheJournalAndNamesIt(t *testing.T) {
	h, j, s := refusalUnit(t, refusalDefaultCap)
	j.handOff(s, "/seal", refusalNote{reason: "session"}, 404, unitCaller(), nil, time.Now())
	j.round()
	dir := filepath.Join(h.g.storeRoot, journalsDir)
	if err := os.WriteFile(filepath.Join(dir, s.name+".forwarded"), []byte("0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !journalFilesLock {
		// remove-scope runs with the gateway stopped where there is no
		// flock: the writer holds no file then
		j.closeFiles()
	}
	r, err := holdRefusalRemoval(h.g.storeRoot, callerScopeA)
	if err != nil || len(r.data) == 0 {
		t.Fatalf("hold: %v", err)
	}
	entryBody := func(both bool) *vObject {
		body := removalBody("remove-scope", "operator-one", callerScopeA)
		body.set("registryFrom", vInt(0))
		body.set("removalFrom", vInt(0))
		body.set("removalBytes", vInt(1))
		body.set("removalDigest", vString(strings.Repeat("0", 64)))
		if both {
			describeRefusalRemoval(body, r.data)
		} else {
			body.set("refusalJournalBytes", vInt(int64(len(r.data))))
		}
		return body
	}
	body := entryBody(true)
	if err := r.remove(); err != nil {
		t.Fatal(err)
	}
	r.release()
	for _, suffix := range []string{".jsonl", ".key", ".forwarded"} {
		if _, err := os.Lstat(filepath.Join(dir, s.name+suffix)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s stands: %v", suffix, err)
		}
	}
	if n, _ := recordCount(body, "refusalJournalBytes"); n != int64(len(r.data)) {
		t.Errorf("the entry's bytes %d", n)
	}
	var e journalEntry
	if !e.bodyLoads(body) {
		t.Error("the remove-scope body with both members does not load")
	}
	if e.bodyLoads(entryBody(false)) {
		t.Error("the remove-scope body with one member loads")
	}
}
