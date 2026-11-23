package main

// The refusal journal of each scope (ADR-0059, accepted with conditions):
// a refused request that ADR-0057 charged to a scope, and whose charge took
// that scope's hold, becomes a signed entry in that scope's own journal,
// written after the answer is flushed and never on any answer's path. The
// journal is ADR-0056's envelope with a derived name and two bodies,
// "refusal" and "tally"; one writer for the gateway signs and appends.

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// refusalJournalVersion is the first engine configuration version that
// reads refusalJournal (ADR-0059 §6), after 46 (scope binding) and 47
// (admission read version 2).
const refusalJournalVersion = "48"

const (
	refusalJournalPrefix = "refusal-"
	refusalNameContext   = "judgment-pack-gateway/refusal-journal-name/1:"
	refusalSaltContext   = "judgment-pack-gateway/refusal-salt/1:"
	refusalRequestLabel  = "refusal-request:"
	refusalKeyPrefix     = "refusal-key."
	// refusalQueueBound is each scope's queue (ADR-0059 §5, open question 6)
	refusalQueueBound = 256
	// refusalRecordBound is a record's bound, its body's canonical bytes
	refusalRecordBound = 2048
	// refusalHeldBound is the most of an answer kept until its handler
	// returns; a longer one is written through as it comes
	refusalHeldBound   = 64 << 10
	refusalDefaultCap  = 64 << 20
	refusalLeastCap    = 1 << 20
	refusalMostCap     = 1 << 30
	refusalTallyEvery  = time.Minute
	refusalDrainWithin = 5 * time.Second
	// pgRefusalJournalLockClass is the first key of the two-int4 advisory
	// lock each refusal journal takes on the PostgreSQL kind (condition C7):
	// the gateway's other advisory locks take the one-bigint form, whose keys
	// PostgreSQL keeps apart from these.
	pgRefusalJournalLockClass int64 = 0x52464a4c
)

// The causes a record is dropped for, and the limits a limit refusal is
// counted by (ADR-0059 §3, tally).
const (
	dropQueueFull = iota
	dropWriteFailed
	dropJournalFull
	dropCauses
)

var dropNames = [dropCauses]string{"queue-full", "write-failed", "journal-full"}

var limitCountNames = []string{limitScopeRate, limitScopeInFlight, limitCallerRate, limitCallerInFlight, limitCallers}

// refusalReasons are the closed lists of ADR-0059 §4, by route.
var refusalReasons = map[string]map[string]bool{
	"/acquire": setOf("session", "source", "scope", "trail", "body", "publisher-policy", "grant", "delegation"),
	"/act": setOf("session", "platform", "tool", writeRequestersStep, "arguments", "action-key", "decision", "cites", "approvals",
		"record", "consistency", "policy-bind", "policy-signed", "policy-packs", "policy-reviewed", "policy-outcome", "policy-handoff",
		"receipt-version", "dry-run", "scope-identifier", "delegation", "grant"),
	"/seal": setOf("session", "scope", "body"),
}

func setOf(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// --- configuration (ADR-0059 §6) ---------------------------------------------

// refusalJournalConfig is the refusalJournal member.
type refusalJournalConfig struct {
	maxBytes int64
}

var (
	errRefusalJournalForm     = errors.New("engine configuration: refusalJournal is an object whose one optional member is maxBytesPerScope")
	errRefusalJournalCap      = errors.New("engine configuration: refusalJournal: maxBytesPerScope is an integer from 1048576 to 1073741824, written with no fraction and no exponent")
	errRefusalJournalIdentity = errors.New("engine configuration: refusalJournal needs identity: with no caller authenticated the journal would hold nothing")
	errRefusalJournalRate     = errors.New("engine configuration: refusalJournal needs a request rate for every scope (limits)")
	errRefusalJournalNames    = errors.New("engine configuration: refusalJournal: two scopes give one journal name")
)

// parseRefusalJournal reads the member; the refusals name the member and
// quote no value.
func parseRefusalJournal(v value) (*refusalJournalConfig, error) {
	obj, ok := v.(*vObject)
	if !ok || exactlyMembers(obj, map[string]bool{"maxBytesPerScope": false}, "") != nil {
		return nil, errRefusalJournalForm
	}
	cfg := &refusalJournalConfig{maxBytes: refusalDefaultCap}
	if raw, given := obj.get("maxBytesPerScope"); given {
		n, isInt := raw.(vInt)
		if !isInt || n < refusalLeastCap || n > refusalMostCap {
			return nil, errRefusalJournalCap
		}
		cfg.maxBytes = int64(n)
	}
	return cfg, nil
}

// holdRefusalJournal is the load's check of the member against the rest of
// the configuration: identity, a request rate for every scope, and one
// journal name for each scope.
func holdRefusalJournal(rj *refusalJournalConfig, identity bool, limits *limitsConfig, scopes map[string]bool) error {
	if rj == nil {
		return nil
	}
	if !identity {
		return errRefusalJournalIdentity
	}
	if limits == nil {
		return errRefusalJournalRate
	}
	entries := limits.entries(scopes)
	names := map[string]bool{}
	for key := range scopes {
		if e, ok := entries[key]; !ok || e.scope.requestsPerMinute < 1 {
			return errRefusalJournalRate
		}
		name := refusalJournalName(key)
		if names[name] {
			return errRefusalJournalNames
		}
		names[name] = true
	}
	return nil
}

// --- the name and the commitment (ADR-0059 §1, §3) ---------------------------

// refusalJournalName is the journal of a scope key: "refusal-" and the
// first 12 bytes of SHA-256 over the name's context and the key, each
// half-byte a letter from a (0) to p (15).
func refusalJournalName(scopeKey string) string {
	sum := sha256.Sum256([]byte(refusalNameContext + scopeKey))
	out := make([]byte, 0, 32)
	out = append(out, refusalJournalPrefix...)
	for _, c := range sum[:12] {
		out = append(out, 'a'+c>>4, 'a'+c&0x0f)
	}
	return string(out)
}

// isRefusalJournalName is the form of a refusal journal's name.
func isRefusalJournalName(s string) bool {
	rest, ok := strings.CutPrefix(s, refusalJournalPrefix)
	if !ok || len(rest) != 24 {
		return false
	}
	for i := 0; i < len(rest); i++ {
		if rest[i] < 'a' || rest[i] > 'p' {
			return false
		}
	}
	return true
}

// refusalKeyName is the name K_scope is kept under on the PostgreSQL kind.
func refusalKeyName(journal string) string {
	return refusalKeyPrefix + journalDigest([]byte(journal))
}

// refusalSalt is the salt of an entry: HMAC-SHA-256 under K_scope of the
// salt's context and the nonce's bytes.
func refusalSalt(key, nonce []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(refusalSaltContext))
	mac.Write(nonce)
	return mac.Sum(nil)
}

// refusalCommitment is an entry's request member: SHA-256 over the salt,
// the label, the route, 0x0A and the body bytes read.
func refusalCommitment(salt []byte, route string, read []byte) string {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(refusalRequestLabel + route + "\n"))
	h.Write(read)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// --- the journals of a serving gateway (ADR-0059 §5) -------------------------

// refusalScope is one scope's journal: its queue and counts, which answers
// touch by a non-blocking send and atomic increments alone, and the
// writer's own view of the journal's end.
type refusalScope struct {
	key, name string
	queue     chan *vObject
	secret    []byte // K_scope, read or made at start; nil where missing
	tally     [dropCauses]atomic.Int64
	limits    [5]atomic.Int64
	minute    atomic.Int64

	// the writer's alone
	since        time.Time
	end          refusalEnd
	loaded       bool
	refusalsFull bool
	closed       bool
	file         *os.File
}

// refusalEnd is a journal's end as its lock holder read it.
type refusalEnd struct {
	ordinal   int64
	previous  string
	bytes     int64
	lastKeyID string
	closed    bool
}

// refusalStore is where a kind keeps the journals.
type refusalStore interface {
	// key is the journal's K_scope: read, or made where the journal holds
	// no entry; missing reports a journal holding entries and no key.
	key(name string) (k []byte, missing bool, err error)
	// append runs entry at the journal's end, under its lock, and appends
	// the line it answers; nil appends nothing.
	append(s *refusalScope, entry func(end refusalEnd) ([]byte, error)) error
	close()
}

// refusalJournals is the gateway's journals and its one writer.
type refusalJournals struct {
	cfg    refusalJournalConfig
	scopes map[string]*refusalScope
	order  []*refusalScope
	store  refusalStore
	signer func() *signingKey
	keys   func() ([]reachedKey, error)
	clock  func() time.Time
	stderr io.Writer
	wake   chan struct{}

	// beforeSign, where a test sets it, runs before each signing
	beforeSign func()

	startOnce, stopOnce sync.Once
	stopping            chan struct{}
	done                chan struct{}
	lastMinute          time.Time
}

// newRefusalJournals makes the journals of the scope keys given and reads
// or makes each scope's key, before the gateway serves.
func newRefusalJournals(cfg *refusalJournalConfig, keys map[string]bool, store refusalStore, signer func() *signingKey, walk func() ([]reachedKey, error), stderr io.Writer) (*refusalJournals, error) {
	j := &refusalJournals{cfg: *cfg, scopes: map[string]*refusalScope{}, store: store, signer: signer, keys: walk,
		clock: time.Now, stderr: stderr, wake: make(chan struct{}, 1), stopping: make(chan struct{}), done: make(chan struct{})}
	sorted := make([]string, 0, len(keys))
	for key := range keys {
		sorted = append(sorted, key)
	}
	sort.Strings(sorted)
	now := j.clock()
	for _, key := range sorted {
		s := &refusalScope{key: key, name: refusalJournalName(key), queue: make(chan *vObject, refusalQueueBound), since: now}
		secret, missing, err := store.key(s.name)
		if err != nil {
			return nil, fmt.Errorf("refusal journal: the key of journal %s could not be read or made: %v", s.name, err)
		}
		if missing {
			// a new key would leave the entries unopenable without a word
			fmt.Fprintf(stderr, "refusal journal: journal %s holds entries and no key; its records are not written (write-failed)\n", s.name)
		}
		s.secret = secret
		j.scopes[key] = s
		j.order = append(j.order, s)
	}
	j.lastMinute = now
	return j, nil
}

func (s *refusalScope) drop(cause int) {
	s.tally[cause].Add(1)
	s.minute.Add(1)
}

// countLimit counts a limit refusal of the scope for its tally: an atomic
// increment, after the limiter chose its answer.
func (s *refusalScope) countLimit(limit string) {
	if s == nil {
		return
	}
	for i, name := range limitCountNames {
		if name == limit {
			s.limits[i].Add(1)
			return
		}
	}
}

// refusalNote is what a handler says of its refusal, beside its answer.
type refusalNote struct {
	reason, refusal, outOfScope string
	noDelegation                bool
}

// handOff makes the record of an answered refusal and offers it to its
// scope's queue, never waiting: a full queue drops it and counts it.
func (j *refusalJournals) handOff(s *refusalScope, route string, note refusalNote, status int, who *caller, read []byte, answeredAt time.Time) {
	if s.secret == nil {
		s.drop(dropWriteFailed)
		return
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		s.drop(dropWriteFailed)
		return
	}
	body := newObject()
	body.set("kind", vString("refusal"))
	body.set("scope", vString(s.key))
	body.set("route", vString(route))
	body.set("reason", vString(note.reason))
	if note.refusal != "" {
		body.set("refusal", vString(note.refusal))
		if note.outOfScope != "" {
			body.set("outOfScope", vString(note.outOfScope))
		}
	}
	body.set("status", vInt(int64(status)))
	body.set("answeredAt", vString(answeredAt.UTC().Format("2006-01-02T15:04:05.000Z")))
	body.set("caller", identityObject(who))
	if !note.noDelegation && who.delegated != nil && who.delegated.credential != nil && who.delegated.credential.chain != nil {
		body.set("delegation", refusalDelegationMember(who.delegated.credential.chain))
	}
	body.set("nonce", vString(hex.EncodeToString(nonce)))
	body.set("request", vString(refusalCommitment(refusalSalt(s.secret, nonce), route, read)))
	if len(canon(body)) > refusalRecordBound {
		s.drop(dropWriteFailed)
		return
	}
	select {
	case s.queue <- body:
		select {
		case j.wake <- struct{}{}:
		default:
		}
	default:
		s.drop(dropQueueFull)
	}
}

// refusalDelegationMember is §11.7's member without admittedAt.
func refusalDelegationMember(c *delegationChain) *vObject {
	leaf := c.leaf()
	v := newObject()
	v.set("id", vString(leaf.id))
	v.set("host", vString(leaf.host))
	v.set("actor", vString(leaf.agent))
	v.set("subject", leaf.sub.value())
	v.set("chain", c.digests())
	return v
}

// --- the writer ----------------------------------------------------------------

// start runs the writer, off every answer path.
func (j *refusalJournals) start() {
	j.startOnce.Do(func() { go j.run() })
}

// stop gives the writer refusalDrainWithin to empty the queues, then
// writes what is left as one stderr line.
func (j *refusalJournals) stop() {
	j.stopOnce.Do(func() {
		close(j.stopping)
		select {
		case <-j.done:
		case <-time.After(refusalDrainWithin + time.Second):
		}
		j.store.close()
	})
}

func (j *refusalJournals) run() {
	defer close(j.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if j.round() {
			select {
			case <-j.stopping:
				j.drain(time.Now().Add(refusalDrainWithin))
				return
			case <-ticker.C:
				j.tick()
			default:
			}
			continue
		}
		select {
		case <-j.wake:
		case <-ticker.C:
			j.tick()
		case <-j.stopping:
			j.drain(time.Now().Add(refusalDrainWithin))
			return
		}
	}
}

// round takes one record from each queue that holds one, in turn.
func (j *refusalJournals) round() bool {
	took := false
	for _, s := range j.order {
		select {
		case body := <-s.queue:
			took = true
			j.writeRefusal(s, body)
		default:
		}
	}
	return took
}

// drain empties the queues by deadline, then writes every scope's tally
// and the stderr line of what was not written.
func (j *refusalJournals) drain(deadline time.Time) {
	for time.Now().Before(deadline) && j.round() {
	}
	for _, s := range j.order {
		for {
			select {
			case <-s.queue:
				s.drop(dropWriteFailed)
				continue
			default:
			}
			break
		}
	}
	j.minuteLine(true)
}

// tick writes each journal's tally once a minute, and the gateway's stderr
// line of the records not written.
func (j *refusalJournals) tick() {
	now := j.clock()
	for _, s := range j.order {
		if now.Sub(s.since) >= refusalTallyEvery {
			j.writeTally(s, now)
		}
	}
	if now.Sub(j.lastMinute) >= refusalTallyEvery {
		j.lastMinute = now
		j.minuteLine(false)
	}
}

func (j *refusalJournals) minuteLine(atStop bool) {
	var n, k int64
	for _, s := range j.order {
		if m := s.minute.Swap(0); m > 0 {
			n += m
			k++
		}
	}
	if n == 0 {
		return
	}
	when := "in the last minute"
	if atStop {
		when = "at stop"
	}
	fmt.Fprintf(j.stderr, "refusal journal: %d records were not written %s, in %d journals; each journal's tally holds its counts\n", n, when, k)
}

// refusalRoom is the bytes refusal entries may take; the rest of the cap is
// kept for tallies (condition C6).
func (j *refusalJournals) refusalRoom() int64 {
	return j.cfg.maxBytes - j.cfg.maxBytes/16
}

// sign is an entry of the scope's journal at end, refused where the key in
// force comes earlier in the key walk than the last entry's.
func (j *refusalJournals) sign(s *refusalScope, end refusalEnd, body *vObject) ([]byte, error) {
	key := j.signer()
	if key == nil {
		return nil, errors.New("no key is in force")
	}
	if end.lastKeyID != "" && end.lastKeyID != key.keyID {
		walk, err := j.keys()
		if err != nil {
			return nil, err
		}
		at, last := -1, -1
		for i, k := range walk {
			switch k.keyID {
			case key.keyID:
				at = i
			case end.lastKeyID:
				last = i
			}
		}
		if at < 0 || at < last {
			return nil, errors.New("the key in force comes earlier in the key walk than the journal's last entry's")
		}
	}
	if j.beforeSign != nil {
		j.beforeSign()
	}
	return signedJournalEntry(key, s.name, end.ordinal, end.previous, j.clock().UTC().Format("2006-01-02T15:04:05Z"), body)
}

func (j *refusalJournals) writeRefusal(s *refusalScope, body *vObject) {
	if s.closed || s.refusalsFull {
		s.drop(dropJournalFull)
		return
	}
	if s.secret == nil {
		s.drop(dropWriteFailed)
		return
	}
	full := false
	err := j.store.append(s, func(end refusalEnd) ([]byte, error) {
		if end.closed {
			full = true
			return nil, nil
		}
		line, err := j.sign(s, end, body)
		if err != nil {
			return nil, err
		}
		if end.bytes+int64(len(line)) > j.refusalRoom() {
			full = true
			return nil, nil
		}
		return line, nil
	})
	switch {
	case err != nil:
		s.drop(dropWriteFailed)
	case full:
		s.refusalsFull = true
		s.drop(dropJournalFull)
	}
}

// tallyBody is the scope's counts since its last tally, taken from the
// counters; restore gives them back where the tally is not written.
func (s *refusalScope) tallyBody(from, to time.Time) (*vObject, func()) {
	var limits [5]int64
	var dropped [dropCauses]int64
	any := false
	for i := range s.limits {
		limits[i] = s.limits[i].Swap(0)
		any = any || limits[i] > 0
	}
	for i := range s.tally {
		dropped[i] = s.tally[i].Swap(0)
		any = any || dropped[i] > 0
	}
	restore := func() {
		for i := range limits {
			s.limits[i].Add(limits[i])
		}
		for i := range dropped {
			s.tally[i].Add(dropped[i])
		}
	}
	if !any {
		return nil, restore
	}
	body := newObject()
	body.set("kind", vString("tally"))
	body.set("scope", vString(s.key))
	body.set("from", vString(from.UTC().Format("2006-01-02T15:04:05Z")))
	body.set("to", vString(to.UTC().Format("2006-01-02T15:04:05Z")))
	l := newObject()
	for i, n := range limits {
		if n > 0 {
			l.set(limitCountNames[i], vInt(n))
		}
	}
	body.set("limit", l)
	d := newObject()
	for i, n := range dropped {
		if n > 0 {
			d.set(dropNames[i], vInt(n))
		}
	}
	body.set("dropped", d)
	return body, restore
}

func (j *refusalJournals) writeTally(s *refusalScope, now time.Time) {
	if s.closed {
		return
	}
	body, restore := s.tallyBody(s.since, now)
	if body == nil {
		s.since = now
		return
	}
	if s.secret == nil {
		// a journal with no key takes no tally either; the counts stay
		restore()
		return
	}
	closing := false
	err := j.store.append(s, func(end refusalEnd) ([]byte, error) {
		if end.closed {
			closing = true
			return nil, nil
		}
		line, err := j.sign(s, end, body)
		if err != nil {
			return nil, err
		}
		if end.bytes+int64(len(line))+journalLineBound+1 > j.cfg.maxBytes {
			body.set("full", vBool(true))
			closing = true
			return j.sign(s, end, body)
		}
		return line, nil
	})
	if err != nil {
		restore()
		s.tally[dropWriteFailed].Add(1)
		return
	}
	s.since = now
	if closing {
		s.closed = true
	}
}

// lastEntryOf is what the writer reads of a journal's last line.
func lastEntryOf(line []byte) (keyID string, closed bool) {
	v, err := parseRecordJSON(line)
	if err != nil {
		return "", false
	}
	obj, ok := v.(*vObject)
	if !ok {
		return "", false
	}
	keyID, _ = memberString(obj, "keyId")
	if raw, ok := obj.get("body"); ok {
		if body, ok := raw.(*vObject); ok {
			if full, ok := body.get("full"); ok {
				b, isBool := full.(vBool)
				closed = isBool && bool(b)
			}
		}
	}
	return keyID, closed
}

// --- the filesystem kind -----------------------------------------------------

// refusalFS keeps the journals at <root>/journals/<name>.jsonl and each key
// at <name>.key, 0600 in 0700.
type refusalFS struct{ root string }

func (f refusalFS) dir() string { return filepath.Join(f.root, journalsDir) }

func (f refusalFS) key(name string) ([]byte, bool, error) {
	path := filepath.Join(f.dir(), name+".key")
	read := func() ([]byte, error) {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		k, err := hex.DecodeString(strings.TrimSuffix(string(raw), "\n"))
		if err != nil || len(k) != 32 {
			return nil, errors.New("the key file is not 32 bytes in hexadecimal")
		}
		return k, nil
	}
	if k, err := read(); err == nil {
		return k, false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	if info, err := os.Lstat(filepath.Join(f.dir(), name+".jsonl")); err == nil && info.Size() > 0 {
		return nil, true, nil
	}
	if err := os.MkdirAll(f.dir(), 0o700); err != nil {
		return nil, false, err
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, false, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		k, err := read()
		return k, false, err
	}
	if err != nil {
		return nil, false, err
	}
	_, err = file.WriteString(hex.EncodeToString(k) + "\n")
	if err == nil {
		err = file.Sync()
	}
	if cerr := file.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, false, err
	}
	syncDir(f.dir())
	return k, false, nil
}

func (f refusalFS) open(s *refusalScope) error {
	if s.file != nil {
		return nil
	}
	if err := os.MkdirAll(f.dir(), 0o700); err != nil {
		return err
	}
	path := filepath.Join(f.dir(), s.name+".jsonl")
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errJournalNotRegular
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	s.file, s.loaded = file, false
	return nil
}

// load reads the journal's end, truncating a torn last piece first: nothing
// else writes the file, and appending after it would make a forged line.
func (f refusalFS) load(s *refusalScope) error {
	if _, err := s.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	data, err := io.ReadAll(s.file)
	if err != nil {
		return err
	}
	lines, torn := journalLines(data)
	if torn > 0 {
		if err := s.file.Truncate(int64(len(data) - torn)); err != nil {
			return err
		}
		if err := s.file.Sync(); err != nil {
			return err
		}
	}
	end := refusalEnd{ordinal: int64(len(lines)), bytes: int64(len(data) - torn)}
	if len(lines) > 0 {
		last := lines[len(lines)-1]
		end.previous = journalDigest(last)
		end.lastKeyID, end.closed = lastEntryOf(last)
	}
	s.end, s.loaded = end, true
	if end.closed {
		s.closed = true
	}
	return nil
}

func (f refusalFS) append(s *refusalScope, entry func(end refusalEnd) ([]byte, error)) error {
	if err := f.open(s); err != nil {
		return err
	}
	if err := lockJournalFile(s.file); err != nil {
		return err
	}
	defer unlockJournalFile(s.file)
	if info, err := s.file.Stat(); err != nil || !s.loaded || info.Size() != s.end.bytes {
		if err := f.load(s); err != nil {
			s.loaded = false
			return err
		}
	}
	line, err := entry(s.end)
	if err != nil || line == nil {
		return err
	}
	if _, err := s.file.WriteAt(line, s.end.bytes); err != nil {
		s.loaded = false
		return err
	}
	if err := s.file.Sync(); err != nil {
		s.loaded = false
		return err
	}
	keyID, closed := lastEntryOf(line[:len(line)-1])
	s.end = refusalEnd{ordinal: s.end.ordinal + 1, previous: journalDigest(line[:len(line)-1]), bytes: s.end.bytes + int64(len(line)), lastKeyID: keyID, closed: closed}
	return nil
}

func (f refusalFS) close() {}

// --- the answer's side (ADR-0059 §5, condition C10) --------------------------

// refusalAnswer is the response of a request while the journal is
// configured: a refusal of a request that holds one scope is kept until its
// handler returns, then written with the Content-Length the server would
// have set, flushed, and only then handed off.
type refusalAnswer struct {
	http.ResponseWriter
	j      *refusalJournals
	pass   *limitPass
	route  string
	note   refusalNote
	noted  bool
	wrote  bool
	held   bool
	status int
	body   bytes.Buffer
	read   *refusalTee
}

func (a *refusalAnswer) Unwrap() http.ResponseWriter { return a.ResponseWriter }

// heldScope is the one scope whose hold the request's charge took, if any
// (condition C3).
func (p *limitPass) heldScope() *refusalScope {
	if p == nil || len(p.holds) != 1 || p.who == nil {
		return nil
	}
	return p.holds[0].s.journal
}

func (a *refusalAnswer) WriteHeader(code int) {
	if a.wrote {
		a.ResponseWriter.WriteHeader(code)
		return
	}
	a.wrote = true
	if code >= 400 && code < 500 && refusalReasons[a.route] != nil && a.pass.heldScope() != nil {
		a.held, a.status = true, code
		return
	}
	a.ResponseWriter.WriteHeader(code)
}

func (a *refusalAnswer) Write(p []byte) (int, error) {
	if !a.wrote {
		a.WriteHeader(http.StatusOK)
	}
	if a.held {
		if a.body.Len()+len(p) <= refusalHeldBound {
			return a.body.Write(p)
		}
		a.letGo()
	}
	return a.ResponseWriter.Write(p)
}

// Flush writes what is held as the server would have, and journals nothing.
func (a *refusalAnswer) Flush() {
	a.letGo()
	if f, ok := a.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// letGo writes a held answer through, unjournaled.
func (a *refusalAnswer) letGo() {
	if !a.held {
		return
	}
	a.held = false
	a.ResponseWriter.WriteHeader(a.status)
	_, _ = a.ResponseWriter.Write(a.body.Bytes())
}

// finish writes the held answer, flushes it, and then hands its record off.
func (a *refusalAnswer) finish() {
	if !a.held {
		return
	}
	a.held = false
	body := a.body.Bytes()
	if a.ResponseWriter.Header().Get("Content-Length") == "" {
		a.ResponseWriter.Header().Set("Content-Length", strconv.Itoa(len(body)))
	}
	a.ResponseWriter.WriteHeader(a.status)
	_, _ = a.ResponseWriter.Write(body)
	_ = http.NewResponseController(a.ResponseWriter).Flush()
	answeredAt := a.j.clock()
	s := a.pass.heldScope()
	note, ok := a.classify(body)
	if !ok || s == nil {
		return
	}
	var read []byte
	if a.read != nil {
		read = a.read.bytes
	}
	a.j.handOff(s, a.route, note, a.status, a.pass.who, read, answeredAt)
}

// classify is the answer's code from section 4's closed list: what the
// handler noted, or, on /act, the step its answer names.
func (a *refusalAnswer) classify(body []byte) (refusalNote, bool) {
	note := a.note
	if a.route == "/act" && !a.noted {
		var answer struct {
			RefusedAt string `json:"refusedAt"`
		}
		if json.Unmarshal(body, &answer) != nil {
			return note, false
		}
		note.reason = answer.RefusedAt
	}
	return note, note.reason != "" && refusalReasons[a.route][note.reason]
}

// noteRefusal is a handler's code for the refusal it is about to answer.
func noteRefusal(w http.ResponseWriter, reason string) {
	if a, ok := w.(*refusalAnswer); ok {
		a.note, a.noted = refusalNote{reason: reason}, reason != ""
	}
}

// noteDelegationRefusal is the code of a delegation refusal (SPEC.md §11.5):
// action-key for the key's own, grant for the grant's, delegation otherwise.
func noteDelegationRefusal(w http.ResponseWriter, r *delegationRefusal) {
	a, ok := w.(*refusalAnswer)
	if !ok {
		return
	}
	switch {
	case strings.HasPrefix(r.name, "action-key"):
		a.note = refusalNote{reason: "action-key"}
	case r.at == "grant":
		a.note = refusalNote{reason: "grant", refusal: r.name}
	default:
		a.note = refusalNote{reason: "delegation", refusal: r.name}
		if r.name == refusalOutOfScope {
			a.note.outOfScope = r.scopeReason
		}
		// a chain that did not hold names no delegation
		a.note.noDelegation = r.name == refusalCredentialMismatch
	}
	a.noted = true
}

// refusalTee keeps the body bytes the gateway reads, for the commitment.
type refusalTee struct {
	io.ReadCloser
	bytes []byte
}

func (t *refusalTee) Read(p []byte) (int, error) {
	n, err := t.ReadCloser.Read(p)
	t.bytes = append(t.bytes, p[:n]...)
	return n, err
}

// teeBody wraps r.Body, already capped, so the bytes read are kept.
func teeBody(w http.ResponseWriter, r *http.Request) {
	if a, ok := w.(*refusalAnswer); ok {
		t := &refusalTee{ReadCloser: r.Body}
		a.read = t
		r.Body = t
	}
}

// acquireRefusalCode is the code of an error acquireScoped answers.
func acquireRefusalCode(err error) string {
	var delegationRefused *delegationRefusal
	if errors.As(err, &delegationRefused) {
		return ""
	}
	var elsewhere sessionHeldElsewhere
	if errors.As(err, &elsewhere) {
		return "session"
	}
	var caller badRequest
	if errors.As(err, &caller) {
		text := caller.Error()
		switch {
		case text == scopeRefusal:
			return "scope"
		case strings.HasPrefix(text, "unknown source: "):
			return "source"
		case strings.HasPrefix(text, "trail: "):
			return "trail"
		}
		return "session"
	}
	if strings.HasPrefix(err.Error(), "publisher-") {
		return "publisher-policy"
	}
	return ""
}

// sealRefusalCode is the code of an error /seal answers.
func sealRefusalCode(err error) string {
	var caller badRequest
	if errors.As(err, &caller) && caller.Error() == scopeRefusal {
		return "scope"
	}
	return "session"
}

// --- posture (ADR-0059 §10) --------------------------------------------------

const protectionRefusalJournal = "refusal-journal"

const refusalJournalEnforced = "refusals of authenticated requests charged to this caller's scopes are signed into the operator's refusal journal after they are answered; nothing of the journal is served"

const refusalJournalNoSource = "no source is reached, so no refusal is charged to a scope; nothing of the journal is served"

// refusalJournalLines is the fixed line, given only where the member is
// configured: computed from the configuration and the reach alone.
func refusalJournalLines(in postureInput) []postureLine {
	if in.refusalJournal == nil {
		return nil
	}
	if len(in.sources) == 0 {
		return []postureLine{{protectionRefusalJournal, postureNotApplicable, refusalJournalNoSource}}
	}
	return []postureLine{{protectionRefusalJournal, postureEnforced, refusalJournalEnforced}}
}

// refusalStartLine is the start's line where the member is configured.
func refusalStartLine(scopes int) string {
	return fmt.Sprintf("refusal journal: %d scopes are journaled, each bounded by its request rate", scopes)
}

// openRefusalJournals makes the gateway's journals over the scopes its
// limiter holds, on its store's kind, before it serves.
func (g *gatewayService) openRefusalJournals(cfg *refusalJournalConfig, stderr io.Writer) error {
	var store refusalStore = refusalFS{root: g.storeRoot}
	if kind, onKind := g.kind.(*pgKind); onKind {
		store = newRefusalPG(kind)
	}
	j, err := newRefusalJournals(cfg, limitScopeKeys(g.sources), store, g.store.signing.key, g.provenanceKeys, stderr)
	if err != nil {
		return err
	}
	if g.limiter != nil {
		for key, s := range j.scopes {
			if held := g.limiter.scopes[key]; held != nil {
				held.journal = s
			}
		}
	}
	g.refusals, g.refusalConfig = j, cfg
	return nil
}
