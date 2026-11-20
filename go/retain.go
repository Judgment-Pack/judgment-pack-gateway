package main

// Retention by signed acknowledgment (docs/adr/0048-retention-by-acknowledgment-and-store-rotation.md,
// options A1 and R1; gateway #535): `gateway retain`, the gateway stopped,
// removes a sealed session of a scope identifier from a store of the
// filesystem kind when an acknowledgment line, signed under the key the
// configuration pins (retention.acknowledgedBy), names its seal exactly and
// retention.window has passed since the later of the seal's time and the
// acknowledgment's. Each removal is ADR-0034's session-removal record alone,
// appended and made durable before any file goes, so §4 step 4 reads the
// session as removed and nothing else in the store changes form. The
// PostgreSQL kind's is gateway store retain (store_retain.go).
//
// Nothing here runs on a timer, and nothing is removed by age unless the
// configuration carries a retention member: a schedule is the operator's
// scheduler running the command.

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// retentionVersion is the engine configuration version that carries the
// retention member. It is the one place the number is spelled.
const retentionVersion = "38"

// retentionAckContext is the prefix an acknowledgment line signs under.
const retentionAckContext = "judgment-pack-gateway/retention-ack/1:"

const (
	retentionAckKind = "retention-ack"
	// minRetentionWindowDays is the shortest window the configuration
	// loads: time to find an acknowledgment that was wrong, and to restore
	// from an export, before anything goes.
	minRetentionWindowDays = 7
	maxRetentionWindowDays = 36500
	// an acknowledgment file is read whole, and bounded: each line as a
	// removal record is, and at most this many lines
	maxRetentionAckLines = 10000
	maxRetentionAckBytes = maxRetentionAckLines * removalLineBound
	// acknowledgedBy lists from one to this many keys: the acknowledging
	// log's key in force, and the ones it overlaps while it rotates
	maxAcknowledgingKeys = 4
)

// retentionConfig is the configuration's retention member.
type retentionConfig struct {
	window     time.Duration
	windowDays int64
	// acknowledgedBy is each key a line may be signed under, in the
	// configuration's order, and keyIDs their key ids, in the same order
	acknowledgedBy []ed25519.PublicKey
	keyIDs         []string
}

// keyFor is the listed key whose id a line names, if one is.
func (c *retentionConfig) keyFor(keyID string) (ed25519.PublicKey, bool) {
	found := -1
	for i, id := range c.keyIDs {
		if subtle.ConstantTimeCompare([]byte(keyID), []byte(id)) == 1 {
			found = i
		}
	}
	if found < 0 {
		return nil, false
	}
	return c.acknowledgedBy[found], true
}

// parseRetentionConfig holds the member to its form: window, a whole number
// of days from 7, and acknowledgedBy, a list of one to four distinct Ed25519
// public keys, each 64 lowercase hexadecimal characters, so the acknowledging
// log's old and new keys overlap while it rotates.
func parseRetentionConfig(v value) (*retentionConfig, error) {
	obj, ok := v.(*vObject)
	if !ok {
		return nil, errors.New("engine configuration: retention is an object")
	}
	if err := exactlyMembers(obj, map[string]bool{"window": true, "acknowledgedBy": true}, "engine configuration: retention"); err != nil {
		return nil, err
	}
	windowV, _ := obj.get("window")
	days, ok := windowV.(vInt)
	if !ok || days < minRetentionWindowDays || days > maxRetentionWindowDays {
		return nil, fmt.Errorf("engine configuration: retention.window is a whole number of days from %d to %d; a shorter window is refused", minRetentionWindowDays, maxRetentionWindowDays)
	}
	listed, _ := obj.get("acknowledgedBy")
	keys, ok := listed.(vArray)
	if !ok || len(keys) < 1 || len(keys) > maxAcknowledgingKeys {
		return nil, fmt.Errorf("engine configuration: retention.acknowledgedBy is a list of 1 to %d Ed25519 public keys, each 64 lowercase hexadecimal characters", maxAcknowledgingKeys)
	}
	cfg := &retentionConfig{window: time.Duration(days) * 24 * time.Hour, windowDays: int64(days)}
	seen := map[string]bool{}
	for i, each := range keys {
		keyHex, isString := each.(vString)
		if !isString || !isLowerHexOfLen(string(keyHex), 64) {
			return nil, fmt.Errorf("engine configuration: retention.acknowledgedBy[%d] is an Ed25519 public key, 64 lowercase hexadecimal characters", i)
		}
		key, _ := hex.DecodeString(string(keyHex))
		if publicKeyFault(key) != keySound {
			return nil, fmt.Errorf("engine configuration: retention.acknowledgedBy[%d] is not a sound Ed25519 public key", i)
		}
		if seen[string(keyHex)] {
			return nil, fmt.Errorf("engine configuration: retention.acknowledgedBy[%d] is listed twice", i)
		}
		seen[string(keyHex)] = true
		cfg.acknowledgedBy = append(cfg.acknowledgedBy, ed25519.PublicKey(key))
		cfg.keyIDs = append(cfg.keyIDs, keyIDFor(key))
	}
	return cfg, nil
}

// retentionAck is one acknowledgment line that verified.
type retentionAck struct {
	line           int
	sessionID      string
	sealSignature  string
	finalCount     int64
	acknowledgedAt time.Time
}

var retentionAckMembers = map[string]bool{
	"kind": true, "sessionId": true, "sealSignature": true, "finalCount": true,
	"acknowledgedAt": true, "keyId": true, "signature": true,
}

// readRetentionAcks reads the acknowledgment file whole, bounded, and holds
// every line to its form and its signature under the pinned key. It answers
// the acknowledgments, the file's SHA-256, and a refusal for each line that
// does not verify, naming the line and never what it holds.
func readRetentionAcks(path string, cfg *retentionConfig) (acks []retentionAck, sum string, refused []string, err error) {
	data, err := readBounded(path, maxRetentionAckBytes)
	if err != nil {
		return nil, "", nil, fmt.Errorf("the acknowledgments: %v", err)
	}
	digest := sha256.Sum256(data)
	sum = "sha256:" + hex.EncodeToString(digest[:])
	if len(data) > 0 && data[len(data)-1] != '\n' {
		return nil, sum, nil, errors.New("the acknowledgments: the file does not end with a line feed")
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, removalLineBound), removalLineBound)
	seen := map[string]int{}
	n := 0
	for scanner.Scan() {
		n++
		if n > maxRetentionAckLines {
			return nil, sum, nil, fmt.Errorf("the acknowledgments: more than %d lines", maxRetentionAckLines)
		}
		ack, why := retentionAckOf(scanner.Bytes(), cfg)
		if why != "" {
			refused = append(refused, fmt.Sprintf("acknowledgment line %d %s", n, why))
			continue
		}
		ack.line = n
		if first, dup := seen[ack.sessionID]; dup {
			refused = append(refused, fmt.Sprintf("acknowledgment line %d names the session line %d names", n, first))
			continue
		}
		seen[ack.sessionID] = n
		acks = append(acks, ack)
	}
	if err := scanner.Err(); err != nil {
		return nil, sum, nil, fmt.Errorf("the acknowledgments: a line is longer than %d bytes", removalLineBound-1)
	}
	return acks, sum, refused, nil
}

// retentionAckOf is the acknowledgment one line states, or why it does not
// verify under the pinned key.
func retentionAckOf(line []byte, cfg *retentionConfig) (retentionAck, string) {
	v, err := parseJSON(line)
	if err != nil {
		return retentionAck{}, "is not canonical JSON"
	}
	obj, ok := v.(*vObject)
	if !ok || !bytes.Equal(canon(obj), line) {
		return retentionAck{}, "is not one canonical JSON object"
	}
	if len(obj.byName) != len(retentionAckMembers) {
		return retentionAck{}, "does not hold exactly an acknowledgment's members"
	}
	for name := range obj.byName {
		if !retentionAckMembers[name] {
			return retentionAck{}, "does not hold exactly an acknowledgment's members"
		}
	}
	kind, _ := memberString(obj, "kind")
	session, okS := memberString(obj, "sessionId")
	sealSig, okSeal := memberString(obj, "sealSignature")
	at, okAt := memberString(obj, "acknowledgedAt")
	keyID, okK := memberString(obj, "keyId")
	sigHex, okSig := memberString(obj, "signature")
	countV, _ := obj.get("finalCount")
	count, okC := countV.(vInt)
	if kind != retentionAckKind || !okS || requireSession(session) != nil || !okSeal || !isLowerHexOfLen(sealSig, 128) ||
		!okAt || !witnessTimeForm.MatchString(at) || !okK || !isLowerHexOfLen(keyID, 32) || !okSig || !isLowerHexOfLen(sigHex, 128) ||
		!okC || count < 0 {
		return retentionAck{}, "is not of an acknowledgment's form"
	}
	when, err := time.Parse(time.RFC3339, at)
	if err != nil {
		return retentionAck{}, "is not of an acknowledgment's form"
	}
	sig, _ := hex.DecodeString(sigHex)
	key, listed := cfg.keyFor(keyID)
	if !listed {
		return retentionAck{}, "names a key that retention.acknowledgedBy does not list"
	}
	if !ed25519.Verify(key, recordSigningInput(retentionAckContext, obj), sig) {
		return retentionAck{}, fmt.Sprintf("does not verify under retention.acknowledgedBy, key %s", keyID)
	}
	return retentionAck{sessionID: session, sealSignature: sealSig, finalCount: int64(count), acknowledgedAt: when}, ""
}

// retentionHold is what a store says of a session an acknowledgment names:
// the scope identifier it is of, whether the store holds it at all, and,
// where it cannot be removed whole, why.
type retentionHold struct {
	scope string
	held  bool
	why   string
	// empty is a session's directory holding no receipt, which a run cut
	// off between its last receipt and its directory leaves: of no scope
	// only because nothing is left to carry one
	empty bool
}

// retentionChoice is what the acknowledgments let a call remove, each
// session to the scope identifier its record names, with a note for each
// session kept and a refusal for each that refuses the call.
type retentionChoice struct {
	take    map[string]string
	finish  map[string]string
	notes   []string
	refused []string
}

// chooseRetained judges every acknowledgment that verified against the
// store's seals, under the window and the command's clock. removed is the
// scope identifier of the session-removal record that already names the
// seal, and whether one does; hold is what the store holds of the session.
// A session recorded as removed whose files or rows are still there is one
// a run cut off after its records left: it goes to finish, under its
// record's scope identifier, and is removed with no record signed again.
func chooseRetained(acks []retentionAck, walk *registryWalk, cfg *retentionConfig, now time.Time, onlyScope string,
	removed func(session string, s seal) (string, bool), hold func(session string) retentionHold) retentionChoice {
	c := retentionChoice{take: map[string]string{}, finish: map[string]string{}}
	named := map[string]bool{}
	window := 0
	for _, ack := range acks {
		named[ack.sessionID] = true
		name := fmt.Sprintf("acknowledgment line %d names session %s", ack.line, ack.sessionID)
		s, sealed := walk.seals[ack.sessionID]
		h := hold(ack.sessionID)
		switch {
		case !sealed && h.held:
			c.refused = append(c.refused, name+", which is open; an open session is never removed")
			continue
		case !sealed:
			c.refused = append(c.refused, name+", which the store does not hold")
			continue
		case walk.conflicted[ack.sessionID]:
			c.refused = append(c.refused, name+", for which the registry holds more than one seal (SPEC.md §3c); a session whose seal is in conflict is never removed")
			continue
		case s.signature != ack.sealSignature || s.finalCount != ack.finalCount:
			c.refused = append(c.refused, name+" under another seal than the store holds")
			continue
		}
		if scope, done := removed(ack.sessionID, s); done {
			switch {
			case !h.held:
				c.notes = append(c.notes, fmt.Sprintf("session %s was recorded as removed already", ack.sessionID))
			case onlyScope != "" && subtle.ConstantTimeCompare([]byte(scope), []byte(onlyScope)) != 1:
				c.notes = append(c.notes, fmt.Sprintf("session %s is of another scope identifier than --scope names; it is kept", ack.sessionID))
			case h.why != "":
				c.refused = append(c.refused, name+", recorded as removed already, which "+h.why)
			case h.scope == "" && !h.empty:
				c.refused = append(c.refused, name+", recorded as removed already under a scope identifier, whose receipts are of none; the session is left whole")
			case h.scope != "" && subtle.ConstantTimeCompare([]byte(h.scope), []byte(scope)) != 1:
				c.refused = append(c.refused, name+", recorded as removed already under another scope identifier than its receipts carry; the session is left whole")
			default:
				c.notes = append(c.notes, fmt.Sprintf("session %s was recorded as removed already; its files, still there, are removed now", ack.sessionID))
				c.finish[ack.sessionID] = scope
			}
			continue
		}
		sealedAt, err := time.Parse(time.RFC3339, s.sealedAt)
		if err != nil {
			c.refused = append(c.refused, name+", whose seal states no time this command reads")
			continue
		}
		switch {
		case ack.acknowledgedAt.Before(sealedAt):
			c.refused = append(c.refused, name+" at a time earlier than its seal's")
			continue
		case ack.acknowledgedAt.After(now):
			c.refused = append(c.refused, name+" at a time later than this command's clock")
			continue
		}
		switch {
		case !h.held:
			c.refused = append(c.refused, name+", which the store does not hold")
			continue
		case h.why != "":
			c.refused = append(c.refused, name+", which "+h.why)
			continue
		case h.scope == "":
			c.refused = append(c.refused, name+", which is of no scope identifier; it goes only with its whole store")
			continue
		}
		if onlyScope != "" && subtle.ConstantTimeCompare([]byte(h.scope), []byte(onlyScope)) != 1 {
			c.notes = append(c.notes, fmt.Sprintf("session %s is of another scope identifier than --scope names; it is kept", ack.sessionID))
			continue
		}
		later := sealedAt
		if ack.acknowledgedAt.After(later) {
			later = ack.acknowledgedAt
		}
		if until := later.Add(cfg.window); now.Before(until) {
			c.notes = append(c.notes, fmt.Sprintf("session %s is within the retention window until %s; it is kept", ack.sessionID, until.UTC().Format(time.RFC3339)))
			window++
			continue
		}
		c.take[ack.sessionID] = h.scope
	}
	// Every sealed session no acknowledgment names is kept, and named, so a
	// call says what it left as well as what it took; a re-run with a
	// cumulative acknowledgment file is the same call.
	var unnamed []string
	for session, s := range walk.seals {
		if _, done := removed(session, s); !named[session] && !done {
			unnamed = append(unnamed, session)
		}
	}
	sort.Strings(unnamed)
	for _, session := range unnamed {
		c.notes = append(c.notes, fmt.Sprintf("session %s is named by no acknowledgment; it is kept", session))
	}
	if len(c.refused) == 0 {
		c.notes = append(c.notes, fmt.Sprintf("kept %d sealed session(s): %d named by no acknowledgment, %d within the retention window", len(unnamed)+window, len(unnamed), window))
	}
	return c
}

// removedUnder is the scope identifier of the session-removal record, of
// any scope identifier, that names the seal, and whether one does
// (removalOf).
func removedUnder(ret *retention) func(string, seal) (string, bool) {
	return func(session string, s seal) (string, bool) {
		rec, ok := ret.removalOf(session, s)
		return rec.scope, ok
	}
}

// retentionSummary is the call's summary, the last thing it says: what it
// removed, the SHA-256 of the acknowledgment file it read and the
// acknowledging keys' ids, each the configuration lists, so the call can be
// traced to the acknowledgments it acted on though no record in the store
// names them (R1).
func retentionSummary(removed int, sum string, keyIDs []string) string {
	return fmt.Sprintf("removed %d session(s) under the acknowledgments %s, acknowledged by key(s) %s", removed, sum, strings.Join(keyIDs, ", "))
}

const retainUsage = `usage: gateway retain --config <engine.json> --acknowledgments <file> [--scope <identifier>] --by <label>
Removes, the gateway stopped, each sealed session of a scope identifier (the
one --scope names, if given) whose seal a line of the acknowledgment file
names exactly, signed under the configuration's retention.acknowledgedBy,
once retention.window has passed since the later of the seal's time and the
acknowledgment's. Each removal is recorded first, in the store's
artifact-removals.jsonl, as a session-removal record signed by the key in
force (SPEC.md §1.3a). An acknowledgment that does not verify, that names a
session the store does not hold or holds under another seal, an open
session, a session of no scope identifier or of several, a time earlier
than the seal's or later than the clock, and a receipt left in the store
that cites a session the call would remove, refuse the whole call, by name,
and nothing is removed. A configuration with no retention member removes
nothing. On the PostgreSQL kind, gateway store retain removes the rows.`

type retainOptions struct {
	config, acks, scope, by string
}

func parseRetain(args []string) (retainOptions, string) {
	flags := map[string]string{}
	for rest := args; len(rest) > 0; rest = rest[2:] {
		switch rest[0] {
		case "--config", "--acknowledgments", "--scope", "--by":
		default:
			return retainOptions{}, ""
		}
		if len(rest) < 2 || rest[1] == "" {
			return retainOptions{}, ""
		}
		if _, given := flags[rest[0]]; given {
			return retainOptions{}, rest[0] + " is given twice"
		}
		flags[rest[0]] = rest[1]
	}
	if flags["--config"] == "" || flags["--acknowledgments"] == "" || flags["--by"] == "" {
		return retainOptions{}, ""
	}
	if scope, given := flags["--scope"]; given && !isScopeIdentifier(scope) {
		return retainOptions{}, "--scope is a scope identifier: " + scopeForm
	}
	if !isScopeIdentifier(flags["--by"]) {
		return retainOptions{}, "--by is a label of the form of a scope identifier: " + scopeForm
	}
	return retainOptions{config: flags["--config"], acks: flags["--acknowledgments"], scope: flags["--scope"], by: flags["--by"]}, "ok"
}

// retainConfig is the engine configuration a retention command reads, held
// to carry the retention member.
func retainConfig(path string) (engineConfig, error) {
	data, err := readBounded(path, maxEngineConfigBytes)
	if err != nil {
		return engineConfig{}, fmt.Errorf("engine configuration: %v", err)
	}
	cfg, err := parseEngineConfig(data)
	if err != nil {
		return engineConfig{}, err
	}
	if cfg.retention == nil {
		return engineConfig{}, errors.New("the engine configuration carries no retention member, so nothing is removed by age")
	}
	return cfg, nil
}

func cmdRetain(args []string, stdout, stderr io.Writer) int {
	return cmdRetainAt(args, stdout, stderr, nowStamp, time.Now)
}

// cmdRetainAt is the command, each record stamped by stamp, judged at now.
func cmdRetainAt(args []string, stdout, stderr io.Writer, stamp func() string, now func() time.Time) int {
	o, msg := parseRetain(args)
	switch msg {
	case "ok":
	case "":
		fmt.Fprintln(stderr, retainUsage)
		return 2
	default:
		fmt.Fprintf(stderr, "retain: %s\n%s\n", msg, retainUsage)
		return 2
	}
	out, unlocked, err := retain(o, stamp, now().UTC())
	for _, record := range out.appended {
		fmt.Fprintf(stdout, "%s\n", canon(record))
	}
	for _, note := range out.notes {
		fmt.Fprintln(stderr, "retain:", note)
	}
	for _, refusal := range out.refused {
		fmt.Fprintln(stderr, "retain:", refusal)
	}
	if unlocked {
		fmt.Fprintln(stderr, "retain: this platform locks no registry, so a gateway still running was not looked for; the gateway was to be stopped")
	}
	if err != nil {
		fmt.Fprintln(stderr, "retain:", err)
		return 1
	}
	if len(out.refused) > 0 {
		return 1
	}
	return 0
}

// retain is the command on the filesystem kind: the configuration and the
// acknowledgments read, the registry held as remove-scope holds it, and the
// sessions chosen removed under it.
func retain(o retainOptions, stamp func() string, now time.Time) (out removalOutcome, unlocked bool, err error) {
	cfg, err := retainConfig(o.config)
	if err != nil {
		return out, false, err
	}
	if cfg.storage != nil {
		return out, false, fmt.Errorf("%w: gateway retain removes the files of a store on disk; on the PostgreSQL kind, gateway store retain removes the rows", errStorageKindUnsupported)
	}
	acks, sum, refused, err := readRetentionAcks(o.acks, cfg.retention)
	if err != nil {
		return out, false, fmt.Errorf("%v, and nothing was removed", err)
	}
	if len(refused) > 0 {
		out.refused = append(refused, "nothing was removed")
		return out, false, nil
	}
	seedNames := []string{cfg.seed}
	if resolved, err := filepath.EvalSymlinks(cfg.seed); err == nil && resolved != cfg.seed {
		seedNames = append(seedNames, resolved)
	}
	seed, err := loadSeed(cfg.seed)
	if err != nil {
		return out, false, fmt.Errorf("seed: %w", err)
	}
	if _, present, err := readRegistryBytes(cfg.registry); err != nil {
		return out, false, fmt.Errorf("registry: %w", err)
	} else if !present {
		return out, false, fmt.Errorf("the registry is not there: %s", cfg.registry)
	}
	// the key in force signs the records: the key service's key version the
	// configuration names, held to signingPublicKey, or else the seed's
	// (ADR-0050)
	sig, err := commandSigner(cfg.signingKeyVersion, cfg.signingPublicKey, seed)
	if err != nil {
		return out, false, err
	}
	key := newSigningKey(sig)
	hold, err := holdEngineRegistryKey(seedNames, cfg.registry, key.public)
	if err != nil {
		if errors.Is(err, errRegistryHeld) {
			return out, false, fmt.Errorf("%w; stop the gateway, then retain", err)
		}
		return out, false, err
	}
	defer hold.Close()
	unlocked = !registryLocked
	data, _, err := readRegistryBytes(cfg.registry)
	if err != nil {
		return out, unlocked, fmt.Errorf("registry: %w", err)
	}
	walk, err := engineWalk(data, key.public)
	if err != nil {
		return out, unlocked, err
	}
	if err := heldUnderAnotherKey(data, walk.keys, key.public, newFsKind(fsLayout{store: cfg.store}).receipts()); err != nil {
		return out, unlocked, err
	}
	out, err = retainFrom(cfg.store, cfg.authority, key, walk, acks, cfg.retention, o, stamp, now)
	if err == nil && len(out.refused) == 0 {
		out.notes = append(out.notes, retentionSummary(out.removed, sum, cfg.retention.keyIDs))
	}
	return out, unlocked, err
}

// retainFrom is the command's work on a store of the filesystem kind, the
// registry held: the store read, the sessions chosen, the plan made and
// refused whole or kept, the records appended, and then the files removed.
func retainFrom(storeRoot, authority string, priv *signingKey, walk *registryWalk, acks []retentionAck, cfg *retentionConfig,
	o retainOptions, stamp func() string, now time.Time) (out removalOutcome, err error) {
	records, torn, err := readRecords(storeRoot, walk.keys)
	if err != nil {
		return out, fmt.Errorf("%v, and nothing was removed", err)
	}
	ret := &retention{removals: records.artifacts, sessions: records.sessions}
	all, err := readStoreReceipts(storeRoot, authority, walk.keys, ret)
	if err != nil {
		return out, fmt.Errorf("the store's receipts could not be read, and nothing was removed: %v", err)
	}
	sessions, err := listSessions(storeRoot)
	if err != nil {
		return out, fmt.Errorf("the store's receipts could not be read, and nothing was removed: %v", err)
	}
	held := map[string][]*storedReceipt{}
	for _, s := range all {
		held[s.sessionID] = append(held[s.sessionID], s)
	}
	listed := map[string]bool{}
	for _, s := range sessions {
		listed[s] = true
	}
	choice := chooseRetained(acks, walk, cfg, now, o.scope, removedUnder(ret), func(session string) retentionHold {
		return fsRetentionHold(listed[session], held[session])
	})
	out.notes = choice.notes
	if len(choice.refused) > 0 {
		out.refused = append(choice.refused, "nothing was removed")
		return out, nil
	}
	if len(choice.take) == 0 && len(choice.finish) == 0 {
		out.notes = append(out.notes, "no session is past retention under an acknowledgment; nothing was removed")
		return out, nil
	}
	plan, refused := planScopeRemoval(storeRoot, all, sessions, walk, ret, func(session string) (string, bool) {
		if scope, take := choice.take[session]; take {
			return scope, true
		}
		scope, finish := choice.finish[session]
		return scope, finish
	})
	if len(refused) > 0 {
		out.refused = append(refused, "nothing was removed")
		return out, nil
	}
	if len(plan.sessions)+len(plan.empty) != len(choice.take)+len(choice.finish) || plan.sealed != int64(len(plan.sessions)) {
		return out, errors.New("the sessions the acknowledgments name are not those the store would remove, and nothing was removed")
	}
	var lines []byte
	for _, session := range plan.sessions {
		if _, finish := choice.finish[session]; finish {
			continue
		}
		s := walk.seals[session]
		record, line, err := signedSessionRemoval(priv, walk.keys, session, s, choice.take[session], carriedSalt(held[session]), o.by, stamp())
		if err != nil {
			return out, fmt.Errorf("%v, and nothing was removed", err)
		}
		lines = append(lines, line...)
		out.appended = append(out.appended, record)
	}
	if len(lines) > 0 {
		if err := appendRemovals(storeRoot, torn, lines); err != nil {
			n := len(out.appended)
			out.appended = nil
			return out, fmt.Errorf("%v; the %d record(s) may be in the file, and nothing was removed; a second run completes it", err, n)
		}
	}
	if err := carryOutRemoval(storeRoot, plan); err != nil {
		return out, err
	}
	out.removed = len(plan.sessions) + len(plan.empty)
	out.notes = append(out.notes, fmt.Sprintf("removed %d session(s), holding %d receipt(s), and %d payload(s)", out.removed, len(plan.receipts), len(plan.payloads)))
	return out, nil
}

// fsRetentionHold is what a store of the filesystem kind holds of a
// session: the scope identifier every receipt of it carries, signed, or why
// it is of none or cannot be removed whole.
func fsRetentionHold(listed bool, receipts []*storedReceipt) retentionHold {
	if !listed {
		return retentionHold{}
	}
	if len(receipts) == 0 {
		return retentionHold{held: true, empty: true}
	}
	first := receipts[0]
	if !passesSignedOrders(first) {
		return retentionHold{held: true, why: "holds a receipt that does not verify under the keys the registry's walk reached; the session is left whole"}
	}
	scope, ok := memberString(first.r.obj, "scope")
	if !ok {
		for _, s := range receipts[1:] {
			if passesSignedOrders(s) {
				if _, scoped := memberString(s.r.obj, "scope"); scoped {
					return retentionHold{held: true, why: "holds receipts of a scope identifier beside receipts of none; the session is left whole"}
				}
			}
		}
		return retentionHold{held: true}
	}
	for _, s := range receipts[1:] {
		if !carriesScope(s, scope) {
			return retentionHold{held: true, why: "holds receipts of more than one scope identifier, of none, or not verifying; the session is left whole"}
		}
	}
	return retentionHold{held: true, scope: scope}
}

// retentionAckLine is an acknowledgment line signed by priv: what the
// external log, or the operator's shipper on its behalf, writes. The tests
// and the documentation's example make it.
func retentionAckLine(priv ed25519.PrivateKey, sessionID, sealSignature string, finalCount int64, at string) []byte {
	obj := newObject()
	obj.set("acknowledgedAt", vString(at))
	obj.set("finalCount", vInt(finalCount))
	obj.set("keyId", vString(keyIDFor(priv.Public().(ed25519.PublicKey))))
	obj.set("kind", vString(retentionAckKind))
	obj.set("sealSignature", vString(sealSignature))
	obj.set("sessionId", vString(sessionID))
	obj.set("signature", vString(hex.EncodeToString(ed25519.Sign(priv, recordSigningInput(retentionAckContext, obj)))))
	return append(canon(obj), '\n')
}
