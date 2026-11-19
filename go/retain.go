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
	"time"
)

// retentionVersion is the engine configuration version that carries the
// retention member. It is the one place the number is spelled.
const retentionVersion = "37"

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
)

// retentionConfig is the configuration's retention member.
type retentionConfig struct {
	window         time.Duration
	windowDays     int64
	acknowledgedBy ed25519.PublicKey
	keyID          string
}

// parseRetentionConfig holds the member to its form: window, a whole number
// of days from 7, and acknowledgedBy, an Ed25519 public key in 64 lowercase
// hexadecimal characters.
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
	keyHex, _ := memberString(obj, "acknowledgedBy")
	if !isLowerHexOfLen(keyHex, 64) {
		return nil, errors.New("engine configuration: retention.acknowledgedBy is an Ed25519 public key, 64 lowercase hexadecimal characters")
	}
	key, _ := hex.DecodeString(keyHex)
	if publicKeyFault(key) != keySound {
		return nil, errors.New("engine configuration: retention.acknowledgedBy is not a sound Ed25519 public key")
	}
	return &retentionConfig{
		window: time.Duration(days) * 24 * time.Hour, windowDays: int64(days),
		acknowledgedBy: ed25519.PublicKey(key), keyID: keyIDFor(key),
	}, nil
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
	if subtle.ConstantTimeCompare([]byte(keyID), []byte(cfg.keyID)) != 1 ||
		!ed25519.Verify(cfg.acknowledgedBy, recordSigningInput(retentionAckContext, obj), sig) {
		return retentionAck{}, fmt.Sprintf("does not verify under retention.acknowledgedBy, key %s", cfg.keyID)
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
}

// retentionChoice is what the acknowledgments let a call remove, each
// session to the scope identifier its record names, with a note for each
// session kept and a refusal for each that refuses the call.
type retentionChoice struct {
	take    map[string]string
	notes   []string
	refused []string
}

// chooseRetained judges every acknowledgment that verified against the
// store's seals, under the window and the command's clock. removed is
// whether a session-removal record already names the seal; hold is what the
// store holds of the session.
func chooseRetained(acks []retentionAck, walk *registryWalk, cfg *retentionConfig, now time.Time, onlyScope string,
	removed func(session string, s seal) bool, hold func(session string) retentionHold) retentionChoice {
	c := retentionChoice{take: map[string]string{}}
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
		case s.signature != ack.sealSignature || s.finalCount != ack.finalCount:
			c.refused = append(c.refused, name+" under another seal than the store holds")
			continue
		}
		if removed(ack.sessionID, s) {
			c.notes = append(c.notes, fmt.Sprintf("session %s was recorded as removed already", ack.sessionID))
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
		if !named[session] && !removed(session, s) {
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

// removedUnder is whether a session-removal record, of any scope identifier,
// names the seal (sessionRemoved).
func removedUnder(ret *retention) func(string, seal) bool {
	return func(session string, s seal) bool { return ret.sessionRemoved(session, s) }
}

// retentionSummary is the call's summary, the last thing it says: what it
// removed, the SHA-256 of the acknowledgment file it read and the
// acknowledging key's id, so the call can be traced to the acknowledgments
// it acted on though no record in the store names them (R1).
func retentionSummary(removed int, sum, keyID string) string {
	return fmt.Sprintf("removed %d session(s) under the acknowledgments %s, acknowledged by key %s", removed, sum, keyID)
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
	hold, err := holdEngineRegistry(seedNames, cfg.registry, seed)
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
	priv := ed25519.NewKeyFromSeed(seed)
	walk, err := engineWalk(data, priv.Public().(ed25519.PublicKey))
	if err != nil {
		return out, unlocked, err
	}
	out, err = retainFrom(cfg.store, cfg.authority, priv, walk, acks, cfg.retention, o, stamp, now)
	if err == nil && len(out.refused) == 0 {
		out.notes = append(out.notes, retentionSummary(len(out.appended), sum, cfg.retention.keyID))
	}
	return out, unlocked, err
}

// retainFrom is the command's work on a store of the filesystem kind, the
// registry held: the store read, the sessions chosen, the plan made and
// refused whole or kept, the records appended, and then the files removed.
func retainFrom(storeRoot, authority string, priv ed25519.PrivateKey, walk *registryWalk, acks []retentionAck, cfg *retentionConfig,
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
	if len(choice.take) == 0 {
		out.notes = append(out.notes, "no session is past retention under an acknowledgment; nothing was removed")
		return out, nil
	}
	plan, refused := planScopeRemoval(storeRoot, all, sessions, walk, ret, func(session string) (string, bool) {
		scope, take := choice.take[session]
		return scope, take
	})
	if len(refused) > 0 {
		out.refused = append(refused, "nothing was removed")
		return out, nil
	}
	if len(plan.sessions) != len(choice.take) || plan.sealed != int64(len(choice.take)) {
		return out, errors.New("the sessions the acknowledgments name are not those the store would remove, and nothing was removed")
	}
	var lines []byte
	for _, session := range plan.sessions {
		s := walk.seals[session]
		record, line, err := signedSessionRemoval(priv, walk.keys, session, s, choice.take[session], carriedSalt(held[session]), o.by, stamp())
		if err != nil {
			return out, fmt.Errorf("%v, and nothing was removed", err)
		}
		lines = append(lines, line...)
		out.appended = append(out.appended, record)
	}
	if err := appendRemovals(storeRoot, torn, lines); err != nil {
		n := len(out.appended)
		out.appended = nil
		return out, fmt.Errorf("%v; the %d record(s) may be in the file, and nothing was removed; a second run completes it", err, n)
	}
	if err := carryOutRemoval(storeRoot, plan); err != nil {
		return out, err
	}
	out.notes = append(out.notes, fmt.Sprintf("removed %d session(s), holding %d receipt(s), and %d payload(s)", len(plan.sessions), len(plan.receipts), len(plan.payloads)))
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
		return retentionHold{held: true}
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
