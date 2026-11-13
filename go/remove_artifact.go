package main

// `gateway remove-artifact` (gateway #422; SPEC.md §1.3a and §6, "Payloads a
// gateway does not keep"; ADR-0028): a recorded removal. The bytes a
// receipt's call kept are removed from the store, the gateway stopped, and
// the removal is recorded first, in the store's artifact-removals.jsonl,
// signed by the key in force. A verifier of this version then passes the
// receipt with the observation artifact-removed where nothing is at its
// artifact's path, and re-digests whatever is there.
//
// What is removed is only what a reader could not be misled by: a receipt
// the ladder passes under the keys the registry's walk reaches (so bytes
// changed before their removal, artifact-mismatch, are refused), of an
// acquisition, that kept its bytes, of the scope --scope gives, whose bytes
// no other receipt in the store still needs and no descriptor provenance in
// the store reads. Each receipt refused is named, and nothing is changed for
// it.
//
// Every record is appended, and made durable, before any byte is removed;
// the bytes are re-digested once more just before each is removed. A run
// stopped between the two leaves the record beside the bytes, which verify
// ok with no observation (§1.3a, step 1), and a second run removes them
// without appending the record again.
//
// The registry is held as gateway seal-open holds it (holdEngineRegistry),
// so a running gateway refuses the command, and the store is read, and the
// records appended, under it.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const removeArtifactUsage = `usage: gateway remove-artifact (--config <engine.json> | --store <dir> --seed <file> --registry <file> --authority <authority>) --receipt <sessionId>/<callIndex> [--receipt <sessionId>/<callIndex> ...] --by <label> [--scope <identifier>]
Removes, the gateway stopped, the bytes a receipt's call kept, and records
the removal first in the store's artifact-removals.jsonl, signed by the key
in force (SPEC.md §1.3a). A receipt that does not verify, an action, one
whose call kept nothing, one whose scope --scope does not give, and one
whose bytes another receipt or a descriptor in the store still reads are
refused and left as they are. --by is a label, recorded and not checked.
Prints each record appended, as its line.`

// removalTarget is a receipt the command line names.
type removalTarget struct {
	sessionID string
	callIndex int64
}

func (n removalTarget) String() string {
	return n.sessionID + "/" + strconv.FormatInt(n.callIndex, 10)
}

func (n removalTarget) fileName() string {
	return strconv.FormatInt(n.callIndex, 10) + ".json"
}

// removeArtifactOptions is the command line.
type removeArtifactOptions struct {
	store, registry, authority string
	seedNames                  []string
	targets                    []removalTarget
	by                         string
	scope                      string
	scoped                     bool
}

// callIndexForm is a call index as a receipt's file names it: decimal, no
// sign, no leading zero.
var callIndexForm = regexp.MustCompile(`^(0|[1-9][0-9]{0,15})$`)

func parseRemovalTarget(s string) (removalTarget, string) {
	session, index, ok := strings.Cut(s, "/")
	if !ok || requireSession(session) != nil || !callIndexForm.MatchString(index) {
		return removalTarget{}, "--receipt names a receipt as <sessionId>/<callIndex>: a session id of ^[A-Za-z0-9._-]{1,128}$ and a call index in decimal"
	}
	n, err := strconv.ParseInt(index, 10, 64)
	if err != nil || n > maxCallIndex {
		return removalTarget{}, "--receipt names a call index from 0 to 2^53-1"
	}
	return removalTarget{sessionID: session, callIndex: n}, ""
}

func parseRemoveArtifact(args []string) (removeArtifactOptions, string) {
	flags := map[string]string{}
	var o removeArtifactOptions
	seen := map[removalTarget]bool{}
	for rest := args; len(rest) > 0; rest = rest[2:] {
		name := rest[0]
		switch name {
		case "--config", "--store", "--seed", "--registry", "--authority", "--receipt", "--by", "--scope":
		default:
			return removeArtifactOptions{}, ""
		}
		if len(rest) < 2 || rest[1] == "" {
			return removeArtifactOptions{}, ""
		}
		if name == "--receipt" {
			target, msg := parseRemovalTarget(rest[1])
			if msg != "" {
				return removeArtifactOptions{}, msg
			}
			if seen[target] {
				return removeArtifactOptions{}, "receipt " + target.String() + " is named twice"
			}
			seen[target] = true
			o.targets = append(o.targets, target)
			continue
		}
		if _, given := flags[name]; given {
			return removeArtifactOptions{}, name + " is given twice"
		}
		flags[name] = rest[1]
	}
	if len(o.targets) == 0 || flags["--by"] == "" {
		return removeArtifactOptions{}, ""
	}
	if !isScopeIdentifier(flags["--by"]) {
		return removeArtifactOptions{}, "--by is a label of the form of a scope identifier: " + scopeForm
	}
	o.by = flags["--by"]
	if scope, given := flags["--scope"]; given {
		if !isScopeIdentifier(scope) {
			return removeArtifactOptions{}, "--scope is a scope identifier: " + scopeForm
		}
		o.scope, o.scoped = scope, true
	}
	if config := flags["--config"]; config != "" {
		for _, other := range []string{"--store", "--seed", "--registry", "--authority"} {
			if flags[other] != "" {
				return removeArtifactOptions{}, "--config names the store, the seed, the registry and the authority; " + other + " is not given beside it"
			}
		}
		data, err := readBounded(config, maxEngineConfigBytes)
		if err != nil {
			return removeArtifactOptions{}, fmt.Sprintf("engine configuration: %v", err)
		}
		cfg, err := parseEngineConfig(data)
		if err != nil {
			return removeArtifactOptions{}, err.Error()
		}
		o.store, o.registry, o.authority, o.seedNames = cfg.store, cfg.registry, cfg.authority, []string{cfg.seed}
		// the seed by the name it resolves to as well, as seal-open looks
		// for a rotation under way beside both
		if resolved, err := filepath.EvalSymlinks(cfg.seed); err == nil && resolved != cfg.seed {
			o.seedNames = append(o.seedNames, resolved)
		}
		return o, "ok"
	}
	for _, need := range []string{"--store", "--seed", "--registry", "--authority"} {
		if flags[need] == "" {
			return removeArtifactOptions{}, ""
		}
	}
	o.store, o.registry, o.authority, o.seedNames = flags["--store"], flags["--registry"], flags["--authority"], []string{flags["--seed"]}
	return o, "ok"
}

func cmdRemoveArtifact(args []string, stdout, stderr io.Writer) int {
	return cmdRemoveArtifactAt(args, stdout, stderr, nowStamp)
}

// cmdRemoveArtifactAt is the command, each record stamped by stamp.
func cmdRemoveArtifactAt(args []string, stdout, stderr io.Writer, stamp func() string) int {
	o, msg := parseRemoveArtifact(args)
	switch msg {
	case "ok":
	case "":
		fmt.Fprintln(stderr, removeArtifactUsage)
		return 2
	default:
		fmt.Fprintf(stderr, "remove-artifact: %s\n%s\n", msg, removeArtifactUsage)
		return 2
	}
	out, unlocked, err := removeArtifact(o, stamp)
	for _, record := range out.appended {
		fmt.Fprintf(stdout, "%s\n", canon(record))
	}
	for _, note := range out.notes {
		fmt.Fprintln(stderr, "remove-artifact:", note)
	}
	for _, refusal := range out.refused {
		fmt.Fprintln(stderr, "remove-artifact:", refusal)
	}
	if unlocked {
		fmt.Fprintln(stderr, "remove-artifact: this platform locks no registry, so a gateway still running was not looked for; the gateway was to be stopped")
	}
	if err != nil {
		fmt.Fprintln(stderr, "remove-artifact:", err)
		return 1
	}
	if len(out.refused) > 0 {
		return 1
	}
	return 0
}

// removeArtifact is the command: the seed read, the registry there and held
// as a gateway holds it while it runs, and what may be removed removed under
// it. unlocked is a platform that locks no registry.
func removeArtifact(o removeArtifactOptions, stamp func() string) (out removalOutcome, unlocked bool, err error) {
	seed, err := loadSeed(o.seedNames[0])
	if err != nil {
		return out, false, fmt.Errorf("seed: %w", err)
	}
	absentRegistry := fmt.Errorf("the registry is not there: %s; a gateway makes it when it starts, and its walk names the keys a receipt is checked under", o.registry)
	if _, present, err := readRegistryBytes(o.registry); err != nil {
		return out, false, fmt.Errorf("registry: %w", err)
	} else if !present {
		return out, false, absentRegistry
	}
	hold, err := holdEngineRegistry(o.seedNames, o.registry, seed)
	if err != nil {
		if errors.Is(err, errRegistryHeld) {
			return out, false, fmt.Errorf("%w; stop the gateway, then remove", err)
		}
		return out, false, err
	}
	defer hold.Close()
	unlocked = !registryLocked
	data, present, err := readRegistryBytes(o.registry)
	if err != nil {
		return out, unlocked, fmt.Errorf("registry: %w", err)
	}
	if !present {
		return out, unlocked, absentRegistry
	}
	priv := ed25519.NewKeyFromSeed(seed)
	walk, err := engineWalk(data, priv.Public().(ed25519.PublicKey))
	if err != nil {
		return out, unlocked, err
	}
	out, err = removeArtifactsUnder(o.store, o.authority, priv, walk.keys, o, stamp)
	return out, unlocked, err
}

// removalOutcome is what a run did: the records appended, in order, what it
// says of a receipt already recorded, and the receipts refused.
type removalOutcome struct {
	appended []*vObject
	notes    []string
	refused  []string
}

// storedReceipt is one file of the store's receipts: where it is, its bytes,
// what the ladder says of it, and the members the command reads of it.
type storedReceipt struct {
	sessionID, fileName string
	data                []byte
	r                   *receipt
	status              string
	// digest is its resultDigest as written, "" where it has none that
	// can be read
	digest string
	// parsed is whether the bytes are JSON the canonical parser reads
	parsed bool
}

func (s *storedReceipt) name() string {
	return s.sessionID + "/" + strings.TrimSuffix(s.fileName, ".json")
}

// keepsNoBytes is whether the receipt holds nothing at its digest's path a
// removal could take from it: it passes the ladder and its call kept no
// payload, or a removal record that loaded names it.
func (s *storedReceipt) keepsNoBytes(ret *retention) bool {
	return s.status == "ok" && s.r != nil && (s.r.notRetained || ret.namedBy(s.r, s.sessionID))
}

// readStoreReceipts is every receipt file in the store, judged by the ladder
// under the keys the walk reached, the removal records read beside them. A
// file that cannot be read stops it all: what it holds is not known.
func readStoreReceipts(storeRoot, authority string, keys []reachedKey, ret *retention) ([]*storedReceipt, error) {
	sessions, err := listSessions(storeRoot)
	if err != nil {
		return nil, err
	}
	var all []*storedReceipt
	for _, session := range sessions {
		entries, err := os.ReadDir(filepath.Join(storeRoot, "receipts", session))
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(storeRoot, "receipts", session, e.Name()))
			if err != nil {
				return nil, err
			}
			s := &storedReceipt{sessionID: session, fileName: e.Name(), data: data}
			s.r, s.status, err = checkReceiptWith(data, storeRoot, session, e.Name(), authority, keys, ret)
			if err != nil {
				return nil, err
			}
			if v, err := parseJSON(data); err == nil {
				s.parsed = true
				if obj, ok := v.(*vObject); ok {
					s.digest, _ = memberString(obj, "resultDigest")
				}
			}
			all = append(all, s)
		}
	}
	return all, nil
}

// descriptorDigests are the digests of every descriptor snapshot and
// statement a receipt in the store names, wherever in it a
// descriptorProvenance member is: descriptor provenance (SPEC.md §9) reads
// them under artifacts/.
func descriptorDigests(all []*storedReceipt) map[string]bool {
	held := map[string]bool{}
	var walk func(v value)
	walk = func(v value) {
		switch x := v.(type) {
		case *vObject:
			for _, name := range x.names {
				member, _ := x.get(name)
				if name == "descriptorProvenance" {
					if o, ok := member.(*vObject); ok {
						for _, part := range []string{"snapshot", "statement"} {
							if d, ok := memberString(o, part); ok {
								held[d] = true
							}
						}
					}
				}
				walk(member)
			}
		case vArray:
			for _, item := range x {
				walk(item)
			}
		}
	}
	for _, s := range all {
		if v, err := parseJSON(s.data); err == nil {
			walk(v)
		}
	}
	return held
}

// removeArtifactsUnder is the command's work, the registry held: every
// receipt named judged, the records of those that may be removed appended,
// and then their bytes removed.
func removeArtifactsUnder(storeRoot, authority string, priv ed25519.PrivateKey, keys []reachedKey, o removeArtifactOptions, stamp func() string) (out removalOutcome, err error) {
	existing, _, err := readRemovals(storeRoot)
	if err != nil {
		return out, fmt.Errorf("%v, and nothing was removed", err)
	}
	ret := &retention{removals: parseRemovals(existing, keys)}
	all, err := readStoreReceipts(storeRoot, authority, keys, ret)
	if err != nil {
		return out, fmt.Errorf("the store's receipts could not be read, and nothing was removed: %v", err)
	}
	at := map[removalTarget]*storedReceipt{}
	for _, s := range all {
		index, msg := parseRemovalTarget(s.sessionID + "/" + strings.TrimSuffix(s.fileName, ".json"))
		if msg == "" && index.fileName() == s.fileName {
			at[index] = s
		}
	}

	// Each receipt alone.
	var accepted []*storedReceipt
	named := map[*storedReceipt]bool{}
	for _, target := range o.targets {
		s := at[target]
		switch {
		case s == nil:
			out.refused = append(out.refused, fmt.Sprintf("receipt %s is not in the store; nothing is removed for it", target))
		case s.status != "ok":
			out.refused = append(out.refused, fmt.Sprintf("receipt %s does not verify under the keys the registry's walk reached (%s); its bytes are not removed", target, s.status))
		case s.r.kind == "action":
			out.refused = append(out.refused, fmt.Sprintf("receipt %s is an action, whose result /act and its recovery read back; its bytes are kept", target))
		case s.r.notRetained:
			out.refused = append(out.refused, fmt.Sprintf("receipt %s says its call kept no payload; there is nothing to remove", target))
		case !removalScopeHolds(s.r, o):
			// one sentence for a scope that differs, one that is not
			// given, and one given for a receipt that carries none, naming
			// no scope identifier, as /acquire refuses
			out.refused = append(out.refused, fmt.Sprintf("receipt %s: the receipt's scope does not match --scope; its bytes are not removed", target))
		default:
			accepted = append(accepted, s)
			named[s] = true
		}
	}

	// Bytes another receipt still reads, or descriptor provenance does.
	descriptors := descriptorDigests(all)
	var removing []*storedReceipt
	for _, s := range accepted {
		if descriptors[s.r.resultDigest] {
			out.refused = append(out.refused, fmt.Sprintf("receipt %s: its digest is a descriptor snapshot's or statement's in the store, which descriptor provenance reads there; its bytes are kept", s.name()))
			continue
		}
		hexSum := strings.TrimPrefix(s.r.resultDigest, "sha256:")
		var sharing []string
		for _, other := range all {
			if named[other] {
				continue
			}
			shares := other.digest == s.r.resultDigest
			// a file the parser refuses is judged by its bytes: one that
			// spells the digest may be a receipt that reads it
			if !other.parsed {
				shares = bytes.Contains(other.data, []byte(hexSum))
			}
			if shares && !other.keepsNoBytes(ret) {
				sharing = append(sharing, other.name())
			}
		}
		if len(sharing) > 0 {
			out.refused = append(out.refused, fmt.Sprintf("receipt %s shares its bytes with %s, which keeps them; its bytes are kept", s.name(), strings.Join(sharing, ", ")))
			continue
		}
		removing = append(removing, s)
	}

	// Every record first, made durable, then the bytes.
	current := keys[len(keys)-1]
	var lines []byte
	for _, s := range removing {
		if ret.namedBy(s.r, s.sessionID) {
			continue
		}
		record := newObject()
		record.set("callIndex", vInt(s.r.callIndex))
		record.set("keyId", vString(current.keyID))
		record.set("kind", vString(removalKind))
		record.set("receiptSignature", vString(s.r.signature))
		record.set("removedAt", vString(stamp()))
		record.set("removedBy", vString(o.by))
		record.set("resultDigest", vString(s.r.resultDigest))
		record.set("sessionId", vString(s.sessionID))
		record.set("signature", vString(hex.EncodeToString(ed25519.Sign(priv, removalSigningInput(record)))))
		line := string(canon(record))
		// what a reader would not load, or would not take as naming this
		// receipt, is not written
		loaded, ok := removalOf(line, keys)
		probe := &retention{removals: map[string][]removalRecord{loaded.receiptSignature: {loaded}}}
		if !ok || !probe.namedBy(s.r, s.sessionID) {
			return out, fmt.Errorf("receipt %s: a removal record for it would not name it as a verifier reads it, and nothing was removed", s.name())
		}
		lines = append(append(lines, line...), '\n')
		out.appended = append(out.appended, record)
	}
	if len(lines) > 0 {
		if err := appendRemovals(storeRoot, existing, lines); err != nil {
			appended := out.appended
			out.appended = nil
			return out, fmt.Errorf("%v; the %d record(s) may be in the file, and nothing was removed; a second run completes it", err, len(appended))
		}
	}
	for _, s := range removing {
		gone, err := removeKeptBytes(storeRoot, s.r.resultDigest)
		if err != nil {
			return out, fmt.Errorf("receipt %s: %v", s.name(), err)
		}
		if ret.namedBy(s.r, s.sessionID) {
			if gone {
				out.notes = append(out.notes, fmt.Sprintf("receipt %s was recorded as removed already; its bytes, still there, are removed now", s.name()))
			} else {
				out.notes = append(out.notes, fmt.Sprintf("receipt %s was recorded as removed already, and its bytes are not there; nothing is changed for it", s.name()))
			}
		}
	}
	return out, nil
}

// removalScopeHolds is whether --scope gives the receipt's scope byte for
// byte: both none, or both the same bytes, compared in a time that does not
// depend on where they first differ.
func removalScopeHolds(r *receipt, o removeArtifactOptions) bool {
	scope, carries := memberString(r.obj, "scope")
	if !carries {
		return !o.scoped
	}
	return o.scoped && subtle.ConstantTimeCompare([]byte(scope), []byte(o.scope)) == 1
}

// appendRemovals appends the records to the store's removal file and makes
// them durable, the file made where it is not there. A file whose last line
// is unterminated -- an earlier append written in part -- is ended first,
// so the records start on lines of their own and the torn line stays one
// that loads nothing.
func appendRemovals(storeRoot string, existing, lines []byte) error {
	path := filepath.Join(storeRoot, removalsFile)
	log, err := openFsLog(path)
	if err != nil {
		return err
	}
	if _, err := log.readLog(0); faultOf(err) == faultAbsent {
		if err := log.createLog(); err != nil {
			return err
		}
		syncDir(storeRoot)
	} else if err != nil {
		return err
	}
	var data []byte
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		data = append(data, '\n')
	}
	data = append(data, lines...)
	_, err = log.appendRecord(data)
	return err
}

// removeKeptBytes removes the bytes at a digest's path, re-digested first:
// bytes that are not the digest's are not removed. gone is whether there
// were bytes to remove.
func removeKeptBytes(storeRoot, digest string) (gone bool, err error) {
	hexSum := strings.TrimPrefix(digest, "sha256:")
	dir := filepath.Join(storeRoot, "artifacts")
	path := filepath.Join(dir, hexSum)
	if nothingAt(storeRoot, hexSum) {
		return false, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("its bytes cannot be read, and are not removed: %v", err)
	}
	if digestOfBytes(data) != hexSum {
		return false, fmt.Errorf("the bytes at its digest's path are not the receipt's, and are not removed; the record stands, and gateway verify reports artifact-mismatch")
	}
	if err := os.Remove(path); err != nil {
		return false, fmt.Errorf("its bytes could not be removed: %v; the record stands, and a second run removes them", err)
	}
	syncDir(dir)
	return true, nil
}
