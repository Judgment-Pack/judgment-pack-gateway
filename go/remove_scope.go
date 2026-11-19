package main

// `gateway remove-scope` (gateway #434; SPEC.md §1.3a, "A removed session",
// and §6, "Removing one scope identifier's records"; ADR-0034): every
// session of one scope identifier removed from a store of the filesystem
// kind, with the payloads only those sessions name, the gateway stopped, and
// the removal recorded first, in the store's artifact-removals.jsonl, signed
// by the key in force: a session-removal record for each sealed session,
// which a verifier of this version reads at §4 step 4, and a scope-removal
// record for the call. The PostgreSQL kind's is gateway store remove-scope
// (store_remove_scope.go).
//
// A receipt carries the scope where it passes orders 1 to 6 of the ladder
// under the keys the registry's walk reached -- so the scope it carries is
// signed -- and its scope is the one --scope gives, byte for byte. A session
// is removed where it holds a receipt and every receipt it holds carries the
// scope. On this kind nothing binds a session to one scope (ADR-0026), so a
// session holding a receipt that carries the scope beside one that does not
// is refused: removing a part of it would break the chain of what is left.
// So is a receipt left in the store that cites one the call would remove,
// whose citation would no longer resolve. Either refuses the whole call,
// naming each session and receipt, before anything is written: a removal
// made in part would leave the store in a state no one asked for.
//
// Every record is appended, and made durable, before anything is removed;
// then the payloads, and then each session's directory, so a run cut off
// leaves sessions a record names still in the store, which are verified as
// they are (§1.3a), and payloads only a receipt still there names: a second
// run finds both and completes the removal, appending no session's record
// again.
//
// The registry is held as gateway seal-open and gateway remove-artifact
// hold it (holdEngineRegistry), so a running gateway refuses the command.

import (
	"bytes"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const removeScopeUsage = `usage: gateway remove-scope (--config <engine.json> | --store <dir> --seed <file> --registry <file> --authority <authority>) --scope <identifier> --by <label>
Removes, the gateway stopped, every session all of whose receipts carry the
scope identifier, and the payloads only those receipts name, and records the
removal first in the store's artifact-removals.jsonl, signed by the key in
force (SPEC.md §1.3a, §6): a session-removal record for each sealed session
and a scope-removal record for the call. A session holding a receipt of
another scope identifier, of none, or one that does not verify, a session
holding anything but its receipt files, a linked artifacts, receipts or
session directory, and a receipt left in the store that cites one the call
would remove, refuse the whole call, by name, and nothing is removed. --by is a label, recorded and
not checked. Prints each record appended, as its line. On the PostgreSQL
kind, gateway store remove-scope removes a scope identifier's rows.`

// removeScopeOptions is the command line.
type removeScopeOptions struct {
	// keyVersion and keyPublic are the configuration's signingKeyVersion
	// and signingPublicKey: the key service's key version the command signs
	// through, "" where the seed signs (ADR-0050)
	keyVersion, keyPublic      string
	store, registry, authority string
	seedNames                  []string
	scope                      string
	by                         string
}

func parseRemoveScope(args []string) (removeScopeOptions, string) {
	flags := map[string]string{}
	for rest := args; len(rest) > 0; rest = rest[2:] {
		name := rest[0]
		switch name {
		case "--config", "--store", "--seed", "--registry", "--authority", "--scope", "--by":
		default:
			return removeScopeOptions{}, ""
		}
		if len(rest) < 2 || rest[1] == "" {
			return removeScopeOptions{}, ""
		}
		if _, given := flags[name]; given {
			return removeScopeOptions{}, name + " is given twice"
		}
		flags[name] = rest[1]
	}
	if flags["--scope"] == "" || flags["--by"] == "" {
		return removeScopeOptions{}, ""
	}
	if !isScopeIdentifier(flags["--scope"]) {
		return removeScopeOptions{}, "--scope is a scope identifier: " + scopeForm
	}
	if !isScopeIdentifier(flags["--by"]) {
		return removeScopeOptions{}, "--by is a label of the form of a scope identifier: " + scopeForm
	}
	o := removeScopeOptions{scope: flags["--scope"], by: flags["--by"]}
	if config := flags["--config"]; config != "" {
		for _, other := range []string{"--store", "--seed", "--registry", "--authority"} {
			if flags[other] != "" {
				return removeScopeOptions{}, "--config names the store, the seed, the registry and the authority; " + other + " is not given beside it"
			}
		}
		data, err := readBounded(config, maxEngineConfigBytes)
		if err != nil {
			return removeScopeOptions{}, fmt.Sprintf("engine configuration: %v", err)
		}
		cfg, err := parseEngineConfig(data)
		if err != nil {
			return removeScopeOptions{}, err.Error()
		}
		if cfg.storage != nil {
			return removeScopeOptions{}, fmt.Errorf("%w: gateway remove-scope removes the files of a store on disk; on the PostgreSQL kind, gateway store remove-scope removes a scope identifier's rows", errStorageKindUnsupported).Error()
		}
		o.keyVersion, o.keyPublic = cfg.signingKeyVersion, cfg.signingPublicKey
		o.store, o.registry, o.authority, o.seedNames = cfg.store, cfg.registry, cfg.authority, []string{cfg.seed}
		if resolved, err := filepath.EvalSymlinks(cfg.seed); err == nil && resolved != cfg.seed {
			o.seedNames = append(o.seedNames, resolved)
		}
		return o, "ok"
	}
	for _, need := range []string{"--store", "--seed", "--registry", "--authority"} {
		if flags[need] == "" {
			return removeScopeOptions{}, ""
		}
	}
	o.store, o.registry, o.authority, o.seedNames = flags["--store"], flags["--registry"], flags["--authority"], []string{flags["--seed"]}
	return o, "ok"
}

func cmdRemoveScope(args []string, stdout, stderr io.Writer) int {
	return cmdRemoveScopeAt(args, stdout, stderr, nowStamp)
}

// cmdRemoveScopeAt is the command, each record stamped by stamp.
func cmdRemoveScopeAt(args []string, stdout, stderr io.Writer, stamp func() string) int {
	o, msg := parseRemoveScope(args)
	switch msg {
	case "ok":
	case "":
		fmt.Fprintln(stderr, removeScopeUsage)
		return 2
	default:
		fmt.Fprintf(stderr, "remove-scope: %s\n%s\n", msg, removeScopeUsage)
		return 2
	}
	out, unlocked, err := removeScope(o, stamp)
	for _, record := range out.appended {
		fmt.Fprintf(stdout, "%s\n", canon(record))
	}
	for _, note := range out.notes {
		fmt.Fprintln(stderr, "remove-scope:", note)
	}
	for _, refusal := range out.refused {
		fmt.Fprintln(stderr, "remove-scope:", refusal)
	}
	if unlocked {
		fmt.Fprintln(stderr, "remove-scope: this platform locks no registry, so a gateway still running was not looked for; the gateway was to be stopped")
	}
	if err != nil {
		fmt.Fprintln(stderr, "remove-scope:", err)
		return 1
	}
	if len(out.refused) > 0 {
		return 1
	}
	return 0
}

// removeScope is the command: the seed read, the registry there and held as
// a gateway holds it while it runs, and the scope's sessions removed under
// it. unlocked is a platform that locks no registry.
func removeScope(o removeScopeOptions, stamp func() string) (out removalOutcome, unlocked bool, err error) {
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
	sig, err := commandSigner(o.keyVersion, o.keyPublic, seed)
	if err != nil {
		return out, false, err
	}
	key := newSigningKey(sig)
	hold, err := holdEngineRegistryKey(o.seedNames, o.registry, key.public)
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
	walk, err := engineWalk(data, key.public)
	if err != nil {
		return out, unlocked, err
	}
	if err := heldUnderAnotherKey(data, walk.keys, key.public, newFsKind(fsLayout{store: o.store}).receipts()); err != nil {
		return out, unlocked, err
	}
	out, err = removeScopeFrom(o.store, o.authority, key, walk, o, stamp)
	return out, unlocked, err
}

// passesSignedOrders is whether a receipt's ladder status is past order 6
// (SPEC.md §1.4): its form, its version, its key, its signature, its place
// and its authority hold, so every member it carries is signed by a key the
// walk reached. Its artifact step may still find it artifact-missing or
// artifact-mismatch: what is at its digest's path is not what it carries.
func passesSignedOrders(s *storedReceipt) bool {
	if s.r == nil {
		return false
	}
	switch s.status {
	case "malformed", "unsupported-version", "key-mismatch", "signature-mismatch", "misfiled", "authority-mismatch":
		return false
	}
	return true
}

// carriesScope is whether the receipt carries the scope identifier: it
// passes the signed orders and its scope is scope byte for byte, compared
// in a time that does not depend on where the two first differ.
func carriesScope(s *storedReceipt, scope string) bool {
	if !passesSignedOrders(s) {
		return false
	}
	carried, ok := memberString(s.r.obj, "scope")
	return ok && subtle.ConstantTimeCompare([]byte(carried), []byte(scope)) == 1
}

// removedInScope is whether a session-removal record of the scope that
// loaded names the sealed session (sessionRemoved, its scope besides).
func removedInScope(ret *retention, sessionID string, s seal, scope string) bool {
	for _, rec := range ret.sessions[sessionID] {
		if rec.sealSignature == s.signature && rec.finalCount == s.finalCount && rec.keyPos >= s.keyPos &&
			subtle.ConstantTimeCompare([]byte(rec.scope), []byte(scope)) == 1 {
			return true
		}
	}
	return false
}

// scopeRemovalPlan is what a call removes: the sessions in byte order, the
// receipts they hold, the payloads by their digests' hex in byte order, and
// the empty directories of sealed sessions a record of the scope names.
type scopeRemovalPlan struct {
	sessions []string
	sealed   int64
	receipts []*storedReceipt
	payloads []string
	empty    []string
}

// removeScopeFrom is the command's work, the registry held: the store read,
// the plan made and refused whole or kept, the records appended, and then
// the payloads and the sessions removed.
func removeScopeFrom(storeRoot, authority string, priv *signingKey, walk *registryWalk, o removeScopeOptions, stamp func() string) (out removalOutcome, err error) {
	keys := walk.keys
	// the records already there, read as a verifier reads them; where
	// something at the file's path is not a regular file nothing is read
	// through it, nor written beside it
	records, torn, err := readRecords(storeRoot, keys)
	if err != nil {
		return out, fmt.Errorf("%v, and nothing was removed", err)
	}
	ret := &retention{removals: records.artifacts, sessions: records.sessions}
	all, err := readStoreReceipts(storeRoot, authority, keys, ret)
	if err != nil {
		return out, fmt.Errorf("the store's receipts could not be read, and nothing was removed: %v", err)
	}
	sessions, err := listSessions(storeRoot)
	if err != nil {
		return out, fmt.Errorf("the store's receipts could not be read, and nothing was removed: %v", err)
	}
	plan, refused := planScopeRemoval(storeRoot, all, sessions, walk, ret, o.scope)
	if len(refused) > 0 {
		out.refused = append(refused, "nothing was removed")
		return out, nil
	}
	if len(plan.sessions) == 0 && len(plan.empty) == 0 {
		out.notes = append(out.notes, "no session of the scope identifier is in the store; nothing was removed")
		return out, nil
	}

	// Every record first, each read back as a verifier reads it, then
	// appended and made durable.
	held := map[string][]*storedReceipt{}
	for _, s := range plan.receipts {
		held[s.sessionID] = append(held[s.sessionID], s)
	}
	var lines []byte
	for _, session := range plan.sessions {
		s, sealed := walk.seals[session]
		if !sealed {
			continue
		}
		if removedInScope(ret, session, s, o.scope) {
			out.notes = append(out.notes, fmt.Sprintf("session %s was recorded as removed already; its files, still there, are removed now", session))
			continue
		}
		record, line, err := signedSessionRemoval(priv, keys, session, s, o.scope, carriedSalt(held[session]), o.by, stamp())
		if err != nil {
			return out, fmt.Errorf("%v, and nothing was removed", err)
		}
		lines = append(lines, line...)
		out.appended = append(out.appended, record)
	}
	if len(plan.sessions) > 0 {
		record, line, err := signedScopeRemoval(priv, keys, o.scope, o.by, stamp(), scopeRemovalCounts{
			open: int64(len(plan.sessions)) - plan.sealed, sealed: plan.sealed,
			receipts: int64(len(plan.receipts)), payloads: int64(len(plan.payloads)),
		})
		if err != nil {
			return out, fmt.Errorf("%v, and nothing was removed", err)
		}
		lines = append(lines, line...)
		out.appended = append(out.appended, record)
	}
	if len(lines) > 0 {
		if err := appendRemovals(storeRoot, torn, lines); err != nil {
			appended := out.appended
			out.appended = nil
			return out, fmt.Errorf("%v; the %d record(s) may be in the file, and nothing was removed; a second run completes it", err, len(appended))
		}
	}

	// Then the payloads, while the receipts that name them are still there
	// for a second run to find, and then the sessions.
	root, err := os.OpenRoot(storeRoot)
	if err != nil {
		return out, fmt.Errorf("the store: %v; the records stand, and a second run completes the removal", err)
	}
	defer root.Close()
	for _, hexSum := range plan.payloads {
		if err := root.Remove(filepath.Join("artifacts", hexSum)); err != nil && !absent(err) {
			return out, fmt.Errorf("a payload could not be removed: %v; the records stand, and a second run completes the removal", err)
		}
	}
	if len(plan.payloads) > 0 {
		syncDir(filepath.Join(storeRoot, "artifacts"))
	}
	// Each receipt the plan read, and then its session's directory, which the
	// plan found holding nothing else: removing it fails, and nothing more
	// is removed, where something came into it since.
	files := map[string][]string{}
	for _, s := range plan.receipts {
		files[s.sessionID] = append(files[s.sessionID], s.fileName)
	}
	for _, session := range append(append([]string{}, plan.sessions...), plan.empty...) {
		for _, name := range files[session] {
			if err := root.Remove(filepath.Join("receipts", session, name)); err != nil && !absent(err) {
				return out, fmt.Errorf("session %s could not be removed: %v; the records stand, and a second run completes the removal", session, err)
			}
		}
		if err := root.Remove(filepath.Join("receipts", session)); err != nil && !absent(err) {
			return out, fmt.Errorf("session %s could not be removed: %v; the records stand, and a second run completes the removal", session, err)
		}
	}
	syncDir(filepath.Join(storeRoot, "receipts"))
	for _, session := range plan.empty {
		out.notes = append(out.notes, fmt.Sprintf("session %s was recorded as removed already, and its directory held no receipt; the directory is removed now", session))
	}
	out.notes = append(out.notes, fmt.Sprintf("removed %d session(s), %d sealed, holding %d receipt(s), and %d payload(s)", len(plan.sessions), plan.sealed, len(plan.receipts), len(plan.payloads)))
	return out, nil
}

// carriedSalt is the scope salt the session's receipts carry (ADR-0042), as
// the first of them that passed the signed orders gives it, "" where none
// does. A salt that is not the seal's is not looked past: the record made
// over it would not name the session, and the call is refused.
func carriedSalt(receipts []*storedReceipt) string {
	for _, s := range receipts {
		if !passesSignedOrders(s) {
			continue
		}
		if salt, ok := memberString(s.r.obj, "scopeSalt"); ok {
			return salt
		}
	}
	return ""
}

// signedSessionRemoval is the session-removal record of a sealed session,
// signed by priv, the key the registry's walk ends at, and its line, read
// back as a verifier reads the removal file before it is kept: it names the
// session and its seal, or it is refused. Both kinds' commands make it. A
// seal of version 3 is named over the scope salt salt, which the record
// carries (ADR-0042); a seal of another form is named as before, and the
// record carries no salt.
func signedSessionRemoval(priv *signingKey, keys []reachedKey, session string, s seal, scope, salt, by, at string) (*vObject, []byte, error) {
	record := newObject()
	record.set("finalCount", vInt(s.finalCount))
	record.set("keyId", vString(keys[len(keys)-1].keyID))
	record.set("kind", vString(sessionRemovalKind))
	record.set("removedAt", vString(at))
	record.set("removedBy", vString(by))
	record.set("scope", vString(scope))
	if s.salted {
		record.set("scopeSalt", vString(salt))
	}
	record.set("sealSignature", vString(s.signature))
	record.set("sessionId", vString(session))
	signature, err := priv.signVerified(recordSigningInput(sessionRemovalContext, record))
	if err != nil {
		return nil, nil, err
	}
	record.set("signature", vString(hex.EncodeToString(signature)))
	line := append(canon(record), '\n')
	loaded, _, _ := scanRecords(bytes.NewReader(line), keys)
	if probe := (&retention{sessions: loaded.sessions}); !probe.sessionRemoved(session, s) {
		return nil, nil, fmt.Errorf("session %s: a session-removal record for it would not name it as a verifier reads it", session)
	}
	return record, line, nil
}

// scopeRemovalCounts is what a scope-removal record counts.
type scopeRemovalCounts struct {
	open, sealed, receipts, payloads int64
}

// signedScopeRemoval is the call's scope-removal record, signed as
// signedSessionRemoval's, and its line, read back as a verifier reads it.
func signedScopeRemoval(priv *signingKey, keys []reachedKey, scope, by, at string, n scopeRemovalCounts) (*vObject, []byte, error) {
	record := newObject()
	record.set("keyId", vString(keys[len(keys)-1].keyID))
	record.set("kind", vString(scopeRemovalKind))
	record.set("openSessions", vInt(n.open))
	record.set("payloads", vInt(n.payloads))
	record.set("receipts", vInt(n.receipts))
	record.set("removedAt", vString(at))
	record.set("removedBy", vString(by))
	record.set("scope", vString(scope))
	record.set("sealedSessions", vInt(n.sealed))
	signature, err := priv.signVerified(recordSigningInput(scopeRemovalContext, record))
	if err != nil {
		return nil, nil, err
	}
	record.set("signature", vString(hex.EncodeToString(signature)))
	line := append(canon(record), '\n')
	if !readsBackAsScopeRemoval(line, keys) {
		return nil, nil, errors.New("the call's scope-removal record would not load as a verifier reads the file")
	}
	return record, line, nil
}

// readsBackAsScopeRemoval is whether the line, read as a verifier reads the
// removal file, is one line within the bound that loads as a scope-removal
// record under the keys the walk reached.
func readsBackAsScopeRemoval(line []byte, keys []reachedKey) bool {
	if len(line) > removalLineBound || bytes.IndexByte(line, '\n') != len(line)-1 {
		return false
	}
	v, err := parseJSON(line[:len(line)-1])
	if err != nil {
		return false
	}
	obj, ok := v.(*vObject)
	if !ok {
		return false
	}
	_, ok = scopeRemovalOf(obj, keys)
	return ok
}

// planScopeRemoval is what the call would remove, or every reason it
// refuses, each naming a session or a receipt and never the scope
// identifier.
func planScopeRemoval(storeRoot string, all []*storedReceipt, sessions []string, walk *registryWalk, ret *retention, scope string) (plan scopeRemovalPlan, refused []string) {
	// The removal goes through the store's root, which refuses a path that
	// leads out of it: artifacts/ or receipts/ that is a symbolic link, or
	// not a directory, refuses the call here, before anything is written,
	// and not after the records, on this run and every one after it.
	for _, dir := range []string{"artifacts", "receipts"} {
		if why := notARealDirectory(filepath.Join(storeRoot, dir)); why != "" {
			refused = append(refused, fmt.Sprintf("the store's %s/ %s; nothing is removed through it", dir, why))
		}
	}
	if len(refused) > 0 {
		return plan, refused
	}
	held := map[string][]*storedReceipt{}
	for _, s := range all {
		held[s.sessionID] = append(held[s.sessionID], s)
	}
	planned := map[string]bool{}
	for _, session := range sessions {
		receipts := held[session]
		if len(receipts) == 0 {
			// a directory holding no receipt: removed only where it is a
			// sealed session a record of the scope names, which a run cut
			// off between its last receipt and its directory leaves
			if requireSession(session) != nil {
				continue
			}
			if s, sealed := walk.seals[session]; sealed && removedInScope(ret, session, s, scope) {
				plan.empty = append(plan.empty, session)
			}
			continue
		}
		var others []string
		for _, s := range receipts {
			if !carriesScope(s, scope) {
				others = append(others, s.name())
			}
		}
		switch {
		case len(others) == len(receipts):
		case len(others) > 0:
			refused = append(refused, fmt.Sprintf("session %s holds receipts of the scope identifier beside %s, of another scope identifier, of none, or not verifying under the keys the registry's walk reached; the session is left whole", session, strings.Join(others, ", ")))
		default:
			planned[session] = true
			plan.sessions = append(plan.sessions, session)
			if _, sealed := walk.seals[session]; sealed {
				plan.sealed++
			}
			plan.receipts = append(plan.receipts, receipts...)
		}
	}

	// A session's directory that is a symbolic link, or not a directory, or
	// that holds anything but receipt files: the receipts read are what the
	// records count, and only they are removed, then the directory, empty.
	for _, session := range append(append([]string{}, plan.sessions...), plan.empty...) {
		dir := filepath.Join(storeRoot, "receipts", session)
		if why := notARealDirectory(dir); why != "" {
			refused = append(refused, fmt.Sprintf("the directory of session %s %s; the session is left whole", session, why))
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			refused = append(refused, fmt.Sprintf("the directory of session %s could not be read (%v); the session is left whole", session, err))
			continue
		}
		for _, e := range entries {
			if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".json") {
				refused = append(refused, fmt.Sprintf("the directory of session %s holds something other than a receipt file, which the call would neither count nor record; the session is left whole", session))
				break
			}
		}
	}

	// A receipt left in the store that cites one the call would remove.
	var signatures []string
	for _, s := range plan.receipts {
		signatures = append(signatures, s.r.signature)
	}
	var left []*storedReceipt
	for _, s := range all {
		if planned[s.sessionID] {
			continue
		}
		left = append(left, s)
		if s.r == nil {
			// bytes the parser refuses are judged by what they spell: one
			// that spells a removed receipt's signature may cite it
			for _, p := range plan.receipts {
				if bytes.Contains(s.data, []byte(p.r.signature)) {
					refused = append(refused, fmt.Sprintf("receipt %s does not parse, and its bytes spell the signature of receipt %s, which the call would remove; it is left as it is", s.name(), p.name()))
					break
				}
			}
			continue
		}
		cites := append([]citation{}, s.r.cites...)
		if s.r.reconciliation != nil {
			cites = append(cites, s.r.reconciliation.action)
		}
		for _, c := range cites {
			if planned[c.sessionID] {
				refused = append(refused, fmt.Sprintf("receipt %s cites receipt %s/%d, of session %s, which the call would remove; its citation would no longer resolve", s.name(), c.sessionID, c.callIndex, c.sessionID))
				break
			}
		}
	}

	// The payloads only the removed receipts name.
	descriptors := descriptorDigests(all)
	digests := map[string]bool{}
	for _, s := range plan.receipts {
		if s.r.notRetained || descriptors[s.r.resultDigest] {
			continue
		}
		digests[s.r.resultDigest] = true
	}
	var names []string
	for digest := range digests {
		names = append(names, digest)
	}
	sort.Strings(names)
	for _, digest := range names {
		hexSum := strings.TrimPrefix(digest, "sha256:")
		shared := false
		for _, other := range left {
			shares := other.digest == digest
			if !other.parsed {
				shares = bytes.Contains(other.data, []byte(hexSum))
			}
			if shares && !other.keepsNoBytes(ret) {
				shared = true
				break
			}
		}
		if shared || nothingAt(storeRoot, hexSum) {
			continue
		}
		info, err := os.Lstat(filepath.Join(storeRoot, "artifacts", hexSum))
		if err != nil || !info.Mode().IsRegular() {
			refused = append(refused, fmt.Sprintf("the payload a receipt of session %s names is at a path that holds something other than a regular file; it is not removed", payloadOwner(plan.receipts, digest)))
			continue
		}
		plan.payloads = append(plan.payloads, hexSum)
	}
	return plan, refused
}

// notARealDirectory is why what is at path, looked at without following a
// symbolic link, is not a directory, or "" where it is one or nothing is
// there.
func notARealDirectory(path string) string {
	info, err := lstat(path)
	switch {
	case err != nil && absent(err):
		return ""
	case err != nil:
		return fmt.Sprintf("could not be looked at (%v)", err)
	case info.Mode()&os.ModeSymlink != 0:
		return "is a symbolic link"
	case !info.IsDir():
		return "is not a directory"
	}
	return ""
}

// payloadOwner is the session of the first receipt to name the digest.
func payloadOwner(receipts []*storedReceipt, digest string) string {
	for _, s := range receipts {
		if s.r.resultDigest == digest {
			return s.sessionID
		}
	}
	return ""
}
