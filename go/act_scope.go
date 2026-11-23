package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// /act's scope identifier (docs/adr/0054-act-takes-a-scope-a-dry-run-is-signed-as-no-action-and-an-action-cites-approval-records.md,
// decision 1). From actScopeVersion a platform may set scope beside write:
// true. /act then takes scope as /acquire takes it, and the action's receipt
// carries scope and scopeSalt. Where no write source is fixed to a scope
// identifier, nothing here changes an answer: the member is refused as one
// /act does not read, and every step answers as it did.

// reachRefusalScopedAct is /act's answer before the body is read where some
// write source is fixed to a scope identifier and the caller's token reaches
// none of the write sources. It names no scope identifier.
const reachRefusalScopedAct = "scope identifier: this caller's token reaches no write source"

// scopedWrite is whether some write source is fixed to a scope identifier.
func (g *gatewayService) scopedWrite() bool {
	for name, spec := range g.sources {
		if strings.HasSuffix(name, "/write") && spec.scope != "" {
			return true
		}
	}
	return false
}

// writeReachRefusal is /act's refusal before the body is read (ADR-0054,
// step 2), or "". Where no write source is fixed to a scope identifier it is
// the one it was (ADR-0037): a caller that does not reach the sources of
// none. Otherwise it is a caller that reaches no write source.
func (g *gatewayService) writeReachRefusal(who *caller) string {
	reach := g.reachOf(who)
	if !g.scopedWrite() {
		if reach.holds("") {
			return ""
		}
		return reachRefusalAct
	}
	for name, spec := range g.sources {
		if strings.HasSuffix(name, "/write") && reach.holds(spec.scope) {
			return ""
		}
	}
	return reachRefusalScopedAct
}

// actScope reads the request's scope member at the scope step (ADR-0054,
// step 8): after the receipt version and before the session is looked up,
// so a label is never looked up in a namespace the caller does not reach,
// and before anything of the action key. A scope that is not a string, one
// named under a delegation or by a reservation's sender (neither reaches a
// scope identifier, SPEC.md §6), and one the caller's token does not reach
// are one refusal, /acquire's sentence, which quotes neither identifier.
// So is a request that names no scope from a caller whose token does not
// reach none, where some write source is fixed to a scope identifier: its
// label would be looked up in the namespace of none, which the caller does
// not reach (steps 8 and 9), and the session step's answer would tell it the
// state of a session of none.
func (g *gatewayService) actScope(raw json.RawMessage, who *caller) (requestedScope, error) {
	if len(raw) == 0 {
		if g.scopedWrite() && !g.reachOf(who).holds("") {
			return requestedScope{}, actRefusal{"scope-identifier", scopeRefusal}
		}
		return requestedScope{}, nil
	}
	v, err := parseJSON(raw)
	s, isString := v.(vString)
	if err != nil || !isString || who.delegated != nil || !g.scopedWrite() || !g.reachOf(who).holds(string(s)) {
		return requestedScope{}, actRefusal{"scope-identifier", scopeRefusal}
	}
	return requestedScope{value: string(s), named: true}, nil
}

// actPlatformScope is the platform step (ADR-0054, step 10). Where no write
// source is fixed to a scope identifier it answers as it did. Otherwise a
// platform with no write source, asked by a caller that does not reach every
// source, and a write source whose scope identifier is not the request's,
// are answered with the scope step's sentence, so the caller learns neither
// which platforms other scopes use nor which scope a platform is fixed to.
func (g *gatewayService) actPlatformScope(platform string, spec sourceSpec, known bool, asked requestedScope, who *caller) error {
	noWrites := actRefusal{"platform", fmt.Sprintf("platform %s allows no writes: a write source is derived only for a platform whose configuration sets write: true and whose binding states a write operation", requestText(platform))}
	if !g.scopedWrite() {
		if !known {
			return noWrites
		}
		if spec.scope != "" {
			return actRefusal{"platform", fmt.Sprintf("platform %s is fixed to a scope identifier, and /act takes none", requestText(platform))}
		}
		return nil
	}
	reach := g.reachOf(who)
	if !known {
		if !g.reachesEverySource(reach) {
			return actRefusal{"scope-identifier", scopeRefusal}
		}
		return noWrites
	}
	if !acquisitionHeld(spec, asked, reach) {
		return actRefusal{"scope-identifier", scopeRefusal}
	}
	return nil
}

// parsePlatformDecisionRecords reads a platform's decisionRecords (ADR-0054,
// decision 1): from actScopeVersion, the decision-record directory of a write
// fixed to a scope identifier, which such a platform must name. Such a
// platform is held to checked caller scopes as well: a scope on a write that
// every caller may name is a label posing as a boundary. Where the directory
// lies is held by decisionRecordsApart once every platform is read.
func parsePlatformDecisionRecords(p *vObject, name, version string, write bool, scope string, callers *callerScopes) (string, error) {
	v, present := p.get("decisionRecords")
	if present && !versionAtLeast(version, actScopeVersion) {
		return "", fmt.Errorf("engine configuration: platform %s: decisionRecords is a platform member from engineVersion %s; engineVersion %s has none", name, actScopeVersion, version)
	}
	if !write || scope == "" {
		if present {
			return "", fmt.Errorf("engine configuration: platform %s: decisionRecords is the decision-record directory of a write fixed to a scope identifier, and the platform is not one; an unscoped write finds its record in the gateway's decisionRecords", name)
		}
		return "", nil
	}
	if callers == nil || callers.unchecked || callers.entries == nil {
		return "", fmt.Errorf("engine configuration: platform %s: a write fixed to a scope identifier needs identity.callerScopes as an object, so that each caller is held to the scope identifiers it reaches; with \"unchecked\", or with no callerScopes, it would be a label any caller names", name)
	}
	if !present {
		return "", fmt.Errorf("engine configuration: platform %s: a write fixed to a scope identifier needs its own decisionRecords, a directory apart from the gateway's and from every other scope's", name)
	}
	dir, ok := stringOf(v)
	if !ok || !filepath.IsAbs(dir) {
		return "", fmt.Errorf("engine configuration: platform %s: decisionRecords must be an absolute path", name)
	}
	if err := requirePlainSpelling(dir, false); err != nil {
		return "", fmt.Errorf("engine configuration: platform %s: decisionRecords: %w", name, err)
	}
	return dir, nil
}

// decisionRecordsApart holds each scoped write's decision-record directory
// apart (ADR-0054, decision 1): never the gateway's, never another scope's,
// and never beneath or above either, so a write in one scope rests on no
// record made for another, and no /act learns whether a record of another
// scope is there. Platforms of one scope identifier may share a directory.
// nested is nestedAsSpelled at load, and nestedOnDisk at start.
func decisionRecordsApart(gateway string, platforms []platformConfig, nested func(a, b string) bool) error {
	for i, p := range platforms {
		if p.decisionRecords == "" {
			continue
		}
		if gateway != "" && nested(p.decisionRecords, gateway) {
			return fmt.Errorf("engine configuration: platform %s: decisionRecords is the gateway's decisionRecords, or beneath or above it; a write fixed to a scope identifier finds its record in a directory of its own", p.name)
		}
		for _, q := range platforms[i+1:] {
			if q.decisionRecords != "" && q.scope != p.scope && nested(p.decisionRecords, q.decisionRecords) {
				return fmt.Errorf("engine configuration: platforms %s and %s are fixed to different scope identifiers, and one's decisionRecords is the other's, or beneath or above it", p.name, q.name)
			}
		}
	}
	return nil
}

// nestedAsSpelled is the load check: the cleaned paths, byte for byte.
func nestedAsSpelled(a, b string) bool {
	return pathsNested(filepath.Clean(a), filepath.Clean(b))
}

// nestedOnDisk is the start check: the paths once every part that exists is
// resolved through its links, and, where one of them is there, the directory
// itself (os.SameFile), so two names for one directory, as a filesystem that
// does not tell case apart gives, are one, and so is a directory beneath
// another under a name of that kind.
func nestedOnDisk(a, b string) bool {
	return pathsNested(resolvedOrClean(a), resolvedOrClean(b)) || sameDirOrBeneath(a, b) || sameDirOrBeneath(b, a)
}

// statOnDisk is os.Stat; a test stands a filesystem that does not tell case
// apart in its place.
var statOnDisk = os.Stat

// sameDirOrBeneath is whether path, or a directory above it that is there,
// is the directory dir is, where dir is there.
func sameDirOrBeneath(dir, path string) bool {
	held, err := statOnDisk(dir)
	if err != nil || !held.IsDir() {
		return false
	}
	for at := resolvedOrClean(path); ; {
		if info, err := statOnDisk(at); err == nil && os.SameFile(held, info) {
			return true
		}
		parent := filepath.Dir(at)
		if parent == at {
			return false
		}
		at = parent
	}
}

// resolvedOrClean is the path with every link followed: where the path is
// not there yet, its nearest ancestor that is there is resolved and the rest
// appended, so a directory not made yet beneath a link is held where the link
// leads, never where its spelling seems to be. A link that leads nowhere yet
// is followed by its text, for the same reason.
func resolvedOrClean(path string) string { return resolvedFrom(path, 0) }

// resolvedLinkDepth bounds the links resolvedFrom follows by their text.
const resolvedLinkDepth = 40

func resolvedFrom(path string, depth int) string {
	path = filepath.Clean(path)
	var rest []string // the components not there yet, deepest first
	beneath := func(dir string) string {
		for i := len(rest) - 1; i >= 0; i-- {
			dir = filepath.Join(dir, rest[i])
		}
		return dir
	}
	for at := path; ; {
		if resolved, err := filepath.EvalSymlinks(at); err == nil {
			return beneath(resolved)
		}
		if target, err := os.Readlink(at); err == nil && depth < resolvedLinkDepth {
			// the link's text is taken a part at a time, each resolved before
			// the next, so a ".." in it leaves the directory the filesystem
			// would reach, not the one its spelling seems to name
			base := string(filepath.Separator)
			if !filepath.IsAbs(target) {
				base = resolvedFrom(filepath.Dir(at), depth+1)
			} else if vol := filepath.VolumeName(target); vol != "" {
				base = vol + string(filepath.Separator)
			}
			return resolvedFrom(beneath(linkTextFrom(base, target, depth+1)), depth+1)
		}
		parent := filepath.Dir(at)
		if parent == at {
			return path
		}
		rest = append(rest, filepath.Base(at))
		at = parent
	}
}

// linkTextFrom is a link's text taken from base a part at a time: "." is
// passed over, ".." is the parent of what is reached so far, which is
// resolved, and any other part is joined and resolved before the next.
func linkTextFrom(base, text string, depth int) string {
	text = strings.TrimPrefix(text, filepath.VolumeName(text))
	for _, part := range strings.Split(filepath.ToSlash(text), "/") {
		switch part {
		case "", ".":
		case "..":
			base = filepath.Dir(base)
		default:
			base = resolvedFrom(filepath.Join(base, part), depth)
		}
	}
	return base
}

// pathsNested is whether two clean absolute paths are one, or one is beneath
// the other.
func pathsNested(a, b string) bool {
	return recordsDirHolds(a, b) || recordsDirHolds(b, a)
}

func recordsDirHolds(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// actionNamespaceIn is the key's namespace for an action of a scope
// identifier, or none's (actionNamespace, byte for byte, for an action of
// none). A scoped key is derived from the authority, the scope identifier,
// the issuer, the subject and the key, so a request in one scope never reads
// a reservation, a first scope or a close of another: there the key is one
// never seen, and action-key-scope-conflict speaks within one scope alone.
func (g *gatewayService) actionNamespaceIn(who *caller, key, scope string) string {
	if scope == "" {
		return g.actionNamespace(who, key)
	}
	v := newObject()
	v.set("authority", vString(g.authority))
	v.set("scope", vString(scope))
	if who.delegated != nil {
		// never reached: a delegated request names no scope (actScope)
		v.set("delegation", who.delegated.scope.value())
	} else {
		v.set("issuer", vString(who.issuer))
		v.set("subject", vString(who.subject))
	}
	v.set("key", vString(key))
	return actionHash("scoped-action-key", v)
}

// scopeDecisionRecords is each scope identifier's decision-record
// directories, those of its write platforms, once each and in order: where
// /verify looks for a scoped action's record (ADR-0054), and nowhere else.
func (g *gatewayService) scopeDecisionRecords() map[string][]string {
	dirs := map[string][]string{}
	for _, spec := range g.sources {
		if spec.scope != "" && spec.decisionRecords != "" && !contains(dirs[spec.scope], spec.decisionRecords) {
			dirs[spec.scope] = append(dirs[spec.scope], spec.decisionRecords)
		}
	}
	for scope := range dirs {
		sort.Strings(dirs[scope])
	}
	return dirs
}

// scopedActionJournals is the directory of the journal that holds each scope
// identifier's journal, its entries and its first-scope index, apart from the
// journal of none: removing a scope removes its journal whole, and the
// journal of none reads as it did. Its name is no journal entry's; journal
// compaction compacts each journal in it by the journal of none's rule.
const scopedActionJournals = "scopes"

// scopedActionJournalName is a scope identifier's journal directory.
func scopedActionJournalName(scope string) string {
	v := newObject()
	v.set("scope", vString(scope))
	return actionHash("action-scope-journal", v)
}

// openScopedActionJournal is the journal of a scope identifier, made where it
// is not there yet, or the journal of none for "".
func openScopedActionJournal(storeRoot, scope string) (*actionJournal, error) {
	journal, err := openActionJournal(storeRoot)
	if err != nil || scope == "" {
		return journal, err
	}
	defer journal.close()
	scopes, err := openActionChild(journal.root, scopedActionJournals)
	if err != nil {
		return nil, err
	}
	defer scopes.Close()
	root, err := openActionChild(scopes, scopedActionJournalName(scope))
	if err != nil {
		return nil, err
	}
	return &actionJournal{root}, nil
}

func openActionChild(parent *os.Root, name string) (*os.Root, error) {
	if err := parent.Mkdir(name, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, errors.New("action-journal-unavailable: cannot create a scope identifier's private journal")
	}
	if err := syncActionDirectory(parent); err != nil {
		return nil, err
	}
	return openActionDirectory(parent, name)
}

// scopedActionJournalPath is where a scope identifier's journal is.
func scopedActionJournalPath(storeRoot, scope string) string {
	return filepath.Join(storeRoot, "actions", scopedActionJournals, scopedActionJournalName(scope))
}

// pendingScopedKeys is a refusal for each key of the scope identifier's
// journal that is pending (ADR-0054, "Removal"): dispatched without an
// answer, or answered uncertain with no read-back receipt in the store that
// resolves it. Each names its key where the journal holds it (the first-scope
// index, or the action's receipt), and its entry otherwise. An entry that
// does not read is pending: the call fails closed.
func pendingScopedKeys(storeRoot, scope string, all []*storedReceipt) ([]string, error) {
	path := scopedActionJournalPath(storeRoot, scope)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	store, err := os.OpenRoot(storeRoot)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	actions, err := openActionDirectory(store, "actions")
	if err != nil {
		return nil, err
	}
	defer actions.Close()
	scopes, err := openActionDirectory(actions, scopedActionJournals)
	if err != nil {
		return nil, err
	}
	defer scopes.Close()
	root, err := openActionDirectory(scopes, scopedActionJournalName(scope))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	keys := map[string]string{} // by reservation, from the first-scope index
	if index, err := openActionDirectory(root, actionIndexDirectory); err == nil {
		records, _ := listHeld(index)
		for _, e := range records {
			if raw, err := readActionRecord(index, e.Name(), actionIndexLimit); err == nil {
				if v, err := parseJSON(raw); err == nil {
					if obj, ok := v.(*vObject); ok {
						key, _ := memberString(obj, "key")
						reservation, _ := memberString(obj, "reservation")
						keys[reservation] = key
					}
				}
			}
		}
		index.Close()
	}
	entries, err := listHeld(root)
	if err != nil {
		return nil, err
	}
	var refused []string
	for _, e := range entries {
		name := e.Name()
		if name == actionIndexDirectory || isStaging(e) || !isLowerHexOfLen(name, 64) {
			continue
		}
		named := "entry " + name
		if key := keys[name]; key != "" {
			named = "key " + key
		}
		pending := func(why string) {
			refused = append(refused, fmt.Sprintf("action %s is pending in the scope identifier's action journal: %s; settle it before the scope identifier is removed", named, why))
		}
		sub, err := openActionDirectory(root, name)
		if err != nil {
			pending("its entry does not read")
			continue
		}
		claim := &actionClaim{root: sub}
		saved, readErr := claim.read("action.json", actionJournalResponseLimit)
		switch {
		case readErr == nil:
			key, uncertain, action := savedActionOf(saved)
			if key != "" {
				named = "key " + key
			}
			if uncertain && !readBackHeld(action, all) {
				pending("it is uncertain, and no read-back in the store resolves it")
			}
		case errors.Is(readErr, os.ErrNotExist):
			// attempt counts a dispatch record that does not read as begun
			if _, begun, err := claim.attempt(); err == nil && begun {
				pending("it was dispatched without an answer, or its dispatch record does not read")
			}
		default:
			pending("its record does not read")
		}
		sub.Close()
	}
	return refused, nil
}

// savedActionOf reads a keyed action's record: its key, whether it was
// answered uncertain, and its receipt's place, as a read-back names it.
func savedActionOf(saved []byte) (key string, uncertain bool, at *vObject) {
	v, err := parseJSON(saved)
	if err != nil {
		return "", true, nil
	}
	out, _ := v.(*vObject)
	if out == nil {
		return "", true, nil
	}
	rv, _ := out.get("receipt")
	receipt, _ := rv.(*vObject)
	if receipt == nil {
		return "", true, nil
	}
	av, _ := receipt.get("action")
	action, _ := av.(*vObject)
	if action == nil {
		return "", true, nil
	}
	dv, _ := action.get("delivery")
	delivery, _ := dv.(*vObject)
	if delivery == nil {
		return "", true, nil
	}
	key, _ = memberString(delivery, "key")
	outcome, _ := memberString(delivery, "outcome")
	return key, outcome != "response", receipt
}

// readBackHeld is whether a read-back receipt in the store resolves the
// action receipt as /verify resolves one (reconciliationMatches): the
// action's receipt, named by session, index and signature, and a read-back
// that names it, each verifying ok. A read-back that names the action and
// does not resolve it -- of another key, contract, platform or scope, or one
// that does not verify -- settles nothing, and the key stays pending.
func readBackHeld(at *vObject, all []*storedReceipt) bool {
	if at == nil {
		return false
	}
	session, _ := memberString(at, "sessionId")
	signature, _ := memberString(at, "signature")
	index, _ := at.get("callIndex")
	if index == nil {
		return false
	}
	var action *receipt
	for _, s := range all {
		if s.status == "ok" && s.r != nil && s.r.sessionID == session && s.r.signature == signature && strconv.FormatInt(s.r.callIndex, 10) == string(canon(index)) {
			action = s.r
			break
		}
	}
	if action == nil {
		return false
	}
	named := citation{action.sessionID, action.callIndex, action.signature}
	for _, s := range all {
		if s.status == "ok" && s.r != nil && s.r.reconciliation != nil && s.r.reconciliation.action == named && reconciliationMatches(s.r, action) {
			return true
		}
	}
	return false
}

// removeScopedActionJournal removes the scope identifier's action journal,
// after its sessions (ADR-0054): a scope re-created under the same identifier
// starts with no keys. The journal is first renamed, in one step, to a name
// no scope identifier's journal has (scopedJournalRemoving), and deleted
// there: a delete that fails part way leaves no half-deleted journal under
// the live name, whose entries a second run would read as pending with the
// sessions that resolved them gone, and the second run finishes the delete.
func removeScopedActionJournal(storeRoot, scope string, out *removalOutcome) error {
	path := scopedActionJournalPath(storeRoot, scope)
	removing := filepath.Join(filepath.Dir(path), scopedJournalRemoving(scope))
	finished, err := deleteRemovingJournal(removing)
	if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil || !info.IsDir():
		return fmt.Errorf("the scope identifier's action journal is not a directory; it is left as it is, and a second run completes the removal")
	default:
		if err := os.Rename(path, removing); err != nil {
			return fmt.Errorf("the scope identifier's action journal could not be removed: %v; a second run completes the removal", err)
		}
		syncDir(filepath.Dir(path))
		if finished, err = deleteRemovingJournal(removing); err != nil {
			return err
		}
	}
	if finished {
		out.notes = append(out.notes, "removed the scope identifier's action journal")
	}
	return nil
}

// scopedJournalRemoving is the name a scope identifier's journal is deleted
// under. It is no scope journal's name, so journal compaction keeps it.
func scopedJournalRemoving(scope string) string {
	return ".removing-" + scopedActionJournalName(scope)
}

// deleteRemovingJournal deletes a journal renamed for removal, and is whether
// one was there.
func deleteRemovingJournal(removing string) (bool, error) {
	info, err := os.Lstat(removing)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !info.IsDir() {
		return false, fmt.Errorf("the scope identifier's action journal, renamed for removal, is not a directory; it is left as it is")
	}
	if err := os.RemoveAll(removing); err != nil {
		return false, fmt.Errorf("the scope identifier's action journal could not be removed: %v; a second run completes the removal", err)
	}
	syncDir(filepath.Dir(removing))
	return true, nil
}
