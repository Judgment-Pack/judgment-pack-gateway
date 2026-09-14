package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The executor (docs/design/executor.md): a write through the engine, minted
// as the action receipt SPEC.md §1.2a defines and verify already resolves.
// Nothing here decides whether the write is right; what it holds is that the
// judgment the requester says the write relies on exists -- the cited
// receipts in this engine's own store under its own key, the decision record
// under its own decision-record directory -- before anything is sent to a
// target, and that the receipt names who asked.

// actRefusal is why an action was refused before any executor ran, and at
// which step of the ladder; it is answered as a bad request naming the step.
type actRefusal struct {
	step   string
	reason string
}

func (r actRefusal) Error() string { return r.step + ": " + r.reason }

// act performs one write for an authenticated requester, or refuses it.
func (g *gatewayService) act(sessionRaw, platformRaw, toolRaw, argumentsRaw, decisionRaw, citesRaw json.RawMessage, who *caller) (map[string]any, error) {
	if who == nil {
		return nil, actRefusal{"requester", errNoRequester.Error() + "; this engine has no identity configured"}
	}
	if g.receiptVersion != receiptVersion3 {
		return nil, actRefusal{"receipt-version", "an action receipt is a version 3 receipt; this engine mints version " + g.receiptVersion}
	}
	// Each member is read at its own step, so a request with several
	// faults -- a member of the wrong type among them -- is answered by
	// the earliest step it fell at.
	sessionID, err := parseString("session", sessionRaw)
	if err != nil {
		return nil, actRefusal{"session", err.Error()}
	}
	if err := requireSession(sessionID); err != nil {
		return nil, actRefusal{"session", err.Error()}
	}
	if reason := g.sessionOpen(sessionID); reason != "" {
		return nil, actRefusal{"session", reason}
	}
	platform, err := parseString("platform", platformRaw)
	if err != nil {
		return nil, actRefusal{"platform", err.Error()}
	}
	source := platform + "/write"
	spec, known := g.sources[source]
	if !known {
		return nil, actRefusal{"platform", fmt.Sprintf("platform %s allows no writes: a write source is derived only for a platform whose configuration sets write: true and whose binding states a write operation", platform)}
	}
	tool, err := parseString("tool", toolRaw)
	if err != nil {
		return nil, actRefusal{"tool", err.Error()}
	}
	if !contains(spec.tools, tool) {
		return nil, actRefusal{"tool", fmt.Sprintf("tool %q is not one the platform's write binding names", tool)}
	}
	// The executor is started for this tool alone (executor.md): a binding
	// naming several write tools offers each request one of them.
	spec = narrowTools(spec, tool)
	arguments := value(newObject())
	if len(argumentsRaw) > 0 {
		parsed, err := parseJSON(argumentsRaw)
		if err != nil {
			return nil, actRefusal{"arguments", "arguments: " + err.Error()}
		}
		arguments = parsed
	}
	if _, isObject := arguments.(*vObject); !isObject {
		return nil, actRefusal{"arguments", "arguments must be a JSON object: the executor sends the request as an object, and the commitment is over what is sent"}
	}
	decisionV, err := parseMember("decision", decisionRaw)
	if err != nil {
		return nil, actRefusal{"decision", err.Error()}
	}
	decision, err := parseDecision(decisionV)
	if err != nil {
		return nil, actRefusal{"decision", err.Error()}
	}
	citesV, err := parseMember("cites", citesRaw)
	if err != nil {
		return nil, actRefusal{"cites", err.Error()}
	}
	// The verifier tolerates members it does not know inside a signed
	// receipt (signed extensibility); a requester's citation is not signed
	// yet, and what the receipt will carry is exactly what was given, so a
	// citation is exactly its three members or it is refused.
	if arr, ok := citesV.(vArray); ok {
		for i, entry := range arr {
			if obj, ok := entry.(*vObject); ok {
				if err := exactlyMembers(obj, map[string]bool{"sessionId": true, "callIndex": true, "signature": true}, fmt.Sprintf("cites[%d]", i)); err != nil {
					return nil, actRefusal{"cites", err.Error()}
				}
			}
		}
	}
	cites, err := parseCitations(citesV, "action")
	if err != nil {
		return nil, actRefusal{"cites", err.Error()}
	}
	if len(cites) == 0 {
		return nil, actRefusal{"cites", "an action cites at least one receipt; a judgment that relied on nothing is not one this engine stands behind"}
	}
	for _, c := range cites {
		if reason := g.resolveCitation(c); reason != "" {
			return nil, actRefusal{"cites", fmt.Sprintf("citation %s/%d does not resolve in this engine's store: %s", c.sessionID, c.callIndex, reason)}
		}
	}
	if g.decisionRecords == "" {
		return nil, actRefusal{"decision", "this engine was started without a decision-record directory, so no record can be found for an action to rely on"}
	}
	recordHex := strings.TrimPrefix(decision.recordDigest, "sha256:")
	found, present, err := decisionCandidates(g.decisionRecords, map[string]bool{recordHex: true}, nil)
	if err != nil {
		// What went wrong is the operator's to read in the log; the
		// requester learns that the directory could not be read, not where
		// it is.
		return nil, actRefusal{"decision", "the decision-record directory could not be read"}
	}
	if !present || !found[recordHex] {
		return nil, actRefusal{"decision", fmt.Sprintf("no candidate under the decision-record directory has the digest %s", decision.recordDigest)}
	}

	// The judgment is there. What follows is the acquisition path with an
	// action's claims: admission, the executor as a source, one receipt in
	// the session chain.
	if g.beforeAdmit != nil {
		g.beforeAdmit()
	}
	if err := g.admitAction(sessionID); err != nil {
		return nil, err
	}
	defer g.release(sessionID)

	request := newObject()
	request.set("tool", vString(tool))
	request.set("arguments", arguments)
	canonicalRequest := canon(request)
	result, _, _, err := g.runSource(source, spec, canonicalRequest)
	if err != nil {
		return nil, err
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	state := g.sessions[sessionID]

	adapterEnvelope, err := parseEnvelope(result)
	if err != nil {
		return nil, fmt.Errorf("source %s: the executor's result is not an envelope: %v", source, err)
	}
	result = adapterEnvelope.result
	var resultOut any
	if err := json.Unmarshal(canon(result), &resultOut); err != nil {
		return nil, fmt.Errorf("source %s: the result cannot be returned: %v", source, err)
	}
	resultDigest, err := g.store.retain(canon(result))
	if err != nil {
		return nil, err
	}

	core := newObject()
	core.set("receiptVersion", vString(receiptVersion3))
	core.set("sessionId", vString(sessionID))
	core.set("callIndex", vInt(state.index))
	if state.prev == "" {
		core.set("prevSignature", vNull{})
	} else {
		core.set("prevSignature", vString(state.prev))
	}
	core.set("source", vString(source))
	core.set("resultDigest", vString(resultDigest))
	core.set("servedAt", vString(nowStamp()))
	core.set("authority", vString(g.authority))
	argsSalt, err := newSalt()
	if err != nil {
		return nil, err
	}
	requestSalt, err := newSalt()
	if err != nil {
		return nil, err
	}
	core.set("argumentsCommitment", vString(commitmentOver(argsSalt, "args:", canon(arguments))))
	core.set("kind", vString("action"))
	core.set("caller", identityObject(who))

	action := newObject()
	action.set("requester", identityObject(who))
	decided := newObject()
	decided.set("recordDigest", vString(decision.recordDigest))
	decided.set("packDigest", vString(decision.packDigest))
	action.set("decision", decided)
	cited := make(vArray, 0, len(cites))
	for _, c := range cites {
		entry := newObject()
		entry.set("sessionId", vString(c.sessionID))
		entry.set("callIndex", vInt(c.callIndex))
		entry.set("signature", vString(c.signature))
		cited = append(cited, entry)
	}
	action.set("cites", cited)
	called := newObject()
	called.set("shape", vString("mcp"))
	if spec.endpoint == "" {
		called.set("endpoint", vNull{})
	} else {
		called.set("endpoint", vString(spec.endpoint))
	}
	called.set("name", vString(tool))
	action.set("tool", called)
	action.set("request", vString(commitmentOver(requestSalt, "request:", canonicalRequest)))
	for _, name := range []string{"adapter", "observedAt"} {
		v, _ := adapterEnvelope.acquisition.get(name)
		action.set(name, v)
	}
	core.set("action", action)

	stored, signature, err := g.store.stamp(core)
	if err != nil {
		return nil, err
	}
	state.index++
	state.prev = signature

	var receiptOut any
	if err := json.Unmarshal(canon(stored), &receiptOut); err != nil {
		return nil, err
	}
	return map[string]any{
		"result":  resultOut,
		"receipt": receiptOut,
		"salts":   map[string]any{"args": hex.EncodeToString(argsSalt), "request": hex.EncodeToString(requestSalt)},
	}, nil
}

// sessionOpen is why an action may not be minted into a session, or "":
// the session is sealed in the registry on disk -- the one record of a seal,
// which this process wrote if it sealed the session itself, and which an
// earlier process wrote otherwise -- or it has receipts on disk that this
// process did not mint: it predates this engine's start, and its chain
// cannot be continued from an empty memory, so a restart never lets an
// action into a session the store already holds. Admission's own recheck
// under the lock holds the in-memory state against a seal that lands
// between here and the spawn. /acquire admits by that memory alone, which
// is what it has always done; an action is held to the disk too, since a
// write that ran and could not be receipted is the one outcome this design
// exists to refuse.
func (g *gatewayService) sessionOpen(sessionID string) string {
	if seals, _, err := loadSeals(g.regPath, g.publicKey); err != nil {
		return "the registry could not be read"
	} else if _, sealed := seals[sessionID]; sealed {
		return "session is sealed in the registry: " + sessionID
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.sessionMintedHere(sessionID)
}

// sessionMintedHere is why a session is not one this process may continue,
// or "": under the lock, a session this process knows is one it owns only
// if it found the store empty there when it first admitted into it -- a
// receipt count says nothing, since a read into an old session can recreate
// a receipt that session lost and count from there; a session it does not
// know must have nothing in the store either. An entry there of any kind (a
// directory, a link, a file) is a session this engine did not mint; a lookup
// that fails for any reason but absence is refused as such, never taken for
// absence, since a dangling link reports absent to a stat that follows it.
// Called by the session step and again by admission, so a reservation made
// between the two changes nothing.
func (g *gatewayService) sessionMintedHere(sessionID string) string {
	if state, seen := g.sessions[sessionID]; seen && state.created {
		return ""
	}
	// Known but not made by this process -- an old session a read continued,
	// or one reserved with nothing minted yet -- or not known at all: the
	// store says whether something is there, and anything is a refusal.
	_, err := os.Lstat(filepath.Join(g.storeRoot, "receipts", sessionID))
	switch {
	case err == nil:
		return "session " + sessionID + " exists in the store as something this engine did not mint; it predates this start, and an action opens a session of its own"
	case errors.Is(err, fs.ErrNotExist):
		return ""
	default:
		return "session " + sessionID + " could not be looked up in the store"
	}
}

// admitAction reserves an action against a session as admit reserves a
// read, and under the same lock judges the seal and takes the session's
// directory for this process, by Mkdir, before any executor runs: two makers
// cannot both succeed, so a session another process put there since the
// session step -- or one this process only reserved, or one it continued
// without making -- is refused here, not found at the stamp after the
// write. The session step's earlier judgment (sessionMintedHere) is the
// same judgment made before the evidence is read, so the answer names the
// session rather than a later step; this is the one that holds.
func (g *gatewayService) admitAction(sessionID string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	state, seen := g.sessions[sessionID]
	if !seen {
		state = &sessionState{}
		g.sessions[sessionID] = state
	}
	if state.sealed {
		return actRefusal{"session", "session is sealed: " + sessionID}
	}
	if !state.created {
		err := os.Mkdir(filepath.Join(g.storeRoot, "receipts", sessionID), 0o755)
		switch {
		case err == nil:
			state.created = true
		case errors.Is(err, fs.ErrExist):
			if state.index == 0 && state.inFlight == 0 {
				delete(g.sessions, sessionID)
			}
			return actRefusal{"session", "session " + sessionID + " exists in the store as something this engine did not mint; it predates this start, and an action opens a session of its own"}
		default:
			if state.index == 0 && state.inFlight == 0 {
				delete(g.sessions, sessionID)
			}
			return actRefusal{"session", "session " + sessionID + " could not be made in the store"}
		}
	}
	state.inFlight++
	return nil
}

// narrowTools is the write source started for one tool: the adapter's
// allowlist is that tool, so a server offering more cannot be asked for
// more, whatever the binding names.
func narrowTools(spec sourceSpec, tool string) sourceSpec {
	argv := make([]string, 0, len(spec.argv))
	own := true
	for _, arg := range spec.argv {
		if arg == "--" {
			// What follows is the server's own command line, the binding's
			// to state and not this engine's to rewrite.
			own = false
		}
		if own && strings.HasPrefix(arg, "--tools=") {
			arg = "--tools=" + tool
		}
		argv = append(argv, arg)
	}
	narrowed := spec
	narrowed.argv = argv
	narrowed.tools = []string{tool}
	return narrowed
}

// parseMember reads one required member of the request body, at its own
// step of the ladder: absent is a refusal there, as unparseable is.
func parseMember(name string, raw json.RawMessage) (value, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%s is required", name)
	}
	parsed, err := parseJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", name, err)
	}
	return parsed, nil
}

// parseString is a member of the request that must be a JSON string, read
// at the step that uses it.
func parseString(name string, raw json.RawMessage) (string, error) {
	parsed, err := parseMember(name, raw)
	if err != nil {
		return "", err
	}
	s, ok := parsed.(vString)
	if !ok {
		return "", fmt.Errorf("%s must be a JSON string", name)
	}
	return string(s), nil
}

// identityObject is a token identity as a receipt names it.
func identityObject(who *caller) *vObject {
	identity := newObject()
	identity.set("issuer", vString(who.issuer))
	identity.set("subject", vString(who.subject))
	identity.set("tokenDigest", vString(who.tokenDigest))
	return identity
}

type decision struct {
	recordDigest string
	packDigest   string
}

// parseDecision holds the requester's decision claim to its shape: an
// object of exactly recordDigest and packDigest, each a digest.
func parseDecision(v value) (decision, error) {
	obj, err := requireObject(v, "decision")
	if err != nil {
		return decision{}, err
	}
	if err := exactlyMembers(obj, map[string]bool{"recordDigest": true, "packDigest": true}, "decision"); err != nil {
		return decision{}, err
	}
	var d decision
	for name, into := range map[string]*string{"recordDigest": &d.recordDigest, "packDigest": &d.packDigest} {
		s, ok := memberString(obj, name)
		if !ok || !isDigest(s) {
			return decision{}, fmt.Errorf("decision.%s must be \"sha256:\" followed by 64 lowercase hex characters", name)
		}
		*into = s
	}
	return d, nil
}

// resolveCitation is why one citation does not resolve in this engine's
// store, or "" when it does: by §4 step 5's rule -- the session directory
// named exactly, the file stem named exactly, the signature the same string
// -- and, beyond what verify reads of a cited receipt, the receipt itself
// passing the ladder under this engine's key, since an action that relied on
// a receipt this engine would not stand behind relied on nothing.
func (g *gatewayService) resolveCitation(c citation) string {
	sessions, err := os.ReadDir(filepath.Join(g.storeRoot, "receipts"))
	if err != nil {
		return "the store's receipts cannot be listed"
	}
	if !dirEntryNamed(sessions, c.sessionID, true) {
		return "no such session"
	}
	fileName := strconv.FormatInt(c.callIndex, 10) + ".json"
	files, err := os.ReadDir(filepath.Join(g.storeRoot, "receipts", c.sessionID))
	if err != nil {
		return "the session's receipts cannot be listed"
	}
	if !dirEntryNamed(files, fileName, false) {
		return "no such receipt"
	}
	data, err := os.ReadFile(filepath.Join(g.storeRoot, "receipts", c.sessionID, fileName))
	if err != nil {
		return "the receipt cannot be read"
	}
	r, status := checkReceipt(data, g.storeRoot, c.sessionID, fileName, g.authority, g.publicKey, g.keyID)
	if status != "ok" {
		return "the receipt does not verify under this engine's key (" + status + ")"
	}
	if r.signature != c.signature {
		return "the signature is not the receipt's"
	}
	return ""
}

// dirEntryNamed reports whether an enumerated entry has exactly this name,
// compared as strings and never by asking the filesystem, so a filesystem
// that folds case or normalises names resolves nothing the listing did not.
func dirEntryNamed(entries []os.DirEntry, name string, dir bool) bool {
	for _, e := range entries {
		if e.Name() == name && e.IsDir() == dir {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

var errNoRequester = errors.New("an action needs an authenticated requester")
