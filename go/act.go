package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
func (g *gatewayService) act(sessionID, platform, tool string, arguments, decisionV, citesV value, who *caller) (map[string]any, error) {
	if who == nil {
		return nil, actRefusal{"requester", errNoRequester.Error() + "; this engine has no identity configured"}
	}
	if g.receiptVersion != receiptVersion3 {
		return nil, actRefusal{"receipt-version", "an action receipt is a version 3 receipt; this engine mints version " + g.receiptVersion}
	}
	if err := requireSession(sessionID); err != nil {
		return nil, badRequest{err}
	}
	source := platform + "/write"
	spec, known := g.sources[source]
	if !known {
		return nil, actRefusal{"platform", fmt.Sprintf("platform %s allows no writes: a write source is derived only for a platform whose configuration sets write: true and whose binding states a write operation", platform)}
	}
	if !contains(spec.tools, tool) {
		return nil, actRefusal{"tool", fmt.Sprintf("tool %q is not one the platform's write binding names", tool)}
	}
	decision, err := parseDecision(decisionV)
	if err != nil {
		return nil, actRefusal{"decision", err.Error()}
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
		return nil, fmt.Errorf("decision-record directory: %w", err)
	}
	if !present || !found[recordHex] {
		return nil, actRefusal{"decision", fmt.Sprintf("no candidate under the decision-record directory has the digest %s", decision.recordDigest)}
	}

	// The judgment is there. What follows is the acquisition path with an
	// action's claims: admission, the executor as a source, one receipt in
	// the session chain.
	if err := g.admit(sessionID); err != nil {
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
