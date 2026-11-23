package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// /act's dry-run and approvals (docs/adr/0054-act-takes-a-scope-a-dry-run-is-signed-as-no-action-and-an-action-cites-approval-records.md,
// decisions 2 and 3). Both members are read from actScopeVersion; below it
// each is refused as a member /act does not read, and every answer is the
// one it was.
//
// A dry-run runs the write's own ladder through the decision record and its
// policy, then the publisher policy and the named-grant check of the write's
// last step, and in place of session admission makes the same checks with no
// effect. It signs a dry-run receipt (SPEC.md §1.2c) and answers it. It does
// nothing of the action key, records no label, makes no session directory,
// holds no session, delivers nothing to the receipt sink, makes no dispatch
// marker, uses no grant, starts no executor and runs no read-back. Under a
// delegation its one read of the issuing host is the admission read at
// "count": false. A dry-run is one /act request: a per-scope limit on /act
// requests counts it as one.

// dryRunRefusal is the dry-run step's refusal (ADR-0054, step 5), or "":
// after the members /act reads and before the credential is presented or a
// reservation authenticated. Only the JSON value true is read. A dry-run
// beside keyScope or reconcile, which are operations on the action journal
// (reconcile runs a read-back), or beside reservation, whose sender never
// dispatches and so has nothing to preview, is refused, as is a dry-run
// under an engine that mints version 2 receipts.
func (g *gatewayService) dryRunRefusal(body map[string]json.RawMessage) string {
	v, err := parseJSON(body["dryRun"])
	if err != nil || v != vBool(true) {
		return "dryRun must be the value true"
	}
	for _, name := range []string{"keyScope", "reconcile", "reservation"} {
		if _, present := body[name]; present {
			return fmt.Sprintf("dryRun is not taken beside %s: keyScope and reconcile are operations on the action journal, which a dry-run never touches, and a reservation's sender never dispatches, so it has nothing to preview", name)
		}
	}
	if g.receiptVersion != receiptVersion3 {
		return "a dry-run previews an action, which is a version 3 receipt; this engine mints version " + g.receiptVersion
	}
	return ""
}

// requestApprovals reads the request's approvals at the approvals step
// (ADR-0054, step 16): §1.2a's form, an array of 1 to 8 {kind, id, digest},
// no id twice, kept in the order given. It answers the member the receipt
// carries as action.approvals, or nil where the request names none.
func requestApprovals(raw json.RawMessage) (value, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	// 8 entries of 4 values and the array: a request past this is out of form
	v, err := parseJSONWithin(raw, 64)
	if err != nil {
		// past the bound the entries cannot be of their form, so the answer
		// is the form's sentence, as parseApprovals words it
		return nil, actRefusal{"approvals", fmt.Sprintf("approvals is an array of 1 to %d entries", maxApprovals)}
	}
	list, err := parseApprovals(v)
	if err != nil {
		return nil, actRefusal{"approvals", strings.TrimPrefix(strings.TrimPrefix(err.Error(), "action: "), "action.")}
	}
	member := make(vArray, 0, len(list))
	for _, a := range list {
		entry := newObject()
		entry.set("kind", vString(a.kind))
		entry.set("id", vString(a.id))
		entry.set("digest", vString(a.digest))
		member = append(member, entry)
	}
	return member, nil
}

// actionClaims is what an action receipt and a dry-run receipt both claim of
// the request (SPEC.md §1.2a, §1.2c): who asked, the decision record and how
// it was found, the receipts cited, the policy the write was held to, the
// tool, and the approvals the requester cites. An action receipt adds its
// delivery, its request commitment and what the target answered.
func actionClaims(requester *caller, d decision, exact bool, cites []citation, policy *decisionPolicy, approvals value, spec sourceSpec, tool string) *vObject {
	action := newObject()
	action.set("requester", identityObject(requester))
	decided := newObject()
	decided.set("recordDigest", vString(d.recordDigest))
	decided.set("packDigest", vString(d.packDigest))
	// How the record was found, under the signature: by its exact bytes for
	// a policy that requires a signed record, which the verifier then reads
	// the same way (SPEC.md §1.2a, §4 step 6); absent otherwise.
	if exact {
		decided.set("recordBytes", vString("exact"))
	}
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
	// The policy the write was held to, by digest, signed with the rest:
	// absent for a tool the operator holds to none.
	if policy != nil {
		action.set("policy", vString(policy.digest))
	}
	called := newObject()
	called.set("shape", vString("mcp"))
	if spec.endpoint == "" {
		called.set("endpoint", vNull{})
	} else {
		called.set("endpoint", vString(spec.endpoint))
	}
	called.set("name", vString(tool))
	// The transport, for a write to a remote server alone (SPEC.md §1.2a,
	// #268): "http", and the endpoint above is then the URL the engine held
	// to the endpoint form before it started, which a verifier holds it to
	// as well. A write over stdio names none, and its receipt is the one it
	// was before the member existed.
	if spec.transport != "" {
		called.set("transport", vString(spec.transport))
	}
	action.set("tool", called)
	// The approval records the requester cites, its claim (ADR-0054,
	// decision 3): absent where it names none, and the receipt is the one it
	// was before the member existed.
	if approvals != nil {
		action.set("approvals", approvals)
	}
	return action
}

// dryRunInput is what the ladder established for a dry-run by the dry-run
// point.
type dryRunInput struct {
	sessionID, scope, platform, source, tool string
	spec                                     sourceSpec
	who                                      *caller
	decision                                 decision
	exact                                    bool
	cites                                    []citation
	policy                                   *decisionPolicy
	approvals                                value
	request                                  *vObject
	canonicalRequest                         []byte
}

// dryRunAct is the rest of a dry-run (ADR-0054, decision 2): the publisher
// policy and the named-grant check of the write's last step, session
// admission's checks with no effect, under a delegation the grant's state
// and the non-counting admission read, and then the dry-run receipt, signed
// under the gateway's signer. The answer is exactly {dryRun, request, salts}.
func (g *gatewayService) dryRunAct(in dryRunInput) (map[string]any, error) {
	spec, delegated := in.spec, in.who.delegated
	if err := publisherRefusal(spec.publishers, in.platform, spec.binding); err != nil {
		return nil, actRefusal{"platform", err.Error()}
	}
	if delegated != nil && spec.grant == nil {
		return nil, grantRefused(refusalGrantUnknown, fmt.Sprintf("platform %s names no connection grant, and a delegated write is admitted only under one", requestText(in.platform)))
	}
	if err := g.previewAdmission(in.sessionID, in.scope); err != nil {
		return nil, err
	}
	var delegationMember *vObject
	if delegated != nil {
		// The grant's state, as the write reads it before its admission, and
		// never its use or the owner read. Then §11.5 steps 0 to 12 with the
		// admission read at "count": false: the host counts nothing, and the
		// delegation's budget is as it was.
		credential := delegated.credential
		if credential == nil || credential.chain.scopeRefusal(g.authority, in.source, in.tool, spec.effects[in.tool]) == nil {
			if refusal := g.askCustody(spec.grant, grantCheck); refusal != nil {
				return nil, refusal
			}
		}
		member, refusal := g.delegation.admitDelegated(delegated, delegatedCall{source: in.source, tool: in.tool, effect: spec.effects[in.tool], count: false})
		if refusal != nil {
			return nil, refusal
		}
		delegationMember = member
	}

	requestSalt, err := newSalt()
	if err != nil {
		return nil, err
	}
	action := actionClaims(in.who, in.decision, in.exact, in.cites, in.policy, in.approvals, spec, in.tool)
	action.set("request", vString(commitmentOver(requestSalt, "request:", in.canonicalRequest)))
	receipt := newObject()
	receipt.set("dryRunVersion", vString(dryRunVersion1))
	receipt.set("authority", vString(g.authority))
	receipt.set("servedAt", vString(nowStamp()))
	receipt.set("source", vString(in.source))
	// present exactly when the write source is fixed to a scope identifier;
	// a dry-run receipt is in no session, so it carries no scopeSalt
	if spec.scope != "" {
		receipt.set("scope", vString(spec.scope))
	}
	if delegationMember != nil {
		receipt.set("delegation", delegationMember)
	}
	receipt.set("action", action)
	// One key signs it and is named by it, read once, as a receipt's is; a
	// P-256 key names its algorithm inside what it signs. Under a key service
	// this is the dry-run's one signing call.
	key := g.store.signing.key()
	receipt.set("keyId", vString(key.keyID))
	setAlg(receipt, "alg", key.alg)
	signature, err := key.signVerified(recordSigningInput(dryRunContext, receipt))
	if err != nil {
		return nil, err
	}
	receipt.set("signature", vString(hex.EncodeToString(signature)))

	var receiptOut, requestOut any
	if err := json.Unmarshal(canon(receipt), &receiptOut); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(in.canonicalRequest, &requestOut); err != nil {
		return nil, err
	}
	return map[string]any{
		"dryRun":  receiptOut,
		"request": requestOut,
		"salts":   map[string]any{"request": hex.EncodeToString(requestSalt)},
	}, nil
}

// previewAdmission is admitAction's judgment with no effect (ADR-0054,
// decision 2): the signer's gate is open, and the session is not sealed, is
// not one another instance or an earlier start made, and is of the request's
// scope, and holds no receipt the sink has not acknowledged. The session's
// directory is not made, the session is not held, nothing is reserved
// against the gate, and nothing is sent to the sink.
func (g *gatewayService) previewAdmission(sessionID, scope string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.gate.closed {
		return g.closedRefusal()
	}
	if state, seen := g.sessions[sessionID]; seen && state.sealed {
		return actRefusal{"session", "session is sealed: " + sessionID}
	}
	if reason := g.sessionMintedHere(sessionID, scope); reason != "" {
		return actRefusal{"session", reason}
	}
	// What the session holds for the receipt sink, read and never sent: the
	// write delivers it again before its executor runs and is refused while
	// it is not (ADR-0049). A dry-run sends nothing, so a receipt held is
	// its refusal, in the sentence the write's would be.
	if g.forwarder != nil {
		if state, seen := g.sessions[sessionID]; seen {
			if err := state.forward.heldRefusal(sealIndex - 1); err != nil {
				return err
			}
		}
	}
	return nil
}
