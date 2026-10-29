package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
)

func actionHash(domain string, v value) string {
	sum := sha256.Sum256(append([]byte("judgment-pack-gateway/"+domain+"/1:"), canon(v)...))
	return hex.EncodeToString(sum[:])
}
func (g *gatewayService) actionNamespace(who *caller, key string) string {
	v := newObject()
	v.set("authority", vString(g.authority))
	v.set("issuer", vString(who.issuer))
	v.set("subject", vString(who.subject))
	v.set("key", vString(key))
	return actionHash("action-key", v)
}

// actionInstallFlags are the adapter flags whose values say where something
// is installed or kept on this host, not what was approved: the credentials
// file, the container runtime client, the sandbox workspace and policy paths,
// and the configuration's copies of the descriptor snapshot and owner
// declaration, whose pins (--descriptor-pin, --owner-declaration-pin) stay in
// the identity. The adapter's own path, argv[0], is left out with them.
var actionInstallFlags = []string{"--credentials=", "--runtime=", "--sandbox-workspace=", "--sandbox-policy=", "--descriptor-snapshot=", "--owner-declaration-file="}

// actionApprovedArgv is a source's command line without its install paths:
// the binding's server, tools, endpoint, image and URL, and the descriptor and
// executable approval pins, as the binding and the approvals state them. The
// server's own command line after "--" is the binding's and is kept whole.
func actionApprovedArgv(argv []string) vArray {
	out := vArray{}
	own := true
	for i, word := range argv {
		if i == 0 {
			continue
		}
		if word == "--" {
			own = false
		}
		if own && slices.ContainsFunc(actionInstallFlags, func(flag string) bool { return strings.HasPrefix(word, flag) }) {
			continue
		}
		out = append(out, vString(word))
	}
	return out
}

// actionSandboxIdentity is what a source's sandbox means: absent (no wrapper),
// or the selector and the digest of the policy bytes the launch is bound to --
// the cached probe's, which sandboxSourceCommand hands the helper as
// --expect-policy -- never the helper's, policy's or workspace's paths.
func actionSandboxIdentity(source sourceSpec) (value, error) {
	if source.sandbox == nil {
		return vNull{}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), sandboxLaunchProbeTimeout)
	defer cancel()
	report, err := sandboxPostureProbe(ctx, source)
	if err != nil {
		return nil, fmt.Errorf("sandbox-not-enforced: the source's sandbox policy could not be measured, so the action cannot be identified: %v", err)
	}
	identity := newObject()
	identity.set("source", vString(source.sandbox.source))
	identity.set("policy", vString(report.PolicyDigest))
	return identity, nil
}

// actionFingerprint is the approved identity of one keyed action: the
// platform, tool, effective arguments, decision and cites, the binding pin,
// the recovery contract and the decision policy, and for the write source
// and the read-back source what each is approved to be -- binding, endpoint,
// transport, approved command line with its descriptor and executable approval
// pins, signed descriptor provenance, and sandbox policy digest. Where the
// programs are installed, the platform's environment and the OS user are left
// out: moving an install or adding an environment variable does not change
// what a retry means, and must not strand the key (docs/design/action-reconciliation.md).
func actionFingerprint(platform, tool string, args, decision, cites value, spec sourceSpec, recovery *actionRecovery, live sourceSpec) (string, error) {
	v := newObject()
	v.set("platform", vString(platform))
	v.set("tool", vString(tool))
	v.set("arguments", args)
	v.set("decision", decision)
	v.set("cites", cites)
	v.set("binding", vString(spec.binding))
	v.set("recovery", vString(recovery.digest()))
	sourceIdentity := func(source sourceSpec) (*vObject, error) {
		identity := newObject()
		identity.set("binding", vString(source.binding))
		identity.set("endpoint", vString(source.endpoint))
		identity.set("transport", vString(source.transport))
		sandbox, err := actionSandboxIdentity(source)
		if err != nil {
			return nil, err
		}
		identity.set("sandbox", sandbox)
		identity.set("argv", actionApprovedArgv(source.argv))
		if source.descriptorProvenance != nil {
			identity.set("descriptorProvenance", source.descriptorProvenance.value())
		}
		return identity, nil
	}
	write, err := sourceIdentity(spec)
	if err != nil {
		return "", err
	}
	v.set("writeSource", write)
	if recovery != nil && recovery.readBack != nil {
		read, err := sourceIdentity(narrowTools(live, recovery.readBack.tool))
		if err != nil {
			return "", err
		}
		v.set("readSource", read)
	}

	if policy := spec.policies[tool]; policy != nil {
		v.set("policy", vString(policy.digest))
	}
	return actionHash("action-intent", v), nil
}

type actionUncertain struct {
	reason string
	action map[string]any
}

func (e *actionUncertain) Error() string { return e.reason }

type actionReconciliationRequest struct {
	action        *vObject
	key, contract string
	read          *actionReadBack
}

func (r *actionReconciliationRequest) member(result value) *vObject {
	v := newObject()
	v.set("action", r.action)
	v.set("key", vString(r.key))
	v.set("contract", vString(r.contract))
	v.set("outcome", vString(r.read.outcome(r.key, result)))
	return v
}
func (g *gatewayService) reconcileAction(session, platform string, args value, who *caller, key string, recovery *actionRecovery, prior map[string]any) (map[string]any, error) {
	if recovery == nil || recovery.readBack == nil {
		return nil, &actionUncertain{"action-reconciliation-unavailable", prior}
	}
	request, err := recovery.readBack.request(key, args)
	if err != nil {
		return nil, &actionUncertain{err.Error(), prior}
	}
	raw, err := json.Marshal(prior["receipt"])
	if err != nil {
		return nil, err
	}
	v, err := parseJSON(raw)
	if err != nil {
		return nil, err
	}
	receipt, err := requireObject(v, "action receipt")
	if err != nil {
		return nil, err
	}
	cited := newObject()
	for _, name := range []string{"sessionId", "callIndex", "signature"} {
		value, _ := receipt.get(name)
		cited.set(name, value)
	}
	r := &actionReconciliationRequest{action: cited, key: key, contract: recovery.digest(), read: recovery.readBack}
	read, err := g.acquireWithReconciliation(session, platform+"/live", "", request, who, r)
	if err != nil {
		return nil, &actionUncertain{"action-reconciliation-unavailable: read-back did not produce evidence", prior}
	}
	return map[string]any{"action": prior, "reconciliation": read}, nil
}

// This envelope explicitly identifies the gateway's uncertainty recorder. It
// cannot invent an executor observation or imply that a target was reached.
func (g *gatewayService) uncertainActionEnvelope() (value, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	digest, err := executableDigest(exe)
	if err != nil {
		return nil, err
	}
	adapter := newObject()
	adapter.set("name", vString("judgment-pack-gateway/uncertainty"))
	adapter.set("version", vString("1"))
	adapter.set("digest", vString(digest))
	acquisition := newObject()
	for _, name := range []string{"endpoint", "statement", "snapshot", "peerIdentity", "schema", "upstreamToken"} {
		acquisition.set(name, vNull{})
	}
	acquisition.set("adapter", adapter)
	acquisition.set("observedAt", vString(nowStamp()))
	result := newObject()
	result.set("outcome", vString("uncertain"))
	result.set("observer", vString("gateway"))
	envelope := newObject()
	envelope.set("result", result)
	envelope.set("acquisition", acquisition)
	return envelope, nil
}

type retainedAction struct {
	response map[string]any
	outcome  string
}

func (g *gatewayService) readActionResponse(raw []byte, who *caller, key, contract string, arguments value, request []byte) (*retainedAction, error) {
	fail := func() (*retainedAction, error) {
		return nil, errors.New("action-journal-invalid: retained action evidence does not verify")
	}
	v, err := parseJSON(raw)
	if err != nil {
		return fail()
	}
	obj, err := requireObject(v, "retained action")
	if err != nil {
		return fail()
	}
	if err = exactlyMembers(obj, map[string]bool{"result": true, "receipt": true, "salts": true}, "retained response"); err != nil {
		return fail()
	}
	rv, _ := obj.get("receipt")
	ro, err := requireObject(rv, "retained receipt")
	if err != nil {
		return fail()
	}
	r, err := receiptFrom(ro)
	if err != nil || r.kind != "action" || r.authority != g.authority {
		return fail()
	}
	av, _ := ro.get("action")
	action, err := requireObject(av, "action")
	if err != nil {
		return fail()
	}
	dv, _ := action.get("delivery")
	delivery, err := requireObject(dv, "delivery")
	if err != nil {
		return fail()
	}
	k, _ := memberString(delivery, "key")
	c, _ := memberString(delivery, "contract")
	outcome, _ := memberString(delivery, "outcome")
	if k != key || c != contract || (outcome != "response" && outcome != "uncertain") {
		return fail()
	}
	iv, _ := action.get("requester")
	identity, err := requireObject(iv, "requester")
	if err != nil {
		return fail()
	}
	issuer, _ := memberString(identity, "issuer")
	subject, _ := memberString(identity, "subject")
	if issuer != who.issuer || subject != who.subject {
		return fail()
	}
	keys, err := g.reachedKeys()
	if err != nil || g.resolveCitation(citation{r.sessionID, r.callIndex, r.signature}, keys) != "" {
		return fail()
	}
	if _, status := checkReceiptUnder(canon(ro), g.storeRoot, r.sessionID, strconv.FormatInt(r.callIndex, 10)+".json", g.authority, keys); status != "ok" {
		return fail()
	}
	result, present := obj.get("result")
	if !present {
		return fail()
	}
	sum := sha256.Sum256(canon(result))
	if "sha256:"+hex.EncodeToString(sum[:]) != r.resultDigest {
		return fail()
	}
	saltsValue, _ := obj.get("salts")
	salts, err := requireObject(saltsValue, "salts")
	if err != nil {
		return fail()
	}
	if err = exactlyMembers(salts, map[string]bool{"args": true, "request": true}, "salts"); err != nil {
		return fail()
	}
	for _, entry := range []struct {
		name, label, member string
		object              *vObject
		bytes               []byte
	}{
		{"args", "args:", "argumentsCommitment", ro, canon(arguments)},
		{"request", "request:", "request", action, request},
	} {
		text, _ := memberString(salts, entry.name)
		if !isLowerHexOfLen(text, 64) {
			return fail()
		}
		salt, _ := hex.DecodeString(text)
		committed, _ := memberString(entry.object, entry.member)
		if commitmentOver(salt, entry.label, entry.bytes) != committed {
			return fail()
		}
	}
	var response map[string]any
	if err = json.Unmarshal(raw, &response); err != nil {
		return fail()
	}
	return &retainedAction{response: response, outcome: outcome}, nil
}
