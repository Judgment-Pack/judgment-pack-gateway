package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// A write held to its decision (docs/adr/0011-hold-a-write-to-its-decision.md).
// The operator may hold a write tool to a decision policy in the engine's
// configuration; for such a tool the executor reads the decision record the
// request names -- the runtime's evaluation record, one line of its audit
// trail -- holds the request's claims to it, and holds it to the policy,
// before anything is sent. A policy may also require the record to be signed
// by a runtime key it trusts (docs/adr/0012-hold-a-write-to-a-signed-record.md,
// record_signature.go). For a tool with no policy nothing here runs and
// nothing in the record is read. The verifier reads the same record by the
// same rule (SPEC.md §4 step 8), after the fact, for what an action receipt
// claims of it.

// decisionPolicy is what the operator holds one write tool to: the outcomes
// a record may have decided, the packs it may have been decided under,
// whether it must have been judged under reviewed law, which of the write's
// arguments must equal which of the record's facts, and which runtime keys,
// if any, one of which must have signed the record. digest names the policy
// as configured, and is what an action receipt carries.
type decisionPolicy struct {
	outcomes []string
	packs    []string // empty when the member is absent: any pack
	reviewed bool
	bind     []factBinding
	signers  []recordSigner // empty when requireSignedRecord is absent: no signature read
	digest   string
}

// factBinding is one entry of a policy's bind: a JSON pointer into the
// request's arguments and one into the record's facts, whose two values
// must be equal.
type factBinding struct {
	argument string
	fact     string
}

var decisionPolicyMembers = map[string]bool{"outcomes": true, "packs": false, "reviewed": false, "bind": false, "requireSignedRecord": false}

// parseDecisionPolicies reads a platform's decisionPolicy member: an object
// keyed by write tool name, each a policy. Whether each tool is one the
// platform's write binding names is judged where the binding is read
// (resolveEngineConfig). version is the file's engineVersion, which says
// which members a policy may have.
func parseDecisionPolicies(v value, platform, version string) (map[string]*decisionPolicy, error) {
	obj, ok := v.(*vObject)
	if !ok {
		return nil, fmt.Errorf("engine configuration: platform %s: decisionPolicy must be an object keyed by write tool name", platform)
	}
	policies := map[string]*decisionPolicy{}
	for _, tool := range obj.names {
		if tool == "" {
			return nil, fmt.Errorf("engine configuration: platform %s: decisionPolicy names a tool by the empty string", platform)
		}
		raw, _ := obj.get(tool)
		policy, err := parseDecisionPolicy(raw, fmt.Sprintf("platform %s: decisionPolicy.%s", platform, requestText(tool)), version)
		if err != nil {
			return nil, fmt.Errorf("engine configuration: %v", err)
		}
		policies[tool] = policy
	}
	return policies, nil
}

// parseDecisionPolicy holds one policy to its closed shape: outcomes a
// non-empty array of outcome ids, packs a non-empty array of digests,
// reviewed a boolean, bind an array of {argument, fact} pointers, and, from
// engineVersion 5, requireSignedRecord a non-empty array of Ed25519 public
// keys -- a list naming one entry twice is refused, as a list nobody meant.
// Its digest is over the canonical form (SPEC.md §1.1) of the object as
// configured, which for this object is its RFC 8785 form too: its member
// names are the fixed ASCII names above, and it holds no number.
func parseDecisionPolicy(v value, where, version string) (*decisionPolicy, error) {
	obj, ok := v.(*vObject)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", where)
	}
	if err := exactlyMembers(obj, decisionPolicyMembers, where); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canon(obj))
	policy := &decisionPolicy{digest: "sha256:" + hex.EncodeToString(sum[:])}
	var err error
	if policy.outcomes, err = policyList(obj, "outcomes", where, func(s string) bool { return s != "" }, "an outcome id"); err != nil {
		return nil, err
	}
	if _, present := obj.get("packs"); present {
		if policy.packs, err = policyList(obj, "packs", where, isDigest, "a digest, sha256:<64 lowercase hex>"); err != nil {
			return nil, err
		}
	}
	if reviewed, present := obj.get("reviewed"); present {
		b, ok := reviewed.(vBool)
		if !ok {
			return nil, fmt.Errorf("%s: reviewed, when present, is a boolean", where)
		}
		policy.reviewed = bool(b)
	}
	if bindV, present := obj.get("bind"); present {
		entries, ok := bindV.(vArray)
		if !ok {
			return nil, fmt.Errorf("%s: bind, when present, is an array of {argument, fact}", where)
		}
		for i, entry := range entries {
			what := fmt.Sprintf("%s: bind[%d]", where, i)
			pair, ok := entry.(*vObject)
			if !ok {
				return nil, fmt.Errorf("%s must be an object of argument and fact", what)
			}
			if err := exactlyMembers(pair, map[string]bool{"argument": true, "fact": true}, what); err != nil {
				return nil, err
			}
			var b factBinding
			for name, into := range map[string]*string{"argument": &b.argument, "fact": &b.fact} {
				s, ok := memberString(pair, name)
				if !ok || !validPointer(s) {
					return nil, fmt.Errorf("%s: %s must be a JSON pointer (RFC 6901): empty, or each token after a /, a ~ in one followed by 0 or 1", what, name)
				}
				*into = s
			}
			for _, prior := range policy.bind {
				if prior == b {
					return nil, fmt.Errorf("%s: bind names one pair twice", where)
				}
			}
			policy.bind = append(policy.bind, b)
		}
	}
	if _, present := obj.get("requireSignedRecord"); present {
		if !versionAtLeast(version, "5") {
			return nil, fmt.Errorf("%s: requireSignedRecord is a version-5 member; engineVersion %s has no requireSignedRecord", where, version)
		}
		keys, err := policyList(obj, "requireSignedRecord", where, func(s string) bool { return isLowerHexOfLen(s, 64) }, "an Ed25519 public key, 64 lowercase hex")
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			raw, _ := hex.DecodeString(k)
			// A key no signature verifies under admits nothing, and one of
			// small order admits a signature anyone can make: neither is a
			// key a writer must hold.
			if reason := unusableSigningKey(raw); reason != "" {
				return nil, fmt.Errorf("%s: requireSignedRecord names a key that %s", where, reason)
			}
			policy.signers = append(policy.signers, recordSigner{keyID: keyIDFor(raw), key: ed25519.PublicKey(raw)})
		}
	}
	return policy, nil
}

// policyList is a required-when-present list of a policy: a non-empty array
// of strings each of the stated form, none given twice.
func policyList(obj *vObject, name, where string, form func(string) bool, what string) ([]string, error) {
	v, _ := obj.get(name)
	arr, ok := v.(vArray)
	if !ok || len(arr) == 0 {
		return nil, fmt.Errorf("%s: %s must be a non-empty array", where, name)
	}
	list := make([]string, 0, len(arr))
	for _, item := range arr {
		s, ok := item.(vString)
		if !ok || !form(string(s)) {
			return nil, fmt.Errorf("%s: each of %s must be %s", where, name, what)
		}
		if contains(list, string(s)) {
			return nil, fmt.Errorf("%s: %s names one entry twice", where, name)
		}
		list = append(list, string(s))
	}
	return list, nil
}

// validPointer is RFC 6901's syntax: the empty pointer, which names the
// whole document, or reference tokens each after a "/", a "~" in one
// followed by "0" or "1".
func validPointer(p string) bool {
	if p == "" {
		return true
	}
	if p[0] != '/' {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] == '~' && (i+1 >= len(p) || (p[i+1] != '0' && p[i+1] != '1')) {
			return false
		}
	}
	return true
}

// resolvePointer is the value a valid pointer names in v (RFC 6901 §4),
// or false when it names none: a member the object does not have, an
// array index that is not one -- a leading zero, "-", past the end -- or a
// token applied to a string, a number, a boolean or null.
func resolvePointer(v value, p string) (value, bool) {
	if p == "" {
		return v, true
	}
	for _, token := range strings.Split(p[1:], "/") {
		token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
		switch c := v.(type) {
		case *vObject:
			next, ok := c.get(token)
			if !ok {
				return nil, false
			}
			v = next
		case vArray:
			if token == "" || (len(token) > 1 && token[0] == '0') || strings.TrimLeft(token, "0123456789") != "" {
				return nil, false
			}
			i, err := strconv.Atoi(token)
			if err != nil || i >= len(c) {
				return nil, false
			}
			v = c[i]
		default:
			return nil, false
		}
	}
	return v, true
}

// runtimeRecord is a decision record this engine understands (SPEC.md §4
// step 8): the runtime's record of one pack evaluated on one facts document
// (runtime ADR-0018) -- one JSON object whose recordVersion is "1", whose
// kind is "evaluation", and whose pack carries the digest of the pack's
// bytes. Nothing else is one.
type runtimeRecord struct {
	obj        *vObject
	packDigest string
}

// readRuntimeRecord reads a decision record's bytes as a runtime evaluation
// record, or says why they are not one. The bytes are read by the canonical
// parser with a number of any form admitted (parseRecordJSON): a record's
// facts and its disposition's value may hold a fraction, and the runtime
// wrote them so; a name given twice at any depth, a string that is not
// UTF-8 or a lone surrogate is a record two readers could read two ways,
// and is none. The reason names what is missing and never a value of the
// record's.
func readRuntimeRecord(data []byte) (*runtimeRecord, string) {
	v, err := parseRecordJSON(data)
	if err != nil {
		return nil, "the record is not one JSON object this engine can read"
	}
	obj, ok := v.(*vObject)
	if !ok {
		return nil, "the record is not a JSON object"
	}
	if version, _ := memberString(obj, "recordVersion"); version != "1" {
		return nil, `the record's recordVersion is not "1", the one version of the runtime's record this engine reads`
	}
	switch kind, _ := memberString(obj, "kind"); kind {
	case "evaluation":
	case "graph-composite":
		return nil, "the record is a graph composite, which carries no pack and no inputs to hold a write to; a composite is not yet one a write can be held to"
	default:
		return nil, `the record's kind is not "evaluation"`
	}
	packV, _ := obj.get("pack")
	pack, _ := packV.(*vObject)
	digest := ""
	if pack != nil {
		digest, _ = memberString(pack, "digest")
	}
	if !isDigest(digest) {
		return nil, "the record carries no pack digest"
	}
	return &runtimeRecord{obj: obj, packDigest: digest}, ""
}

// citations are the record's cites, read as an action receipt's are: none
// when the member is absent, an error when it is not of the shape. The
// record was read with numbers of any form, so the member is held to the
// canonical domain here, as an action's citations are by being signed: a
// member beside the three, at any depth, may hold a number outside it.
func (r *runtimeRecord) citations() ([]citation, error) {
	citesV, present := r.obj.get("cites")
	if !present {
		return nil, nil
	}
	if !canonicalValue(citesV) {
		return nil, fmt.Errorf("record: cites holds a number outside the canonical domain")
	}
	return parseCitations(citesV, "record")
}

// sameCitations reports whether two lists of citations name the same set
// of receipts: the same (sessionId, callIndex, signature) triples, order and
// repetition aside.
func sameCitations(a, b []citation) bool {
	set := func(list []citation) map[citation]bool {
		s := map[citation]bool{}
		for _, c := range list {
			s[c] = true
		}
		return s
	}
	sa, sb := set(a), set(b)
	if len(sa) != len(sb) {
		return false
	}
	for c := range sa {
		if !sb[c] {
			return false
		}
	}
	return true
}

// holdToPolicy is the executor's steps 8 to 11 for a tool held to a policy
// (docs/design/executor.md): the record whose digest step 7 matched, read as
// the runtime's evaluation record; when the policy requires it, the record
// signed by a key the policy trusts, in the sidecar beside it (signed holds
// what the walk found there); the request's claims held to the record it
// names; the record held to the operator's policy -- outcome, handoff,
// packs, reviewed, bind, in that order. The first that fails is the refusal,
// and nothing is sent. The bytes read are the bytes step 7 hashed, so the
// record judged is the record named.
func holdToPolicy(data []byte, claimed decision, cites []citation, arguments value, policy *decisionPolicy, signed sidecarEvidence) error {
	record, why := readRuntimeRecord(data)
	if record == nil {
		return actRefusal{"record", why + "; a tool held to a decision policy acts only on a runtime evaluation record"}
	}
	// Whose record it is comes before anything in it is compared: a record
	// no trusted key signed is not judged further, so a hand-written one
	// learns nothing of which of the policy's checks it would fail.
	if len(policy.signers) > 0 {
		if err := holdToSignature(record, claimed.recordDigest, signed, policy.signers); err != nil {
			return err
		}
	}
	// The request's claims, held to the record they name (option A of
	// ADR-0011): a request whose claims do not match its record is refused.
	if record.packDigest != claimed.packDigest {
		return actRefusal{"consistency", "decision.packDigest is not the digest of the pack the record was decided under"}
	}
	recorded, err := record.citations()
	if err != nil {
		return actRefusal{"consistency", "the record's cites is not of the shape an action's citations take"}
	}
	if !sameCitations(recorded, cites) {
		return actRefusal{"consistency", "the receipts this action cites are not, as a set, the receipts the record cites; a record that cites none matches no action"}
	}
	// The record, held to the operator's policy (option B).
	dispositionV, _ := record.obj.get("disposition")
	disposition, _ := dispositionV.(*vObject)
	var kind, outcome, handoff string
	if disposition != nil {
		kind, _ = memberString(disposition, "kind")
		outcome, _ = memberString(disposition, "outcomeId")
		if h, ok := disposition.get("handoff"); ok {
			if handoffObj, ok := h.(*vObject); ok {
				handoff, _ = memberString(handoffObj, "state")
			}
		}
	}
	if kind != "outcome" || !contains(policy.outcomes, outcome) {
		return actRefusal{"policy-outcome", "the record's disposition is not an outcome the tool's decision policy allows"}
	}
	if handoff != "none" {
		return actRefusal{"policy-handoff", "the record's disposition does not state a handoff of \"none\"; a requested handoff is a person's to take, never a write's"}
	}
	if len(policy.packs) > 0 && !contains(policy.packs, record.packDigest) {
		return actRefusal{"policy-packs", "the record was decided under a pack the tool's decision policy does not name"}
	}
	if policy.reviewed {
		reviewed, _ := record.obj.get("reviewed")
		if b, ok := reviewed.(vBool); !ok || !bool(b) {
			return actRefusal{"policy-reviewed", `the record does not carry "reviewed": true, and the tool's decision policy requires a decision judged under reviewed law`}
		}
	}
	var facts value
	if inputsV, ok := record.obj.get("inputs"); ok {
		if inputs, ok := inputsV.(*vObject); ok {
			facts, _ = inputs.get("facts")
		}
	}
	for _, b := range policy.bind {
		argument, ok := resolvePointer(arguments, b.argument)
		if !ok {
			return actRefusal{"policy-bind", fmt.Sprintf("the request's arguments hold nothing at %q, which the tool's decision policy binds to the fact at %q", b.argument, b.fact)}
		}
		var fact value
		ok = false
		if facts != nil {
			fact, ok = resolvePointer(facts, b.fact)
		}
		if !ok {
			return actRefusal{"policy-bind", fmt.Sprintf("the record's facts hold nothing at %q, which the tool's decision policy binds to the argument at %q", b.fact, b.argument)}
		}
		// Equal as JSON values, types included: both in the canonical
		// domain and the same canonical bytes. The arguments are held to the
		// domain already, so a fact outside it -- a fraction, an exponent, an
		// integer past the safe range -- can equal no argument.
		if !canonicalValue(fact) || !bytes.Equal(canon(argument), canon(fact)) {
			return actRefusal{"policy-bind", fmt.Sprintf("the argument at %q does not equal the fact at %q", b.argument, b.fact)}
		}
	}
	return nil
}

// recordClaims is what the verifier reads of a decision record an action
// receipt names (SPEC.md §4 step 8): whether it is a runtime evaluation
// record at all, and if so the pack digest and the citations it states --
// citesRead false when its cites is not of the shape, which no action's
// citations match.
type recordClaims struct {
	understood bool
	packDigest string
	cites      []citation
	citesRead  bool
}

func recordClaimsOf(data []byte) recordClaims {
	record, _ := readRuntimeRecord(data)
	if record == nil {
		return recordClaims{}
	}
	cites, err := record.citations()
	return recordClaims{understood: true, packDigest: record.packDigest, cites: cites, citesRead: err == nil}
}
