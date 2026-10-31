package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"time"
)

// The delegation statement of spec RFC 0030 §2, as this gateway reads it
// (SPEC.md §11.1): a signed, bounded statement that a subject authorizes an
// actor for a scope until an expiry. This file is steps 1 to 7 of the RFC's
// verification -- the steps that depend only on the bytes and a pinned key,
// which any party can repeat -- and the narrowing check of its §3. Admission
// (steps 0 and 8 to 12) is delegation_admission.go's.

// delegationContext is the signing prefix of a statement; it carries the
// version and domain-separates a statement from a receipt, a seal and a
// witness statement.
const delegationContext = "judgment-pack/delegation/1:"

// The bounds of RFC 0030's open questions 3 and 21, enforced here: a chain of
// at most maxDelegationDepth+1 links, a link living at most a day, and the
// statement's own size caps.
const (
	maxDelegationDepth    = 4
	maxDelegationLifetime = 24 * time.Hour
	maxStatementBytes     = 65536
	maxScopeEntries       = 256
	maxScopeTools         = 256
	maxScopeLimits        = 16
)

// The refusals of the verification steps (RFC 0030 §2, SPEC.md §11.1, §11.5).
const (
	refusalMalformed          = "malformed"
	refusalUnsupportedVersion = "unsupported-version"
	refusalKeyMismatch        = "key-mismatch"
	refusalSignatureMismatch  = "signature-mismatch"
	refusalChainBroken        = "chain-broken"
	refusalWidened            = "widened"
	refusalNotYetValid        = "not-yet-valid"
	refusalExpired            = "expired"
	refusalCredentialMismatch = "credential-mismatch"
	refusalOutOfScope         = "out-of-scope"
)

// delegationRefusal is a refusal by name, with a sentence that repeats no
// credential and no statement.
type delegationRefusal struct {
	name   string
	reason string
	// scopeReason is step 11's reason, for out-of-scope alone.
	scopeReason string
}

func (r *delegationRefusal) Error() string {
	if r.reason == "" {
		return r.name
	}
	return r.name + ": " + r.reason
}

func refuse(name, format string, args ...any) *delegationRefusal {
	return &delegationRefusal{name: name, reason: fmt.Sprintf(format, args...)}
}

// principalRef names a person or a service: the issuer and subject of the
// identity the host verified for it, and its kind (RFC 0030, "Principal
// reference"). Two are equal only when all three members are.
type principalRef struct {
	kind, issuer, subject string
}

func (p principalRef) value() *vObject {
	v := newObject()
	v.set("kind", vString(p.kind))
	v.set("issuer", vString(p.issuer))
	v.set("subject", vString(p.subject))
	return v
}

// scopeEntry is one entry of a link's scope.
type scopeEntry struct {
	audienceKind, audienceName, source string
	tools, effects                     []string
	limits                             map[string]int64
}

// delegationLink is one statement as verified.
type delegationLink struct {
	obj         *vObject
	id, host    string
	keyID       string
	sub         principalRef
	agent       string
	software    value
	entries     []scopeEntry
	mayDelegate bool
	issuedAt    time.Time
	expiresAt   time.Time
	parentID    string // "" for a root
	parentHash  string
	depth       int64
	signature   string
	canonical   []byte
	digest      string
}

// delegationChain is a chain of links, root first, that passed steps 1 to 7.
type delegationChain struct {
	links     []*delegationLink
	canonical []byte // canon of the chain as an array
}

func (c *delegationChain) root() *delegationLink { return c.links[0] }
func (c *delegationChain) leaf() *delegationLink { return c.links[len(c.links)-1] }

// digests are the chain's digests, root first.
func (c *delegationChain) digests() vArray {
	out := make(vArray, 0, len(c.links))
	for _, l := range c.links {
		out = append(out, vString(l.digest))
	}
	return out
}

// readOnly reports whether every entry of every link admits only pure,
// read or read-external: the one chain a bearer credential may be bound to
// (RFC 0030 §2, open question 8).
func (c *delegationChain) readOnly() bool {
	for _, l := range c.links {
		for _, e := range l.entries {
			for _, effect := range e.effects {
				if effect == "propose" || effect == "act" {
					return false
				}
			}
		}
	}
	return true
}

// delegationTimeForm is the RFC's time: UTC with exactly milliseconds.
var delegationTimeForm = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$`)

const delegationTimeLayout = "2006-01-02T15:04:05.000Z"

// parseDelegationTime reads a time of the RFC's form, of a date that exists.
func parseDelegationTime(s string) (time.Time, bool) {
	if !delegationTimeForm.MatchString(s) {
		return time.Time{}, false
	}
	t, err := time.Parse(delegationTimeLayout, s)
	if err != nil || t.Format(delegationTimeLayout) != s {
		return time.Time{}, false
	}
	return t, true
}

// delegationTime is an instant in the RFC's form, to the millisecond.
func delegationTime(t time.Time) string {
	return t.UTC().Truncate(time.Millisecond).Format(delegationTimeLayout)
}

// isOpaqueID is the RFC's opaque identifier: 32 lowercase hex characters.
func isOpaqueID(s string) bool { return isLowerHexOfLen(s, 32) }

func isFlatTokenString(s string) bool { return requireSession(s) == nil }

// isGatewayAudienceName is the form of a gateway audience's name: the
// authority label, 1 to 256 characters from U+0021 to U+007E.
func isGatewayAudienceName(s string) bool {
	if len(s) == 0 || len(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

var limitNameForm = regexp.MustCompile(`^x-[A-Za-z0-9._-]{1,128}$`)

// isLimitName is `calls`, or `x-` and a flat token.
func isLimitName(s string) bool {
	if s == "calls" {
		return true
	}
	return limitNameForm.MatchString(s) && s != "x-." && s != "x-.."
}

// effectStrength is ADR-0027's order of the effect classes.
var effectStrength = map[string]int{"pure": 0, "read": 1, "read-external": 2, "propose": 3, "act": 4}

// exactObject is an object of exactly the members named, every one present.
func exactObject(v value, members ...string) (*vObject, bool) {
	obj, ok := v.(*vObject)
	if !ok || len(obj.byName) != len(members) {
		return nil, false
	}
	for _, m := range members {
		if _, present := obj.get(m); !present {
			return nil, false
		}
	}
	return obj, true
}

func stringOf(v value) (string, bool) {
	s, ok := v.(vString)
	return string(s), ok
}

// parsePrincipalRef reads a principal reference: exactly kind, issuer and
// subject, the kind person or service, issuer and subject non-empty.
func parsePrincipalRef(v value) (principalRef, bool) {
	obj, ok := exactObject(v, "kind", "issuer", "subject")
	if !ok {
		return principalRef{}, false
	}
	kind, ok1 := memberString(obj, "kind")
	issuer, ok2 := memberString(obj, "issuer")
	subject, ok3 := memberString(obj, "subject")
	if !ok1 || !ok2 || !ok3 || (kind != "person" && kind != "service") || issuer == "" || subject == "" {
		return principalRef{}, false
	}
	return principalRef{kind, issuer, subject}, true
}

// validSoftware is the RFC's software identity: exactly one of
// {package, version} and {harness}.
func validSoftware(v value) bool {
	if obj, ok := exactObject(v, "package", "version"); ok {
		p, ok1 := memberString(obj, "package")
		ver, ok2 := memberString(obj, "version")
		return ok1 && ok2 && p != "" && ver != ""
	}
	if obj, ok := exactObject(v, "harness"); ok {
		h, ok := memberString(obj, "harness")
		return ok && isDigest(h)
	}
	return false
}

// sortedStrings reads an array of strings, at least one and at most max,
// in strictly increasing code-point order (so with no repeat).
func sortedStrings(v value, max int) ([]string, bool) {
	arr, ok := v.(vArray)
	if !ok || len(arr) == 0 || len(arr) > max {
		return nil, false
	}
	out := make([]string, 0, len(arr))
	for i, item := range arr {
		s, ok := stringOf(item)
		if !ok || (i > 0 && !codePointLess(out[i-1], s)) {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// codePointLess orders strings by Unicode code point, which for valid UTF-8
// is the order of their bytes.
func codePointLess(a, b string) bool { return a < b }

// parseScopeEntry reads one entry of a scope.
func parseScopeEntry(v value) (scopeEntry, bool) {
	obj, ok := exactObject(v, "audience", "source", "tools", "effects", "limits")
	if !ok {
		return scopeEntry{}, false
	}
	var e scopeEntry
	audienceV, _ := obj.get("audience")
	audience, ok := exactObject(audienceV, "kind", "name")
	if !ok {
		return scopeEntry{}, false
	}
	e.audienceKind, _ = memberString(audience, "kind")
	e.audienceName, _ = memberString(audience, "name")
	switch e.audienceKind {
	case "gateway":
		if !isGatewayAudienceName(e.audienceName) {
			return scopeEntry{}, false
		}
	case "agent-host":
		if !isFlatTokenString(e.audienceName) {
			return scopeEntry{}, false
		}
	default:
		return scopeEntry{}, false
	}
	if e.source, ok = memberString(obj, "source"); !ok || e.source == "" {
		return scopeEntry{}, false
	}
	toolsV, _ := obj.get("tools")
	if e.tools, ok = sortedStrings(toolsV, maxScopeTools); !ok {
		return scopeEntry{}, false
	}
	effectsV, _ := obj.get("effects")
	effects, isArray := effectsV.(vArray)
	if !isArray || len(effects) == 0 {
		return scopeEntry{}, false
	}
	for i, item := range effects {
		s, ok := stringOf(item)
		strength, known := effectStrength[s]
		if !ok || !known || (i > 0 && strength <= effectStrength[e.effects[i-1]]) {
			return scopeEntry{}, false
		}
		e.effects = append(e.effects, s)
	}
	limitsV, _ := obj.get("limits")
	limits, ok := limitsV.(*vObject)
	if !ok || len(limits.byName) > maxScopeLimits {
		return scopeEntry{}, false
	}
	e.limits = map[string]int64{}
	for name, lv := range limits.byName {
		n, isInt := lv.(vInt)
		if !isLimitName(name) || !isInt || n < 0 {
			return scopeEntry{}, false
		}
		e.limits[name] = int64(n)
	}
	return e, true
}

// entryOrder is the order of scope entries: audience kind, audience name,
// source, each by code point.
func entryLess(a, b scopeEntry) bool {
	if a.audienceKind != b.audienceKind {
		return codePointLess(a.audienceKind, b.audienceKind)
	}
	if a.audienceName != b.audienceName {
		return codePointLess(a.audienceName, b.audienceName)
	}
	return codePointLess(a.source, b.source)
}

// v1Members are the members of a version 1 statement. A link carries each;
// one beside them is left to the signature (SPEC.md §11.1).
var v1Members = []string{"delegationVersion", "id", "host", "keyId", "sub", "act", "scope", "mayDelegate", "issuedAt", "expiresAt", "parent", "depth", "signature"}

// parseLink holds one link to version 1's structure (step 3).
func parseLink(obj *vObject) (*delegationLink, string) {
	for _, m := range v1Members {
		if _, present := obj.get(m); !present {
			return nil, "member " + m + " is missing"
		}
	}
	l := &delegationLink{obj: obj}
	var ok bool
	if l.id, ok = memberString(obj, "id"); !ok || !isOpaqueID(l.id) {
		return nil, "id is not an opaque identifier"
	}
	if l.host, ok = memberString(obj, "host"); !ok || !isFlatTokenString(l.host) {
		return nil, "host is not a flat token"
	}
	if l.keyID, ok = memberString(obj, "keyId"); !ok || !isLowerHexOfLen(l.keyID, 32) {
		return nil, "keyId is not a key identifier"
	}
	subV, _ := obj.get("sub")
	if l.sub, ok = parsePrincipalRef(subV); !ok {
		return nil, "sub is not a principal reference"
	}
	actV, _ := obj.get("act")
	act, ok := exactObject(actV, "agent", "software")
	if !ok {
		return nil, "act is not {agent, software}"
	}
	if l.agent, ok = memberString(act, "agent"); !ok || !isOpaqueID(l.agent) {
		return nil, "act.agent is not an opaque identifier"
	}
	l.software, _ = act.get("software")
	if !validSoftware(l.software) {
		return nil, "act.software is not a software identity"
	}
	scopeV, _ := obj.get("scope")
	scope, ok := exactObject(scopeV, "sources")
	if !ok {
		return nil, "scope is not {sources}"
	}
	sourcesV, _ := scope.get("sources")
	sources, ok := sourcesV.(vArray)
	if !ok || len(sources) == 0 || len(sources) > maxScopeEntries {
		return nil, "scope.sources is not an array of 1 to 256 entries"
	}
	for i, sv := range sources {
		e, ok := parseScopeEntry(sv)
		if !ok {
			return nil, fmt.Sprintf("scope.sources[%d] is not a scope entry", i)
		}
		if i > 0 && !entryLess(l.entries[i-1], e) {
			return nil, "scope.sources is out of order or repeats an audience and source"
		}
		l.entries = append(l.entries, e)
	}
	mayV, _ := obj.get("mayDelegate")
	may, ok := mayV.(vBool)
	if !ok {
		return nil, "mayDelegate is not a boolean"
	}
	l.mayDelegate = bool(may)
	issued, ok1 := memberString(obj, "issuedAt")
	expires, ok2 := memberString(obj, "expiresAt")
	if l.issuedAt, ok = parseDelegationTime(issued); !ok1 || !ok {
		return nil, "issuedAt is not a time"
	}
	if l.expiresAt, ok = parseDelegationTime(expires); !ok2 || !ok {
		return nil, "expiresAt is not a time"
	}
	if !l.expiresAt.After(l.issuedAt) {
		return nil, "expiresAt is not after issuedAt"
	}
	if l.expiresAt.Sub(l.issuedAt) > maxDelegationLifetime {
		return nil, "the link lives more than 24 hours"
	}
	depthV, _ := obj.get("depth")
	depth, ok := depthV.(vInt)
	if !ok || depth < 0 {
		return nil, "depth is not a non-negative integer"
	}
	l.depth = int64(depth)
	parentV, _ := obj.get("parent")
	if _, isNull := parentV.(vNull); isNull {
		if l.depth != 0 {
			return nil, "a link with no parent has a depth other than 0"
		}
	} else {
		parent, ok := exactObject(parentV, "id", "digest")
		if !ok {
			return nil, "parent is neither null nor {id, digest}"
		}
		l.parentID, _ = memberString(parent, "id")
		l.parentHash, _ = memberString(parent, "digest")
		if !isOpaqueID(l.parentID) || !isDigest(l.parentHash) {
			return nil, "parent is not of its form"
		}
		if l.depth == 0 {
			return nil, "a link with a parent has a depth of 0"
		}
	}
	if l.signature, ok = memberString(obj, "signature"); !ok || !isSignature3(l.signature) {
		return nil, "signature is not 128 lowercase hexadecimal characters"
	}
	l.canonical = canon(obj)
	if len(l.canonical) > maxStatementBytes {
		return nil, "the link is over 65536 bytes"
	}
	sum := sha256.Sum256(l.canonical)
	l.digest = "sha256:" + hex.EncodeToString(sum[:])
	return l, ""
}

// signingInput is the prefix and canon of the link without its signature.
func (l *delegationLink) signingInput() []byte {
	covered := newObject()
	for _, name := range l.obj.names {
		if name == "signature" {
			continue
		}
		v, _ := l.obj.get(name)
		covered.set(name, v)
	}
	return append([]byte(delegationContext), canon(covered)...)
}

// delegationKeys are the keys pinned per issuing host, by key identifier.
type delegationKeys map[string]map[string]ed25519.PublicKey

// verifyDelegationChain applies steps 1 to 7 to a chain, in order, stopping at
// the first failure.
func verifyDelegationChain(chainV value, keys delegationKeys) (*delegationChain, *delegationRefusal) {
	// Step 1. The parser has refused a duplicate member and a value outside
	// the canon domain before this; what remains is the array's own form.
	arr, ok := chainV.(vArray)
	if !ok || len(arr) == 0 || len(arr) > maxDelegationDepth+1 {
		return nil, refuse(refusalMalformed, "a chain is an array of one to five statements")
	}
	objs := make([]*vObject, 0, len(arr))
	for i, item := range arr {
		obj, ok := item.(*vObject)
		if !ok {
			return nil, refuse(refusalMalformed, "link %d is not an object", i)
		}
		if _, ok := memberString(obj, "delegationVersion"); !ok {
			return nil, refuse(refusalMalformed, "link %d has no string delegationVersion", i)
		}
		objs = append(objs, obj)
	}
	// Step 2.
	for i, obj := range objs {
		if version, _ := memberString(obj, "delegationVersion"); version != "1" {
			return nil, refuse(refusalUnsupportedVersion, "link %d is of a delegation version this gateway does not read", i)
		}
	}
	// Step 3.
	chain := &delegationChain{canonical: canon(arr)}
	for i, obj := range objs {
		l, why := parseLink(obj)
		if l == nil {
			return nil, refuse(refusalMalformed, "link %d: %s", i, why)
		}
		chain.links = append(chain.links, l)
	}
	// Step 4.
	for i, l := range chain.links {
		if _, pinned := keys[l.host][l.keyID]; !pinned {
			return nil, refuse(refusalKeyMismatch, "link %d is signed by a key not pinned for its host", i)
		}
	}
	// Step 5.
	for i, l := range chain.links {
		signature, err := hex.DecodeString(l.signature)
		if err != nil || !ed25519.Verify(keys[l.host][l.keyID], l.signingInput(), signature) {
			return nil, refuse(refusalSignatureMismatch, "link %d's signature does not verify", i)
		}
	}
	// Step 6: clauses 0 to 3.
	if r := chain.root(); r.parentID != "" || r.depth != 0 {
		return nil, refuse(refusalChainBroken, "the chain does not start at a root")
	}
	for k := 1; k < len(chain.links); k++ {
		c, p := chain.links[k], chain.links[k-1]
		switch {
		case c.parentID != p.id || c.parentHash != p.digest:
			return nil, refuse(refusalChainBroken, "link %d does not name link %d as its parent", k, k-1)
		case c.depth != p.depth+1 || c.depth > maxDelegationDepth:
			return nil, refuse(refusalChainBroken, "link %d's depth is not its parent's plus one, within the maximum", k)
		case c.host != p.host:
			return nil, refuse(refusalChainBroken, "link %d names another host than its parent", k)
		}
	}
	// Step 7: clauses 4 to 8.
	for k := 1; k < len(chain.links); k++ {
		if why := narrows(chain.links[k], chain.links[k-1]); why != "" {
			return nil, refuse(refusalWidened, "link %d %s", k, why)
		}
	}
	return chain, nil
}

// narrows is clauses 4 to 8 for a child and its parent, or "" when they
// hold.
func narrows(c, p *delegationLink) string {
	if c.sub != p.sub {
		return "changes the subject"
	}
	if c.issuedAt.Before(p.issuedAt) || c.expiresAt.After(p.expiresAt) {
		return "is valid outside its parent's validity"
	}
	for _, e := range c.entries {
		var parent *scopeEntry
		for i := range p.entries {
			pe := &p.entries[i]
			if pe.audienceKind == e.audienceKind && pe.audienceName == e.audienceName && pe.source == e.source {
				parent = pe
				break
			}
		}
		if parent == nil {
			return "admits a source its parent does not"
		}
		for _, t := range e.tools {
			if !slices.Contains(parent.tools, t) {
				return "admits a tool its parent does not"
			}
		}
		for _, effect := range e.effects {
			if !slices.Contains(parent.effects, effect) {
				return "admits an effect its parent does not"
			}
		}
		for name, bound := range parent.limits {
			mine, present := e.limits[name]
			if !present || mine > bound {
				return "drops or raises a limit of its parent"
			}
		}
	}
	if !p.mayDelegate {
		return "is below a link that permits no child"
	}
	return ""
}

// timeRefusal is step 8 at the gateway's time t: not yet valid, then expired,
// links root first within each.
func (c *delegationChain) timeRefusal(t time.Time) *delegationRefusal {
	for i, l := range c.links {
		if t.Before(l.issuedAt) {
			return refuse(refusalNotYetValid, "link %d is not yet valid", i)
		}
	}
	for i, l := range c.links {
		if !t.Before(l.expiresAt) {
			return refuse(refusalExpired, "link %d has expired", i)
		}
	}
	return nil
}

// scopeRefusal is the gateway's own part of step 11 for one call: the first
// failing reason, in the order source, tool, effect, limit-unknown, taken
// within a link before the next link. The limit reason for calls is the
// issuing host's, which holds the counter.
func (c *delegationChain) scopeRefusal(audience, source, tool, effect string) *delegationRefusal {
	return c.scopeCheck(audience, source, tool, effect, false)
}

// scopeCheck is scopeRefusal, or, with sourceToolOnly, its source and tool
// reasons alone.
func (c *delegationChain) scopeCheck(audience, source, tool, effect string, sourceToolOnly bool) *delegationRefusal {
	for i, l := range c.links {
		var entry *scopeEntry
		for j := range l.entries {
			e := &l.entries[j]
			if e.audienceKind == "gateway" && e.audienceName == audience && e.source == source {
				entry = e
				break
			}
		}
		reason := ""
		switch {
		case entry == nil:
			reason = "source"
		case tool == "" || !slices.Contains(entry.tools, tool):
			reason = "tool"
		case sourceToolOnly:
		case effect == "" || !slices.Contains(entry.effects, effect):
			reason = "effect"
		default:
			for name := range entry.limits {
				if name != "calls" {
					reason = "limit-unknown"
				}
			}
		}
		if reason != "" {
			return &delegationRefusal{name: refusalOutOfScope, scopeReason: reason, reason: fmt.Sprintf("link %d does not admit the call (%s)", i, reason)}
		}
	}
	return nil
}

// sourceToolRefusal is step 11's source and tool reasons alone: what the
// actor's row of the sender table holds a request the key lookup answers to
// (spec #284 NC1), which dispatches nothing and so is not held to effects or
// limits.
func (c *delegationChain) sourceToolRefusal(audience, source, tool string) bool {
	return c.scopeCheck(audience, source, tool, "", true) != nil
}
