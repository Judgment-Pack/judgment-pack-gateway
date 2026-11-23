package main

// Caller scope identifiers (docs/adr/0037-a-caller-is-held-to-the-scope-identifiers-its-token-and-the-configuration-allow.md;
// SPEC.md §6, "Caller scope identifiers"): a caller's signed token names the
// scope identifiers it is for in one claim, scope_ids, which the Runner reads
// in the same form, and engine configuration version 27's
// identity.callerScopes grants each subject what it may be for. A request is
// held to the claim's scope identifiers, each of which the subject's entry
// must grant. "Scope identifier" here is ADR-0026's, never a delegation's
// scope or an action key's.

import (
	"errors"
	"fmt"
)

// scopeClaimName is the token claim naming the scope identifiers a caller is
// for: the Runner's claim too, so that one issuer serves both.
const scopeClaimName = "scope_ids"

// unscopedMarker, in a claim or in a configuration's list, names the sources
// of no scope identifier. It is never a scope identifier a caller is granted,
// and from engine version 27 no platform is fixed to it (parsePlatformScope);
// a platform of an earlier file fixed to these bytes is reached by an
// installation caller alone.
const unscopedMarker = "unscoped"

// maxCallerScopes bounds a claim and a configuration's list.
const maxCallerScopes = 256

// The two refusals of a token the identity verified, answered 401 before the
// route reads the request (authenticate) on every route that takes a token
// but the witness's /witness/*, which verify the token, read no claim and
// carry no scope data; they quote nothing of the token or the configuration. A claimless token
// whose subject's entry is a list without the marker is refused with the
// wider claim's sentence (ADR-0037, decision 4).
var (
	errScopeClaimForm  = errors.New("the token's " + scopeClaimName + " is not 1 to 256 scope identifiers, each once")
	errScopeClaimWider = errors.New("the token's " + scopeClaimName + " names a scope identifier the configuration does not grant its subject")
)

// callerScopes is identity.callerScopes as loaded. Its zero value is the
// default, checked with every subject "unscoped": a configuration that does
// not write the member is held, never opened.
type callerScopes struct {
	unchecked bool
	entries   map[string]callerEntry // by subject of the identity's issuer
}

// callerEntry is one subject's entry: "installation", which grants every
// scope identifier and the marker, or the strings it grants, the marker
// among them where it may reach the sources of no scope identifier.
// "unscoped" is the entry granting the marker alone, and a subject with no
// entry has it.
type callerEntry struct {
	installation bool
	grants       map[string]bool
}

var unscopedEntry = callerEntry{grants: map[string]bool{unscopedMarker: true}}

func (e callerEntry) grant(s string) bool { return e.installation || e.grants[s] }

// entryFor is the entry the configuration gives a caller's subject, or
// "unscoped": an entry is of a subject of the identity's one issuer.
func (c callerScopes) entryFor(issuer, subject, identityIssuer string) callerEntry {
	if issuer == identityIssuer {
		if e, held := c.entries[subject]; held {
			return e
		}
	}
	return unscopedEntry
}

// errCallerScopesForm is the refusal of a member out of its form; it names
// the member and the form, and repeats no value.
const errCallerScopesForm = `identity.callerScopes must be "unchecked", or an object whose members are subjects, each naming "unscoped", "installation", or 1 to 256 strings, each once, each a scope identifier or "unscoped"`

// parseCallerScopes reads identity.callerScopes.
func parseCallerScopes(v value) (callerScopes, error) {
	if s, isString := v.(vString); isString {
		if s == "unchecked" {
			return callerScopes{unchecked: true}, nil
		}
		return callerScopes{}, errors.New(errCallerScopesForm)
	}
	obj, isObject := v.(*vObject)
	if !isObject {
		return callerScopes{}, errors.New(errCallerScopesForm)
	}
	out := callerScopes{entries: map[string]callerEntry{}}
	for _, subject := range obj.names {
		if subject == "" {
			return callerScopes{}, errors.New("identity.callerScopes: a member's name is a subject, which is never empty")
		}
		entry, err := parseCallerEntry(obj.byName[subject])
		if err != nil {
			return callerScopes{}, err
		}
		out.entries[subject] = entry
	}
	return out, nil
}

func parseCallerEntry(v value) (callerEntry, error) {
	switch v := v.(type) {
	case vString:
		switch v {
		case unscopedMarker:
			return unscopedEntry, nil
		case "installation":
			return callerEntry{installation: true}, nil
		}
	case vArray:
		grants, ok := scopeList(v)
		if ok {
			return callerEntry{grants: grants}, nil
		}
	}
	return callerEntry{}, errors.New(errCallerScopesForm)
}

// scopeList is a claim's or an entry's list: 1 to 256 strings, each once,
// each a scope identifier in §1.2a's form (the marker is of that form).
func scopeList(items vArray) (map[string]bool, bool) {
	if len(items) == 0 || len(items) > maxCallerScopes {
		return nil, false
	}
	out := make(map[string]bool, len(items))
	for _, item := range items {
		s, isString := item.(vString)
		if !isString || !isScopeIdentifier(string(s)) || out[string(s)] {
			return nil, false
		}
		out[string(s)] = true
	}
	return out, true
}

// scopeReach is what a caller's request may be for: every source, the
// sources of no scope identifier, and these scope identifiers. Its zero
// value reaches nothing.
type scopeReach struct {
	every bool
	none  bool
	ids   map[string]bool
}

// holds is whether the reach takes a source fixed to scope ("" for none).
func (r scopeReach) holds(scope string) bool {
	switch {
	case r.every:
		return true
	case scope == "":
		return r.none
	}
	return r.ids[scope]
}

// narrowedTo is the reach held to the scope identifier a /seal request names
// (ADR-0041): where it names one, the reach takes that identifier alone, and
// only where it took it already; where it names none, the reach is as it
// was. A request naming a scope reaches no session of none, so a front fixed
// to one scope identifier, which names it on every seal, seals that
// identifier's sessions and no other: one of another scope, or of none, is
// answered as one the gateway does not hold (sealFor).
func (r scopeReach) narrowedTo(asked requestedScope) scopeReach {
	if !asked.named {
		return r
	}
	if asked.value == "" || !r.holds(asked.value) {
		return scopeReach{}
	}
	return scopeReach{ids: map[string]bool{asked.value: true}}
}

// reachOf is what a caller reaches under the configured identity (ADR-0037,
// decision 3), or the 401 refusal of a token its subject's entry does not
// grant. With no identity there is no caller to hold, and with "unchecked"
// the claim is not read: either reaches every source, as before, and the
// start and /posture say so. An acquisition the gateway makes for no caller
// under an identity (no route makes one; a caller is authenticated first)
// reaches the sources of none alone, never a scope identifier.
func reachOf(id *identityConfig, who *caller) (scopeReach, error) {
	if id == nil || id.callers.unchecked {
		return scopeReach{every: true}, nil
	}
	if who == nil {
		return scopeReach{none: true}, nil
	}
	entry := id.callers.entryFor(who.issuer, who.subject, id.issuer)
	if who.delegated != nil {
		// A chain bound to one scope identifier (spec RFC 0030 §2) reaches
		// that identifier's sources alone, and only where the subject's own
		// entry grants it: the binding replaces decision 5 for a bound chain
		// and widens nothing the configuration has not granted the subject.
		// The request check (delegatedScopeRefused) has already held the
		// request to the binding and to the issuing host's scopeIds.
		if c := who.delegated.credential; c != nil {
			if id, bound := c.chain.scopeBinding(); bound {
				if entry.grant(id) {
					return scopeReach{ids: map[string]bool{id: true}}, nil
				}
				return scopeReach{}, nil
			}
		}
		// A chain's subject is stated by its issuing host, and a chain
		// carries no claim: a delegated request reaches the sources of no
		// scope identifier where the subject's own claimless token would,
		// and never a scope identifier (decision 5).
		if entry.installation || entry.grants[unscopedMarker] {
			return scopeReach{none: true}, nil
		}
		return scopeReach{}, nil
	}
	if !who.claimed {
		switch {
		case entry.installation:
			return scopeReach{every: true}, nil
		case entry.grants[unscopedMarker]:
			return scopeReach{none: true}, nil
		}
		return scopeReach{}, errScopeClaimWider
	}
	items, isArray := who.scopeClaim.(vArray)
	claim, ok := scopeList(items)
	if !isArray || !ok {
		return scopeReach{}, errScopeClaimForm
	}
	reach := scopeReach{ids: map[string]bool{}}
	for s := range claim {
		if !entry.grant(s) {
			return scopeReach{}, errScopeClaimWider
		}
		if s == unscopedMarker {
			reach.none = true
		} else {
			reach.ids[s] = true
		}
	}
	return reach, nil
}

// reachRefusalAct is the 403 of /act to a caller that does not reach the sources
// of no scope identifier: the same sentence whatever the request names.
const reachRefusalAct = "scope identifier: a write source is of no scope identifier, and this caller's token does not reach the sources of none"

// reachRefusalVerify is the 403 of /verify to a caller that does not reach
// every source the store's verdict covers.
const reachRefusalVerify = "scope identifier: the store's verdict covers sessions of every scope identifier, and this caller's token does not reach every one"

// callerScopesMode is what the start and /posture say of the rule: checked,
// unchecked, or not held for want of an identity.
func callerScopesMode(id *identityConfig) string {
	switch {
	case id == nil:
		return "no-identity"
	case id.callers.unchecked:
		return "unchecked"
	}
	return "checked"
}

// callerScopesStartLine is the start's line, given wherever an identity is
// configured or some source is fixed to a scope identifier ("" elsewhere): a
// configuration with an identity refuses 401 a token whose claim its
// subject's entry does not grant, scoped sources or none, so the start says
// so whenever it can happen.
func callerScopesStartLine(id *identityConfig, sources map[string]sourceSpec) string {
	scoped := anyScoped(sources)
	switch callerScopesMode(id) {
	case "no-identity":
		if !scoped {
			return ""
		}
		return "no identity is configured, so no caller is held to scope identifiers: every request reaches every source"
	case "unchecked":
		return "identity.callerScopes is \"unchecked\": no caller is held to scope identifiers, and every caller reaches every source"
	}
	line := fmt.Sprintf("caller scope identifiers are checked: a request is held to the scope identifiers its token's %s names and identity.callerScopes grants its subject", scopeClaimName)
	if !scoped {
		line += fmt.Sprintf("; no platform is fixed to a scope identifier, and a token whose %s names one the configuration does not grant its subject is refused 401", scopeClaimName)
	}
	return line
}

// callerScopesLine is /posture's line, given wherever an identity is
// configured or some source is fixed to a scope identifier. cut is whether
// the report is served to a caller held to scope identifiers and the sources
// are the ones its token reaches (hostPosture, ADR-0041): where none of them
// is fixed to a scope identifier the line says so of them alone, and says
// nothing of whether another scope identifier's sources exist.
func callerScopesLine(mode string, sources map[string]sourceSpec, cut bool) []postureLine {
	scoped := anyScoped(sources)
	if mode == "" || mode == "no-identity" && !scoped {
		return nil
	}
	switch mode {
	case "checked":
		if !scoped && cut {
			return []postureLine{{protectionCallerScopes, postureEnforced,
				"no source this caller's token reaches is fixed to a scope identifier; a token whose " + scopeClaimName + " names one the configuration does not grant its subject is refused 401"}}
		}
		if !scoped {
			return []postureLine{{protectionCallerScopes, postureEnforced,
				"no source is fixed to a scope identifier; a token whose " + scopeClaimName + " names one the configuration does not grant its subject is refused 401"}}
		}
		return []postureLine{{protectionCallerScopes, postureEnforced,
			"a request to a source fixed to a scope identifier is served only to a caller whose token names it and whose subject the configuration grants it"}}
	case "unchecked":
		return []postureLine{{protectionCallerScopes, postureNotEnforced,
			"identity.callerScopes is \"unchecked\": every caller reaches every scope identifier"}}
	}
	return []postureLine{{protectionCallerScopes, postureNotEnforced,
		"no identity is configured: every request reaches every scope identifier"}}
}

// anyScoped is whether some source is fixed to a scope identifier.
func anyScoped(sources map[string]sourceSpec) bool {
	for _, spec := range sources {
		if spec.scope != "" {
			return true
		}
	}
	return false
}
