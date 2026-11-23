package main

// The limits member, its start line and its posture (ADR-0057, decisions 1
// and 5; gateway #507). The limiter is limits.go; the routes that charge a
// request are limits_serve.go.

import (
	"errors"
	"fmt"
	"sort"
)

// requestLimitsVersion is the engine configuration version from which a
// configuration may carry the top-level limits member (ADR-0057).
const requestLimitsVersion = "44"

// defaultBeforeScope is the gateway-wide cap of a limits member that gives
// no beforeScope (the maintainer's ruling: 1024).
const defaultBeforeScope = 1024

// limitsConfig is the limits member: the gateway-wide cap, the default
// entry, and the entry of each scope key it names (a scope identifier, or
// unscopedMarker). Each instance counts alone.
type limitsConfig struct {
	beforeScope int
	byDefault   *limitEntry
	scopes      map[string]limitEntry
}

var (
	errLimitsForm      = errors.New("engine configuration: limits is an object of beforeScope, default and scopes, with at least one of them")
	errLimitsEntryForm = errors.New("engine configuration: limits: an entry is an object of requestsPerMinute, burst, inFlight and perCaller, with at least one of them; perCaller holds the first three alone")
	errLimitsBefore    = errors.New("engine configuration: limits.beforeScope is {\"inFlight\": n}, an integer from 1 to 65536")
	errLimitsScopes    = errors.New("engine configuration: limits.scopes is an object whose keys are scope identifiers")
	errLimitsUnknown   = errors.New("engine configuration: limits.scopes: a key is a scope identifier some platform is fixed to, or \"unscoped\" where some platform is of none")
	errLimitsPerCaller = errors.New("engine configuration: limits: perCaller counts each caller, and this configuration has no identity to name one")
)

// parseLimitsConfig holds the limits member to its form. platformScopes are
// the scope keys the configuration's platforms are fixed to, and identity is
// whether it has one.
func parseLimitsConfig(v value, platformScopes map[string]bool, identity bool) (*limitsConfig, error) {
	obj, ok := v.(*vObject)
	if !ok || len(obj.names) == 0 {
		return nil, errLimitsForm
	}
	if exactlyMembers(obj, map[string]bool{"beforeScope": false, "default": false, "scopes": false}, "engine configuration: limits") != nil {
		return nil, errLimitsForm
	}
	cfg := &limitsConfig{beforeScope: defaultBeforeScope, scopes: map[string]limitEntry{}}
	if before, present := obj.get("beforeScope"); present {
		b, isObject := before.(*vObject)
		if !isObject || len(b.names) != 1 || exactlyMembers(b, map[string]bool{"inFlight": true}, "") != nil {
			return nil, errLimitsBefore
		}
		n, _ := b.get("inFlight")
		in, isInt := n.(vInt)
		if !isInt || in < 1 || in > maxBeforeScope {
			return nil, errLimitsBefore
		}
		cfg.beforeScope = int(in)
	}
	if def, present := obj.get("default"); present {
		e, err := parseLimitEntry(def)
		if err != nil {
			return nil, err
		}
		cfg.byDefault = &e
	}
	if scopes, present := obj.get("scopes"); present {
		s, isObject := scopes.(*vObject)
		if !isObject {
			return nil, errLimitsScopes
		}
		for _, key := range s.names {
			if !platformScopes[key] {
				return nil, errLimitsUnknown
			}
			raw, _ := s.get(key)
			e, err := parseLimitEntry(raw)
			if err != nil {
				return nil, err
			}
			cfg.scopes[key] = e
		}
	}
	if !identity {
		for _, e := range cfg.entries(platformScopes) {
			if e.perCaller != nil {
				return nil, errLimitsPerCaller
			}
		}
	}
	// the limiter's own checks: a pair given together, a caller's value
	// at or under its scope's
	if _, err := newRequestLimiter(monotonicLimitClock(), cfg.beforeScope, cfg.entries(platformScopes)); err != nil {
		return nil, fmt.Errorf("engine configuration: %v", err)
	}
	return cfg, nil
}

// parseLimitEntry is one entry: at least one member, each an integer in
// its range, and perCaller the same three at least one of them.
func parseLimitEntry(v value) (limitEntry, error) {
	scope, rest, err := parseLimitValues(v, true)
	if err != nil {
		return limitEntry{}, err
	}
	e := limitEntry{scope: scope}
	if rest != nil {
		caller, _, err := parseLimitValues(rest, false)
		if err != nil {
			return limitEntry{}, err
		}
		e.perCaller = &caller
	}
	return e, nil
}

// parseLimitValues reads requestsPerMinute, burst and inFlight, and returns
// perCaller unread where it may be given.
func parseLimitValues(v value, perCaller bool) (limitValues, value, error) {
	obj, ok := v.(*vObject)
	members := map[string]bool{"requestsPerMinute": false, "burst": false, "inFlight": false}
	if perCaller {
		members["perCaller"] = false
	}
	if !ok || len(obj.names) == 0 || exactlyMembers(obj, members, "") != nil {
		return limitValues{}, nil, errLimitsEntryForm
	}
	var out limitValues
	for _, m := range []struct {
		name string
		most int64
		into *int
		err  error
	}{
		{"requestsPerMinute", maxRequestsPerMinute, &out.requestsPerMinute, errLimitRate},
		{"burst", maxLimitBurst, &out.burst, errLimitBurst},
		{"inFlight", maxLimitInFlight, &out.inFlight, errLimitInFlight},
	} {
		raw, present := obj.get(m.name)
		if !present {
			continue
		}
		n, isInt := raw.(vInt)
		if !isInt || n < 1 || int64(n) > m.most {
			return limitValues{}, nil, fmt.Errorf("engine configuration: %v", m.err)
		}
		*m.into = int(n)
	}
	if (out.requestsPerMinute == 0) != (out.burst == 0) {
		return limitValues{}, nil, fmt.Errorf("engine configuration: %v", errLimitPair)
	}
	rest, _ := obj.get("perCaller")
	return out, rest, nil
}

// entries are the effective entries of the scope keys given: a scope's own
// entry, replacing default whole, or default.
func (c *limitsConfig) entries(keys map[string]bool) map[string]limitEntry {
	out := map[string]limitEntry{}
	for key := range keys {
		if e, named := c.scopes[key]; named {
			out[key] = e
		} else if c.byDefault != nil {
			out[key] = *c.byDefault
		}
	}
	return out
}

// limitScopeKey is the limits key of a source's scope: its identifier, or
// unscopedMarker for none.
func limitScopeKey(scope string) string {
	if scope == "" {
		return unscopedMarker
	}
	return scope
}

// limitScopeKeys are the scope keys of the sources given.
func limitScopeKeys(sources map[string]sourceSpec) map[string]bool {
	keys := map[string]bool{}
	for _, spec := range sources {
		keys[limitScopeKey(spec.scope)] = true
	}
	return keys
}

// limiterFor is the limiter of a configuration's limits over the sources it
// serves; nil, limiting nothing, where it has none.
func limiterFor(c *limitsConfig, sources map[string]sourceSpec) (*requestLimiter, error) {
	if c == nil {
		return nil, nil
	}
	return newRequestLimiter(monotonicLimitClock(), c.beforeScope, c.entries(limitScopeKeys(sources)))
}

// requestLimitsStartLine is the start's line where limits is configured,
// and "" otherwise.
func requestLimitsStartLine(c *limitsConfig, sources map[string]sourceSpec) string {
	if c == nil {
		return ""
	}
	keys := limitScopeKeys(sources)
	return fmt.Sprintf("request limits: %d of %d scopes are limited, counted by this instance alone", len(c.entries(keys)), len(keys))
}

// protectionRequestLimits is the posture line of the limits (ADR-0057,
// decision 5).
const protectionRequestLimits = "request-limits"

const limitsPerInstance = "counted by this instance alone; under several instances each one counts its own"

// requestLimitsLines is the line, given only where limits is configured,
// judged over the sources the report is of (already cut to the caller's
// reach) and nothing else.
func requestLimitsLines(in postureInput) []postureLine {
	if in.limits == nil {
		return nil
	}
	line := func(state, reason string) []postureLine {
		return []postureLine{{protectionRequestLimits, state, reason}}
	}
	keys := limitScopeKeys(in.sources)
	whose := "this gateway serves"
	if in.reach != nil {
		whose = "this caller's token reaches"
	}
	before := fmt.Sprintf("the gateway-wide cap holds %d requests before their scope", in.limits.beforeScope)
	if len(keys) == 0 {
		return line(postureNotApplicable, fmt.Sprintf("%s no source, so there is no scope to judge; %s; %s", whose, before, limitsPerInstance))
	}
	entries := in.limits.entries(keys)
	full := 0
	for _, e := range entries {
		if e.scope.requestsPerMinute > 0 && e.scope.inFlight > 0 {
			full++
		}
	}
	counts := fmt.Sprintf("%d of the %d scopes %s have a request rate and an in-flight cap", full, len(keys), whose)
	switch {
	case len(entries) == 0:
		return line(postureNotEnforced, fmt.Sprintf("none of the %d scopes %s is limited; %s; %s", len(keys), whose, before, limitsPerInstance))
	case in.callerScopes != "checked":
		// any caller can spend any scope's share
		return line(posturePartial, fmt.Sprintf("%s, and callers are not held to their scopes, so any caller can spend any scope's share; %s; %s", counts, before, limitsPerInstance))
	case full == len(keys):
		return line(postureEnforced, fmt.Sprintf("%s, and callers are held to their scopes; %s; %s", counts, before, limitsPerInstance))
	}
	return line(posturePartial, fmt.Sprintf("%s; %s; %s", counts, before, limitsPerInstance))
}

// limitsPosture is the posture member: one entry for each scope of the
// report that has an effective entry, sorted by the scope's bytes.
func limitsPosture(in postureInput) vArray {
	entries := in.limits.entries(limitScopeKeys(in.sources))
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := vArray{}
	for _, key := range keys {
		e := entries[key]
		o := limitValuesObject(e.scope)
		o.set("scope", vString(key))
		if e.perCaller != nil {
			o.set("perCaller", limitValuesObject(*e.perCaller))
		}
		out = append(out, o)
	}
	return out
}

func limitValuesObject(v limitValues) *vObject {
	o := newObject()
	for _, m := range []struct {
		name string
		n    int
	}{{"requestsPerMinute", v.requestsPerMinute}, {"burst", v.burst}, {"inFlight", v.inFlight}} {
		if m.n > 0 {
			o.set(m.name, vInt(m.n))
		}
	}
	return o
}
