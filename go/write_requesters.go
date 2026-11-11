package main

import (
	"fmt"
	"sort"
	"strings"
)

// A platform's writeRequesters (engineVersion 18, gateway #383): who may ask
// for a write through each of the platform's write tools. Without the member
// every requester the identity, or a delegation, authenticates may ask for a
// write through any write tool, as before; with it, a write through a tool
// the member holds is refused unless its requester is one the tool's list
// names -- the tool's own list where the member gives the tool one, the
// platform's otherwise. A list that is present and empty names nobody, so a
// member that is present never admits more than its absence would.
//
// The requester is the one an action receipt names as action.requester
// (SPEC.md §1.2a, §11.7): the configured issuer and the subject of a bearer
// token; under a delegation credential, the chain's sub, on whose behalf the
// run acts, never the agent presenting it; on a request naming a reservation
// (SPEC.md §11.8), the reservation's sub, never the subject of the token of
// the host or the operator who sends it. An entry names the requester by
// its issuer and subject, compared with the request's byte for byte: no
// case folding, no Unicode normalization, no trimming, and no subject of one
// issuer is another issuer's.
//
// It is held in /act after the tool is known and before the arguments, the
// action key, the decision and the cites are read (act), so a requester the
// list refuses learns nothing of the policy, the record, the key or whether
// its arguments would pass; it is refused 403 at refusedAt write-requesters,
// with one fixed sentence that names no requester and no list, nothing sent
// and nothing minted.

// requesterRef is one requester a list names.
type requesterRef struct {
	issuer, subject string
}

// writeRequesters is the member as configured. platform is the list a tool
// with no list of its own is held to, nil when the member gives none; tools
// are the tools' own lists, each replacing the platform's for its tool. A
// list given empty is a non-nil empty set and names nobody.
type writeRequesters struct {
	platform map[requesterRef]bool
	tools    map[string]map[requesterRef]bool
}

// writeRequestersStep is the refusedAt of a requester a tool's list does not
// name, and writeRequestersRefusal its one sentence.
const (
	writeRequestersStep    = "write-requesters"
	writeRequestersRefusal = "the requester is not one the configuration's writeRequesters names for this tool"
)

// listFor is the list a write through tool is held to, nil when none is.
func (w *writeRequesters) listFor(tool string) map[requesterRef]bool {
	if w == nil {
		return nil
	}
	if list, own := w.tools[tool]; own {
		return list
	}
	return w.platform
}

// refusal is why who may not ask for a write through tool, or nil: a tool
// held to a list admits only a requester the list names, by its issuer and
// subject exactly; a tool held to none admits every requester.
func (w *writeRequesters) refusal(tool string, who *caller) error {
	list := w.listFor(tool)
	if list == nil {
		return nil
	}
	if who != nil && list[requesterRef{issuer: who.issuer, subject: who.subject}] {
		return nil
	}
	return actRefusal{writeRequestersStep, writeRequestersRefusal}
}

var writeRequestersMembers = map[string]bool{"platform": false, "tools": false}

// parseWriteRequesters holds a platform's writeRequesters to its shape: an
// object of platform, an array of requesters, and tools, an object of at
// least one write tool each with an array of requesters, at least one of the
// two given. issuer is identity.issuer; without a delegation every
// requester is of that issuer, so an entry of another could never be met
// and is refused, while a delegation's chain may name a sub of any issuer.
func parseWriteRequesters(v value, platform, issuer string, delegation bool) (*writeRequesters, error) {
	where := "platform " + platform + ": writeRequesters"
	obj, ok := v.(*vObject)
	if !ok {
		return nil, fmt.Errorf("engine configuration: %s must be an object of platform, tools or both", where)
	}
	if err := exactlyMembers(obj, writeRequestersMembers, "engine configuration: "+where); err != nil {
		return nil, err
	}
	if len(obj.names) == 0 {
		return nil, fmt.Errorf("engine configuration: %s names neither platform nor tools, and restricts nothing", where)
	}
	w := &writeRequesters{}
	if raw, present := obj.get("platform"); present {
		list, err := parseRequesterList(raw, where+".platform", issuer, delegation)
		if err != nil {
			return nil, err
		}
		w.platform = list
	}
	if raw, present := obj.get("tools"); present {
		tools, ok := raw.(*vObject)
		if !ok || len(tools.names) == 0 {
			return nil, fmt.Errorf("engine configuration: %s.tools, when present, is an object naming at least one write tool", where)
		}
		w.tools = map[string]map[requesterRef]bool{}
		for _, tool := range tools.names {
			if tool == "" {
				return nil, fmt.Errorf("engine configuration: %s.tools names a tool by the empty string", where)
			}
			raw, _ := tools.get(tool)
			list, err := parseRequesterList(raw, where+".tools."+requestText(tool), issuer, delegation)
			if err != nil {
				return nil, err
			}
			w.tools[tool] = list
		}
	}
	return w, nil
}

// parseRequesterList reads one list: an array, possibly empty, of exactly
// {issuer, subject}, each a non-empty string, no requester named twice.
// A refusal names the entry by its place and never repeats its strings.
func parseRequesterList(v value, where, issuer string, delegation bool) (map[requesterRef]bool, error) {
	arr, ok := v.(vArray)
	if !ok {
		return nil, fmt.Errorf("engine configuration: %s must be an array of requesters, each {issuer, subject}", where)
	}
	list := make(map[requesterRef]bool, len(arr))
	for i, item := range arr {
		at := fmt.Sprintf("%s[%d]", where, i)
		obj, ok := item.(*vObject)
		if !ok {
			return nil, fmt.Errorf("engine configuration: %s must be an object of issuer and subject", at)
		}
		if err := exactlyMembers(obj, map[string]bool{"issuer": true, "subject": true}, "engine configuration: "+at); err != nil {
			return nil, err
		}
		entry := requesterRef{}
		for _, m := range []struct {
			name string
			into *string
		}{{"issuer", &entry.issuer}, {"subject", &entry.subject}} {
			s, ok := memberString(obj, m.name)
			if !ok || s == "" {
				return nil, fmt.Errorf("engine configuration: %s: %s must be a non-empty string", at, m.name)
			}
			*m.into = s
		}
		if !delegation && entry.issuer != issuer {
			return nil, fmt.Errorf("engine configuration: %s: issuer is not identity.issuer, and with no delegation configured every requester is of identity.issuer", at)
		}
		if list[entry] {
			return nil, fmt.Errorf("engine configuration: %s names a requester an earlier entry of the list names", at)
		}
		list[entry] = true
	}
	return list, nil
}

// requestersMatch holds a platform's writeRequesters to its binding: each
// tool it gives a list names a tool the binding's write operation names,
// since a list for a tool no write can reach would read as a restriction on
// nothing.
func requestersMatch(p platformConfig, b binding) error {
	if p.requesters == nil {
		return nil
	}
	tools := make([]string, 0, len(p.requesters.tools))
	for tool := range p.requesters.tools {
		tools = append(tools, tool)
	}
	sort.Strings(tools)
	for _, tool := range tools {
		if b.write == nil {
			return fmt.Errorf("writeRequesters names tool %q, and binding %s states no write operation", requestText(tool), p.binding)
		}
		if !contains(b.write.tools, tool) {
			return fmt.Errorf("writeRequesters names tool %q, which the binding's write operation does not name", requestText(tool))
		}
	}
	return nil
}

// writeRequestersLines is the posture line of a configuration that gives
// some platform writeRequesters, none for one that gives none: how many of
// the write tools the sources offer are held to a list, a count and never a
// requester.
func writeRequestersLines(sources map[string]sourceSpec) []postureLine {
	held, total, given := 0, 0, false
	for name, spec := range sources {
		if !strings.HasSuffix(name, "/write") {
			continue
		}
		given = given || spec.requesters != nil
		for _, tool := range spec.tools {
			total++
			if spec.requesters.listFor(tool) != nil {
				held++
			}
		}
	}
	if !given {
		return nil
	}
	admit := func(n int) string {
		if n == 1 {
			return "admits"
		}
		return "admit"
	}
	if held == total {
		if total == 1 {
			return []postureLine{{protectionWriteRequesters, postureEnforced,
				"the 1 write tool admits a write only from a requester its writeRequesters list names"}}
		}
		return []postureLine{{protectionWriteRequesters, postureEnforced,
			fmt.Sprintf("each of the %d write tools admits a write only from a requester its writeRequesters list names", total)}}
	}
	return []postureLine{{protectionWriteRequesters, postureNotEnforced,
		fmt.Sprintf("%d of the %d write tools %s a write only from a requester a writeRequesters list names; the other %d %s any requester the identity or a delegation authenticates", held, total, admit(held), total-held, admit(total-held))}}
}
