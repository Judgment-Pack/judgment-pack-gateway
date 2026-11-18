package main

// Grants through groups on a gcp-asset source (engineVersion 30, gateway
// #496, docs/adr/0039-a-read-only-asset-inventory-connection-for-configuration-drift.md,
// Amendment (gateway #496), G2 to G7): the operation's optional `groups`,
// by which adapter-gcp-asset resolves each group a binding of a role
// outside the read-only list names, with a third token of the
// cloud-identity.groups.readonly scope, to a depth and within bounds. A
// principal found refuses the page credential-bound-at-resource and closes
// the source, as a direct binding does, by status 9 and its report
// (gcp_asset_binding.go). What the signer adds here is the reading of
// what is left: every acquisition of a source that resolves groups
// answers its envelope beside how many groups it left unresolved and the
// last one's reason, and under unresolved "refuse" a page with a group
// unresolved exits 1 with that report, failing the acquisition without
// closing the source. A source that left any group unresolved since the
// start reports groupBindings "unchecked" on /posture until it restarts,
// and the read-only-credentials line is partial while one does. Nothing a
// report names is a group, a member or the platform's text: the reason is
// one of a closed list, and anything else fails the acquisition.

import (
	"fmt"
	"strings"
)

const (
	// gcpAssetGroupsVersion is the engine configuration version that
	// admits the member.
	gcpAssetGroupsVersion = "30"
	// The opt-in's settings and their ranges (G2, G4), the adapter's
	// (adapters/gcpasset, DefaultGroupDepth and the rest).
	defaultGCPAssetGroupDepth   = 2
	maxGCPAssetGroupDepth       = 4
	defaultGCPAssetGroupMembers = 5000
	maxGCPAssetGroupMembers     = 50000
	maxGCPAssetGroupsRead       = 64
	gcpAssetUnresolvedServe     = "serve"
	gcpAssetUnresolvedRefuse    = "refuse"
	// refusalGroupUnresolved is the refusal of a page with a group
	// unresolved under "refuse" (adapters/gcpasset, ReasonGroupUnresolved),
	// reported beside status 1, never 9.
	refusalGroupUnresolved = "group-unresolved"
	// maxGroupReport bounds the report the signer reads beside status 1;
	// maxGroupsUnresolved the count either report gives.
	maxGroupReport      = 256
	maxGroupsUnresolved = 1 << 20
)

// The groupBindings of a gcp-asset source on /posture (G6).
const (
	groupBindingsOff       = "off"
	groupBindingsChecked   = "checked"
	groupBindingsUnchecked = "unchecked"
)

// gcpAssetGroupReasons are the reasons a group is left unresolved (G5;
// adapters/gcpasset, GroupReasons): the only text of a group's that leaves
// the adapter.
var gcpAssetGroupReasons = []string{"unreadable", "unavailable", "malformed", "member-type", "depth", "members", "groups", "time", "no-token"}

// gcpAssetGroups is the opt-in as the binding fixes it; a binding that
// does not opt in, or sets resolve false, has none.
type gcpAssetGroups struct {
	depth, members int
	unresolved     string
}

var gcpAssetGroupsMembers = map[string]bool{"resolve": true, "depth": false, "members": false, "unresolved": false}

// parseGCPAssetGroups holds an operation's groups to its form: an object
// of resolve, a boolean, and optionally depth, an integer from 0 to 4
// (default 2), members, from 1 to 50000 (default 5000), and unresolved,
// "serve" (the default) or "refuse". Each setting is held to its range
// whether resolve is true or false; with resolve false the source is as
// one without the member. A refusal names the member and repeats no
// value.
func parseGCPAssetGroups(v value, name string) (*gcpAssetGroups, error) {
	where := "operation " + name + ": groups"
	obj, ok := v.(*vObject)
	if !ok {
		return nil, fmt.Errorf("%s is an object, {\"resolve\": true} and its settings", where)
	}
	if err := exactlyMembers(obj, gcpAssetGroupsMembers, where); err != nil {
		return nil, err
	}
	raw, _ := obj.get("resolve")
	resolve, ok := raw.(vBool)
	if !ok {
		return nil, fmt.Errorf("%s: resolve is true or false", where)
	}
	g := &gcpAssetGroups{depth: defaultGCPAssetGroupDepth, members: defaultGCPAssetGroupMembers, unresolved: gcpAssetUnresolvedServe}
	integer := func(member string, least, most int, into *int) error {
		raw, present := obj.get(member)
		if !present {
			return nil
		}
		n, ok := raw.(vInt)
		if !ok || n < vInt(least) || n > vInt(most) {
			return fmt.Errorf("%s: %s is an integer from %d to %d", where, member, least, most)
		}
		*into = int(n)
		return nil
	}
	if err := integer("depth", 0, maxGCPAssetGroupDepth, &g.depth); err != nil {
		return nil, err
	}
	if err := integer("members", 1, maxGCPAssetGroupMembers, &g.members); err != nil {
		return nil, err
	}
	if _, present := obj.get("unresolved"); present {
		s, ok := memberString(obj, "unresolved")
		if !ok || (s != gcpAssetUnresolvedServe && s != gcpAssetUnresolvedRefuse) {
			return nil, fmt.Errorf("%s: unresolved is %q, which serves a page with a group unresolved and reports it, or %q, which refuses it", where, gcpAssetUnresolvedServe, gcpAssetUnresolvedRefuse)
		}
		g.unresolved = s
	}
	if !resolve {
		return nil, nil
	}
	return g, nil
}

// gcpAssetGroupsArgv are the adapter's flags for the opt-in, none where
// the source does not opt in.
func gcpAssetGroupsArgv(g *gcpAssetGroups) []string {
	if g == nil {
		return nil
	}
	return []string{"--groups-resolve", fmt.Sprintf("--groups-depth=%d", g.depth), fmt.Sprintf("--groups-members=%d", g.members), "--groups-unresolved=" + g.unresolved}
}

// groupReason is a reason the adapter reports, "" for one not among
// G5's.
func groupReason(v value) string {
	s, ok := v.(vString)
	if !ok {
		return ""
	}
	for _, reason := range gcpAssetGroupReasons {
		if string(s) == reason {
			return reason
		}
	}
	return ""
}

// gcpAssetGroupAnswer unwraps the answer of an acquisition whose source
// resolves groups: exactly {"envelope": E, "groupBindings": {"unresolved":
// N, "reason": R}}, N from 0 to its bound, and R null where N is 0 and one
// of G5's reasons otherwise. The envelope is then read as any envelope is.
// Anything else fails the acquisition: an answer that does not say whether
// its groups were resolved is not served.
func gcpAssetGroupAnswer(source string, result value) (value, int, string, error) {
	failed := fmt.Errorf("source %s failed: the adapter did not answer its envelope beside the report of the groups it resolved, and a page whose groups are not reported is not served", source)
	outer, ok := result.(*vObject)
	if !ok || exactlyMembers(outer, map[string]bool{"envelope": true, "groupBindings": true}, "answer") != nil {
		return nil, 0, "", failed
	}
	raw, _ := outer.get("groupBindings")
	report, ok := raw.(*vObject)
	if !ok || exactlyMembers(report, map[string]bool{"unresolved": true, "reason": true}, "group report") != nil {
		return nil, 0, "", failed
	}
	rawCount, _ := report.get("unresolved")
	count, ok := rawCount.(vInt)
	if !ok || count < 0 || count > maxGroupsUnresolved {
		return nil, 0, "", failed
	}
	rawReason, _ := report.get("reason")
	reason := groupReason(rawReason)
	_, isNull := rawReason.(vNull)
	if (count == 0) != isNull || (count > 0 && reason == "") {
		return nil, 0, "", failed
	}
	envelope, _ := outer.get("envelope")
	return envelope, int(count), reason, nil
}

// gcpAssetGroupRefused is a run of a source under unresolved "refuse"
// that exited 1 with its report: a page with a group unresolved, refused.
// The acquisition fails as a failed source does, and the source is not
// closed: only an answer of the platform that shows a grant closes one.
type gcpAssetGroupRefused struct {
	reason string
	groups int
	failed error
}

func (e *gcpAssetGroupRefused) Error() string {
	return fmt.Sprintf("source failed: %s: %s: %d groups a binding outside the read-only list names were not resolved, and this source refuses such a page; the source serves on, and the next acquisition resolves again",
		refusalGroupUnresolved, e.reason, e.groups)
}

func (e *gcpAssetGroupRefused) Unwrap() error { return e.failed }

// groupUnresolvedReport reads adapter-gcp-asset's stdout beside status 1
// under unresolved "refuse": exactly {"groupUnresolved": {"reason": R,
// "groups": N}}, R one of G5's reasons and N from 1 to its bound, the
// whole at most maxGroupReport bytes with nothing before or after it.
// Anything else is no report: the run failed as any other.
func groupUnresolvedReport(stdout []byte) (string, int, bool) {
	if len(stdout) == 0 || len(stdout) > maxGroupReport || isJSONSpace(stdout[0]) || isJSONSpace(stdout[len(stdout)-1]) {
		return "", 0, false
	}
	v, err := parseJSON(stdout)
	if err != nil {
		return "", 0, false
	}
	outer, ok := v.(*vObject)
	if !ok || exactlyMembers(outer, map[string]bool{"groupUnresolved": true}, "group report") != nil {
		return "", 0, false
	}
	raw, _ := outer.get("groupUnresolved")
	report, ok := raw.(*vObject)
	if !ok || exactlyMembers(report, map[string]bool{"reason": true, "groups": true}, "group report") != nil {
		return "", 0, false
	}
	rawReason, _ := report.get("reason")
	reason := groupReason(rawReason)
	rawCount, _ := report.get("groups")
	count, ok := rawCount.(vInt)
	if reason == "" || !ok || count < 1 || count > maxGroupsUnresolved {
		return "", 0, false
	}
	return reason, int(count), true
}

// noteGroups records an acquisition's groups left unresolved, served or
// refused: counted, and the last one's reason kept. A count never falls,
// so a source that left one unresolved is unchecked until it restarts.
func (s *gcpAssetSource) noteGroups(unresolved int, reason string) {
	if unresolved == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.groupsUnresolved = min(s.groupsUnresolved+unresolved, maxGroupsUnresolved)
	s.groupReason = reason
}

// groupBindings is the source's groupBindings (G6): "off" where it does
// not opt in; "unchecked" where it serves no IAM_POLICY, or where any
// group met since the start was left unresolved, with the count and the
// last reason; "checked" otherwise.
func (s *gcpAssetSource) groupBindings() (string, int, string) {
	if s.op.groups == nil {
		return groupBindingsOff, 0, ""
	}
	if !s.op.serves(gcpAssetContentIAMPolicy) {
		return groupBindingsUnchecked, 0, ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.groupsUnresolved > 0 {
		return groupBindingsUnchecked, s.groupsUnresolved, s.groupReason
	}
	return groupBindingsChecked, 0, ""
}

// gcpAssetGroupsStartLine is what the start says of a source that opts
// in: the third token and what its read-only property rests on, the
// bounds, the unresolved setting, the operator's part, and what stays
// outside (G2, G6, G7).
func gcpAssetGroupsStartLine(name string, s *gcpAssetSource) string {
	g := s.op.groups
	if !s.op.serves(gcpAssetContentIAMPolicy) {
		return fmt.Sprintf("source %s: group-bindings: unchecked: the platform serves no IAM_POLICY, so no group is resolved and no groups token is obtained", name)
	}
	unresolved := "a page with a group unresolved is served, and /posture reports the source's groupBindings unchecked until it restarts"
	if g.unresolved == gcpAssetUnresolvedRefuse {
		unresolved = "a page with a group unresolved is refused " + refusalGroupUnresolved + ", which fails the acquisition and does not close the source"
	}
	return strings.Join([]string{
		fmt.Sprintf("source %s: group-bindings: resolved, through a third token of scope cloud-identity.groups.readonly held to that scope", name),
		"for groups.lookup and groups.memberships.list alone, read-only by its scope since no write check covers the directory",
		fmt.Sprintf("to depth %d, at most %d memberships and %d groups an acquisition, in at most half its time and 10 s", g.depth, g.members, maxGCPAssetGroupsRead),
		unresolved,
		"the principal reads only the memberships the operator lets it view, which the gateway neither grants nor verifies",
		"outside: nesting past the depth, domain: members, principal sets and pools, groups it cannot read, deny policies, and a membership removed in the directory while IAM still holds its grant; a binding's condition is read as holding",
	}, "; ")
}
