package gcpasset

// Grants through groups (ADR-0039, Amendment (gateway #496), G1 to G9):
// opt-in, and bounded. On an IAM_POLICY page, every group: member of a
// binding whose role is outside the read-only list is resolved downward
// from the group the binding names -- groups.lookup for its resource name,
// then groups.memberships.list in the FULL view, page by page, and each
// nested group in turn, breadth first, to the configured depth -- with a
// third token, of the cloud-identity.groups.readonly scope alone, for
// those two calls and nothing else.
//
// The check may say "not a member" only on an answer that shows it: a
// group is resolved only when every page of it, and of every nested group
// to the depth, was read and no nested group is left beyond it. Anything
// else leaves the group unresolved, with one reason of G5, and an
// unresolved group never counts as "not found". The only outcome that
// asserts something of the principal is "found", which refuses the page
// credential-bound-at-resource as a direct binding does.
//
// Members read are compared and dropped: none is put in a result, a
// report, a diagnostic or an error, and no count of a group's members is
// reported. What was read is held in this process's memory for the one
// acquisition and gone when it exits. No error carries the platform's
// text, which can name a group.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"adapters/internal/canon"
)

// GroupsScope is the one scope the groups token is requested with: it
// reads the directory's groups and their memberships, and its API refuses
// every write.
const GroupsScope = "https://www.googleapis.com/auth/cloud-identity.groups.readonly"

// The settings of the opt-in (G2, G4).
const (
	DefaultGroupDepth   = 2
	MaxGroupDepth       = 4
	DefaultGroupMembers = 5000
	MaxGroupMembers     = 50000
	// UnresolvedServe serves a page with a group unresolved and reports it;
	// UnresolvedRefuse refuses the page group-unresolved.
	UnresolvedServe  = "serve"
	UnresolvedRefuse = "refuse"
	// MaxGroupsRead is the most groups read for one acquisition, each
	// counted once; maxGroupTime the longest the read may take.
	MaxGroupsRead = 64
	maxGroupTime  = 10 * time.Second
	// membershipPageSize is the platform's bound on a FULL page.
	membershipPageSize = 500
	// maxGroupAnswer bounds one lookup's or one memberships page's answer.
	maxGroupAnswer = 4 << 20
	// maxMemberKey and maxGroupPageToken bound what a page names.
	maxMemberKey      = 512
	maxGroupPageToken = 8192
)

// The reasons a group is left unresolved (G5). A refusal, a report and a
// diagnostic name the reason alone.
const (
	GroupUnreadable  = "unreadable"
	GroupUnavailable = "unavailable"
	GroupMalformed   = "malformed"
	GroupMemberType  = "member-type"
	GroupDepth       = "depth"
	GroupMembers     = "members"
	GroupGroups      = "groups"
	GroupTime        = "time"
	GroupNoToken     = "no-token"
)

// GroupReasons are every reason, in G5's order.
var GroupReasons = []string{GroupUnreadable, GroupUnavailable, GroupMalformed, GroupMemberType, GroupDepth, GroupMembers, GroupGroups, GroupTime, GroupNoToken}

// ReasonGroupUnresolved is the refusal of a page with a group unresolved
// under unresolved "refuse": the command exits 1, never 9, and the source
// is not closed.
const ReasonGroupUnresolved = "group-unresolved"

// Groups is the opt-in: off unless Resolve.
type Groups struct {
	Resolve bool
	// Depth is the nested levels read below a group a binding names, 0 to
	// MaxGroupDepth; Members the memberships read for one acquisition, 1
	// to MaxGroupMembers; Unresolved UnresolvedServe or UnresolvedRefuse.
	Depth, Members int
	Unresolved     string
}

// groupsProblem holds the opt-in's settings to their ranges.
func groupsProblem(g Groups) error {
	if !g.Resolve {
		return nil
	}
	if g.Depth < 0 || g.Depth > MaxGroupDepth {
		return fmt.Errorf("--groups-depth must be from 0 to %d", MaxGroupDepth)
	}
	if g.Members < 1 || g.Members > MaxGroupMembers {
		return fmt.Errorf("--groups-members must be from 1 to %d", MaxGroupMembers)
	}
	if g.Unresolved != UnresolvedServe && g.Unresolved != UnresolvedRefuse {
		return fmt.Errorf("--groups-unresolved is %q or %q", UnresolvedServe, UnresolvedRefuse)
	}
	return nil
}

// resolvesGroups is whether an IAM_POLICY page's groups are resolved, so
// whether the groups token is obtained at all.
func (cfg Config) resolvesGroups() bool {
	return cfg.Groups.Resolve && contains(cfg.ContentTypes, ContentIAMPolicy)
}

// GroupUnresolved is a page refused under unresolved "refuse": Reason is
// the last group's, Groups how many were unresolved. The command exits 1
// with Report on stdout.
type GroupUnresolved struct {
	Reason string
	Groups int
}

func (e *GroupUnresolved) Error() string { return ReasonGroupUnresolved + ": " + e.Reason }

// Report is {"groupUnresolved": {"reason": R, "groups": N}}.
func (e *GroupUnresolved) Report() []byte {
	out, _ := canon.EncodeJSON(map[string]any{"groupUnresolved": map[string]any{"reason": e.Reason, "groups": e.Groups}})
	return out
}

// groupReport is what an acquisition that resolves groups answers beside
// its envelope: how many groups were unresolved, and the last one's
// reason, null where none was.
type groupReport struct {
	Unresolved int     `json:"unresolved"`
	Reason     *string `json:"reason"`
}

// withGroupReport is an acquisition's answer where groups are resolved:
// {"envelope": E, "groupBindings": {"unresolved": N, "reason": R | null}}.
func withGroupReport(envelope []byte, report groupReport) ([]byte, error) {
	return canon.EncodeJSON(struct {
		Envelope      json.RawMessage `json:"envelope"`
		GroupBindings groupReport     `json:"groupBindings"`
	}{Envelope: envelope, GroupBindings: report})
}

// groupRef is a group a binding of a role outside the read-only list
// names: the asset it is on, and the member as the binding wrote it,
// lower-cased.
type groupRef struct {
	asset, member string
}

// groupMember is whether a binding's member, lower-cased, stands for a
// group this check resolves: group:<email>, or a deleted group, which is
// never resolved.
func groupMember(member string) bool {
	return strings.HasPrefix(member, "group:") || strings.HasPrefix(member, "deleted:group:")
}

// groupOutcome is a page's groups resolved: the asset a found principal
// is bound at, or how many groups are unresolved and the last reason.
type groupOutcome struct {
	foundAt    string
	unresolved int
	reason     string
}

// child is a nested member that is not a leaf: its key, lower-cased, and
// whether its type was GROUP (a 404 on its lookup is then unreadable; for
// a member of another type, or none, it shows the member is no group).
type child struct {
	key   string
	group bool
}

// lookedUp is one groups.lookup: the resource name, or notFound, or the
// reason the lookup left the group unresolved.
type lookedUp struct {
	name     string
	notFound bool
	reason   string
}

// listed is one group's memberships read: whether the principal is a
// direct member, the nested members to read, and the reason the read left
// the group unresolved, "" when every page was read.
type listed struct {
	found    bool
	children []child
	reason   string
}

// resolver is one acquisition's resolution: its own time, the groups
// token, the principal's bare email lower-cased, the bounds, and what was
// read, each group once.
type resolver struct {
	s         *source
	ctx       context.Context
	token     string
	principal string
	depth     int
	members   int
	lookups   map[string]*lookedUp
	lists     map[string]*listed
	read      int
	looked    int
	// stopped is the bound that stopped the read, "" while it reads.
	stopped string
}

// groupTime is the time the read may take: half of what the run's time
// leaves, at most maxGroupTime.
func groupTime(ctx context.Context) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		return min(time.Until(deadline)/2, maxGroupTime)
	}
	return maxGroupTime
}

// resolveGroups resolves every group refs names, in the page's order,
// each once. A group in which the principal is found refuses, naming the
// first asset whose binding names it; failing that, the outcome counts
// the groups unresolved, and the last one's reason. Without a groups
// token every group is unresolved, no-token, and nothing is asked.
func (s *source) resolveGroups(ctx context.Context, token, principal string, refs []groupRef) groupOutcome {
	var out groupOutcome
	if len(refs) == 0 {
		return out
	}
	walk, cancel := context.WithTimeout(ctx, groupTime(ctx))
	defer cancel()
	r := &resolver{s: s, ctx: walk, token: token, principal: strings.ToLower(principal), depth: s.cfg.Groups.Depth,
		members: s.cfg.Groups.Members, lookups: map[string]*lookedUp{}, lists: map[string]*listed{}}
	done := map[string]bool{}
	for _, ref := range refs {
		if done[ref.member] {
			continue
		}
		done[ref.member] = true
		var found bool
		var reason string
		switch email, isGroup := strings.CutPrefix(ref.member, "group:"); {
		case !isGroup:
			reason = GroupUnreadable
		case token == "":
			reason = GroupNoToken
		case email == "" || len(email) > maxMemberKey || !emailForm.MatchString(email):
			reason = GroupMalformed
		default:
			found, reason = r.resolve(email)
		}
		if found {
			return groupOutcome{foundAt: ref.asset}
		}
		if reason != "" {
			out.unresolved++
			out.reason = reason
		}
	}
	return out
}

// resolve is one group a binding names, read breadth first to the depth:
// found where the principal is a direct member of it or of a nested group
// read; otherwise the first reason met, "" where every group to the depth
// was read whole and none is left beyond it. A group met again in this
// walk is skipped, not unresolved.
func (r *resolver) resolve(key string) (bool, string) {
	type queued struct {
		c     child
		level int
	}
	reason := ""
	note := func(why string) {
		if reason == "" {
			reason = why
		}
	}
	visited, names := map[string]bool{key: true}, map[string]bool{}
	queue := []queued{{child{key: key, group: true}, 0}}
	for len(queue) > 0 {
		q := queue[0]
		queue = queue[1:]
		lu := r.lookup(q.c.key)
		switch {
		case lu.reason != "":
			note(lu.reason)
			continue
		case lu.notFound && q.c.group:
			note(GroupUnreadable)
			continue
		case lu.notFound:
			note(GroupMemberType)
			continue
		case names[lu.name]:
			continue
		}
		names[lu.name] = true
		g := r.list(lu.name)
		if g.found {
			return true, ""
		}
		if g.reason != "" {
			note(g.reason)
		}
		for _, c := range g.children {
			if visited[c.key] {
				continue
			}
			visited[c.key] = true
			if q.level < r.depth {
				queue = append(queue, queued{c, q.level + 1})
				continue
			}
			// Beyond the depth: a group's members would need reading. A
			// member of another type, or none, is looked up all the same,
			// since it is never a leaf: one that is no group leaves its
			// parent unresolved for its type.
			if c.group {
				note(GroupDepth)
				continue
			}
			switch lu := r.lookup(c.key); {
			case lu.reason != "":
				note(lu.reason)
			case lu.notFound:
				note(GroupMemberType)
			default:
				note(GroupDepth)
			}
		}
	}
	return false, reason
}

// groupName is a group's resource name as groups.lookup answers it.
var groupName = regexp.MustCompile(`^groups/[A-Za-z0-9._~-]{1,128}$`)

// lookup is groups.lookup of a member's key, once per acquisition, each
// counted against MaxGroupsRead.
func (r *resolver) lookup(key string) *lookedUp {
	if lu, ok := r.lookups[key]; ok {
		return lu
	}
	lu := &lookedUp{}
	r.lookups[key] = lu
	if r.stopped != "" {
		lu.reason = r.stopped
		return lu
	}
	if r.looked >= MaxGroupsRead {
		r.stopped = GroupGroups
		lu.reason = r.stopped
		return lu
	}
	r.looked++
	q := url.Values{}
	q.Set("groupKey.id", key)
	status, raw, why := r.get(endpoints.Identity + "/v1/groups:lookup?" + q.Encode())
	switch {
	case why != "":
		lu.reason = why
	case status == http.StatusNotFound:
		lu.notFound = true
	case status != http.StatusOK:
		lu.reason = statusReason(status)
	default:
		answer, ok := object(raw)
		if !ok || !stringMember(answer["name"], &lu.name) || !groupName.MatchString(lu.name) {
			lu.name, lu.reason = "", GroupMalformed
		}
	}
	return lu
}

// list reads one group's memberships, every page, once per acquisition:
// the principal found among its users and service accounts, its nested
// members kept to read, and any page not read, any member out of form,
// leaves it unresolved. The read of a group stops where the principal is
// found, and where it is first left unresolved.
func (r *resolver) list(name string) *listed {
	if g, ok := r.lists[name]; ok {
		return g
	}
	g := &listed{}
	r.lists[name] = g
	seen := map[string]bool{}
	token := ""
	for {
		if r.stopped != "" {
			g.reason = r.stopped
			return g
		}
		if r.read >= r.members {
			r.stopped = GroupMembers
			g.reason = r.stopped
			return g
		}
		q := url.Values{}
		q.Set("view", "FULL")
		q.Set("pageSize", strconv.Itoa(min(membershipPageSize, r.members-r.read)))
		if token != "" {
			q.Set("pageToken", token)
		}
		status, raw, why := r.get(endpoints.Identity + "/v1/" + name + "/memberships?" + q.Encode())
		switch {
		case why != "":
			g.reason = why
			return g
		case status == http.StatusNotFound:
			g.reason = GroupUnreadable
			return g
		case status != http.StatusOK:
			g.reason = statusReason(status)
			return g
		}
		next, why := r.page(raw, g)
		if g.found {
			return g
		}
		if why != "" {
			g.reason = why
			return g
		}
		if next == "" {
			return g
		}
		if next == token || seen[next] {
			g.reason = GroupMalformed
			return g
		}
		seen[next] = true
		token = next
	}
}

// page reads one memberships page into g: each member compared or kept to
// read, the count of memberships read raised, and the next page token, ""
// on the last page; the reason it leaves the group unresolved, "" where
// none. Every member is compared before any reason is taken, so a
// principal on a page out of form is found all the same.
func (r *resolver) page(raw []byte, g *listed) (string, string) {
	answer, ok := object(raw)
	if !ok {
		return "", GroupMalformed
	}
	var items []json.RawMessage
	if !absent(answer["memberships"]) {
		if items, ok = array(answer["memberships"]); !ok {
			return "", GroupMalformed
		}
	}
	next, ok := optionalString(answer["nextPageToken"])
	if !ok || (next != nil && (len(*next) > maxGroupPageToken || !printable(*next))) {
		return "", GroupMalformed
	}
	why := ""
	note := func(reason string) {
		if why == "" {
			why = reason
		}
	}
	for _, item := range items {
		m, ok := object(item)
		key, okKey := object(m["preferredMemberKey"])
		var id string
		if !ok || !okKey || !stringMember(key["id"], &id) || id == "" || len(id) > maxMemberKey || !printable(id) {
			note(GroupMalformed)
			continue
		}
		// A key with a namespace is an external identity's: it never
		// matches, and the group is not resolved.
		if !absent(key["namespace"]) {
			note(GroupMalformed)
			continue
		}
		id = strings.ToLower(id)
		kind, ok := optionalString(m["type"])
		if !ok {
			note(GroupMalformed)
			continue
		}
		switch {
		case kind != nil && (*kind == "USER" || *kind == "SERVICE_ACCOUNT"):
			if id == r.principal {
				g.found = true
				return "", ""
			}
		case kind != nil && *kind == "GROUP":
			g.children = append(g.children, child{key: id, group: true})
		default:
			// Any other type, or none, is never a leaf: it is looked up as
			// a group.
			g.children = append(g.children, child{key: id})
		}
	}
	r.read += len(items)
	if r.read > r.members {
		r.stopped = GroupMembers
		note(GroupMembers)
	}
	if why != "" {
		return "", why
	}
	if next == nil {
		return "", ""
	}
	return *next, ""
}

// statusReason is a status other than 200 and 404: throttled or
// unavailable, unavailable; a refusal of the read, unreadable; anything
// else, an answer out of form.
func statusReason(status int) string {
	switch {
	case status == http.StatusTooManyRequests || status >= 500:
		return GroupUnavailable
	case status >= 400:
		return GroupUnreadable
	}
	return GroupMalformed
}

// get is one call with the groups token: its status and, for a 200, its
// answer, JSON in the canonical domain within maxGroupAnswer; or the
// reason it brought back nothing to read. Nothing of the platform's
// answer but its status is ever read from a refusal, and nothing of any
// answer leaves this file. Nothing is retried.
func (r *resolver) get(target string) (int, []byte, string) {
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, nil, GroupMalformed
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "judgment-pack-"+adapterName+"/"+Version)
	resp, err := r.s.api.Do(req)
	if err != nil {
		switch {
		case r.ctx.Err() != nil:
			r.stopped = GroupTime
			return 0, nil, GroupTime
		case errors.Is(err, errRedirect):
			return 0, nil, GroupMalformed
		}
		return 0, nil, GroupUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil, ""
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxGroupAnswer+1))
	switch {
	case err != nil && r.ctx.Err() != nil:
		r.stopped = GroupTime
		return 0, nil, GroupTime
	case err != nil:
		return 0, nil, GroupUnavailable
	case len(raw) > maxGroupAnswer:
		return 0, nil, GroupMalformed
	}
	if mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mediaType != "application/json" {
		return 0, nil, GroupMalformed
	}
	if !within(raw, maxNesting) {
		return 0, nil, GroupMalformed
	}
	canonical, err := canon.Canonicalize(raw, canon.CarryNumbersAsText)
	if err != nil {
		return 0, nil, GroupMalformed
	}
	return http.StatusOK, canonical, ""
}
