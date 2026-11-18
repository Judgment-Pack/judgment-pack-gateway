package gcpasset

// What the result holds (decisions 4 and 5): each asset type served has an
// allow-list projection, and only the members it names are carried; an
// environment variable's value is never carried; IAM members are carried as
// written, or, under count-users, a binding's user members are replaced by
// their count. All of it is done here, before the envelope is written, so
// the gateway's resultDigest is of the projected page and the same for
// every caller of the source. The resource-binding check reads each
// IAM_POLICY page before it is projected, and keeps, where groups are
// resolved (groups.go), the groups each binding outside the read-only list
// names; they are resolved once the whole page is read.
//
// The answer is bounded before it is decoded: its size by MaxAnswer, its
// depth by maxNesting in one pass over the bytes, a member named twice by
// the canonical reading; the projection then visits each member once, so
// the work is linear in the answer.

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"adapters/internal/canon"
)

// node is one member's projection: keep carries the value as answered;
// obj projects an object; each projects every object of an array; env is a
// container's environment.
type node struct {
	keep bool
	obj  map[string]*node
	each map[string]*node
	env  bool
}

var keep = &node{keep: true}

func obj(members map[string]*node) *node  { return &node{obj: members} }
func each(members map[string]*node) *node { return &node{each: members} }

// leaves is an object projection carrying each named member as answered.
func leaves(names ...string) map[string]*node {
	out := map[string]*node{}
	for _, name := range names {
		out[name] = keep
	}
	return out
}

func with(base map[string]*node, name string, n *node) map[string]*node {
	base[name] = n
	return base
}

// container is a Cloud Run container: its name, its image and its
// environment's names and secret references.
var container = map[string]*node{"name": keep, "image": keep, "env": {env: true}}

// resourceProjections are the allow-lists of resource.data, by asset type.
// The adapter's README lists them. Cloud Run's is of both forms the
// platform has published a service in: the Admin API v1 (Knative) form and
// the v2 form; a member of neither is dropped.
var resourceProjections = map[string]map[string]*node{
	"run.googleapis.com/Service": with(with(with(map[string]*node{
		// v1
		"apiVersion": keep, "kind": keep,
		"metadata": obj(leaves("name", "namespace", "generation", "labels")),
		"spec": obj(map[string]*node{
			"template": obj(map[string]*node{
				"metadata": obj(leaves("name")),
				"spec":     obj(map[string]*node{"serviceAccountName": keep, "containers": each(container)}),
			}),
			"traffic": each(leaves("revisionName", "percent", "latestRevision", "tag")),
		}),
		// v2
		"name": keep, "uid": keep, "generation": keep, "labels": keep, "ingress": keep,
	}, "template", obj(map[string]*node{"revision": keep, "serviceAccount": keep, "containers": each(container)})),
		"traffic", each(leaves("type", "revision", "percent", "tag"))),
		"launchStage", keep),
	"secretmanager.googleapis.com/Secret":         leaves("name", "labels", "replication", "versionAliases", "createTime"),
	"secretmanager.googleapis.com/SecretVersion":  leaves("name", "state", "createTime", "destroyTime"),
	"iam.googleapis.com/ServiceAccount":           leaves("name", "email", "uniqueId", "disabled", "displayName"),
	"storage.googleapis.com/Bucket":               leaves("name", "location", "storageClass", "labels", "versioning", "iamConfiguration", "retentionPolicy"),
	"cloudresourcemanager.googleapis.com/Project": leaves("projectId", "projectNumber", "lifecycleState", "labels", "parent"),
}

// ServedAssetTypes are the asset types with a projection, sorted.
func ServedAssetTypes() []string {
	out := make([]string, 0, len(resourceProjections))
	for t := range resourceProjections {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// readOnlyRoles are the predefined roles a binding of the source's own
// principal may name on an IAM_POLICY page. A custom role is never on it,
// whatever its name: its name says nothing of what it grants. The
// adapter's README lists it.
var readOnlyRoles = map[string]bool{
	"roles/viewer":                          true,
	"roles/browser":                         true,
	"roles/iam.securityReviewer":            true,
	"roles/iam.roleViewer":                  true,
	"roles/cloudasset.viewer":               true,
	"roles/run.viewer":                      true,
	"roles/secretmanager.viewer":            true,
	"roles/storage.objectViewer":            true,
	"roles/storage.legacyBucketReader":      true,
	"roles/storage.legacyObjectReader":      true,
	"roles/logging.viewer":                  true,
	"roles/monitoring.viewer":               true,
	"roles/serviceusage.serviceUsageViewer": true,
	"roles/artifactregistry.reader":         true,
}

// ReadOnlyRoles is the read-only role list, sorted, for the README's test.
func ReadOnlyRoles() []string {
	out := make([]string, 0, len(readOnlyRoles))
	for r := range readOnlyRoles {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// projectedPage is the result: the page's assets, projected, its readTime,
// and its nextPageToken as written, or null on the last page. groups, never
// part of the result, are the groups to resolve, in the page's order.
type projectedPage struct {
	ReadTime      *string           `json:"readTime"`
	Assets        []json.RawMessage `json:"assets"`
	NextPageToken *string           `json:"nextPageToken"`
	groups        []groupRef
}

// within reports whether raw nests no deeper than limit containers, read
// in one pass that tracks strings and their escapes.
func within(raw []byte, limit int) bool {
	depth, inString, escaped := 0, false, false
	for _, c := range raw {
		switch {
		case inString:
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
		case c == '"':
			inString = true
		case c == '{' || c == '[':
			if depth++; depth > limit {
				return false
			}
		case c == '}' || c == ']':
			depth--
		}
	}
	return true
}

// Every upstream answer is read as objects by their members' exact names.
// encoding/json matches a struct's fields without regard to case, so an
// answer holding both "bindings" and "Bindings" would be read as whichever
// came last; a map is matched exactly, and the canonical reading has
// already refused a name given twice.

// object is raw as an object, or false: absent, null or another value.
func object(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var members map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &members) != nil || members == nil {
		return nil, false
	}
	return members, true
}

// array is raw as an array, or false: absent, null or another value.
func array(raw json.RawMessage) ([]json.RawMessage, bool) {
	var items []json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &items) != nil || items == nil {
		return nil, false
	}
	return items, true
}

// absent is a member not given, or given as null.
func absent(raw json.RawMessage) bool {
	return len(raw) == 0 || string(raw) == "null"
}

// optionalString is a member that is absent, null or a string.
func optionalString(raw json.RawMessage) (*string, bool) {
	if absent(raw) {
		return nil, true
	}
	var s string
	if !stringMember(raw, &s) {
		return nil, false
	}
	return &s, true
}

// projectPage reads the list call's answer and projects it: for an
// IAM_POLICY page, after the resource-binding check.
func (s *source) projectPage(body []byte, req Request, principal string) (*projectedPage, error) {
	if !within(body, maxNesting) {
		return nil, fmt.Errorf("the list call's answer nests deeper than %d levels", maxNesting)
	}
	canonical, err := canon.Canonicalize(body, canon.CarryNumbersAsText)
	if err != nil {
		return nil, errors.New("the list call's answer is not one JSON value in the canonical domain")
	}
	notAList := errors.New("the list call's answer is not a list of assets")
	answer, ok := object(canonical)
	if !ok {
		return nil, notAList
	}
	var assets []json.RawMessage
	if !absent(answer["assets"]) {
		if assets, ok = array(answer["assets"]); !ok {
			return nil, notAList
		}
	}
	readTime, okTime := optionalString(answer["readTime"])
	next, okNext := optionalString(answer["nextPageToken"])
	if !okTime || !okNext {
		return nil, notAList
	}
	page := &projectedPage{ReadTime: readTime, Assets: make([]json.RawMessage, 0, len(assets))}
	if next != nil && *next != "" {
		page.NextPageToken = next
	}
	own := ownPrincipals(principal)
	for i, raw := range assets {
		projected, groups, err := s.projectAsset(raw, req, own)
		if err != nil {
			var r *Refused
			if errors.As(err, &r) {
				return nil, err
			}
			return nil, fmt.Errorf("assets[%d] %v", i, err)
		}
		page.Assets = append(page.Assets, projected)
		page.groups = append(page.groups, groups...)
	}
	return page, nil
}

// binding is one binding of an allow policy, as this adapter reads it.
type binding struct {
	Role      string
	Members   []string
	Condition json.RawMessage
}

// policyOf reads an allow policy's bindings: each an object whose role is
// a string and whose members are an array of strings. Anything else is a
// malformed policy, which refuses the page rather than passing the
// resource-binding check by being unread.
func policyOf(raw json.RawMessage) (version json.RawMessage, bindings []binding, err error) {
	malformed := errors.New("has an IAM policy of a form this adapter does not read")
	policy, ok := object(raw)
	if !ok {
		return nil, nil, malformed
	}
	var items []json.RawMessage
	if !absent(policy["bindings"]) {
		if items, ok = array(policy["bindings"]); !ok {
			return nil, nil, malformed
		}
	}
	for _, item := range items {
		members, ok := object(item)
		var b binding
		if !ok || !stringMember(members["role"], &b.Role) {
			return nil, nil, malformed
		}
		if !absent(members["members"]) {
			list, ok := array(members["members"])
			if !ok {
				return nil, nil, malformed
			}
			for _, m := range list {
				var text string
				if !stringMember(m, &text) {
					return nil, nil, malformed
				}
				b.Members = append(b.Members, text)
			}
		}
		b.Condition = members["condition"]
		bindings = append(bindings, b)
	}
	return policy["version"], bindings, nil
}

// projectAsset is one asset, projected: its name, type and update time; for
// a RESOURCE page its resource's data by the type's projection, location
// and parent; for an IAM_POLICY page its policy's bindings, after the
// resource-binding check, with the groups to resolve its bindings name.
func (s *source) projectAsset(raw json.RawMessage, req Request, own []string) (json.RawMessage, []groupRef, error) {
	notAnAsset := errors.New("is not an asset of the form this adapter reads")
	a, ok := object(raw)
	var name, assetType string
	if !ok || !stringMember(a["name"], &name) || !stringMember(a["assetType"], &assetType) {
		return nil, nil, notAnAsset
	}
	if !contains(req.AssetTypes, assetType) {
		return nil, nil, errors.New("is of an asset type the request did not name")
	}
	var groups []groupRef
	out := map[string]any{"name": name, "assetType": assetType}
	if !absent(a["updateTime"]) {
		out["updateTime"] = a["updateTime"]
	}
	switch req.ContentType {
	case ContentResource:
		if !absent(a["resource"]) {
			r, ok := object(a["resource"])
			if !ok {
				return nil, nil, notAnAsset
			}
			resource := map[string]any{}
			if data := project(r["data"], &node{obj: resourceProjections[assetType]}); data != nil {
				resource["data"] = data
			}
			for _, member := range []string{"location", "parent"} {
				if !absent(r[member]) {
					resource[member] = r[member]
				}
			}
			out["resource"] = resource
		}
	case ContentIAMPolicy:
		if !absent(a["iamPolicy"]) {
			version, bindings, err := policyOf(a["iamPolicy"])
			if err != nil {
				return nil, nil, err
			}
			if groups, err = boundAtResource(name, bindings, own, s.cfg.resolvesGroups()); err != nil {
				return nil, nil, err
			}
			out["iamPolicy"] = s.projectPolicy(version, bindings)
		}
	}
	encoded, err := canon.EncodeJSON(out)
	return encoded, groups, err
}

// project carries raw through n: nil when raw is not of the form n reads,
// so a member of an unexpected form is dropped, never carried whole.
func project(raw json.RawMessage, n *node) any {
	if len(raw) == 0 {
		return nil
	}
	switch {
	case n.keep:
		return raw
	case n.env:
		return projectEnv(raw)
	case n.obj != nil:
		var members map[string]json.RawMessage
		if json.Unmarshal(raw, &members) != nil || members == nil {
			return nil
		}
		out := map[string]any{}
		for name, child := range n.obj {
			if v, present := members[name]; present {
				if projected := project(v, child); projected != nil {
					out[name] = projected
				}
			}
		}
		return out
	case n.each != nil:
		var items []json.RawMessage
		if json.Unmarshal(raw, &items) != nil {
			return nil
		}
		out := make([]any, 0, len(items))
		for _, item := range items {
			if projected := project(item, &node{obj: n.each}); projected != nil {
				out = append(out, projected)
			}
		}
		return out
	}
	return nil
}

// projectEnv is a container's environment: each variable's name, and for a
// variable that names a secret, the secret's name and version, in the form
// it was answered in (v1 valueFrom.secretKeyRef {name, key}; v2
// valueSource.secretKeyRef {secret, version}). A value is never carried,
// in any form. A reference of another form is dropped and the variable
// keeps its name alone; a variable whose name is not a string is dropped.
func projectEnv(raw json.RawMessage) any {
	items, ok := array(raw)
	if !ok {
		return nil
	}
	out := make([]any, 0, len(items))
	for _, item := range items {
		v, ok := object(item)
		var name string
		if !ok || !stringMember(v["name"], &name) {
			continue
		}
		entry := map[string]any{"name": name}
		if ref := secretRef(v["valueFrom"], "name", "key"); ref != nil {
			entry["valueFrom"] = map[string]any{"secretKeyRef": ref}
		}
		if ref := secretRef(v["valueSource"], "secret", "version"); ref != nil {
			entry["valueSource"] = map[string]any{"secretKeyRef": ref}
		}
		out = append(out, entry)
	}
	return out
}

// secretRef is raw's secretKeyRef, its two named members, each a string;
// nil when raw holds none of that form.
func secretRef(raw json.RawMessage, first, second string) map[string]any {
	holder, ok := object(raw)
	if !ok {
		return nil
	}
	ref, ok := object(holder["secretKeyRef"])
	if !ok {
		return nil
	}
	out := map[string]any{}
	for _, name := range []string{first, second} {
		if absent(ref[name]) {
			continue
		}
		var text string
		if !stringMember(ref[name], &text) {
			return nil
		}
		out[name] = text
	}
	return out
}

// projectPolicy is a policy's bindings, each its role, its members as
// written and its condition's title and expression; under count-users, a
// binding's user members are replaced by their count, users.
func (s *source) projectPolicy(version json.RawMessage, bindings []binding) map[string]any {
	out := make([]any, 0, len(bindings))
	for _, b := range bindings {
		entry := map[string]any{"role": b.Role}
		members := append([]string{}, b.Members...)
		if s.cfg.Members == MembersCountUsers {
			kept := members[:0]
			users := 0
			for _, m := range members {
				if isUser(m) {
					users++
					continue
				}
				kept = append(kept, m)
			}
			members = kept
			entry["users"] = users
		}
		entry["members"] = members
		if condition := project(b.Condition, obj(leaves("title", "expression"))); condition != nil {
			entry["condition"] = condition
		}
		out = append(out, entry)
	}
	policy := map[string]any{"bindings": out}
	if len(version) > 0 {
		policy["version"] = version
	}
	return policy
}

// isUser is whether a member names a user: user:, and a deleted user's
// deleted:user:, so that count-users leaves no user identity in the result.
func isUser(member string) bool {
	return strings.HasPrefix(member, "user:") || strings.HasPrefix(member, "deleted:user:")
}

// ownPrincipals are the member forms the source's own principal is bound
// by: the service account, as an allow policy names it and in the
// principal identifier form.
func ownPrincipals(email string) []string {
	if email == "" {
		return nil
	}
	return []string{"serviceaccount:" + strings.ToLower(email), "principal://iam.googleapis.com/projects/-/serviceaccounts/" + strings.ToLower(email)}
}

// publicMembers are the members that grant every caller, the source's own
// principal among them, as an allow policy names them, lower-cased: a role
// granted to either is one the credential holds there.
var publicMembers = []string{"allusers", "allauthenticatedusers"}

// boundAtResource refuses a binding of the source's own principal, or of
// allUsers or allAuthenticatedUsers, to a role outside the read-only list,
// naming the asset. Members are compared without regard to case, so a
// spelling does not slip a binding past. Where groups are resolved, it
// returns the group members of those bindings, lower-cased, for
// resolveGroups (groups.go); a binding of a read-only role is never
// resolved. A domain or a principal set is not resolved at all, and the
// README says so; a condition on a binding is read as holding, so a
// condition never hides a grant.
func boundAtResource(assetName string, bindings []binding, own []string, groups bool) ([]groupRef, error) {
	var refs []groupRef
	for _, b := range bindings {
		if readOnlyRoles[b.Role] {
			continue
		}
		for _, m := range b.Members {
			member := strings.ToLower(m)
			if contains(own, member) || contains(publicMembers, member) {
				return nil, refused(ReasonBoundAtResource, assetName)
			}
			if groups && groupMember(member) {
				refs = append(refs, groupRef{asset: assetName, member: member})
			}
		}
	}
	return refs, nil
}
