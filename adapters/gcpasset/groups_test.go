package gcpasset

// Grants through groups (the Amendment for gateway #496, G8): every
// directory here is the in-process stand-in's, hand-written; every group,
// member and domain is synthetic, under example.invalid.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	groupAsset = "//run.googleapis.com/projects/example-project-1/locations/europe-west1/services/orders"
	otherAsset = "//storage.googleapis.com/example-bucket"
	opsGroup   = "ops@example.invalid"
	teamGroup  = "team@example.invalid"
	deepGroup  = "deep@example.invalid"
	someone    = "someone@example.invalid"
)

// bind is one binding's JSON: its role and its members.
func bind(role string, members ...string) string {
	return `{"role":"` + role + `","members":` + mustJSON(members) + `}`
}

// groupPolicy is an IAM_POLICY page of one asset holding the bindings.
func groupPolicy(bindings ...string) string {
	return `{"assets":[{"name":"` + groupAsset + `","assetType":"run.googleapis.com/Service","iamPolicy":{"bindings":[` + strings.Join(bindings, ",") + `]}}]}`
}

// groupsConfig is the fake's configuration, resolving groups with the
// settings given.
func groupsConfig(t *testing.T, f *fake, depth, members int, unresolved string) Config {
	cfg := f.config(t)
	cfg.Groups = Groups{Resolve: true, Depth: depth, Members: members, Unresolved: unresolved}
	return cfg
}

func iamRequest() Request {
	req := resourceRequest()
	req.ContentType = ContentIAMPolicy
	return req
}

// groupAnswer is an acquisition's answer where groups are resolved: its
// group report and its envelope.
func groupAnswer(t *testing.T, out []byte) (groupReport, []byte) {
	t.Helper()
	var answer struct {
		Envelope      json.RawMessage `json:"envelope"`
		GroupBindings *struct {
			Unresolved *int    `json:"unresolved"`
			Reason     *string `json:"reason"`
		} `json:"groupBindings"`
	}
	if err := json.Unmarshal(out, &answer); err != nil || answer.Envelope == nil || answer.GroupBindings == nil || answer.GroupBindings.Unresolved == nil {
		t.Fatalf("not an envelope with its group report: %v\n%s", err, out)
	}
	return groupReport{Unresolved: *answer.GroupBindings.Unresolved, Reason: answer.GroupBindings.Reason}, answer.Envelope
}

// served is an acquisition that served its page: its group report.
func served(t *testing.T, f *fake, cfg Config) groupReport {
	t.Helper()
	out, err := Acquire(ctx, cfg, iamRequest())
	if err != nil {
		t.Fatalf("not served: %v", err)
	}
	report, _ := groupAnswer(t, out)
	return report
}

func reasonOf(r groupReport) string {
	if r.Reason == nil {
		return ""
	}
	return *r.Reason
}

// chain is a directory of nested groups, ops > team > deep > g3 > g4, the
// last one's members given: the principal found at depth n is a member of
// the group n levels below ops.
func chain(f *fake, n int, last ...string) {
	names := []string{opsGroup, teamGroup, deepGroup, "g3@example.invalid", "g4@example.invalid"}
	for i := 0; i < n; i++ {
		f.groups[names[i]] = []string{membership("USER", someone), membership("GROUP", names[i+1])}
	}
	f.groups[names[n]] = last
}

// A principal found refuses as a direct binding does, naming the asset:
// in the group itself and at each depth the configuration reads to, by
// its bare email in any case, as a user or a service account, through a
// conditional binding, and whatever another group left unresolved.
func TestAGroupHoldingThePrincipalRefuses(t *testing.T) {
	for depth := 0; depth <= MaxGroupDepth; depth++ {
		t.Run(fmt.Sprintf("found at depth %d", depth), func(t *testing.T) {
			f := newFake(t)
			chain(f, depth, membership("SERVICE_ACCOUNT", testEmail))
			f.page = func(*http.Request) (int, string) {
				return 200, groupPolicy(bind("roles/run.developer", "group:"+opsGroup))
			}
			_, err := Acquire(ctx, groupsConfig(t, f, depth, DefaultGroupMembers, UnresolvedServe), iamRequest())
			if r := refusal(t, err, ReasonBoundAtResource); r.Subject == nil || *r.Subject != groupAsset {
				t.Fatalf("names the asset: %v", err)
			}
		})
	}
	cases := []struct {
		name     string
		setup    func(*fake)
		bindings []string
	}{
		{"a user, its key in another case", func(f *fake) {
			f.groups[opsGroup] = []string{membership("USER", someone), membership("USER", strings.ToUpper(testEmail))}
		}, []string{bind("roles/owner", "group:"+opsGroup)}},
		{"the group named in another case", func(f *fake) {
			f.groups[opsGroup] = []string{membership("SERVICE_ACCOUNT", testEmail)}
		}, []string{bind("roles/owner", "Group:OPS@Example.Invalid")}},
		{"a conditional binding, read as holding", func(f *fake) {
			f.groups[opsGroup] = []string{membership("SERVICE_ACCOUNT", testEmail)}
		}, []string{`{"role":"roles/run.developer","members":["group:` + opsGroup + `"],"condition":{"title":"never","expression":"false"}}`}},
		{"after a group left unresolved", func(f *fake) {
			f.groups[teamGroup] = []string{membership("SERVICE_ACCOUNT", testEmail)}
			f.identity = func(r *http.Request) (int, string, bool) {
				return 403, `{}`, strings.HasSuffix(r.URL.Path, groupID(opsGroup)+"/memberships")
			}
			f.groups[opsGroup] = nil
		}, []string{bind("roles/owner", "group:"+opsGroup), bind("roles/editor", "group:"+teamGroup)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(t)
			c.setup(f)
			f.page = func(*http.Request) (int, string) { return 200, groupPolicy(c.bindings...) }
			_, err := Acquire(ctx, groupsConfig(t, f, DefaultGroupDepth, DefaultGroupMembers, UnresolvedServe), iamRequest())
			refusal(t, err, ReasonBoundAtResource)
		})
	}
	// The first asset whose binding names the group is the one named.
	f := newFake(t)
	f.groups[opsGroup] = []string{membership("USER", testEmail)}
	f.page = func(*http.Request) (int, string) {
		return 200, `{"assets":[{"name":"` + otherAsset + `","assetType":"storage.googleapis.com/Bucket","iamPolicy":{"bindings":[` + bind("roles/storage.admin", "group:"+opsGroup) + `]}},` +
			`{"name":"` + groupAsset + `","assetType":"run.googleapis.com/Service","iamPolicy":{"bindings":[` + bind("roles/run.admin", "group:"+opsGroup) + `]}}]}`
	}
	_, err := Acquire(ctx, groupsConfig(t, f, DefaultGroupDepth, DefaultGroupMembers, UnresolvedServe), iamRequest())
	if r := refusal(t, err, ReasonBoundAtResource); *r.Subject != otherAsset {
		t.Fatalf("names the first asset: %v", err)
	}
}

// Not found after a complete read: every page of every group to the depth
// read in the FULL view with the groups token alone, the page served and
// reported with no group unresolved, and the projection unchanged.
func TestAGroupReadWholeWithoutThePrincipalIsResolved(t *testing.T) {
	f := newFake(t)
	f.groupPage = 2
	f.groups[opsGroup] = []string{membership("USER", someone), membership("GROUP", teamGroup), membership("USER", "b@example.invalid"),
		membership("SERVICE_ACCOUNT", "other-sa@example-project-1.iam.gserviceaccount.com"), membership("USER", "serviceAccount:"+testEmail)}
	f.groups[teamGroup] = []string{membership("USER", "c@example.invalid")}
	policy := groupPolicy(bind("roles/run.viewer", "serviceAccount:"+testEmail), bind("roles/run.developer", "group:"+opsGroup, "domain:example.invalid"))
	f.page = func(*http.Request) (int, string) { return 200, policy }
	out, err := Acquire(ctx, groupsConfig(t, f, 1, DefaultGroupMembers, UnresolvedServe), iamRequest())
	if err != nil {
		t.Fatal(err)
	}
	report, env := groupAnswer(t, out)
	if report.Unresolved != 0 || report.Reason != nil {
		t.Fatalf("resolved: %+v", report)
	}
	result, _ := resultOf(t, env)
	if !strings.Contains(result, `"group:`+opsGroup+`"`) || !strings.Contains(result, `"domain:example.invalid"`) {
		t.Fatalf("the projection carries the binding's members as written: %s", result)
	}
	for _, member := range []string{someone, "b@example.invalid", "c@example.invalid", teamGroup, groupID(opsGroup)} {
		if strings.Contains(string(out), member) {
			t.Fatalf("the answer carries what the directory answered: %s", member)
		}
	}
	calls := f.callsTo("/identity/")
	if len(calls) != 2+3+1 {
		t.Fatalf("two lookups and four pages: %+v", calls)
	}
	for _, c := range calls {
		if f.minted[c.token] != GroupsScope {
			t.Fatalf("a directory call without the groups token: %+v", c)
		}
		if strings.HasSuffix(c.path, "/memberships") && !strings.Contains(c.query, "view=FULL") {
			t.Fatalf("a page not in the FULL view: %+v", c)
		}
	}
	if !reflect.DeepEqual(f.scopes, []string{AssetScope, CheckScope, GroupsScope}) {
		t.Fatalf("the scopes requested: %q", f.scopes)
	}
	for _, c := range f.callsTo("/asset/") {
		if f.minted[c.token] != AssetScope {
			t.Fatal("the list call used another token")
		}
	}
}

// Every reason of G5, and every bound of G4, leaves the group unresolved:
// the page is served and the reason reported; a partial read is no read.
func TestEveryReasonLeavesTheGroupUnresolved(t *testing.T) {
	plain := []string{membership("USER", someone)}
	pageOf := func(path string) bool { return strings.HasSuffix(path, "/memberships") }
	cases := []struct {
		name, want string
		depth      int
		members    int
		setup      func(*testing.T, *fake)
		bindings   []string
	}{
		{"a read the platform refuses", GroupUnreadable, 2, 0, func(_ *testing.T, f *fake) {
			f.groups[opsGroup] = plain
			f.identity = func(r *http.Request) (int, string, bool) {
				return 403, `{"error":{"code":403,"message":"Permission denied on ` + opsGroup + `","status":"PERMISSION_DENIED"}}`, pageOf(r.URL.Path)
			}
		}, nil},
		{"a lookup's 404", GroupUnreadable, 2, 0, func(*testing.T, *fake) {}, nil},
		{"a nested group's lookup 404", GroupUnreadable, 2, 0, func(_ *testing.T, f *fake) {
			f.groups[opsGroup] = []string{membership("GROUP", "gone@example.invalid")}
		}, nil},
		{"a deleted group", GroupUnreadable, 2, 0, func(*testing.T, *fake) {}, []string{bind("roles/owner", "deleted:group:"+opsGroup+"?uid=123456789")}},
		{"throttled", GroupUnavailable, 2, 0, func(_ *testing.T, f *fake) {
			f.groups[opsGroup] = plain
			f.identity = func(r *http.Request) (int, string, bool) { return 429, `{}`, pageOf(r.URL.Path) }
		}, nil},
		{"unavailable", GroupUnavailable, 2, 0, func(_ *testing.T, f *fake) {
			f.identity = func(r *http.Request) (int, string, bool) { return 503, `{}`, true }
		}, nil},
		{"a connection that fails", GroupUnavailable, 2, 0, func(t *testing.T, f *fake) {
			closed := httptest.NewTLSServer(http.NotFoundHandler())
			closed.Close()
			endpoints.Identity = closed.URL
		}, nil},
		{"a page unread after one read", GroupUnavailable, 2, 0, func(_ *testing.T, f *fake) {
			f.groupPage = 1
			f.groups[opsGroup] = []string{membership("USER", someone), membership("USER", "b@example.invalid")}
			f.identity = func(r *http.Request) (int, string, bool) { return 503, `{}`, r.URL.Query().Get("pageToken") != "" }
		}, nil},
		{"a lookup out of form", GroupMalformed, 2, 0, func(_ *testing.T, f *fake) {
			f.identity = func(r *http.Request) (int, string, bool) { return 200, `{"name":"groups/../x"}`, !pageOf(r.URL.Path) }
		}, nil},
		{"a page out of form", GroupMalformed, 2, 0, func(_ *testing.T, f *fake) {
			f.groups[opsGroup] = plain
			f.identity = func(r *http.Request) (int, string, bool) { return 200, `{"memberships":{}}`, pageOf(r.URL.Path) }
		}, nil},
		{"a next token repeated", GroupMalformed, 2, 0, func(_ *testing.T, f *fake) {
			f.groups[opsGroup] = plain
			f.identity = func(r *http.Request) (int, string, bool) {
				return 200, `{"memberships":[` + membership("USER", someone) + `],"nextPageToken":"again"}`, pageOf(r.URL.Path)
			}
		}, nil},
		{"a member with no key", GroupMalformed, 2, 0, func(_ *testing.T, f *fake) {
			f.groups[opsGroup] = []string{`{"name":"groups/x/memberships/1","type":"USER"}`}
		}, nil},
		{"a key with a namespace", GroupMalformed, 2, 0, func(_ *testing.T, f *fake) {
			f.groups[opsGroup] = []string{`{"name":"groups/x/memberships/1","preferredMemberKey":{"id":"` + testEmail + `","namespace":"identitysources/example"},"type":"SERVICE_ACCOUNT"}`}
		}, nil},
		{"a member of another type", GroupMemberType, 2, 0, func(_ *testing.T, f *fake) {
			f.groups[opsGroup] = []string{membership("SHARED_DRIVE", "drive@example.invalid")}
		}, nil},
		{"a member of no type", GroupMemberType, 2, 0, func(_ *testing.T, f *fake) {
			f.groups[opsGroup] = []string{membership("", "device@example.invalid")}
		}, nil},
		{"a nested group past the depth", GroupDepth, 0, 0, func(_ *testing.T, f *fake) {
			f.groups[opsGroup] = []string{membership("GROUP", teamGroup)}
			f.groups[teamGroup] = plain
		}, nil},
		{"a group of another type past the depth", GroupDepth, 1, 0, func(_ *testing.T, f *fake) {
			chain(f, 1, membership("OTHER", deepGroup))
			f.groups[deepGroup] = plain
		}, nil},
		{"the memberships bound", GroupMembers, 2, 3, func(_ *testing.T, f *fake) {
			f.groups[opsGroup] = []string{membership("USER", someone), membership("USER", "b@example.invalid"), membership("USER", "c@example.invalid"), membership("USER", "d@example.invalid")}
		}, nil},
		{"the groups bound", GroupGroups, 1, 0, func(_ *testing.T, f *fake) {
			var nested []string
			for i := 0; i < MaxGroupsRead; i++ {
				name := fmt.Sprintf("n%d@example.invalid", i)
				nested = append(nested, membership("GROUP", name))
				f.groups[name] = plain
			}
			f.groups[opsGroup] = nested
		}, nil},
		{"the time bound", GroupTime, 2, 0, func(_ *testing.T, f *fake) {
			f.groups[opsGroup] = plain
			f.identity = func(r *http.Request) (int, string, bool) {
				<-r.Context().Done()
				return 200, `{}`, true
			}
		}, nil},
		{"no groups token", GroupNoToken, 2, 0, func(_ *testing.T, f *fake) {
			f.groups[opsGroup] = []string{membership("USER", testEmail)}
			f.refuseScope[GroupsScope] = true
		}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(t)
			c.setup(t, f)
			bindings := c.bindings
			if bindings == nil {
				bindings = []string{bind("roles/run.developer", "group:"+opsGroup)}
			}
			f.page = func(*http.Request) (int, string) { return 200, groupPolicy(bindings...) }
			members := DefaultGroupMembers
			if c.members > 0 {
				members = c.members
			}
			run := ctx
			if c.want == GroupTime {
				var cancel context.CancelFunc
				run, cancel = context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
			}
			out, err := Acquire(run, groupsConfig(t, f, c.depth, members, UnresolvedServe), iamRequest())
			if err != nil {
				t.Fatalf("not served: %v", err)
			}
			report, _ := groupAnswer(t, out)
			if report.Unresolved != 1 || reasonOf(report) != c.want {
				t.Fatalf("want one group unresolved, %s: %+v %q", c.want, report, reasonOf(report))
			}
		})
	}
}

// unresolved "refuse": a page with a group unresolved is refused
// group-unresolved, by its reason and the count, never as a read-only
// refusal; and a group resolved serves as under "serve".
func TestRefuseRefusesAPageWithAGroupUnresolved(t *testing.T) {
	f := newFake(t)
	f.groups[teamGroup] = []string{membership("USER", someone)}
	f.page = func(*http.Request) (int, string) {
		return 200, groupPolicy(bind("roles/owner", "group:"+opsGroup, "group:"+teamGroup), bind("roles/editor", "deleted:group:gone@example.invalid"))
	}
	out, err := Acquire(ctx, groupsConfig(t, f, DefaultGroupDepth, DefaultGroupMembers, UnresolvedRefuse), iamRequest())
	var unresolved *GroupUnresolved
	var r *Refused
	if out != nil || !errors.As(err, &unresolved) || errors.As(err, &r) || unresolved.Reason != GroupUnreadable || unresolved.Groups != 2 {
		t.Fatalf("refused group-unresolved: %v", err)
	}
	if err.Error() != "group-unresolved: unreadable" || string(unresolved.Report()) != `{"groupUnresolved":{"groups":2,"reason":"unreadable"}}` {
		t.Fatalf("the refusal and its report: %q %s", err.Error(), unresolved.Report())
	}
	f.page = func(*http.Request) (int, string) { return 200, groupPolicy(bind("roles/owner", "group:"+teamGroup)) }
	if report := served(t, f, groupsConfig(t, f, DefaultGroupDepth, DefaultGroupMembers, UnresolvedRefuse)); report.Unresolved != 0 {
		t.Fatalf("a group resolved under refuse: %+v", report)
	}
}

// A cycle between groups is skipped, not unresolved; a group met twice --
// in two bindings, on two assets, nested under two groups -- is read once
// and counted once.
func TestACycleAndAGroupMetTwice(t *testing.T) {
	f := newFake(t)
	f.groups[opsGroup] = []string{membership("GROUP", teamGroup), membership("USER", someone)}
	f.groups[teamGroup] = []string{membership("GROUP", opsGroup), membership("GROUP", deepGroup)}
	f.groups["other@example.invalid"] = []string{membership("GROUP", deepGroup)}
	f.groups[deepGroup] = []string{membership("USER", "b@example.invalid")}
	f.page = func(*http.Request) (int, string) {
		return 200, `{"assets":[{"name":"` + otherAsset + `","assetType":"storage.googleapis.com/Bucket","iamPolicy":{"bindings":[` + bind("roles/storage.admin", "group:"+opsGroup) + `]}},` +
			`{"name":"` + groupAsset + `","assetType":"run.googleapis.com/Service","iamPolicy":{"bindings":[` + bind("roles/run.admin", "group:"+opsGroup, "group:other@example.invalid") + `,` + bind("roles/owner", "group:"+opsGroup) + `]}}]}`
	}
	if report := served(t, f, groupsConfig(t, f, 4, DefaultGroupMembers, UnresolvedServe)); report.Unresolved != 0 {
		t.Fatalf("a cycle left a group unresolved: %+v %q", report, reasonOf(report))
	}
	seen := map[string]int{}
	for _, c := range f.callsTo("/identity/") {
		seen[c.path+"?"+c.query]++
	}
	for call, n := range seen {
		if n != 1 {
			t.Fatalf("read %d times: %s", n, call)
		}
	}
	if len(seen) != 4+4 {
		t.Fatalf("four groups, each looked up and listed once: %v", seen)
	}
}

// Each member type: a user or a service account is a leaf; a group is
// read; a member of another type, or of none, is looked up as a group and
// read as one where it is one, and otherwise leaves its parent
// unresolved, never a leaf.
func TestEachMemberType(t *testing.T) {
	for _, c := range []struct {
		name, kind string
		isGroup    bool
		want       string
	}{
		{"a group", "GROUP", true, "found"},
		{"another type that is a group", "OTHER", true, "found"},
		{"no type, a group", "", true, "found"},
		{"another type that is no group", "OTHER", false, GroupMemberType},
		{"a shared drive", "SHARED_DRIVE", false, GroupMemberType},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(t)
			f.groups[opsGroup] = []string{membership(c.kind, teamGroup)}
			if c.isGroup {
				f.groups[teamGroup] = []string{membership("SERVICE_ACCOUNT", testEmail)}
			}
			f.page = func(*http.Request) (int, string) { return 200, groupPolicy(bind("roles/owner", "group:"+opsGroup)) }
			out, err := Acquire(ctx, groupsConfig(t, f, DefaultGroupDepth, DefaultGroupMembers, UnresolvedServe), iamRequest())
			if c.want == "found" {
				refusal(t, err, ReasonBoundAtResource)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if report, _ := groupAnswer(t, out); report.Unresolved != 1 || reasonOf(report) != c.want {
				t.Fatalf("%+v %q", report, reasonOf(report))
			}
		})
	}
	// A user or a service account that is not the principal is compared
	// and dropped: nothing is looked up for it.
	f := newFake(t)
	f.groups[opsGroup] = []string{membership("USER", someone), membership("SERVICE_ACCOUNT", "orders-runtime@example-project-1.iam.gserviceaccount.com")}
	f.page = func(*http.Request) (int, string) { return 200, groupPolicy(bind("roles/owner", "group:"+opsGroup)) }
	if report := served(t, f, groupsConfig(t, f, DefaultGroupDepth, DefaultGroupMembers, UnresolvedServe)); report.Unresolved != 0 || len(f.callsTo("/identity/v1/groups:lookup")) != 1 {
		t.Fatalf("leaves: %+v", report)
	}
}

// Only a binding to a role outside the read-only list is resolved; a page
// of another content type resolves nothing; a domain and a principal set
// are outside, resolved never and reported as no group.
func TestWhatIsNotResolved(t *testing.T) {
	f := newFake(t)
	f.groups[opsGroup] = []string{membership("SERVICE_ACCOUNT", testEmail)}
	f.page = func(*http.Request) (int, string) {
		return 200, groupPolicy(bind("roles/run.viewer", "group:"+opsGroup), bind("roles/owner", "domain:example.invalid", "principalSet://goog/group/"+opsGroup))
	}
	cfg := groupsConfig(t, f, DefaultGroupDepth, DefaultGroupMembers, UnresolvedServe)
	if report := served(t, f, cfg); report.Unresolved != 0 || len(f.callsTo("/identity/")) != 0 {
		t.Fatalf("a read-only role's group or a set outside was resolved: %+v", report)
	}
	f.page = func(*http.Request) (int, string) { return 200, fixture(t, "resources-page.json") }
	out, err := Acquire(ctx, cfg, resourceRequest())
	if err != nil {
		t.Fatal(err)
	}
	if report, _ := groupAnswer(t, out); report.Unresolved != 0 || len(f.callsTo("/identity/")) != 0 {
		t.Fatalf("a RESOURCE page: %+v", report)
	}
	// A source serving no IAM_POLICY obtains no groups token at all.
	g := newFake(t)
	cfg = groupsConfig(t, g, DefaultGroupDepth, DefaultGroupMembers, UnresolvedServe)
	cfg.ContentTypes = []string{ContentResource}
	if _, err := Acquire(ctx, cfg, resourceRequest()); err != nil || contains(g.scopes, GroupsScope) {
		t.Fatalf("a groups token for a source serving no IAM_POLICY: %v %q", err, g.scopes)
	}
}

// A source that does not opt in is as it was: two tokens, no directory
// call, its group bindings unseen, and the envelope alone on its answer.
func TestASourceThatDoesNotOptInIsUnchanged(t *testing.T) {
	f := newFake(t)
	f.groups[opsGroup] = []string{membership("SERVICE_ACCOUNT", testEmail)}
	f.page = func(*http.Request) (int, string) { return 200, groupPolicy(bind("roles/owner", "group:"+opsGroup)) }
	out, err := Acquire(ctx, f.config(t), iamRequest())
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]json.RawMessage
	json.Unmarshal(out, &env)
	if _, ok := env["acquisition"]; !ok || len(env) != 2 || len(f.callsTo("/identity/")) != 0 || !reflect.DeepEqual(f.scopes, []string{AssetScope, CheckScope}) {
		t.Fatalf("unchanged: %s %q", out, f.scopes)
	}
}

// The groups token is held to its scope as the others are: a grant beyond
// it refuses credential-scope-unknown, at the start and on a refresh;
// sealed beside the list token, it is opened for the acquisition, and a
// seal of a configuration that resolves no groups is not opened where
// they are resolved.
func TestTheGroupsToken(t *testing.T) {
	f := newFake(t)
	f.scopeMember = func(s string) any {
		if s == GroupsScope {
			return s + " https://www.googleapis.com/auth/cloud-identity.groups"
		}
		return s
	}
	cfg := groupsConfig(t, f, DefaultGroupDepth, DefaultGroupMembers, UnresolvedServe)
	if _, err := ObtainSealed(ctx, cfg); refusal(t, err, ReasonScopeUnknown) == nil {
		t.Fatal("a groups token granted more")
	}
	if _, err := Check(ctx, cfg); refusal(t, err, ReasonScopeUnknown) == nil {
		t.Fatal("a groups token granted more, by --check")
	}

	// The metadata server: the third token minted after the write check,
	// its scope read, sealed, and used for the directory alone.
	g := newFake(t)
	g.groups[opsGroup] = []string{membership("SERVICE_ACCOUNT", testEmail)}
	g.page = func(*http.Request) (int, string) { return 200, groupPolicy(bind("roles/owner", "group:"+opsGroup)) }
	cfg = groupsConfig(t, g, DefaultGroupDepth, DefaultGroupMembers, UnresolvedServe)
	cfg.TokenSource, cfg.Credentials = TokenSourceMetadata, sealKeyFile(t)
	plain := cfg
	plain.Groups = Groups{}
	plainSeal, err := ObtainSealed(ctx, plain)
	if err != nil {
		t.Fatal(err)
	}
	g.scopes = nil
	answer, err := ObtainSealed(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g.scopes, []string{AssetScope, CheckScope, GroupsScope}) {
		t.Fatalf("the scopes requested: %q", g.scopes)
	}
	var calls []string
	for _, c := range g.calls {
		calls = append(calls, c.path+"?"+c.query)
	}
	checkAt, groupsAt := -1, -1
	for i, c := range calls {
		if strings.Contains(c, ":testIamPermissions") {
			checkAt = i
		}
		if strings.Contains(c, "scopes=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-identity") {
			groupsAt = i
		}
	}
	if checkAt < 0 || groupsAt < checkAt {
		t.Fatalf("the groups token is minted after the write check: %q", calls)
	}
	var sealedAnswer struct{ Sealed string }
	json.Unmarshal(answer, &sealedAnswer)
	run := cfg
	run.SealedToken = sealedAnswer.Sealed
	if _, err := Acquire(ctx, run, iamRequest()); refusal(t, err, ReasonBoundAtResource) == nil {
		t.Fatal("the sealed groups token")
	}
	json.Unmarshal(plainSeal, &sealedAnswer)
	run.SealedToken = sealedAnswer.Sealed
	var failure *TokenFailure
	if _, err := Acquire(ctx, run, iamRequest()); !errors.As(err, &failure) || failure.Kind != StatusSealUnusable {
		t.Fatalf("a seal without the groups token opened where groups are resolved: %v", err)
	}
	for _, c := range g.callsTo("/identity/") {
		if g.minted[c.token] != GroupsScope {
			t.Fatal("a directory call without the groups token")
		}
	}
}

// What leaves the adapter names a reason alone: never the platform's
// error text, which names the group here, nor a group's name, email or
// resource name, nor a member -- in the refusal, its report, the group
// report or the answer.
func TestNoPlatformTextAndNoGroupLeavesTheAdapter(t *testing.T) {
	const secretMember = "hidden-member@example.invalid"
	named := `{"error":{"code":%d,"message":"Group ` + opsGroup + ` (` + groupID(opsGroup) + `) member ` + secretMember + `","status":"X"}}`
	var texts []string
	for _, status := range []int{400, 403, 404, 429, 500, 503} {
		for _, mode := range []string{UnresolvedServe, UnresolvedRefuse} {
			f := newFake(t)
			f.groups[opsGroup] = []string{membership("USER", secretMember)}
			f.identity = func(r *http.Request) (int, string, bool) {
				return status, fmt.Sprintf(named, status), strings.HasSuffix(r.URL.Path, "/memberships")
			}
			f.page = func(*http.Request) (int, string) { return 200, groupPolicy(bind("roles/owner", "group:"+opsGroup)) }
			out, err := Acquire(ctx, groupsConfig(t, f, DefaultGroupDepth, DefaultGroupMembers, mode), iamRequest())
			if mode == UnresolvedServe {
				report, _ := groupAnswer(t, out)
				texts = append(texts, mustJSON(report))
				// The result carries the binding's members as written,
				// the group among them (decision 5); nothing else of it.
				texts = append(texts, strings.ReplaceAll(string(out), `"group:`+opsGroup+`"`, ""))
				continue
			}
			var unresolved *GroupUnresolved
			if !errors.As(err, &unresolved) {
				t.Fatalf("%d: %v", status, err)
			}
			texts = append(texts, err.Error(), string(unresolved.Report()))
		}
	}
	all := strings.Join(texts, "\n")
	for _, word := range []string{opsGroup, groupID(opsGroup), secretMember, "message", "Group "} {
		if strings.Contains(all, word) {
			t.Fatalf("%q leaves the adapter:\n%s", word, all)
		}
	}
	for _, line := range texts {
		if strings.HasPrefix(line, ReasonGroupUnresolved) && !contains(GroupReasons, strings.TrimPrefix(line, ReasonGroupUnresolved+": ")) {
			t.Fatalf("the refusal names more than its reason: %s", line)
		}
	}
}

// The opt-in's settings are held to their ranges before anything is read.
func TestGroupSettingsAreHeldToTheirRanges(t *testing.T) {
	f := newFake(t)
	for _, g := range []Groups{
		{Resolve: true, Depth: -1, Members: 1, Unresolved: UnresolvedServe},
		{Resolve: true, Depth: MaxGroupDepth + 1, Members: 1, Unresolved: UnresolvedServe},
		{Resolve: true, Depth: 0, Members: 0, Unresolved: UnresolvedServe},
		{Resolve: true, Depth: 0, Members: MaxGroupMembers + 1, Unresolved: UnresolvedServe},
		{Resolve: true, Depth: 0, Members: 1, Unresolved: "warn"},
	} {
		cfg := f.config(t)
		cfg.Groups = g
		if _, err := Acquire(ctx, cfg, iamRequest()); err == nil || !strings.Contains(err.Error(), "--groups-") {
			t.Errorf("%+v: %v", g, err)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("a setting out of range reached the platform: %+v", f.calls)
	}
}
