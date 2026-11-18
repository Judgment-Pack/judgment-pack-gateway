package main

// Grants through groups on a gcp-asset source (ADR-0039, Amendment
// (gateway #496)): the signer's side, against the stand-in adapter of
// gcp_asset_binding_test.go. What the adapter resolves, and how, is held
// by adapters/gcpasset's own tests against an in-process directory.

import (
	"io"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// inventoryGroupsBinding is the inventory binding serving IAM_POLICY with
// the groups given.
func inventoryGroupsBinding(groups string) string {
	return `{"bindingVersion":"1","platform":"inventory","operations":{"live":{"shape":"gcp-asset","licence":"Apache-2.0",` +
		`"parents":["projects/example-project-1"],"assetTypes":["storage.googleapis.com/Bucket"],"contentTypes":["RESOURCE","IAM_POLICY"]` + groups + `}}}`
}

// groups is a binding's groups member, absent, or of resolve false, a
// source as one without it; each setting is held to its range, resolve
// true or false, and a refusal repeats no value.
func TestGCPAssetGroupsParse(t *testing.T) {
	for _, c := range []struct {
		name, groups string
		want         *gcpAssetGroups
	}{
		{"the defaults", `{"resolve":true}`, &gcpAssetGroups{depth: 2, members: 5000, unresolved: "serve"}},
		{"every setting", `{"resolve":true,"depth":0,"members":1,"unresolved":"refuse"}`, &gcpAssetGroups{depth: 0, members: 1, unresolved: "refuse"}},
		{"the most", `{"resolve":true,"depth":4,"members":50000,"unresolved":"serve"}`, &gcpAssetGroups{depth: 4, members: 50000, unresolved: "serve"}},
		{"resolve false", `{"resolve":false,"depth":3}`, nil},
	} {
		b, err := parseBinding([]byte(inventoryGroupsBinding(`,"groups":` + c.groups)))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		op := *b.live.gcpAsset
		if !op.groupsGiven || !reflect.DeepEqual(op.groups, c.want) {
			t.Fatalf("%s: %+v", c.name, op.groups)
		}
		argv := gcpAssetSourceArgv("adapter-gcp-asset", op, "/c.json", "metadata")
		flags := []string{"--groups-resolve", "--groups-depth=", "--groups-members=", "--groups-unresolved="}
		for _, flag := range flags {
			found := false
			for _, word := range argv {
				found = found || strings.HasPrefix(word, flag)
			}
			if found != (c.want != nil) {
				t.Fatalf("%s: argv %q", c.name, argv)
			}
		}
		if c.want != nil && !contains(argv, "--groups-depth="+strconv.Itoa(c.want.depth)) {
			t.Fatalf("%s: the depth handed: %q", c.name, argv)
		}
	}
	b, _ := parseBinding([]byte(inventoryGroupsBinding(``)))
	if b.live.gcpAsset.groupsGiven || b.live.gcpAsset.groups != nil {
		t.Fatalf("no groups member: %+v", b.live.gcpAsset)
	}

	for _, c := range []struct{ name, groups, want string }{
		{"a string", `"resolve"`, "groups is an object"},
		{"null", `null`, "groups is an object"},
		{"no resolve", `{"depth":2}`, `missing member "resolve"`},
		{"resolve a string", `{"resolve":"yes-please"}`, "resolve is true or false"},
		{"another member", `{"resolve":true,"domains":true}`, `unknown member "domains"`},
		{"a depth below", `{"resolve":true,"depth":-1}`, "depth is an integer from 0 to 4"},
		{"a depth past", `{"resolve":true,"depth":5}`, "depth is an integer from 0 to 4"},
		{"a depth a string", `{"resolve":true,"depth":"2"}`, "depth is an integer from 0 to 4"},
		{"no members", `{"resolve":true,"members":0}`, "members is an integer from 1 to 50000"},
		{"members past", `{"resolve":true,"members":50001}`, "members is an integer from 1 to 50000"},
		{"members out of range, resolve false", `{"resolve":false,"members":987654321}`, "members is an integer from 1 to 50000"},
		{"unresolved of another value", `{"resolve":true,"unresolved":"warn-loudly"}`, `unresolved is "serve"`},
		{"unresolved null", `{"resolve":true,"unresolved":null}`, `unresolved is "serve"`},
	} {
		_, err := parseBinding([]byte(inventoryGroupsBinding(`,"groups":` + c.groups)))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want %q, got %v", c.name, c.want, err)
			continue
		}
		for _, value := range []string{"yes-please", "987654321", "warn-loudly"} {
			if strings.Contains(err.Error(), value) {
				t.Errorf("%s: the refusal repeats a value: %v", c.name, err)
			}
		}
	}
}

// Version 30 admits groups; version 29 and earlier refuse the member,
// resolve false among them; and a binding without it derives the
// command line it did at version 29.
func TestEngineAdmitsGroupsFromVersion30(t *testing.T) {
	with := inventoryGroupsBinding(`,"groups":{"resolve":true,"unresolved":"refuse"}`)
	off := inventoryGroupsBinding(`,"groups":{"resolve":false}`)
	without := inventoryGroupsBinding(``)
	loadAt := func(version, binding string) (map[string]sourceSpec, error) {
		catalog := catalogWith(t, map[string]string{"inventory": binding})
		_, sources, err := load(t, engineAt(t, version, catalog, gcpPlatformJSON(t, "inventory@"+digestOf(binding), `{"kind":"metadata"}`, ``)))
		return sources, err
	}
	for _, binding := range []string{with, off} {
		_, err := loadAt("29", binding)
		if err == nil || !strings.Contains(err.Error(), "names groups, a version-30 member; engineVersion 29 has none") {
			t.Errorf("%s at version 29: %v", binding, err)
		}
	}
	sources, err := loadAt("30", with)
	if err != nil {
		t.Fatal(err)
	}
	live := sources["inventory/live"]
	if live.gcpAsset.op.groups == nil || live.gcpAsset.op.groups.unresolved != "refuse" {
		t.Fatalf("version 30: %+v", live.gcpAsset.op)
	}
	if want := []string{"--groups-resolve", "--groups-depth=2", "--groups-members=5000", "--groups-unresolved=refuse"}; !reflect.DeepEqual(live.argv[4:8], want) {
		t.Fatalf("the groups' flags: %q", live.argv)
	}
	at29, err := loadAt("29", without)
	if err != nil {
		t.Fatal(err)
	}
	for _, binding := range []string{without, off} {
		at30, err := loadAt("30", binding)
		if err != nil {
			t.Fatal(err)
		}
		a, b := at29["inventory/live"].argv, at30["inventory/live"].argv
		if len(a) != len(b) || !reflect.DeepEqual(a[:4], b[:4]) || a[5] != b[5] {
			t.Fatalf("%s: the command line changed: %q %q", binding, a, b)
		}
		if at30["inventory/live"].gcpAsset.op.groups != nil {
			t.Fatalf("%s resolves groups", binding)
		}
	}
}

// The answer of a source that resolves groups is its envelope beside its
// report, exactly; the report beside status 1 is exactly its form; either
// names one of G5's reasons and nothing else.
func TestGCPAssetGroupReports(t *testing.T) {
	answer := func(text string) (value, int, string, error) {
		v, err := parseJSON([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		return gcpAssetGroupAnswer("inventory/live", v)
	}
	env, n, reason, err := answer(`{"envelope":{"ok":true},"groupBindings":{"reason":null,"unresolved":0}}`)
	if err != nil || n != 0 || reason != "" || string(canonicalJSONOf(t, env)) != `{"ok":true}` {
		t.Fatalf("resolved: %v %d %q", err, n, reason)
	}
	if _, n, reason, err = answer(`{"envelope":{"ok":true},"groupBindings":{"reason":"member-type","unresolved":3}}`); err != nil || n != 3 || reason != "member-type" {
		t.Fatalf("unresolved: %v %d %q", err, n, reason)
	}
	for _, text := range []string{
		`{"ok":true}`,
		`{"envelope":{"ok":true}}`,
		`{"envelope":{"ok":true},"groupBindings":null}`,
		`{"envelope":{"ok":true},"groupBindings":{"unresolved":0}}`,
		`{"envelope":{"ok":true},"groupBindings":{"reason":null,"unresolved":0,"group":"ops@example.invalid"}}`,
		`{"envelope":{"ok":true},"groupBindings":{"reason":null,"unresolved":2}}`,
		`{"envelope":{"ok":true},"groupBindings":{"reason":"time","unresolved":0}}`,
		`{"envelope":{"ok":true},"groupBindings":{"reason":"ops@example.invalid","unresolved":1}}`,
		`{"envelope":{"ok":true},"groupBindings":{"reason":"time","unresolved":-1}}`,
		`{"envelope":{"ok":true},"groupBindings":{"reason":"time","unresolved":"1"}}`,
		`{"envelope":{"ok":true},"groupBindings":{"reason":null,"unresolved":0},"extra":1}`,
	} {
		if _, _, _, err := answer(text); err == nil || !strings.Contains(err.Error(), "is not served") || strings.Contains(err.Error(), "example.invalid") {
			t.Errorf("%s: %v", text, err)
		}
	}
	if reason, n, ok := groupUnresolvedReport([]byte(`{"groupUnresolved":{"groups":2,"reason":"unreadable"}}`)); !ok || reason != "unreadable" || n != 2 {
		t.Fatalf("the report: %q %d %v", reason, n, ok)
	}
	for _, text := range []string{
		``, ` {"groupUnresolved":{"groups":2,"reason":"unreadable"}}`, `{"groupUnresolved":{"groups":0,"reason":"unreadable"}}`,
		`{"groupUnresolved":{"groups":2,"reason":"Permission denied on ops@example.invalid"}}`, `{"groupUnresolved":{"groups":2}}`,
		`{"groupUnresolved":{"groups":2,"reason":"time","group":"ops@example.invalid"}}`, `{"refused":{"reason":"time","subject":null}}`,
		`{"groupUnresolved":{"groups":2,"reason":"` + strings.Repeat("x", maxGroupReport) + `"}}`,
	} {
		if _, _, ok := groupUnresolvedReport([]byte(text)); ok {
			t.Errorf("read as a report: %s", text)
		}
	}
	// What the refusal says is the signer's own sentence: the reason and
	// the count, never the adapter's text.
	refused := &gcpAssetGroupRefused{reason: "unreadable", groups: 2, failed: &sourceExited{code: 1, text: "source failed: adapter text"}}
	if s := refused.Error(); !strings.HasPrefix(s, "source failed: group-unresolved: unreadable: 2 groups") || strings.Contains(s, "adapter text") || !strings.Contains(s, "the source serves on") {
		t.Fatalf("the refusal: %s", s)
	}
}

func canonicalJSONOf(t *testing.T, v value) []byte {
	t.Helper()
	if v == nil {
		t.Fatal("no value")
	}
	return canon(v)
}

// groupsOp is the stand-in's operation, serving IAM_POLICY and resolving
// groups as unresolved says.
func groupsOp(unresolved string) gcpAssetOperation {
	op := gcpStandInOp
	op.contentTypes = []string{"RESOURCE", "IAM_POLICY"}
	op.groups = &gcpAssetGroups{depth: 2, members: 5000, unresolved: unresolved}
	return op
}

const gcpStandInArguments = `{"parent":"projects/example-project-1","contentType":"RESOURCE","assetTypes":["compute.googleapis.com/Instance"]}`

// A source that resolves groups: its answer unwrapped to the envelope;
// the groups it left unresolved counted, the last reason kept, the
// source then unchecked until it restarts, the line partial, and the
// page served all the same under "serve"; an answer without its report
// not served; and nothing of a group named.
func TestAGCPAssetSourceReportsItsGroups(t *testing.T) {
	service, _ := testService(t)
	dir := t.TempDir()
	const source = "inventory/live"
	set := func(pageOut string, pageExit int, op gcpAssetOperation) {
		spec := gcpStandIn(dir, op, gcpStandInToken, 0, pageOut, pageExit)
		if existing, ok := service.sources[source]; ok {
			spec.gcpAsset = existing.gcpAsset
		}
		service.sources[source] = spec
	}
	service.sources = map[string]sourceSpec{}
	set(``, 0, groupsOp("serve"))
	if err := service.gcpAssetStart(io.Discard); err != nil {
		t.Fatal(err)
	}
	posture := func() readOnlySourcePosture {
		t.Helper()
		p := readOnlySourcePostures(service.sources, nil)
		if len(p) != 1 {
			t.Fatalf("%+v", p)
		}
		return p[0]
	}
	state := func() string { return readOnlyCredentialsLines(service.sources, nil)[0].state }
	if p := posture(); p.groupBindings != "checked" || state() != postureEnforced {
		t.Fatalf("before any page: %+v %s", p, state())
	}

	set(`{"envelope":{"ok":true},"groupBindings":{"reason":null,"unresolved":0}}`, 0, groupsOp("serve"))
	result, _, _, err := service.runGCPAssetSource(source, service.sources[source], []byte(gcpStandInArguments))
	if err != nil || string(canonicalJSONOf(t, result)) != `{"ok":true}` {
		t.Fatalf("a page with its groups resolved: %v", err)
	}
	if p := posture(); p.groupBindings != "checked" || p.groupsUnresolved != 0 || state() != postureEnforced {
		t.Fatalf("resolved: %+v", p)
	}

	set(`{"envelope":{"ok":true},"groupBindings":{"reason":"time","unresolved":2}}`, 0, groupsOp("serve"))
	if result, _, _, err = service.runGCPAssetSource(source, service.sources[source], []byte(gcpStandInArguments)); err != nil || result == nil {
		t.Fatalf("a page served with a group unresolved: %v", err)
	}
	set(`{"envelope":{"ok":true},"groupBindings":{"reason":"unreadable","unresolved":1}}`, 0, groupsOp("serve"))
	service.runGCPAssetSource(source, service.sources[source], []byte(gcpStandInArguments))
	set(`{"envelope":{"ok":true},"groupBindings":{"reason":null,"unresolved":0}}`, 0, groupsOp("serve"))
	service.runGCPAssetSource(source, service.sources[source], []byte(gcpStandInArguments))
	p := posture()
	if p.groupBindings != "unchecked" || p.groupsUnresolved != 3 || p.groupReason != "unreadable" || p.state != "serving" || state() != posturePartial {
		t.Fatalf("unchecked, and it stays so: %+v %s", p, state())
	}
	value := canonicalJSONOf(t, p.value())
	if !strings.Contains(string(value), `"groupBindings":"unchecked"`) || !strings.Contains(string(value), `"groupReason":"unreadable"`) || !strings.Contains(string(value), `"groupsUnresolved":3`) {
		t.Fatalf("the entry: %s", value)
	}
	if !strings.Contains(p.text(), "groupBindings=unchecked groupsUnresolved=3 groupReason=unreadable") {
		t.Fatalf("the text: %s", p.text())
	}

	// An answer without its report, or with one out of form, is not
	// served, and counts nothing.
	for _, out := range []string{`{"ok":true}`, `{"envelope":{"ok":true},"groupBindings":{"reason":"ops@example.invalid","unresolved":1}}`} {
		set(out, 0, groupsOp("serve"))
		result, _, _, err := service.runGCPAssetSource(source, service.sources[source], []byte(gcpStandInArguments))
		if err == nil || result != nil || strings.Contains(err.Error(), "example.invalid") {
			t.Fatalf("%s served: %v", out, err)
		}
	}
	if p := posture(); p.groupsUnresolved != 3 || p.state != "serving" {
		t.Fatalf("a report out of form counted, or closed the source: %+v", p)
	}
}

// Under "refuse", a page with a group unresolved is the adapter's status
// 1 with its report: the acquisition fails with the signer's sentence,
// the groups are counted, and the source is not closed, so the next
// acquisition runs; the same status without the report, or under
// "serve", is a failure as any other, counted nowhere. A principal found
// in a group is the adapter's status 9, which closes the source as a
// direct binding does.
func TestUnderRefuseAGroupUnresolvedFailsTheAcquisitionAndClosesNothing(t *testing.T) {
	service, server := testService(t)
	dir := t.TempDir()
	const source = "inventory/live"
	report := `{"groupUnresolved":{"groups":2,"reason":"members"}}`
	service.sources = map[string]sourceSpec{source: gcpStandIn(dir, groupsOp("refuse"), gcpStandInToken, 0, report, 1)}
	if err := service.gcpAssetStart(io.Discard); err != nil {
		t.Fatal(err)
	}
	got := postRaw(t, server.URL, "/acquire", gcpStandInRequest)
	if got.code == 200 || !strings.Contains(got.body, "group-unresolved: members: 2 groups") || strings.Contains(got.body, "is closed") {
		t.Fatalf("a page refused for a group unresolved: %d %s", got.code, got.body)
	}
	requireNothingKept(t, service, "drift-1")
	p := readOnlySourcePostures(service.sources, nil)[0]
	if p.state != "serving" || p.refusal != nil || p.groupBindings != "unchecked" || p.groupsUnresolved != 2 || p.groupReason != "members" {
		t.Fatalf("refused, and not closed: %+v", p)
	}
	postRaw(t, server.URL, "/acquire", gcpStandInRequest)
	if runs := gcpStandInRuns(dir); !reflect.DeepEqual(runs, []string{"TOKEN:false", "TOKEN:false", "PAGE:true", "TOKEN:false", "PAGE:true"}) {
		t.Fatalf("the next acquisition did not run: %v", runs)
	}
	if p := readOnlySourcePostures(service.sources, nil)[0]; p.groupsUnresolved != 4 {
		t.Fatalf("the second refusal is not counted: %+v", p)
	}

	// The status without its report, or the report under "serve": a
	// failure as any other.
	for _, c := range []struct {
		op  gcpAssetOperation
		out string
	}{{groupsOp("refuse"), `{"groupUnresolved":{"groups":2,"reason":"ops@example.invalid"}}`}, {groupsOp("serve"), report}} {
		dir := t.TempDir()
		service.sources = map[string]sourceSpec{source: gcpStandIn(dir, c.op, gcpStandInToken, 0, c.out, 1)}
		if err := service.gcpAssetStart(io.Discard); err != nil {
			t.Fatal(err)
		}
		_, _, _, err := service.runGCPAssetSource(source, service.sources[source], []byte(gcpStandInArguments))
		if err == nil || strings.Contains(err.Error(), "group-unresolved") || strings.Contains(err.Error(), "example.invalid") {
			t.Fatalf("%s: %v", c.out, err)
		}
		if p := readOnlySourcePostures(service.sources, nil)[0]; p.groupsUnresolved != 0 || p.groupBindings != "checked" || p.state != "serving" {
			t.Fatalf("%s counted: %+v", c.out, p)
		}
	}

	// Found: status 9, credential-bound-at-resource, closes the source.
	dir = t.TempDir()
	service.sources = map[string]sourceSpec{source: gcpStandIn(dir, groupsOp("serve"), gcpStandInToken, 0,
		`{"refused":{"reason":"credential-bound-at-resource","subject":"//storage.googleapis.com/example-bucket"}}`, sourceExitRefused)}
	if err := service.gcpAssetStart(io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := service.runGCPAssetSource(source, service.sources[source], []byte(gcpStandInArguments)); err == nil || !strings.Contains(err.Error(), "is closed") {
		t.Fatalf("found: %v", err)
	}
	if p := readOnlySourcePostures(service.sources, nil)[0]; p.state != "closed" || p.refusal.reason != refusalCredentialBoundAtRsrc {
		t.Fatalf("found closes the source: %+v", p)
	}
}

// groupBindings is "off" where a source does not opt in, which changes
// nothing; "unchecked" where it serves no IAM_POLICY; and the
// read-only-credentials line is partial while any source it is judged
// over is unchecked, whoever asks, its counts of the sources the caller
// reaches, and its text as before where the caller reaches none that
// resolves groups.
func TestGroupBindingsOnPosture(t *testing.T) {
	iamOp := gcpStandInOp
	iamOp.contentTypes = []string{"RESOURCE", "IAM_POLICY"}
	resourceOnly := gcpStandInOp
	resourceOnly.groups = &gcpAssetGroups{depth: 2, members: 5000, unresolved: "serve"}
	off := newGCPAssetSource(iamOp, gcpAssetTokenMetadata, false)
	checked := newGCPAssetSource(groupsOp("serve"), gcpAssetTokenMetadata, false)
	unchecked := newGCPAssetSource(groupsOp("refuse"), gcpAssetTokenMetadata, false)
	unchecked.noteGroups(1, "no-token")
	for _, c := range []struct {
		s    *gcpAssetSource
		want string
	}{{off, "off"}, {checked, "checked"}, {unchecked, "unchecked"}, {newGCPAssetSource(resourceOnly, gcpAssetTokenMetadata, false), "unchecked"}} {
		if state, _, _ := c.s.groupBindings(); state != c.want {
			t.Errorf("%+v: %s, want %s", c.s.op, state, c.want)
		}
	}
	value := canonicalJSONOf(t, readOnlySourcePostures(map[string]sourceSpec{"a/live": {shape: "http", gcpAsset: off}}, nil)[0].value())
	if !strings.Contains(string(value), `"groupBindings":"off","groupReason":null,"groupsUnresolved":0`) {
		t.Fatalf("off: %s", value)
	}

	// Every source serving IAM_POLICY, none opted in: enforced, as before.
	sources := map[string]sourceSpec{"a/live": {shape: "http", scope: "scope-a", gcpAsset: off}}
	if lines := readOnlyCredentialsLines(sources, nil); lines[0].state != postureEnforced || !strings.Contains(lines[0].reason, "not a grant through a group") {
		t.Fatalf("off changes nothing: %+v", lines)
	}
	sources["b/live"] = sourceSpec{shape: "http", scope: "scope-b", gcpAsset: checked}
	lines := readOnlyCredentialsLines(sources, nil)
	if lines[0].state != postureEnforced || !strings.Contains(lines[0].reason, "1 of them resolve a grant through a group") || !strings.Contains(lines[0].reason, "0 of those left a group unresolved") {
		t.Fatalf("checked: %+v", lines)
	}
	sources["c/live"] = sourceSpec{shape: "http", scope: "scope-c", gcpAsset: unchecked}
	for _, c := range []struct {
		name  string
		reach *scopeReach
		want  string
	}{
		{"every source", nil, "2 of them resolve a grant through a group with a third token held to a read-only scope, over the memberships the operator lets the principal view, and 1 of those left a group unresolved"},
		{"scope B's caller", &scopeReach{ids: map[string]bool{"scope-b": true}}, "1 of them resolve a grant through a group with a third token held to a read-only scope, over the memberships the operator lets the principal view, and 0 of those left a group unresolved"},
		{"scope A's caller", &scopeReach{ids: map[string]bool{"scope-a": true}}, "not a grant through a group"},
	} {
		lines := readOnlyCredentialsLines(sources, c.reach)
		if len(lines) != 1 || lines[0].state != posturePartial || !strings.Contains(lines[0].reason, c.want) {
			t.Errorf("%s: %+v", c.name, lines)
		}
	}
}

// The start says, of a source that opts in, that its groups are resolved,
// by what token, within what bounds, what an unresolved group does, the
// operator's part and what stays outside; of one that does not, what it
// said before.
func TestTheStartSaysWhetherGroupsAreResolved(t *testing.T) {
	lines := func(op gcpAssetOperation) string {
		return strings.Join(gcpAssetStartLines("inventory/live", sourceSpec{gcpAsset: newGCPAssetSource(op, gcpAssetTokenMetadata, false)}), "\n")
	}
	iamOp := gcpStandInOp
	iamOp.contentTypes = []string{"RESOURCE", "IAM_POLICY"}
	before := lines(iamOp)
	if strings.Contains(before, "group-bindings") || !strings.Contains(before, "a grant through a group, or on an asset type the source does not serve, is not seen") {
		t.Fatalf("a source that does not opt in: %s", before)
	}
	refuse := groupsOp("refuse")
	refuse.groups.depth, refuse.groups.members = 3, 700
	said := lines(refuse)
	for _, want := range []string{"or to a group in which it is found, closes the source", "group-bindings: resolved, through a third token of scope cloud-identity.groups.readonly",
		"read-only by its scope since no write check covers the directory", "to depth 3, at most 700 memberships and 64 groups an acquisition, in at most half its time and 10 s",
		"refused group-unresolved, which fails the acquisition and does not close the source", "the operator lets it view", "domain: members, principal sets and pools"} {
		if !strings.Contains(said, want) {
			t.Errorf("the start does not say %q:\n%s", want, said)
		}
	}
	if said := lines(groupsOp("serve")); !strings.Contains(said, "served, and /posture reports the source's groupBindings unchecked") {
		t.Errorf("serve: %s", said)
	}
	resourceOnly := gcpStandInOp
	resourceOnly.groups = &gcpAssetGroups{depth: 2, members: 5000, unresolved: "serve"}
	if said := lines(resourceOnly); !strings.Contains(said, "group-bindings: unchecked: the platform serves no IAM_POLICY") {
		t.Errorf("no IAM_POLICY: %s", said)
	}
}
