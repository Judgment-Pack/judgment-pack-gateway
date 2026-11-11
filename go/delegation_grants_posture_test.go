package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// grantsLineOf is the delegation-grants line of a report, and whether it has
// one.
func grantsLineOf(report postureReport) (postureLine, bool) {
	for _, l := range report.lines {
		if l.name == protectionDelegationGrants {
			return l, true
		}
	}
	return postureLine{}, false
}

// The delegation-grants line (gateway #376): every platform a delegated call
// can reach names a grant (enforced, counted), some do not (enforced, the
// rest named), none does (not-applicable: the delegation serves no call),
// or nothing takes a delegated call at all. A platform is reached through a
// write source or an mcp source, and judged per platform, not per source.
func TestDelegationGrantsPostureLine(t *testing.T) {
	gate := &grantGate{provider: "azure-devops", connection: "boards"}
	mcp := func(granted bool) sourceSpec {
		spec := sourceSpec{shape: "mcp", tools: []string{"query"}}
		if granted {
			spec.grant = gate
		}
		return spec
	}
	// Sources a delegated call never reaches whatever they name: an airbyte
	// history and an http live read no tool.
	unreached := map[string]sourceSpec{
		"archive/history": {shape: "airbyte"},
		"feed/live":       {shape: "http"},
	}
	with := func(extra map[string]sourceSpec) map[string]sourceSpec {
		sources := map[string]sourceSpec{}
		for name, spec := range unreached {
			sources[name] = spec
		}
		for name, spec := range extra {
			sources[name] = spec
		}
		return sources
	}
	many := map[string]sourceSpec{}
	for _, name := range []string{"p7", "p3", "p1", "p6", "p2", "p5", "p4"} {
		many[name+"/live"] = mcp(false)
	}
	for _, c := range []struct {
		name    string
		sources map[string]sourceSpec
		state   string
		reason  string
	}{
		{"one platform, named", with(map[string]sourceSpec{"tickets/live": mcp(true), "tickets/write": mcp(true), "tickets/history": {shape: "airbyte"}}), postureEnforced,
			"the 1 platform a delegated call can reach names a connection grant, and every delegated call on it is admitted only under that grant"},
		{"all named", with(map[string]sourceSpec{"tickets/live": mcp(true), "crm/write": {tools: []string{"update"}, grant: gate}}), postureEnforced,
			"each of the 2 platforms a delegated call can reach names a connection grant, and every delegated call is admitted only under its platform's grant"},
		{"some named", with(map[string]sourceSpec{"tickets/live": mcp(true), "crm/live": mcp(false), "notes/write": {tools: []string{"append"}}}), postureEnforced,
			`1 of the 3 platforms a delegated call can reach names a connection grant, and every delegated call is admitted only under its platform's grant; platforms "crm", "notes" name no connection grant and refuse every delegated call (grant-unknown) until they name one`},
		{"a platform one of whose sources names none", with(map[string]sourceSpec{"tickets/live": mcp(true), "tickets/write": mcp(false), "crm/live": mcp(true), "docs/live": mcp(true)}), postureEnforced,
			`2 of the 3 platforms a delegated call can reach name a connection grant, and every delegated call is admitted only under its platform's grant; platform "tickets" names no connection grant and refuses every delegated call (grant-unknown) until it names one`},
		{"none named, one platform", with(map[string]sourceSpec{"crm/live": mcp(false), "crm/write": mcp(false)}), postureNotApplicable,
			`platform "crm" names no connection grant and refuses every delegated call (grant-unknown) until it names one, so the delegation serves no call`},
		{"none named, more than the line names", many, postureNotApplicable,
			`platforms "p1", "p2", "p3", "p4", "p5" and 2 more name no connection grant and refuse every delegated call (grant-unknown) until they name one, so the delegation serves no call`},
		{"nothing a delegated call reaches", with(nil), postureNotApplicable,
			"no source offers a tool a delegated call could name, so the delegation serves no call"},
		{"no source", nil, postureNotApplicable,
			"no source offers a tool a delegated call could name, so the delegation serves no call"},
	} {
		t.Run(c.name, func(t *testing.T) {
			l, reported := grantsLineOf(hostPosture(postureInput{configured: true, sources: c.sources, delegation: &delegationPosture{}}))
			if !reported || l.state != c.state || l.reason != c.reason {
				t.Fatalf("%v %s\n got %q\nwant %q", reported, l.state, l.reason, c.reason)
			}
		})
	}
}

// A gateway without a delegation reports no grants line, whatever its
// platforms name; with one, the line follows the sender constraint and comes
// before write-requesters.
func TestDelegationGrantsPostureLinePlace(t *testing.T) {
	sources := map[string]sourceSpec{
		"crm/live":      {shape: "mcp", tools: []string{"query"}},
		"tickets/write": {shape: "mcp", tools: []string{"update"}, requesters: &writeRequesters{}},
	}
	if l, reported := grantsLineOf(hostPosture(postureInput{configured: true, sources: sources})); reported {
		t.Fatalf("a gateway without a delegation reports %+v", l)
	}
	var names []string
	for _, l := range hostPosture(postureInput{configured: true, sources: sources, delegation: &delegationPosture{}}).lines {
		names = append(names, l.name)
	}
	want := append(append([]string{}, postureOrder...), protectionDelegationNarrowing, protectionDelegationSender, protectionDelegationGrants, protectionWriteRequesters)
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("lines:\n got %v\nwant %v", names, want)
	}
}

// An engine configuration's platforms are judged as serve derives them: a
// platform that names a grant gives every source it derives the gate.
func TestDelegationGrantsPostureOfConfig(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	ref := "postgres@" + digestOf(postgresBinding)
	pub := hex.EncodeToString(ed25519.NewKeyFromSeed(delegationHostSeed).Public().(ed25519.PublicKey))
	extra := `,"adapters":"` + abs(t, t.TempDir(), "bin") + `","identity":{"issuer":"https://login.example","audience":"gateway:acme","keys":"` + abs(t, t.TempDir(), "keys.json") + `"},"delegation":` + delegationConfigText(pub, "https://desk.example/admission", abs(t, t.TempDir(), "token"), "")
	grant := `,"grant":{"provider":"azure-devops","connection":"boards","stateDir":"` + abs(t, t.TempDir(), "custody") + `","principal":"operator","user":"engine-desk"}`
	lineOf := func(t *testing.T, platformExtra string) postureLine {
		t.Helper()
		text := strings.Replace(engineJSON(t, catalog, extra, platformJSONFor(t, "warehouse", ref, "engine-warehouse", platformExtra, "history", "live", "write")), `"engineVersion":"1"`, `"engineVersion":"16"`, 1)
		path := filepath.Join(t.TempDir(), "engine.json")
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		in, err := postureOfConfig(path, stubAccounts(stubUsers))
		if err != nil {
			t.Fatal(err)
		}
		l, reported := grantsLineOf(hostPosture(in))
		if !reported {
			t.Fatal("a configuration with a delegation reports no grants line")
		}
		return l
	}
	if l := lineOf(t, `,"write":true`+grant); l.state != postureEnforced || l.reason != "the 1 platform a delegated call can reach names a connection grant, and every delegated call on it is admitted only under that grant" {
		t.Fatalf("a platform naming a grant: %+v", l)
	}
	if l := lineOf(t, `,"write":true`); l.state != postureNotApplicable || l.reason != `platform "warehouse" names no connection grant and refuses every delegated call (grant-unknown) until it names one, so the delegation serves no call` {
		t.Fatalf("a platform naming none: %+v", l)
	}
}

// /posture answers the line, naming the platforms as its program entries
// already do, and no path and no account.
func TestDelegationGrantsPostureEndpoint(t *testing.T) {
	service, server := testService(t)
	service.sources["crm/live"] = sourceSpec{argv: []string{os.Args[0]}, env: helperEnv, shape: "mcp", tools: []string{"query"}}
	service.attachDelegation(newDelegationService(nil, nil, false))
	resp, err := http.Get(server.URL + "/posture")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	state, reason := postureLineIn(t, body, protectionDelegationGrants)
	if state != postureNotApplicable || reason != `platform "crm" names no connection grant and refuses every delegated call (grant-unknown) until it names one, so the delegation serves no call` {
		t.Fatalf("/posture: %s %q", state, reason)
	}
	if !strings.Contains(string(body), `"source":"crm/live"`) {
		t.Fatalf("the program entries name the source: %s", body)
	}
	if strings.ContainsAny(reason, `/\`) {
		t.Fatalf("the reason names a path: %q", reason)
	}
}
