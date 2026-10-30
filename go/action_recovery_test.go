package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

const recoveryDeclaration = `{"query":{"idempotencyArgument":"request_id","readBack":{"tool":"query","arguments":{"key":{"actionKey":true},"ticket":{"argument":"/ticket"},"literal":{"literal":7}},"keyPointer":"/key","outcomePointer":"/state","committedValue":"done"}},"sibling":null}`

func TestActionRecoveryPinnedContract(t *testing.T) {
	base := strings.Replace(customerBinding("https://example.test/read", "https://example.test/write"), `"bindingVersion":"2"`, `"bindingVersion":"3"`, 1)
	base = strings.TrimSuffix(base, "}") + `,"actionRecovery":` + recoveryDeclaration + `}`
	b, err := parseBinding([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	contract := b.actionRecovery["query"]
	key := strings.Repeat("a", 64)
	args := newObject()
	args.set("ticket", vString("T-1"))
	if err := contract.applyKey(args, key); err != nil {
		t.Fatal(err)
	}
	if err := contract.applyKey(args, strings.Repeat("b", 64)); err == nil {
		t.Fatal("conflicting idempotency argument accepted")
	}
	request, err := contract.readBack.request(key, args)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(canon(request)); got != `{"arguments":{"key":"`+key+`","literal":7,"ticket":"T-1"},"tool":"query"}` {
		t.Fatal(got)
	}
	for _, tc := range []struct{ raw, want string }{
		{`{"key":"` + key + `","state":"done"}`, "committed"},
		{`{"key":"other","state":"done"}`, "unknown"},
		{`{"key":"` + key + `","state":"absent"}`, "unknown"},
		{`{}`, "unknown"},
	} {
		v, _ := parseJSON([]byte(tc.raw))
		if got := contract.readBack.outcome(key, v); got != tc.want {
			t.Fatalf("%s: %s", tc.raw, got)
		}
	}
	if _, err = contract.readBack.request(key, newObject()); err == nil {
		t.Fatal("missing original argument accepted")
	}
	for name, broken := range map[string]string{
		"old version":         strings.Replace(base, `"bindingVersion":"3"`, `"bindingVersion":"2"`, 1),
		"missing declaration": strings.Replace(base, `,"actionRecovery":`+recoveryDeclaration, "", 1),
		"missing tool":        strings.Replace(base, `,"sibling":null`, "", 1),
		"extra tool":          strings.Replace(base, `"sibling":null`, `"sibling":null,"other":null`, 1),
		"empty support":       strings.Replace(base, `"sibling":null`, `"sibling":{}`, 1),
		"unknown support":     strings.Replace(base, `"sibling":null`, `"sibling":{"retry":true}`, 1),
		"write readback":      strings.Replace(base, `"operation":"read"`, `"operation":"act"`, 1),
		"bad pointer":         strings.Replace(base, `"/key"`, `"/key~2"`, 1),
		"false key":           strings.Replace(base, `"actionKey":true`, `"actionKey":false`, 1),
		"ambiguous map":       strings.Replace(base, `"actionKey":true`, `"actionKey":true,"literal":"x"`, 1),
		"unallowed read tool": strings.Replace(base, `"tool":"query"`, `"tool":"other"`, 1),
		"null argument name":  strings.Replace(base, `"idempotencyArgument":"request_id"`, `"idempotencyArgument":null`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseBinding([]byte(broken)); err == nil {
				t.Fatal("accepted malformed recovery")
			}
		})
	}
}

// stubSandboxPolicyDigests stands in for the sandbox probe: a policy path's
// digest is the digest of the bytes policies gives it (its own name when
// absent), so tests can move a policy without changing its bytes.
func stubSandboxPolicyDigests(t *testing.T, policies map[string]string) {
	t.Helper()
	saved := sandboxPostureProbe
	sandboxPostureProbe = func(_ context.Context, spec sourceSpec) (sandboxProbeReport, error) {
		var report sandboxProbeReport
		bytes, ok := policies[spec.sandbox.policy]
		if !ok {
			bytes = spec.sandbox.policy
		}
		if bytes == "unmeasurable" {
			return report, errors.New("probe failed")
		}
		report.PolicyDigest = digestOf(bytes)
		return report, nil
	}
	t.Cleanup(func() { sandboxPostureProbe = saved })
}

// #351 M1 and #355: the fingerprint is the approved identity. What a retry
// means changes it; where the programs are installed, the platform's
// environment and the OS user do not, and in identity version 2 neither does
// how a release composes the adapter's command line. Version 1 (v0.23.0's)
// is computed as it was, so that its reservations are still recognized.
func TestActionFingerprintBindsApprovedIdentityNotInstall(t *testing.T) {
	stubSandboxPolicyDigests(t, map[string]string{"/etc/a/policy.json": "policy-v1", "/etc/b/policy.json": "policy-v1", "/etc/c/policy.json": "policy-v2", "/broken": "unmeasurable"})
	pin := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	base := sourceSpec{
		argv:                 []string{"/opt/gateway-1/adapter-mcp", "--credentials=/home/engine/.credentials/tickets", "--tools=write", "--sandbox-workspace=/srv/work", "--sandbox-policy=/etc/a/policy.json", "--sandbox-source=tickets/write", "--endpoint=https://tickets.example", "--error-results", "--customer-binding", "--owner-declaration-file=/etc/engine.json.descriptors/c.json", "--owner-declaration-pin=" + pin("c"), "--descriptor-snapshot=/etc/engine.json.descriptors/b.json", "--descriptor-pin=" + pin("b"), "--approved-operation=write", "--approved-platform=tickets", "--approved-binding=tickets@" + pin("a"), "--sandbox-enclosing", "--", "/opt/server/bin/tickets", "serve"},
		env:                  []string{"HOME=/home/engine", "PATH=/usr/bin"},
		user:                 "engine-tickets",
		binding:              "tickets@" + pin("a"),
		tools:                []string{"write"},
		endpoint:             "https://tickets.example",
		sandbox:              &sourceSandbox{helper: "/opt/gateway-1/adapter-sandbox", policy: "/etc/a/policy.json", workspace: "/srv/work", source: "tickets/write"},
		descriptorProvenance: &descriptorProvenance{snapshot: pin("d"), statement: pin("e"), binding: "tickets@" + pin("a")},
		approval: &sourceApproval{
			platformEndpoint: "https://tickets.example", command: []string{"/opt/server/bin/tickets", "serve"}, customer: true,
			descriptorPin: pin("b"), ownerDeclarationPin: pin("c"), approvedOperation: "write", approvedPlatform: "tickets", approvedBinding: "tickets@" + pin("a"),
			sandboxSource: "tickets/write",
		},
	}
	recovery := &actionRecovery{declaration: newObject(), readBack: &actionReadBack{tool: "read"}}
	fingerprint := func(write, live sourceSpec) actionIdentity {
		t.Helper()
		got, err := actionFingerprint("tickets", "write", newObject(), newObject(), vArray{}, write, recovery, live)
		if err != nil {
			t.Fatal(err)
		}
		if !isLowerHexOfLen(got.fingerprint, 64) || !isLowerHexOfLen(got.previous, 64) || got.fingerprint == got.previous {
			t.Fatalf("identity %+v", got)
		}
		return got
	}
	want := fingerprint(base, base)
	replaceWord := func(argv []string, prefix, word string) []string {
		out := append([]string(nil), argv...)
		for i, w := range out {
			if strings.HasPrefix(w, prefix) {
				out[i] = word
			}
		}
		return out
	}
	changed := func(edit func(*sourceSpec)) sourceSpec {
		c := base
		boundary := *base.sandbox
		c.sandbox = &boundary
		approval := *base.approval
		c.approval = &approval
		edit(&c)
		return c
	}
	// Neither version changes.
	same := map[string]sourceSpec{
		"adapter installed elsewhere": changed(func(s *sourceSpec) {
			s.argv = replaceWord(s.argv, "/opt/gateway-1/adapter-mcp", "/opt/gateway-2/adapter-mcp")
		}),
		"credentials path": changed(func(s *sourceSpec) {
			s.argv = replaceWord(s.argv, "--credentials=", "--credentials=/var/lib/engine/tickets")
		}),
		"workspace path": changed(func(s *sourceSpec) {
			s.argv = replaceWord(s.argv, "--sandbox-workspace=", "--sandbox-workspace=/srv/other")
			s.sandbox.workspace = "/srv/other"
		}),
		"policy moved, same bytes": changed(func(s *sourceSpec) {
			s.argv = replaceWord(s.argv, "--sandbox-policy=", "--sandbox-policy=/etc/b/policy.json")
			s.sandbox.policy = "/etc/b/policy.json"
		}),
		"sandbox helper path": changed(func(s *sourceSpec) { s.sandbox.helper = "/opt/gateway-2/adapter-sandbox" }),
		"snapshot copy path": changed(func(s *sourceSpec) {
			s.argv = replaceWord(s.argv, "--descriptor-snapshot=", "--descriptor-snapshot=/srv/engine.json.descriptors/b.json")
		}),
		"owner declaration copy path": changed(func(s *sourceSpec) {
			s.argv = replaceWord(s.argv, "--owner-declaration-file=", "--owner-declaration-file=/srv/engine.json.descriptors/c.json")
		}),
		"environment variable added": changed(func(s *sourceSpec) { s.env = append(append([]string(nil), s.env...), "TZ=UTC") }),
		"home moved":                 changed(func(s *sourceSpec) { s.env = []string{"HOME=/var/lib/engine", "PATH=/usr/bin"} }),
		"OS user":                    changed(func(s *sourceSpec) { s.user = "engine-tickets-2" }),
		"probe cache":                changed(func(s *sourceSpec) { s.sandbox.probe = &sourceSandboxProbe{done: true} }),
	}
	for name, spec := range same {
		if fingerprint(spec, base) != want || fingerprint(base, spec) != want {
			t.Errorf("%s changed the action's identity", name)
		}
	}
	// A later release's composition of the same approval: version 2 stays,
	// version 1 moves (the reason for version 2).
	release := map[string]sourceSpec{
		"a derived flag added": changed(func(s *sourceSpec) {
			s.argv = append(append(append([]string(nil), s.argv[:3]...), "--max-response=1048576"), s.argv[3:]...)
		}),
		"derived flags reordered": changed(func(s *sourceSpec) {
			s.argv = append([]string(nil), s.argv...)
			s.argv[2], s.argv[6] = s.argv[6], s.argv[2]
		}),
		"a derived flag renamed": changed(func(s *sourceSpec) { s.argv = replaceWord(s.argv, "--error-results", "--results-as-errors") }),
		"a derived flag dropped": changed(func(s *sourceSpec) {
			s.argv = slices.DeleteFunc(append([]string(nil), s.argv...), func(w string) bool { return w == "--sandbox-enclosing" })
		}),
	}
	for name, spec := range release {
		for _, got := range []actionIdentity{fingerprint(spec, base), fingerprint(base, spec)} {
			if got.fingerprint != want.fingerprint {
				t.Errorf("%s changed identity version 2", name)
			}
			if got.previous == want.previous {
				t.Errorf("%s left identity version 1 as it was; the case shows nothing", name)
			}
		}
	}
	// What a retry means changes both versions.
	differs := map[string]sourceSpec{
		"sandbox presence": changed(func(s *sourceSpec) { s.sandbox = nil }),
		"sandbox selector": changed(func(s *sourceSpec) { s.sandbox.source = "other/write" }),
		"policy bytes":     changed(func(s *sourceSpec) { s.sandbox.policy = "/etc/c/policy.json" }),
		"binding":          changed(func(s *sourceSpec) { s.binding = "tickets@" + pin("f") }),
		"endpoint":         changed(func(s *sourceSpec) { s.endpoint = "https://other.example" }),
		"transport":        changed(func(s *sourceSpec) { s.transport = "http" }),
		"descriptor provenance": changed(func(s *sourceSpec) {
			s.descriptorProvenance = &descriptorProvenance{snapshot: pin("f"), statement: s.descriptorProvenance.statement, binding: s.descriptorProvenance.binding}
		}),
		"descriptor provenance gone": changed(func(s *sourceSpec) { s.descriptorProvenance = nil }),
	}
	for name, spec := range differs {
		for _, got := range []actionIdentity{fingerprint(spec, base), fingerprint(base, spec)} {
			if got.fingerprint == want.fingerprint || got.previous == want.previous {
				t.Errorf("%s did not change both identities of the write and read sources", name)
			}
		}
	}
	// The request's decision policy and recovery contract change both
	// versions: the policy is the write source's, the contract the tool's.
	withPolicy := changed(func(s *sourceSpec) { s.policies = map[string]*decisionPolicy{"write": {digest: pin("9")}} })
	otherPolicy := changed(func(s *sourceSpec) { s.policies = map[string]*decisionPolicy{"write": {digest: pin("8")}} })
	if got, other := fingerprint(withPolicy, base), fingerprint(otherPolicy, base); got.fingerprint == want.fingerprint || got.previous == want.previous || got.fingerprint == other.fingerprint || got.previous == other.previous {
		t.Error("the decision policy did not change both identities")
	}
	declaration := newObject()
	declaration.set("idempotencyArgument", vString("request_id"))
	for name, contract := range map[string]*actionRecovery{
		"another recovery contract": {declaration: declaration, readBack: recovery.readBack},
		"no recovery contract":      nil,
	} {
		got, err := actionFingerprint("tickets", "write", newObject(), newObject(), vArray{}, base, contract, base)
		if err != nil {
			t.Fatal(err)
		}
		if got.fingerprint == want.fingerprint || got.previous == want.previous {
			t.Errorf("%s did not change both identities", name)
		}
	}
	// Each named approval field, in version 2.
	approvals := map[string]func(*sourceApproval){
		"descriptor approval":       func(a *sourceApproval) { a.descriptorPin = pin("f") },
		"owner declaration":         func(a *sourceApproval) { a.ownerDeclarationPin = pin("f") },
		"approved operation":        func(a *sourceApproval) { a.approvedOperation = "other" },
		"approved platform":         func(a *sourceApproval) { a.approvedPlatform = "other" },
		"approved binding":          func(a *sourceApproval) { a.approvedBinding = "tickets@" + pin("f") },
		"platform endpoint":         func(a *sourceApproval) { a.platformEndpoint = "https://other.example" },
		"server command line":       func(a *sourceApproval) { a.command = []string{"/opt/server/bin/tickets", "serve-all"} },
		"server command word order": func(a *sourceApproval) { a.command = []string{"serve", "/opt/server/bin/tickets"} },
		"server arguments":          func(a *sourceApproval) { a.serverArgs = []string{"--read-only"} },
		"image":                     func(a *sourceApproval) { a.image = "registry.example/tickets@" + pin("f") },
		"remote URL":                func(a *sourceApproval) { a.url = "https://other.example/mcp" },
		"fixed headers":             func(a *sourceApproval) { a.headers = []string{"X-Mode=read"} },
		"customer binding":          func(a *sourceApproval) { a.customer = false },
		"sandbox source":            func(a *sourceApproval) { a.sandboxSource = "other/write" },
		"approval absent":           nil,
	}
	for name, edit := range approvals {
		spec := changed(func(s *sourceSpec) {
			if edit == nil {
				s.approval = nil
			} else {
				edit(s.approval)
			}
		})
		if fingerprint(spec, base).fingerprint == want.fingerprint || fingerprint(base, spec).fingerprint == want.fingerprint {
			t.Errorf("%s did not change identity version 2", name)
		}
	}
	// The same changes as version 1 read them, from the command line.
	for name, argv := range map[string][]string{
		"descriptor approval": replaceWord(base.argv, "--descriptor-pin=", "--descriptor-pin="+pin("f")),
		"owner declaration":   replaceWord(base.argv, "--owner-declaration-pin=", "--owner-declaration-pin="+pin("f")),
		"platform endpoint":   replaceWord(base.argv, "--endpoint=", "--endpoint=https://other.example"),
		"server command line": replaceWord(base.argv, "serve", "serve-all"),
	} {
		spec := changed(func(s *sourceSpec) { s.argv = argv })
		if fingerprint(spec, base).previous == want.previous || fingerprint(base, spec).previous == want.previous {
			t.Errorf("%s did not change identity version 1", name)
		}
	}
	// The write source's tool is its own; the read-back source is narrowed to
	// its read tool whatever it lists.
	if got := fingerprint(changed(func(s *sourceSpec) { s.tools = []string{"other"} }), base); got.fingerprint == want.fingerprint {
		t.Error("the write tool did not change identity version 2")
	}
	if got := fingerprint(changed(func(s *sourceSpec) { s.argv = replaceWord(s.argv, "--tools=", "--tools=other") }), base); got.previous == want.previous {
		t.Error("the write tool did not change identity version 1")
	}
	if got := fingerprint(base, changed(func(s *sourceSpec) { s.tools = []string{"other", "more"} })); got != want {
		t.Error("the read-back source's listed tools changed the identity")
	}
	if got, err := actionFingerprint("tickets", "write", newObject(), newObject(), vArray{}, changed(func(s *sourceSpec) { s.sandbox.policy = "/broken" }), recovery, base); err == nil || got != (actionIdentity{}) {
		t.Fatal("an unmeasurable sandbox policy identified the action")
	}
}
