package main

import (
	"context"
	"errors"
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

// #351 M1: the fingerprint is the approved identity. What a retry means
// changes it; where the programs are installed, the platform's environment
// and the OS user do not.
func TestActionFingerprintBindsApprovedIdentityNotInstall(t *testing.T) {
	stubSandboxPolicyDigests(t, map[string]string{"/etc/a/policy.json": "policy-v1", "/etc/b/policy.json": "policy-v1", "/etc/c/policy.json": "policy-v2", "/broken": "unmeasurable"})
	base := sourceSpec{
		argv:                 []string{"/opt/gateway-1/adapter-mcp", "--credentials=/home/engine/.credentials/tickets", "--runtime=/usr/bin/docker", "--tools=write", "--sandbox-workspace=/srv/work", "--sandbox-policy=/etc/a/policy.json", "--sandbox-source=tickets/write", "--descriptor-snapshot=/etc/engine.json.descriptors/b.json", "--descriptor-pin=sha256:" + strings.Repeat("b", 64), "--owner-declaration-file=/etc/engine.json.descriptors/c.json", "--owner-declaration-pin=sha256:" + strings.Repeat("c", 64), "--endpoint=https://tickets.example", "--", "/opt/server/bin/tickets", "serve"},
		env:                  []string{"HOME=/home/engine", "PATH=/usr/bin"},
		user:                 "engine-tickets",
		binding:              "tickets@sha256:" + strings.Repeat("a", 64),
		endpoint:             "https://tickets.example",
		sandbox:              &sourceSandbox{helper: "/opt/gateway-1/adapter-sandbox", policy: "/etc/a/policy.json", workspace: "/srv/work", source: "tickets/write"},
		descriptorProvenance: &descriptorProvenance{snapshot: "sha256:" + strings.Repeat("d", 64), statement: "sha256:" + strings.Repeat("e", 64), binding: "tickets@sha256:" + strings.Repeat("a", 64)},
	}
	recovery := &actionRecovery{declaration: newObject(), readBack: &actionReadBack{tool: "read"}}
	fingerprint := func(write, live sourceSpec) string {
		t.Helper()
		got, err := actionFingerprint("tickets", "write", newObject(), newObject(), vArray{}, write, recovery, live)
		if err != nil {
			t.Fatal(err)
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
		edit(&c)
		return c
	}
	same := map[string]sourceSpec{
		"adapter installed elsewhere": changed(func(s *sourceSpec) {
			s.argv = replaceWord(s.argv, "/opt/gateway-1/adapter-mcp", "/opt/gateway-2/adapter-mcp")
		}),
		"credentials path": changed(func(s *sourceSpec) {
			s.argv = replaceWord(s.argv, "--credentials=", "--credentials=/var/lib/engine/tickets")
		}),
		"runtime path": changed(func(s *sourceSpec) { s.argv = replaceWord(s.argv, "--runtime=", "--runtime=/usr/local/bin/docker") }),
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
	differs := map[string]sourceSpec{
		"sandbox presence": changed(func(s *sourceSpec) { s.sandbox = nil }),
		"sandbox selector": changed(func(s *sourceSpec) { s.sandbox.source = "other/write" }),
		"policy bytes":     changed(func(s *sourceSpec) { s.sandbox.policy = "/etc/c/policy.json" }),
		"binding":          changed(func(s *sourceSpec) { s.binding = "tickets@sha256:" + strings.Repeat("f", 64) }),
		"endpoint":         changed(func(s *sourceSpec) { s.endpoint = "https://other.example" }),
		"transport":        changed(func(s *sourceSpec) { s.transport = "http" }),
		"descriptor approval": changed(func(s *sourceSpec) {
			s.argv = replaceWord(s.argv, "--descriptor-pin=", "--descriptor-pin=sha256:"+strings.Repeat("f", 64))
		}),
		"owner declaration": changed(func(s *sourceSpec) {
			s.argv = replaceWord(s.argv, "--owner-declaration-pin=", "--owner-declaration-pin=sha256:"+strings.Repeat("f", 64))
		}),
		"platform endpoint":   changed(func(s *sourceSpec) { s.argv = replaceWord(s.argv, "--endpoint=", "--endpoint=https://other.example") }),
		"server command line": changed(func(s *sourceSpec) { s.argv = replaceWord(s.argv, "serve", "serve-all") }),
		"descriptor provenance": changed(func(s *sourceSpec) {
			s.descriptorProvenance = &descriptorProvenance{snapshot: "sha256:" + strings.Repeat("f", 64), statement: s.descriptorProvenance.statement, binding: s.descriptorProvenance.binding}
		}),
		"descriptor provenance gone": changed(func(s *sourceSpec) { s.descriptorProvenance = nil }),
	}
	for name, spec := range differs {
		if fingerprint(spec, base) == want || fingerprint(base, spec) == want {
			t.Errorf("%s did not change the write and read identities", name)
		}
	}
	// The read-back source is narrowed to its read tool whatever it lists;
	// the write source's tool is its own.
	if fingerprint(changed(func(s *sourceSpec) { s.argv = replaceWord(s.argv, "--tools=", "--tools=other") }), base) == want {
		t.Error("the write tool did not change the action's identity")
	}
	if got, err := actionFingerprint("tickets", "write", newObject(), newObject(), vArray{}, changed(func(s *sourceSpec) { s.sandbox.policy = "/broken" }), recovery, base); err == nil || got != "" {
		t.Fatal("an unmeasurable sandbox policy identified the action")
	}
}
