package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSandboxProbeSharedSettings(t *testing.T) {
	raw, err := os.ReadFile("../testdata/sandbox-policy/settings.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		settings := row["settings"].(map[string]any)
		row["protection"] = map[string]any{"mode": settings["mode"], "backend": "none", "state": "not-enforced", "reason": "fixed vector; no backend was run"}
		encoded, _ := json.Marshal(row)
		if _, err := decodeSandboxProbe(encoded); err != nil {
			t.Fatalf("shared settings: %s: %v", encoded, err)
		}
	}
}

func TestSandboxProbeRejectsFalseClaims(t *testing.T) {
	good := `{"preset":"review","settings":{"mode":"read-only","approval":"always","operations":["ask","check","discover","read"]},"protection":{"mode":"read-only","backend":"landlock","state":"partial","reason":"metadata remains writable"}}`
	if _, err := decodeSandboxProbe([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range [][2]string{
		{`"preset":"review"`, `"preset":"full"`},
		{`"approval":"always"`, `"approval":"never"`},
		{`"ask",`, ``},
		{`"ask","check"`, `"ask","ask"`},
		{`"ask","check"`, `"check","ask"`},
		{`"read"]`, `"unknown"]`},
		{`"state":"partial"`, `"state":"enforced"`},
		{`"backend":"landlock"`, `"backend":"none"`},
		{`"backend":"landlock"`, `"backend":"unknown"`},
		{`"backend":"landlock"`, `"backend":"windows-restricted-token"`},
		{`"state":"partial"`, `"state":"not-applicable"`},
		{`"reason":"metadata remains writable"`, `"reason":""`},
		{`"settings":`, `"Settings":`},
		{`"preset":"review"`, `"preset":"review","preset":"review"`},
		{`"mode":"read-only"`, `"mode":"danger-full-access"`},
	} {
		bad := strings.Replace(good, mutation[0], mutation[1], 1)
		if bad == good {
			t.Fatal("mutation did not match", mutation)
		}
		if _, err := decodeSandboxProbe([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

func TestSandboxSourceLaunchPreservesOriginalIdentityAndArguments(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	argv := []string{self, "argument with spaces", "--", "--policy=untrusted"}
	s := sourceSpec{argv: argv, sandbox: &sourceSandbox{helper: self, source: "fixture/live", workspace: t.TempDir(), policy: filepath.Join(t.TempDir(), "policy.json")}}
	cmd, err := sandboxSourceCommand(context.Background(), s, self, argv)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{self, "run", "--policy=" + s.sandbox.policy, "--source=fixture/live", "--workspace=" + s.sandbox.workspace, "--", self, "argument with spaces", "--", "--policy=untrusted"}
	if !reflect.DeepEqual(cmd.Args, want) || !reflect.DeepEqual(s.argv, argv) {
		t.Fatalf("launch changed identity or argument boundaries: %v", cmd.Args)
	}
	s.sandbox = nil
	legacy, err := sandboxSourceCommand(context.Background(), s, self, argv)
	if err != nil || !reflect.DeepEqual(legacy.Args, argv) {
		t.Fatalf("legacy launch: %v %v", legacy, err)
	}
}

func TestSandboxSourcePolicyAlignment(t *testing.T) {
	workspace, policy := t.TempDir(), filepath.Join(t.TempDir(), "policy.json")
	op := &operation{name: "live", command: []string{"fixture"}, workspace: workspace, sandboxPolicy: policy, customer: true}
	bindings := map[string]binding{"fixture": {live: op}}
	cfg := engineConfig{platforms: []platformConfig{{name: "fixture"}}, sandbox: &engineSandbox{policy: policy, workspaces: map[string]string{"fixture/live": workspace}}}
	if err := validateEngineSandbox(cfg, bindings); err != nil {
		t.Fatal(err)
	}
	spec := deriveSources(cfg, bindings)["fixture/live"]
	if spec.sandbox.policy != policy || spec.sandbox.workspace != workspace || !reflect.DeepEqual(spec.sandbox.classes, []string{"adapter", "customer-command"}) {
		t.Fatalf("derived selection: %+v", spec.sandbox)
	}
	op.sandboxPolicy = ""
	spec = deriveSources(cfg, bindings)["fixture/live"]
	if !contains(spec.argv, "--sandbox-policy="+policy) || !contains(spec.argv, "--sandbox-enclosing") {
		t.Fatal("effective outer policy was not passed to adapter", spec.argv)
	}
	op.sandboxPolicy = policy
	for name, selection := range map[string]*engineSandbox{
		"unknown source":     {workspaces: map[string]string{"fixture/absent": workspace}},
		"workspace mismatch": {workspaces: map[string]string{"fixture/live": t.TempDir()}},
		"policy mismatch":    {policy: filepath.Join(t.TempDir(), "other.json")},
	} {
		t.Run(name, func(t *testing.T) {
			cfg.sandbox = selection
			if err := validateEngineSandbox(cfg, bindings); err == nil {
				t.Fatal("conflicting selection accepted")
			}
		})
	}
}

func TestSandboxEngineVersionAndShape(t *testing.T) {
	base := engineJSON(t, t.TempDir(), "", "")
	latest := strings.Replace(base, `"engineVersion":"1"`, `"engineVersion":"13"`, 1)
	cfg, err := parseEngineConfig([]byte(latest))
	if err != nil || cfg.sandbox == nil || cfg.sandbox.policy != "" || len(cfg.sandbox.workspaces) != 0 {
		t.Fatalf("default selection: %+v %v", cfg.sandbox, err)
	}
	for _, raw := range []string{`null`, `[]`, `{"policy":""}`, `{"policy":"relative"}`, `{"workspaces":{"":"relative"}}`, `{"mode":"full"}`, `{"workspaces":null}`} {
		candidate := strings.Replace(latest, `"engineVersion":"13"`, `"engineVersion":"13","sandbox":`+raw, 1)
		if _, err := parseEngineConfig([]byte(candidate)); err == nil {
			t.Fatalf("invalid sandbox accepted: %s", raw)
		}
	}
	legacy := strings.Replace(base, `"engineVersion":"1"`, `"engineVersion":"12","sandbox":{}`, 1)
	if _, err := parseEngineConfig([]byte(legacy)); err == nil {
		t.Fatal("new policy accepted under legacy engine version")
	}
}

func TestSandboxPostureIsPerClassAndConservative(t *testing.T) {
	saved := sandboxPostureProbe
	t.Cleanup(func() { sandboxPostureProbe = saved })
	calls := 0
	sandboxPostureProbe = func(_ context.Context, s sourceSpec) (sandboxProbeReport, error) {
		calls++
		return decodeSandboxProbe([]byte(`{"preset":"custom","settings":{"mode":"workspace-write","approval":"","operations":null},"protection":{"mode":"workspace-write","backend":"bubblewrap","state":"enforced","reason":"fixed probe"}}`))
	}
	programs := sourceProgramPosture(map[string]sourceSpec{
		"b/live":    {sandbox: &sourceSandbox{classes: []string{"adapter", "customer-command"}}},
		"a/history": {sandbox: &sourceSandbox{classes: []string{"adapter", "container-helper"}}},
		"c/live":    {},
	})
	if calls != 2 || len(programs) != 5 || programs[0].source != "a/history" || programs[1].class != "container-helper" || programs[1].report.Protection.State != "partial" || programs[4].report.Protection.State != "not-enforced" {
		t.Fatalf("program posture: %+v", programs)
	}
	if programConfinementPosture(programs).state != "partial" {
		t.Fatal("aggregate overstated enforcement")
	}
}
