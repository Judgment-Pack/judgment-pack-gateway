package main

import (
	"context"
	"encoding/json"
	"errors"
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
		row["policyDigest"] = "none"
		encoded, _ := json.Marshal(row)
		if _, err := decodeSandboxProbe(encoded); err != nil {
			t.Fatalf("shared settings: %s: %v", encoded, err)
		}
	}
}

func TestSandboxProbeRejectsFalseClaims(t *testing.T) {
	good := `{"preset":"review","policyDigest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","settings":{"mode":"read-only","approval":"always","operations":["ask","check","discover","read"]},"protection":{"mode":"read-only","backend":"landlock","state":"partial","reason":"metadata remains writable"}}`
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
		{`"backend":"landlock","state":"partial"`, `"backend":"seatbelt","state":"enforced"`},
		{`"backend":"landlock"`, `"backend":"none"`},
		{`"backend":"landlock"`, `"backend":"unknown"`},
		{`"backend":"landlock"`, `"backend":"windows-restricted-token"`},
		{`"state":"partial"`, `"state":"not-applicable"`},
		{`"reason":"metadata remains writable"`, `"reason":""`},
		{`"settings":`, `"Settings":`},
		{`"preset":"review"`, `"preset":"review","preset":"review"`},
		{`"mode":"read-only"`, `"mode":"danger-full-access"`},
		{`"policyDigest":"sha256:0123`, `"policyDigest":"sha256:ABCD`},
		{`"policyDigest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"`, `"policyDigest":""`},
		{`"policyDigest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",`, ``},
		{`"policyDigest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"`, `"policyDigest":"sha256:0123"`},
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
	stubSandboxProbe(t, `{"preset":"custom","policyDigest":"none","settings":{"mode":"workspace-write","approval":"","operations":null},"protection":{"mode":"workspace-write","backend":"landlock","state":"partial","reason":"fixed probe"}}`, nil)
	cmd, err := sandboxSourceCommand(context.Background(), s, self, argv)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{self, "run", "--policy=" + s.sandbox.policy, "--source=fixture/live", "--workspace=" + s.sandbox.workspace, "--expect-mode=workspace-write", "--expect-backend=landlock", "--expect-policy=none", "--", self, "argument with spaces", "--", "--policy=untrusted"}
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
		return decodeSandboxProbe([]byte(`{"preset":"custom","policyDigest":"none","settings":{"mode":"workspace-write","approval":"","operations":null},"protection":{"mode":"workspace-write","backend":"bubblewrap","state":"enforced","reason":"fixed probe"}}`))
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

// stubSandboxProbe replaces the posture probe with one answering raw (or
// failing with err), and counts its calls.
func stubSandboxProbe(t *testing.T, raw string, err error) *int {
	t.Helper()
	saved := sandboxPostureProbe
	t.Cleanup(func() { sandboxPostureProbe = saved })
	calls := new(int)
	sandboxPostureProbe = func(context.Context, sourceSpec) (sandboxProbeReport, error) {
		*calls++
		if err != nil {
			return sandboxProbeReport{}, err
		}
		return decodeSandboxProbe([]byte(raw))
	}
	return calls
}

// A launch is bound to exactly the posture reported for its source: the
// probe's mode, backend and policy digest go to the helper, which refuses to
// run under any other; with no completed probe the launch does not start.
func TestSandboxLaunchIsBoundToReportedPosture(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	argv := []string{self}
	digest := "sha256:" + strings.Repeat("ab", 32)
	for _, c := range []struct {
		name, mode, backend, state string
		classes                    []string
		runtime                    bool
	}{
		{"bubblewrap", "workspace-write", "bubblewrap", "enforced", []string{"adapter"}, false},
		{"landlock", "read-only", "landlock", "partial", []string{"adapter", "customer-command"}, false},
		{"full access", "danger-full-access", "none", "not-enforced", []string{"adapter"}, false},
		{"image source", "workspace-write", "bubblewrap", "partial", []string{"adapter", "container-helper"}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			raw := `{"preset":"custom","policyDigest":"` + digest + `","settings":{"mode":"` + c.mode + `","approval":"","operations":null},"protection":{"mode":"` + c.mode + `","backend":"` + c.backend + `","state":"` + c.state + `","reason":"fixed probe"}}`
			calls := stubSandboxProbe(t, raw, nil)
			spec := sourceSpec{argv: argv, sandbox: &sourceSandbox{helper: self, source: "fixture/live", workspace: t.TempDir(), policy: "/policy.json", classes: c.classes}}
			// What posture reports for the source ...
			programs := sourceProgramPosture(map[string]sourceSpec{"fixture/live": spec})
			if len(programs) == 0 || programs[0].report.Protection.Backend != c.backend || programs[0].report.Protection.Mode != c.mode {
				t.Fatalf("posture: %+v", programs)
			}
			// ... is what the launch is bound to.
			cmd, err := sandboxSourceCommand(context.Background(), spec, self, argv)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"--expect-mode=" + c.mode, "--expect-backend=" + c.backend, "--expect-policy=" + digest} {
				if !contains(cmd.Args, want) {
					t.Fatalf("launch not bound to posture (%s): %v", want, cmd.Args)
				}
			}
			if contains(cmd.Args, "--container-runtime") != c.runtime {
				t.Fatalf("runtime socket choice differs from the probe's: %v", cmd.Args)
			}
			if *calls != 2 {
				t.Fatalf("posture and launch each consult the probe once: %d", *calls)
			}
		})
	}
	stubSandboxProbe(t, "", errors.New("probe did not complete"))
	spec := sourceSpec{argv: argv, sandbox: &sourceSandbox{helper: self, source: "fixture/live", workspace: t.TempDir()}}
	if cmd, err := sandboxSourceCommand(context.Background(), spec, self, argv); err == nil || cmd != nil || !strings.Contains(err.Error(), "sandbox-not-enforced:") {
		t.Fatalf("launch without a measured posture: %v %v", cmd, err)
	}
	spec.sandbox.helper = "adapter-sandbox"
	if _, err := sandboxSourceCommand(context.Background(), spec, self, argv); err == nil {
		t.Fatal("an unheld helper name was looked up")
	}
}

// The probe and the launch name the same selection, runtime sockets included.
func TestSandboxProbeAndLaunchShareSelection(t *testing.T) {
	s := &sourceSandbox{policy: "/p.json", source: "a/history", workspace: "/w", classes: []string{"adapter", "container-helper"}}
	probe, run := sandboxHelperArgs(s, "probe"), sandboxHelperArgs(s, "run")
	if !reflect.DeepEqual(probe[1:], run[1:]) || !contains(probe, "--container-runtime") {
		t.Fatalf("probe %v, run %v", probe, run)
	}
	s.classes = []string{"adapter"}
	if contains(sandboxHelperArgs(s, "probe"), "--container-runtime") {
		t.Fatal("a source with no runtime client keeps runtime sockets")
	}
}

// A policy file must lie outside every configured workspace, another
// source's included.
func TestSandboxPolicyOutsideEveryWorkspace(t *testing.T) {
	other := t.TempDir()
	workspace := t.TempDir()
	op := &operation{name: "live", command: []string{"fixture"}, workspace: workspace, customer: true}
	bindings := map[string]binding{"fixture": {live: op}, "fixture2": {history: &operation{name: "history"}}}
	cfg := engineConfig{platforms: []platformConfig{{name: "fixture"}, {name: "fixture2"}}, sandbox: &engineSandbox{workspaces: map[string]string{}}}
	if err := validateEngineSandbox(cfg, bindings); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(){
		"engine policy inside a customer workspace":  func() { cfg.sandbox.policy = filepath.Join(workspace, "policy.json") },
		"binding policy inside a customer workspace": func() { op.sandboxPolicy = filepath.Join(workspace, "sub", "policy.json") },
		"engine policy inside another workspace": func() {
			cfg.sandbox.policy = filepath.Join(other, "policy.json")
			cfg.sandbox.workspaces["fixture2/history"] = other
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg.sandbox, op.sandboxPolicy = &engineSandbox{workspaces: map[string]string{}}, ""
			mutate()
			if err := validateEngineSandbox(cfg, bindings); err == nil || !strings.Contains(err.Error(), "outside every configured workspace") {
				t.Fatalf("policy inside a workspace accepted: %v", err)
			}
		})
	}
	cfg.sandbox, op.sandboxPolicy = &engineSandbox{policy: filepath.Join(t.TempDir(), "policy.json"), workspaces: map[string]string{"fixture2/history": other}}, ""
	if err := validateEngineSandbox(cfg, bindings); err != nil {
		t.Fatal(err)
	}
}

// Every wrapped source -- not only a customer command -- refuses a platform
// environment that names a dynamic-loader variable.
func TestWrappedSourceRefusesLoaderEnvironment(t *testing.T) {
	bindings := map[string]binding{"fixture": {history: &operation{name: "history"}}}
	for _, name := range []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "GCONV_PATH"} {
		cfg := engineConfig{platforms: []platformConfig{{name: "fixture", environment: []string{"SERVICE_MODE=1", name + "=library.so"}}}, sandbox: &engineSandbox{workspaces: map[string]string{}}}
		if len(deriveSources(cfg, bindings)) == 0 {
			t.Fatal("fixture derives no source")
		}
		if err := validateEngineSandbox(cfg, bindings); err == nil || !strings.Contains(err.Error(), "sandbox-loader-variable-refused:") {
			t.Fatalf("%s: %v", name, err)
		}
		cfg.sandbox = nil // engine versions before 13 wrap nothing
		if err := validateEngineSandbox(cfg, bindings); err != nil {
			t.Fatal(err)
		}
	}
}

// A launch whose completed probe measured the boundary as not holding
// refuses, as a launch with no backend does; full access, which claims no
// boundary, still runs.
func TestSandboxLaunchRefusesAMeasuredFailure(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	argv := []string{self}
	for _, backend := range []string{"landlock", "bubblewrap", "none"} {
		stubSandboxProbe(t, `{"preset":"custom","policyDigest":"none","settings":{"mode":"workspace-write","approval":"","operations":null},"protection":{"mode":"workspace-write","backend":"`+backend+`","state":"not-enforced","reason":"sandbox-not-enforced: observed writes do not match the selected mode"}}`, nil)
		spec := sourceSpec{argv: argv, sandbox: &sourceSandbox{helper: self, source: "fixture/live", workspace: t.TempDir()}}
		if cmd, err := sandboxSourceCommand(context.Background(), spec, self, argv); err == nil || cmd != nil || !strings.Contains(err.Error(), "sandbox-not-enforced:") {
			t.Fatalf("%s measured failing: %v %v", backend, cmd, err)
		}
	}
	stubSandboxProbe(t, `{"preset":"custom","policyDigest":"none","settings":{"mode":"danger-full-access","approval":"","operations":null},"protection":{"mode":"danger-full-access","backend":"none","state":"not-enforced","reason":"the operator explicitly selected unrestricted filesystem access"}}`, nil)
	spec := sourceSpec{argv: argv, sandbox: &sourceSandbox{helper: self, source: "fixture/live", workspace: t.TempDir()}}
	if _, err := sandboxSourceCommand(context.Background(), spec, self, argv); err != nil {
		t.Fatalf("full access: %v", err)
	}
}

// A probe that timed out is not kept: the next posture or launch probes again.
func TestSandboxProbeTimeoutIsNotCached(t *testing.T) {
	saved := runSourceSandboxProbe
	t.Cleanup(func() { runSourceSandboxProbe = saved })
	calls := 0
	reason := probeTimedOut
	runSourceSandboxProbe = func(context.Context, sourceSpec) (sandboxProbeReport, error) {
		calls++
		var r sandboxProbeReport
		r.Protection.Mode, r.Protection.Backend, r.Protection.State, r.Protection.Reason = "workspace-write", "landlock", "not-enforced", reason
		if reason != probeTimedOut {
			r.Protection.State = "partial"
		}
		return r, nil
	}
	spec := sourceSpec{sandbox: &sourceSandbox{probe: &sourceSandboxProbe{}}}
	probeSourceSandbox(context.Background(), spec)
	probeSourceSandbox(context.Background(), spec)
	if calls != 2 {
		t.Fatalf("a timed-out probe was kept: %d probes", calls)
	}
	reason = "measured"
	probeSourceSandbox(context.Background(), spec)
	probeSourceSandbox(context.Background(), spec)
	if calls != 3 {
		t.Fatalf("a completed probe was not kept: %d probes", calls)
	}
}

// /posture names no path, no home directory and no uid in any reason; the
// operator's own report keeps the helper's words.
func TestPublicPostureReasonsNameNoPathOrAccount(t *testing.T) {
	uid := "4242"
	home := filepath.Join("/", "home", "someone-"+uid)
	helperReason := "filesystem mounts are read-only outside the declared writable directories (launcher /usr/bin/bwrap); masked inside the sandbox: /run/user/" + uid + ", " + home + "/.docker/run/docker.sock; sandbox-launcher-untrusted: /usr/local/bin/bwrap is not owned by root along its path"
	sources := map[string]sourceSpec{}
	for i, c := range []struct{ backend, state string }{{"bubblewrap", "enforced"}, {"bubblewrap", "partial"}, {"landlock", "partial"}, {"seatbelt", "partial"}, {"none", "not-enforced"}} {
		name := string(rune('a'+i)) + "/live"
		// Encoded, not spliced: a Windows path holds backslashes.
		reason, _ := json.Marshal(helperReason)
		raw := `{"preset":"custom","policyDigest":"none","settings":{"mode":"workspace-write","approval":"","operations":null},"protection":{"mode":"workspace-write","backend":"` + c.backend + `","state":"` + c.state + `","reason":` + string(reason) + `}}`
		report, err := decodeSandboxProbe([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		probe := &sourceSandboxProbe{done: true, report: report}
		sources[name] = sourceSpec{sandbox: &sourceSandbox{probe: probe, classes: []string{"adapter", "customer-command", "container-helper"}}}
	}
	sources["z/live"] = sourceSpec{}
	t.Setenv("HOME", home)
	public := hostPosture(postureInput{configured: true, sources: sources, public: true}).canonical()
	parsed, err := parseJSON(public)
	if err != nil {
		t.Fatal(err)
	}
	var reasons []string
	for _, member := range []string{"protections", "programs"} {
		list, _ := parsed.(*vObject).byName[member].(vArray)
		for _, entry := range list {
			reasons = append(reasons, string(entry.(*vObject).byName["reason"].(vString)))
		}
	}
	if len(reasons) < 15 {
		t.Fatalf("too few reasons judged: %d", len(reasons))
	}
	for _, reason := range reasons {
		for i, r := range reason {
			if r == '/' && (i == 0 || strings.ContainsRune(" (\"'=:,", rune(reason[i-1]))) {
				t.Fatalf("a /posture reason names an absolute path: %q", reason)
			}
		}
		if strings.Contains(reason, home) || strings.Contains(reason, uid) || strings.Contains(reason, "someone") {
			t.Fatalf("a /posture reason names an account: %q", reason)
		}
	}
	operator := hostPosture(postureInput{configured: true, sources: sources}).canonical()
	if !strings.Contains(string(operator), "/run/user/"+uid) {
		t.Fatal("the operator's report lost the helper's detail")
	}
}
