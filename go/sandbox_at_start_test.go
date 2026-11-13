package main

// measureSandboxAtStart (engineVersion 23; sandbox_at_start.go): the start
// measures each source's sandbox through the probe a launch takes -- the
// sandboxPostureProbe seam, so no helper, launcher or other program runs
// here and nothing needs a privilege -- and refuses to start exactly where a
// launch of the source would be refused.

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// probeReturning is the sandboxPostureProbe seam answering each source by
// its name -- a report of the given mode, backend and state, or err -- and
// counting the probes each source was given.
func probeReturning(t *testing.T, answers map[string]struct {
	mode, backend, state string
	err                  error
}) map[string]int {
	t.Helper()
	saved := sandboxPostureProbe
	t.Cleanup(func() { sandboxPostureProbe = saved })
	calls := map[string]int{}
	sandboxPostureProbe = func(ctx context.Context, spec sourceSpec) (sandboxProbeReport, error) {
		calls[spec.sandbox.source]++
		a, ok := answers[spec.sandbox.source]
		if !ok {
			t.Fatalf("a probe of %s, which no answer was given for", spec.sandbox.source)
		}
		var r sandboxProbeReport
		if a.err != nil {
			return r, a.err
		}
		r.Protection.Mode, r.Protection.Backend, r.Protection.State = a.mode, a.backend, a.state
		r.Protection.Reason = "fixed for " + spec.sandbox.source
		return r, nil
	}
	return calls
}

func wrappedSources(names ...string) map[string]sourceSpec {
	sources := map[string]sourceSpec{}
	for _, name := range names {
		sources[name] = sourceSpec{argv: []string{"adapter-fixture"}, user: "engine-1", sandbox: &sourceSandbox{helper: "adapter-sandbox-fixture", source: name, probe: &sourceSandboxProbe{}}}
	}
	return sources
}

var measuring = engineConfig{measureSandboxAtStart: true}

type probeAnswer = struct {
	mode, backend, state string
	err                  error
}

// Off -- the default, and every file of an earlier version -- the start
// probes nothing and says nothing, whatever a probe would have found.
func TestSandboxAtStartOffProbesNothing(t *testing.T) {
	calls := probeReturning(t, map[string]probeAnswer{"a/live": {"workspace-write", "none", "not-enforced", nil}})
	line, err := sandboxAtStart(engineConfig{}, wrappedSources("a/live"))
	if err != nil || line != "" || len(calls) != 0 {
		t.Fatalf("off: %q %v, probes %v", line, err, calls)
	}
}

// A restricted mode measured as not enforced is a source no launch of
// which starts (sandboxSourceCommand); the engine does not start, and the
// refusal names the source, its mode and backend, and the probe's reason.
func TestSandboxAtStartRefusesAModeNotEnforced(t *testing.T) {
	for _, backend := range []string{"none", "landlock", "bubblewrap"} {
		probeReturning(t, map[string]probeAnswer{"a/live": {"workspace-write", backend, "not-enforced", nil}})
		line, err := sandboxAtStart(measuring, wrappedSources("a/live"))
		want := "measureSandboxAtStart: source a/live: workspace-write is not enforced under " + backend + ": fixed for a/live; the engine does not start"
		if err == nil || line != "" || !strings.HasPrefix(err.Error(), want) {
			t.Fatalf("%s: %q %v", backend, line, err)
		}
	}
}

// A probe that gives no report is refused as a launch refuses it, whatever
// the mode would have been; the cause is given without the path an
// *os.PathError carries.
func TestSandboxAtStartRefusesAProbeWithNoReport(t *testing.T) {
	cause := &os.PathError{Op: "fork/exec", Path: "/somewhere/adapter-sandbox", Err: errors.New("operation not permitted")}
	probeReturning(t, map[string]probeAnswer{"a/live": {err: cause}})
	_, err := sandboxAtStart(measuring, wrappedSources("a/live"))
	if err == nil || !strings.HasPrefix(err.Error(), "measureSandboxAtStart: source a/live: its sandbox check as its user gave no report: fork/exec: operation not permitted; the engine does not start") || strings.Contains(err.Error(), "/somewhere") {
		t.Fatalf("no report: %v", err)
	}
}

// A source the configuration does not wrap is refused: the member
// promises a measurement of every source.
func TestSandboxAtStartRefusesASourceItCannotMeasure(t *testing.T) {
	calls := probeReturning(t, map[string]probeAnswer{})
	sources := map[string]sourceSpec{"a/live": {argv: []string{"adapter-fixture"}, user: "engine-1"}}
	_, err := sandboxAtStart(measuring, sources)
	if err == nil || !strings.HasPrefix(err.Error(), "measureSandboxAtStart: source a/live: the configuration does not select the adapter sandbox wrapper for it; the engine does not start") || len(calls) != 0 {
		t.Fatalf("unwrapped: %v, probes %v", err, calls)
	}
}

// Every source is probed once, in name order, and every one refused is
// named: the operator learns all of them from one start.
func TestSandboxAtStartNamesEverySourceItRefuses(t *testing.T) {
	calls := probeReturning(t, map[string]probeAnswer{
		"a/live":    {"workspace-write", "bubblewrap", "enforced", nil},
		"b/history": {"read-only", "none", "not-enforced", nil},
		"c/live":    {err: errors.New("signal: killed")},
	})
	_, err := sandboxAtStart(measuring, wrappedSources("c/live", "a/live", "b/history"))
	want := "measureSandboxAtStart: source b/history: read-only is not enforced under none: fixed for b/history; source c/live: its sandbox check as its user gave no report: signal: killed; the engine does not start"
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("got %v\nwant %s", err, want)
	}
	if calls["a/live"] != 1 || calls["b/history"] != 1 || calls["c/live"] != 1 {
		t.Fatalf("probes: %v", calls)
	}
}

// What a launch runs under passes: enforced, partial (Landlock's
// measured limits), and danger-full-access, which claims no boundary and
// which the operator chose; the line names each source's measurement.
func TestSandboxAtStartPassesWhatALaunchRunsUnder(t *testing.T) {
	probeReturning(t, map[string]probeAnswer{
		"a/live":    {"workspace-write", "bubblewrap", "enforced", nil},
		"b/history": {"workspace-write", "landlock", "partial", nil},
		"c/live":    {"danger-full-access", "none", "not-enforced", nil},
	})
	line, err := sandboxAtStart(measuring, wrappedSources("a/live", "b/history", "c/live"))
	want := "measureSandboxAtStart: measured a/live workspace-write bubblewrap enforced, b/history workspace-write landlock partial, c/live danger-full-access none not-enforced"
	if err != nil || line != want {
		t.Fatalf("got %q %v\nwant %q", line, err, want)
	}
	if line, err := sandboxAtStart(measuring, map[string]sourceSpec{}); err != nil || line != "measureSandboxAtStart: the configuration has no source to measure" {
		t.Fatalf("no sources: %q %v", line, err)
	}
}

// Each probe is bounded by a launch's own budget, so a helper that hangs
// ends the start in a bounded time, refused.
func TestSandboxAtStartBoundsEachProbe(t *testing.T) {
	saved := sandboxPostureProbe
	t.Cleanup(func() { sandboxPostureProbe = saved })
	sandboxPostureProbe = func(ctx context.Context, spec sourceSpec) (sandboxProbeReport, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > sandboxLaunchProbeTimeout {
			t.Fatalf("a probe without a launch's budget: %v %v", deadline, ok)
		}
		return sandboxProbeReport{}, context.DeadlineExceeded
	}
	if _, err := sandboxAtStart(measuring, wrappedSources("a/live")); err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("hung probe: %v", err)
	}
}

// The start's measurement is the one each launch is then bound to: the
// probe is kept for the source, and a launch after the start runs none.
func TestSandboxAtStartIsWhatTheLaunchIsBoundTo(t *testing.T) {
	saved := runSourceSandboxProbe
	t.Cleanup(func() { runSourceSandboxProbe = saved })
	runs := 0
	runSourceSandboxProbe = func(context.Context, sourceSpec) (sandboxProbeReport, error) {
		runs++
		var r sandboxProbeReport
		r.Protection.Mode, r.Protection.Backend, r.Protection.State, r.PolicyDigest = "workspace-write", "bubblewrap", "enforced", "sha256:"+strings.Repeat("ab", 32)
		return r, nil
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string]sourceSpec{"a/live": {argv: []string{self}, sandbox: &sourceSandbox{helper: self, source: "a/live", workspace: t.TempDir(), probe: &sourceSandboxProbe{}}}}
	if _, err := sandboxAtStart(measuring, sources); err != nil || runs != 1 {
		t.Fatalf("start: %v, %d probes", err, runs)
	}
	cmd, err := sandboxSourceCommand(context.Background(), sources["a/live"], self, []string{self})
	if err != nil || runs != 1 || !strings.Contains(strings.Join(cmd.Args, " "), "--expect-backend=bubblewrap") {
		t.Fatalf("launch: %v, %d probes", err, runs)
	}
}

// The member: version 23, true or false and nothing else, refused by name
// in a file of an earlier version.
func TestTheMeasureSandboxAtStartMember(t *testing.T) {
	catalog := t.TempDir()
	at := func(version, extra string) string {
		return strings.Replace(engineJSON(t, catalog, extra, ``), `"engineVersion":"1"`, `"engineVersion":"`+version+`"`, 1)
	}
	for _, tc := range []struct {
		name, text string
		on         bool
	}{
		{"version 23 without it", at("23", ``), false},
		{"version 23, false", at("23", `,"measureSandboxAtStart":false`), false},
		{"version 23, true", at("23", `,"measureSandboxAtStart":true`), true},
	} {
		cfg, err := parseEngineConfig([]byte(tc.text))
		if err != nil || cfg.measureSandboxAtStart != tc.on {
			t.Fatalf("%s: %v %v", tc.name, err, cfg.measureSandboxAtStart)
		}
	}
	for _, tc := range []struct{ name, text, want string }{
		{"version 22", at("22", `,"measureSandboxAtStart":true`), "engine configuration: measureSandboxAtStart is a version-23 member; engineVersion 22 has no measureSandboxAtStart"},
		{"version 13, false", at("13", `,"measureSandboxAtStart":false`), "engine configuration: measureSandboxAtStart is a version-23 member; engineVersion 13 has no measureSandboxAtStart"},
		{"a string", at("23", `,"measureSandboxAtStart":"true"`), "engine configuration: measureSandboxAtStart, when present, is true or false"},
		{"a number", at("23", `,"measureSandboxAtStart":1`), "engine configuration: measureSandboxAtStart, when present, is true or false"},
	} {
		if _, err := parseEngineConfig([]byte(tc.text)); err == nil || err.Error() != tc.want {
			t.Fatalf("%s: %v", tc.name, err)
		}
	}
}
