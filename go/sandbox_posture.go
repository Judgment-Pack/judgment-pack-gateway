package main

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"slices"
	"sort"
	"time"
)

type sandboxProbeReport struct {
	Settings struct {
		Mode       string   `json:"mode"`
		Approval   string   `json:"approval"`
		Operations []string `json:"operations"`
	} `json:"settings"`
	Preset     string `json:"preset"`
	Protection struct {
		Mode    string `json:"mode"`
		Backend string `json:"backend"`
		State   string `json:"state"`
		Reason  string `json:"reason"`
	} `json:"protection"`
}

type postureProgram struct {
	source, class string
	report        sandboxProbeReport
}

var sandboxPostureProbe = probeSourceSandbox

func sourceProgramPosture(sources map[string]sourceSpec) []postureProgram {
	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}
	sort.Strings(names)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	var programs []postureProgram
	for _, name := range names {
		spec := sources[name]
		classes := []string{"adapter"}
		var report sandboxProbeReport
		report.Preset = "custom"
		report.Protection.Mode, report.Settings.Mode = "unconfigured", "unconfigured"
		report.Protection.Backend, report.Protection.State = "none", postureNotEnforced
		report.Protection.Reason = "this source configuration does not select the adapter sandbox wrapper"
		if spec.sandbox != nil {
			classes = spec.sandbox.classes
			probed, err := sandboxPostureProbe(ctx, spec)
			if err == nil {
				report = probed
			} else {
				report.Protection.Reason = "sandbox-not-enforced: source-user backend check did not complete successfully"
			}
		}
		for _, class := range classes {
			entry := report
			if class == "container-helper" {
				if entry.Protection.State == postureEnforced {
					entry.Protection.State = "partial"
				}
				entry.Protection.Reason += "; this confines the runtime client only, not filesystem writes performed by its external container daemon"
			}
			programs = append(programs, postureProgram{name, class, entry})
		}
	}
	return programs
}

func probeSourceSandbox(ctx context.Context, spec sourceSpec) (sandboxProbeReport, error) {
	if cache := spec.sandbox.probe; cache != nil {
		cache.mu.Lock()
		defer cache.mu.Unlock()
		if cache.done {
			return cache.report, nil
		}
		report, err := runSandboxProbe(ctx, spec)
		if err == nil {
			cache.report, cache.done = report, true
		}
		return report, err
	}
	return runSandboxProbe(ctx, spec)
}

func runSandboxProbe(ctx context.Context, spec sourceSpec) (sandboxProbeReport, error) {
	var report sandboxProbeReport
	if err := ctx.Err(); err != nil {
		return report, err
	}
	s := spec.sandbox
	// The standalone posture command does not run engine startup admission.
	// Hold its helper too: an untrusted executable cannot manufacture evidence.
	helper, err := holdAdapter(s.helper, osEngineHost())
	if err != nil {
		return report, err
	}
	cmd := exec.CommandContext(ctx, helper, "probe", "--policy="+s.policy, "--source="+s.source, "--workspace="+s.workspace)
	cmd.Env = sourceEnvironment(spec)
	group, err := prepareSourceProcess(cmd, spec.user)
	if err != nil {
		return report, err
	}
	defer group.reap()
	cmd.WaitDelay = time.Second
	stdout := &boundedBuffer{limit: 8192}
	stderr := &boundedBuffer{limit: 1024}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err = group.start(cmd); err != nil {
		return report, err
	}
	if err = cmd.Wait(); err != nil {
		return report, err
	}
	if stdout.overflowed {
		return report, errors.New("sandbox probe output exceeds bound")
	}
	return decodeSandboxProbe(stdout.buf.Bytes())
}

func decodeSandboxProbe(raw []byte) (sandboxProbeReport, error) {
	var report sandboxProbeReport
	value, err := parseJSON(raw)
	if err != nil {
		return report, err
	}
	top, err := requireObject(value, "sandbox probe")
	if err != nil {
		return report, err
	}
	if err = exactlyMembers(top, map[string]bool{"settings": true, "preset": true, "protection": true}, "sandbox probe"); err != nil {
		return report, err
	}
	for key, members := range map[string]map[string]bool{
		"settings":   {"mode": true, "approval": true, "operations": true},
		"protection": {"mode": true, "backend": true, "state": true, "reason": true},
	} {
		object, err := requireObject(top.byName[key], key)
		if err != nil {
			return report, err
		}
		if err = exactlyMembers(object, members, key); err != nil {
			return report, err
		}
	}
	if err = json.Unmarshal(raw, &report); err != nil {
		return report, err
	}
	p := report.Protection
	if p.Mode != report.Settings.Mode || p.Reason == "" || (p.Mode != "read-only" && p.Mode != "workspace-write" && p.Mode != "danger-full-access") {
		return report, errors.New("invalid sandbox probe mode")
	}
	if p.State != "enforced" && p.State != "partial" && p.State != "not-enforced" {
		return report, errors.New("invalid sandbox probe state")
	}
	if p.State == "enforced" && p.Backend != "bubblewrap" && p.Backend != "seatbelt" {
		return report, errors.New("unsupported complete-enforcement claim")
	}
	if p.Mode == "danger-full-access" && p.State != "not-enforced" {
		return report, errors.New("unrestricted mode claims enforcement")
	}
	if p.Backend != "none" && p.Backend != "bubblewrap" && p.Backend != "landlock" && p.Backend != "seatbelt" {
		return report, errors.New("invalid sandbox probe backend")
	}
	if p.Backend == "none" && p.State != "not-enforced" {
		return report, errors.New("missing backend claims enforcement")
	}
	approval, ops := report.Settings.Approval, report.Settings.Operations
	if approval == "" {
		if len(ops) != 0 || report.Preset != "custom" {
			return report, errors.New("legacy policy invents permission settings")
		}
	} else {
		if approval != "always" && approval != "policy" {
			return report, errors.New("invalid sandbox approval setting")
		}
		previous := ""
		for _, op := range ops {
			if op <= previous || !slices.Contains([]string{"act", "answer", "ask", "check", "discover", "evaluate", "own-state", "propose", "read", "run", "transform"}, op) {
				return report, errors.New("invalid sandbox operation families")
			}
			previous = op
		}
		if !slices.Contains(ops, "ask") {
			return report, errors.New("sandbox permission settings omit ask")
		}
		preset := "custom"
		if p.Mode == "read-only" && approval == "always" && slices.Equal(ops, []string{"ask", "check", "discover", "read"}) {
			preset = "review"
		}
		if approval == "policy" && slices.Equal(ops, []string{"act", "ask", "check", "discover", "propose", "read"}) {
			if p.Mode == "workspace-write" {
				preset = "work"
			} else if p.Mode == "danger-full-access" {
				preset = "full"
			}
		}
		if report.Preset != preset {
			return report, errors.New("sandbox preset contradicts expanded settings")
		}
	}
	return report, nil
}

func (p postureProgram) value() value {
	v := newObject()
	for key, text := range map[string]string{"source": p.source, "class": p.class, "mode": p.report.Protection.Mode, "backend": p.report.Protection.Backend, "state": p.report.Protection.State, "reason": p.report.Protection.Reason, "preset": p.report.Preset, "approval": p.report.Settings.Approval} {
		v.set(key, vString(text))
	}
	ops := vArray{}
	for _, op := range p.report.Settings.Operations {
		ops = append(ops, vString(op))
	}
	v.set("operations", ops)
	return v
}

func programConfinementPosture(programs []postureProgram) postureLine {
	if len(programs) == 0 {
		return operatorProgramsLine
	}
	all, any := true, false
	for _, p := range programs {
		state := p.report.Protection.State
		all = all && state == postureEnforced
		any = any || state == postureEnforced || state == "partial"
	}
	if !any {
		return operatorProgramsLine
	}
	state := "partial"
	if all {
		state = postureEnforced
	}
	return postureLine{protectionOperatorPrograms, state, "filesystem write-policy checks ran as the configured source users; program entries name their scope and backend limits; reads and network access remain outside this policy"}
}
