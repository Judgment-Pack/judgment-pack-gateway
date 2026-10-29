package main

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"
)

type sandboxProbeReport struct {
	Settings struct {
		Mode       string   `json:"mode"`
		Approval   string   `json:"approval"`
		Operations []string `json:"operations"`
	} `json:"settings"`
	Preset       string `json:"preset"`
	PolicyDigest string `json:"policyDigest"`
	Protection   struct {
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
			switch class {
			case "container-helper":
				if entry.Protection.State == postureEnforced {
					entry.Protection.State = "partial"
				}
				entry.Protection.Reason += "; " + containerHelperNote
			case "customer-command":
				entry.Protection.Reason += "; " + customerExecutionNote()
			}
			programs = append(programs, postureProgram{name, class, entry})
		}
	}
	return programs
}

const containerHelperNote = "this confines the runtime client only, not filesystem writes performed by its external container daemon"

// customerExecutionNote says what of a customer command runs as the exact
// bytes approved and what is re-checked by path, and when, on this host.
func customerExecutionNote() string {
	if runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64") {
		return "a customer command's binary runs from a sealed in-memory copy of its approved bytes; a #! script, its interpreters and a script operand are opened by path and digested again immediately before the start, and a change after that re-check is not detected"
	}
	return "a customer command's files are executed or opened by path and digested again immediately before the start, and a change after that re-check is not detected"
}

// probeTimedOut is the reason a probe gives when its backend check did not
// finish in time.
const probeTimedOut = "sandbox-probe-failed: backend check timed out"

// runSourceSandboxProbe runs one probe; a test replaces it.
var runSourceSandboxProbe = runSandboxProbe

func probeSourceSandbox(ctx context.Context, spec sourceSpec) (sandboxProbeReport, error) {
	if cache := spec.sandbox.probe; cache != nil {
		cache.mu.Lock()
		defer cache.mu.Unlock()
		if cache.done {
			return cache.report, nil
		}
		report, err := runSourceSandboxProbe(ctx, spec)
		// A probe that timed out measured nothing: the next posture or
		// launch probes again rather than keep that until a restart.
		if err == nil && report.Protection.Reason != probeTimedOut {
			cache.report, cache.done = report, true
		}
		return report, err
	}
	return runSourceSandboxProbe(ctx, spec)
}

// publicProgramReason is a program entry's reason as /posture answers it: a
// fixed sentence chosen by its mode, backend, state and class, never the
// helper's own words, which name launcher locations, masked paths below a
// user's home or runtime directory, and so accounts and uids. gateway
// posture, run by the operator, keeps the helper's words.
func publicProgramReason(p postureProgram) string {
	protection := p.report.Protection
	var reason string
	switch {
	case protection.Mode == "unconfigured":
		reason = "this source configuration does not select the adapter sandbox wrapper"
	case protection.Mode == "danger-full-access":
		reason = "the operator explicitly selected unrestricted filesystem access"
	case protection.State == postureNotEnforced:
		reason = "the backend check did not establish the selected mode for this source, and its restricted launches refuse; gateway posture, given the configuration, says why"
	case protection.Backend == "bubblewrap" && protection.State == postureEnforced:
		reason = "bubblewrap keeps filesystem mounts read-only outside the declared writable directories and hides the host's listening Unix sockets; network access is unchanged"
	case protection.Backend == "bubblewrap":
		reason = "bubblewrap keeps filesystem mounts read-only outside the declared writable directories; some local sockets stay reachable, and the programs behind them are not confined by this boundary; network access is unchanged"
	case protection.Backend == "landlock":
		reason = "Landlock restricts file-content writes, truncation and directory mutations; metadata changes, connections to local sockets and network access are not restricted"
	case protection.Backend == "seatbelt":
		reason = "Seatbelt denies file writes outside the declared writable directories; connections to local sockets and system services, and network access, are not restricted"
	default:
		reason = "the backend's measured limits are named by gateway posture, given the configuration"
	}
	switch p.class {
	case "container-helper":
		reason += "; " + containerHelperNote
	case "customer-command":
		reason += "; " + customerExecutionNote()
	}
	return reason
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
	cmd := exec.CommandContext(ctx, helper, sandboxHelperArgs(s, "probe")...)
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
	if err = exactlyMembers(top, map[string]bool{"settings": true, "preset": true, "policyDigest": true, "protection": true}, "sandbox probe"); err != nil {
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
	if d := report.PolicyDigest; d != "none" && !(len(d) == len("sha256:")+64 && strings.HasPrefix(d, "sha256:") && strings.Trim(d[len("sha256:"):], "0123456789abcdef") == "") {
		return report, errors.New("invalid sandbox policy digest")
	}
	p := report.Protection
	if p.Mode != report.Settings.Mode || p.Reason == "" || (p.Mode != "read-only" && p.Mode != "workspace-write" && p.Mode != "danger-full-access") {
		return report, errors.New("invalid sandbox probe mode")
	}
	if p.State != "enforced" && p.State != "partial" && p.State != "not-enforced" {
		return report, errors.New("invalid sandbox probe state")
	}
	// Only bubblewrap hides the host's sockets; Seatbelt and Landlock are
	// partial at best.
	if p.State == "enforced" && p.Backend != "bubblewrap" {
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
