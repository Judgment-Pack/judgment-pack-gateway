//go:build linux

package main

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The descendants' probe on this host: the source group's own kill leaves
// no grandchild, and a kill that reaches the direct child alone leaves
// one, which the probe reports and then ends.
func TestPostureDescendantProbeFlips(t *testing.T) {
	line := probeDescendants(func(g *sourceGroup, _ *exec.Cmd) { g.kill() })
	if line.name != protectionDescendants || line.state != postureEnforced {
		t.Fatalf("the group's kill: %+v", line)
	}
	if got := descendantPosture(); got != line {
		t.Fatalf("the report's line is the probe's: %+v", got)
	}
	start := time.Now()
	line = probeDescendants(func(_ *sourceGroup, child *exec.Cmd) { _ = child.Process.Kill() })
	if line.state != postureNotEnforced || !strings.Contains(line.reason, "survived the group's kill") {
		t.Fatalf("a kill of the direct child alone: %+v", line)
	}
	if elapsed := time.Since(start); elapsed > 3*postureProbeWait {
		t.Fatalf("the probe took %s", elapsed)
	}
	if left := probeProcesses(t); len(left) > 0 {
		t.Fatalf("the probe left processes running: %v", left)
	}
}

// probeProcesses lists this process's probe children still alive, by the
// marker in their environment, after a bounded wait for them to go.
func probeProcesses(t *testing.T) []string {
	t.Helper()
	deadline := time.Now().Add(2 * postureProbeWait)
	for {
		var left []string
		entries, err := os.ReadDir("/proc")
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			environ, err := os.ReadFile("/proc/" + e.Name() + "/environ")
			if err != nil || !strings.Contains(string(environ), envPostureProbe+"=1") {
				continue
			}
			if stat, err := os.ReadFile("/proc/" + e.Name() + "/stat"); err == nil && !strings.Contains(string(stat), ") Z ") {
				left = append(left, e.Name())
			}
		}
		if len(left) == 0 || time.Now().After(deadline) {
			return left
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A probe mode needs the pipe the probe holds on stdin: started any other
// way, with the marker and the argument, it exits at once with a failure.
func TestPostureProbeModeNeedsAPipe(t *testing.T) {
	for _, arg := range []string{postureChildArg, postureGrandchildArg} {
		cmd := exec.Command("/proc/self/exe", arg)
		cmd.Env = []string{envPostureProbe + "=1"}
		devnull, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stdin = devnull
		err = cmd.Run()
		devnull.Close()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 2 {
			t.Fatalf("%s without a pipe: %v", arg, err)
		}
	}
}

// The custody line, flipped one marker at a time from the engine image's
// facts; and this host, which is not the image, is not under its custody.
func TestPostureCustodyFlips(t *testing.T) {
	image := func() custodyFacts {
		return custodyFacts{
			executable: imageGateway, exeOwner: 65532, exeMode: 0o700, capabilities: true, euid: 65532,
			sets: capabilitySets{effective: 1<<5 | 1<<6 | 1<<7, permitted: 1<<5 | 1<<6 | 1<<7, known: true},
			trees: map[string]treeFact{
				imageTrees[0]: {directory: true, owner: 0, mode: 0o755},
				imageTrees[1]: {directory: true, owner: 0, mode: 0o755},
			},
		}
	}
	for _, public := range []bool{false, true} {
		if line := judgeCustody(image(), public); line.name != protectionContainerCustody || line.state != postureEnforced {
			t.Fatalf("the image as built: %+v", line)
		}
	}
	for _, tc := range []struct {
		name   string
		change func(*custodyFacts)
		reason string
	}{
		{"not the image", func(f *custodyFacts) {
			f.executable = "/opt/gateway"
			f.trees = map[string]treeFact{imageTrees[0]: {err: os.ErrNotExist}, imageTrees[1]: {err: os.ErrNotExist}}
		}, "does not run from the engine image"},
		{"another binary in the image", func(f *custodyFacts) { f.executable = "/usr/local/bin/engine-mcp" }, "not the engine image's"},
		{"running binary unreadable", func(f *custodyFacts) {
			f.exeErr = &os.PathError{Op: "open", Path: "/proc/self/exe", Err: os.ErrPermission}
		}, "could not be examined"},
		{"root signer", func(f *custodyFacts) { f.euid, f.exeOwner = 0, 0 }, "runs as root"},
		{"binary another user's", func(f *custodyFacts) { f.exeOwner = 0 }, "not the signer's own at mode 0700"},
		{"binary executable by others", func(f *custodyFacts) { f.exeMode = 0o755 }, "not the signer's own at mode 0700"},
		{"no file capabilities", func(f *custodyFacts) { f.capabilities = false }, "carries no file capabilities"},
		{"capabilities unknown", func(f *custodyFacts) { f.sets = capabilitySets{} }, "does not report"},
		{"CAP_KILL dropped", func(f *custodyFacts) { f.sets.effective &^= 1 << 5 }, "lacks CAP_KILL"},
		// the three and nothing more (capabilityRefusal), one set at a time
		{"CAP_DAC_OVERRIDE in effect", func(f *custodyFacts) { f.sets.effective |= 1 << capDacOverride }, "CAP_DAC_OVERRIDE or CAP_DAC_READ_SEARCH"},
		{"CAP_DAC_READ_SEARCH permitted", func(f *custodyFacts) { f.sets.permitted |= 1 << capDacReadSearch }, "CAP_DAC_OVERRIDE or CAP_DAC_READ_SEARCH"},
		{"an ambient capability", func(f *custodyFacts) { f.sets.ambient = 1 << 5 }, "ambient capabilities"},
		{"an inheritable capability", func(f *custodyFacts) { f.sets.inheritable = 1 << 7 }, "inheritable capabilities"},
		{"corpus missing", func(f *custodyFacts) {
			f.trees[imageTrees[1]] = treeFact{err: &os.PathError{Op: "lstat", Path: imageTrees[1], Err: os.ErrNotExist}}
		}, "could not be examined"},
		{"catalog writable by others", func(f *custodyFacts) { f.trees[imageTrees[0]] = treeFact{directory: true, owner: 0, mode: 0o757} }, "nobody else may write"},
		{"catalog writable by group", func(f *custodyFacts) { f.trees[imageTrees[0]] = treeFact{directory: true, owner: 0, mode: 0o775} }, "nobody else may write"},
		{"corpus not root's", func(f *custodyFacts) { f.trees[imageTrees[1]] = treeFact{directory: true, owner: 65532, mode: 0o755} }, "nobody else may write"},
		{"corpus a file", func(f *custodyFacts) { f.trees[imageTrees[1]] = treeFact{owner: 0, mode: 0o644} }, "nobody else may write"},
	} {
		facts := image()
		tc.change(&facts)
		if line := judgeCustody(facts, false); line.state != postureNotEnforced || !strings.Contains(line.reason, tc.reason) {
			t.Fatalf("%s: %+v", tc.name, line)
		}
		// /posture's form of the same line: as not enforced, naming no path
		if line := judgeCustody(facts, true); line.state != postureNotEnforced || strings.Contains(line.reason, "/") {
			t.Fatalf("%s, as /posture says it: %+v", tc.name, line)
		}
	}
	// The test binary is not the image's gateway: gathered here, the line
	// is not enforced.
	if line := custodyPosture(false); line.state != postureNotEnforced {
		t.Fatalf("this host: %+v", line)
	}
}
