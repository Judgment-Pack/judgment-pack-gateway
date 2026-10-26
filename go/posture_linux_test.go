//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func groupKill(g *sourceGroup, _ *exec.Cmd) { g.kill() }

// The test's own probe modes, beside the probe's (posture_linux.go): a
// child whose grandchild leaves the source's process group (setsid) and
// does not end at the end of its input, so the group's kill misses it and
// closing the input does not end it either. It ends at its own bound.
const (
	postureStrayChildArg      = "_posture-probe-stray-child"
	postureStrayGrandchildArg = "_posture-probe-stray-grandchild"
)

func init() {
	if os.Getenv(envPostureProbe) != "1" || len(os.Args) < 2 {
		return
	}
	switch os.Args[1] {
	case postureStrayChildArg:
		grandchild := exec.Command("/proc/self/exe", postureStrayGrandchildArg)
		grandchild.Env = []string{envPostureProbe + "=1"}
		grandchild.Stdin, grandchild.Stdout = os.Stdin, os.Stdout
		grandchild.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := grandchild.Start(); err != nil {
			os.Exit(3)
		}
		fmt.Fprintf(os.Stdout, "child %d\n", os.Getpid())
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	case postureStrayGrandchildArg:
		fmt.Fprintf(os.Stdout, "grandchild %d\n", os.Getpid())
		time.Sleep(postureProbeLifetime)
		os.Exit(0)
	}
}

// The descendants' probe on this host: the source group's own kill leaves
// no grandchild, and a kill that reaches the direct child alone leaves
// one, which the probe reports and then ends.
func TestPostureDescendantProbeFlips(t *testing.T) {
	line, verdict := probeDescendants(postureChildArg, groupKill)
	if !verdict || line.name != protectionDescendants || line.state != postureEnforced {
		t.Fatalf("the group's kill: %+v", line)
	}
	if got := descendantPosture(); got.name != line.name || got.state != line.state ||
		!strings.HasPrefix(got.reason, line.reason+"; checked at ") {
		t.Fatalf("the report's line is the probe's: %+v", got)
	}
	start := time.Now()
	line, verdict = probeDescendants(postureChildArg, func(_ *sourceGroup, child *exec.Cmd) { _ = child.Process.Kill() })
	if !verdict || line.state != postureNotEnforced || !strings.Contains(line.reason, "survived the group's kill") {
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

// A grandchild that left the source's group and does not end at the end of
// its input: the group's kill misses it, the probe says so, and endProbe
// ends it by its pid, leaving nothing behind.
func TestPostureProbeEndsAGrandchildOutsideTheGroupByItsPid(t *testing.T) {
	line, verdict := probeDescendants(postureStrayChildArg, groupKill)
	left := probeProcesses(t)
	for _, pid := range left {
		if n, err := strconv.Atoi(pid); err == nil {
			_ = syscall.Kill(n, syscall.SIGKILL)
		}
	}
	if !verdict || line.state != postureNotEnforced || !strings.Contains(line.reason, "survived the group's kill") {
		t.Fatalf("a grandchild outside the group: %+v", line)
	}
	if len(left) > 0 {
		t.Fatalf("the grandchild outside the group was not ended by its pid: %v", left)
	}
}

// prSetChildSubreaper is prctl's PR_SET_CHILD_SUBREAPER.
const prSetChildSubreaper = 36

// As PID 1 the probe's grandchild, orphaned when the child dies, is this
// process's own, and the probe waits for it. Being PID 1 takes a PID
// namespace; a child subreaper, which any process may become, adopts its
// descendants' orphans the same way, so the test becomes one and says it
// is PID 1. Not PID 1, the grandchild is left to its reaper, here the test,
// which shows the stand-in holds: a zombie of the test's own.
func TestPostureProbeReapsItsGrandchildAsPID1(t *testing.T) {
	if _, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, prSetChildSubreaper, 1, 0, 0, 0, 0); errno != 0 {
		t.Fatalf("prctl(PR_SET_CHILD_SUBREAPER): %v", errno)
	}
	t.Cleanup(func() {
		_, _, _ = syscall.RawSyscall6(syscall.SYS_PRCTL, prSetChildSubreaper, 0, 0, 0, 0, 0)
		for _, pid := range adoptedZombies(t, 0) {
			var status syscall.WaitStatus
			_, _ = syscall.Wait4(pid, &status, 0, nil)
		}
	})
	initial := postureIsInit
	t.Cleanup(func() { postureIsInit = initial })

	postureIsInit = func() bool { return false }
	if line, _ := probeDescendants(postureChildArg, groupKill); line.state != postureEnforced {
		t.Fatalf("the group's kill: %+v", line)
	}
	zombies := adoptedZombies(t, postureProbeWait)
	if len(zombies) != 1 {
		t.Fatalf("not PID 1, the grandchild is left to its reaper: %v", zombies)
	}
	var status syscall.WaitStatus
	_, _ = syscall.Wait4(zombies[0], &status, 0, nil)

	postureIsInit = func() bool { return true }
	if line, _ := probeDescendants(postureChildArg, groupKill); line.state != postureEnforced {
		t.Fatalf("the group's kill, as PID 1: %+v", line)
	}
	deadline := time.Now().Add(postureProbeWait)
	for len(adoptedZombies(t, 0)) > 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if left := adoptedZombies(t, 0); len(left) > 0 {
		t.Fatalf("as PID 1 the probe left its grandchild a zombie: %v", left)
	}
}

// adoptedZombies is the zombies whose parent is this process, waiting up
// to wait for one to show.
func adoptedZombies(t *testing.T, wait time.Duration) []int {
	t.Helper()
	deadline := time.Now().Add(wait)
	for {
		var zombies []int
		entries, err := os.ReadDir("/proc")
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			pid, err := strconv.Atoi(e.Name())
			if err != nil {
				continue
			}
			stat, err := os.ReadFile("/proc/" + e.Name() + "/stat")
			if err != nil {
				continue
			}
			// pid (comm) state ppid ...
			fields := strings.Fields(string(stat[bytes.LastIndexByte(stat, ')')+1:]))
			if len(fields) > 1 && fields[0] == "Z" && fields[1] == strconv.Itoa(os.Getpid()) {
				zombies = append(zombies, pid)
			}
		}
		if len(zombies) > 0 || !time.Now().Before(deadline) {
			return zombies
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The descendants' line is kept for the process once a probe reaches a
// verdict: two concurrent /posture calls start one probe between them, and
// both answer the same bytes, saying when it was checked. A probe that
// reached no verdict is not kept, and the next call probes again.
func TestPostureProbeIsKeptForTheProcess(t *testing.T) {
	initialCheck, initialProbe := descendants, descendantProbe
	t.Cleanup(func() { descendants, descendantProbe = initialCheck, initialProbe })
	var mu sync.Mutex
	probes, verdict := 0, false
	descendantProbe = func() (postureLine, bool) {
		mu.Lock()
		probes++
		v := verdict
		mu.Unlock()
		time.Sleep(200 * time.Millisecond) // long enough for the calls to meet
		return postureLine{protectionDescendants, postureEnforced, "probed"}, v
	}
	_, server := testService(t)
	get := func() []byte {
		resp, err := http.Get(server.URL + "/posture")
		if err != nil {
			t.Error(err)
			return nil
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return body
	}
	concurrently := func() [2][]byte {
		var bodies [2][]byte
		var wg sync.WaitGroup
		for i := range bodies {
			wg.Add(1)
			go func() { defer wg.Done(); bodies[i] = get() }()
		}
		wg.Wait()
		return bodies
	}
	counted := func() int { mu.Lock(); defer mu.Unlock(); return probes }

	// no verdict: not kept, so each call probes, one at a time
	descendants = &descendantCheck{}
	concurrently()
	if n := counted(); n != 2 {
		t.Fatalf("a probe without a verdict is not kept: %d probes for two calls", n)
	}

	mu.Lock()
	probes, verdict = 0, true
	mu.Unlock()
	descendants = &descendantCheck{}
	bodies := concurrently()
	if n := counted(); n != 1 {
		t.Fatalf("two concurrent calls started %d probes", n)
	}
	if !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatalf("the two calls answered differently:\n%s\n%s", bodies[0], bodies[1])
	}
	_, reason := postureLineIn(t, bodies[0], protectionDescendants)
	at, ok := strings.CutPrefix(reason, "probed; checked at ")
	if _, err := time.Parse(time.RFC3339, at); !ok || err != nil {
		t.Fatalf("the reason says when it was checked: %q", reason)
	}
	if again := get(); !bytes.Equal(again, bodies[0]) || counted() != 1 {
		t.Fatalf("a later call probes again: %d probes\n%s", counted(), again)
	}
}
