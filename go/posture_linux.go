//go:build linux

package main

// The two posture lines Linux checks at run time rather than states:
// whether a source's descendants die with it, by a probe that runs the
// source group's own code, and whether this gateway runs under the engine
// image's custody, by the markers the image is built with
// (docs/design/engine-image.md).

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The probe modes of this executable, selected by envPostureProbe and an
// argument together before main or any test runs. Each requires a pipe
// on stdin -- the one the probe holds -- and reads it to its end: the
// probe ends both by closing it, and a process that merely inherited the
// marker does not sit consuming a terminal. The child starts the
// grandchild on its own stdin and stdout, so the grandchild holds the
// probe's pipes as a source's descendant holds a source's.
func init() {
	if os.Getenv(envPostureProbe) != "1" || len(os.Args) < 2 {
		return
	}
	if os.Args[1] != postureChildArg && os.Args[1] != postureGrandchildArg {
		return
	}
	info, err := os.Stdin.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		os.Exit(2)
	}
	if os.Args[1] == postureChildArg {
		grandchild := exec.Command("/proc/self/exe", postureGrandchildArg)
		grandchild.Env = []string{envPostureProbe + "=1"}
		grandchild.Stdin, grandchild.Stdout = os.Stdin, os.Stdout
		if err := grandchild.Start(); err != nil {
			os.Exit(3)
		}
		fmt.Fprintf(os.Stdout, "child %d\n", os.Getpid())
	} else {
		fmt.Fprintf(os.Stdout, "grandchild %d\n", os.Getpid())
		// bounded, so a grandchild nothing reached ends all the same
		time.AfterFunc(postureProbeLifetime, func() { os.Exit(0) })
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

const (
	// postureProbeWait bounds each wait of the probe: for its two
	// processes to say they are running, and for the pipe they hold to
	// close once the group has been killed.
	postureProbeWait = 3 * time.Second
	// postureProbeLifetime is how long a grandchild that survived
	// everything else lives.
	postureProbeLifetime = 30 * time.Second
)

var (
	descendantsOnce   sync.Once
	descendantsResult postureLine
)

// descendantPosture runs the probe once per process: what it finds is the
// kernel's and this binary's, which do not change while it runs.
func descendantPosture() postureLine {
	descendantsOnce.Do(func() {
		descendantsResult = probeDescendants(func(g *sourceGroup, _ *exec.Cmd) { g.kill() })
	})
	return descendantsResult
}

// probeDescendants starts a child as a source is started -- in an
// anchor-led process group (prepareSourceProcess) -- which starts a
// grandchild of its own; once both are running it stops them with kill,
// which is the group's own kill outside a test, and both must be gone: the
// pipe they held must reach end of file within the wait. One still holding
// it survived, and is ended afterwards by closing its input or, failing
// that, by its pid; the child is waited for only then, so a kill that
// missed it never holds the probe.
func probeDescendants(kill func(*sourceGroup, *exec.Cmd)) postureLine {
	line := func(state, reason string) postureLine { return postureLine{protectionDescendants, state, reason} }
	inRead, inWrite, err := os.Pipe()
	if err != nil {
		return line(postureNotEnforced, "the probe could not run: "+err.Error())
	}
	defer inWrite.Close()
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		inRead.Close()
		return line(postureNotEnforced, "the probe could not run: "+err.Error())
	}
	defer outRead.Close()
	// The context is a backstop only: its Cancel is the group's kill.
	ctx, cancel := context.WithTimeout(context.Background(), postureProbeLifetime)
	defer cancel()
	child := exec.CommandContext(ctx, "/proc/self/exe", postureChildArg)
	child.Env = []string{envPostureProbe + "=1"}
	child.Stdin, child.Stdout = inRead, outWrite
	group, err := prepareSourceProcess(child, "")
	if err != nil {
		inRead.Close()
		outWrite.Close()
		return line(postureNotEnforced, "the probe could not run: "+err.Error())
	}
	defer group.reap()
	err = group.start(child)
	inRead.Close()
	outWrite.Close()
	if err != nil {
		return line(postureNotEnforced, "the probe could not run: "+err.Error())
	}
	out := bufio.NewReader(outRead)
	_ = outRead.SetReadDeadline(time.Now().Add(postureProbeWait))
	grandchild := 0
	for seen := 0; seen < 2; seen++ {
		text, err := out.ReadString('\n')
		if err != nil {
			endProbe(inWrite, out, outRead, child, grandchild)
			return line(postureNotEnforced, "the probe's processes did not both start: "+probeReadError(err))
		}
		if pid, ok := strings.CutPrefix(strings.TrimSpace(text), "grandchild "); ok {
			grandchild, _ = strconv.Atoi(pid)
		}
	}
	kill(group, child)
	_ = outRead.SetReadDeadline(time.Now().Add(postureProbeWait))
	_, err = io.Copy(io.Discard, out)
	endProbe(inWrite, out, outRead, child, grandchild)
	if err == nil {
		return line(postureEnforced, "a grandchild a probe started inside a source's process group did not survive the group's kill; a descendant that leaves the group is not reached by it")
	}
	return line(postureNotEnforced, "a process a probe started inside a source's process group survived the group's kill, so a source or what it started can outlive being stopped")
}

// endProbe ends whatever of the probe is left: closing its input ends both
// of its processes, and one that still holds the pipe after the wait is
// killed by its pid, which it holds while it holds the pipe. Only then is
// the child waited for.
func endProbe(input *os.File, out *bufio.Reader, outRead *os.File, child *exec.Cmd, grandchild int) {
	input.Close()
	_ = outRead.SetReadDeadline(time.Now().Add(postureProbeWait))
	if _, err := io.Copy(io.Discard, out); err != nil {
		_ = child.Process.Kill()
		if grandchild > 0 {
			_ = syscall.Kill(grandchild, syscall.SIGKILL)
		}
	}
	_ = child.Wait()
}

func probeReadError(err error) string {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return fmt.Sprintf("nothing within %s", postureProbeWait)
	}
	if errors.Is(err, io.EOF) {
		return "the pipe closed first"
	}
	return err.Error()
}

// The engine image's custody markers (docs/design/engine-image.md): the
// signer's binary at its path, the signer's own at mode 0700 and carrying
// its file capabilities, run by that user, not root, with the three
// capabilities in effect; and the catalog and the corpus root's, beside it.
const imageGateway = "/usr/local/bin/gateway"

var imageTrees = []string{"/usr/share/engine/catalog", "/usr/share/engine/corpus"}

// custodyFacts is what the custody line is judged on, gathered from the
// running image (/proc/self/exe) and the filesystem.
type custodyFacts struct {
	executable   string // what /proc/self/exe names
	exeErr       error
	exeOwner     int
	exeMode      os.FileMode
	capabilities bool // the running image carries a file capability attribute
	euid         int
	sets         capabilitySets
	trees        map[string]treeFact
}

type treeFact struct {
	err       error
	directory bool
	owner     int
	mode      os.FileMode
}

func custodyPosture() postureLine { return judgeCustody(gatherCustody()) }

func gatherCustody() custodyFacts {
	facts := custodyFacts{euid: os.Geteuid(), sets: processCapabilities(), trees: map[string]treeFact{}}
	if exe, err := executableFacts(); err != nil {
		facts.exeErr = err
	} else {
		facts.executable, facts.exeMode, facts.capabilities = exe.path, exe.mode, exe.capabilities
		facts.exeOwner = -1
		if info, err := os.Stat("/proc/self/exe"); err == nil {
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				facts.exeOwner = int(st.Uid)
			}
		}
	}
	for _, tree := range imageTrees {
		info, err := os.Lstat(tree)
		if err != nil {
			facts.trees[tree] = treeFact{err: err}
			continue
		}
		fact := treeFact{directory: info.IsDir(), owner: -1, mode: info.Mode().Perm()}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			fact.owner = int(st.Uid)
		}
		facts.trees[tree] = fact
	}
	return facts
}

// judgeCustody holds the facts to the image's markers, one at a time, and
// names the first that does not hold.
func judgeCustody(f custodyFacts) postureLine {
	line := func(state, reason string) postureLine { return postureLine{protectionContainerCustody, state, reason} }
	if f.exeErr != nil {
		return line(postureNotEnforced, "the running binary could not be examined: "+f.exeErr.Error())
	}
	inImage := f.executable == imageGateway
	for _, tree := range imageTrees {
		if f.trees[tree].err == nil {
			inImage = true
		}
	}
	if !inImage {
		return line(postureNotEnforced, "this gateway does not run from the engine image, so the signer is held apart from its sources by their users and the host alone")
	}
	if f.executable != imageGateway {
		return line(postureNotEnforced, fmt.Sprintf("the running binary is %q, not the engine image's %s", f.executable, imageGateway))
	}
	if f.euid == 0 {
		return line(postureNotEnforced, "the signer runs as root, which holds whatever the container runtime gives root and is outside the image's custody")
	}
	if f.exeOwner != f.euid || f.exeMode != 0o700 {
		return line(postureNotEnforced, fmt.Sprintf("the gateway binary is not the signer's own at mode 0700 (owner uid %d, mode %04o, signer uid %d)", f.exeOwner, f.exeMode, f.euid))
	}
	if !f.capabilities {
		return line(postureNotEnforced, "the gateway binary carries no file capabilities, so the signer cannot switch an adapter to its platform's user")
	}
	if !f.sets.known {
		return line(postureNotEnforced, "the kernel does not report this process's capabilities")
	}
	if missing := missingCapabilitiesInSets(f.sets); len(missing) > 0 {
		return line(postureNotEnforced, "the signer lacks "+strings.Join(missing, ", ")+", so it cannot switch an adapter to its platform's user and stop it")
	}
	for _, tree := range imageTrees {
		t := f.trees[tree]
		switch {
		case t.err != nil:
			return line(postureNotEnforced, fmt.Sprintf("the image's %s could not be examined: %v", tree, t.err))
		case !t.directory || t.owner != 0 || t.mode&0o022 != 0:
			return line(postureNotEnforced, fmt.Sprintf("the image's %s is not a directory of root's that nobody else may write", tree))
		}
	}
	return line(postureEnforced, "this gateway runs from the engine image: the signer's own binary at mode 0700 with its file capabilities, run by a user that is not root, beside the image's catalog and corpus")
}
