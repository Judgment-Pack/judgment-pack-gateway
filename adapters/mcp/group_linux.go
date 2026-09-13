//go:build linux

package mcp

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// adoptOrphans makes this process the reaper of its descendants' orphans
// (PR_SET_CHILD_SUBREAPER): a process a command server left behind is
// reparented here rather than to init when the server exits, so it is
// still a descendant when the server is stopped and can be reached.
func adoptOrphans() error {
	const prSetChildSubreaper = 36 // PR_SET_CHILD_SUBREAPER, linux/prctl.h
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetChildSubreaper, 1, 0); errno != 0 {
		return fmt.Errorf("cannot adopt the server's orphaned descendants: %v", errno)
	}
	return nil
}

// descendantsDeadline bounds how long a stop waits for every descendant
// to be gone.
const descendantsDeadline = 3 * time.Second

// killDescendants sends SIGKILL to every process descended from this one
// -- the server, what it started, and what those left behind -- found
// through /proc, and rescans until none is left alive, reaping the ones
// adopted here, or reports the survivors. The server stays in this
// process's own group, so under the gateway the source group's kill
// reaches all of it as well. A session or a group of its own does not
// change a process's parentage, so it is found here -- it is the group's
// kill, the fallback, that a new session escapes; a process in another
// pid namespace is not seen. --image is the shape that keeps the
// lifecycle under a name.
func killDescendants() error {
	return stopDescendants(liveDescendants, func(pid int) { syscall.Kill(pid, syscall.SIGKILL) }, descendantsDeadline)
}

// stopDescendants is killDescendants with the scan and the kill given,
// so the rule can be held on its own.
func stopDescendants(scan func() ([]int, int, error), kill func(int), within time.Duration) error {
	deadline := time.Now().Add(within)
	quiet := 0
	for {
		live, reaped, err := scan()
		if err != nil {
			return err
		}
		// Done only after a scan that found nothing alive and reaped
		// nothing, twice over: a process forked between the listing and
		// the reading of its parent is found on the next scan, once its
		// parent is gone and it is this process's own.
		switch {
		case len(live) == 0 && reaped == 0:
			quiet++
			if quiet >= 2 {
				return nil
			}
		case len(live) == 0:
			quiet = 0
		default:
			quiet = 0
			for _, pid := range live {
				kill(pid)
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%d process(es) the server left behind survived being stopped and may hold the credentials", len(live))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// liveDescendants lists the descendants of this process that are not
// zombies, reaping a zombie this process adopted on the way, so that it
// leaves /proc, and says how many it reaped.
func liveDescendants() (live []int, reaped int, err error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, 0, fmt.Errorf("cannot list processes: %w", err)
	}
	type process struct {
		ppid   int
		zombie bool
	}
	processes := map[int]process{}
	children := map[int][]int{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		stat, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue // gone between the listing and the read
		}
		// The command name is in parentheses and may hold spaces; the
		// fields after it are the state and the parent's pid.
		text := string(stat)
		end := strings.LastIndexByte(text, ')')
		if end < 0 {
			continue
		}
		fields := strings.Fields(text[end+1:])
		if len(fields) < 2 {
			continue
		}
		ppid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		processes[pid] = process{ppid: ppid, zombie: fields[0] == "Z"}
		children[ppid] = append(children[ppid], pid)
	}
	self := os.Getpid()
	queue := []int{self}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		for _, child := range children[parent] {
			if processes[child].zombie {
				if parent == self {
					if pid, _ := syscall.Wait4(child, nil, syscall.WNOHANG, nil); pid == child {
						reaped++
					}
				}
				continue
			}
			live = append(live, child)
			queue = append(queue, child)
		}
	}
	return live, reaped, nil
}
