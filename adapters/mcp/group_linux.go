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
// reaches all of it as well. A descendant that made a session of its own
// is not descended any more and is not found; --image is the shape that
// keeps the lifecycle under a name.
func killDescendants() error {
	deadline := time.Now().Add(descendantsDeadline)
	for {
		live, err := liveDescendants()
		if err != nil {
			return err
		}
		if len(live) == 0 {
			return nil
		}
		for _, pid := range live {
			syscall.Kill(pid, syscall.SIGKILL)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%d process(es) the server left behind survived being stopped and may hold the credentials", len(live))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// liveDescendants lists the descendants of this process that are not
// zombies, reaping a zombie this process adopted on the way, so that it
// leaves /proc.
func liveDescendants() ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("cannot list processes: %w", err)
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
	var live []int
	queue := []int{self}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		for _, child := range children[parent] {
			if processes[child].zombie {
				if parent == self {
					syscall.Wait4(child, nil, syscall.WNOHANG, nil)
				}
				continue
			}
			live = append(live, child)
			queue = append(queue, child)
		}
	}
	return live, nil
}
