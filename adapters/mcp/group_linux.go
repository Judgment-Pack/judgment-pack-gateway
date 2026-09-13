//go:build linux

package mcp

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// adoptOrphans makes this process the reaper of its descendants' orphans
// (PR_SET_CHILD_SUBREAPER): a process a command server left behind is
// reparented here rather than to init when the server exits, so it is
// still a descendant when the server is stopped and can be reached.
func adoptOrphans() {
	const prSetChildSubreaper = 36 // PR_SET_CHILD_SUBREAPER, linux/prctl.h
	syscall.RawSyscall(syscall.SYS_PRCTL, prSetChildSubreaper, 1, 0)
}

// killDescendants sends SIGKILL to every process descended from this one,
// found through /proc: the server, what it started, and what those left
// behind. The server stays in this process's own group, so under the
// gateway the source group's kill reaches all of it as well. A descendant
// that made a session of its own is not descended any more and is not
// found; --image is the shape that keeps the lifecycle under a name.
func killDescendants() {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	children := map[int][]int{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		stat, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
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
		children[ppid] = append(children[ppid], pid)
	}
	queue := []int{os.Getpid()}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		for _, child := range children[parent] {
			syscall.Kill(child, syscall.SIGKILL)
			queue = append(queue, child)
		}
	}
}
