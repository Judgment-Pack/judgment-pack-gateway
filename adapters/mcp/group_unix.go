//go:build unix

package mcp

import (
	"os/exec"
	"syscall"
)

// ownGroup starts the command as the leader of a process group of its
// own, so that what it starts can be reached when it is stopped.
func ownGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killGroup sends SIGKILL to the command's whole process group: the
// server and every descendant it left behind, each of which inherited
// the credentials in its environment.
func killGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
