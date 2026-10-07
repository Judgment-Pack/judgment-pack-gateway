//go:build unix

package program

import (
	"os/exec"
	"syscall"
)

// startGroup starts the program as the leader of a process group of its own.
func startGroup(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

// endGroup ends every process left in the program's group, the program and
// what it started included.
func endGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
