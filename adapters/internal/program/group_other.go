//go:build !unix

package program

import "os/exec"

// startGroup is the unix one's counterpart; here the program is started as
// any other.
func startGroup(*exec.Cmd) {}

// endGroup ends the program; what it started is not reached here.
func endGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
