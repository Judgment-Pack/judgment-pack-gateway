//go:build linux

package sandbox

import (
	"context"
	"os"
	"os/exec"
	"strconv"
)

// descriptorPath is how a process names its inherited descriptor fd when it
// executes it: the kernel runs the open file, whatever its path now names.
func descriptorPath(fd int) string { return "/proc/self/fd/" + strconv.Itoa(fd) }

// directCommand runs the server without a launcher. A binary is executed
// through the descriptor that was digested; a "#!" script is executed by
// path, because its interpreter reopens the path it is given.
func directCommand(ctx context.Context, launch Launch) (*exec.Cmd, bool) {
	if launch.File != nil && !isScript(launch.File) {
		cmd := exec.CommandContext(ctx, descriptorPath(3), launch.Args...)
		cmd.Args[0] = launch.Argv0
		cmd.ExtraFiles = []*os.File{launch.File}
		return cmd, true
	}
	cmd := exec.CommandContext(ctx, launch.Path, launch.Args...)
	cmd.Args[0] = launch.Argv0
	return cmd, false
}
