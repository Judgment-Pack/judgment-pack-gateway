//go:build !linux

package sandbox

import (
	"context"
	"os/exec"
)

// directCommand runs the server without a launcher, by path: this platform
// offers no execution of an open descriptor, so the caller re-checks the
// digest immediately before the start.
func directCommand(ctx context.Context, launch Launch) (*exec.Cmd, bool) {
	cmd := exec.CommandContext(ctx, launch.Path, launch.Args...)
	cmd.Args[0] = launch.Argv0
	return cmd, false
}
