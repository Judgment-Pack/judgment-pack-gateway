//go:build !unix

package main

// On platforms without a Unix credential model the gateway cannot run a source
// as another user, and the seed file's protection is not expressed in owner
// and mode bits. Both are said plainly rather than approximated: a declared
// source user is refused at startup, and the seed check reports that it does
// not apply. os/exec on Windows hands a child only the handles it is told to,
// so there is nothing to mark close-on-exec.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// sourceGroup has nothing to hold here: without process groups a source is
// the direct child and nothing more, and os/exec kills that on cancellation.
type sourceGroup struct{}

func (*sourceGroup) reap() {}

func prepareSourceProcess(cmd *exec.Cmd, name string) (*sourceGroup, error) {
	if name != "" {
		return nil, fmt.Errorf("running a source as user %q is not supported on this platform", name)
	}
	return &sourceGroup{}, nil
}

func requireUserSwitching(sources map[string]sourceSpec) error {
	for name, spec := range sources {
		if spec.user != "" {
			return fmt.Errorf("--source-user %s=%s: running a source as another user is not supported on this platform", name, spec.user)
		}
	}
	return nil
}

func openSeed(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("seed must be a regular file")
	}
	fmt.Fprintln(os.Stderr, "note: seed file ownership and permissions are not checked on this platform; protect it with the filesystem's own access control")
	return io.ReadAll(io.LimitReader(file, maxSeedFileBytes+1))
}

func markInheritedCloseOnExec() {}
