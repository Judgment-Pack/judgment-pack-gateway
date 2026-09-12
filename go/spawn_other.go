//go:build !unix

package main

// On platforms without a Unix credential model the gateway cannot run a source
// as another user, and the seed file's protection is not expressed in mode
// bits. Both are said plainly rather than approximated: a declared source user
// is refused at startup, and the seed check reports that it does not apply.

import (
	"fmt"
	"os"
	"os/exec"
)

func applySourceUser(cmd *exec.Cmd, name string) error {
	if name == "" {
		return nil
	}
	return fmt.Errorf("running a source as user %q is not supported on this platform", name)
}

func requireUserSwitching(sources map[string]sourceSpec) error {
	for name, spec := range sources {
		if spec.user != "" {
			return fmt.Errorf("--source-user %s=%s: running a source as another user is not supported on this platform", name, spec.user)
		}
	}
	return nil
}

func checkSeedPermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("seed must be a regular file")
	}
	fmt.Fprintln(os.Stderr, "note: seed file permissions are not checked on this platform; protect it with the filesystem's own access control")
	return nil
}
