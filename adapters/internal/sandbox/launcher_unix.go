//go:build !windows

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Launchers are taken only from these fixed absolute locations, never from
// PATH: a PATH directory someone other than root can write would otherwise
// let a stand-in decide the boundary and run, unconfined, as the source's
// user. The first location that exists is the launcher, and it must pass
// trustedFile; one that fails refuses, with no fallback to a later location,
// to PATH, or to another backend.
var (
	bwrapLocations       = []string{"/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"}
	sandboxExecLocations = []string{"/usr/bin/sandbox-exec"}
	// trustedOwner is the only owner a launcher and its directories may have.
	trustedOwner uint32 = 0
)

// trustedLauncher returns the launcher at the first of locations that
// exists. found is false when none exists. err, a sandbox-launcher-untrusted
// refusal, is set when the one that exists fails trustedFile.
func trustedLauncher(locations []string) (path string, found bool, err error) {
	for _, candidate := range locations {
		if _, statErr := os.Lstat(candidate); statErr != nil {
			continue
		}
		if err := trustedFile(candidate); err != nil {
			return "", true, err
		}
		return candidate, true, nil
	}
	return "", false, nil
}

// trustedFile holds a launcher to: an executable regular file, owned by
// root and writable by neither group nor others, in directories each owned by
// root and writable by neither group nor others, both along the path as
// written (a link there owned by root) and along the path it resolves to.
func trustedFile(path string) error {
	untrusted := func(what string) error {
		return fmt.Errorf("sandbox-launcher-untrusted: %s %s; a sandbox launcher must be a root-owned file in root-owned directories that only root can write", path, what)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return untrusted("cannot be resolved")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return untrusted("is not an executable regular file")
	}
	check := func(p string) error {
		for {
			info, err := os.Lstat(p)
			if err != nil {
				return untrusted("has a component that cannot be read")
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || st.Uid != trustedOwner {
				return untrusted("is not owned by root along its path")
			}
			if info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o022 != 0 {
				return untrusted("is writable by group or others along its path")
			}
			parent := filepath.Dir(p)
			if parent == p {
				return nil
			}
			p = parent
		}
	}
	if err := check(path); err != nil {
		return err
	}
	return check(resolved)
}
