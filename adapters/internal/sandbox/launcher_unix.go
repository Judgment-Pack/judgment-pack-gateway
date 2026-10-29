//go:build !windows

package sandbox

import (
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	// launcherTrusted is trustedFile; a test replaces it to stand a failing
	// launcher at a fixed location.
	launcherTrusted = trustedFile
)

// trustedLauncher returns the launcher at the first of locations that
// exists. found is false when none exists. err, a sandbox-launcher-untrusted
// refusal, is set when the one that exists fails trustedFile.
func trustedLauncher(locations []string) (path string, found bool, err error) {
	for _, candidate := range locations {
		if _, statErr := os.Lstat(candidate); statErr != nil {
			continue
		}
		if err := launcherTrusted(candidate); err != nil {
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
// An ELF launcher's program interpreter is held the same way, and each
// directory its RPATH or RUNPATH names must be one only root can change: the
// loader runs that code in the launcher before anything is confined.
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
	if what := rootHeld(path); what != "" {
		return untrusted(what)
	}
	if what := rootHeld(resolved); what != "" {
		return untrusted(what)
	}
	if what := launcherLoader(resolved, rootHeldFile); what != "" {
		return untrusted(what)
	}
	return nil
}

// rootHeld says why path, and every directory above it, is not owned by
// root and writable by root alone ("" when it is). A link is judged by its
// owner, not its mode.
func rootHeld(p string) string {
	for {
		info, err := os.Lstat(p)
		if err != nil {
			return "has a component that cannot be read"
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != trustedOwner {
			return "is not owned by root along its path"
		}
		if info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o022 != 0 {
			return "is writable by group or others along its path"
		}
		parent := filepath.Dir(p)
		if parent == p {
			return ""
		}
		p = parent
	}
}

// rootHeldFile is rootHeld along a path as written and as resolved.
func rootHeldFile(p string) string {
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "cannot be resolved"
	}
	if what := rootHeld(p); what != "" {
		return what
	}
	return rootHeld(resolved)
}

// launcherLoader says why the code an ELF launcher's loader runs before its
// main is not held ("" when it is, and for a file that is not ELF: macOS's
// launcher is a platform binary). held judges a path as rootHeldFile does.
//   - PT_INTERP, the program interpreter, must be held.
//   - Each DT_RPATH and DT_RUNPATH entry, $ORIGIN expanded, must be an
//     absolute directory that is held where it exists, and otherwise one whose
//     nearest existing ancestor is held, so no one else can create it.
//   - A dynamic segment the check cannot read refuses.
func launcherLoader(path string, held func(string) string) string {
	f, err := elf.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	dynamic := false
	for _, prog := range f.Progs {
		switch prog.Type {
		case elf.PT_DYNAMIC:
			dynamic = true
		case elf.PT_INTERP:
			if prog.Filesz == 0 || prog.Filesz > 4096 {
				return "names a program interpreter this check cannot read"
			}
			name := make([]byte, prog.Filesz)
			if _, err := prog.ReadAt(name, 0); err != nil {
				return "names a program interpreter this check cannot read"
			}
			interp := strings.TrimRight(string(name), "\x00")
			if !filepath.IsAbs(interp) {
				return "names a relative program interpreter"
			}
			if what := held(interp); what != "" {
				return "has a program interpreter that " + what
			}
		}
	}
	if dynamic && f.SectionByType(elf.SHT_DYNAMIC) == nil {
		return "has a dynamic segment without the section this check reads"
	}
	for _, tag := range []elf.DynTag{elf.DT_RPATH, elf.DT_RUNPATH} {
		values, err := f.DynString(tag)
		if err != nil {
			return "has a library search path this check cannot read"
		}
		for _, value := range values {
			for _, dir := range strings.Split(value, ":") {
				dir = strings.ReplaceAll(strings.ReplaceAll(dir, "${ORIGIN}", filepath.Dir(path)), "$ORIGIN", filepath.Dir(path))
				if !filepath.IsAbs(dir) {
					return "has a relative or empty library search path entry, which searches the working directory"
				}
				dir = filepath.Clean(dir)
				for {
					if _, err := os.Lstat(dir); err == nil || filepath.Dir(dir) == dir {
						break
					}
					dir = filepath.Dir(dir)
				}
				if what := held(dir); what != "" {
					return "has a library search path directory that " + what
				}
			}
		}
	}
	return ""
}
