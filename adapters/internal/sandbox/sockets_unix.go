//go:build !windows

package sandbox

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// runtimeSocketPaths are known container-runtime sockets. A process that can
// connect to one can have the runtime's daemon, which no backend here
// confines, write anywhere on its behalf.
var runtimeSocketPaths = []string{
	"/var/run/docker.sock", "/run/docker.sock",
	"/run/podman/podman.sock",
	"/run/containerd/containerd.sock",
	"/run/crio/crio.sock",
	"/run/buildkit/buildkitd.sock",
}

// userRuntimeSocketNames are the runtime sockets kept below a per-user
// runtime directory or home directory (rootless and desktop runtimes).
var userRuntimeSocketNames = []string{
	"docker.sock", "podman/podman.sock",
	".docker/run/docker.sock", ".colima/default/docker.sock", ".rd/docker.sock",
	".local/share/containers/podman/machine/podman.sock",
}

// envValue is the last value of name in env, or "".
func envValue(env []string, name string) string {
	value := ""
	for _, pair := range env {
		if k, v, ok := strings.Cut(pair, "="); ok && k == name {
			value = v
		}
	}
	return value
}

// userRuntimeDirs are the per-user runtime directories of the launching user:
// the server's XDG_RUNTIME_DIR and /run/user/<uid>, those that exist as
// directories, resolved. They hold rootless runtimes' sockets and the user's
// service manager and session bus, any of which can start an unconfined
// process.
func userRuntimeDirs(env []string) []string {
	seen := map[string]bool{}
	var dirs []string
	for _, dir := range []string{envValue(env, "XDG_RUNTIME_DIR"), "/run/user/" + strconv.Itoa(os.Getuid())} {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		resolved, err := filepath.EvalSymlinks(dir)
		if err != nil {
			continue
		}
		if info, err := os.Stat(resolved); err != nil || !info.IsDir() || resolved == "/" || seen[resolved] {
			continue
		}
		seen[resolved] = true
		dirs = append(dirs, resolved)
	}
	return dirs
}

// reachableRuntimeSockets are the known runtime sockets that exist for this
// launch, resolved and sorted: the fixed system paths, and the per-user names
// below the user's runtime directories and home directory.
func reachableRuntimeSockets(env []string) []string {
	candidates := append([]string{}, runtimeSocketPaths...)
	bases := userRuntimeDirs(env)
	// The server's HOME, else this process's (no os/user: it would link the
	// C library, and the loader variables refused here would act on it).
	home := envValue(env, "HOME")
	if home == "" {
		home = os.Getenv("HOME")
	}
	if filepath.IsAbs(home) {
		bases = append(bases, home)
	}
	for _, base := range bases {
		for _, name := range userRuntimeSocketNames {
			candidates = append(candidates, filepath.Join(base, name))
		}
	}
	seen := map[string]bool{}
	var found []string
	for _, candidate := range candidates {
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil || seen[resolved] {
			continue
		}
		if info, err := os.Stat(resolved); err != nil || info.Mode()&os.ModeSocket == 0 {
			continue
		}
		seen[resolved] = true
		found = append(found, resolved)
	}
	sort.Strings(found)
	return found
}

// within reports whether path is dir or below it.
func within(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// runtimeSocketNote is the report's statement about runtime sockets when they
// stay reachable.
func runtimeSocketNote(launch Launch, sockets []string) string {
	if launch.RuntimeSockets {
		return "container-runtime sockets stay reachable for the runtime client, and the runtime's daemon is not confined by this boundary"
	}
	if len(sockets) == 0 {
		return ""
	}
	return "reachable container-runtime sockets (" + strings.Join(sockets, ", ") + ") are not masked by this backend, and the runtime's daemon is not confined"
}
