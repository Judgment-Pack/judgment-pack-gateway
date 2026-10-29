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
// runtime directory or home directory (rootless and desktop runtimes:
// Docker Desktop, Colima, Rancher Desktop, Lima, OrbStack, Podman machine).
var userRuntimeSocketNames = []string{
	"docker.sock", "podman/podman.sock",
	".docker/run/docker.sock", ".docker/desktop/docker.sock", ".colima/default/docker.sock", ".rd/docker.sock",
	".lima/default/sock/docker.sock", ".orbstack/run/docker.sock",
	".local/share/containers/podman/machine/podman.sock",
}

// SocketLimit is the boundary's stated limit on local services: enforced
// means the filesystem write boundary holds, and says nothing of what a
// program reaches over a socket. Masks are defence in depth only: a socket
// created after the launch, bound in another network namespace or by a
// relative path is not masked, and a read-only mount does not stop connect.
const SocketLimit = "local services reached over Unix sockets may remain reachable (a socket created after the launch, bound in another network namespace or by a relative path is not masked), and this filesystem write boundary does not cover what they do"

// runtimeHostVariables name a runtime's socket in a client's environment:
// a "unix://" value there is that runtime's socket, wherever it lies.
var runtimeHostVariables = []string{"DOCKER_HOST", "CONTAINER_HOST"}

// procNetUnix lists the Unix sockets of this network namespace.
var procNetUnix = "/proc/net/unix"

// listeningSockets reads procNetUnix: the paths of the listening sockets
// bound to a filesystem path, and how many listening sockets are bound to
// an abstract name, which no filesystem mask hides. ok is false when the
// list cannot be read, so what is reachable is not known.
func listeningSockets() (paths []string, abstract int, ok bool) {
	raw, err := os.ReadFile(procNetUnix)
	if err != nil {
		return nil, 0, false
	}
	lines := strings.Split(string(raw), "\n")
	for _, line := range lines[1:] {
		// Num RefCount Protocol Flags Type St Inode [Path]; a path holds no
		// space unless the kernel escaped it, and a name is never quoted.
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil || flags&0x10000 == 0 { // __SO_ACCEPTCON: listening
			continue
		}
		name := strings.Join(fields[7:], " ")
		if strings.HasPrefix(name, "@") {
			abstract++
		} else if filepath.IsAbs(name) {
			paths = append(paths, name)
		}
	}
	return paths, abstract, true
}

// unixTarget is the socket path a "unix://PATH" value names, or "".
func unixTarget(value string) string {
	path, ok := strings.CutPrefix(value, "unix://")
	if !ok || !filepath.IsAbs(path) {
		return ""
	}
	return path
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
// launch, resolved and sorted: the fixed system paths, the sockets the
// runtime host variables name in the server's environment or this process's,
// and the per-user names below the user's runtime directories and home
// directory.
func reachableRuntimeSockets(env []string) []string {
	candidates := append([]string{}, runtimeSocketPaths...)
	for _, name := range runtimeHostVariables {
		for _, value := range []string{envValue(env, name), os.Getenv(name)} {
			if target := unixTarget(value); target != "" {
				candidates = append(candidates, target)
			}
		}
	}
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
	return existingSockets(candidates)
}

// existingSockets are those of candidates that are sockets, resolved, once
// each, and sorted.
func existingSockets(candidates []string) []string {
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
