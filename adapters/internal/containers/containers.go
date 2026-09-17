// Package containers runs one connector command inside the operator's
// container runtime and ends it with the container established gone: the
// lifecycle every adapter shares.
package containers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// The budget for stopping a container once the acquisition is over, on top
// of the acquisition's own timeout: the kill, the inspect that follows a
// refused kill and the drain of its pipes, and the wait for the client's
// pipes after that, which a descendant holding stderr can stretch to the
// wait delay. Seven seconds at most -- nine for a container with stdin,
// which is first given the wait delay to end on end-of-input; the commands'
// default timeouts leave that room, and some to report, under the
// gateway's default source timeout of thirty seconds.
const (
	KillWindow    = 3 * time.Second
	InspectWindow = time.Second
	InspectDrain  = time.Second
	WaitDelay     = 2 * time.Second
)

// Container is one connector command running inside the operator's
// container runtime: its stdout a stream the caller drains, its stdin a
// pipe the caller writes when it asked for one.
type Container struct {
	redact func(text string, truncated bool) string
	// Name is the name the container was run under.
	Name string
	// Stdout is the container's standard output, closed with the context.
	Stdout io.ReadCloser
	// Stdin is the container's standard input when Spec.Stdin was set.
	Stdin io.WriteCloser

	runtime  string
	dir      string
	cmd      *exec.Cmd
	stderr   *boundedBuffer
	ctx      context.Context
	cancel   context.CancelFunc
	waitOnce sync.Once
	waitErr  error
	stopped  bool
}

// Spec is what to run. Files are written into a private directory and
// mounted read-only at /secrets; Flags go to the runtime before the image,
// with "{mount}" replaced by the host path of the mounted directory (for a
// runtime option the client reads on the host, such as --env-file); Args
// go after the image, to the connector.
type Spec struct {
	Runtime string
	Image   string
	Files   map[string][]byte
	Flags   []string
	Args    []string
	Stdin   bool
	// Redact is applied to everything the runtime or the container wrote
	// before any of it is cut to a line for a diagnostic, so a credential
	// longer than the cut, or spanning lines, still matches; truncated
	// says the buffer overflowed, so what ends it may be the start of a
	// credential whose rest was dropped.
	Redact func(text string, truncated bool) string
}

// startContainer writes files into a private directory, mounts it read-only
// at /secrets, and starts
//
//	RUNTIME run --rm --name NAME -v DIR/secrets:/secrets:ro IMAGE VERB ARGS...
//
// The private directory is this process's alone (0700); the directory
// mounted is the one inside it, readable by any user (0755, files 0644), so
// that a connector running as its image's non-root user under a rootless
// runtime -- whose identity does not map to this process's -- can read its
// configuration, while no other user on the host can reach the parent. The
// runtime inherits this process's environment: it is the adapter's own,
// declared by the operator when the gateway spawned it, and a runtime needs
// its HOME and PATH. The connector sees only its files.
func Start(ctx context.Context, spec Spec) (*Container, error) {
	runtime, image, files := spec.Runtime, spec.Image, spec.Files
	dir, err := os.MkdirTemp("", "adapter-")
	if err != nil {
		return nil, fmt.Errorf("mount directory: %w", err)
	}
	// The modes are set after creation, so the process's umask -- which
	// a restrictive launcher may have set to 077 -- does not narrow them.
	mount := filepath.Join(dir, "secrets")
	if err := os.Mkdir(mount, 0o755); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("mount directory: %w", err)
	}
	if err := os.Chmod(mount, 0o755); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("mount directory: %w", err)
	}
	for name, data := range files {
		path := filepath.Join(mount, name)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			os.RemoveAll(dir)
			return nil, fmt.Errorf("mount directory: %w", err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			os.RemoveAll(dir)
			return nil, fmt.Errorf("mount directory: %w", err)
		}
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	name := "jp-adapter-" + hex.EncodeToString(suffix[:])
	argv := []string{"run", "--rm", "--name", name, "-v", mount + ":/secrets:ro"}
	for _, flag := range spec.Flags {
		argv = append(argv, strings.ReplaceAll(flag, "{mount}", mount))
	}
	if spec.Stdin {
		argv = append(argv, "-i")
	}
	// The runtime's option parsing ends here: what follows is the image
	// and the container's arguments, whatever they look like.
	argv = append(argv, "--", image)
	argv = append(argv, spec.Args...)
	runCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(runCtx, runtime, argv...)
	cmd.Env = os.Environ()
	cmd.WaitDelay = WaitDelay
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		os.RemoveAll(dir)
		return nil, err
	}
	stderr := &boundedBuffer{limit: DiagnosticBytes}
	cmd.Stderr = stderr
	var stdin io.WriteCloser
	if spec.Stdin {
		if stdin, err = cmd.StdinPipe(); err != nil {
			cancel()
			os.RemoveAll(dir)
			return nil, err
		}
	}
	if err := cmd.Start(); err != nil {
		cancel()
		os.RemoveAll(dir)
		return nil, fmt.Errorf("%s could not be started: %w", runtime, err)
	}
	// A reader blocked on stdout returns when the context ends, whoever
	// holds the pipe's other end: a descendant of the runtime client that
	// outlived it would otherwise hold the scanner past every deadline.
	go func() {
		<-runCtx.Done()
		stdout.Close()
		if stdin != nil {
			stdin.Close()
		}
	}()
	redactor := spec.Redact
	if redactor == nil {
		redactor = func(text string, truncated bool) string { return text }
	}
	return &Container{Name: name, Stdout: stdout, Stdin: stdin, runtime: runtime, dir: dir, cmd: cmd, stderr: stderr, ctx: runCtx, cancel: cancel, redact: redactor}, nil
}

// Wait waits once for the runtime client and returns its error; a second
// caller, from another goroutine, waits for the first.
func (c *Container) Wait() error {
	c.waitOnce.Do(func() { c.waitErr = c.cmd.Wait() })
	return c.waitErr
}

// Stop ends the container and removes the mount directory, and establishes
// that the container is gone: the client's exit says nothing certain about
// its container, and a killed client leaves one running, so the container
// is always told to stop by name, and a kill the runtime refuses is
// followed by an inspect. A container the runtime still knows after that is
// an error the acquisition must not hide -- it holds the credentials mount.
// Safe to call twice; the second call does nothing and returns nil. A
// stdin pipe is closed first, so a server that ends on end-of-input ends.
func (c *Container) Stop() error {
	if c.stopped {
		return nil
	}
	c.stopped = true
	if c.Stdin != nil {
		// End of input first, and a bounded chance to end on it, before
		// the container is told to stop: a server that ends cleanly on
		// end-of-input ends cleanly. The container is still told to
		// stop by name afterwards, since the client's exit establishes
		// nothing about its container.
		c.Stdin.Close()
		done := make(chan struct{})
		go func() { c.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(WaitDelay):
		}
	}
	c.cancel()
	err := c.stopByName()
	c.Wait()
	if c.dir != "" {
		os.RemoveAll(c.dir)
		c.dir = ""
	}
	return err
}

// stopByName kills the container and, when the runtime refuses, establishes
// positively that the container is absent: an inspect that succeeds means
// present; one the runtime answers with "no such" and the container's own
// name -- docker's "No such object: NAME", podman's "no such container
// NAME" -- means absent; anything else -- a timeout, a daemon that is down,
// a host that cannot be resolved ("no such host" names no container) --
// leaves the question open, and an open question is an error, not an
// absence.
func (c *Container) stopByName() error {
	killCtx, cancelKill := context.WithTimeout(context.Background(), KillWindow)
	defer cancelKill()
	kill := exec.CommandContext(killCtx, c.runtime, "kill", c.Name)
	kill.Env = os.Environ()
	if kill.Run() == nil {
		return nil
	}
	inspectCtx, cancelInspect := context.WithTimeout(context.Background(), InspectWindow)
	defer cancelInspect()
	inspect := exec.CommandContext(inspectCtx, c.runtime, "inspect", c.Name)
	inspect.Env = os.Environ()
	// The answer is read through pipes, and a descendant of the runtime
	// holding one would otherwise hold this past the window: the drain is
	// bounded too.
	inspect.WaitDelay = InspectDrain
	answer := &boundedBuffer{limit: DiagnosticBytes}
	inspect.Stderr = answer
	inspect.Stdout = io.Discard
	err := inspect.Run()
	switch {
	case err == nil:
		return fmt.Errorf("container %s could not be stopped and is still known to %s; stop it by hand -- it holds the credentials mount", c.Name, c.runtime)
	case SaysAbsent(answer.String(), c.Name):
		return nil // absent: it ended on its own, and --rm removed it
	}
	return fmt.Errorf("container %s could not be stopped and %s could not say whether it is gone (%s); check it by hand -- it may hold the credentials mount", c.Name, c.runtime, firstLineOf(c.redact(answer.String(), answer.overflowed()), err))
}

// SaysAbsent reports whether an inspect's answer is the runtime saying the
// container itself does not exist: docker's "No such object: NAME" or "No
// such container: NAME", podman's "no such container NAME" -- the absence
// phrase, in either case, immediately followed by the name as a whole
// token in its exact case, quoted or not, ending at whitespace or the end
// of the text. Names are case-sensitive to a runtime, and a dot, a dash or
// an underscore are name characters, so "NAME.other" and a recased name
// are other containers and do not match; and a transport failure that
// mentions the name elsewhere, as a request URL does ("Get
// .../containers/NAME/json: ... no such host"), is not an absence.
func SaysAbsent(answer, name string) bool {
	pattern := regexp.MustCompile(`(?i:no such (?:object|container)):?\s*"?` + regexp.QuoteMeta(name) + `"?(?:\s|$)`)
	return pattern.MatchString(answer)
}

func firstLineOf(text string, err error) string {
	for i, r := range text {
		if r == '\n' {
			text = text[:i]
			break
		}
	}
	if text == "" {
		return err.Error()
	}
	return text
}

// diagnosticBytes is how much of what a runtime or a container writes is
// kept for a diagnostic: enough that a credential echoed whole is still
// whole when the redactor sees it, before the first line is cut.
const DiagnosticBytes = 64 << 10

// FirstLine is the first line of what the connector wrote on stderr,
// redacted before the cut, for an error message; never the whole of it.
func (c *Container) FirstLine() string {
	text := c.redact(c.stderr.String(), c.stderr.overflowed())
	for i, r := range text {
		if r == '\n' {
			return text[:i]
		}
	}
	return text
}

// boundedBuffer keeps the first limit bytes written to it and drops the
// rest, reporting every write as complete: a writer that reported a short
// write would have os/exec's copier stop and close the pipe on the child.
// It is written by that copier and read for a diagnostic, so it locks.
type boundedBuffer struct {
	mu      sync.Mutex
	limit   int
	buf     []byte
	dropped bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	room := b.limit - len(b.buf)
	if room < len(p) {
		b.dropped = true
	}
	if room > 0 {
		kept := p
		if len(kept) > room {
			kept = kept[:room]
		}
		b.buf = append(b.buf, kept...)
	}
	return len(p), nil
}

// overflowed reports whether anything written was dropped.
func (b *boundedBuffer) overflowed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dropped
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

// Image is a digest-pinned image reference taken apart: what runs is then
// what a receipt names, not whatever a tag resolved to at pull time.
type Image struct{ Name, Version, Digest string }

// imageReference is the shape of name[:tag]: a registry with an optional
// port, path components, and a tag, every component beginning with a
// letter or digit -- so nothing that is handed to a runtime as an image
// can be read by it as an option.
var imageReference = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(?::[0-9]+)?(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?$`)

// ParseImage requires name[:tag]@sha256:<64 hex>, the name a reference.
func ParseImage(ref string) (Image, error) {
	name, digest, ok := strings.Cut(ref, "@")
	if !ok || !isDigest(digest) {
		return Image{}, fmt.Errorf("image %q must be pinned: name[:tag]@sha256:<64 hex>", ref)
	}
	if !imageReference.MatchString(name) {
		return Image{}, fmt.Errorf("image %q is not a reference: registry, path and tag components, each beginning with a letter or digit", ref)
	}
	version := ""
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		version, name = name[i+1:], name[:i]
	}
	if name == "" {
		return Image{}, fmt.Errorf("image %q has no name", ref)
	}
	return Image{Name: name, Version: version, Digest: digest}, nil
}

func isDigest(s string) bool {
	h, ok := strings.CutPrefix(s, "sha256:")
	if !ok || len(h) != 64 {
		return false
	}
	for _, c := range h {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
