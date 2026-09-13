package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"adapters/internal/containers"
	"adapters/internal/redact"
)

// server is a running MCP server reached over stdio: a pinned image in the
// operator's container runtime, or a local command.
type server struct {
	stdin     io.WriteCloser
	stdout    io.ReadCloser
	stop      func() error
	firstLine func() string
	identity  adapterIdentity
}

// startServer starts the server the configuration names with the
// credentials as its environment and nothing else added: a container gets
// them through an env file in its private mount; a command gets them
// beside this process's own environment, which is what the operator
// declared for the adapter and what a command like npx needs.
func startServer(ctx context.Context, cfg Config, env, secrets []string) (*server, error) {
	// Everything a server or a runtime wrote is redacted before it is
	// cut; when the buffer overflowed, what ends it may be the start of
	// a credential whose rest was dropped, and that is cut off first.
	redactor := func(text string, truncated bool) string { return redact.Diagnostic(text, truncated, secrets) }
	if cfg.Image != "" {
		image, err := containers.ParseImage(cfg.Image)
		if err != nil {
			return nil, err
		}
		var envFile []byte
		for _, pair := range env {
			envFile = append(envFile, pair...)
			envFile = append(envFile, '\n')
		}
		c, err := containers.Start(ctx, containers.Spec{
			Runtime: cfg.Runtime, Image: cfg.Image,
			Files:  map[string][]byte{"env": envFile},
			Flags:  []string{"--env-file", "{mount}/env"},
			Args:   cfg.Args,
			Stdin:  true,
			Redact: redactor,
		})
		if err != nil {
			return nil, err
		}
		return &server{stdin: c.Stdin, stdout: c.Stdout, stop: c.Stop, firstLine: c.FirstLine,
			identity: adapterIdentity{Name: image.Name, Version: image.Version, Digest: image.Digest}}, nil
	}
	path, err := exec.LookPath(cfg.Command[0])
	if err != nil {
		return nil, fmt.Errorf("server command could not be resolved: %v", err)
	}
	digest, err := executableDigest(path)
	if err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(runCtx, path, cfg.Command[1:]...)
	cmd.Args[0] = cfg.Command[0]
	cmd.Env = append(os.Environ(), env...)
	cmd.WaitDelay = containers.WaitDelay
	// The server stays in this process's group, so a kill of the group
	// -- the gateway's, when this adapter is ended -- reaches it and what
	// it started; what it leaves behind is adopted here (Linux) and
	// reached when it is stopped.
	if err := adoptOrphans(); err != nil {
		cancel()
		return nil, err
	}
	stderr := &boundedBuffer{limit: containers.DiagnosticBytes}
	cmd.Stderr = stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("server could not be started: %v", err)
	}
	// A reader blocked on stdout, or a writer blocked on stdin because a
	// descendant holds the pipe without reading, returns when the context
	// ends: both ends are closed with it.
	go func() {
		<-runCtx.Done()
		stdout.Close()
		stdin.Close()
	}()
	var waited bool
	var waitErr error
	wait := func() error {
		if !waited {
			waited = true
			waitErr = cmd.Wait()
		}
		return waitErr
	}
	stopped := false
	stop := func() error {
		if stopped {
			return nil
		}
		stopped = true
		// End of input ends a well-behaved server; one that lingers is
		// killed after the wait delay; and every descendant still here
		// is killed last, so a process the command left behind does not
		// keep the credentials.
		stdin.Close()
		done := make(chan error, 1)
		go func() { done <- wait() }()
		select {
		case <-done:
		case <-time.After(containers.WaitDelay):
			cancel()
			<-done
		}
		cancel()
		// A descendant that could not be established gone fails the
		// stop, and with it the check or the acquisition: it may hold
		// the credentials.
		return killDescendants()
	}
	return &server{stdin: stdin, stdout: stdout, stop: stop, firstLine: func() string { return stderr.firstLine(redactor) },
		identity: adapterIdentity{Name: cfg.Command[0], Digest: digest}}, nil
}

// executableDigest is the SHA-256 of the regular file at path, streamed,
// as the core digests a command it runs.
func executableDigest(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("server executable could not be read for its digest: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("server executable %s is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("server executable could not be read for its digest: %w", err)
	}
	defer file.Close()
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", fmt.Errorf("server executable could not be read for its digest: %w", err)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// boundedBuffer keeps the first limit bytes and reports every write whole.
// It is written by os/exec's copier and read for a diagnostic, so it locks.
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

// firstLine is the first line of what was written, redacted before the
// cut so a credential longer than a line, or spanning lines, is matched.
func (b *boundedBuffer) firstLine(redactor func(string, bool) string) string {
	b.mu.Lock()
	text := redactor(string(b.buf), b.dropped)
	b.mu.Unlock()
	for i, r := range text {
		if r == '\n' {
			return text[:i]
		}
	}
	return text
}

var errNoServer = errors.New("exactly one of --image and --command names the server")
