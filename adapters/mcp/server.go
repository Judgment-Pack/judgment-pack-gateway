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
func startServer(ctx context.Context, cfg Config, env []string) (*server, error) {
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
			Files: map[string][]byte{"env": envFile},
			Flags: []string{"--env-file", "{mount}/env"},
			Args:  cfg.Args,
			Stdin: true,
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
	// The command leads a process group of its own (where there are
	// process groups), so a descendant it leaves behind -- holding the
	// credentials in its environment -- is reached when it is stopped.
	ownGroup(cmd)
	stderr := &boundedBuffer{limit: 4096}
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
		// killed after the wait delay; and the whole process group is
		// killed last, so a descendant the command left behind does not
		// keep the credentials. The group is addressed after its leader
		// was reaped, a window in which the id could in principle be
		// reused; under the gateway the adapter's own group is killed
		// too, which closes it, and --image is the shape that keeps the
		// lifecycle under a name.
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
		killGroup(cmd)
		return nil
	}
	return &server{stdin: stdin, stdout: stdout, stop: stop, firstLine: stderr.firstLine,
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
	mu    sync.Mutex
	limit int
	buf   []byte
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := b.limit - len(b.buf); room > 0 {
		kept := p
		if len(kept) > room {
			kept = kept[:room]
		}
		b.buf = append(b.buf, kept...)
	}
	return len(p), nil
}

func (b *boundedBuffer) firstLine() string {
	b.mu.Lock()
	text := string(b.buf)
	b.mu.Unlock()
	for i, r := range text {
		if r == '\n' {
			return text[:i]
		}
	}
	return text
}

var errNoServer = errors.New("exactly one of --image and --command names the server")
