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
	"path/filepath"
	"sync"
	"time"

	"adapters/internal/containers"
	"adapters/internal/redact"
	"adapters/internal/sandbox"
	"adapters/mcphttp"
)

// server is the MCP server a conversation is held with: a running server
// reached over stdio -- a pinned image in the operator's container
// runtime, or a local command -- or a remote one reached over Streamable
// HTTP (remote.go), whose client is remote.
type server struct {
	sandbox   *sandbox.Report
	rpc       conversation
	stop      func() error
	firstLine func() string
	identity  adapterIdentity
	remote    *mcphttp.Client
	// executable is a customer command's measured identity, which its
	// approval binds (snapshot version 4).
	executable *executableIdentity
}

// stdioConversation is JSON-RPC over a started server's stdio.
type stdioConversation struct{ *client }

func (s stdioConversation) initialized(_ context.Context, _ string) error {
	return s.notify("notifications/initialized", map[string]any{})
}

var sandboxCommand = sandbox.Command

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
		return &server{rpc: stdioConversation{newClient(c.Stdin, c.Stdout)}, stop: c.Stop, firstLine: c.FirstLine,
			identity: adapterIdentity{Name: image.Name, Version: image.Version, Digest: image.Digest}}, nil
	}
	runCtx, cancel := context.WithCancel(ctx)
	var cmd *exec.Cmd
	var digest string
	var measured *measuredCommand
	var protection *sandbox.Report
	cleanup := func() error { return nil }
	if cfg.Customer {
		// A loader variable would choose code before the policy applies
		// (and, before this refusal, before the launcher confined anything).
		if err := loaderVariableRefusal(os.Environ(), env); err != nil {
			cancel()
			return nil, err
		}
		mode, err := sandbox.ModeForWorkspace(cfg.SandboxPolicy, cfg.SandboxSource, cfg.SandboxWorkspace)
		if err != nil {
			cancel()
			return nil, err
		}
		// Resolved and digested afresh at every start; with an approval
		// held, a different file or digest refuses before anything runs.
		measured, err = measureCustomerCommand(cfg.Command, cfg.SandboxWorkspace)
		if err != nil {
			cancel()
			return nil, err
		}
		if cfg.approvalHeld {
			if err := approvedCommandRefusal(cfg.approvedExecutable, measured.identity); err != nil {
				measured.file.Close()
				cancel()
				return nil, err
			}
		}
		digest = measured.identity.Digest
		launch := sandbox.Launch{Path: measured.identity.Path, File: measured.file, Argv0: measured.identity.Path, Args: cfg.Command[1:], Env: append(os.Environ(), env...)}
		var report sandbox.Report
		var release func() error
		cmd, report, release, err = sandboxCommand(runCtx, launch, mode, cfg.SandboxWorkspace)
		if err != nil {
			measured.file.Close()
			cancel()
			return nil, err
		}
		protection = &report
		file := measured.file
		cleanup = func() error {
			file.Close()
			return release()
		}
	} else {
		path, err := exec.LookPath(cfg.Command[0])
		if err != nil {
			cancel()
			return nil, fmt.Errorf("server command could not be resolved: %v", err)
		}
		path, err = filepath.Abs(path)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("server command could not be resolved: %v", err)
		}
		if digest, err = executableDigest(path); err != nil {
			cancel()
			return nil, err
		}
		cmd = exec.CommandContext(runCtx, path, cfg.Command[1:]...)
		cmd.Args[0] = cfg.Command[0]
		cmd.Env = append(os.Environ(), env...)
	}
	cmd.WaitDelay = containers.WaitDelay
	// The server stays in this process's group, so a kill of the group
	// -- the gateway's, when this adapter is ended -- reaches it and what
	// it started; what it leaves behind is adopted here (Linux) and
	// reached when it is stopped.
	if err := adoptOrphans(); err != nil {
		cancel()
		return nil, errors.Join(err, cleanup())
	}
	stderr := &boundedBuffer{limit: containers.DiagnosticBytes}
	cmd.Stderr = stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, errors.Join(err, cleanup())
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, errors.Join(err, cleanup())
	}
	if measured != nil {
		// What is not executed through its digested descriptor is digested
		// again here, as close to the start as this process can.
		if err := recheckBeforeStart(measured, protection.ExecutesDigestedFile()); err != nil {
			cancel()
			return nil, errors.Join(err, cleanup())
		}
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, errors.Join(fmt.Errorf("server could not be started: %v", err), cleanup())
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
	var stopErr error
	stop := func() error {
		if stopped {
			return stopErr
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
		stopErr = killDescendants()
		if stopErr == nil {
			stopErr = cleanup()
		}
		return stopErr
	}
	srv := &server{sandbox: protection, rpc: stdioConversation{newClient(stdin, stdout)}, stop: stop, firstLine: func() string { return stderr.firstLine(redactor) },
		identity: adapterIdentity{Name: cfg.Command[0], Digest: digest}}
	if measured != nil {
		identity := measured.identity
		srv.executable = &identity
	}
	return srv, nil
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

// errNoServer is a configuration that names no server to run, or two.
// The command spells the three as the operator gives them: --image,
// --url, or a server command after --.
var errNoServer = errors.New("exactly one of --image, --url and a server command after -- names the server")
