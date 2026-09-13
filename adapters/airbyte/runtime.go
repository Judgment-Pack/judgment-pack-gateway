package airbyte

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// container is one connector command running inside the operator's
// container runtime, its stdout a stream the caller drains.
type container struct {
	runtime string
	name    string
	dir     string
	cmd     *exec.Cmd
	stdout  io.ReadCloser
	stderr  *boundedBuffer
	ctx     context.Context
	cancel  context.CancelFunc
	waited  bool
	waitErr error
	killed  bool
}

// startContainer writes files into a private directory, mounts it read-only
// at /secrets, and starts
//
//	RUNTIME run --rm --name NAME -v DIR:/secrets:ro IMAGE VERB ARGS...
//
// The runtime inherits this process's environment: it is the adapter's own,
// declared by the operator when the gateway spawned it, and a runtime needs
// its HOME and PATH. The connector sees only its files.
func startContainer(ctx context.Context, runtime, image, verb string, files map[string][]byte, args []string) (*container, error) {
	dir, err := os.MkdirTemp("", "adapter-airbyte-")
	if err != nil {
		return nil, fmt.Errorf("mount directory: %w", err)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			os.RemoveAll(dir)
			return nil, fmt.Errorf("mount directory: %w", err)
		}
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	name := "jp-airbyte-" + hex.EncodeToString(suffix[:])
	argv := append([]string{"run", "--rm", "--name", name, "-v", dir + ":/secrets:ro", image, verb}, args...)
	runCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(runCtx, runtime, argv...)
	cmd.Env = os.Environ()
	cmd.WaitDelay = 5 * time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		os.RemoveAll(dir)
		return nil, err
	}
	stderr := &boundedBuffer{limit: 4096}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		cancel()
		os.RemoveAll(dir)
		return nil, fmt.Errorf("%s could not be started: %w", runtime, err)
	}
	return &container{runtime: runtime, name: name, dir: dir, cmd: cmd, stdout: stdout, stderr: stderr, ctx: runCtx, cancel: cancel}, nil
}

// wait waits once for the runtime client and returns its error.
func (c *container) wait() error {
	if !c.waited {
		c.waited = true
		c.waitErr = c.cmd.Wait()
	}
	return c.waitErr
}

// stop ends the container whether or not its command has finished, and
// removes the mount directory. A runtime client that is killed leaves its
// container running, so the container is told to stop by name whenever the
// client did not end on its own: when it is still running here, or when
// its context was cancelled -- by this adapter once the page was complete,
// or by the caller's deadline -- before it was waited for. A client that
// ran to its own end took its container with it. Safe to call twice.
func (c *container) stop() {
	ended := c.waited && c.ctx.Err() == nil
	c.cancel()
	if !ended && !c.killed {
		c.killed = true
		killCtx, cancelKill := context.WithTimeout(context.Background(), 10*time.Second)
		kill := exec.CommandContext(killCtx, c.runtime, "kill", c.name)
		kill.Env = os.Environ()
		_ = kill.Run()
		cancelKill()
	}
	c.wait()
	if c.dir != "" {
		os.RemoveAll(c.dir)
		c.dir = ""
	}
}

// firstLine is the first line of what the connector wrote on stderr, for an
// error message; never the whole of it.
func (c *container) firstLine() string {
	text := c.stderr.String()
	for i, r := range text {
		if r == '\n' {
			return text[:i]
		}
	}
	return text
}

// boundedBuffer keeps the first limit bytes written to it and drops the rest.
type boundedBuffer struct {
	limit int
	buf   []byte
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if room := b.limit - len(b.buf); room > 0 {
		if len(p) > room {
			p = p[:room]
		}
		b.buf = append(b.buf, p...)
	}
	return len(p), nil
}

func (b *boundedBuffer) String() string { return string(b.buf) }
