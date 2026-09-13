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

// The budget for stopping a container once the acquisition is over, on top
// of the acquisition's own timeout: the kill, and the inspect that follows
// a failed kill. The command's default timeout leaves room for both under
// the gateway's thirty seconds.
const (
	killWindow    = 3 * time.Second
	inspectWindow = 2 * time.Second
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
	stopped bool
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
func startContainer(ctx context.Context, runtime, image, verb string, files map[string][]byte, args []string) (*container, error) {
	dir, err := os.MkdirTemp("", "adapter-airbyte-")
	if err != nil {
		return nil, fmt.Errorf("mount directory: %w", err)
	}
	mount := filepath.Join(dir, "secrets")
	if err := os.Mkdir(mount, 0o755); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("mount directory: %w", err)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(mount, name), data, 0o644); err != nil {
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
	argv := append([]string{"run", "--rm", "--name", name, "-v", mount + ":/secrets:ro", image, verb}, args...)
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
	// A reader blocked on stdout returns when the context ends, whoever
	// holds the pipe's other end: a descendant of the runtime client that
	// outlived it would otherwise hold the scanner past every deadline.
	go func() {
		<-runCtx.Done()
		stdout.Close()
	}()
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

// stop ends the container and removes the mount directory, and establishes
// that the container is gone: the client's exit says nothing certain about
// its container, and a killed client leaves one running, so the container
// is always told to stop by name, and a kill the runtime refuses is
// followed by an inspect. A container the runtime still knows after that is
// an error the acquisition must not hide -- it holds the credentials mount.
// Safe to call twice; the second call does nothing and returns nil.
func (c *container) stop() error {
	if c.stopped {
		return nil
	}
	c.stopped = true
	c.cancel()
	err := c.stopByName()
	c.wait()
	if c.dir != "" {
		os.RemoveAll(c.dir)
		c.dir = ""
	}
	return err
}

func (c *container) stopByName() error {
	killCtx, cancelKill := context.WithTimeout(context.Background(), killWindow)
	defer cancelKill()
	kill := exec.CommandContext(killCtx, c.runtime, "kill", c.name)
	kill.Env = os.Environ()
	if kill.Run() == nil {
		return nil
	}
	inspectCtx, cancelInspect := context.WithTimeout(context.Background(), inspectWindow)
	defer cancelInspect()
	inspect := exec.CommandContext(inspectCtx, c.runtime, "inspect", c.name)
	inspect.Env = os.Environ()
	if inspect.Run() != nil {
		return nil // absent: it ended on its own, and --rm removed it
	}
	return fmt.Errorf("container %s could not be stopped and is still known to %s; stop it by hand -- it holds the credentials mount", c.name, c.runtime)
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

// boundedBuffer keeps the first limit bytes written to it and drops the
// rest, reporting every write as complete: a writer that reported a short
// write would have os/exec's copier stop and close the pipe on the child.
type boundedBuffer struct {
	limit int
	buf   []byte
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if room := b.limit - len(b.buf); room > 0 {
		kept := p
		if len(kept) > room {
			kept = kept[:room]
		}
		b.buf = append(b.buf, kept...)
	}
	return len(p), nil
}

func (b *boundedBuffer) String() string { return string(b.buf) }
