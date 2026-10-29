//go:build !windows

package mcp

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"adapters/internal/sandbox"
)

// otherAnswer is a tools/call result file holding another answer, which a
// program other than the approved one returns.
func otherAnswer(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "answer.json")
	if err := os.WriteFile(path, []byte(`{"content":[{"type":"text","text":"a different answer"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A "#!" command binds the interpreter that runs it, by path and digest, and
// for "#!/usr/bin/env NAME" the program env finds on the server's PATH: a
// re-pointed interpreter link, other interpreter bytes, or another NAME
// earlier on PATH refuses before anything starts.
func TestCustomerShebangInterpreterBound(t *testing.T) {
	for _, mode := range customerModes() {
		t.Run(mode, func(t *testing.T) {
			bin := filepath.Join(t.TempDir(), "server")
			copyExecutable(t, bin)
			cfg := customerCommand(t, nil, mode)
			ws := cfg.SandboxWorkspace
			// A virtual environment's bin/python is such a link.
			interp := filepath.Join(ws, "interp")
			if err := os.Symlink("/bin/sh", interp); err != nil {
				t.Fatal(err)
			}
			script := filepath.Join(ws, "server.sh")
			if err := os.WriteFile(script, []byte("#!"+interp+"\nexec '"+bin+"' \"$@\"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			cfg.Command = []string{script}
			approved, snap := registerCustomer(t, cfg)
			sh, _ := filepath.EvalSymlinks("/bin/sh")
			if len(snap.Executable.Interpreters) != 1 || snap.Executable.Interpreters[0].Path != sh {
				t.Fatalf("approved interpreters %+v, want %s", snap.Executable.Interpreters, sh)
			}
			evil := filepath.Join(ws, "evil")
			if err := os.WriteFile(evil, []byte("#!/bin/sh\nMCP_FAKE_RESULT="+otherAnswer(t)+" exec '"+bin+"' \"$@\"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			os.Remove(interp)
			if err := os.Symlink(evil, interp); err != nil {
				t.Fatal(err)
			}
			_, err := Acquire(within(t), approved, query("select 1"))
			refusedBeforeStart(t, err, "mcp-executable-changed:")
			if !strings.Contains(err.Error(), "#! interpreter") {
				t.Fatalf("the refusal names something else: %v", err)
			}
			// The same path, other bytes: an interpreter copied into the
			// workspace and then changed there.
			os.Remove(interp)
			copyFile(t, sh, interp)
			cfg.Command = []string{script}
			approved, _ = registerCustomer(t, cfg)
			f, err := os.OpenFile(interp, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			f.Write([]byte("other bytes"))
			f.Close()
			_, err = Acquire(within(t), approved, query("select 1"))
			refusedBeforeStart(t, err, "mcp-executable-changed: a #! interpreter differs from the")
		})
	}
}

func TestCustomerEnvShebangProgramBound(t *testing.T) {
	if _, err := os.Stat("/usr/bin/env"); err != nil {
		t.Skip("no /usr/bin/env")
	}
	for _, mode := range customerModes() {
		t.Run(mode, func(t *testing.T) {
			bin := filepath.Join(t.TempDir(), "server")
			copyExecutable(t, bin)
			first, earlier := t.TempDir(), t.TempDir()
			if err := os.WriteFile(filepath.Join(first, "probe-interp"), []byte("#!/bin/sh\nshift\nexec '"+bin+"' \"$@\"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", first+string(os.PathListSeparator)+os.Getenv("PATH"))
			cfg := customerCommand(t, nil, mode)
			script := filepath.Join(cfg.SandboxWorkspace, "server")
			if err := os.WriteFile(script, []byte("#!/usr/bin/env probe-interp\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			cfg.Command = []string{script}
			approved, snap := registerCustomer(t, cfg)
			found, _ := filepath.EvalSymlinks(filepath.Join(first, "probe-interp"))
			chain := snap.Executable.Interpreters
			if len(chain) < 2 || !strings.HasSuffix(chain[0].Path, "/env") || chain[1].Path != found {
				t.Fatalf("approved chain %+v, want env then %s", chain, found)
			}
			if err := os.WriteFile(filepath.Join(earlier, "probe-interp"), []byte("#!/bin/sh\nshift\nMCP_FAKE_RESULT="+otherAnswer(t)+" exec '"+bin+"' \"$@\"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", earlier+string(os.PathListSeparator)+os.Getenv("PATH"))
			_, err := Acquire(within(t), approved, query("select 1"))
			refusedBeforeStart(t, err, "mcp-executable-changed: a #! interpreter now resolves to another file")
		})
	}
	// env with an option or an assignment names no bindable program.
	for _, line := range []string{"#!/usr/bin/env -i probe\n", "#!/usr/bin/env PATH=/x probe\n", "#!/usr/bin/env\n"} {
		ws := t.TempDir()
		path := filepath.Join(ws, "server")
		os.WriteFile(path, []byte(line), 0o755)
		if _, err := measureCustomerCommand([]string{path}, ws, os.Environ()); err == nil || !strings.Contains(err.Error(), "mcp-executable-unbindable:") {
			t.Fatalf("%q: %v", line, err)
		}
	}
}

// A "#!" chain is opened by path, so it is resolved and digested again
// immediately before the start: a change after the measurement refuses.
func TestCustomerInterpreterRecheckBeforeStart(t *testing.T) {
	ws := t.TempDir()
	interp := filepath.Join(ws, "interp")
	if err := os.Symlink("/bin/sh", interp); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(ws, "server.sh")
	if err := os.WriteFile(script, []byte("#!"+interp+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	m, err := measureCustomerCommand([]string{script}, ws, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	defer m.file.Close()
	if err := recheckBeforeStart(m, false); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(ws, "other")
	copyFile(t, os.Args[0], other)
	os.Remove(interp)
	if err := os.Symlink(other, interp); err != nil {
		t.Fatal(err)
	}
	if err := recheckBeforeStart(m, false); err == nil || !strings.Contains(err.Error(), "mcp-executable-changed: a #! interpreter changed between its digest and its start") {
		t.Fatalf("an interpreter changed before the start: %v", err)
	}
}

// A writer of the approved file that rewrites it in place, after its digest
// and before its start, does not change what runs: a binary runs from a
// sealed copy of the digested bytes. The check report says so.
func TestCustomerInPlaceRewriteAfterDigestDoesNotRun(t *testing.T) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("a sealed copy is Linux's; elsewhere the file is re-checked by path")
	}
	for _, mode := range customerModes() {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			server, other := filepath.Join(dir, "server"), filepath.Join(dir, "other")
			copyExecutable(t, server)
			copyExecutable(t, other)
			cfg := customerCommand(t, []string{server}, mode)
			out, err := Check(within(t), cfg)
			if err != nil {
				t.Fatal(err)
			}
			var report struct {
				Check struct {
					Sandbox sandbox.Report `json:"sandbox"`
				} `json:"check"`
			}
			if json.Unmarshal(out, &report) != nil || !strings.Contains(report.Check.Sandbox.Reason, "runs from a sealed in-memory copy of the digested bytes") {
				t.Fatalf("the report does not say what runs: %s", out)
			}
			approved, snap := registerCustomer(t, cfg)
			saved := sandboxCommand
			t.Cleanup(func() { sandboxCommand = saved })
			rewrites := 0
			sandboxCommand = func(ctx context.Context, launch sandbox.Launch, mode, workspace string) (*exec.Cmd, sandbox.Report, func() error, error) {
				// Between the digest and the start, the same file (same
				// inode) is written with another program.
				w, err := os.OpenFile(launch.Path, os.O_WRONLY|os.O_TRUNC, 0)
				if err == nil {
					w.Write([]byte("#!/bin/sh\nMCP_FAKE_RESULT=" + otherAnswer(t) + " exec '" + other + "' \"$@\"\n"))
					w.Close()
					rewrites++
				}
				return saved(ctx, launch, mode, workspace)
			}
			out, err = Acquire(within(t), approved, query("select 1"))
			if rewrites != 1 {
				t.Fatalf("the rewrite did not happen: %d", rewrites)
			}
			if err != nil {
				t.Fatalf("the approved bytes did not run: %v", err)
			}
			acq, result := decode(t, out)
			if strings.Contains(string(result), "a different answer") {
				t.Fatalf("the rewritten file ran: %s", result)
			}
			if adapter, _ := acq["adapter"].(map[string]any); adapter["digest"] != snap.Executable.Digest {
				t.Fatalf("receipt digest %v, approved %s", adapter["digest"], snap.Executable.Digest)
			}
		})
	}
}

// The script is the first operand that names a regular file: an option's
// separate value that is not a file is passed over.
func TestCustomerScriptOperandIsTheFirstFile(t *testing.T) {
	ws := t.TempDir()
	for _, name := range []string{"server.py", "hook.js", "server.js"} {
		os.WriteFile(filepath.Join(ws, name), []byte(name), 0o644)
	}
	os.Mkdir(filepath.Join(ws, "dev"), 0o755)
	for _, c := range []struct {
		command []string
		want    string
	}{
		{[]string{"/bin/sh", "-X", "dev", "server.py"}, "server.py"},
		{[]string{"/bin/sh", "-X", "absent", "server.py"}, "server.py"},
		{[]string{"/bin/sh", "server.py"}, "server.py"},
		{[]string{"/bin/sh", "-c", "true"}, ""},
	} {
		m, err := measureCustomerCommand(c.command, ws, os.Environ())
		if err != nil {
			t.Fatal(err)
		}
		m.file.Close()
		got := ""
		if m.identity.Script != nil {
			got = filepath.Base(m.identity.Script.Path)
		}
		if got != c.want {
			t.Fatalf("%v binds %q, want %q", c.command[1:], got, c.want)
		}
	}
}

// A FIFO at the command path refuses at once: it is opened without waiting
// for a writer and is not a regular file.
func TestCustomerFifoAtCommandPathRefusesWithoutBlocking(t *testing.T) {
	ws := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(ws, "server"), 0o755); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := measureCustomerCommand([]string{"./server"}, ws, os.Environ())
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "is not a regular file") {
			t.Fatalf("a FIFO command: %v", err)
		}
	case <-time.After(5 * time.Second):
		w, _ := os.OpenFile(filepath.Join(ws, "server"), os.O_WRONLY, 0)
		w.Close()
		<-done
		t.Fatal("opening the command blocked on a FIFO")
	}
}

// The server's argv[0] is the configured word, which a multi-call program
// dispatches on; the binding is the resolved path.
func TestCustomerArgv0IsTheConfiguredWord(t *testing.T) {
	dir := t.TempDir()
	server := filepath.Join(dir, "server")
	copyExecutable(t, server)
	link := filepath.Join(dir, "sh")
	if err := os.Symlink(server, link); err != nil {
		t.Fatal(err)
	}
	cfg := customerCommand(t, []string{link}, customerModes()[0])
	saved := sandboxCommand
	t.Cleanup(func() { sandboxCommand = saved })
	var argv0, path string
	sandboxCommand = func(ctx context.Context, launch sandbox.Launch, mode, workspace string) (*exec.Cmd, sandbox.Report, func() error, error) {
		argv0, path = launch.Argv0, launch.Path
		return saved(ctx, launch, mode, workspace)
	}
	if _, err := Check(within(t), cfg); err != nil {
		t.Fatal(err)
	}
	resolved, _ := filepath.EvalSymlinks(server)
	if argv0 != link || path != resolved {
		t.Fatalf("argv[0] %q (want %q), path %q (want %q)", argv0, link, path, resolved)
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o755); err != nil {
		t.Fatal(err)
	}
}
