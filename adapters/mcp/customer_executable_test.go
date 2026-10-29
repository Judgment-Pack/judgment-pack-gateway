package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"adapters/internal/fakemcp"
	"adapters/internal/sandbox"
)

// withoutLoaderVariables removes from this test's environment, which a
// server command inherits as the adapter's own, every variable a customer
// command refuses (a runner's toolchain may set LD_LIBRARY_PATH); the
// adapter itself runs with the engine's environment, which holds none.
func withoutLoaderVariables(t *testing.T) {
	t.Helper()
	for _, pair := range os.Environ() {
		name, _, _ := strings.Cut(pair, "=")
		if sandbox.LoaderVariable(name) {
			t.Setenv(name, "")
			os.Unsetenv(name)
		}
	}
}

// customerModes are the policies a customer command can run under here:
// Windows refuses every restricted mode before a process starts.
func customerModes() []string {
	if runtime.GOOS == "windows" {
		return []string{"danger-full-access"}
	}
	return []string{"workspace-write", "danger-full-access"}
}

// customerCommand is a customer command configuration for registration,
// with the fake server's files inside the workspace a confined server may
// write, and the sandbox policy outside it.
func customerCommand(t *testing.T, command []string, mode string) Config {
	t.Helper()
	cfg := fake(t)
	workspace := t.TempDir()
	t.Setenv(fakemcp.EnvTrace, filepath.Join(workspace, "trace.jsonl"))
	t.Setenv(fakemcp.EnvKills, filepath.Join(workspace, "kills"))
	t.Setenv(fakemcp.EnvHolderPid, filepath.Join(workspace, "holder"))
	cfg.Customer = true
	cfg.Command = command
	cfg.SandboxWorkspace = workspace
	cfg.SandboxPolicy = filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(cfg.SandboxPolicy, []byte(`{"policyVersion":"1","defaultMode":"`+mode+`","sources":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Tools = []string{"query"}
	cfg.ToolTaxonomies = map[string]ToolTaxonomy{"query": {Operation: "read", Effect: "read-external"}}
	cfg.Descriptors = &DescriptorTarget{Platform: "tickets", Binding: testBinding, Operation: "live"}
	return cfg
}

// registerCustomer runs the registration check and approves what it
// captured, as connect does; it returns the approving configuration and the
// approved snapshot.
func registerCustomer(t *testing.T, cfg Config) (Config, snapshot) {
	t.Helper()
	out, err := Check(within(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw := readReport(t, out).Descriptors
	var snap snapshot
	if json.Unmarshal(raw, &snap) != nil || snap.SnapshotVersion != "4" || snap.Executable == nil {
		t.Fatalf("customer command capture binds no executable: %s", raw)
	}
	cfg.Descriptors = nil
	cfg.DescriptorSnapshot = filepath.Join(t.TempDir(), "approved.json")
	cfg.ApprovedPlatform, cfg.ApprovedBinding, cfg.ApprovedOperation = "tickets", testBinding, "live"
	writeApproval(t, &cfg, raw)
	if _, err := Acquire(within(t), cfg, query("select 1")); err != nil {
		t.Fatal(err)
	}
	return cfg, snap
}

// copyExecutable copies the test binary, the fake server, to path.
func copyExecutable(t *testing.T, path string) {
	t.Helper()
	in, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

func exe(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

// refusedBeforeStart holds a refusal to its named reason and to no server
// start: the fake's trace is unchanged.
func refusedBeforeStart(t *testing.T, err error, reason string) {
	t.Helper()
	before, _ := os.ReadFile(os.Getenv(fakemcp.EnvTrace))
	if err == nil || !strings.Contains(err.Error(), reason) {
		t.Fatalf("want %s, got %v", reason, err)
	}
	after, _ := os.ReadFile(os.Getenv(fakemcp.EnvTrace))
	if !bytes.Equal(before, after) {
		t.Fatal("the refused command was started")
	}
}

func TestCustomerExecutableSwappedBinaryRefused(t *testing.T) {
	for _, mode := range customerModes() {
		t.Run(mode, func(t *testing.T) {
			server := filepath.Join(t.TempDir(), exe("server"))
			copyExecutable(t, server)
			cfg, snap := registerCustomer(t, customerCommand(t, []string{server}, mode))
			resolved, _ := filepath.EvalSymlinks(server)
			digest, _ := executableDigest(server)
			if snap.Executable.Path != resolved || snap.Executable.Digest != digest || snap.Executable.Script != nil {
				t.Fatalf("approved executable %+v, want %s %s", snap.Executable, resolved, digest)
			}
			// The same program with other bytes, put in place at the
			// approved path.
			replaceWithOtherBytes(t, server)
			_, err := Acquire(within(t), cfg, query("select 1"))
			refusedBeforeStart(t, err, "mcp-executable-changed:")
			_, err = Check(within(t), cfg)
			refusedBeforeStart(t, err, "mcp-executable-changed:")
		})
	}
}

func TestCustomerExecutableSwappedScriptRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("restricted modes refuse on Windows, and the script needs a POSIX shell")
	}
	for _, mode := range customerModes() {
		t.Run(mode, func(t *testing.T) {
			bin := filepath.Join(t.TempDir(), "server")
			copyExecutable(t, bin)
			cfg := customerCommand(t, []string{"/bin/sh", "server.sh"}, mode)
			script := filepath.Join(cfg.SandboxWorkspace, "server.sh")
			if err := os.WriteFile(script, []byte("exec '"+bin+"' \"$@\"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			cfg, snap := registerCustomer(t, cfg)
			resolved, _ := filepath.EvalSymlinks(script)
			digest, _ := executableDigest(script)
			if snap.Executable.Script == nil || snap.Executable.Script.Path != resolved || snap.Executable.Script.Digest != digest {
				t.Fatalf("approved script %+v, want %s %s", snap.Executable.Script, resolved, digest)
			}
			// The same interpreter runs a different script.
			if err := os.WriteFile(script, []byte("MCP_FAKE_RESULT=/dev/null exec '"+bin+"' \"$@\"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := Acquire(within(t), cfg, query("select 1"))
			refusedBeforeStart(t, err, "mcp-executable-changed: the script differs")
		})
	}
}

func TestCustomerExecutablePathChangeRefused(t *testing.T) {
	for _, mode := range customerModes() {
		t.Run(mode, func(t *testing.T) {
			first, second := t.TempDir(), t.TempDir()
			// Identical bytes: only the resolved path differs.
			copyExecutable(t, filepath.Join(first, exe("gateway-test-server")))
			copyExecutable(t, filepath.Join(second, exe("gateway-test-server")))
			t.Setenv("PATH", first)
			cfg, _ := registerCustomer(t, customerCommand(t, []string{"gateway-test-server"}, mode))
			t.Setenv("PATH", second)
			_, err := Acquire(within(t), cfg, query("select 1"))
			refusedBeforeStart(t, err, "mcp-executable-changed: the command now resolves to another file")
		})
	}
}

// An approval written before the executable was bound -- version 3 for a
// command -- is never read as approved, and one that drops the member is
// refused.
func TestCustomerExecutableOldApprovalNeedsReapproval(t *testing.T) {
	server := filepath.Join(t.TempDir(), exe("server"))
	copyExecutable(t, server)
	cfg, _ := registerCustomer(t, customerCommand(t, []string{server}, customerModes()[0]))
	raw, err := os.ReadFile(cfg.DescriptorSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "executable")
	withoutExecutable, _ := canonicalJSON(fields)
	fields["snapshotVersion"] = json.RawMessage(`"3"`)
	version3, _ := canonicalJSON(fields)
	for name, tc := range map[string]struct {
		raw    []byte
		reason string
	}{
		"version-3":          {version3, "mcp-approval-reapproval-required:"},
		"missing-executable": {withoutExecutable, "approved executable identity is missing"},
	} {
		t.Run(name, func(t *testing.T) {
			old := cfg
			old.DescriptorSnapshot = filepath.Join(t.TempDir(), "approved.json")
			writeApproval(t, &old, tc.raw)
			_, err := Acquire(within(t), old, query("select 1"))
			refusedBeforeStart(t, err, tc.reason)
			_, err = Check(within(t), old)
			refusedBeforeStart(t, err, tc.reason)
		})
	}
}

func TestCustomerLoaderVariableRefused(t *testing.T) {
	for _, tc := range []struct{ name, credentials, env string }{
		{"credential-LD_PRELOAD", `{"LD_PRELOAD":"/workspace/lib.so"}`, ""},
		{"credential-DYLD_INSERT_LIBRARIES", `{"DYLD_INSERT_LIBRARIES":"/workspace/lib.dylib"}`, ""},
		{"environment-LD_LIBRARY_PATH", "", "LD_LIBRARY_PATH"},
		{"environment-GCONV_PATH", "", "GCONV_PATH"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := filepath.Join(t.TempDir(), exe("server"))
			copyExecutable(t, server)
			cfg := customerCommand(t, []string{server}, customerModes()[0])
			approved, _ := registerCustomer(t, cfg)
			if tc.credentials != "" {
				if err := os.WriteFile(cfg.Credentials, []byte(tc.credentials), 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				t.Setenv(tc.env, cfg.SandboxWorkspace)
			}
			// At registration and at every start, before anything runs.
			_, err := Check(within(t), cfg)
			refusedBeforeStart(t, err, "sandbox-loader-variable-refused:")
			_, err = Acquire(within(t), approved, query("select 1"))
			refusedBeforeStart(t, err, "sandbox-loader-variable-refused:")
			if strings.Contains(err.Error(), "/workspace/") {
				t.Fatal("the refusal repeats a credential value")
			}
		})
	}
}

func TestCustomerExecutableRecheckBeforeStart(t *testing.T) {
	dir := t.TempDir()
	server, script := filepath.Join(dir, "server"), filepath.Join(dir, "server.sh")
	copyExecutable(t, server)
	if err := os.WriteFile(script, []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := measureCustomerCommand([]string{server, "server.sh"}, dir, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	if err := recheckBeforeStart(m, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("second"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := recheckBeforeStart(m, true); err == nil || !strings.Contains(err.Error(), "mcp-executable-changed: the script changed") {
		t.Fatalf("script change between digest and start: %v", err)
	}
	if err := os.WriteFile(script, []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Closed first: Windows does not replace a file that is open.
	m.file.Close()
	replaceWithOtherBytes(t, server)
	if err := recheckBeforeStart(m, true); err != nil {
		t.Fatalf("a command executed through its descriptor is not re-read: %v", err)
	}
	if err := recheckBeforeStart(m, false); err == nil || !strings.Contains(err.Error(), "mcp-executable-changed: the command's file changed") {
		t.Fatalf("command change between digest and start: %v", err)
	}
}

// replaceWithOtherBytes puts a copy of the fake server with bytes appended in
// place of path, as an update replaces a file.
func replaceWithOtherBytes(t *testing.T, path string) {
	t.Helper()
	next := path + ".next"
	copyExecutable(t, next)
	f, err := os.OpenFile(next, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("other bytes"))
	f.Close()
	if err := os.Rename(next, path); err != nil {
		t.Fatal(err)
	}
}
