package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"testing"

	"adapters/internal/sandbox"
)

func TestEnclosingSandboxKeepsCustomerRegistrationGates(t *testing.T) {
	cfg := fake(t)
	cfg.Customer, cfg.SandboxEnclosing = true, true
	cfg.SandboxWorkspace = t.TempDir()
	if err := cfg.Refusal(); err == nil {
		t.Fatal("enclosing assertion bypassed owner declaration")
	}
	cfg.Tools = []string{"query"}
	cfg.ToolTaxonomies = map[string]ToolTaxonomy{"query": {Operation: "read", Effect: "read-external"}}
	if err := cfg.Refusal(); err == nil {
		t.Fatal("enclosing assertion bypassed snapshot approval")
	}
	cfg.Descriptors = &DescriptorTarget{Platform: "tickets", Binding: testBinding, Operation: "live"}
	if err := cfg.Refusal(); err != nil {
		t.Fatal(err)
	}
	saved := sandboxCommand
	t.Cleanup(func() { sandboxCommand = saved })
	sandboxCommand = func(context.Context, sandbox.Launch, string, string) (*exec.Cmd, sandbox.Report, func() error, error) {
		t.Error("enclosing assertion nested a native sandbox")
		return nil, sandbox.Report{}, func() error { return nil }, errors.New("unexpected nested sandbox")
	}
	raw, err := Check(within(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var wrapper struct {
		Check struct {
			Sandbox *sandbox.Report `json:"sandbox"`
		} `json:"check"`
	}
	if err = json.Unmarshal(raw, &wrapper); err != nil {
		t.Fatal(err)
	}
	report := wrapper.Check
	if report.Sandbox == nil || report.Sandbox.State != "not-enforced" || report.Sandbox.Backend != "enclosing-operator" || report.Sandbox.Mode != "workspace-write" {
		t.Fatalf("assertion became enforcement claim: %s", raw)
	}
	for _, change := range []func(*Config){func(c *Config) { c.Customer = false }, func(c *Config) { c.URL = "https://example.invalid/mcp"; c.Command = nil }, func(c *Config) { c.Image = "example@sha256:"; c.Command = nil }} {
		bad := cfg
		change(&bad)
		if err := bad.Refusal(); err == nil {
			t.Fatal("enclosing flag accepted without customer command")
		}
	}
}

func init() {
	if len(os.Args) > 1 && os.Args[1] == "_enclosing_environment_probe" {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]string{"TMPDIR": os.Getenv("TMPDIR"), "TMP": os.Getenv("TMP"), "TEMP": os.Getenv("TEMP")}})
		var b [1]byte
		os.Stdin.Read(b[:])
		os.Exit(0)
	}
}

func TestEnclosingSandboxPreservesPrivateTemporaryEnvironment(t *testing.T) {
	private := t.TempDir()
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(name, private)
	}
	cfg := Config{Customer: true, SandboxEnclosing: true, Command: []string{os.Args[0], "_enclosing_environment_probe"}, SandboxWorkspace: t.TempDir()}
	srv, err := startServer(within(t), cfg, []string{"TMPDIR=credential", "TMP=credential", "TEMP=credential"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.stop()
	raw, err := srv.rpc.call(within(t), "initialize", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err = json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		if got[name] != private {
			t.Fatalf("credentials replaced %s", name)
		}
	}
}
