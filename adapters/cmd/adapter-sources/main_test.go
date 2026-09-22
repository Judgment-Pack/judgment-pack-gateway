//go:build linux || darwin

package main

import (
	"adapters/attachment"
	"adapters/connections"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourcesCLIHelper(t *testing.T) {
	if os.Getenv("SOURCES_CLI_HELPER") != "1" {
		return
	}
	if json.Unmarshal([]byte(os.Getenv("SOURCES_CLI_ARGS")), &os.Args) != nil {
		os.Exit(99)
	}
	os.Exit(run())
}

func TestSourcesCLIConsumesOnlyTheSelectedGrant(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	vault := filepath.Join(dir, "vault")
	os.Mkdir(vault, 0700)
	os.Mkdir(filepath.Join(vault, ".obsidian"), 0700)
	os.WriteFile(filepath.Join(vault, "Policy.md"), []byte("Synthetic policy.\n"), 0600)
	store, err := connections.OpenObsidianStore(filepath.Join(dir, "state"), "fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	broker := connections.NewObsidian(store, false)
	defer broker.Close()
	params, _ := json.Marshal(map[string]string{"path": vault})
	if _, err = broker.Handle(context.Background(), "configure", params); err != nil {
		t.Fatal(err)
	}
	result, err := broker.Handle(context.Background(), "search", []byte(`{"query":"Policy"}`))
	if err != nil {
		t.Fatal(err)
	}
	params, _ = json.Marshal(map[string]any{"resourceIds": []string{"Policy.md"}, "selectionContext": result.(connections.SourceSearch).SelectionContext})
	selection, err := broker.Handle(context.Background(), "select", params)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(selection.([]connections.SourceSelection)[0])
	runCLI := func(provider, input string) ([]byte, string, error) {
		args, _ := json.Marshal([]string{"adapter-sources", "--state-dir", filepath.Join(dir, "state"), "--principal", "fixture", "--provider", provider})
		cmd := exec.Command(os.Args[0], "-test.run=^TestSourcesCLIHelper$")
		cmd.Env = append(os.Environ(), "SOURCES_CLI_HELPER=1", "SOURCES_CLI_ARGS="+string(args))
		cmd.Stdin = strings.NewReader(input)
		var diagnostic bytes.Buffer
		cmd.Stderr = &diagnostic
		out, err := cmd.Output()
		return out, diagnostic.String(), err
	}
	if out, _, err := runCLI("notion", string(raw)); err == nil || len(out) != 0 {
		t.Fatal("cross-provider grant accepted")
	}
	if out, _, err := runCLI("unknown", string(raw)); err == nil || len(out) != 0 {
		t.Fatal("unknown provider accepted")
	}
	if out, diagnostic, err := runCLI("obsidian", strings.Repeat(" ", 4097)); err == nil || len(out) != 0 || diagnostic != "invalid-request\n" {
		t.Fatal("oversized request accepted", err)
	}
	out, diagnostic, err := runCLI("obsidian", string(raw))
	if err != nil || diagnostic != "" || attachment.Check(out) != nil {
		t.Fatal("valid selected note refused", err, diagnostic)
	}
	if bytes.Contains(out, []byte(vault)) {
		t.Fatal("absolute vault path leaked")
	}
	if out, _, err := runCLI("obsidian", string(raw)); err == nil || len(out) != 0 {
		t.Fatal("replayed grant accepted")
	}
}
