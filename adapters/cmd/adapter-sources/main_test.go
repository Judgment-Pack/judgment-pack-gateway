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
	"time"
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

// --long-search is the web-search source's alone, as --document-processing
// is S3's: any other provider launched with it is refused.
func TestTheLongSearchEnvelopeIsWebSearchsAlone(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	for _, provider := range []string{"notion", "obsidian", "aws-s3", "databricks", "azure-devops"} {
		args, _ := json.Marshal([]string{"adapter-sources", "--state-dir", dir, "--principal", "fixture", "--provider", provider, "--long-search"})
		cmd := exec.Command(os.Args[0], "-test.run=^TestSourcesCLIHelper$")
		cmd.Env = append(os.Environ(), "SOURCES_CLI_HELPER=1", "SOURCES_CLI_ARGS="+string(args))
		cmd.Stdin = strings.NewReader("{}")
		err := cmd.Run()
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 2 {
			t.Fatalf("%s took --long-search: %v", provider, err)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatal("a refused launch opened custody")
	}
}

// Each launch gives the read the deadline its envelope allows: 55 seconds,
// 125 under --long-search, 140 under --document-processing.
func TestEachLaunchGivesTheReadItsDeadline(t *testing.T) {
	for _, c := range []struct {
		processing, longSearch bool
		want                   time.Duration
	}{{false, false, 55 * time.Second}, {false, true, 125 * time.Second}, {true, false, 140 * time.Second}} {
		ctx, cancel := readContext(c.processing, c.longSearch)
		deadline, ok := ctx.Deadline()
		cancel()
		if left := time.Until(deadline); !ok || left > c.want || left < c.want-time.Second {
			t.Errorf("processing %v, long search %v: %v left, want %v", c.processing, c.longSearch, left, c.want)
		}
	}
}

func TestResearchDescriptionUsesTheAdapterWithoutAcquisition(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	store, err := connections.OpenSearchStore(dir, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	broker := connections.NewSearch(store, false)
	_, err = broker.Handle(t.Context(), "configure", []byte(`{"id":"test","name":"Test","provider":"tavily","dailyLimit":1,"credential":"tvly-fixture-secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	status, err := broker.Handle(t.Context(), "status", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(status)
	var state struct{ Connections []connections.SearchStatusRow }
	if json.Unmarshal(raw, &state) != nil || len(state.Connections) != 1 {
		t.Fatal("missing connection", string(raw))
	}
	c := state.Connections[0]
	broker.Close()
	store.Close()
	args, _ := json.Marshal([]string{"adapter-sources", "--state-dir", dir, "--principal", "fixture", "--provider", "web-search", "--describe-research"})
	request, _ := json.Marshal(map[string]string{"connection": c.ID, "revision": c.Revision})
	cmd := exec.Command(os.Args[0], "-test.run=^TestSourcesCLIHelper$")
	cmd.Env = append(os.Environ(), "SOURCES_CLI_HELPER=1", "SOURCES_CLI_ARGS="+string(args))
	cmd.Stdin = bytes.NewReader(request)
	var diagnostic bytes.Buffer
	cmd.Stderr = &diagnostic
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err, diagnostic.String())
	}
	var d connections.ResearchBindingDescriptor
	if json.Unmarshal(out, &d) != nil || d.Version != 1 || d.Adapter.Name != "adapter-sources" || d.Endpoint != "https://api.tavily.com/search" || d.FixedArguments["revision"] != c.Revision || bytes.Contains(out, []byte("tvly-fixture-secret")) {
		t.Fatal("invalid description")
	}
	// The acquisition request parser is not switched by a JSON member. This mode
	// exists only on an operator-selected invocation of the trusted executable.
	for _, provider := range []string{"notion", "obsidian", "aws-s3", "databricks", "azure-devops"} {
		args, _ := json.Marshal([]string{"adapter-sources", "--state-dir", dir, "--principal", "fixture", "--provider", provider, "--describe-research"})
		cmd := exec.Command(os.Args[0], "-test.run=^TestSourcesCLIHelper$")
		cmd.Env = append(os.Environ(), "SOURCES_CLI_HELPER=1", "SOURCES_CLI_ARGS="+string(args))
		cmd.Stdin = strings.NewReader("{}")
		if err := cmd.Run(); err == nil {
			t.Fatal("foreign provider accepted description mode", provider)
		}
	}
}
