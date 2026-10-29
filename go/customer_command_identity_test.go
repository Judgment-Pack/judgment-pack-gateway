package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A version-3 approval of a customer command predates executable binding:
// it is never read as approved, and the refusal names re-approval.
func TestCustomerCommandVersion3ApprovalNeedsReapproval(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "tool-taxonomy", "v4.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		SnapshotText string
		Operation    string
		Command      []string
		Tools        map[string]ToolTaxonomy
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(v.SnapshotText), &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "executable")
	fields["snapshotVersion"] = json.RawMessage(`"3"`)
	text, _ := json.Marshal(fields)
	s, err := parseSnapshot(text)
	if err != nil {
		t.Fatal(err)
	}
	op := operation{customer: true, name: v.Operation, taxonomies: v.Tools, command: v.Command}
	if err := snapshotOwners(s, &op); err == nil || !strings.Contains(err.Error(), "mcp-approval-reapproval-required:") {
		t.Fatalf("version-3 command approval: %v", err)
	}
	// The same snapshot still approves a customer binding that runs no command.
	op.command = nil
	if err := snapshotOwners(s, &op); err != nil {
		t.Fatal(err)
	}
}

func TestCustomerCommandLoaderEnvironmentRefused(t *testing.T) {
	command := binding{live: &operation{customer: true, command: []string{"server"}}}
	for _, name := range []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "GCONV_PATH"} {
		p := platformConfig{name: "tickets", environment: []string{"SERVICE_MODE=1", name + "=/workspace"}}
		if err := customerCommandEnvironment(p, command); err == nil || !strings.Contains(err.Error(), "sandbox-loader-variable-refused:") {
			t.Fatalf("%s: %v", name, err)
		}
		// A binding that runs no customer command is not this refusal's.
		for _, b := range []binding{{live: &operation{customer: true}}, {live: &operation{command: []string{"server"}}}} {
			if err := customerCommandEnvironment(p, b); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := customerCommandEnvironment(platformConfig{name: "tickets", environment: []string{"SERVICE_MODE=1"}}, command); err != nil {
		t.Fatal(err)
	}
}
