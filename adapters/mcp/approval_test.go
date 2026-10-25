package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"adapters/internal/fakemcp"
)

const ownedTools = `[{"name":"query","description":"Read tickets","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":true}},{"name":"close","description":"Close ticket","inputSchema":{"type":"object"},"annotations":{"destructiveHint":true}},{"name":"unallowed","inputSchema":{"type":"object"}}]`

func approvedFixture(t *testing.T) (*fakemcp.HTTPServer, Config, []byte) {
	t.Helper()
	server, cfg := remote(t, false, fakemcp.Script{Tools: ownedTools})
	cfg.Tools = []string{"query", "close"}
	cfg.ToolTaxonomies = map[string]ToolTaxonomy{"query": {Operation: "read", Effect: "read-external"}, "close": {Operation: "act", Effect: "act"}}
	cfg.Descriptors = &DescriptorTarget{Platform: "tickets", Binding: testBinding, Operation: "live"}
	out, err := Check(within(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw := readReport(t, out).Descriptors
	var snap snapshot
	if json.Unmarshal(raw, &snap) != nil || snap.SnapshotVersion != "2" || snap.Operation != "live" || len(snap.Tools) != 2 {
		t.Fatalf("capture: %s", raw)
	}
	cfg.Descriptors = nil
	cfg.DescriptorSnapshot = filepath.Join(t.TempDir(), "approved.json")
	cfg.ApprovedPlatform, cfg.ApprovedBinding, cfg.ApprovedOperation = "tickets", testBinding, "live"
	writeApproval(t, &cfg, raw)
	return server, cfg, raw
}

func writeApproval(t *testing.T, cfg *Config, raw []byte) {
	t.Helper()
	sum := sha256.Sum256(raw)
	cfg.DescriptorPin = "sha256:" + hex.EncodeToString(sum[:])
	if err := os.WriteFile(cfg.DescriptorSnapshot, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func callsSince(server *fakemcp.HTTPServer, start int) int {
	count := 0
	for _, r := range server.Requests()[start:] {
		if r.Method == "tools/call" {
			count++
		}
	}
	return count
}

func TestV2ApprovedInvocationAndHealthUseOriginalEvidence(t *testing.T) {
	server, cfg, raw := approvedFixture(t)
	for _, name := range cfg.Tools {
		before := len(server.Requests())
		if _, err := Acquire(within(t), cfg, Request{Tool: name, Arguments: json.RawMessage(`{}`)}); err != nil {
			t.Fatal(err)
		}
		if callsSince(server, before) != 1 {
			t.Fatal("one selected allowed call required")
		}
	}
	before := len(server.Requests())
	out, err := Check(within(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if callsSince(server, before) != 0 || !bytes.Equal(readReport(t, out).Descriptors, raw) {
		t.Fatal("health check changed approval or executed a tool")
	}
	kept, _ := os.ReadFile(cfg.DescriptorSnapshot)
	if !bytes.Equal(raw, kept) {
		t.Fatal("approval was refreshed")
	}
	before = len(server.Requests())
	if _, err := Acquire(within(t), cfg, Request{Tool: "unallowed"}); err == nil || len(server.Requests()) != before {
		t.Fatal("unallowed name reached server")
	}
}

func TestV2DriftRefusesBeforeCallWithoutReapproval(t *testing.T) {
	cases := map[string]func(*fakemcp.Script){
		"description": func(s *fakemcp.Script) { s.Tools = strings.Replace(ownedTools, "Read tickets", "Read changed", 1) },
		"schema": func(s *fakemcp.Script) {
			s.Tools = strings.Replace(ownedTools, `"type":"object"`, `"type":"string"`, 1)
		},
		"constraint": func(s *fakemcp.Script) {
			s.Tools = strings.Replace(ownedTools, `"readOnlyHint":true`, `"readOnlyHint":false`, 1)
		},
		"server":    func(s *fakemcp.Script) { s.ServerInfo = `{"name":"changed","version":"2.0"}` },
		"missing":   func(s *fakemcp.Script) { s.Tools = `[{"name":"close","inputSchema":{"type":"object"}}]` },
		"duplicate": func(s *fakemcp.Script) { s.Tools = `[{"name":"query"},{"name":"query"},{"name":"close"}]` },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			server, cfg, raw := approvedFixture(t)
			server.Set(change)
			before := len(server.Requests())
			for _, health := range []bool{false, true} {
				var err error
				if health {
					_, err = Check(within(t), cfg)
				} else {
					_, err = Acquire(within(t), cfg, Request{Tool: "query", Arguments: json.RawMessage(`{}`)})
				}
				if err == nil {
					t.Fatal("drift accepted")
				}
			}
			if callsSince(server, before) != 0 {
				t.Fatal("drifted tool called")
			}
			kept, _ := os.ReadFile(cfg.DescriptorSnapshot)
			if !bytes.Equal(raw, kept) {
				t.Fatal("drift reapproved")
			}
		})
	}
}

func TestV2ApprovalIdentityAndMalformedEvidenceRefuseBeforeStart(t *testing.T) {
	cases := map[string]func(*Config, []byte){
		"wrong-operation": func(c *Config, _ []byte) { c.ApprovedOperation = "write" },
		"wrong-platform":  func(c *Config, _ []byte) { c.ApprovedPlatform = "other" },
		"wrong-binding":   func(c *Config, _ []byte) { c.ApprovedBinding = "other@sha256:" + strings.Repeat("0", 64) },
		"wrong-endpoint":  func(c *Config, _ []byte) { c.URL += "/other" },
		"wrong-owner":     func(c *Config, _ []byte) { c.ToolTaxonomies["query"] = ToolTaxonomy{Operation: "act", Effect: "act"} },
		"missing-file":    func(c *Config, _ []byte) { c.DescriptorSnapshot += ".missing" },
		"wrong-pin":       func(c *Config, _ []byte) { c.DescriptorPin = "sha256:" + strings.Repeat("0", 64) },
		"unsafe-server": func(c *Config, raw []byte) {
			raw = bytes.Replace(raw, []byte(`"name":"fake-remote-mcp"`), []byte(`"name":"unsafe\u001b"`), 1)
			writeApproval(t, c, raw)
		},
		"unknown-owner-key": func(c *Config, raw []byte) {
			raw = bytes.Replace(raw, []byte(`"taxonomy":{"effect":"read-external"`), []byte(`"taxonomy":{"unknown":true,"effect":"read-external"`), 1)
			v, err := canonicalJSON(json.RawMessage(raw))
			if err != nil {
				t.Fatal(err)
			}
			writeApproval(t, c, v)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			server, cfg, raw := approvedFixture(t)
			change(&cfg, raw)
			before := len(server.Requests())
			cfg.Credentials = filepath.Join(t.TempDir(), "must-not-read-credentials")
			if _, err := Acquire(within(t), cfg, Request{Tool: "query"}); err == nil || strings.Contains(err.Error(), "must-not-read-credentials") {
				t.Fatalf("prestart refusal: %v", err)
			}
			if len(server.Requests()) != before {
				t.Fatal("invalid approval reached server")
			}
		})
	}
}

func TestV2CaptureModesAndOwnerSetRefuseBeforeStart(t *testing.T) {
	for _, name := range []string{"missing-operation", "unknown-operation", "missing-owner", "extra-owner", "duplicate-allowed", "act-probe", "overflow", "mixed-modes"} {
		t.Run(name, func(t *testing.T) {
			server, cfg, _ := approvedFixture(t)
			cfg.DescriptorSnapshot, cfg.DescriptorPin = "", ""
			cfg.ApprovedPlatform, cfg.ApprovedBinding, cfg.ApprovedOperation = "", "", ""
			cfg.Descriptors = &DescriptorTarget{Platform: "tickets", Binding: testBinding, Operation: "live"}
			switch name {
			case "missing-operation":
				cfg.Descriptors.Operation = ""
			case "unknown-operation":
				cfg.Descriptors.Operation = "history"
			case "missing-owner":
				delete(cfg.ToolTaxonomies, "query")
			case "extra-owner":
				cfg.ToolTaxonomies["alias"] = cfg.ToolTaxonomies["query"]
			case "duplicate-allowed":
				cfg.Tools = []string{"query", "query"}
			case "act-probe":
				cfg.Probe = "close"
			case "overflow":
				key := strings.Repeat("x", MaxOwnerDeclarationBytes)
				cfg.Tools = []string{key}
				cfg.ToolTaxonomies = map[string]ToolTaxonomy{key: {Operation: "act", Effect: "act"}}
			case "mixed-modes":
				cfg.DescriptorSnapshot = "other"
				cfg.DescriptorPin = "sha256:" + strings.Repeat("0", 64)
			}
			before := len(server.Requests())
			cfg.Credentials = filepath.Join(t.TempDir(), "must-not-read-credentials")
			if _, err := Check(context.Background(), cfg); err == nil || strings.Contains(err.Error(), "must-not-read-credentials") {
				t.Fatalf("invalid capture: %v", err)
			}
			if len(server.Requests()) != before {
				t.Fatal("invalid capture started target")
			}
		})
	}
}

func TestV2SelectedExecutionCannotReachApprovedSibling(t *testing.T) {
	server, cfg, _ := approvedFixture(t)
	cfg.Tools = []string{"close"}
	before := len(server.Requests())
	if _, err := Acquire(within(t), cfg, Request{Tool: "query"}); err == nil || len(server.Requests()) != before {
		t.Fatal("approved sibling exceeded narrowed execution allowlist")
	}
	if _, err := Acquire(within(t), cfg, Request{Tool: "close", Arguments: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if callsSince(server, before) != 1 {
		t.Fatal("selected tool must call once")
	}
	server.Set(func(s *fakemcp.Script) { s.Tools = strings.Replace(ownedTools, "Read tickets", "Sibling changed", 1) })
	before = len(server.Requests())
	if _, err := Acquire(within(t), cfg, Request{Tool: "close", Arguments: json.RawMessage(`{}`)}); err == nil || callsSince(server, before) != 0 {
		t.Fatal("unselected sibling drift did not block selected call")
	}
	cfg.Tools = []string{"outside-owner"}
	before = len(server.Requests())
	if _, err := Acquire(within(t), cfg, Request{Tool: "outside-owner"}); err == nil || len(server.Requests()) != before {
		t.Fatal("execution subset escaped approved map")
	}
}

func TestV2FreshCaptureRefusesOwnerConstraintContradiction(t *testing.T) {
	for _, hint := range []string{`"readOnlyHint":false`, `"destructiveHint":true`} {
		t.Run(hint, func(t *testing.T) {
			server, cfg, _ := approvedFixture(t)
			cfg.DescriptorSnapshot, cfg.DescriptorPin = "", ""
			cfg.ApprovedPlatform, cfg.ApprovedBinding, cfg.ApprovedOperation = "", "", ""
			cfg.Descriptors = &DescriptorTarget{Platform: "tickets", Binding: testBinding, Operation: "live"}
			server.Set(func(s *fakemcp.Script) { s.Tools = strings.Replace(ownedTools, `"readOnlyHint":true`, hint, 1) })
			before := len(server.Requests())
			if _, err := Check(within(t), cfg); err == nil {
				t.Fatal("contradictory owner registration accepted")
			}
			if callsSince(server, before) != 0 {
				t.Fatal("capture executed tool")
			}
		})
	}
}
