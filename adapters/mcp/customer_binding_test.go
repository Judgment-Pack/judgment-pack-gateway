package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"adapters/internal/fakemcp"
)

func TestServerSandboxEscalationIsANamedRefusal(t *testing.T) {
	cfg := fake(t)
	t.Setenv(fakemcp.EnvServerRequest, "sandbox/escalate")
	acquire(t, cfg, query("select 1"))
	for _, msg := range trace(t) {
		if msg["id"] == "srv-1" {
			err, ok := msg["error"].(map[string]any)
			if !ok || err["code"] != float64(-32601) || !strings.HasPrefix(err["message"].(string), "sandbox-escalation-refused:") {
				t.Fatalf("escalation response: %v", msg)
			}
			return
		}
	}
	t.Fatal("no escalation refusal sent")
}

func customerApproval(t *testing.T) (*fakemcp.HTTPServer, Config) {
	t.Helper()
	server, cfg, _ := approvedFixture(t)
	cfg.Customer = true
	file := cfg.DescriptorSnapshot
	cfg.DescriptorSnapshot, cfg.DescriptorPin = "", ""
	cfg.Descriptors = &DescriptorTarget{Platform: cfg.ApprovedPlatform, Binding: cfg.ApprovedBinding, Operation: cfg.ApprovedOperation}
	cfg.ApprovedPlatform, cfg.ApprovedBinding, cfg.ApprovedOperation = "", "", ""
	out, err := Check(within(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw := readReport(t, out).Descriptors
	var snap snapshot
	if json.Unmarshal(raw, &snap) != nil || snap.SnapshotVersion != "3" {
		t.Fatalf("customer capture: %s", raw)
	}
	// Independent expected digest of the handwritten query descriptor.
	sum := sha256.Sum256([]byte(`{"name":"query","description":"Read tickets","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":true}}`))
	if snap.Tools["query"].DescriptorDigest != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatal("snapshot omitted the complete wire descriptor")
	}
	cfg.DescriptorSnapshot = file
	cfg.ApprovedPlatform, cfg.ApprovedBinding, cfg.ApprovedOperation = cfg.Descriptors.Platform, cfg.Descriptors.Binding, cfg.Descriptors.Operation
	cfg.Descriptors = nil
	writeApproval(t, &cfg, raw)
	return server, cfg
}

func TestCustomerSnapshotChecksCompleteDescriptors(t *testing.T) {
	for _, replacement := range []string{
		`"inputSchema":{"type":"object","pattern":"changed"}`,
		`"inputSchema":{"type":"object"},"outputSchema":{"type":"string"}`,
		`"inputSchema":{"type":"object"},"title":"Changed title"`,
	} {
		server, cfg := customerApproval(t)
		if _, err := Acquire(within(t), cfg, Request{Tool: "query", Arguments: json.RawMessage(`{}`)}); err != nil {
			t.Fatal(err)
		}
		before := len(server.Requests())
		server.Set(func(s *fakemcp.Script) {
			s.Tools = strings.Replace(ownedTools, `"inputSchema":{"type":"object"}`, replacement, 1)
		})
		_, err := Acquire(within(t), cfg, Request{Tool: "query", Arguments: json.RawMessage(`{}`)})
		if err == nil || !strings.Contains(err.Error(), "mcp-descriptor-drift:") || callsSince(server, before) != 0 {
			t.Fatalf("complete descriptor drift: %v", err)
		}
	}
}

func TestApprovedCustomerAcquisitionNamesBindingAndDescriptorSnapshot(t *testing.T) {
	_, cfg := customerApproval(t)
	out, err := Acquire(within(t), cfg, Request{Tool: "query", Arguments: json.RawMessage(`{"id":"7"}`)})
	if err != nil {
		t.Fatal(err)
	}
	var got envelope
	if err := json.Unmarshal(out, &got); err != nil || got.Acquisition.Statement == nil {
		t.Fatalf("missing acquisition statement: %v", err)
	}
	var statement map[string]json.RawMessage
	if err := json.Unmarshal([]byte(*got.Acquisition.Statement), &statement); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"binding": cfg.ApprovedBinding, "descriptorSnapshot": cfg.DescriptorPin, "tool": "query"} {
		var value string
		if json.Unmarshal(statement[key], &value) != nil || value != want {
			t.Fatalf("statement %s = %s, want %q", key, statement[key], want)
		}
	}
	if string(statement["arguments"]) != `{"id":"7"}` || len(statement) != 4 {
		t.Fatalf("call arguments changed: %s", *got.Acquisition.Statement)
	}
	if got.Acquisition.Snapshot != nil {
		t.Fatal("descriptor approval must not masquerade as an upstream currency bookmark")
	}
}

func TestCustomerBindingNamedRefusalsSendNoToolCall(t *testing.T) {
	for _, scenario := range []string{"unallowed", "drift", "contradiction"} {
		t.Run(scenario, func(t *testing.T) {
			server, cfg := customerApproval(t)
			before := len(server.Requests())
			tool, want := "query", "mcp-tool-not-allowed:"
			switch scenario {
			case "unallowed":
				tool = "unallowed"
			case "drift":
				want = "mcp-descriptor-drift:"
				server.Set(func(s *fakemcp.Script) {
					s.Tools = strings.Replace(ownedTools, "Read tickets", "Changed description", 1)
				})
			case "contradiction":
				want = "mcp-taxonomy-contradiction:"
				server.Set(func(s *fakemcp.Script) {
					s.Tools = strings.Replace(ownedTools, `"readOnlyHint":true`, `"readOnlyHint":false`, 1)
				})
			}
			_, err := Acquire(within(t), cfg, Request{Tool: tool, Arguments: json.RawMessage(`{}`)})
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("want named refusal %s, got %v", want, err)
			}
			if callsSince(server, before) != 0 {
				t.Fatal("refused tool reached tools/call")
			}
		})
	}
}
