package mcp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ownerFileFixture(t *testing.T, cfg Config) (Config, []byte) {
	t.Helper()
	raw, err := canonicalJSON(map[string]any{"declarationVersion": "1", "platform": cfg.ApprovedPlatform, "binding": cfg.ApprovedBinding, "operation": cfg.ApprovedOperation, "tools": cfg.ToolTaxonomies})
	if err != nil {
		t.Fatal(err)
	}
	cfg.OwnerDeclarationFile = filepath.Join(t.TempDir(), "owner.json")
	cfg.ToolTaxonomies = nil
	writeOwnerFile(t, &cfg, raw)
	return cfg, raw
}
func writeOwnerFile(t *testing.T, cfg *Config, raw []byte) {
	t.Helper()
	other := *cfg
	other.DescriptorSnapshot = cfg.OwnerDeclarationFile
	writeApproval(t, &other, raw)
	cfg.OwnerDeclarationPin = other.DescriptorPin
}

func TestV2OwnerFileSupportsCompleteCaptureAndNarrowedInvocation(t *testing.T) {
	server, cfg, _ := approvedFixture(t)
	cfg, _ = ownerFileFixture(t, cfg)
	cfg.Tools = []string{"close"}
	if _, err := Acquire(within(t), cfg, Request{Tool: "close", Arguments: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	before := len(server.Requests())
	if _, err := Acquire(within(t), cfg, Request{Tool: "query"}); err == nil || len(server.Requests()) != before {
		t.Fatal("file projection widened execution")
	}
	capture := cfg
	capture.Tools = []string{"query", "close"}
	capture.DescriptorSnapshot, capture.DescriptorPin = "", ""
	capture.ApprovedPlatform, capture.ApprovedBinding, capture.ApprovedOperation = "", "", ""
	capture.Descriptors = &DescriptorTarget{Platform: "tickets", Binding: testBinding, Operation: "live"}
	if _, err := Check(within(t), capture); err != nil {
		t.Fatal(err)
	}
	capture.Tools = []string{"close"}
	before = len(server.Requests())
	if _, err := Check(within(t), capture); err == nil || len(server.Requests()) != before {
		t.Fatal("partial capture accepted")
	}
}

func TestV2OwnerFileMalformedOrChangedEvidenceRefusesBeforeCredentials(t *testing.T) {
	for _, name := range []string{"missing", "changed", "wrong-pin", "unknown-version", "operation", "binding", "platform", "unknown-key", "noncanonical", "overflow", "symbolic-file", "symbolic-parent", "mixed", "missing-pin"} {
		t.Run(name, func(t *testing.T) {
			server, cfg, _ := approvedFixture(t)
			cfg, raw := ownerFileFixture(t, cfg)
			switch name {
			case "missing":
				cfg.OwnerDeclarationFile += ".missing"
			case "wrong-pin":
				cfg.OwnerDeclarationPin = "sha256:" + strings.Repeat("0", 64)
			case "changed":
				os.WriteFile(cfg.OwnerDeclarationFile, append(raw, ' '), 0o600)
			case "unknown-version":
				writeOwnerFile(t, &cfg, bytes.Replace(raw, []byte(`"declarationVersion":"1"`), []byte(`"declarationVersion":"2"`), 1))
			case "operation":
				cfg.ApprovedOperation = "write"
			case "binding":
				cfg.ApprovedBinding = "other@sha256:" + strings.Repeat("0", 64)
			case "platform":
				cfg.ApprovedPlatform = "other"
			case "unknown-key":
				writeOwnerFile(t, &cfg, bytes.Replace(raw, []byte(`{"binding"`), []byte(`{"extra":true,"binding"`), 1))
			case "noncanonical":
				writeOwnerFile(t, &cfg, append(raw, ' '))
			case "overflow":
				writeOwnerFile(t, &cfg, bytes.Repeat([]byte("x"), MaxOwnerDeclarationBytes+1))
			case "symbolic-file":
				target := cfg.OwnerDeclarationFile
				cfg.OwnerDeclarationFile = filepath.Join(t.TempDir(), "link")
				if err := os.Symlink(target, cfg.OwnerDeclarationFile); err != nil {
					t.Fatal(err)
				}
			case "symbolic-parent":
				target := filepath.Dir(cfg.OwnerDeclarationFile)
				parent := filepath.Join(t.TempDir(), "link")
				if err := os.Symlink(target, parent); err != nil {
					t.Fatal(err)
				}
				cfg.OwnerDeclarationFile = filepath.Join(parent, "owner.json")
			case "mixed":
				cfg.ToolTaxonomies = map[string]ToolTaxonomy{"query": {Operation: "read", Effect: "read-external"}}
			case "missing-pin":
				cfg.OwnerDeclarationPin = ""
			}
			before := len(server.Requests())
			cfg.Credentials = filepath.Join(t.TempDir(), "must-not-read-credentials")
			if _, err := Acquire(within(t), cfg, Request{Tool: "query"}); err == nil || strings.Contains(err.Error(), "must-not-read-credentials") {
				t.Fatalf("owner admission: %v", err)
			}
			if len(server.Requests()) != before {
				t.Fatal("invalid owner file reached target")
			}
		})
	}
}
