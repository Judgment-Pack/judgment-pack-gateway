package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"adapters/internal/canon"
)

// The owner projection alone cannot exceed the existing complete snapshot ceiling.
const MaxOwnerDeclarationBytes = maxSnapshot
const OwnerChunkBytes = 16 << 10

func DecodeOwnerTaxonomies(chunks []string) (map[string]ToolTaxonomy, error) {
	if len(chunks) == 0 {
		return nil, nil
	}
	text := ""
	for _, part := range chunks {
		if len(part) > OwnerChunkBytes {
			return nil, errors.New("owner declaration chunk exceeds bound")
		}
		text += part
		if len(text) > base64.RawURLEncoding.EncodedLen(MaxOwnerDeclarationBytes) {
			return nil, errors.New("owner declaration exceeds snapshot bound")
		}
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil || len(raw) > MaxOwnerDeclarationBytes {
		return nil, errors.New("invalid owner declaration encoding")
	}
	canonical, err := canon.Canonicalize(raw, canon.RefuseNumbers)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, errors.New("owner declaration is not canonical")
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || len(obj) != 2 || string(obj["version"]) != `"1"` || obj["tools"] == nil {
		return nil, errors.New("unsupported owner declaration version")
	}
	var tools map[string]json.RawMessage
	if json.Unmarshal(obj["tools"], &tools) != nil || len(tools) == 0 {
		return nil, errors.New("missing owner tool declarations")
	}
	result := map[string]ToolTaxonomy{}
	for name, raw := range tools {
		t, err := decodeTaxonomy(raw)
		if err != nil || !t.External() {
			return nil, errors.New("invalid external owner declaration")
		}
		result[name] = t
	}
	return result, nil
}

func (cfg Config) ownerRefusal() error {
	if (cfg.OwnerDeclarationFile == "") != (cfg.OwnerDeclarationPin == "") {
		return errors.New("owner declaration file and pin go together")
	}
	if cfg.OwnerDeclarationFile != "" && (!canon.IsDigestString(cfg.OwnerDeclarationPin) || (cfg.ToolTaxonomies != nil && !cfg.ownerDeclarationLoaded)) {
		return errors.New("owner file and argv declarations are mutually exclusive and require an exact digest")
	}
	if cfg.Descriptors != nil {
		if err := cfg.Descriptors.refusal(); err != nil {
			return err
		}
		if cfg.DescriptorSnapshot != "" {
			return errors.New("capture and existing approval are separate modes")
		}
		if cfg.ToolTaxonomies != nil || cfg.OwnerDeclarationFile != "" {
			if cfg.Descriptors.Operation != "live" && cfg.Descriptors.Operation != "write" {
				return errors.New("V2 capture requires exact operation")
			}
		} else if cfg.Descriptors.Operation != "" {
			return errors.New("operation selector requires owner declarations")
		}
	}
	if cfg.DescriptorSnapshot == "" && (cfg.ApprovedOperation != "" || cfg.ApprovedPlatform != "" || cfg.ApprovedBinding != "") {
		return errors.New("approved identity requires a snapshot and pin")
	}
	if cfg.ToolTaxonomies != nil {
		if len(cfg.Tools) == 0 || (cfg.DescriptorSnapshot == "" && len(cfg.Tools) != len(cfg.ToolTaxonomies)) {
			return errors.New("owner map must match exact allowed tool set")
		}
		raw, err := canonicalJSON(map[string]any{"version": "1", "tools": cfg.ToolTaxonomies})
		if err != nil || len(raw) > MaxOwnerDeclarationBytes {
			return errors.New("owner declaration exceeds snapshot bound")
		}
		seen := map[string]bool{}
		for _, name := range cfg.Tools {
			t, ok := cfg.ToolTaxonomies[name]
			if seen[name] || !ok || !t.External() {
				return errors.New("missing, duplicate or extra owner declaration")
			}
			seen[name] = true
		}
		if cfg.Probe != "" && cfg.ToolTaxonomies[cfg.Probe].Effect == "act" {
			return errors.New("a check cannot probe an act tool")
		}
	}
	if (cfg.DescriptorSnapshot == "") != (cfg.DescriptorPin == "") {
		return errors.New("approved snapshot file and pin go together")
	}
	if cfg.DescriptorSnapshot != "" && ((cfg.ToolTaxonomies == nil && cfg.OwnerDeclarationFile == "") || !canon.IsDigestString(cfg.DescriptorPin) || (cfg.ApprovedOperation != "live" && cfg.ApprovedOperation != "write") || (DescriptorTarget{Platform: cfg.ApprovedPlatform, Binding: cfg.ApprovedBinding}).refusal() != nil) {
		return errors.New("snapshot approval requires owner declarations and a digest")
	}
	return nil
}

// Read and verify immutable approved bytes before any server or credential is reached.
func approvedSnapshot(cfg Config) (*snapshot, []byte, error) {
	if cfg.DescriptorSnapshot == "" {
		if cfg.ToolTaxonomies != nil {
			return nil, nil, errors.New("V2 invocation requires an approved snapshot")
		}
		return nil, nil, nil
	}
	raw, err := readImmutableEvidence(cfg.DescriptorSnapshot, maxSnapshot)
	if err != nil {
		return nil, nil, err
	}
	sum := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(sum[:]) != cfg.DescriptorPin {
		return nil, nil, errors.New("approved snapshot digest changed")
	}
	canonical, err := canon.Canonicalize(raw, canon.RefuseNumbers)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, nil, errors.New("approved snapshot is not canonical")
	}
	fields, err := exactMembers(raw)
	if err != nil {
		return nil, nil, err
	}
	for key := range fields {
		switch key {
		case "snapshotVersion", "operation", "binding", "capturedAt", "platform", "policy", "tools", "server", "endpoint":
		default:
			return nil, nil, errors.New("unknown snapshot member")
		}
	}
	for _, name := range []string{"snapshotVersion", "operation", "binding", "capturedAt", "platform"} {
		if len(fields[name]) == 0 || fields[name][0] != '"' {
			return nil, nil, errors.New("missing or malformed approved identity")
		}
	}
	server, err := exactMembers(fields["server"])
	if err != nil || len(server) != 2 {
		return nil, nil, errors.New("malformed approved server identity")
	}
	for _, name := range []string{"name", "version"} {
		if len(server[name]) == 0 || server[name][0] != '"' {
			return nil, nil, errors.New("malformed approved server identity")
		}
	}
	var snap snapshot
	if json.Unmarshal(raw, &snap) != nil || snap.SnapshotVersion != "2" || snap.Operation != cfg.ApprovedOperation || snap.Policy != displayPolicy || snap.Server == nil || snap.Platform != cfg.ApprovedPlatform || snap.Binding != cfg.ApprovedBinding || snap.Endpoint != cfg.URL || len(snap.Tools) != len(cfg.ToolTaxonomies) {
		return nil, nil, errors.New("approved V2 snapshot identity differs")
	}
	if snap.Server.Name == "" || checkIdentity(snap.Server.Name, snap.Server.Version, nil) != nil {
		return nil, nil, errors.New("invalid approved server identity")
	}
	if endpoint, present := fields["endpoint"]; present && (len(endpoint) == 0 || endpoint[0] != '"') {
		return nil, nil, errors.New("invalid approved endpoint")
	}
	parsed, err := time.Parse(stampLayout, snap.CapturedAt)
	if err != nil || parsed.Format(stampLayout) != snap.CapturedAt {
		return nil, nil, errors.New("invalid approved capture timestamp")
	}
	for name, t := range cfg.ToolTaxonomies {
		tool, ok := snap.Tools[name]
		if !ok || tool.Taxonomy == nil || *tool.Taxonomy != t {
			return nil, nil, errors.New("approved owner map differs")
		}
		// Decode the closed entry and owner shape independently of encoding/json's case folding.
		var entries map[string]json.RawMessage
		json.Unmarshal(fields["tools"], &entries)
		entry, err := exactMembers(entries[name])
		if err != nil {
			return nil, nil, err
		}
		for key := range entry {
			if key != "taxonomy" && key != "serverAnnotations" && key != "description" && key != "inputSchemaText" {
				return nil, nil, errors.New("unknown approved tool member")
			}
		}
		owner, err := decodeTaxonomy(entry["taxonomy"])
		if err != nil || owner != t {
			return nil, nil, errors.New("invalid approved taxonomy")
		}
		for _, key := range []string{"description", "inputSchemaText"} {
			if raw, present := entry[key]; present && (len(raw) == 0 || raw[0] != '"') {
				return nil, nil, errors.New("malformed approved display candidate")
			}
		}
		hints, err := recognizedAnnotations(entry["serverAnnotations"])
		if err != nil {
			return nil, nil, err
		}
		if raw, present := entry["serverAnnotations"]; present {
			members, _ := exactMembers(raw)
			if len(hints) != len(members) {
				return nil, nil, errors.New("unsupported approved server constraint")
			}
		}
		if t.Contradiction(hints) {
			return nil, nil, errors.New("approved server constraints contradict owner")
		}
		if tool.Description != nil {
			if _, r := checkDescription(entry["description"], nil); r != nil {
				return nil, nil, errors.New("invalid approved description")
			}
		}
		if tool.InputSchemaText != nil {
			if r := checkSchema([]byte(*tool.InputSchemaText), nil); r != nil {
				return nil, nil, errors.New("invalid approved input schema")
			}
		}
	}
	return &snap, raw, nil
}

func recognizedAnnotations(raw []byte) (map[string]bool, error) {
	if raw == nil {
		return nil, nil
	}
	fields, err := exactMembers(raw)
	if err != nil {
		return nil, errors.New("server annotations are not an object")
	}
	result := map[string]bool{}
	for key, value := range fields {
		if key != "readOnlyHint" && key != "destructiveHint" && key != "idempotentHint" && key != "openWorldHint" {
			continue
		}
		if string(value) != "true" && string(value) != "false" {
			return nil, errors.New("recognized server annotation is not boolean")
		}
		result[key] = string(value) == "true"
	}
	return result, nil
}

func (c *capturer) addOwned(tool listedTool, owner ToolTaxonomy) error {
	if holdsSecret(tool.name, c.secrets) {
		return errors.New("owner tool name holds a credential")
	}
	entry, refused := candidates(tool, c.secrets)
	for _, f := range refused {
		c.fallBack(f)
	}
	members, err := exactMembers(tool.descriptor)
	if err != nil {
		return err
	}
	hints, err := recognizedAnnotations(members["annotations"])
	if err != nil {
		return err
	}
	if owner.Contradiction(hints) {
		return errors.New("server constraints contradict owner taxonomy")
	}
	entry.Taxonomy = &owner
	entry.ServerAnnotations = hints
	name, err := canonicalJSON(tool.name)
	if err != nil {
		return err
	}
	encoded, err := canonicalJSON(entry)
	if err != nil {
		return err
	}
	grow := len(name) + 1 + len(encoded)
	if len(c.snap.Tools) > 0 {
		grow++
	}
	text := len(deref(entry.Description)) + len(deref(entry.InputSchemaText))
	if c.size+grow > maxSnapshot || c.text+text > maxCandidateText {
		c.fallBack(fallback{Tool: tool.name, Part: partTool, Reason: overBudget})
		entry.Description, entry.InputSchemaText = nil, nil
		text = 0
		encoded, err = canonicalJSON(entry)
		if err != nil {
			return err
		}
		grow = len(name) + 1 + len(encoded)
		if len(c.snap.Tools) > 0 {
			grow++
		}
	}
	if c.size+grow > maxSnapshot {
		return errors.New("complete V2 owner metadata exceeds snapshot bound")
	}
	c.snap.Tools[tool.name] = entry
	c.size += grow
	c.text += text

	return nil
}

func observedApprovedTool(ctx context.Context, cfg Config, rpc conversation, info initializeResult, secrets []string, approved *snapshot, original []byte, wanted string) (json.RawMessage, error) {
	capture, err := newCapturer(DescriptorTarget{Platform: approved.Platform, Binding: approved.Binding}, info, secrets, approved.CapturedAt, cfg.URL)
	if err != nil {
		return nil, err
	}
	if err := capture.beginOwned(approved.Operation); err != nil {
		return nil, err
	}
	if capture.snap.Server == nil {
		return nil, errors.New("current server identity unavailable")
	}
	found := map[string]listedTool{}
	_, err = listTools(ctx, rpc, true, func(tool listedTool) error {
		if _, allowed := cfg.ToolTaxonomies[tool.name]; allowed {
			found[tool.name] = tool
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, name := range ownerNames(cfg.ToolTaxonomies) {
		tool, ok := found[name]
		if !ok {
			return nil, errors.New("approved tool missing from current server")
		}
		if err := capture.addOwned(tool, cfg.ToolTaxonomies[name]); err != nil {
			return nil, err
		}
	}
	selected := found[wanted].descriptor
	projection, err := canonicalJSON(capture.snap)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(projection, original) {
		return nil, errors.New("current server descriptor projection differs from approved snapshot")
	}
	if selected == nil {
		return nil, fmt.Errorf("requested tool was not approved")
	}
	return selected, nil
}

func ownerNames(tools map[string]ToolTaxonomy) []string {
	names := make([]string, 0, len(tools))
	for name := range tools {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (c *capturer) beginOwned(operation string) error {
	if operation != "live" && operation != "write" {
		return errors.New("V2 capture requires exact operation")
	}
	c.snap.SnapshotVersion, c.snap.Operation = "2", operation
	raw, err := canonicalJSON(c.snap)
	if err != nil {
		return err
	}
	c.size = len(raw)
	if c.size > maxSnapshot {
		return errors.New("V2 snapshot identity exceeds bound")
	}
	return nil
}
