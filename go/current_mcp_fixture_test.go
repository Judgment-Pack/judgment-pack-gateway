package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Current frontend tests explicitly owner-declare their synthetic read leaves and
// capture a distinct V2 fixture. Original historical reader fixtures/bytes remain
// untouched. Actual registration and source calls are covered by disposable-server
// producer tests, not by this presentation/transport fixture constructor.
func newDeclaredMCPTestServer(t *testing.T, cfg engineConfig, bindings map[string]binding, identity *identityConfig, path string) (*mcpServer, error) {
	t.Helper()
	previousPath := cfg.configPath
	if path == "" {
		path = filepath.Join(t.TempDir(), "engine.json")
		if err := os.WriteFile(path, []byte("{}"), 0o640); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(path+".descriptors", 0o755); err != nil {
		return nil, err
	}
	cfg.platforms = append([]platformConfig(nil), cfg.platforms...)
	owned := map[string]binding{}
	for name, b := range bindings {
		owned[name] = b
	}
	for i := range cfg.platforms {
		p := &cfg.platforms[i]
		b := owned[p.name]
		if b.live == nil {
			continue
		}
		op := *b.live
		op.name = "live"
		op.taxonomies = map[string]ToolTaxonomy{}
		for _, name := range op.tools {
			op.taxonomies[name] = ToolTaxonomy{Operation: "read", Effect: "read-external"}
		}
		b.live = &op
		b.version = "2"
		owned[p.name] = b
		if !isBindingRef(p.binding) {
			p.binding = p.name + "@sha256:" + strings.Repeat("0", 64)
		}
		tools := newObject()
		server := newObject()
		server.set("name", vString("fixture"))
		server.set("version", vString("1"))
		snap := newObject()
		snap.set("binding", vString(p.binding))
		snap.set("platform", vString(p.name))
		snap.set("capturedAt", vString("2026-10-25T00:00:00Z"))
		snap.set("policy", vInt(1))
		snap.set("server", server)
		snap.set("tools", tools)
		pin, base := p.descriptors, path
		if pin == "" && p.operationDescriptors["live"] != "" {
			pin = p.operationDescriptors["live"]
			if previousPath != "" {
				base = previousPath
			}
		}
		if pin != "" {
			raw, err := os.ReadFile(filepath.Join(base+".descriptors", strings.TrimPrefix(pin, "sha256:")+".json"))
			if err != nil {
				return nil, err
			}
			if digestOf(string(raw)) != pin {
				return nil, fmt.Errorf("platform %s: fixture snapshot does not digest to its pin", p.name)
			}
			if _, err := parseSnapshot(raw); err != nil {
				return nil, err
			}
			value, err := parseJSON(raw)
			if err != nil {
				return nil, err
			}
			snap = value.(*vObject)
			v, _ := snap.get("tools")
			tools = v.(*vObject)
		}
		for name, owner := range op.taxonomies {
			v, present := tools.get(name)
			entry := newObject()
			if present {
				entry = v.(*vObject)
			}
			entry.set("taxonomy", taxonomyAsValue(owner))
			tools.set(name, entry)
		}
		snap.set("operation", vString("live"))
		snap.set("snapshotVersion", vString("2"))
		snap.set("tools", tools)
		raw := canon(snap)
		current := digestOf(string(raw))
		file := filepath.Join(path+".descriptors", strings.TrimPrefix(current, "sha256:")+".json")
		if err := os.WriteFile(file, raw, 0o644); err != nil {
			return nil, err
		}
		p.descriptors = ""
		p.operationDescriptors = map[string]string{"live": current}
	}
	cfg.configPath = path
	return newMCPServer(cfg, owned, identity, path)
}
