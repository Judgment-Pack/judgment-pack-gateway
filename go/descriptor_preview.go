package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// previewDescriptors renders what the MCP server would serve for a
// platform's tools (docs/design/tool-descriptors.md, "Change, and the
// operator"): each tool's description and input schema, from the snapshot
// the platform pins, read and verified as the server reads it at start,
// before any drop the listing's bound would make across platforms. Every
// line the server would serve is written after "  | ", with every
// character outside printable ASCII escaped, so nothing it holds moves the
// terminal or passes for a line of the preview's own.
func previewDescriptors(configPath string, cfg engineConfig, bindings map[string]binding, platform string, operations ...string) (string, error) {
	var entry *platformConfig
	for i := range cfg.platforms {
		if cfg.platforms[i].name == platform {
			entry = &cfg.platforms[i]
		}
	}
	if entry == nil {
		return "", fmt.Errorf("platform %s is not configured", platform)
	}
	b := bindings[platform]
	if b.hasOwnerDeclarations() {
		operation := ""
		if len(operations) > 0 {
			operation = operations[0]
		}
		ops := enabledMCPOperations(*entry, b)
		if operation == "" {
			if len(ops) != 1 {
				return "", fmt.Errorf("preview requires --operation live or write")
			}
			for name := range ops {
				operation = name
			}
		}
		op := ops[operation]
		if op == nil {
			return "", fmt.Errorf("preview operation is not enabled")
		}
		dir, err := openServedDirectory(configPath, cfg)
		if err != nil {
			return "", err
		}
		defer dir.Close()
		served, err := dir.readOperation(*entry, b, operation)
		if err != nil {
			return "", err
		}
		var text strings.Builder
		fmt.Fprintf(&text, "preview: platform %s operation %s; %s approval; write tools remain /act only\n", previewEscape(platform), operation, entry.operationDescriptors[operation])
		names := append([]string(nil), op.tools...)
		sort.Strings(names)
		for _, name := range names {
			t := mcpTool{name: platform + "." + name, platform: platform, tool: name, binding: entry.binding, taxonomy: op.taxonomies[name]}
			schema, _ := json.Marshal(servedSchema(t, served))
			fmt.Fprintf(&text, "tool %s %s/%s\n  inputSchema: %s\n", previewEscape(name), t.taxonomy.Operation, t.taxonomy.Effect, previewEscape(string(schema)))
			for _, line := range strings.Split(describePlatformTool(t, served), "\n") {
				fmt.Fprintf(&text, "  | %s\n", previewEscape(line))
			}
		}
		return text.String(), nil
	}
	described := describedOperation(b, entry.write)
	if described == nil {
		return "", fmt.Errorf("platform %s has no live operation, so the MCP server lists no tool of it", platform)
	}
	if b.live == nil {
		return previewWriteDescriptors(configPath, cfg, bindings, *entry, described)
	}
	only := cfg
	only.platforms = []platformConfig{*entry}
	served, err := readServedPlatforms(configPath, only, bindings)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "preview: what the MCP server would serve for platform %s, before any drop the listing's bound makes across platforms; every character outside printable ASCII is escaped\n", previewEscape(platform))
	if entry.descriptors == "" {
		sb.WriteString("preview: the platform pins no snapshot, so each tool is described as if nothing were captured\n")
	}
	tools := append([]string(nil), b.live.tools...)
	sort.Slice(tools, func(i, j int) bool { return platform+"."+tools[i] < platform+"."+tools[j] })
	for _, tool := range tools {
		t := mcpTool{name: platform + "." + tool, platform: platform, tool: tool, binding: entry.binding}
		schema, err := json.Marshal(servedSchema(t, served[platform]))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&sb, "tool %s\n  description:\n", previewEscape(t.name))
		for _, line := range strings.Split(describePlatformTool(t, served[platform]), "\n") {
			sb.WriteString("  | " + previewEscape(line) + "\n")
		}
		sb.WriteString("  inputSchema:\n  | " + previewEscape(string(schema)) + "\n")
	}
	return sb.String(), nil
}

// previewWriteDescriptors renders what connect captured of the write tools
// of a platform whose binding has no live operation: the MCP server lists
// none of them, since it calls /acquire alone and a write is made through
// /act, so the preview renders each tool's captured description and the
// schema as the server would project it, and says that nothing serves them
// as tools.
func previewWriteDescriptors(configPath string, cfg engineConfig, bindings map[string]binding, entry platformConfig, write *operation) (string, error) {
	only := cfg
	only.platforms = []platformConfig{entry}
	served, err := readServedPlatforms(configPath, only, bindings)
	if err != nil {
		return "", err
	}
	platform := entry.name
	var sb strings.Builder
	fmt.Fprintf(&sb, "preview: platform %s has no live operation, so the MCP server lists no tool of it; its write tools are called through /act alone, and what connect captured of them is rendered below; every character outside printable ASCII is escaped\n", previewEscape(platform))
	if entry.descriptors == "" {
		sb.WriteString("preview: the platform pins no snapshot, so nothing of its write tools was captured\n")
	}
	tools := append([]string(nil), write.tools...)
	sort.Strings(tools)
	for _, tool := range tools {
		t := mcpTool{name: platform + "." + tool, platform: platform, tool: tool, binding: entry.binding}
		schema, err := json.Marshal(servedSchema(t, served[platform]))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&sb, "write tool %s\n", previewEscape(tool))
		if sp := served[platform]; sp != nil && sp.tools[tool].description != nil {
			sb.WriteString("  description, in the platform's server's own words, as captured:\n")
			for _, line := range strings.Split(*sp.tools[tool].description, "\n") {
				sb.WriteString("  | " + previewEscape(line) + "\n")
			}
		}
		sb.WriteString("  inputSchema:\n  | " + previewEscape(string(schema)) + "\n")
	}
	return sb.String(), nil
}

// previewEscape writes every character outside printable ASCII as a
// visible escape, \u{XXXX}.
func previewEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			fmt.Fprintf(&b, `\u{%04X}`, r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
