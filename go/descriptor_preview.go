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
func previewDescriptors(configPath string, cfg engineConfig, bindings map[string]binding, platform string) (string, error) {
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
	if b.live == nil {
		return "", fmt.Errorf("platform %s has no live operation, so the MCP server lists no tool of it", platform)
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
