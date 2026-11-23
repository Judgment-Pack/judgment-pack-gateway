package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The admission read version "2" (ADR-0058; spec RFC 0030 §2a): what the
// gateway holds at start for it -- the descriptor digest each source's
// pinned snapshot gives its tools, and the binding's version labels -- and
// what posture says of it. The reads themselves are delegation_admission.go.

// holdToolVersions reads, once at start, the descriptor snapshot each MCP
// operation pins and holds each tool's descriptorDigest on the operation's
// source (sourceSpec.versions), which a version "2" call read names as
// call.version (ADR-0058 decision 3). The snapshot is read by the note's
// checks, its bytes held to the pin before they are parsed, and one that
// cannot be read refuses the start, as it refuses the MCP server's. Nothing
// is read where no issuing host is read at "2": no read then names a
// version, and a start that never read the snapshots does not begin to.
func holdToolVersions(cfg engineConfig, bindings map[string]binding, sources map[string]sourceSpec) error {
	if cfg.delegation == nil || !readsVersion2(cfg.delegation.readVersions()) {
		return nil
	}
	dir, err := openServedDirectory(cfg.configPath, cfg)
	if err != nil || dir == nil {
		return err
	}
	defer dir.Close()
	for _, p := range cfg.platforms {
		b := bindings[p.name]
		for _, name := range []string{"live", "write"} {
			key := p.name + "/" + name
			spec, ok := sources[key]
			if !ok || spec.shape != "mcp" || !pinsOperationSnapshot(p, b, name) {
				continue
			}
			served, err := dir.readOperation(p, b, name)
			if err != nil {
				return fmt.Errorf("platform %s: descriptors: %w", p.name, err)
			}
			spec.versions = map[string]string{}
			for tool, t := range served.tools {
				if t.descriptorDigest != "" {
					spec.versions[tool] = t.descriptorDigest
				}
			}
			sources[key] = spec
		}
	}
	return nil
}

// pinsOperationSnapshot is whether p pins a snapshot for its operation
// name: an owner-declared binding's per-operation pin of an enabled
// operation, or a binding of none's one pin, which is its live operation's
// where it has one and its write operation's otherwise (descriptorProvenance).
func pinsOperationSnapshot(p platformConfig, b binding, name string) bool {
	if b.hasOwnerDeclarations() {
		return p.operationDescriptors[name] != "" && enabledMCPOperations(p, b)[name] != nil
	}
	if p.descriptors == "" {
		return false
	}
	if name == "live" {
		return b.live != nil
	}
	return b.live == nil && b.write != nil
}

func readsVersion2(versions map[string]string) bool {
	for _, v := range versions {
		if v == "2" {
			return true
		}
	}
	return false
}

// readVersions is each configured issuing host's readVersion, by host;
// empty below admissionReadV2Version.
func (s *delegationSpec) readVersions() map[string]string {
	out := map[string]string{}
	for _, h := range s.hosts {
		if h.readVersion != "" {
			out[h.host] = h.readVersion
		}
	}
	return out
}

func (d *delegationService) readVersions() map[string]string {
	out := map[string]string{}
	for name, h := range d.hosts {
		if h.readVersion != "" {
			out[name] = h.readVersion
		}
	}
	return out
}

// protectionDelegationReadVersion is the posture line naming each issuing
// host's read version (SPEC.md §11.9; ADR-0058 decision 11).
const protectionDelegationReadVersion = "delegation-read-version"

// delegationReadVersionLine names each issuing host with the version its
// reads are sent at: enforced where every host is read at "2", so each is
// named the called tool's descriptor digest, partial where some are, and
// not-enforced where none is.
func delegationReadVersionLine(versions map[string]string) postureLine {
	hosts := make([]string, 0, len(versions))
	for h := range versions {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	parts := make([]string, 0, len(hosts))
	atTwo := 0
	for _, h := range hosts {
		parts = append(parts, fmt.Sprintf("%s at %q", h, versions[h]))
		if versions[h] == "2" {
			atTwo++
		}
	}
	state := postureNotEnforced
	switch {
	case atTwo == len(hosts):
		state = postureEnforced
	case atTwo > 0:
		state = posturePartial
	}
	return postureLine{protectionDelegationReadVersion, state,
		"admission reads by issuing host: " + strings.Join(parts, ", ") + `; a host read at "2" is named the called tool's descriptor digest, one at "1" is not`}
}

// versionLabelForm is a toolVersions label: 1 to 64 characters of A-Z a-z
// 0-9 . _ + -, the first a letter or digit (ADR-0058 decision 8).
var versionLabelForm = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)

// parseToolVersions reads a bindingVersion 2 operation's optional
// toolVersions: an object whose keys are among the operation's allowed
// tools and whose values are labels; nil where it is absent.
func parseToolVersions(raw *vObject, allowed []string) (map[string]string, error) {
	v, present := raw.get("toolVersions")
	if !present {
		return nil, nil
	}
	labels, ok := v.(*vObject)
	if !ok {
		return nil, fmt.Errorf("toolVersions must be an object of version labels by allowed tool")
	}
	out := map[string]string{}
	for _, tool := range labels.names {
		if !contains(allowed, tool) {
			return nil, fmt.Errorf("toolVersions names a tool the operation does not allow")
		}
		lv, _ := labels.get(tool)
		label, ok := stringOf(lv)
		if !ok || !versionLabelForm.MatchString(label) {
			return nil, fmt.Errorf("toolVersions: a label is 1 to 64 characters of A-Z a-z 0-9 . _ + -, the first a letter or digit")
		}
		out[tool] = label
	}
	return out, nil
}

// declaresToolVersions is whether either MCP operation of b declares
// toolVersions, which an engine configuration below admissionReadV2Version
// refuses.
func declaresToolVersions(b binding) bool {
	return (b.live != nil && b.live.toolVersions != nil) || (b.write != nil && b.write.toolVersions != nil)
}
