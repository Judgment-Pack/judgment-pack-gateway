package main

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"
)

// Tool descriptor snapshots (docs/design/tool-descriptors.md): what the
// live operation's check captured of a platform's tools -- each allowed
// tool's description and input schema as the server wrote them, and the
// server's identity -- kept by connect beside the configuration, one
// immutable file per snapshot named by its digest, and served by the
// frontend. The signer never reads one, and no receipt covers one.

const (
	// maxSnapshotBytes bounds a snapshot, the whole file, and
	// maxCandidateTextBytes its descriptions and schema texts together.
	maxSnapshotBytes      = 320 << 10
	maxCandidateTextBytes = 256 << 10
	// descriptorPolicy is the display policy this engine implements.
	descriptorPolicy = 1
)

type snapshot struct {
	platform   string
	binding    string
	capturedAt string
	server     *snapshotServer // nil when the identity fell back
	tools      map[string]snapshotTool
	names      []string // the tools, sorted
}

type snapshotServer struct{ name, version string }

// snapshotTool is a tool's captured candidates; at least one is present.
type snapshotTool struct {
	description     *string
	inputSchemaText *string
}

var capturedAtForm = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)

var snapshotMembers = map[string]bool{"binding": true, "capturedAt": true, "platform": true, "policy": true, "tools": true, "server": false}

// parseSnapshot holds a snapshot's bytes to the note's shape: at most
// maxSnapshotBytes, one strict JSON value -- valid UTF-8, no lone
// surrogate, no member twice at any depth, nothing after it -- in the
// canonical form it is digested in, with exactly the members stated, each
// of its type, and a policy this engine implements. Whether it is the
// snapshot a platform pins, of that platform's binding and tools, is the
// caller's to judge.
func parseSnapshot(data []byte) (snapshot, error) {
	if len(data) > maxSnapshotBytes {
		return snapshot{}, fmt.Errorf("snapshot: %d bytes, over %d", len(data), maxSnapshotBytes)
	}
	v, err := parseJSON(data)
	if err != nil {
		return snapshot{}, fmt.Errorf("snapshot: %v", err)
	}
	if !bytes.Equal(canon(v), data) {
		return snapshot{}, errors.New("snapshot: not in canonical form")
	}
	obj, ok := v.(*vObject)
	if !ok {
		return snapshot{}, errors.New("snapshot: not an object")
	}
	if err := exactlyMembers(obj, snapshotMembers, "snapshot"); err != nil {
		return snapshot{}, err
	}
	var s snapshot
	if s.platform, err = requireString(obj, "platform"); err != nil || validPlatformName(s.platform) != nil {
		return snapshot{}, errors.New("snapshot: platform is not a platform's name")
	}
	if s.binding, err = requireString(obj, "binding"); err != nil || !isBindingRef(s.binding) {
		return snapshot{}, errors.New("snapshot: binding is not name@sha256:<64 hex>")
	}
	if s.capturedAt, err = requireString(obj, "capturedAt"); err != nil || !capturedAtForm.MatchString(s.capturedAt) {
		return snapshot{}, errors.New("snapshot: capturedAt is not RFC 3339 in UTC, to the second")
	}
	if _, err := time.Parse(time.RFC3339, s.capturedAt); err != nil {
		return snapshot{}, errors.New("snapshot: capturedAt is not RFC 3339 in UTC, to the second")
	}
	if policy, _ := obj.get("policy"); policy != vInt(descriptorPolicy) {
		return snapshot{}, fmt.Errorf("snapshot: its display policy is not %d, the one this engine implements", descriptorPolicy)
	}
	if raw, present := obj.get("server"); present {
		server, err := requireObject(raw, "server")
		if err != nil {
			return snapshot{}, fmt.Errorf("snapshot: %v", err)
		}
		if err := exactlyMembers(server, map[string]bool{"name": true, "version": true}, "snapshot server"); err != nil {
			return snapshot{}, err
		}
		name, err := requireString(server, "name")
		if err != nil {
			return snapshot{}, fmt.Errorf("snapshot: server %v", err)
		}
		version, err := requireString(server, "version")
		if err != nil {
			return snapshot{}, fmt.Errorf("snapshot: server %v", err)
		}
		s.server = &snapshotServer{name: name, version: version}
	}
	rawTools, _ := obj.get("tools")
	tools, err := requireObject(rawTools, "tools")
	if err != nil {
		return snapshot{}, fmt.Errorf("snapshot: %v", err)
	}
	s.tools = map[string]snapshotTool{}
	for _, name := range tools.names {
		raw, _ := tools.get(name)
		entry, ok := raw.(*vObject)
		if !ok || len(entry.names) == 0 {
			return snapshot{}, errors.New("snapshot: a tool is not an object holding a description, an input schema's text, or both")
		}
		var t snapshotTool
		for _, member := range entry.names {
			text, ok := memberString(entry, member)
			switch {
			case !ok:
				return snapshot{}, fmt.Errorf("snapshot: a tool's %s is not a string", printable(member))
			case member == "description":
				t.description = &text
			case member == "inputSchemaText":
				t.inputSchemaText = &text
			default:
				return snapshot{}, fmt.Errorf("snapshot: a tool has unknown member %s", printable(member))
			}
		}
		s.tools[name] = t
		s.names = append(s.names, name)
	}
	sort.Strings(s.names)
	return s, nil
}
