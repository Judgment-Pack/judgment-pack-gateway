package main

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"path/filepath"
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
	version   string
	operation string

	platform string
	binding  string
	// endpoint is the URL a remote server's check reached, as the platform's
	// parameters resolved it; "" for a server the adapter runs, whose
	// snapshot names none.
	endpoint   string
	capturedAt string
	server     *snapshotServer // nil when the identity fell back
	// executable is a customer command's approved executable identity
	// (version 4): the file its command resolved to and, when its first
	// operand named one, the script.
	executable *snapshotExecutableIdentity
	tools      map[string]snapshotTool
	names      []string // the tools, sorted
}

type snapshotServer struct{ name, version string }

type snapshotExecutableIdentity struct {
	path, digest string
	script       *snapshotExecutableIdentity
}

// snapshotExecutable holds a version-4 snapshot's executable member to its
// shape: exactly an absolute path and a digest, and optionally a script with
// exactly the same two.
func snapshotExecutable(raw value) (*snapshotExecutableIdentity, error) {
	bad := errors.New("snapshot: executable is not an absolute path and a digest, with at most a script of the same")
	var read func(raw value, script bool) (*snapshotExecutableIdentity, error)
	read = func(raw value, script bool) (*snapshotExecutableIdentity, error) {
		obj, ok := raw.(*vObject)
		if !ok {
			return nil, bad
		}
		if exactlyMembers(obj, map[string]bool{"path": true, "digest": true, "script": false}, "snapshot executable") != nil {
			return nil, bad
		}
		var id snapshotExecutableIdentity
		var err error
		// Absolute on this system, or a POSIX absolute path: the adapter
		// compares it with the path measured where the command runs.
		if id.path, err = requireString(obj, "path"); err != nil || !(filepath.IsAbs(id.path) || path.IsAbs(id.path)) {
			return nil, bad
		}
		if id.digest, err = requireString(obj, "digest"); err != nil || !isDigest(id.digest) {
			return nil, bad
		}
		if inner, present := obj.get("script"); present {
			if script {
				return nil, bad
			}
			if id.script, err = read(inner, true); err != nil {
				return nil, err
			}
		}
		return &id, nil
	}
	return read(raw, false)
}

// snapshotTool is a tool's captured candidates; at least one is present.
type snapshotTool struct {
	descriptorDigest  string
	taxonomy          ToolTaxonomy
	serverAnnotations map[string]bool

	description     *string
	inputSchemaText *string
}

var capturedAtForm = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)

var snapshotMembers = map[string]bool{"binding": true, "capturedAt": true, "platform": true, "policy": true, "tools": true, "server": false, "endpoint": false}

// snapshotEndpointProblem is why a snapshot does not describe the server
// the platform's described operation reaches, or nil. A remote server's
// snapshot names the URL its check reached, and that must be the URL the
// platform's parameters resolve to now: a binding's digest pins its
// template and not its tenant, so a platform whose organization or
// workspace changed would otherwise serve another tenant's descriptors for
// the server it now reaches. A server the adapter runs is named by the
// binding's pinned image, and its snapshot names no endpoint. The refusal
// names the endpoints compared by their roles and repeats neither: a URL
// may carry, by mistake, what is never to be shown.
func snapshotEndpointProblem(s snapshot, described *operation) error {
	switch {
	case described.url == "" && s.endpoint != "":
		return errors.New("the pinned descriptors were captured at a remote server, and the platform's operation runs a server of its own; capture its descriptors anew with connect --replace")
	case described.url != "" && s.endpoint == "":
		return errors.New("the snapshot of the pinned descriptors names no endpoint, and the platform's operation reaches a remote server; a remote server's descriptors are pinned with the endpoint they were captured at, so capture them anew with connect --replace")
	case s.endpoint != described.url:
		return errors.New("the platform's operation now reaches another endpoint than the one its pinned descriptors were captured at, as its parameters resolve it: descriptors are pinned with the resolved endpoint they were captured at, so an endpoint that changed, a parameter's change among them, is captured anew with connect --replace")
	}
	return nil
}

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
	members := snapshotMembers
	version, hasVersion := memberString(obj, "snapshotVersion")
	if _, present := obj.get("snapshotVersion"); present {
		if !hasVersion || (version != "2" && version != "3" && version != "4") {
			return snapshot{}, errors.New("snapshot: unsupported snapshotVersion")
		}
		members = map[string]bool{}
		for k, v := range snapshotMembers {
			members[k] = v
		}
		members["snapshotVersion"] = true
		members["operation"] = true
		if version == "4" {
			// A customer command's snapshot binds its executable identity.
			members["executable"] = true
		}
	}
	if err := exactlyMembers(obj, members, "snapshot"); err != nil {
		return snapshot{}, err
	}
	s := snapshot{version: version}
	if version == "4" {
		raw, _ := obj.get("executable")
		if s.executable, err = snapshotExecutable(raw); err != nil {
			return snapshot{}, err
		}
	}
	if version == "2" || version == "3" || version == "4" {
		s.operation, err = requireString(obj, "operation")
		if err != nil || (s.operation != "live" && s.operation != "write") {
			return snapshot{}, errors.New("snapshot: invalid operation identity")
		}
	}
	if s.platform, err = requireString(obj, "platform"); err != nil || validPlatformName(s.platform) != nil {
		return snapshot{}, errors.New("snapshot: platform is not a platform's name")
	}
	if s.binding, err = requireString(obj, "binding"); err != nil || !isBindingRef(s.binding) {
		return snapshot{}, errors.New("snapshot: binding is not name@sha256:<64 hex>")
	}
	if _, present := obj.get("endpoint"); present {
		if s.endpoint, err = requireString(obj, "endpoint"); err != nil || !isRemoteEndpoint(s.endpoint) {
			return snapshot{}, errors.New("snapshot: endpoint is not a remote server's endpoint")
		}
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
		if version == "3" || version == "4" {
			t.descriptorDigest, err = requireString(entry, "descriptorDigest")
			if err != nil || !isDigest(t.descriptorDigest) {
				return snapshot{}, errors.New("snapshot: missing complete descriptor digest")
			}
		}
		if version == "2" || version == "3" || version == "4" {
			raw, _ := entry.get("taxonomy")
			t.taxonomy, err = taxonomyValue(raw)
			if err != nil || !t.taxonomy.External() {
				return snapshot{}, errors.New("snapshot: missing or invalid owner taxonomy")
			}
			if raw, present := entry.get("serverAnnotations"); present {
				hints, ok := raw.(*vObject)
				if !ok {
					return snapshot{}, errors.New("snapshot: malformed serverAnnotations")
				}
				t.serverAnnotations = map[string]bool{}
				for _, key := range hints.names {
					v, _ := hints.get(key)
					b, ok := v.(vBool)
					if !ok || !annotationKey(key) {
						return snapshot{}, errors.New("snapshot: unsupported server constraint")
					}
					t.serverAnnotations[key] = bool(b)
				}
				if t.taxonomy.Contradiction(t.serverAnnotations) {
					return snapshot{}, errors.New("snapshot: server constraints contradict owner taxonomy")
				}
			}
		}
		for _, member := range entry.names {
			if (version == "3" || version == "4") && member == "descriptorDigest" {
				continue
			}
			if (version == "2" || version == "3" || version == "4") && (member == "taxonomy" || member == "serverAnnotations") {
				continue
			}
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
