package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// callReferenceVersion is the engine configuration version from which a
// platform may set callReference: true, the operator's opt-in for that
// platform's binding to receive a per-call reference (docs/adr/0060-a-call-
// reference-passed-to-a-binding-and-signed-into-the-receipt.md). Its number
// is a placeholder, assigned at merge: 49 expected, after the refusal
// journal's (48), which merges first. engine.go lists it in engineVersions.
const callReferenceVersion = "48"

// The names a call reference travels under. The gateway hands adapter-mcp the
// reference and the session identifier in its environment, for that call
// alone; the adapter takes both out of its own environment before it starts
// a server, and puts them in the tools/call request's params._meta under the
// two names below, and nothing else beside them.
const (
	callRefVariable       = "ADAPTER_MCP_CALL_REF"
	callSessionIDVariable = "ADAPTER_MCP_SESSION_ID"
	metaCallRef           = "judgment-pack/callRef"
	metaSessionID         = "judgment-pack/sessionId"
)

// callRefRandom is the operating system's random source; a test stands in a
// failing one.
var callRefRandom = rand.Read

// newCallRef draws one call reference: 32 random bytes as lowercase hex.
func newCallRef() (string, error) {
	b := make([]byte, 32)
	if _, err := callRefRandom(b); err != nil {
		return "", fmt.Errorf("call-reference: the call reference could not be drawn, and the binding was not called: %v", err)
	}
	return hex.EncodeToString(b), nil
}

// isCallRef is a receipt's callRef form: 64 lowercase hexadecimal characters.
func isCallRef(s string) bool { return isLowerHexOfLen(s, 64) }

// withCallReference is the source as one call runs it. A source whose
// platform did not opt in is returned as it is, and nothing is drawn: its
// adapter is started with the environment and stdin it always was. One that
// did gets a fresh reference, drawn before the binding is called, and the
// session identifier the receipt will name, appended to a copy of its
// environment; the reference is returned for the receipt. A failed draw
// refuses the call before the source starts.
func withCallReference(spec sourceSpec, sessionID string) (sourceSpec, string, error) {
	if !spec.callReference {
		return spec, "", nil
	}
	ref, err := newCallRef()
	if err != nil {
		return spec, "", err
	}
	run := spec
	run.env = append(append([]string(nil), spec.env...), callRefVariable+"="+ref, callSessionIDVariable+"="+sessionID)
	return run, ref, nil
}

// withoutCallReference is the source as configured, before withCallReference
// added one call's reference: its environment without the two variables. The
// sandbox posture probe measures the source with it, so no probe is handed a
// reference meant for the server alone.
func withoutCallReference(spec sourceSpec) sourceSpec {
	if !spec.callReference {
		return spec
	}
	env := make([]string, 0, len(spec.env))
	for _, kv := range spec.env {
		name, _, _ := strings.Cut(kv, "=")
		if name == callRefVariable || name == callSessionIDVariable {
			continue
		}
		env = append(env, kv)
	}
	out := spec
	out.env = env
	return out
}

// parsePlatformCallReference reads a platform's callReference: a boolean,
// from callReferenceVersion, refused by name below it.
func parsePlatformCallReference(v value, name, version string) (bool, error) {
	if !versionAtLeast(version, callReferenceVersion) {
		return false, fmt.Errorf("engine configuration: platform %s: callReference is a version-%s member; engineVersion %s has no callReference, and the binding %s would not be sent the call reference it opts into", name, callReferenceVersion, version, name)
	}
	b, ok := v.(vBool)
	if !ok {
		return false, fmt.Errorf("engine configuration: platform %s: callReference, when present, is a boolean", name)
	}
	return bool(b), nil
}

// callReferenceRefusal holds every source that opts in to what the opt-in
// needs: an MCP server, whose tools/call request alone has a _meta. The
// gateway never starts with an opt-in it would not honour. Only an engine
// configuration's platform sets callReference, and an engine's receipts are
// always version 3 (engineServeOptions), so the version 3 receipt that alone
// carries callRef needs no check here (ADR-0060, amendment of 2026-11-23).
func callReferenceRefusal(sources map[string]sourceSpec) error {
	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		spec := sources[name]
		if !spec.callReference {
			continue
		}
		platform, _, _ := strings.Cut(name, "/")
		if spec.shape != "mcp" {
			return fmt.Errorf("platform %s: callReference on source %s (binding %s), whose operation is not an MCP server: only a tools/call request carries the reference", platform, name, spec.binding)
		}
	}
	return nil
}
