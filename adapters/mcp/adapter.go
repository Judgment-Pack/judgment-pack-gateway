// Package mcp is the gateway's MCP-shaped adapter: a client of a Model
// Context Protocol server reached over stdio -- a pinned server image in
// the operator's container runtime, or a local command -- that calls one
// tool and writes the envelope SPEC.md §6 states on stdout: the tool's
// result as the result, and the acquisition as this adapter recorded it.
// It holds the server's credentials and never the signing seed, and it
// imports nothing of the core module.
package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"adapters/internal/canon"
	"adapters/internal/redact"
)

// Config is the operator's configuration of one adapter invocation, from
// the command line the gateway spawned it with.
type Config struct {
	// Runtime is the container runtime command, for Image.
	Runtime string
	// Image is the pinned server image reference, name[:tag]@sha256:hex.
	Image string
	// Command is a local server command with its arguments, instead of
	// Image.
	Command []string
	// Args are the server's own arguments when Image is given: what
	// follows the image on the runtime's command line. A command carries
	// its own, and Args with Command is refused.
	Args []string
	// Credentials is the path of a JSON object of strings that become the
	// server's environment; empty for a server that needs none.
	Credentials string
	// Endpoint is the host the server reaches as the operator names it,
	// recorded as the receipt's endpoint; empty records null.
	Endpoint string
	// Tools, when given, are the only tools a request may name.
	Tools []string
	// ErrorResults, when set, makes a tool result that reports an error
	// (isError true) the result of the call rather than its failure: what
	// an executor needs, since a target's refusal of a write is a response
	// to receipt, where a source's is a read that did not happen.
	ErrorResults bool
	// Probe, when given, is a tool a check calls once with no arguments
	// to establish that the server reaches its platform -- a server that
	// starts and lists its tools without a working connection answers the
	// handshake all the same. The result is read for an error and
	// discarded; nothing is minted from a check.
	Probe string
	// ProbeFailure, when given, is text a probe's answer begins with when
	// the platform was not reached: a server that catches its own
	// failure and answers it as ordinary text, isError false, says so
	// only in the text, and the binding that pins the server knows what
	// it says.
	ProbeFailure string
	// Descriptors, when given, has a check capture the allowed tools'
	// descriptions and input schemas, and the server's identity, into
	// the snapshot connect keeps for the platform it names
	// (docs/design/tool-descriptors.md). Only the live operation's check
	// is given it; a write operation's may run under other credentials,
	// against another server.
	Descriptors *DescriptorTarget
	// MaxOutput bounds the envelope in bytes.
	MaxOutput int64
}

// Request is the canonical arguments the gateway hands the adapter on
// stdin: which tool, with what arguments.
type Request struct {
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments"`
}

const (
	protocolVersion = "2025-06-18"
	clientName      = "judgment-pack-adapter-mcp"
	stampLayout     = "2006-01-02T15:04:05Z"
	maxToolPages    = 32
)

// supportedVersions are the protocol revisions this client implements: the
// one it proposes and the two before it, whose tools/list, tools/call and
// lifecycle it speaks unchanged. A server that answers with any other
// version is refused rather than talked to on a guess.
var supportedVersions = map[string]bool{"2025-06-18": true, "2025-03-26": true, "2024-11-05": true}

// ParseRequest reads the request strictly: an object with the known members
// only, a non-empty tool, arguments that are an object when given.
func ParseRequest(r io.Reader) (Request, error) {
	dec := json.NewDecoder(io.LimitReader(r, 1<<20))
	dec.DisallowUnknownFields()
	var req Request
	if err := dec.Decode(&req); err != nil {
		return req, fmt.Errorf("request: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return req, errors.New("request: trailing content after the object")
	}
	if req.Tool == "" {
		return req, errors.New(`request: "tool" is required`)
	}
	if len(req.Arguments) == 0 || string(req.Arguments) == "null" {
		req.Arguments = json.RawMessage("{}")
	}
	if !canon.IsObject(req.Arguments) {
		return req, errors.New(`request: "arguments" must be an object`)
	}
	return req, nil
}

func malformedCredentials(err error) error { return redact.MalformedCredentials(err) }

// envName is the shape of an environment variable's name.
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// credentialsEnv reads the credentials file as a JSON object of strings and
// returns them as KEY=VALUE pairs, with every value for redaction. A value
// with a newline cannot be carried in an env file and is refused.
func credentialsEnv(path string) (env []string, secrets []string, err error) {
	if path == "" {
		return nil, nil, nil
	}
	data, err := redact.ReadCredentials(path)
	if err != nil {
		return nil, nil, err
	}
	// Held to exact member names with a duplicate refused, so that every
	// value is one the redactor knows; each value a string, so a null or
	// a number is not carried as an empty or a spelled-out variable.
	if _, err := canon.Canonicalize(data, canon.CarryNumbersAsText); err != nil {
		return nil, nil, malformedCredentials(err)
	}
	members, err := exactMembers(data)
	if err != nil {
		return nil, nil, errors.New("credentials file is not a JSON object of strings")
	}
	keys := make([]string, 0, len(members))
	for k := range members {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		// None of these names the member: a member's name may be another
		// member's value, and the file is not yet one the redactor knows.
		var value string
		if raw := bytes.TrimSpace(members[k]); !bytes.HasPrefix(raw, []byte(`"`)) || json.Unmarshal(raw, &value) != nil {
			return nil, nil, errors.New("a credentials member is not a string")
		}
		// A name an environment and an env file both carry unchanged:
		// a runtime's env-file parser drops a line that begins with a
		// comment mark or whitespace, and a shell refuses other names.
		if !envName.MatchString(k) {
			return nil, nil, errors.New("a credentials member is not an environment variable name")
		}
		// A value both carry unchanged: an env file is read by lines,
		// and a carriage return before the newline is dropped with it.
		if strings.ContainsAny(value, "\n\r\x00") {
			return nil, nil, errors.New("a credentials member has a value an environment cannot carry")
		}
		env = append(env, k+"="+value)
	}
	return env, redact.SecretsOf(data), nil
}

// Acquire calls the requested tool once and returns the envelope.
func Acquire(ctx context.Context, cfg Config, req Request) ([]byte, error) {
	if (cfg.Image == "") == (len(cfg.Command) == 0) {
		return nil, errNoServer
	}
	if err := cfg.serverRefusal(); err != nil {
		return nil, err
	}
	if cfg.MaxOutput < 1 {
		return nil, errors.New("max-output must be positive")
	}
	if len(cfg.Tools) > 0 && !contains(cfg.Tools, req.Tool) {
		return nil, fmt.Errorf("tool %q is not one this source may call: %v", req.Tool, cfg.Tools)
	}
	env, secrets, err := credentialsEnv(cfg.Credentials)
	if err != nil {
		return nil, err
	}
	srv, err := startServer(ctx, cfg, env, secrets)
	if err != nil {
		return nil, err
	}
	// Every exit passes here: the server is stopped, a container that
	// would not stop comes first in the error, and every diagnostic --
	// the server's, the runtime's, this adapter's own about what the
	// server said -- is redacted once and bounded before it crosses the
	// source boundary.
	finish := func(out []byte, err error) ([]byte, error) {
		if stopErr := srv.stop(); stopErr != nil {
			if err == nil {
				err = stopErr
			} else {
				err = fmt.Errorf("%v; the acquisition had also failed: %v", stopErr, err)
			}
		}
		if err != nil {
			return nil, errors.New(redact.Redact(err.Error(), secrets))
		}
		return out, nil
	}
	// fail reports why a call did not complete: the deadline as such, or
	// the error with the server's first line of stderr when the server
	// ended -- read after the server has been stopped, so the line is
	// whole and no longer being written.
	fail := func(err error) ([]byte, error) {
		if ctx.Err() != nil {
			return finish(nil, fmt.Errorf("the server did not answer in time: %v", ctx.Err()))
		}
		stopErr := srv.stop()
		message := withStderr(err, srv)
		if stopErr != nil {
			message = stopErr.Error() + "; the acquisition had also failed: " + message
		}
		return nil, errors.New(redact.Redact(message, secrets))
	}
	rpc := newClient(srv.stdin, srv.stdout)
	// The handshake: a version this client speaks, a server that offers
	// tools, and this client done negotiating.
	raw, err := rpc.call(ctx, "initialize", map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": clientName, "version": "0"},
	})
	if err != nil {
		return fail(err)
	}
	initialized, err := parseInitialize(raw)
	if err != nil {
		return finish(nil, err)
	}
	if err := rpc.notify("notifications/initialized", map[string]any{}); err != nil {
		return fail(err)
	}
	identity := srv.identity
	if identity.Version == "" {
		// A command's version is what the server says of itself, and it
		// goes into the receipt: redacted, as a diagnostic would be.
		identity.Version = redact.Redact(initialized.version, secrets)
	}
	// The tool, as the server describes it: its declared output schema is
	// the schema the receipt names, and null when it declares none.
	descriptor, names, err := findTool(ctx, rpc, req.Tool)
	if err != nil {
		if names != nil {
			return finish(nil, fmt.Errorf("tool %q is not one the server offers: %v", req.Tool, names))
		}
		return fail(err)
	}
	schema, err := outputSchemaOf(descriptor)
	if err != nil {
		return finish(nil, fmt.Errorf("tool %q: %v", req.Tool, err))
	}
	// The call.
	raw, err = rpc.call(ctx, "tools/call", map[string]any{"name": req.Tool, "arguments": req.Arguments})
	if err != nil {
		return fail(err)
	}
	observedAt := time.Now().UTC().Truncate(time.Second).Format(stampLayout)
	if int64(len(raw)) > cfg.MaxOutput {
		return finish(nil, fmt.Errorf("the tool's result exceeds the output bound of %d bytes", cfg.MaxOutput))
	}
	result, err := parseToolResult(raw, cfg.ErrorResults)
	if err != nil {
		return finish(nil, err)
	}
	if err := srv.stop(); err != nil {
		return nil, errors.New(redact.Redact(err.Error(), secrets))
	}
	out, err := buildEnvelope(cfg, identity, req, schema, result, observedAt)
	if err != nil {
		return nil, errors.New(redact.Redact(err.Error(), secrets))
	}
	return out, nil
}

// serverRefusal is why the configuration names no server to run, or nil:
// exactly one of an image and a command, a runtime for an image, and
// arguments only beside an image.
func (cfg Config) serverRefusal() error {
	if (cfg.Image == "") == (len(cfg.Command) == 0) {
		return errNoServer
	}
	if cfg.Image != "" && cfg.Runtime == "" {
		return errors.New("a container runtime is required to run a server image")
	}
	if len(cfg.Command) > 0 && len(cfg.Args) > 0 {
		return errors.New("a server command carries its own arguments; args are for an image")
	}
	return nil
}

// checkReport is what Check writes: the server as it identified itself,
// the protocol version it answered with, and every tool it offers; with
// descriptors asked for, the snapshot and why each candidate that is not
// in it fell back. It is for the operator who is connecting a platform,
// and it is not an envelope: nothing is minted from it. Every string
// outside the snapshot is at most maxReportField bytes, and each list at
// most maxReportList bytes with what passes it counted, so the report
// stays within reportBound with any snapshot inside it.
type checkReport struct {
	Status          string          `json:"status"`
	Adapter         adapterIdentity `json:"adapter"`
	Server          serverIdentity  `json:"server"`
	ProtocolVersion string          `json:"protocolVersion"`
	Tools           []string        `json:"tools"`
	ToolsUnlisted   int             `json:"toolsUnlisted,omitempty"`
	Probe           *probeReport    `json:"probe,omitempty"`
	// Descriptors is the snapshot in its canonical form, as connect
	// writes it.
	Descriptors        json.RawMessage `json:"descriptors,omitempty"`
	Fallbacks          []fallback      `json:"fallbacks,omitempty"`
	FallbacksUnlisted  int             `json:"fallbacksUnlisted,omitempty"`
	DescriptorsDropped string          `json:"descriptorsDropped,omitempty"`
}

// probeReport says which tool the check called and that it answered.
type probeReport struct {
	Tool     string `json:"tool"`
	Answered bool   `json:"answered"`
}

// FailedCheck is the report of a check that did not succeed, for stdout
// beside the exit status: the same member the success carries, so a
// caller reads one shape, and the reason as the adapter reported it,
// already redacted.
func FailedCheck(reason string) []byte {
	out, _ := canon.EncodeJSON(map[string]any{"check": map[string]string{"status": "failed", "message": reason}})
	return out
}

type serverIdentity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Check starts the server with the credentials, completes the handshake,
// lists its tools, and reports; it calls nothing. A tool the configuration
// allows (Tools) that the server does not offer fails the check, so a
// binding that names a tool the pinned server lacks is found out when the
// platform is connected, not at the first acquisition.
func Check(ctx context.Context, cfg Config) ([]byte, error) {
	if err := cfg.serverRefusal(); err != nil {
		return nil, err
	}
	if cfg.Descriptors != nil {
		if err := cfg.Descriptors.refusal(); err != nil {
			return nil, err
		}
	}
	env, secrets, err := credentialsEnv(cfg.Credentials)
	if err != nil {
		return nil, err
	}
	srv, err := startServer(ctx, cfg, env, secrets)
	if err != nil {
		return nil, err
	}
	finish := func(out []byte, err error) ([]byte, error) {
		if stopErr := srv.stop(); stopErr != nil {
			if err == nil {
				err = stopErr
			} else {
				err = fmt.Errorf("%v; the check had also failed: %v", stopErr, err)
			}
		}
		if err != nil {
			return nil, errors.New(redact.Redact(err.Error(), secrets))
		}
		return out, nil
	}
	fail := func(err error) ([]byte, error) {
		if ctx.Err() != nil {
			return finish(nil, fmt.Errorf("the server did not answer in time: %v", ctx.Err()))
		}
		stopErr := srv.stop()
		message := withStderr(err, srv)
		if stopErr != nil {
			message = stopErr.Error() + "; the check had also failed: " + message
		}
		return nil, errors.New(redact.Redact(message, secrets))
	}
	rpc := newClient(srv.stdin, srv.stdout)
	raw, err := rpc.call(ctx, "initialize", map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": clientName, "version": "0"},
	})
	if err != nil {
		return fail(err)
	}
	initialized, err := parseInitialize(raw)
	if err != nil {
		return finish(nil, err)
	}
	if err := rpc.notify("notifications/initialized", map[string]any{}); err != nil {
		return fail(err)
	}
	// A listing that is captured is pinned, and held to what pinning
	// needs; each allowed tool is judged as its page is read, and what is
	// not captured is not kept.
	var capture *capturer
	var visit func(listedTool) error
	if cfg.Descriptors != nil {
		capturedAt := now().UTC().Truncate(time.Second).Format(stampLayout)
		if capture, err = newCapturer(*cfg.Descriptors, initialized, secrets, capturedAt); err != nil {
			return finish(nil, err)
		}
		visit = func(tool listedTool) error {
			if len(cfg.Tools) > 0 && !contains(cfg.Tools, tool.name) {
				return nil
			}
			return capture.add(tool)
		}
	}
	names, err := listTools(ctx, rpc, capture != nil, visit)
	if err != nil {
		return fail(err)
	}
	for _, allowed := range cfg.Tools {
		if !contains(names, allowed) {
			return finish(nil, fmt.Errorf("tool %q is allowed by the configuration but not offered by the server: %v", allowed, names))
		}
	}
	var probe *probeReport
	if cfg.Probe != "" {
		// The probe is one of the tools this source may call, offered by
		// the server, and it must answer without an error: a connection
		// the server could not make is what it answers with.
		if len(cfg.Tools) > 0 && !contains(cfg.Tools, cfg.Probe) {
			return finish(nil, fmt.Errorf("probe %q is not one this source may call: %v", cfg.Probe, cfg.Tools))
		}
		if !contains(names, cfg.Probe) {
			return finish(nil, fmt.Errorf("probe %q is not one the server offers: %v", cfg.Probe, names))
		}
		raw, err := rpc.call(ctx, "tools/call", map[string]any{"name": cfg.Probe, "arguments": map[string]any{}})
		if err != nil {
			return fail(err)
		}
		if int64(len(raw)) > cfg.MaxOutput {
			return finish(nil, fmt.Errorf("the probe's result exceeds the output bound of %d bytes", cfg.MaxOutput))
		}
		if _, err := parseToolResult(raw, false); err != nil {
			return finish(nil, fmt.Errorf("probe %q: %v", cfg.Probe, err))
		}
		if cfg.ProbeFailure != "" {
			// On the answer as the server wrote it, not the canonical
			// form, in which a number would have become a string.
			text, failed, err := answersFailure(raw, cfg.ProbeFailure)
			if err != nil {
				return finish(nil, fmt.Errorf("probe %q: %v", cfg.Probe, err))
			}
			if failed {
				return finish(nil, fmt.Errorf("probe %q: the platform was not reached: %s", cfg.Probe, text))
			}
		}
		probe = &probeReport{Tool: cfg.Probe, Answered: true}
	}
	// Everything the server said of itself is redacted before it is
	// reported, as every diagnostic is: a server echoes what it was given.
	identity := srv.identity
	if identity.Version == "" {
		identity.Version = redact.Redact(initialized.version, secrets)
	}
	identity = adapterIdentity{Name: capField(identity.Name), Version: capField(identity.Version), Digest: capField(identity.Digest)}
	redacted := make([]string, 0, len(names))
	for _, name := range names {
		redacted = append(redacted, reportField(name, secrets))
	}
	report := checkReport{
		Status:          "succeeded",
		Adapter:         identity,
		Server:          serverIdentity{Name: reportField(initialized.name, secrets), Version: reportField(initialized.version, secrets)},
		ProtocolVersion: capField(initialized.protocol),
		Probe:           probe,
	}
	report.Tools, report.ToolsUnlisted = capList(redacted, maxReportList)
	if probe != nil {
		probe.Tool = capField(probe.Tool)
	}
	if capture != nil {
		snapshot, fallbacks, unlisted, dropped, err := capture.finish()
		if err != nil {
			return finish(nil, err)
		}
		report.Descriptors, report.DescriptorsDropped = snapshot, dropped
		report.Fallbacks, report.FallbacksUnlisted = fallbacks, unlisted
	}
	out, err := encodeCheckReport(report)
	if err != nil {
		return finish(nil, err)
	}
	return finish(out, nil)
}

// encodeCheckReport writes the report within reportBound, which connect
// holds it to by killing an adapter that writes more. The caps keep it
// well inside with any snapshot; should it pass anyway, the snapshot is
// dropped, every tool falls back, and the report says so.
func encodeCheckReport(report checkReport) ([]byte, error) {
	out, err := canon.EncodeJSON(map[string]any{"check": report})
	if err != nil {
		return nil, err
	}
	if len(out) > reportBound && report.Descriptors != nil {
		report.Descriptors = nil
		report.DescriptorsDropped = fmt.Sprintf("the report with the snapshot would pass %d bytes, so no tool's descriptors are captured", reportBound)
		if out, err = canon.EncodeJSON(map[string]any{"check": report}); err != nil {
			return nil, err
		}
	}
	if len(out) > reportBound {
		return nil, fmt.Errorf("the check's report would pass %d bytes", reportBound)
	}
	return out, nil
}

type initializeResult struct {
	protocol string
	name     string
	version  string
}

// parseInitialize holds the server's answer to what the lifecycle
// requires: a protocol version this client speaks, a tools capability,
// and the server's own name and version.
func parseInitialize(raw json.RawMessage) (initializeResult, error) {
	members, err := exactMembers(raw)
	if err != nil {
		return initializeResult{}, fmt.Errorf("initialize: the server's answer is not an initialize result: %v", err)
	}
	var protocol string
	if json.Unmarshal(members["protocolVersion"], &protocol) != nil || protocol == "" {
		return initializeResult{}, errors.New("initialize: the server's answer names no protocol version")
	}
	if !supportedVersions[protocol] {
		// Written as the server said it, not quoted with %q: an escape
		// would put it past the redactor.
		return initializeResult{}, fmt.Errorf("initialize: the server speaks protocol version '%s', which this client does not", protocol)
	}
	capabilities, err := exactMembers(members["capabilities"])
	if err != nil {
		return initializeResult{}, errors.New("initialize: the server's answer carries no capabilities object")
	}
	if !canon.IsObject(capabilities["tools"]) {
		return initializeResult{}, errors.New("initialize: the server offers no tools capability")
	}
	// The server's identity is required of an initialize result, and it
	// is what a check reports and what a command-form receipt carries as
	// the adapter's version.
	info, err := exactMembers(members["serverInfo"])
	if err != nil {
		return initializeResult{}, errors.New("initialize: the server's answer carries no serverInfo object")
	}
	var name, version string
	if json.Unmarshal(info["name"], &name) != nil || name == "" {
		return initializeResult{}, errors.New("initialize: serverInfo names no server")
	}
	if raw, ok := info["version"]; !ok || string(bytes.TrimSpace(raw)) == "null" || json.Unmarshal(raw, &version) != nil {
		return initializeResult{}, errors.New("initialize: serverInfo carries no version string")
	}
	return initializeResult{protocol: protocol, name: name, version: version}, nil
}

// exactMembers decodes an object by its members' exact names -- Go's
// struct decoding would match "ISERROR" to isError and let the last one
// win -- refusing anything but an object.
func exactMembers(raw json.RawMessage) (map[string]json.RawMessage, error) {
	if !canon.IsObject(raw) {
		return nil, errors.New("not an object")
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, err
	}
	return members, nil
}

// outputSchemaOf is the tool's declared output schema in canonical form,
// or nil when the tool declares none. The descriptor's other members --
// name, title, description, annotations -- are presentation, not schema,
// and a schema that changed with a description would name nothing.
func outputSchemaOf(descriptor json.RawMessage) ([]byte, error) {
	// The whole descriptor is canonicalized first, which refuses a
	// duplicate member name: a second outputSchema could otherwise pick
	// which one is named, or suppress the schema with a trailing null.
	canonical, err := canon.Canonicalize(descriptor, canon.CarryNumbersAsText)
	if err != nil {
		return nil, fmt.Errorf("descriptor: %v", err)
	}
	members, err := exactMembers(canonical)
	if err != nil {
		return nil, fmt.Errorf("descriptor: %v", err)
	}
	raw, ok := members["outputSchema"]
	if !ok || string(raw) == "null" {
		return nil, nil
	}
	if !canon.IsObject(raw) {
		return nil, errors.New("descriptor: outputSchema is not an object")
	}
	return canon.Canonicalize(raw, canon.CarryNumbersAsText)
}

// parseToolResult holds the server's answer to what a CallToolResult is
// -- content, an array of objects each with a string type; structured
// content, an object when present; isError, a boolean when present -- by
// exact member names on the canonical form, which has refused a duplicate
// name already, and returns that canonical form as the result. A result
// that says isError is not a fact and fails the acquisition with its text.
func parseToolResult(raw json.RawMessage, errorResults bool) ([]byte, error) {
	result, err := canon.Canonicalize(raw, canon.CarryNumbersAsText)
	if err != nil {
		return nil, fmt.Errorf("tools/call: the tool's result: %v", err)
	}
	// The shape is checked on the answer as the server wrote it -- no
	// duplicate names survive the canonicalization above, so exact member
	// names are unambiguous -- and before any number was carried as text,
	// so a numeric type is still a number.
	members, err := exactMembers(raw)
	if err != nil {
		return nil, errors.New("tools/call: the server's answer is not a tool result")
	}
	var content []json.RawMessage
	contentRaw, ok := members["content"]
	if !ok || json.Unmarshal(contentRaw, &content) != nil || string(contentRaw) == "null" {
		return nil, errors.New("tools/call: the tool's result has no content array")
	}
	for _, item := range content {
		itemMembers, err := exactMembers(item)
		if err != nil {
			return nil, errors.New("tools/call: a content item that is not an object")
		}
		var kind string
		if typ, ok := itemMembers["type"]; !ok || len(typ) == 0 || typ[0] != '"' || json.Unmarshal(typ, &kind) != nil || kind == "" {
			return nil, errors.New("tools/call: a content item without a type")
		}
		// A text item's text is a string in the form the server wrote:
		// judged before any number was carried as text, and null is not
		// a string whatever a decoder would fill in for it.
		if kind == "text" {
			if text, ok := itemMembers["text"]; !ok || len(text) == 0 || text[0] != '"' || !json.Valid(text) {
				return nil, errors.New("tools/call: a text item's text is not a string")
			}
		}
	}
	if structured, ok := members["structuredContent"]; ok && !canon.IsObject(structured) {
		return nil, errors.New("tools/call: structuredContent is not an object")
	}
	if flag, ok := members["isError"]; ok {
		switch string(flag) {
		case "true":
			// A source's error is a read that did not happen and fails the
			// acquisition; an executor's is the target's answer to a write,
			// enveloped and receipted as the response it is (ErrorResults).
			if !errorResults {
				return nil, fmt.Errorf("the tool reported an error: %s", textOf(content))
			}
		case "false":
		default:
			return nil, errors.New("tools/call: isError is not a boolean")
		}
	}
	return result, nil
}

// findTool pages through tools/list until the tool is found; when it is
// not, the names seen come back with the error.
func findTool(ctx context.Context, rpc *client, name string) (json.RawMessage, []string, error) {
	var names []string
	params := map[string]any{}
	for page := 0; page < maxToolPages; page++ {
		tools, next, err := toolPage(ctx, rpc, params)
		if err != nil {
			return nil, nil, err
		}
		for _, tool := range tools {
			if tool.name == name {
				return tool.descriptor, nil, nil
			}
			names = append(names, tool.name)
		}
		if next == "" {
			if names == nil {
				names = []string{}
			}
			return nil, names, errors.New("not offered")
		}
		params = map[string]any{"cursor": next}
	}
	return nil, nil, fmt.Errorf("tools/list did not end within %d pages", maxToolPages)
}

// listTools is every tool the server offers, by name, in the order the
// server lists them across its pages; visit, when given, is handed each
// tool with its descriptor as the server wrote it, in that order, as its
// page is read. A pinned listing -- one a snapshot is captured from --
// fails on a cursor seen twice, or on a name offered twice anywhere in it,
// even with the same descriptor: a listing that does either cannot be
// pinned.
func listTools(ctx context.Context, rpc *client, pinned bool, visit func(listedTool) error) ([]string, error) {
	names := []string{}
	// A cursor is remembered by its digest, and only by a pinned listing:
	// a server's cursor may be megabytes, and only the one to send next
	// need be kept whole.
	seen, cursors := map[string]bool{}, map[[sha256.Size]byte]bool{}
	params := map[string]any{}
	for page := 0; page < maxToolPages; page++ {
		tools, next, err := toolPage(ctx, rpc, params)
		if err != nil {
			return nil, err
		}
		for _, tool := range tools {
			if pinned {
				if seen[tool.name] {
					// The name is not written: it is the server's, and
					// could hold what moves an operator's terminal.
					return nil, errors.New("tools/list: the server offers one tool name twice")
				}
				seen[tool.name] = true
			}
			names = append(names, tool.name)
			if visit != nil {
				if err := visit(tool); err != nil {
					return nil, err
				}
			}
		}
		if next == "" {
			return names, nil
		}
		if pinned {
			digest := sha256.Sum256([]byte(next))
			if cursors[digest] {
				return nil, errors.New("tools/list: the server gave a cursor it had given before")
			}
			cursors[digest] = true
		}
		params = map[string]any{"cursor": next}
	}
	return nil, fmt.Errorf("tools/list did not end within %d pages", maxToolPages)
}

type listedTool struct {
	name       string
	descriptor json.RawMessage
}

// toolPage is one page of tools/list: the tools it names and the cursor
// of the next page, empty on the last.
func toolPage(ctx context.Context, rpc *client, params map[string]any) ([]listedTool, string, error) {
	raw, err := rpc.call(ctx, "tools/list", params)
	if err != nil {
		return nil, "", err
	}
	// A page is an object with a tools array, present and an array, and a
	// cursor that is a non-empty string when there is a next page: an
	// answer with neither is not a page, not an empty one.
	members, err := exactMembers(raw)
	if err != nil {
		return nil, "", errors.New("tools/list: the server's answer is not a tool list")
	}
	toolsRaw, ok := members["tools"]
	if !ok || !bytes.HasPrefix(bytes.TrimSpace(toolsRaw), []byte("[")) {
		return nil, "", errors.New("tools/list: the server's answer carries no tools array")
	}
	var listed struct {
		Tools []json.RawMessage
	}
	if json.Unmarshal(toolsRaw, &listed.Tools) != nil {
		return nil, "", errors.New("tools/list: the server's answer is not a tool list")
	}
	next := ""
	if cursorRaw, ok := members["nextCursor"]; ok {
		if json.Unmarshal(cursorRaw, &next) != nil || next == "" {
			return nil, "", errors.New("tools/list: nextCursor, when present, is a non-empty string")
		}
	}
	var tools []listedTool
	for _, tool := range listed.Tools {
		// A descriptor's name is read by its exact member name, with a
		// duplicate refused: "NAME" beside "name" would otherwise let a
		// descriptor answer to a name the server did not give it.
		if _, err := canon.Canonicalize(tool, canon.CarryNumbersAsText); err != nil {
			return nil, "", fmt.Errorf("tools/list: a tool descriptor is malformed: %v", err)
		}
		head, err := exactMembers(tool)
		if err != nil {
			return nil, "", errors.New("tools/list: a tool that is not an object")
		}
		var name string
		if json.Unmarshal(head["name"], &name) != nil || name == "" {
			return nil, "", errors.New("tools/list: a tool without a name")
		}
		tools = append(tools, listedTool{name: name, descriptor: tool})
	}
	return tools, next, nil
}

// answersFailure reports whether a tool result, isError or not, carries a
// text item beginning with the failure text the binding named -- as
// written, neither trimmed -- and that item's text. Items are read by
// their exact member names: struct decoding would let a "Text" beside
// "text" make the item unreadable and so passed over, and a text item
// that cannot be read is an error rather than an answer.
func answersFailure(result []byte, failure string) (text string, failed bool, err error) {
	members, err := exactMembers(result)
	if err != nil {
		return "", false, errors.New("the answer is not an object")
	}
	var content []json.RawMessage
	if json.Unmarshal(members["content"], &content) != nil {
		return "", false, errors.New("the answer carries no content array")
	}
	for _, item := range content {
		fields, err := exactMembers(item)
		if err != nil {
			return "", false, errors.New("a content item is not an object")
		}
		var kind string
		if json.Unmarshal(fields["type"], &kind) != nil || kind != "text" {
			continue
		}
		var body string
		if raw, ok := fields["text"]; !ok || len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &body) != nil {
			return "", false, errors.New("a text item's text is not a string")
		}
		if strings.HasPrefix(body, failure) {
			return body, true, nil
		}
	}
	return "", false, nil
}

// textOf joins the text parts of a tool result's content, for an error
// message.
func textOf(content []json.RawMessage) string {
	var parts []string
	for _, item := range content {
		var text struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if json.Unmarshal(item, &text) == nil && text.Type == "text" && text.Text != "" {
			parts = append(parts, text.Text)
		}
	}
	if len(parts) == 0 {
		return "no message"
	}
	return strings.Join(parts, " ")
}

// withStderr adds the server's first line of stderr to an error about a
// call that did not complete, which is where a server says why.
func withStderr(err error, srv *server) string {
	if line := srv.firstLine(); line != "" {
		return err.Error() + ": " + line
	}
	return err.Error()
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

type adapterIdentity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

type acquisition struct {
	Adapter       adapterIdentity `json:"adapter"`
	Endpoint      *string         `json:"endpoint"`
	Statement     *string         `json:"statement"`
	Snapshot      *string         `json:"snapshot"`
	PeerIdentity  *string         `json:"peerIdentity"`
	Schema        *string         `json:"schema"`
	UpstreamToken *string         `json:"upstreamToken"`
	ObservedAt    string          `json:"observedAt"`
}

type envelope struct {
	Acquisition acquisition     `json:"acquisition"`
	Result      json.RawMessage `json:"result"`
}

// buildEnvelope is the envelope of SPEC.md §6 for one tool call: the
// tool's whole result as the result, and the acquisition as this adapter
// recorded it -- the server as the adapter, the call as the statement, the
// tool's declared output schema digested as the schema (null when it
// declares none), and null for what a server reached over stdio cannot tell
// it: a snapshot, the peer's identity, any token the upstream produced. A
// tool call is one result, never a page.
func buildEnvelope(cfg Config, identity adapterIdentity, req Request, schema, result []byte, observedAt string) ([]byte, error) {
	statement, err := canon.EncodeJSON(map[string]any{"tool": req.Tool, "arguments": req.Arguments})
	if err != nil {
		return nil, err
	}
	acq := acquisition{
		Adapter:    identity,
		Statement:  ptr(string(statement)),
		ObservedAt: observedAt,
	}
	if schema != nil {
		sum := sha256.Sum256(schema)
		acq.Schema = ptr("sha256:" + hex.EncodeToString(sum[:]))
	}
	if cfg.Endpoint != "" {
		acq.Endpoint = ptr(cfg.Endpoint)
	}
	out, err := canon.EncodeJSON(envelope{Acquisition: acq, Result: json.RawMessage(result)})
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > cfg.MaxOutput {
		return nil, fmt.Errorf("the envelope exceeds the output bound of %d bytes", cfg.MaxOutput)
	}
	return out, nil
}

func ptr(s string) *string { return &s }
