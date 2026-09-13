// Package mcp is the gateway's MCP-shaped adapter: a client of a Model
// Context Protocol server reached over stdio -- a pinned server image in
// the operator's container runtime, or a local command -- that calls one
// tool and writes the envelope SPEC.md §6 states on stdout: the tool's
// result as the result, and the acquisition as this adapter recorded it.
// It holds the server's credentials and never the signing seed, and it
// imports nothing of the core module.
package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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
	// Credentials is the path of a JSON object of strings that become the
	// server's environment; empty for a server that needs none.
	Credentials string
	// Endpoint is the host the server reaches as the operator names it,
	// recorded as the receipt's endpoint; empty records null.
	Endpoint string
	// Tools, when given, are the only tools a request may name.
	Tools []string
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

// credentialsEnv reads the credentials file as a JSON object of strings and
// returns them as KEY=VALUE pairs, with every value for redaction. A value
// with a newline cannot be carried in an env file and is refused.
func credentialsEnv(path string) (env []string, secrets []string, err error) {
	if path == "" {
		return nil, nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("credentials could not be read: %w", err)
	}
	var values map[string]string
	if err := json.Unmarshal(data, &values); err != nil {
		return nil, nil, errors.New("credentials file is not a JSON object of strings")
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if k == "" || strings.ContainsAny(k, "=\n\x00") || strings.ContainsAny(values[k], "\n\x00") {
			return nil, nil, fmt.Errorf("credentials member %q cannot be carried as an environment variable", k)
		}
		env = append(env, k+"="+values[k])
	}
	return env, redact.SecretsOf(data), nil
}

// Acquire calls the requested tool once and returns the envelope.
func Acquire(ctx context.Context, cfg Config, req Request) ([]byte, error) {
	if (cfg.Image == "") == (len(cfg.Command) == 0) {
		return nil, errNoServer
	}
	if cfg.Image != "" && cfg.Runtime == "" {
		return nil, errors.New("a container runtime is required to run a server image")
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
	srv, err := startServer(ctx, cfg, env)
	if err != nil {
		return nil, err
	}
	finish := func(out []byte, err error) ([]byte, error) {
		if stopErr := srv.stop(); stopErr != nil {
			if err == nil {
				return nil, stopErr
			}
			err = fmt.Errorf("%v; the acquisition had also failed: %v", stopErr, err)
		}
		return out, err
	}
	fail := func(err error) ([]byte, error) {
		if ctx.Err() != nil {
			return finish(nil, fmt.Errorf("the server did not answer in time: %v", ctx.Err()))
		}
		return finish(nil, fmt.Errorf("%s", redact.Redact(withStderr(err, srv), secrets)))
	}
	rpc := newClient(srv.stdin, srv.stdout)
	// The handshake: what the server is, and that this client is done
	// negotiating.
	raw, err := rpc.call(ctx, "initialize", map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": clientName, "version": "0"},
	})
	if err != nil {
		return fail(err)
	}
	var initialized struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(raw, &initialized); err != nil || initialized.ProtocolVersion == "" {
		return fail(errors.New("initialize: the server's answer is not an initialize result"))
	}
	if err := rpc.notify("notifications/initialized", map[string]any{}); err != nil {
		return fail(err)
	}
	identity := srv.identity
	if identity.Version == "" {
		identity.Version = initialized.ServerInfo.Version
	}
	// The tool, as the server describes it: its descriptor is the schema
	// the receipt names.
	descriptor, names, err := findTool(ctx, rpc, req.Tool)
	if err != nil {
		if names != nil {
			return finish(nil, fmt.Errorf("tool %q is not one the server offers: %v", req.Tool, names))
		}
		return fail(err)
	}
	schema, err := canon.Canonicalize(descriptor, canon.CarryNumbersAsText)
	if err != nil {
		return finish(nil, fmt.Errorf("tool %q: descriptor: %v", req.Tool, err))
	}
	// The call.
	raw, err = rpc.call(ctx, "tools/call", map[string]any{"name": req.Tool, "arguments": req.Arguments})
	if err != nil {
		return fail(err)
	}
	observedAt := time.Now().UTC().Truncate(time.Second).Format(stampLayout)
	var outcome struct {
		IsError bool              `json:"isError"`
		Content []json.RawMessage `json:"content"`
	}
	if !canon.IsObject(raw) || json.Unmarshal(raw, &outcome) != nil {
		return finish(nil, errors.New("tools/call: the server's answer is not a tool result"))
	}
	if outcome.IsError {
		return finish(nil, fmt.Errorf("the tool reported an error: %s", redact.Redact(textOf(outcome.Content), secrets)))
	}
	if int64(len(raw)) > cfg.MaxOutput {
		return finish(nil, fmt.Errorf("the tool's result exceeds the output bound of %d bytes", cfg.MaxOutput))
	}
	result, err := canon.Canonicalize(raw, canon.CarryNumbersAsText)
	if err != nil {
		return finish(nil, fmt.Errorf("the tool's result: %v", err))
	}
	if err := srv.stop(); err != nil {
		return nil, err
	}
	return buildEnvelope(cfg, identity, req, schema, result, observedAt)
}

// findTool pages through tools/list until the tool is found; when it is
// not, the names seen come back with the error.
func findTool(ctx context.Context, rpc *client, name string) (json.RawMessage, []string, error) {
	var names []string
	params := map[string]any{}
	for page := 0; page < maxToolPages; page++ {
		raw, err := rpc.call(ctx, "tools/list", params)
		if err != nil {
			return nil, nil, err
		}
		var listed struct {
			Tools      []json.RawMessage `json:"tools"`
			NextCursor string            `json:"nextCursor"`
		}
		if !canon.IsObject(raw) || json.Unmarshal(raw, &listed) != nil {
			return nil, nil, errors.New("tools/list: the server's answer is not a tool list")
		}
		for _, tool := range listed.Tools {
			var head struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(tool, &head) != nil || head.Name == "" {
				return nil, nil, errors.New("tools/list: a tool without a name")
			}
			if head.Name == name {
				return tool, nil, nil
			}
			names = append(names, head.Name)
		}
		if listed.NextCursor == "" {
			if names == nil {
				names = []string{}
			}
			return nil, names, errors.New("not offered")
		}
		params = map[string]any{"cursor": listed.NextCursor}
	}
	return nil, nil, fmt.Errorf("tools/list did not end within %d pages", maxToolPages)
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

// withStderr adds the server's first line of stderr to an error about its
// ending, which is where a server says why.
func withStderr(err error, srv *server) string {
	if line := srv.firstLine(); line != "" && strings.Contains(err.Error(), "ended before") {
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
// tool's descriptor digested as the schema, and null for what a server
// reached over stdio cannot tell it: a snapshot, the peer's identity, any
// token the upstream produced. A tool call is one result, never a page.
func buildEnvelope(cfg Config, identity adapterIdentity, req Request, schema, result []byte, observedAt string) ([]byte, error) {
	statement, err := canon.EncodeJSON(map[string]any{"tool": req.Tool, "arguments": req.Arguments})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(schema)
	acq := acquisition{
		Adapter:    identity,
		Statement:  ptr(string(statement)),
		Schema:     ptr("sha256:" + hex.EncodeToString(sum[:])),
		ObservedAt: observedAt,
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
