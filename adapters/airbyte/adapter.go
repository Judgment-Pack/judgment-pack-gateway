// Package airbyte is the gateway's Airbyte-shaped adapter: it runs a pinned
// connector image through the operator's container runtime, reads one page
// of one stream's records, and writes the envelope SPEC.md §6 states on
// stdout -- the records as the result, and the acquisition as this adapter
// recorded it. It holds the connector's credentials and never the signing
// seed, and it imports nothing of the core module.
package airbyte

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Config is the operator's configuration of one adapter invocation, from
// the command line the gateway spawned it with.
type Config struct {
	// Runtime is the container runtime command: docker or podman.
	Runtime string
	// Image is the pinned connector image reference, name[:tag]@sha256:hex.
	Image string
	// Credentials is the path of the connector's configuration JSON, a file
	// this adapter's identity can read and the signer's cannot.
	Credentials string
	// Endpoint is the host the connector reaches as the operator names it,
	// recorded as the receipt's endpoint; empty records null.
	Endpoint string
	// MaxRecords caps the records read in one acquisition, whatever the
	// request's limit: past it, a stream that has offered no checkpoint is
	// given up on.
	MaxRecords int
	// MaxOutput bounds the envelope in bytes.
	MaxOutput int64
}

// Request is the canonical arguments the gateway hands the adapter on stdin:
// which stream, in which namespace when the connector has more than one,
// how many records the page should hold, and the snapshot of the previous
// page to resume from, exactly as its receipt recorded it.
type Request struct {
	Stream    string  `json:"stream"`
	Namespace *string `json:"namespace"`
	Limit     int     `json:"limit"`
	State     *string `json:"state"`
}

const defaultLimit = 1000

const stampLayout = "2006-01-02T15:04:05Z"

// ParseRequest reads the request strictly: an object with the known members
// only, a non-empty stream, a limit within the adapter's cap, a state that
// is the snapshot text or absent.
func ParseRequest(r io.Reader, maxRecords int) (Request, error) {
	dec := json.NewDecoder(io.LimitReader(r, 1<<20))
	dec.DisallowUnknownFields()
	var req Request
	if err := dec.Decode(&req); err != nil {
		return req, fmt.Errorf("request: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return req, errors.New("request: trailing content after the object")
	}
	if req.Stream == "" {
		return req, errors.New(`request: "stream" is required`)
	}
	if req.Limit == 0 {
		req.Limit = defaultLimit
	}
	if req.Limit < 1 || req.Limit > maxRecords {
		return req, fmt.Errorf(`request: "limit" must be between 1 and %d`, maxRecords)
	}
	if req.State != nil && *req.State == "" {
		return req, errors.New(`request: "state" is the previous snapshot text, or absent`)
	}
	return req, nil
}

type imageRef struct{ name, version, digest string }

// parseImage requires a digest-pinned reference: what runs is then what the
// receipt names, not whatever a tag resolved to at pull time.
func parseImage(ref string) (imageRef, error) {
	name, digest, ok := strings.Cut(ref, "@")
	if !ok || !isDigestString(digest) {
		return imageRef{}, fmt.Errorf("image %q must be pinned: name[:tag]@sha256:<64 hex>", ref)
	}
	version := ""
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		version, name = name[i+1:], name[:i]
	}
	if name == "" {
		return imageRef{}, fmt.Errorf("image %q has no name", ref)
	}
	return imageRef{name: name, version: version, digest: digest}, nil
}

// Acquire reads one page of the requested stream and returns the envelope.
func Acquire(ctx context.Context, cfg Config, req Request) ([]byte, error) {
	image, err := parseImage(cfg.Image)
	if err != nil {
		return nil, err
	}
	if cfg.MaxRecords < 1 || cfg.MaxOutput < 1 {
		return nil, errors.New("max-records and max-output must be positive")
	}
	if cfg.Runtime == "" {
		return nil, errors.New("a container runtime is required")
	}
	config, err := os.ReadFile(cfg.Credentials)
	if err != nil {
		return nil, fmt.Errorf("credentials could not be read: %w", err)
	}
	if !json.Valid(config) {
		return nil, errors.New("credentials file is not JSON")
	}
	secrets := secretsOf(config)
	strm, err := discover(ctx, cfg, req, config, secrets)
	if err != nil {
		return nil, err
	}
	catalogFile, mode, cursor := configuredCatalog(strm)
	stateFile, err := stateFileFor(req.State)
	if err != nil {
		return nil, err
	}
	schema, err := canonicalize(strm.JSONSchema, carryNumbersAsText)
	if err != nil {
		return nil, fmt.Errorf("stream %q: schema: %v", req.Stream, err)
	}
	p, err := readPage(ctx, cfg, req, strm, config, catalogFile, stateFile, secrets)
	if err != nil {
		return nil, err
	}
	return buildEnvelope(cfg, image, req, strm, mode, cursor, schema, p)
}

// discover runs the connector's discover and finds the requested stream in
// the catalog it emits: by name, and by namespace when the request gives
// one; a name the catalog holds in more than one namespace is ambiguous
// without it.
func discover(ctx context.Context, cfg Config, req Request, config []byte, secrets []string) (stream, error) {
	c, err := startContainer(ctx, cfg.Runtime, cfg.Image, "discover",
		map[string][]byte{"config.json": config}, []string{"--config", "/secrets/config.json"})
	if err != nil {
		return stream{}, err
	}
	finish := func(s stream, err error) (stream, error) {
		if stopErr := c.stop(); stopErr != nil {
			if err == nil {
				return stream{}, stopErr
			}
			err = fmt.Errorf("%v; also: %v", err, stopErr)
		}
		return s, err
	}
	var found *catalog
	scanner := newScanner(c.stdout)
	for scanner.Scan() {
		m, isMessage := parseMessage(scanner.Bytes())
		if !isMessage {
			continue
		}
		switch m.Type {
		case "CATALOG":
			found = m.Catalog
		case "TRACE":
			if m.Trace != nil && m.Trace.Type == "ERROR" {
				return finish(stream{}, fmt.Errorf("connector reported an error during discover: %s", redact(traceMessage(m.Trace), secrets)))
			}
		}
	}
	scanErr := scanner.Err()
	waitErr := c.wait()
	if ctx.Err() != nil {
		return finish(stream{}, fmt.Errorf("connector discover stopped: %v", ctx.Err()))
	}
	if scanErr != nil {
		return finish(stream{}, fmt.Errorf("reading the connector's catalog: %w", scanErr))
	}
	if waitErr != nil {
		return finish(stream{}, fmt.Errorf("connector discover failed: %s", redact(failure(c, waitErr), secrets)))
	}
	if found == nil {
		return finish(stream{}, errors.New("the connector emitted no catalog"))
	}
	var candidates []stream
	var names []string
	for _, raw := range found.Streams {
		var s stream
		if err := json.Unmarshal(raw, &s); err != nil || s.Name == "" {
			return finish(stream{}, errors.New("the connector's catalog is malformed"))
		}
		s.raw = raw
		names = append(names, describe(s.Name, s.Namespace))
		if s.Name != req.Stream || (req.Namespace != nil && s.Namespace != *req.Namespace) {
			continue
		}
		candidates = append(candidates, s)
	}
	switch len(candidates) {
	case 0:
		return finish(stream{}, fmt.Errorf("stream %q is not one the connector offers: %v", describe(req.Stream, deref(req.Namespace)), names))
	case 1:
		if len(candidates[0].JSONSchema) == 0 {
			return finish(stream{}, fmt.Errorf("stream %q has no schema", req.Stream))
		}
		return finish(candidates[0], nil)
	}
	var namespaces []string
	for _, s := range candidates {
		namespaces = append(namespaces, s.Namespace)
	}
	return finish(stream{}, fmt.Errorf(`stream %q exists in more than one namespace %v; name one with "namespace"`, req.Stream, namespaces))
}

func describe(name, namespace string) string {
	if namespace == "" {
		return name
	}
	return namespace + "/" + name
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// configuredCatalog is the ConfiguredAirbyteCatalog for one stream:
// incremental when the connector supports it, with its default cursor.
func configuredCatalog(s stream) (file []byte, mode string, cursor []string) {
	mode = "full_refresh"
	for _, m := range s.SupportedSyncModes {
		if m == "incremental" {
			mode = "incremental"
		}
	}
	entry := map[string]any{
		"stream":                s.raw,
		"sync_mode":             mode,
		"destination_sync_mode": "append",
	}
	if mode == "incremental" && len(s.DefaultCursorField) > 0 {
		cursor = s.DefaultCursorField
		entry["cursor_field"] = cursor
	}
	file, _ = json.Marshal(map[string]any{"streams": []any{entry}})
	return file, mode, cursor
}

// stateFileFor writes the previous snapshot back in the form the connector
// reads: a per-stream or global state message inside an array, a legacy
// state as its data.
func stateFileFor(snapshot *string) ([]byte, error) {
	if snapshot == nil {
		return nil, nil
	}
	var sm stateMessage
	if err := json.Unmarshal([]byte(*snapshot), &sm); err != nil {
		return nil, fmt.Errorf(`request: "state" is not a state the connector emitted: %v`, err)
	}
	switch {
	case sm.Type == "STREAM" || sm.Type == "GLOBAL":
		return []byte("[" + *snapshot + "]"), nil
	case len(sm.Data) > 0:
		return sm.Data, nil
	}
	return nil, errors.New(`request: "state" is neither a stream, a global nor a legacy state`)
}

// parseMessage tells a protocol message from a line that is not one. A
// line that is not a JSON object with a string "type" is something the
// connector printed, and is skipped; a line that is a message of a known
// type but malformed is an error the caller must not skip.
func parseMessage(line []byte) (message, bool) {
	var probe struct {
		Type *string `json:"type"`
	}
	if json.Unmarshal(line, &probe) != nil || probe.Type == nil {
		return message{}, false
	}
	var m message
	if err := json.Unmarshal(line, &m); err != nil {
		return message{Type: *probe.Type, malformed: err}, true
	}
	return m, true
}

type page struct {
	items      [][]byte
	state      []byte
	observedAt string
}

// readPage runs the connector's read and collects the page: the requested
// stream's records until the limit is reached and a checkpoint that covers
// them has arrived, or until the stream ends. Records after the limit are
// kept while waiting for the checkpoint, since the checkpoint covers them;
// past MaxRecords without one, the read is given up on. A stream that ends
// with records after its last checkpoint is refused: a page bookmarked by
// that checkpoint would repeat them on resume, and the envelope has no
// member to say so. The container is stopped as soon as the page is
// complete, and stopping it is part of the acquisition's success.
func readPage(ctx context.Context, cfg Config, req Request, strm stream, config, catalogFile, stateFile []byte, secrets []string) (page, error) {
	files := map[string][]byte{"config.json": config, "catalog.json": catalogFile}
	args := []string{"--config", "/secrets/config.json", "--catalog", "/secrets/catalog.json"}
	if stateFile != nil {
		files["state.json"] = stateFile
		args = append(args, "--state", "/secrets/state.json")
	}
	c, err := startContainer(ctx, cfg.Runtime, cfg.Image, "read", files, args)
	if err != nil {
		return page{}, err
	}
	finish := func(p page, err error) (page, error) {
		if stopErr := c.stop(); stopErr != nil {
			if err == nil {
				return page{}, stopErr
			}
			err = fmt.Errorf("%v; also: %v", err, stopErr)
		}
		return p, err
	}
	var p page
	var size int64
	uncovered := 0 // records since the last checkpoint
	scanner := newScanner(c.stdout)
	for scanner.Scan() {
		m, isMessage := parseMessage(scanner.Bytes())
		if !isMessage {
			continue
		}
		switch m.Type {
		case "RECORD":
			if m.malformed != nil || m.Record == nil || m.Record.Stream == "" {
				return finish(page{}, errors.New("the connector emitted a malformed RECORD message"))
			}
			if m.Record.Stream != strm.Name || m.Record.Namespace != strm.Namespace {
				continue
			}
			if !isObject(m.Record.Data) {
				return finish(page{}, fmt.Errorf("record %d of stream %q: data is not an object", len(p.items)+1, req.Stream))
			}
			item, err := canonicalize(m.Record.Data, carryNumbersAsText)
			if err != nil {
				return finish(page{}, fmt.Errorf("record %d of stream %q: %v", len(p.items)+1, req.Stream, err))
			}
			p.items = append(p.items, item)
			p.observedAt = time.Now().UTC().Truncate(time.Second).Format(stampLayout)
			uncovered++
			size += int64(len(item)) + 1
			if size > cfg.MaxOutput {
				return finish(page{}, fmt.Errorf("the page exceeds the output bound of %d bytes after %d records; lower the limit", cfg.MaxOutput, len(p.items)))
			}
			if len(p.items) > cfg.MaxRecords {
				return finish(page{}, fmt.Errorf("no checkpoint within %d records of stream %q; the stream cannot be paged", cfg.MaxRecords, req.Stream))
			}
		case "STATE":
			belongs, err := stateBelongsTo(m, strm)
			if err != nil {
				return finish(page{}, err)
			}
			if !belongs {
				continue
			}
			compacted, err := compact(m.State)
			if err != nil {
				return finish(page{}, fmt.Errorf("the connector's state is malformed: %v", err))
			}
			p.state = compacted
			uncovered = 0
			if len(p.items) >= req.Limit {
				if p.observedAt == "" {
					p.observedAt = time.Now().UTC().Truncate(time.Second).Format(stampLayout)
				}
				return finish(p, nil)
			}
		case "TRACE":
			if m.Trace != nil && m.Trace.Type == "ERROR" {
				return finish(page{}, fmt.Errorf("connector reported an error: %s", redact(traceMessage(m.Trace), secrets)))
			}
		}
	}
	scanErr := scanner.Err()
	waitErr := c.wait()
	if ctx.Err() != nil {
		return finish(page{}, fmt.Errorf("connector read stopped after %d records: %v", len(p.items), ctx.Err()))
	}
	if scanErr != nil {
		return finish(page{}, fmt.Errorf("reading the connector's records: %w", scanErr))
	}
	if waitErr != nil {
		return finish(page{}, fmt.Errorf("connector read failed: %s", redact(failure(c, waitErr), secrets)))
	}
	if p.state != nil && uncovered > 0 {
		return finish(page{}, fmt.Errorf("the connector ended stream %q with %d records after its last checkpoint; a page bookmarked there would repeat them on resume", req.Stream, uncovered))
	}
	if p.observedAt == "" {
		p.observedAt = time.Now().UTC().Truncate(time.Second).Format(stampLayout)
	}
	return finish(p, nil)
}

// stateBelongsTo reports whether a state message bookmarks the stream: a
// per-stream state names it by name and namespace; a global or legacy
// state covers every stream. A STATE message without a state object, or a
// per-stream one without a descriptor, is malformed.
func stateBelongsTo(m message, strm stream) (bool, error) {
	if m.malformed != nil || !isObject(m.State) {
		return false, errors.New("the connector emitted a malformed STATE message")
	}
	var sm stateMessage
	if err := json.Unmarshal(m.State, &sm); err != nil {
		return false, errors.New("the connector emitted a malformed STATE message")
	}
	switch sm.Type {
	case "STREAM":
		if sm.Stream == nil || sm.Stream.Descriptor.Name == "" {
			return false, errors.New("the connector emitted a STREAM state without a stream descriptor")
		}
		return sm.Stream.Descriptor.Name == strm.Name && sm.Stream.Descriptor.Namespace == strm.Namespace, nil
	case "GLOBAL", "LEGACY", "":
		return true, nil
	}
	return false, fmt.Errorf("the connector emitted a state of unknown type %q", sm.Type)
}

// isObject reports whether raw is a non-empty JSON object.
func isObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 2 && trimmed[0] == '{' && json.Valid(trimmed)
}

func traceMessage(t *trace) string {
	if t.Error != nil && t.Error.Message != "" {
		return t.Error.Message
	}
	return "no message"
}

// failure names why a connector command failed: the connector's own first
// line of stderr when it wrote one, otherwise the runtime's error.
func failure(c *container, err error) string {
	if line := c.firstLine(); line != "" {
		return line
	}
	return err.Error()
}

// secretsOf collects every string value of the connector's configuration,
// at any depth, four bytes or longer -- a password, a token, a host -- so
// that a diagnostic repeating one is redacted before it crosses the source
// boundary, where the gateway returns it to whoever called /acquire. It is
// as good as the connector's habit of quoting its configuration verbatim:
// a secret it encodes or splits is not caught.
func secretsOf(config []byte) []string {
	var value any
	if json.Unmarshal(config, &value) != nil {
		return nil
	}
	var out []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			if len(x) >= 4 {
				out = append(out, x)
			}
		case map[string]any:
			for _, e := range x {
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(value)
	return out
}

const maxDiagnostic = 512

// redact replaces every configured string value in a diagnostic and bounds
// its length.
func redact(text string, secrets []string) string {
	for _, s := range secrets {
		text = strings.ReplaceAll(text, s, "[redacted]")
	}
	if len(text) > maxDiagnostic {
		text = text[:maxDiagnostic] + "…"
	}
	return text
}

func newScanner(r io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1<<20), 64<<20)
	return scanner
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
	Acquisition acquisition       `json:"acquisition"`
	Result      []json.RawMessage `json:"result"`
	Page        bool              `json:"page"`
}

// buildEnvelope is the envelope of SPEC.md §6 for one page: the records as
// the result, and the acquisition as this adapter recorded it -- the image
// as the adapter, the read request as the statement, the connector's last
// checkpoint as the snapshot, the discovered schema's digest, and null for
// what a connector inside a container cannot tell it: the peer's identity
// and any token the upstream produced.
func buildEnvelope(cfg Config, image imageRef, req Request, strm stream, mode string, cursor []string, schema []byte, p page) ([]byte, error) {
	statementValue := map[string]any{
		"stream":      strm.Name,
		"namespace":   nil,
		"syncMode":    mode,
		"cursorField": cursor,
		"state":       nil,
	}
	if strm.Namespace != "" {
		statementValue["namespace"] = strm.Namespace
	}
	if req.State != nil {
		statementValue["state"] = json.RawMessage(*req.State)
	}
	statement, err := encodeJSON(statementValue)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(schema)
	schemaDigest := "sha256:" + hex.EncodeToString(sum[:])
	acq := acquisition{
		Adapter:    adapterIdentity{Name: image.name, Version: image.version, Digest: image.digest},
		Statement:  ptr(string(statement)),
		Schema:     ptr(schemaDigest),
		ObservedAt: p.observedAt,
	}
	if cfg.Endpoint != "" {
		acq.Endpoint = ptr(cfg.Endpoint)
	}
	if p.state != nil {
		acq.Snapshot = ptr(string(p.state))
	}
	result := make([]json.RawMessage, 0, len(p.items))
	for _, item := range p.items {
		result = append(result, json.RawMessage(item))
	}
	out, err := encodeJSON(envelope{Acquisition: acq, Result: result, Page: true})
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > cfg.MaxOutput {
		return nil, fmt.Errorf("the envelope exceeds the output bound of %d bytes; lower the limit", cfg.MaxOutput)
	}
	return out, nil
}

// encodeJSON marshals without HTML escaping and without a trailing newline.
func encodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func ptr(s string) *string { return &s }
