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
// which stream, how many records the page should hold, and the snapshot of
// the previous page to resume from, exactly as its receipt recorded it.
type Request struct {
	Stream string  `json:"stream"`
	Limit  int     `json:"limit"`
	State  *string `json:"state"`
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
	strm, err := discover(ctx, cfg, req.Stream, config)
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
	p, err := readPage(ctx, cfg, req, config, catalogFile, stateFile)
	if err != nil {
		return nil, err
	}
	return buildEnvelope(cfg, image, req, mode, cursor, schema, p)
}

// discover runs the connector's discover and finds the requested stream in
// the catalog it emits.
func discover(ctx context.Context, cfg Config, name string, config []byte) (stream, error) {
	c, err := startContainer(ctx, cfg.Runtime, cfg.Image, "discover",
		map[string][]byte{"config.json": config}, []string{"--config", "/secrets/config.json"})
	if err != nil {
		return stream{}, err
	}
	defer c.stop()
	var found *catalog
	scanner := newScanner(c.stdout)
	for scanner.Scan() {
		var m message
		if json.Unmarshal(scanner.Bytes(), &m) != nil {
			continue
		}
		switch m.Type {
		case "CATALOG":
			found = m.Catalog
		case "TRACE":
			if m.Trace != nil && m.Trace.Type == "ERROR" {
				return stream{}, fmt.Errorf("connector reported an error during discover: %s", traceMessage(m.Trace))
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return stream{}, fmt.Errorf("reading the connector's catalog: %w", err)
	}
	waitErr := c.wait()
	if ctx.Err() != nil {
		return stream{}, fmt.Errorf("connector discover stopped: %v", ctx.Err())
	}
	if waitErr != nil && found == nil {
		return stream{}, fmt.Errorf("connector discover failed: %s", failure(c, waitErr))
	}
	if found == nil {
		return stream{}, errors.New("the connector emitted no catalog")
	}
	var names []string
	for _, raw := range found.Streams {
		var s stream
		if err := json.Unmarshal(raw, &s); err != nil {
			return stream{}, fmt.Errorf("the connector's catalog is malformed: %v", err)
		}
		if s.Name == name {
			if len(s.JSONSchema) == 0 {
				return stream{}, fmt.Errorf("stream %q has no schema", name)
			}
			s.raw = raw
			return s, nil
		}
		names = append(names, s.Name)
	}
	return stream{}, fmt.Errorf("stream %q is not one the connector offers: %v", name, names)
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

type page struct {
	items      [][]byte
	state      []byte
	observedAt string
}

// readPage runs the connector's read and collects the page: the requested
// stream's records until the limit is reached and a checkpoint that covers
// them has arrived, or until the stream ends. Records after the limit are
// kept while waiting for the checkpoint, since the checkpoint covers them;
// past MaxRecords without one, the read is given up on. The container is
// stopped as soon as the page is complete.
func readPage(ctx context.Context, cfg Config, req Request, config, catalogFile, stateFile []byte) (page, error) {
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
	defer c.stop()
	var p page
	var size int64
	covered := true
	scanner := newScanner(c.stdout)
	for scanner.Scan() {
		var m message
		if json.Unmarshal(scanner.Bytes(), &m) != nil {
			continue
		}
		switch m.Type {
		case "RECORD":
			if m.Record == nil || m.Record.Stream != req.Stream {
				continue
			}
			item, err := canonicalize(m.Record.Data, carryNumbersAsText)
			if err != nil {
				return page{}, fmt.Errorf("record %d of stream %q: %v", len(p.items)+1, req.Stream, err)
			}
			p.items = append(p.items, item)
			p.observedAt = time.Now().UTC().Truncate(time.Second).Format(stampLayout)
			covered = false
			size += int64(len(item)) + 1
			if size > cfg.MaxOutput {
				return page{}, fmt.Errorf("the page exceeds the output bound of %d bytes after %d records; lower the limit", cfg.MaxOutput, len(p.items))
			}
			if len(p.items) > cfg.MaxRecords {
				return page{}, fmt.Errorf("no checkpoint within %d records of stream %q; the stream cannot be paged", cfg.MaxRecords, req.Stream)
			}
		case "STATE":
			if !stateBelongsTo(m.State, req.Stream) {
				continue
			}
			compacted, err := compact(m.State)
			if err != nil {
				return page{}, fmt.Errorf("the connector's state is malformed: %v", err)
			}
			p.state = compacted
			covered = true
			if len(p.items) >= req.Limit {
				if p.observedAt == "" {
					p.observedAt = time.Now().UTC().Truncate(time.Second).Format(stampLayout)
				}
				c.stop()
				return p, nil
			}
		case "TRACE":
			if m.Trace != nil && m.Trace.Type == "ERROR" {
				return page{}, fmt.Errorf("connector reported an error: %s", traceMessage(m.Trace))
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return page{}, fmt.Errorf("reading the connector's records: %w", err)
	}
	waitErr := c.wait()
	if ctx.Err() != nil {
		return page{}, fmt.Errorf("connector read stopped after %d records: %v", len(p.items), ctx.Err())
	}
	if waitErr != nil {
		return page{}, fmt.Errorf("connector read failed: %s", failure(c, waitErr))
	}
	_ = covered // at the end of the stream the last bookmark is the snapshot, covering or not
	if p.observedAt == "" {
		p.observedAt = time.Now().UTC().Truncate(time.Second).Format(stampLayout)
	}
	return p, nil
}

// stateBelongsTo reports whether a state message bookmarks the stream: a
// per-stream state names it; a global or legacy state covers every stream.
func stateBelongsTo(raw json.RawMessage, stream string) bool {
	var sm stateMessage
	if json.Unmarshal(raw, &sm) != nil {
		return false
	}
	if sm.Type == "STREAM" {
		return sm.Stream != nil && sm.Stream.Descriptor.Name == stream
	}
	return true
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
func buildEnvelope(cfg Config, image imageRef, req Request, mode string, cursor []string, schema []byte, p page) ([]byte, error) {
	statementValue := map[string]any{
		"stream":      req.Stream,
		"syncMode":    mode,
		"cursorField": cursor,
		"state":       nil,
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
