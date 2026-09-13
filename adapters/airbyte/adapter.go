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
	"sort"
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
	Stream    string         `json:"stream"`
	Namespace OptionalString `json:"namespace"`
	Limit     int            `json:"limit"`
	State     *string        `json:"state"`
}

// OptionalString tells an absent member from a null one and from a string:
// a namespace not given constrains nothing, a null one names the streams
// without a namespace, a string names that namespace.
type OptionalString struct {
	Given bool
	Value *string
}

func (o *OptionalString) UnmarshalJSON(data []byte) error {
	o.Given = true
	if string(data) == "null" {
		o.Value = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf(`"namespace" must be a string or null`)
	}
	o.Value = &s
	return nil
}

func (o OptionalString) MarshalJSON() ([]byte, error) {
	if !o.Given || o.Value == nil {
		return []byte("null"), nil
	}
	return json.Marshal(*o.Value)
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
			// The container that needs a hand comes first: the gateway
			// keeps only the start of a source's diagnostic.
			if err == nil {
				return stream{}, stopErr
			}
			err = fmt.Errorf("%v; the acquisition had also failed: %v", stopErr, err)
		}
		return s, err
	}
	var found *catalog
	scanner := newScanner(c.stdout)
	for scanner.Scan() {
		m, isMessage, err := parseMessage(scanner.Bytes())
		if err != nil {
			return finish(stream{}, err)
		}
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
		if s.Name != req.Stream || (req.Namespace.Given && !sameNamespace(s.Namespace, req.Namespace.Value)) {
			continue
		}
		candidates = append(candidates, s)
	}
	switch len(candidates) {
	case 0:
		return finish(stream{}, fmt.Errorf("stream %q is not one the connector offers: %v", describe(req.Stream, req.Namespace.Value), names))
	case 1:
		if len(candidates[0].JSONSchema) == 0 {
			return finish(stream{}, fmt.Errorf("stream %q has no schema", req.Stream))
		}
		return finish(candidates[0], nil)
	}
	var namespaces []string
	for _, s := range candidates {
		namespaces = append(namespaces, describeNamespace(s.Namespace))
	}
	return finish(stream{}, fmt.Errorf(`stream %q exists in more than one namespace %v; name one with "namespace"`, req.Stream, namespaces))
}

// describe names a stream for a message: namespace/name, or the name alone
// when the namespace is null; an empty namespace shows as "/name".
func describe(name string, namespace *string) string {
	if namespace == nil {
		return name
	}
	return *namespace + "/" + name
}

func describeNamespace(namespace *string) string {
	if namespace == nil {
		return "null"
	}
	return *namespace
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

// parseMessage tells a protocol message from a line that is not one, and
// refuses a message of a known type that does not have its shape. A line
// that is not a JSON object with a string "type" is something the
// connector printed, and is skipped; a RECORD, STATE, TRACE or CATALOG
// that does not decode as one is an error the caller must not skip, since
// what it failed to say may have been an error.
func parseMessage(line []byte) (message, bool, error) {
	var probe struct {
		Type *string `json:"type"`
	}
	if json.Unmarshal(line, &probe) != nil || probe.Type == nil {
		return message{}, false, nil
	}
	malformed := fmt.Errorf("the connector emitted a malformed %s message", *probe.Type)
	var m message
	if err := json.Unmarshal(line, &m); err != nil {
		switch *probe.Type {
		case "RECORD", "STATE", "TRACE", "CATALOG":
			return message{}, true, malformed
		}
		return message{}, false, nil
	}
	// The payload the type requires must be there, whatever phase reads
	// it: a scalar STATE during discover or a null CATALOG during read is
	// refused where it appears.
	switch m.Type {
	case "RECORD":
		if m.Record == nil || m.Record.Stream == "" || len(m.Record.Data) == 0 {
			return message{}, true, malformed
		}
	case "STATE":
		if !validState(m.State) {
			return message{}, true, malformed
		}
	case "TRACE":
		if m.Trace == nil || m.Trace.Type == "" {
			return message{}, true, malformed
		}
	case "CATALOG":
		if m.Catalog == nil {
			return message{}, true, malformed
		}
	}
	return m, true, nil
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
			err = fmt.Errorf("%v; the acquisition had also failed: %v", stopErr, err)
		}
		return p, err
	}
	var p page
	var size int64
	uncovered := 0 // records since the last checkpoint
	scanner := newScanner(c.stdout)
	for scanner.Scan() {
		m, isMessage, err := parseMessage(scanner.Bytes())
		if err != nil {
			return finish(page{}, err)
		}
		if !isMessage {
			continue
		}
		switch m.Type {
		case "RECORD":
			if m.Record.Stream != strm.Name || !sameNamespace(m.Record.Namespace, strm.Namespace) {
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

// validState reports whether a STATE message carries the payload its type
// requires, so that every bookmark recorded can be handed back
// (stateFileFor): a STREAM state its descriptor with a name, a GLOBAL state
// its global object, a LEGACY or untyped state its data object. A state of
// any other type is refused.
func validState(raw json.RawMessage) bool {
	if members, ok := objectMembers(raw); !ok || members == 0 {
		return false
	}
	var sm stateMessage
	if json.Unmarshal(raw, &sm) != nil {
		return false
	}
	switch sm.Type {
	case "STREAM":
		return sm.Stream != nil && sm.Stream.Descriptor.Name != ""
	case "GLOBAL":
		_, ok := objectMembers(sm.Global)
		return ok
	case "LEGACY", "":
		_, ok := objectMembers(sm.Data)
		return ok
	}
	return false
}

// stateBelongsTo reports whether a state message, already known to be
// valid, bookmarks the stream: a per-stream state names it by name and
// namespace; a global or legacy state covers every stream.
func stateBelongsTo(m message, strm stream) (bool, error) {
	var sm stateMessage
	if err := json.Unmarshal(m.State, &sm); err != nil {
		return false, errors.New("the connector emitted a malformed STATE message")
	}
	if sm.Type == "STREAM" {
		return sm.Stream.Descriptor.Name == strm.Name && sameNamespace(sm.Stream.Descriptor.Namespace, strm.Namespace), nil
	}
	return true, nil
}

// objectMembers reports whether raw is a JSON object, and how many members
// it has: structurally, so {} and { } are the same empty object.
func objectMembers(raw json.RawMessage) (int, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return 0, false
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(trimmed, &members) != nil {
		return 0, false
	}
	return len(members), true
}

// isObject reports whether raw is a JSON object, empty or not.
func isObject(raw json.RawMessage) bool {
	_, ok := objectMembers(raw)
	return ok
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

// secretsOf collects every scalar of the connector's configuration, at any
// depth -- every non-empty string and every number, as written, each once
// -- so that a diagnostic repeating one is redacted before it crosses the
// source boundary, where the gateway returns it to whoever called
// /acquire. The list is sorted longest first so a value that contains
// another is replaced whole. It is as good as the connector's habit of
// quoting its configuration verbatim: a secret it encodes or splits is not
// caught, and a one-letter value redacts every letter like it.
func secretsOf(config []byte) []string {
	dec := json.NewDecoder(bytes.NewReader(config))
	dec.UseNumber()
	var value any
	if dec.Decode(&value) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			add(x)
		case json.Number:
			add(x.String())
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
	sort.SliceStable(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

const maxDiagnostic = 512

// redact rewrites a diagnostic in one pass over the original text: at each
// position the longest configured value that starts there is replaced, and
// what was written is never scanned again, so a replacement can neither
// grow the text past its bound nor be re-matched. The output is bounded as
// it is built.
func redact(text string, secrets []string) string {
	var out strings.Builder
	for i := 0; i < len(text); {
		if out.Len() > maxDiagnostic {
			break
		}
		matched := false
		for _, s := range secrets {
			if strings.HasPrefix(text[i:], s) {
				out.WriteString("[redacted]")
				i += len(s)
				matched = true
				break
			}
		}
		if !matched {
			out.WriteByte(text[i])
			i++
		}
	}
	if out.Len() > maxDiagnostic {
		return out.String()[:maxDiagnostic] + "…"
	}
	return out.String()
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
	if strm.Namespace != nil {
		statementValue["namespace"] = *strm.Namespace
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
