// Package airbyte is the gateway's Airbyte-shaped adapter: it runs a pinned
// connector image through the operator's container runtime, reads one page
// of one stream's records, and writes the envelope SPEC.md §6 states on
// stdout -- the records as the result, and the acquisition as this adapter
// recorded it. It holds the connector's credentials and never the signing
// seed, and it imports nothing of the core module.
package airbyte

import (
	"adapters/internal/canon"
	"adapters/internal/containers"
	"adapters/internal/redact"
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// Acquire reads one page of the requested stream and returns the envelope.
func Acquire(ctx context.Context, cfg Config, req Request) ([]byte, error) {
	image, err := containers.ParseImage(cfg.Image)
	if err != nil {
		return nil, err
	}
	if cfg.MaxRecords < 1 || cfg.MaxOutput < 1 {
		return nil, errors.New("max-records and max-output must be positive")
	}
	if cfg.Runtime == "" {
		return nil, errors.New("a container runtime is required")
	}
	config, secrets, err := readConfig(cfg.Credentials)
	if err != nil {
		return nil, err
	}
	strm, err := discover(ctx, cfg, req, config, secrets)
	if err != nil {
		return nil, err
	}
	catalogFile, mode, cursor := configuredCatalog(strm)
	stateFile, err := stateFileFor(req.State)
	if err != nil {
		return nil, err
	}
	schema, err := canon.Canonicalize(strm.JSONSchema, canon.CarryNumbersAsText)
	if err != nil {
		return nil, fmt.Errorf("stream %q: schema: %v", req.Stream, err)
	}
	p, err := readPage(ctx, cfg, req, strm, config, catalogFile, stateFile, secrets)
	if err != nil {
		return nil, err
	}
	return buildEnvelope(cfg, image, req, strm, mode, cursor, schema, p)
}

// checkReport is what Check writes: the pinned image and what the
// connector answered. It is for the operator who is connecting a platform,
// and it is not an envelope: nothing is minted from it.
type checkReport struct {
	Status  string          `json:"status"`
	Adapter adapterIdentity `json:"adapter"`
	Message string          `json:"message"`
}

// FailedCheck is the report of a check that did not succeed, for stdout
// beside the exit status: the same members a success carries, so a
// caller reads one shape, and the reason as the adapter reported it,
// already redacted.
func FailedCheck(reason string) []byte {
	out, _ := canon.EncodeJSON(map[string]any{"check": map[string]string{"status": "failed", "message": reason}})
	return out
}

// Check runs the connector's check with the credentials and reports what
// the platform answered; it reads nothing. A connector that answers FAILED,
// reports an error, or answers nothing fails the check with the connector's
// own message, redacted; a connector exits 0 whichever way it answers, so
// the answer is read from the message and never from the exit status.
func Check(ctx context.Context, cfg Config) ([]byte, error) {
	image, err := containers.ParseImage(cfg.Image)
	if err != nil {
		return nil, err
	}
	if cfg.Runtime == "" {
		return nil, errors.New("a container runtime is required")
	}
	config, secrets, err := readConfig(cfg.Credentials)
	if err != nil {
		return nil, err
	}
	c, err := containers.Start(ctx, containers.Spec{
		Redact:  func(text string, truncated bool) string { return redact.Diagnostic(text, truncated, secrets) },
		Runtime: cfg.Runtime, Image: cfg.Image,
		Files: map[string][]byte{"config.json": config},
		Args:  []string{"check", "--config", "/secrets/config.json"},
	})
	if err != nil {
		return nil, err
	}
	// Every error crosses the same redaction, a container that would not
	// stop included: an inspect's answer can quote what it was asked.
	finish := func(out []byte, err error) ([]byte, error) {
		if stopErr := c.Stop(); stopErr != nil {
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
	var answer *connectionStatus
	scanner := newScanner(c.Stdout)
	for scanner.Scan() {
		m, isMessage, err := parseMessage(scanner.Bytes())
		if err != nil {
			return finish(nil, err)
		}
		if !isMessage {
			continue
		}
		switch m.Type {
		case "CONNECTION_STATUS":
			// The first answer is the answer: a later one cannot revise
			// it, and a FAILED ends the check where it is said.
			if answer != nil {
				return finish(nil, errors.New("the connector answered more than once"))
			}
			answer = m.ConnectionStatus
			if answer.Status != "SUCCEEDED" {
				return finish(nil, fmt.Errorf("the connector could not connect (%s): %s", answer.Status, answer.Message))
			}
		case "TRACE":
			if m.Trace != nil && m.Trace.Type == "ERROR" {
				return finish(nil, fmt.Errorf("connector reported an error during check: %s", traceMessage(m.Trace)))
			}
		}
	}
	scanErr := scanner.Err()
	waitErr := c.Wait()
	if ctx.Err() != nil {
		return finish(nil, fmt.Errorf("connector check stopped: %v", ctx.Err()))
	}
	if scanErr != nil {
		return finish(nil, fmt.Errorf("reading the connector's answer: %w", scanErr))
	}
	if waitErr != nil {
		return finish(nil, fmt.Errorf("connector check failed: %s", failure(c, waitErr)))
	}
	if answer == nil {
		// The connector may have said why on stderr; that is the
		// operator's to read, redacted as every diagnostic is.
		reason := "the connector answered no connection status"
		if line := c.FirstLine(); line != "" {
			reason += ": " + line
		}
		return finish(nil, errors.New(reason))
	}
	report, err := canon.EncodeJSON(map[string]any{"check": checkReport{
		Status:  "succeeded",
		Adapter: adapterIdentity{Name: image.Name, Version: image.Version, Digest: image.Digest},
		Message: redact.Redact(answer.Message, secrets),
	}})
	if err != nil {
		return finish(nil, err)
	}
	return finish(report, nil)
}

// readConfig reads the connector's configuration: at most 1 MiB, an
// object, held to exact member names with a duplicate refused, so that
// every value in it is one the redactor knows.
func readConfig(path string) (config []byte, secrets []string, err error) {
	config, err = redact.ReadCredentials(path)
	if err != nil {
		return nil, nil, err
	}
	if _, err := canon.Canonicalize(config, canon.CarryNumbersAsText); err != nil {
		return nil, nil, redact.MalformedCredentials(err)
	}
	if !canon.IsObject(config) {
		return nil, nil, errors.New("credentials file is not a JSON object")
	}
	return config, redact.SecretsOf(config), nil
}

// discover runs the connector's discover and finds the requested stream in
// the catalog it emits: by name, and by namespace when the request gives
// one; a name the catalog holds in more than one namespace is ambiguous
// without it.
func discover(ctx context.Context, cfg Config, req Request, config []byte, secrets []string) (stream, error) {
	c, err := containers.Start(ctx, containers.Spec{
		Redact:  func(text string, truncated bool) string { return redact.Diagnostic(text, truncated, secrets) },
		Runtime: cfg.Runtime, Image: cfg.Image,
		Files: map[string][]byte{"config.json": config},
		Args:  []string{"discover", "--config", "/secrets/config.json"},
	})
	if err != nil {
		return stream{}, err
	}
	finish := func(s stream, err error) (stream, error) {
		if stopErr := c.Stop(); stopErr != nil {
			// The container that needs a hand comes first: the gateway
			// keeps only the start of a source's diagnostic.
			if err == nil {
				err = stopErr
			} else {
				err = fmt.Errorf("%v; the acquisition had also failed: %v", stopErr, err)
			}
		}
		if err != nil {
			return stream{}, errors.New(redact.Redact(err.Error(), secrets))
		}
		return s, nil
	}
	var found *catalog
	scanner := newScanner(c.Stdout)
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
				return finish(stream{}, fmt.Errorf("connector reported an error during discover: %s", redact.Redact(traceMessage(m.Trace), secrets)))
			}
		}
	}
	scanErr := scanner.Err()
	waitErr := c.Wait()
	if ctx.Err() != nil {
		return finish(stream{}, fmt.Errorf("connector discover stopped: %v", ctx.Err()))
	}
	if scanErr != nil {
		return finish(stream{}, fmt.Errorf("reading the connector's catalog: %w", scanErr))
	}
	if waitErr != nil {
		return finish(stream{}, fmt.Errorf("connector discover failed: %s", redact.Redact(failure(c, waitErr), secrets)))
	}
	if found == nil {
		return finish(stream{}, errors.New("the connector emitted no catalog"))
	}
	var candidates []stream
	var names []string
	for _, raw := range found.Streams {
		s, ok := parseStream(raw)
		if !ok {
			return finish(stream{}, errors.New("the connector's catalog is malformed"))
		}
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
	sm, ok := objectOf([]byte(*snapshot))
	if !ok {
		return nil, errors.New(`request: "state" is not a state the connector emitted`)
	}
	typ, _ := sm.str("type")
	switch {
	case typ == "STREAM" || typ == "GLOBAL":
		return []byte("[" + *snapshot + "]"), nil
	case len(sm["data"]) > 0:
		return sm["data"], nil
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
	// Whether the line is an object is read from its first byte, not
	// from a decoder: a decoder would refuse an object too deep to read,
	// and a line that begins an object and cannot be read is refused
	// below, not skipped.
	if !startsObject(line) {
		return message{}, false, nil
	}
	// Every object line is held to exact member names with a duplicate
	// refused at any depth, and to the nesting a decoder reads -- before
	// it is classified, since a second "type" spelled with an escape, or
	// a member too deep to read, would otherwise decide what the line is;
	// the canonical form itself is not used, so a checkpoint is handed
	// back as emitted.
	if _, err := canon.Canonicalize(line, canon.CarryNumbersAsText); err != nil {
		return message{}, true, fmt.Errorf("the connector emitted a malformed message: %v", err)
	}
	members, ok := objectOf(line)
	if !ok {
		return message{}, true, errors.New("the connector emitted a malformed message: an object that does not decode")
	}
	typ, ok := members.str("type")
	if !ok {
		return message{}, false, nil
	}
	switch typ {
	case "RECORD", "STATE", "TRACE", "CATALOG", "CONNECTION_STATUS":
	default:
		return message{}, false, nil // LOG, SPEC, CONTROL: not read here
	}
	malformed := fmt.Errorf("the connector emitted a malformed %s message", typ)
	m := message{Type: typ}
	switch typ {
	case "RECORD":
		rec, ok := objectOf(members["record"])
		if !ok {
			return message{}, true, malformed
		}
		r := &record{Data: rec["data"]}
		if r.Stream, ok = rec.str("stream"); !ok || r.Stream == "" || len(r.Data) == 0 {
			return message{}, true, malformed
		}
		if r.Namespace, ok = rec.optional("namespace"); !ok {
			return message{}, true, malformed
		}
		m.Record = r
	case "STATE":
		// The payload the type requires must be there, whatever phase
		// reads it: a scalar STATE during discover is refused where it
		// appears.
		m.State = members["state"]
		if !validState(m.State) {
			return message{}, true, malformed
		}
	case "TRACE":
		tr, ok := objectOf(members["trace"])
		if !ok {
			return message{}, true, malformed
		}
		t := &trace{}
		if t.Type, ok = tr.str("type"); !ok || t.Type == "" {
			return message{}, true, malformed
		}
		if raw, present := tr["error"]; present && string(raw) != "null" {
			errObj, ok := objectOf(raw)
			if !ok {
				return message{}, true, malformed
			}
			msg, ok := errObj.str("message")
			if raw, present := errObj["message"]; present && !ok && string(raw) != "null" {
				return message{}, true, malformed
			}
			t.Error = &traceError{Message: msg}
		}
		m.Trace = t
	case "CATALOG":
		cat, ok := objectOf(members["catalog"])
		if !ok {
			return message{}, true, malformed
		}
		c := &catalog{}
		if raw, present := cat["streams"]; present && json.Unmarshal(raw, &c.Streams) != nil {
			return message{}, true, malformed
		}
		m.Catalog = c
	case "CONNECTION_STATUS":
		status, ok := objectOf(members["connectionStatus"])
		if !ok {
			return message{}, true, malformed
		}
		cs := &connectionStatus{}
		if cs.Status, ok = status.str("status"); !ok || cs.Status == "" {
			return message{}, true, malformed
		}
		if raw, present := status["message"]; present {
			if cs.Message, ok = status.str("message"); !ok && string(raw) != "null" {
				return message{}, true, malformed
			}
		}
		m.ConnectionStatus = cs
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
	c, err := containers.Start(ctx, containers.Spec{
		Redact: func(text string, truncated bool) string { return redact.Diagnostic(text, truncated, secrets) }, Runtime: cfg.Runtime, Image: cfg.Image, Files: files, Args: append([]string{"read"}, args...)})
	if err != nil {
		return page{}, err
	}
	finish := func(p page, err error) (page, error) {
		if stopErr := c.Stop(); stopErr != nil {
			if err == nil {
				err = stopErr
			} else {
				err = fmt.Errorf("%v; the acquisition had also failed: %v", stopErr, err)
			}
		}
		if err != nil {
			return page{}, errors.New(redact.Redact(err.Error(), secrets))
		}
		return p, err
	}
	var p page
	var size int64
	uncovered := 0 // records since the last checkpoint
	scanner := newScanner(c.Stdout)
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
			if !canon.IsObject(m.Record.Data) {
				return finish(page{}, fmt.Errorf("record %d of stream %q: data is not an object", len(p.items)+1, req.Stream))
			}
			item, err := canon.Canonicalize(m.Record.Data, canon.CarryNumbersAsText)
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
			compacted, err := canon.Compact(m.State)
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
				return finish(page{}, fmt.Errorf("connector reported an error: %s", redact.Redact(traceMessage(m.Trace), secrets)))
			}
		}
	}
	scanErr := scanner.Err()
	waitErr := c.Wait()
	if ctx.Err() != nil {
		return finish(page{}, fmt.Errorf("connector read stopped after %d records: %v", len(p.items), ctx.Err()))
	}
	if scanErr != nil {
		return finish(page{}, fmt.Errorf("reading the connector's records: %w", scanErr))
	}
	if waitErr != nil {
		return finish(page{}, fmt.Errorf("connector read failed: %s", redact.Redact(failure(c, waitErr), secrets)))
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
	sm, ok := objectOf(raw)
	if !ok || len(sm) == 0 {
		return false
	}
	typ := ""
	if _, present := sm["type"]; present {
		if typ, ok = sm.str("type"); !ok {
			return false
		}
	}
	switch typ {
	case "STREAM":
		st, ok := objectOf(sm["stream"])
		if !ok {
			return false
		}
		descriptor, ok := objectOf(st["stream_descriptor"])
		if !ok {
			return false
		}
		name, ok := descriptor.str("name")
		return ok && name != ""
	case "GLOBAL":
		_, ok := objectOf(sm["global"])
		return ok
	case "LEGACY", "":
		_, ok := objectOf(sm["data"])
		return ok
	}
	return false
}

// stateBelongsTo reports whether a state message, already known to be
// valid, bookmarks the stream: a per-stream state names it by name and
// namespace; a global or legacy state covers every stream.
func stateBelongsTo(m message, strm stream) (bool, error) {
	sm, _ := objectOf(m.State)
	if typ, _ := sm.str("type"); typ == "STREAM" {
		st, _ := objectOf(sm["stream"])
		descriptor, _ := objectOf(st["stream_descriptor"])
		name, _ := descriptor.str("name")
		namespace, ok := descriptor.optional("namespace")
		if !ok {
			return false, errors.New("the connector emitted a malformed STATE message")
		}
		return name == strm.Name && sameNamespace(namespace, strm.Namespace), nil
	}
	return true, nil
}

func traceMessage(t *trace) string {
	if t.Error != nil && t.Error.Message != "" {
		return t.Error.Message
	}
	return "no message"
}

// failure names why a connector command failed: the connector's own first
// line of stderr when it wrote one, otherwise the runtime's error.
func failure(c *containers.Container, err error) string {
	if line := c.FirstLine(); line != "" {
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
func buildEnvelope(cfg Config, image containers.Image, req Request, strm stream, mode string, cursor []string, schema []byte, p page) ([]byte, error) {
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
	statement, err := canon.EncodeJSON(statementValue)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(schema)
	schemaDigest := "sha256:" + hex.EncodeToString(sum[:])
	acq := acquisition{
		Adapter:    adapterIdentity{Name: image.Name, Version: image.Version, Digest: image.Digest},
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
	out, err := canon.EncodeJSON(envelope{Acquisition: acq, Result: result, Page: true})
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > cfg.MaxOutput {
		return nil, fmt.Errorf("the envelope exceeds the output bound of %d bytes; lower the limit", cfg.MaxOutput)
	}
	return out, nil
}

func ptr(s string) *string { return &s }
