package airbyte

import (
	"bytes"
	"encoding/json"

	"adapters/internal/canon"
)

// The Airbyte protocol, as much of it as this adapter reads: one JSON object
// per line on the connector's stdout, typed by its "type" member. Lines that
// are not messages are what connectors print when they log to stdout, and
// are skipped. A message is read by its members' exact names, with a
// duplicate member refused at any depth (parseMessage): Go's struct
// decoding would let "TYPE" stand in for type, or "STREAM" for stream, and
// a second member overwrite the first, on lines that decide what a record
// belongs to and whether the platform answered.
type message struct {
	Type             string
	Record           *record
	State            json.RawMessage
	Catalog          *catalog
	Trace            *trace
	ConnectionStatus *connectionStatus
}

type record struct {
	Stream    string
	Namespace *string
	Data      json.RawMessage
}

type catalog struct {
	Streams []json.RawMessage
}

// stream is the part of an AirbyteStream the adapter reads. raw is the
// whole object as the connector gave it, carried into the configured
// catalog untouched.
type stream struct {
	Name               string
	Namespace          *string
	JSONSchema         json.RawMessage
	SupportedSyncModes []string
	// DefaultCursorField is the cursor the connector names for the stream;
	// SourceDefinedCursor says the connector manages the cursor itself, in
	// which case it may name none.
	DefaultCursorField  []string
	SourceDefinedCursor bool
	raw                 json.RawMessage
}

type trace struct {
	Type  string
	Error *traceError
}

type traceError struct {
	Message string
}

// connectionStatus is what a connector's check answers: SUCCEEDED or
// FAILED, with a message the connector chose.
type connectionStatus struct {
	Status  string
	Message string
}

// object is a JSON object read by its members' exact names.
type object map[string]json.RawMessage

// startsObject reports whether a line begins, after whitespace, an object.
func startsObject(line []byte) bool {
	trimmed := bytes.TrimLeft(line, " \t\r\n")
	return len(trimmed) > 0 && trimmed[0] == '{'
}

func objectOf(raw json.RawMessage) (object, bool) {
	if !canon.IsObject(raw) {
		return nil, false
	}
	var members object
	if json.Unmarshal(raw, &members) != nil {
		return nil, false
	}
	return members, true
}

// str is the member's value when it is present and a string.
func (o object) str(name string) (string, bool) {
	var s string
	if raw, ok := o[name]; !ok || json.Unmarshal(raw, &s) != nil || string(raw) == "null" {
		return "", false
	}
	return s, true
}

// optional is the member's value when it is a string, nil when it is null
// or absent, and not ok otherwise.
func (o object) optional(name string) (*string, bool) {
	raw, ok := o[name]
	if !ok || string(raw) == "null" {
		return nil, true
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return nil, false
	}
	return &s, true
}

// boolean is the member's value when it is a boolean, false when absent,
// and not ok otherwise.
func (o object) boolean(name string) (bool, bool) {
	raw, ok := o[name]
	if !ok {
		return false, true
	}
	var b bool
	if string(raw) == "null" || json.Unmarshal(raw, &b) != nil {
		return false, false
	}
	return b, true
}

// strings is the member's value when it is an array of strings, nil when
// absent, and not ok otherwise.
func (o object) strings(name string) ([]string, bool) {
	raw, ok := o[name]
	if !ok {
		return nil, true
	}
	var list []string
	if json.Unmarshal(raw, &list) != nil {
		return nil, false
	}
	return list, true
}

// parseStream reads a catalog's stream entry.
func parseStream(raw json.RawMessage) (stream, bool) {
	o, ok := objectOf(raw)
	if !ok {
		return stream{}, false
	}
	s := stream{raw: raw}
	if s.Name, ok = o.str("name"); !ok || s.Name == "" {
		return stream{}, false
	}
	if s.Namespace, ok = o.optional("namespace"); !ok {
		return stream{}, false
	}
	s.JSONSchema = o["json_schema"]
	if s.SupportedSyncModes, ok = o.strings("supported_sync_modes"); !ok {
		return stream{}, false
	}
	if s.DefaultCursorField, ok = o.strings("default_cursor_field"); !ok {
		return stream{}, false
	}
	if s.SourceDefinedCursor, ok = o.boolean("source_defined_cursor"); !ok {
		return stream{}, false
	}
	return s, true
}

// sameNamespace treats a null or absent namespace and an empty one as
// distinct, as the protocol does.
func sameNamespace(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
