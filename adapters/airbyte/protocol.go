package airbyte

import "encoding/json"

// The Airbyte protocol, as much of it as this adapter reads: one JSON object
// per line on the connector's stdout, typed by its "type" member. Lines that
// are not messages are what connectors print when they log to stdout, and
// are skipped.
type message struct {
	Type    string          `json:"type"`
	Record  *record         `json:"record"`
	State   json.RawMessage `json:"state"`
	Catalog *catalog        `json:"catalog"`
	Trace   *trace          `json:"trace"`
}

type record struct {
	Stream    string          `json:"stream"`
	Namespace *string         `json:"namespace"`
	Data      json.RawMessage `json:"data"`
}

type catalog struct {
	Streams []json.RawMessage `json:"streams"`
}

// stream is the part of an AirbyteStream the adapter reads. raw is the
// whole object as the connector gave it, carried into the configured
// catalog untouched.
type stream struct {
	Name               string          `json:"name"`
	Namespace          *string         `json:"namespace"`
	JSONSchema         json.RawMessage `json:"json_schema"`
	SupportedSyncModes []string        `json:"supported_sync_modes"`
	DefaultCursorField []string        `json:"default_cursor_field"`
	raw                json.RawMessage
}

type trace struct {
	Type  string `json:"type"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// stateMessage is the part of an AirbyteStateMessage the adapter reads: to
// attribute a bookmark to a stream, and to write one back for a resume in
// the form the connector expects.
type stateMessage struct {
	Type   string `json:"type"`
	Stream *struct {
		Descriptor struct {
			Name      string  `json:"name"`
			Namespace *string `json:"namespace"`
		} `json:"stream_descriptor"`
	} `json:"stream"`
	Data json.RawMessage `json:"data"`
}

// sameNamespace treats a null or absent namespace and an empty one as
// distinct, as the protocol does.
func sameNamespace(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
