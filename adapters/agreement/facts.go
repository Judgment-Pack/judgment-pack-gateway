// Package agreement is the both-paths agreement ADR-0001 promises: one
// record of one platform, fetched through the history shape and through the
// live shape, must derive to byte-identical canonical facts. It holds the
// rule by which each shape's envelope yields a record's facts, and the test
// beside it holds the golden records of each shipped platform to the rule --
// over fixtures the adapters captured, and, where a container runtime is at
// hand, over a fresh fetch (docs/design/both-paths-agreement.md).
package agreement

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"adapters/internal/canon"
)

// Acquisition is what an adapter recorded about the fetch, the members
// SPEC.md §6 requires of an envelope and no other.
type Acquisition struct {
	Adapter struct {
		Name    string
		Version string
		Digest  string
	}
	Endpoint      *string
	Statement     *string
	Snapshot      *string
	PeerIdentity  *string
	Schema        *string
	UpstreamToken *string
	ObservedAt    string
}

// Envelope is what either adapter writes on stdout (SPEC.md §6): the
// acquisition it recorded, the result, whose shape is the adapter's, and
// whether the result is a page of items.
type Envelope struct {
	Acquisition Acquisition
	Result      json.RawMessage
	Page        bool
}

const observedAtLayout = "2006-01-02T15:04:05Z"

// Parse reads an envelope from its bytes as the signer would: in the canon
// domain, no duplicate member anywhere, and held to §6's member set --
// exactly acquisition and result, page when present true and the result
// then an array; an acquisition of exactly the eight members, each of its
// type and form; an adapter of exactly name, version and digest.
func Parse(data []byte) (Envelope, error) {
	if _, err := canon.Canonicalize(data, canon.RefuseNumbers); err != nil {
		return Envelope{}, fmt.Errorf("envelope: %w", err)
	}
	top, err := members(data, []string{"acquisition", "result"}, []string{"page"})
	if err != nil {
		return Envelope{}, fmt.Errorf("envelope: %w", err)
	}
	var e Envelope
	if raw, ok := top["page"]; ok {
		if string(raw) != "true" {
			return Envelope{}, errors.New("envelope: page is present and not true")
		}
		if !isArray(top["result"]) {
			return Envelope{}, errors.New("envelope: page is true and result is not an array")
		}
		e.Page = true
	}
	e.Result = top["result"]
	acq, err := members(top["acquisition"], []string{"adapter", "endpoint", "statement", "snapshot", "peerIdentity", "schema", "upstreamToken", "observedAt"}, nil)
	if err != nil {
		return Envelope{}, fmt.Errorf("acquisition: %w", err)
	}
	adapter, err := members(acq["adapter"], []string{"name", "version", "digest"}, nil)
	if err != nil {
		return Envelope{}, fmt.Errorf("adapter: %w", err)
	}
	for name, into := range map[string]*string{"name": &e.Acquisition.Adapter.Name, "version": &e.Acquisition.Adapter.Version, "digest": &e.Acquisition.Adapter.Digest} {
		if !isString(adapter[name]) {
			return Envelope{}, fmt.Errorf("adapter: %s is not a string", name)
		}
		_ = json.Unmarshal(adapter[name], into)
	}
	if !canon.IsDigestString(e.Acquisition.Adapter.Digest) {
		return Envelope{}, errors.New("adapter: digest is not sha256:<64 hex>")
	}
	for name, into := range map[string]**string{"endpoint": &e.Acquisition.Endpoint, "statement": &e.Acquisition.Statement, "snapshot": &e.Acquisition.Snapshot, "peerIdentity": &e.Acquisition.PeerIdentity, "schema": &e.Acquisition.Schema, "upstreamToken": &e.Acquisition.UpstreamToken} {
		if string(acq[name]) == "null" {
			continue
		}
		if !isString(acq[name]) {
			return Envelope{}, fmt.Errorf("acquisition: %s is neither null nor a string", name)
		}
		var s string
		_ = json.Unmarshal(acq[name], &s)
		*into = &s
	}
	if e.Acquisition.Schema != nil && !canon.IsDigestString(*e.Acquisition.Schema) {
		return Envelope{}, errors.New("acquisition: schema is neither null nor sha256:<64 hex>")
	}
	if !isString(acq["observedAt"]) {
		return Envelope{}, errors.New("acquisition: observedAt is not a string")
	}
	_ = json.Unmarshal(acq["observedAt"], &e.Acquisition.ObservedAt)
	if _, err := time.Parse(observedAtLayout, e.Acquisition.ObservedAt); err != nil {
		return Envelope{}, errors.New("acquisition: observedAt is not of the form YYYY-MM-DDThh:mm:ssZ")
	}
	return e, nil
}

// Statement reads the statement an adapter recorded as the object it
// encodes, refusing a duplicate member: it is a JSON text inside a string,
// which the envelope's own check does not look into. A resumed read's
// state may carry a number past the canon domain, so the check carries
// numbers as text and judges nothing else about them.
func Statement(e Envelope) (map[string]json.RawMessage, error) {
	if e.Acquisition.Statement == nil {
		return nil, errors.New("no statement recorded")
	}
	raw := []byte(*e.Acquisition.Statement)
	if _, err := canon.Canonicalize(raw, canon.CarryNumbersAsText); err != nil {
		return nil, fmt.Errorf("statement: %w", err)
	}
	m, err := members(raw, nil, nil)
	if err != nil && !errors.Is(err, errUnknownMember) {
		return nil, fmt.Errorf("statement: %w", err)
	}
	return m, nil
}

var errUnknownMember = errors.New("unexpected member")

// members reads an object by its members' exact names: every required one
// present, no member outside required and optional unless both lists are
// nil, in which case the object is returned whole. Case is not folded and
// nothing unknown is tolerated, the signer's rule for what it did not ask
// for; the caller has already refused duplicates through the canonicalizer.
func members(raw json.RawMessage, required, optional []string) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, errors.New("not an object")
	}
	for _, name := range required {
		if _, ok := m[name]; !ok {
			return nil, fmt.Errorf("no member %q", name)
		}
	}
	if required == nil && optional == nil {
		return m, nil
	}
	for name := range m {
		known := false
		for _, allowed := range append(append([]string(nil), required...), optional...) {
			if name == allowed {
				known = true
			}
		}
		if !known {
			return nil, fmt.Errorf("%w %q", errUnknownMember, name)
		}
	}
	return m, nil
}

// isString reports whether raw is a JSON string, isArray a JSON array.
func isString(raw json.RawMessage) bool {
	t := bytes.TrimLeft(raw, " \t\r\n")
	return len(t) > 0 && t[0] == '"' && json.Valid(raw)
}

func isArray(raw json.RawMessage) bool {
	t := bytes.TrimLeft(raw, " \t\r\n")
	return len(t) > 0 && t[0] == '[' && json.Valid(raw)
}

// isStrings reports whether raw is a JSON array of strings.
func isStrings(raw json.RawMessage) bool {
	var items []json.RawMessage
	if !isArray(raw) || json.Unmarshal(raw, &items) != nil {
		return false
	}
	for _, item := range items {
		if !isString(item) {
			return false
		}
	}
	return true
}

// HistoryFacts derives a record's facts from a history-shape envelope: the
// result is the page's records as the connector emitted them (each already
// in the canon domain, numbers past it carried as text); the record is the
// one whose member `key` equals `value`, compared in canonical form, and its
// facts are that record's canonical bytes.
func HistoryFacts(e Envelope, key string, value json.RawMessage) ([]byte, error) {
	if _, err := canon.Canonicalize(e.Result, canon.RefuseNumbers); err != nil {
		return nil, fmt.Errorf("history result: %w", err)
	}
	if !e.Page || !isArray(e.Result) {
		return nil, errors.New("history result is not a page")
	}
	var records []json.RawMessage
	if err := json.Unmarshal(e.Result, &records); err != nil {
		return nil, fmt.Errorf("history result is not a page of records: %w", err)
	}
	want, err := canon.Canonicalize(value, canon.CarryNumbersAsText)
	if err != nil {
		return nil, fmt.Errorf("key value: %w", err)
	}
	var found []byte
	for _, r := range records {
		record, err := members(r, nil, nil)
		if err != nil {
			return nil, errors.New("a record is not an object")
		}
		got, ok := record[key]
		if !ok {
			continue
		}
		c, err := canon.Canonicalize(got, canon.CarryNumbersAsText)
		if err != nil {
			return nil, fmt.Errorf("record member %s: %w", key, err)
		}
		if string(c) != string(want) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("more than one record has %s = %s", key, want)
		}
		if found, err = canon.Canonicalize(r, canon.CarryNumbersAsText); err != nil {
			return nil, fmt.Errorf("record: %w", err)
		}
	}
	if found == nil {
		return nil, fmt.Errorf("no record has %s = %s among %d", key, want, len(records))
	}
	return found, nil
}

// LiveFacts derives a record's facts from a live-shape envelope answered by
// DBHub's execute_sql. The query asked the database to render the row as
// JSON and to hand it over as text -- SELECT to_jsonb(c)::text AS record --
// so the row reaches the adapter spelled as Postgres spelled it and no
// driver types it on the way; the answer is one text content item holding
// {"success": true, "data": {"statements": [{"sql", "rows": [{"record":
// "<json>"}], "count": 1}], "source_id", "messages"?}}, the echoed sql is
// the one the statement records, and the facts are the canonical bytes of
// the object the text holds. Every object on the way is read by its
// members' exact names, each of its type, nothing unknown tolerated, a
// duplicate refused.
func LiveFacts(e Envelope) ([]byte, error) {
	row, err := liveRow(e)
	if err != nil {
		return nil, err
	}
	m, err := members(row, []string{"record"}, nil)
	if err != nil {
		return nil, fmt.Errorf("the row is not exactly one member `record`: %w; the query must render the row with to_jsonb(...)::text", err)
	}
	if !isString(m["record"]) {
		return nil, errors.New("`record` is not text: the query must hand the rendered row over as text, to_jsonb(...)::text")
	}
	var text string
	_ = json.Unmarshal(m["record"], &text)
	if !canon.IsObject(json.RawMessage(text)) {
		return nil, errors.New("`record` does not hold a JSON object")
	}
	return canon.Canonicalize([]byte(text), canon.CarryNumbersAsText)
}

// LiveRowFacts derives facts from a live-shape answer as the driver typed
// the row: the one row's canonical bytes, whatever its members. It is the
// derivation the rule does not use, kept for showing why: a driver's
// typing is not the database's (a plain SELECT hands bigint back as
// strings; a jsonb column is parsed as a JavaScript number and an integer
// past 2^53 is rounded on the way).
func LiveRowFacts(e Envelope) ([]byte, error) {
	row, err := liveRow(e)
	if err != nil {
		return nil, err
	}
	return canon.Canonicalize(row, canon.CarryNumbersAsText)
}

// liveRow reads a DBHub execute_sql answer down to its one row, refusing
// an error result, an answer that is not success, an answer to other SQL
// than the statement records, and any shape other than one statement with
// one row and a count of one. The result is held to the canon domain and
// to no duplicate member first, as Parse holds the envelope, so an
// envelope built by hand is held to the same.
func liveRow(e Envelope) (json.RawMessage, error) {
	if _, err := canon.Canonicalize(e.Result, canon.RefuseNumbers); err != nil {
		return nil, fmt.Errorf("live result: %w", err)
	}
	result, err := members(e.Result, []string{"content"}, []string{"isError", "structuredContent", "_meta"})
	if err != nil {
		return nil, fmt.Errorf("live result is not a tool result: %w", err)
	}
	switch raw, ok := result["isError"]; {
	case ok && string(raw) == "true":
		return nil, errors.New("live result reports an error")
	case ok && string(raw) != "false":
		return nil, errors.New("live result's isError is not a boolean")
	}
	for _, name := range []string{"structuredContent", "_meta"} {
		if raw, ok := result[name]; ok && !canon.IsObject(raw) {
			return nil, fmt.Errorf("live result's %s is not an object", name)
		}
	}
	var content []json.RawMessage
	if !isArray(result["content"]) || json.Unmarshal(result["content"], &content) != nil || len(content) != 1 {
		return nil, errors.New("live result is not one content item")
	}
	item, err := members(content[0], []string{"type", "text"}, []string{"annotations", "_meta"})
	if err != nil {
		return nil, fmt.Errorf("live content item: %w", err)
	}
	for _, name := range []string{"annotations", "_meta"} {
		if raw, ok := item[name]; ok && !canon.IsObject(raw) {
			return nil, fmt.Errorf("live content item's %s is not an object", name)
		}
	}
	if string(item["type"]) != `"text"` || !isString(item["text"]) {
		return nil, errors.New("live content item is not text")
	}
	var text string
	_ = json.Unmarshal(item["text"], &text)
	if _, err := canon.Canonicalize([]byte(text), canon.CarryNumbersAsText); err != nil {
		return nil, fmt.Errorf("live text is not well-formed JSON: %w", err)
	}
	body, err := members(json.RawMessage(text), []string{"success", "data"}, nil)
	if err != nil {
		return nil, fmt.Errorf("live text is not DBHub's answer: %w", err)
	}
	if string(body["success"]) != "true" {
		return nil, errors.New("live answer is not a success")
	}
	data, err := members(body["data"], []string{"statements", "source_id"}, []string{"messages"})
	if err != nil {
		return nil, fmt.Errorf("live answer's data: %w", err)
	}
	if !isString(data["source_id"]) {
		return nil, errors.New("live answer's source_id is not a string")
	}
	if raw, ok := data["messages"]; ok && !isStrings(raw) {
		return nil, errors.New("live answer's messages is not an array of strings")
	}
	var statements []json.RawMessage
	if !isArray(data["statements"]) || json.Unmarshal(data["statements"], &statements) != nil || len(statements) != 1 {
		return nil, errors.New("live answer is not one statement")
	}
	statement, err := members(statements[0], []string{"sql", "rows", "count"}, nil)
	if err != nil {
		return nil, fmt.Errorf("live answer's statement: %w", err)
	}
	if !isString(statement["sql"]) {
		return nil, errors.New("live answer's sql is not a string")
	}
	recorded, err := Statement(e)
	if err != nil {
		return nil, err
	}
	args, err := members(recorded["arguments"], []string{"sql"}, nil)
	if err != nil || string(recorded["tool"]) != `"execute_sql"` || len(recorded) != 2 {
		return nil, errors.New("the statement is not an execute_sql call of one sql argument")
	}
	if string(args["sql"]) != string(statement["sql"]) {
		return nil, errors.New("the answer echoes other SQL than the statement records")
	}
	var rows []json.RawMessage
	if !isArray(statement["rows"]) || json.Unmarshal(statement["rows"], &rows) != nil || len(rows) != 1 || string(statement["count"]) != "1" {
		return nil, errors.New("live answer is not one row with a count of one")
	}
	if !canon.IsObject(rows[0]) {
		return nil, errors.New("the row is not an object")
	}
	return rows[0], nil
}
