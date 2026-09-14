// Package agreement is the both-paths agreement ADR-0001 promises: one
// record of one platform, fetched through the history shape and through the
// live shape, must derive to byte-identical canonical facts. It holds the
// rule by which each shape's envelope yields a record's facts, and the test
// beside it holds the golden record of each shipped platform to the rule --
// over fixtures the adapters captured, and, where a container runtime is at
// hand, over a fresh fetch (docs/design/both-paths-agreement.md).
package agreement

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

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

var observedAtForm = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)

// Parse reads an envelope from its bytes, holding it to §6's member set:
// exactly acquisition and result, page when present true; an acquisition
// of exactly the eight members, each of its type; an adapter of exactly
// name, version and digest. A duplicate member anywhere refuses it.
func Parse(data []byte) (Envelope, error) {
	if _, err := canon.Canonicalize(data, canon.CarryNumbersAsText); err != nil {
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
		e.Page = true
		var items []json.RawMessage
		if json.Unmarshal(top["result"], &items) != nil {
			return Envelope{}, errors.New("envelope: page is true and result is not an array")
		}
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
		if err := json.Unmarshal(adapter[name], into); err != nil || *into == "" {
			return Envelope{}, fmt.Errorf("adapter: %s is not a non-empty string", name)
		}
	}
	if !canon.IsDigestString(e.Acquisition.Adapter.Digest) {
		return Envelope{}, errors.New("adapter: digest is not sha256:<64 hex>")
	}
	for name, into := range map[string]**string{"endpoint": &e.Acquisition.Endpoint, "statement": &e.Acquisition.Statement, "snapshot": &e.Acquisition.Snapshot, "peerIdentity": &e.Acquisition.PeerIdentity, "schema": &e.Acquisition.Schema, "upstreamToken": &e.Acquisition.UpstreamToken} {
		if string(acq[name]) == "null" {
			continue
		}
		var s string
		if err := json.Unmarshal(acq[name], &s); err != nil {
			return Envelope{}, fmt.Errorf("acquisition: %s is neither null nor a string", name)
		}
		*into = &s
	}
	if json.Unmarshal(acq["observedAt"], &e.Acquisition.ObservedAt) != nil || !observedAtForm.MatchString(e.Acquisition.ObservedAt) {
		return Envelope{}, errors.New("acquisition: observedAt is not of the form YYYY-MM-DDThh:mm:ssZ")
	}
	return e, nil
}

// members reads an object by its members' exact names: every required one
// present, no member outside required and optional. Case is not folded and
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
	for name := range m {
		known := false
		for _, allowed := range append(append([]string(nil), required...), optional...) {
			if name == allowed {
				known = true
			}
		}
		if !known {
			return nil, fmt.Errorf("unexpected member %q", name)
		}
	}
	return m, nil
}

// HistoryFacts derives a record's facts from a history-shape envelope: the
// result is the page's records as the connector emitted them (each already
// in the canon domain, numbers past it carried as text); the record is the
// one whose member `key` equals `value`, compared in canonical form, and its
// facts are that record's canonical bytes.
func HistoryFacts(e Envelope, key string, value json.RawMessage) ([]byte, error) {
	if !e.Page {
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
		var record map[string]json.RawMessage
		if err := json.Unmarshal(r, &record); err != nil || record == nil {
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
// "<json>"}], "count": 1}], "source_id"}}, and the facts are the canonical
// bytes of the object that text holds. Every object on the way is read by
// its members' exact names, nothing unknown tolerated, a duplicate refused.
func LiveFacts(e Envelope) ([]byte, error) {
	row, err := liveRow(e)
	if err != nil {
		return nil, err
	}
	if _, err := members(row, []string{"record"}, nil); err != nil {
		return nil, fmt.Errorf("the row is not exactly one member `record`: %w; the query must render the row with to_jsonb(...)::text", err)
	}
	var text string
	if err := json.Unmarshal(mustMember(row, "record"), &text); err != nil {
		return nil, errors.New("`record` is not text: the query must hand the rendered row over as text, to_jsonb(...)::text")
	}
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
// an error result, an answer that is not success, and any shape other than
// one statement with one row and a count of one.
func liveRow(e Envelope) (json.RawMessage, error) {
	result, err := members(e.Result, []string{"content"}, []string{"isError", "structuredContent", "_meta"})
	if err != nil {
		return nil, fmt.Errorf("live result is not a tool result: %w", err)
	}
	if raw, ok := result["isError"]; ok && string(raw) != "false" {
		return nil, errors.New("live result reports an error")
	}
	var content []json.RawMessage
	if json.Unmarshal(result["content"], &content) != nil || len(content) != 1 {
		return nil, errors.New("live result is not one content item")
	}
	item, err := members(content[0], []string{"type", "text"}, []string{"annotations", "_meta"})
	if err != nil {
		return nil, fmt.Errorf("live content item: %w", err)
	}
	var text string
	if string(item["type"]) != `"text"` || json.Unmarshal(item["text"], &text) != nil {
		return nil, errors.New("live content item is not text")
	}
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
	data, err := members(body["data"], []string{"statements", "source_id"}, nil)
	if err != nil {
		return nil, fmt.Errorf("live answer's data: %w", err)
	}
	var statements []json.RawMessage
	if json.Unmarshal(data["statements"], &statements) != nil || len(statements) != 1 {
		return nil, errors.New("live answer is not one statement")
	}
	statement, err := members(statements[0], []string{"sql", "rows", "count"}, nil)
	if err != nil {
		return nil, fmt.Errorf("live answer's statement: %w", err)
	}
	var rows []json.RawMessage
	if json.Unmarshal(statement["rows"], &rows) != nil || len(rows) != 1 || string(statement["count"]) != "1" {
		return nil, errors.New("live answer is not one row with a count of one")
	}
	if !canon.IsObject(rows[0]) {
		return nil, errors.New("the row is not an object")
	}
	return rows[0], nil
}

func mustMember(raw json.RawMessage, name string) json.RawMessage {
	var m map[string]json.RawMessage
	_ = json.Unmarshal(raw, &m)
	return m[name]
}
