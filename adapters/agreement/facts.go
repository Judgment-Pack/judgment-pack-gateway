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

	"adapters/internal/canon"
)

// Envelope is what either adapter writes on stdout (SPEC.md §6): the
// acquisition it recorded and the result, whose shape is the adapter's.
type Envelope struct {
	Acquisition struct {
		Adapter struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Digest  string `json:"digest"`
		} `json:"adapter"`
		Statement string `json:"statement"`
	} `json:"acquisition"`
	Result json.RawMessage `json:"result"`
}

// Parse reads an envelope from its bytes.
func Parse(data []byte) (Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return e, fmt.Errorf("envelope: %w", err)
	}
	if e.Acquisition.Adapter.Digest == "" || len(e.Result) == 0 {
		return e, errors.New("envelope: no adapter digest or no result")
	}
	return e, nil
}

// HistoryFacts derives a record's facts from a history-shape envelope: the
// result is the page's records as the connector emitted them (each already
// in the canon domain, numbers past it carried as text); the record is the
// one whose member `key` equals `value`, compared in canonical form, and its
// facts are that record's canonical bytes.
func HistoryFacts(e Envelope, key string, value json.RawMessage) ([]byte, error) {
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
		var members map[string]json.RawMessage
		if err := json.Unmarshal(r, &members); err != nil {
			return nil, fmt.Errorf("a record is not an object: %w", err)
		}
		got, ok := members[key]
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
// DBHub's execute_sql: the result's first text content item holds JSON text
// -- {"success", "data": {"statements": [{"sql", "rows", "count"}], ...}} --
// and the query asked the database to render the row as JSON, so the one
// row's one member `record` is the record as Postgres itself typed it. The
// facts are that object's canonical bytes.
func LiveFacts(e Envelope) ([]byte, error) {
	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(e.Result, &result); err != nil {
		return nil, fmt.Errorf("live result is not a tool result: %w", err)
	}
	if result.IsError || len(result.Content) != 1 || result.Content[0].Type != "text" {
		return nil, errors.New("live result is not one text content item without error")
	}
	var body struct {
		Success bool `json:"success"`
		Data    struct {
			Statements []struct {
				Rows  []map[string]json.RawMessage `json:"rows"`
				Count int                          `json:"count"`
			} `json:"statements"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(result.Content[0].Text), &body); err != nil {
		return nil, fmt.Errorf("live text is not DBHub's JSON: %w", err)
	}
	if !body.Success || len(body.Data.Statements) != 1 || len(body.Data.Statements[0].Rows) != 1 {
		return nil, fmt.Errorf("live answer is not one statement with one row: success=%v statements=%d", body.Success, len(body.Data.Statements))
	}
	record, ok := body.Data.Statements[0].Rows[0]["record"]
	if !ok {
		return nil, errors.New("the row has no `record` member: the query must render the row with to_jsonb")
	}
	if !canon.IsObject(record) {
		return nil, errors.New("`record` is not an object")
	}
	return canon.Canonicalize(record, canon.CarryNumbersAsText)
}

// LiveRowFacts derives facts from a live-shape answer to a plain SELECT --
// the first row as the driver typed it -- for showing why the rule above
// asks the database to render the row: a driver's typing is not the
// database's.
func LiveRowFacts(e Envelope) ([]byte, error) {
	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(e.Result, &result); err != nil || len(result.Content) != 1 {
		return nil, errors.New("live result is not one text content item")
	}
	var body struct {
		Data struct {
			Statements []struct {
				Rows []json.RawMessage `json:"rows"`
			} `json:"statements"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(result.Content[0].Text), &body); err != nil || len(body.Data.Statements) != 1 || len(body.Data.Statements[0].Rows) != 1 {
		return nil, errors.New("live answer is not one statement with one row")
	}
	return canon.Canonicalize(body.Data.Statements[0].Rows[0], canon.CarryNumbersAsText)
}
