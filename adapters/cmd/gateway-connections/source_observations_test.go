package main

import (
	"adapters/connections"
	"adapters/internal/canon"
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSourceObservationLineBoundIsExactAndExclusive(t *testing.T) {
	if connections.SourceObservationLineBytes != (16<<20)+(64<<10) || requestBound("source-observe") != connections.ControlLineBytes {
		t.Fatal("observation bounds changed")
	}
	base := response("observe", map[string]string{"document": ""}, nil)
	short, _ := json.Marshal(base)
	length := connections.SourceObservationLineBytes - len(short) - 1
	result := response("observe", map[string]string{"document": strings.Repeat("x", length)}, nil)
	var output bytes.Buffer
	if err := writeResponseLimit(&output, result, "observe", "source-observe"); err != nil || output.Len() != connections.SourceObservationLineBytes || bytes.Count(output.Bytes(), []byte{'\n'}) != 1 {
		t.Fatal("exact-bound line refused or split", output.Len(), err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(output.Bytes()))
	scanner.Buffer(make([]byte, 4096), connections.SourceObservationLineBytes+3)
	if !scanner.Scan() || !json.Valid(scanner.Bytes()) || scanner.Scan() || scanner.Err() != nil {
		t.Fatal("reply did not form one complete JSON line", scanner.Err())
	}
	output.Reset()
	oversize := response("observe", map[string]string{"document": strings.Repeat("x", length+1)}, nil)
	if err := writeResponseLimit(&output, oversize, "observe", "source-observe"); err != nil || output.String() != `{"error":"response-too-large","id":"observe"}`+"\n" {
		t.Fatal("oversize artifact leaked or was truncated", output.Len(), err)
	}
	for _, method := range []string{"source-bind", "source-bindings", "source-revoke", "status", "files-read"} {
		output.Reset()
		if err := writeResponseLimit(&output, result, "observe", method); err != nil || output.String() != `{"error":"response-too-large","id":"observe"}`+"\n" {
			t.Fatal("another method acquired the observation bound", method, output.Len(), err)
		}
	}
}

func TestSourceObservationPipePreservesCanonicalArtifactBytes(t *testing.T) {
	document, err := canon.EncodeJSON(map[string]any{"text": "<policy>&\u2028\u2029\nnext", "size": 12})
	if err == nil {
		document, err = canon.Canonicalize(document, canon.RefuseNumbers)
	}
	if err != nil {
		t.Fatal(err)
	}
	result := response("observe", map[string]any{"document": json.RawMessage(document)}, nil)
	var output bytes.Buffer
	if err := writeResponseLimit(&output, result, "observe", "source-observe"); err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Result struct {
			Document json.RawMessage `json:"document"`
		} `json:"result"`
	}
	if err := json.Unmarshal(output.Bytes(), &parsed); err != nil || !bytes.Equal(parsed.Result.Document, document) {
		t.Fatal("wire re-escaped extraction artifact", output.String(), err)
	}
}
