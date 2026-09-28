package main

import (
	"adapters/connections"
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestFailedResponseDoesNotExposePartialResult(t *testing.T) {
	data, err := json.Marshal(response("request", map[string]string{"subject": "private subject", "grant": "private grant"}, errors.New("canceled")))
	if err != nil || strings.Contains(string(data), "private") || strings.Contains(string(data), "result") {
		t.Fatalf("failed response exposed data: %s %v", data, err)
	}
	if string(data) != `{"error":"canceled","id":"request"}` {
		t.Fatalf("wrong envelope: %s", data)
	}
}

func TestControlReplyRefusesOversizeWithoutLeakingPartialResult(t *testing.T) {
	var output bytes.Buffer
	if err := writeResponse(&output, response("request", map[string]string{"private": strings.Repeat("x", connections.ControlLineBytes)}, nil), "request"); err != nil {
		t.Fatal(err)
	}
	if output.Len() > connections.ControlLineBytes || strings.Contains(output.String(), "private") || output.String() != `{"error":"response-too-large","id":"request"}`+"\n" {
		t.Fatal("oversize response leaked", output.Len())
	}
	output.Reset()
	if err := writeResponse(&output, response("request", map[string]bool{"disconnected": true, "revoked": false}, nil), "request"); err != nil || !strings.Contains(output.String(), `"revoked":false`) {
		t.Fatal("valid response lost", err)
	}
}

func TestStorageMetadataPageAllowsEscapedLongKeysOnlyForList(t *testing.T) {
	items := make([]connections.StorageFile, 24)
	for i := range items {
		items[i] = connections.StorageFile{ID: strings.Repeat("&", 1024), Name: strings.Repeat("&", 1024), Kind: "file"}
	}
	result := response("request", connections.StoragePage{Items: items}, nil)
	var output bytes.Buffer
	if err := writeResponseLimit(&output, result, "request", "files-list"); err != nil {
		t.Fatal(err)
	}
	if output.Len() <= connections.ControlLineBytes || output.Len() > connections.StorageMetadataBytes || strings.Contains(output.String(), "response-too-large") {
		t.Fatal("legal metadata page refused", output.Len())
	}
	output.Reset()
	if err := writeResponseLimit(&output, result, "request", "files-status"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "response-too-large") {
		t.Fatal("ordinary bound relaxed")
	}
}
