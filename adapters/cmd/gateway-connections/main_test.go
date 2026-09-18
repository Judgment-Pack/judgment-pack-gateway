package main

import (
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
