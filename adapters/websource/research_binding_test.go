package websource

import (
	"adapters/attachment"
	"adapters/document"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"testing"
)

func TestPageBindingDescribesTheActualAcquisitionIdentity(t *testing.T) {
	// An identity hardcoded to the build's default version must fail this test.
	// This package's tests do not run in parallel.
	old := document.Version
	document.Version = "page-binding-test"
	t.Cleanup(func() { document.Version = old })
	raw, err := DescribeResearchBinding()
	if err != nil || len(raw) > 16<<10 {
		t.Fatal("page binding unavailable or oversized", err)
	}
	var d PageBindingDescriptor
	if json.Unmarshal(raw, &d) != nil || d.Version != 1 || d.Shape != "http" ||
		d.Adapter.Name != "adapter-web" || d.Adapter.Version != document.Version ||
		d.Endpoint != nil || len(d.FixedArguments) != 0 || d.ResultRecord != "attachment-v1" ||
		len(d.Research.Capabilities) != 1 || d.Research.Capabilities[0] != "page" {
		t.Fatal("description changed the page contract", string(raw))
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	closeErr := f.Close()
	if err != nil || closeErr != nil || d.Adapter.Digest != "sha256:"+hex.EncodeToString(h.Sum(nil)) {
		t.Fatal("description does not name this executable", err, closeErr)
	}
	again, err := DescribeResearchBinding()
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("read-only description changed", err)
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(raw, &members) != nil || len(members) != 8 || string(members["endpoint"]) != "null" || string(members["fixedArguments"]) != "{}" {
		t.Fatal("description added authority or omitted its explicit empty members")
	}
	reader := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "Retained public page.")
	})
	result, err := read(context.Background(), []byte(`{"url":"https://example.com/page?view=1"}`), reader)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Acquisition struct {
			Adapter attachment.Identity
		}
	}
	if json.Unmarshal(result, &envelope) != nil || envelope.Acquisition.Adapter != d.Adapter {
		t.Fatal("description and acquisition report different identities")
	}
}

func TestPageBindingRequestShapeKeepsOperatorControlsClosed(t *testing.T) {
	raw, err := DescribeResearchBinding()
	if err != nil {
		t.Fatal(err)
	}
	var d PageBindingDescriptor
	var schema struct {
		Type                 string
		AdditionalProperties bool
		Required             []string
		Properties           map[string]struct {
			Type      string
			MinLength int
			MaxLength int
		}
	}
	if json.Unmarshal(raw, &d) != nil || json.Unmarshal(d.RequestSchema, &schema) != nil ||
		schema.Type != "object" || schema.AdditionalProperties || len(schema.Required) != 1 ||
		schema.Required[0] != "url" || len(schema.Properties) != 2 {
		t.Fatal("page request shape is not closed")
	}
	for _, name := range []string{"url", "site"} {
		p, ok := schema.Properties[name]
		if !ok || p.Type != "string" || p.MinLength != 1 || p.MaxLength != 4096 {
			t.Fatal("page argument shape changed", name)
		}
	}
	for _, request := range []string{
		`{}`, `{"url":""}`, `{"url":42}`,
		`{"url":"https://example.com","site":""}`,
		`{"url":"https://example.com","headers":{}}`,
		`{"url":"https://example.com","redirectPolicies":["any-origin"]}`,
		`{"URL":"https://example.com"}`,
	} {
		// A malformed argument set must stop before network setup or acquisition.
		if _, err := read(context.Background(), []byte(request), fetcher{}); !errors.Is(err, ErrRequest) {
			t.Errorf("%s: %v", request, err)
		}
	}
}
