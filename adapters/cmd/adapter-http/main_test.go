package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunUsage(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--endpoint", "https://api.example"},
		{"--paths", "/search"},
		{"--endpoint", "https://api.example", "--paths", "/search", "positional"},
		{"--endpoint", "https://api.example", "--paths", "/search", "--unknown"},
		{"--endpoint", "https://api.example", "--paths", "/search", "--check-path", "/x"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, strings.NewReader(`{"path":"/search"}`), &stdout, &stderr); code != 2 || stdout.Len() != 0 {
			t.Errorf("%v: exit %d, want 2 with nothing on stdout (%s)", args, code, stderr.String())
		}
	}
}

func TestRunEndToEnd(t *testing.T) {
	var bodies [][]byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, body)
		if r.Header.Get("Authorization") != "Bearer secret-token-value" || r.Header.Get("Accept") != "application/json" || r.Header.Get("X-Return-Format") != "text, plain" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"e1"`)
		io.WriteString(w, `{"data":{"title":"Policy","content":"text"}}`)
	}))
	defer server.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	credentials := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(credentials, []byte(`{"TOKEN":"secret-token-value"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// Every flag one word, as the gateway splits a source on whitespace;
	// a header may be repeated, and its value may carry a comma.
	args := []string{"--endpoint", server.URL, "--paths", "/,/search", "--credentials", credentials, "--bearer", "TOKEN",
		"--header", "Accept=application/json", "--header", "X-Return-Format=text, plain", "--ca-file", ca}
	var stdout, stderr bytes.Buffer
	if code := run(args, strings.NewReader(`{"path":"/","body":{"url":"https://example.org/policy"}}`), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	out := stdout.String()
	sum := sha256.Sum256(server.Certificate().Raw)
	if !strings.HasPrefix(out, `{"acquisition":{"adapter":{"name":"adapter-http","version":"`) ||
		!strings.Contains(out, `"endpoint":"`+server.URL+`/"`) || !strings.Contains(out, `"snapshot":"\"e1\""`) ||
		!strings.Contains(out, `"peerIdentity":"tls:sha256:`+hex.EncodeToString(sum[:])+`"`) ||
		!strings.Contains(out, `"bodyEncoding":"json","body":{"data":{"content":"text","title":"Policy"}}}`) ||
		strings.Contains(out, `"page"`) || strings.Contains(out, "secret-token") {
		t.Fatalf("envelope: %s", out)
	}
	if string(bodies[0]) != `{"url":"https://example.org/policy"}` {
		t.Fatalf("the body reaches the endpoint: %s", bodies[0])
	}
	stdout.Reset()
	if code := run(args, strings.NewReader(`{"path":"/extract","body":{}}`), &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "is not one this source may request") {
		t.Fatalf("a failed acquisition exits 1 with the reason on stderr: %d %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatal("nothing is written on stdout for a failed acquisition")
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(args, strings.NewReader(`not a request`), &stdout, &stderr); code != 1 || stdout.Len() != 0 {
		t.Fatalf("a malformed request exits 1 with nothing on stdout: %d %s", code, stderr.String())
	}
}

func TestRunCheck(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			io.WriteString(w, "ok")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	// stdin is not read by a check: what is attached is the operator's.
	stdin := strings.NewReader("not a request")
	var stdout, stderr bytes.Buffer
	args := []string{"--endpoint", server.URL, "--paths", "/search", "--ca-file", ca, "--check", "--check-path", "/health"}
	if code := run(args, stdin, &stdout, &stderr); code != 0 || !strings.HasPrefix(stdout.String(), `{"check":{"status":"succeeded","adapter":{"name":"adapter-http"`) || !strings.Contains(stdout.String(), `"probe":{"path":"/health","status":200}`) {
		t.Fatalf("check: %d %s %s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	args[len(args)-1] = "/missing"
	if code := run(args, stdin, &stdout, &stderr); code != 1 || !strings.HasPrefix(stdout.String(), `{"check":{"message":"`) || !strings.Contains(stdout.String(), `"status":"failed"`) {
		t.Fatalf("a failed check writes a report of the same shape beside exit 1: %d %s", code, stdout.String())
	}
}
