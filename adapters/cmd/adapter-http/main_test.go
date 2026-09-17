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
	"time"

	"adapters/internal/redact"
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
	// stdin is not read by a check: what is attached is the operator's, and
	// a reader that fails the test on any read is what holds that.
	stdin := neverRead{t}
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

// neverRead fails the test on any read.
type neverRead struct{ t *testing.T }

func (n neverRead) Read([]byte) (int, error) {
	n.t.Fatal("a check read stdin")
	return 0, io.EOF
}

func TestRunRedactsAndBoundsEveryDiagnostic(t *testing.T) {
	dir := t.TempDir()
	credentials := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(credentials, []byte(`{"TOKEN":"secret-token-value"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--endpoint", "https://api.example", "--paths", "/search", "--credentials", credentials, "--bearer", "TOKEN"}
	var stdout, stderr bytes.Buffer
	// A request naming a member after the credential: refused before the
	// acquisition is prepared, and the refusal does not repeat it.
	if code := run(args, strings.NewReader(`{"path":"/search","secret-token-value":0}`), &stdout, &stderr); code != 1 ||
		strings.Contains(stderr.String(), "secret-token-value") || !strings.Contains(stderr.String(), "[redacted]") {
		t.Fatalf("%d %s", code, stderr.String())
	}
	stderr.Reset()
	// A refusal of unbounded length is cut.
	long := strings.Repeat("m", 60000)
	if code := run(args, strings.NewReader(`{"path":"/search","`+long+`":0}`), &stdout, &stderr); code != 1 || stderr.Len() > 1024 {
		t.Fatalf("%d: %d bytes of diagnostic", code, stderr.Len())
	}
	stderr.Reset()
	// A configuration refused for a path that carries the credential, and a
	// check that reports the same refusal: neither repeats it.
	args = append(args, "--ca-file", filepath.Join(dir, "secret-token-value.pem"), "--check")
	if code := run(args, neverRead{t}, &stdout, &stderr); code != 1 ||
		strings.Contains(stderr.String(), "secret-token-value") || strings.Contains(stdout.String(), "secret-token-value") ||
		!strings.HasPrefix(stdout.String(), `{"check":{"message":"`) {
		t.Fatalf("%d %s %s", code, stderr.String(), stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	// A flag the command does not know: the quotation of the operator's own
	// command line is bounded, and the listing of the command's flags, which
	// quotes nothing of that line, follows it whole -- so the guidance a flag
	// carries can be read from the command that carries it.
	if code := run([]string{"--endpoint", "https://api.example", "--paths", "/", "--" + strings.Repeat("z", 5000)}, neverRead{t}, &stdout, &stderr); code != 2 ||
		strings.Contains(stderr.String(), strings.Repeat("z", redact.MaxDiagnostic+1)) ||
		!strings.Contains(stderr.String(), "-timeout duration") {
		t.Fatalf("%d: %d bytes of diagnostic: %s", code, stderr.Len(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	// And the usage an operator asks for reaches the flags past the bound
	// the diagnostic is held to, the timeout's guidance among them, which is
	// what the gateway's source timeout has to be kept under.
	if code := run([]string{"-h"}, neverRead{t}, &stdout, &stderr); code != 2 || stdout.Len() != 0 ||
		!strings.Contains(stderr.String(), "-timeout duration") || !strings.Contains(stderr.String(), "--source-timeout") {
		t.Fatalf("-h: %d %s", code, stderr.String())
	}
}

func TestRunHoldsItsOwnTimeout(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	}))
	defer server.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	started := time.Now()
	code := run([]string{"--endpoint", server.URL, "--paths", "/", "--ca-file", ca, "--timeout", "200ms"}, strings.NewReader(`{"path":"/","body":{}}`), &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "did not answer in time") || time.Since(started) > 2*time.Second {
		t.Fatalf("%d %s after %v", code, stderr.String(), time.Since(started))
	}
}
