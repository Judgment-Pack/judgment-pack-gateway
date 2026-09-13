package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"adapters/internal/fakemcp"
)

func TestMain(m *testing.M) {
	if os.Getenv(fakemcp.EnvActivate) == "1" {
		os.Exit(fakemcp.Run(os.Args[1:]))
	}
	os.Exit(m.Run())
}

const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestRunUsage(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--image", "x@" + digest, "--", "y"},
		{"--unknown", "--", "y"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, strings.NewReader(`{"tool":"query"}`), &stdout, &stderr); code != 2 || stdout.Len() != 0 {
			t.Errorf("%v: exit %d, want 2 with nothing on stdout (%s)", args, code, stderr.String())
		}
	}
}

func TestRunEndToEnd(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(fakemcp.EnvActivate, "1")
	t.Setenv(fakemcp.EnvTrace, filepath.Join(dir, "trace.jsonl"))
	credentials := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(credentials, []byte(`{"TOKEN":"secret-token"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// The server command comes after --, word by word, since the gateway
	// splits a source on whitespace and parses no quotes.
	args := []string{"--credentials", credentials, "--endpoint", "api.example", "--tools", "query,other", "--", os.Args[0], "--server-flag", "value"}
	var stdout, stderr bytes.Buffer
	if code := run(args, strings.NewReader(`{"tool":"query","arguments":{"sql":"select 1"}}`), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.HasPrefix(out, `{"acquisition":{"adapter":{"name":"`+os.Args[0]+`","version":"1.0","digest":"sha256:`) ||
		!strings.Contains(out, `"endpoint":"api.example"`) || !strings.Contains(out, `"result":{"content":`) || strings.Contains(out, `"page"`) || strings.Contains(out, "secret-token") {
		t.Fatalf("envelope: %s", out)
	}
	stdout.Reset()
	tr, _ := os.ReadFile(os.Getenv(fakemcp.EnvTrace))
	if !strings.Contains(string(tr), `"--server-flag","value"`) {
		t.Fatalf("the server's own arguments reach it: %s", tr)
	}
	if code := run(args, strings.NewReader(`{"tool":"drop_table"}`), &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "is not one this source may call") {
		t.Fatalf("a failed acquisition exits 1 with the reason on stderr: %d %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatal("nothing is written on stdout for a failed acquisition")
	}
}
