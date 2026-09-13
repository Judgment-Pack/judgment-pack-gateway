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
		{"--check"},
		{"--unknown", "--", "y"},
		{"--probe", "query", "--", "y"},
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

func TestRunCheck(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(fakemcp.EnvActivate, "1")
	t.Setenv(fakemcp.EnvTrace, filepath.Join(dir, "trace.jsonl"))
	credentials := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(credentials, []byte(`{"TOKEN":"secret-token"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// stdin is not read by a check: what is attached is the operator's.
	stdin := strings.NewReader("not a request")
	var stdout, stderr bytes.Buffer
	args := []string{"--check", "--credentials", credentials, "--tools", "query", "--", os.Args[0], "--server-flag"}
	if code := run(args, stdin, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.HasPrefix(out, `{"check":{"status":"succeeded","adapter":{"name":"`+os.Args[0]+`","version":"1.0","digest":"sha256:`) || !strings.Contains(out, `"server":{"name":"fake-mcp","version":"1.0"}`) ||
		!strings.Contains(out, `"tools":["query"]`) || strings.Contains(out, "secret-token") || stdin.Len() != len("not a request") {
		t.Fatalf("report: %s (stdin left %d bytes)", out, stdin.Len())
	}
	// With --image, what follows -- are the server's arguments inside the
	// container, after the image on the runtime's command line.
	stdout.Reset()
	args = []string{"--check", "--image", "x/y:1@" + digest, "--runtime", os.Args[0], "--credentials", credentials, "--", "--access-mode=restricted"}
	if code := run(args, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.HasPrefix(stdout.String(), `{"check":{"status":"succeeded","adapter":{"name":"x/y","version":"1","digest":"`+digest+`"}`) {
		t.Fatalf("the report names the pinned image: %s", stdout.String())
	}
	tr, _ := os.ReadFile(os.Getenv(fakemcp.EnvTrace))
	if !strings.Contains(string(tr), `"x/y:1@`+digest+`","--access-mode=restricted"`) {
		t.Fatalf("the server's arguments follow the image: %s", tr)
	}
	stdout.Reset()
	args = []string{"--check", "--tools", "drop_table", "--", os.Args[0]}
	if code := run(args, strings.NewReader(""), &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "not offered by the server") ||
		!strings.HasPrefix(stdout.String(), `{"check":{"message":"tool \"drop_table\" is allowed by the configuration but not offered by the server: [query]","status":"failed"}}`) {
		t.Fatalf("a failed check exits 1 with the reason on stderr and as a failed report on stdout: %d %s %s", code, stderr.String(), stdout.String())
	}
	// A server command, or a server's arguments, follow --; without the
	// delimiter, flag parsing would hand later flags to the server.
	stdout.Reset()
	for _, args := range [][]string{
		{"--check", "--image", "x/y:1@" + digest, "serve", "--tools", "query"},
		{"--credentials", credentials, os.Args[0]},
		{"--check", "--image", "x/y:1@" + digest, "stray", "--", "--flag"},
	} {
		if code := run(args, strings.NewReader(""), &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "follow --") {
			t.Fatalf("%v: exit %d %s", args, code, stderr.String())
		}
	}
	// A "--" cannot be consumed as a flag's value: the split comes first,
	// and the flag is then missing its value.
	stderr.Reset()
	if code := run([]string{"--check", "--endpoint", "--", os.Args[0], "--tools", "query"}, strings.NewReader(""), &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "flag needs an argument") {
		t.Fatalf("a -- consumed as a value: exit %d %s", code, stderr.String())
	}
}
