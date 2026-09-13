package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"adapters/internal/fakeruntime"
)

func TestMain(m *testing.M) {
	if os.Getenv(fakeruntime.EnvActivate) == "1" {
		os.Exit(fakeruntime.Run(os.Args[1:]))
	}
	os.Exit(m.Run())
}

const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestRunUsage(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--image", "x@" + digest},
		{"--credentials", "c"},
		{"--image", "x@" + digest, "--credentials", "c", "stray"},
		{"--image", "x@" + digest, "--credentials", "c", "--unknown"},
	} {
		var stderr bytes.Buffer
		if code := run(args, strings.NewReader(`{"stream":"s"}`), &bytes.Buffer{}, &stderr); code != 2 {
			t.Errorf("%v: exit %d, want 2 (%s)", args, code, stderr.String())
		}
	}
}

func TestRunEndToEnd(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	t.Setenv(fakeruntime.EnvActivate, "1")
	t.Setenv(fakeruntime.EnvDiscover, write("discover.out",
		`{"type":"CATALOG","catalog":{"streams":[{"name":"s","json_schema":{"type":"object"},"supported_sync_modes":["full_refresh"]}]}}`+"\n"))
	t.Setenv(fakeruntime.EnvRead, write("read.out",
		`{"type":"RECORD","record":{"stream":"s","emitted_at":1,"data":{"id":1}}}`+"\n"))
	credentials := write("credentials.json", `{"host":"h"}`)
	args := []string{"--image", "x/y:1@" + digest, "--credentials", credentials, "--runtime", os.Args[0], "--endpoint", "h:1"}
	var stdout, stderr bytes.Buffer
	if code := run(args, strings.NewReader(`{"stream":"s","limit":5}`), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.HasPrefix(out, `{"acquisition":{"adapter":{"name":"x/y","version":"1","digest":"`+digest+`"},"endpoint":"h:1"`) ||
		!strings.Contains(out, `"result":[{"id":1}],"page":true}`) || strings.Contains(out, `"snapshot":"`) {
		t.Fatalf("envelope: %s", out)
	}
	stdout.Reset()
	if code := run(args, strings.NewReader(`{"stream":"missing"}`), &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "not one the connector offers") {
		t.Fatalf("a failed acquisition exits 1 with the reason on stderr: %d %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatal("nothing is written on stdout for a failed acquisition")
	}
}
