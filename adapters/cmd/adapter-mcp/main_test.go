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
		{"--check", "--probe-failure", "Error:", "--", "y"},
		// Descriptors are captured by a check, for a platform and its
		// pinned binding together.
		{"--check", "--descriptors-platform=tickets", "--", "y"},
		{"--check", "--descriptors-binding=tickets@" + digest, "--", "y"},
		{"--descriptors-platform=tickets", "--descriptors-binding=tickets@" + digest, "--", "y"},
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
	// A tool named "--", allowed and probed, is a value like any other.
	tools := filepath.Join(dir, "tools.json")
	if err := os.WriteFile(tools, []byte(`[{"name":"--","inputSchema":{"type":"object"}}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(fakemcp.EnvTools, tools)
	stdout.Reset()
	if code := run([]string{"--check", "--tools=--", "--probe=--", "--credentials", credentials, "--", os.Args[0]}, strings.NewReader(""), &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), `"tools":["--"],"probe":{"tool":"--","answered":true}`) {
		t.Fatalf("a tool named --: exit %d %s %s", code, stderr.String(), stdout.String())
	}
	t.Setenv(fakemcp.EnvTools, "")
	// As flag=value, a value of "--" is one word and not the delimiter.
	stdout.Reset()
	if code := run([]string{"--check", "--probe=query", "--probe-failure=--", "--credentials", credentials, "--", os.Args[0]}, strings.NewReader(""), &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), `"probe":{"tool":"query","answered":true}`) {
		t.Fatalf("flag=value with a -- value: exit %d %s %s", code, stderr.String(), stdout.String())
	}
	// A "--" cannot be consumed as a flag's value: the split comes first,
	// and the flag is then missing its value.
	stderr.Reset()
	if code := run([]string{"--check", "--endpoint", "--", os.Args[0], "--tools", "query"}, strings.NewReader(""), &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "flag needs an argument") {
		t.Fatalf("a -- consumed as a value: exit %d %s", code, stderr.String())
	}
}

func TestRunCapturesDescriptorsWhenAsked(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(fakemcp.EnvActivate, "1")
	t.Setenv(fakemcp.EnvTrace, filepath.Join(dir, "trace.jsonl"))
	var stdout, stderr bytes.Buffer
	args := []string{"--check", "--tools=query", "--descriptors-platform=tickets", "--descriptors-binding=tickets@" + digest, "--", os.Args[0]}
	if code := run(args, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if out := stdout.String(); !strings.Contains(out, `"descriptors":{"binding":"tickets@`+digest+`",`) || !strings.Contains(out, `"platform":"tickets","policy":1,`) ||
		!strings.Contains(out, `"tools":{"query":{"description":"Run a read-only query","inputSchemaText":`) {
		t.Fatalf("the report carries the snapshot: %s", out)
	}
	stdout.Reset()
	args = []string{"--check", "--descriptors-platform=tickets", "--descriptors-binding=tickets", "--", os.Args[0]}
	if code := run(args, strings.NewReader(""), &stdout, &stderr); code != 1 || !strings.Contains(stdout.String(), "pinned binding") {
		t.Fatalf("a binding that is not pinned fails the check: %d %s", code, stdout.String())
	}
}

// A server's name never reaches the operator's terminal as it was written:
// a name offered twice, holding the escape that clears a screen, fails the
// check without echoing it.
func TestRunKeepsAServersNameOffTheTerminal(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(fakemcp.EnvActivate, "1")
	t.Setenv(fakemcp.EnvTrace, filepath.Join(dir, "trace.jsonl"))
	tools := filepath.Join(dir, "tools.json")
	// The escape as JSON writes it; decoded, it is ESC.
	name := `q\u001b[2J`
	if err := os.WriteFile(tools, []byte(`[{"name":"`+name+`","inputSchema":{"type":"object"}},{"name":"`+name+`","inputSchema":{"type":"object"}}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(fakemcp.EnvTools, tools)
	var stdout, stderr bytes.Buffer
	args := []string{"--check", "--descriptors-platform=tickets", "--descriptors-binding=tickets@" + digest, "--", os.Args[0]}
	if code := run(args, strings.NewReader(""), &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "offers one tool name twice") {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	for _, b := range strings.TrimSuffix(stderr.String(), "\n") {
		if b < 0x20 {
			t.Fatalf("stderr holds a control character: %q", stderr.String())
		}
	}
}

// The remote form from the command line: --url with the credential named
// by --bearer, fixed headers given one per --header, the server's roots in
// --ca-file. The credential, the other member of its file and the session
// id reach nothing the command writes -- not the envelope, not the report,
// not a refusal on stdout or stderr -- and a configuration refused for its
// form is refused with stdin unread.
func TestRunRemote(t *testing.T) {
	const bearer, other, session = "bearer-marker-91ab", "other-marker-c3d2", "session-marker-77e1"
	dir := t.TempDir()
	srv := fakemcp.NewHTTP(true, fakemcp.Script{Session: session})
	defer srv.Close()
	ca := filepath.Join(dir, "ca.pem")
	if err := srv.WriteCA(ca); err != nil {
		t.Fatal(err)
	}
	credentials := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(credentials, []byte(`{"TOKEN":"`+bearer+`","OTHER":"`+other+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	clean := func(what string, texts ...string) {
		t.Helper()
		for _, text := range texts {
			for _, marker := range []string{bearer, other, session} {
				if strings.Contains(text, marker) {
					t.Fatalf("%s carries %q: %s", what, marker, text)
				}
			}
		}
	}
	base := []string{"--url", srv.URL, "--ca-file", ca, "--credentials", credentials, "--bearer", "TOKEN", "--tools", "query", "--header", "X-MCP-Readonly=true", "--header", "X-Other=1"}
	var stdout, stderr bytes.Buffer
	if code := run(base, strings.NewReader(`{"tool":"query","arguments":{"sql":"select 1"}}`), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if out := stdout.String(); !strings.HasPrefix(out, `{"acquisition":{"adapter":{"name":"adapter-mcp","version":"0","digest":"sha256:`) ||
		!strings.Contains(out, `"endpoint":"`+srv.URL+`"`) || !strings.Contains(out, `"peerIdentity":"tls:sha256:`) ||
		!strings.HasSuffix(strings.SplitN(out, `"result"`, 2)[0], `"transport":"http","server":{"name":"fake-remote-mcp","version":"2.0"}},`) {
		t.Fatalf("envelope: %s", out)
	}
	clean("the envelope", stdout.String(), stderr.String())
	for _, r := range srv.Requests() {
		if r.Header.Get("X-MCP-Readonly") != "true" || r.Header.Get("X-Other") != "1" || r.Header.Get("Authorization") != "Bearer "+bearer {
			t.Fatalf("each request carries the fixed headers and the bearer: %v", r.Header)
		}
	}
	stdout.Reset()
	if code := run(append([]string{"--check"}, base...), strings.NewReader(""), &stdout, &stderr); code != 0 ||
		!strings.Contains(stdout.String(), `"transport":"http","endpoint":"`+srv.URL+`","peerIdentity":"tls:sha256:`) {
		t.Fatalf("check: exit %d %s %s", code, stdout.String(), stderr.String())
	}
	clean("the report", stdout.String(), stderr.String())
	// Refused for the form, before stdin is read and before anything is
	// sent; a check writes its failed report beside the reason.
	sent := len(srv.Requests())
	for _, tc := range []struct {
		args []string
		want string
	}{
		{append(append([]string{}, base...), "--image", "x/y:1@"+digest), "exactly one of --image, --url"},
		{append(append([]string{}, base...), "--", os.Args[0]), "takes no command and no arguments"},
		{append(append([]string{}, base...), "--header", "Authorization=Bearer "+other), "is a credential's"},
		{[]string{"--url", "http://mcp.example/mcp", "--credentials", credentials, "--bearer", "TOKEN"}, "http is accepted at a loopback address"},
		{[]string{"--url", srv.URL, "--credentials", credentials}, "--bearer names no member"},
		{[]string{"--bearer", "TOKEN", "--credentials", credentials, "--", os.Args[0]}, "are for a remote server, given by --url"},
	} {
		for _, check := range []bool{false, true} {
			args := tc.args
			if check {
				args = append([]string{"--check"}, args...)
			}
			stdout.Reset()
			stderr.Reset()
			stdin := strings.NewReader(`{"tool":"query"}`)
			code := run(args, stdin, &stdout, &stderr)
			if code != 1 || !strings.Contains(stderr.String(), tc.want) || stdin.Len() != len(`{"tool":"query"}`) {
				t.Fatalf("%v: exit %d, stdin left %d: %s", args, code, stdin.Len(), stderr.String())
			}
			if check != strings.HasPrefix(stdout.String(), `{"check":{"message":`) {
				t.Fatalf("%v: stdout %q", args, stdout.String())
			}
			clean("a refusal", stdout.String(), stderr.String())
		}
	}
	if len(srv.Requests()) != sent {
		t.Fatal("a configuration refused for its form sent a request")
	}
	// Refused by the server, in its own words, redacted.
	srv.Set(func(s *fakemcp.Script) { s.Refuse = `{"code":-32000,"message":"denied for ` + other + `"}` })
	for _, check := range []bool{false, true} {
		args := base
		if check {
			args = append([]string{"--check", "--probe", "query"}, base...)
		}
		stdout.Reset()
		stderr.Reset()
		if code := run(args, strings.NewReader(`{"tool":"query"}`), &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "denied for [redacted]") {
			t.Fatalf("a server's refusal: exit %d %s", code, stderr.String())
		}
		clean("a server's refusal", stdout.String(), stderr.String())
	}
}
