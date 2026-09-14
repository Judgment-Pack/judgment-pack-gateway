package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMCPBounds(t *testing.T) {
	f := newMCPFixture(t, false)
	f.server.cfg.mcp.callsPerMinute = 2
	// the window is what is shifted below, not the transport session's idle bound
	f.server.cfg.mcp.idleSeconds = 86400
	sid := f.open(t)
	// the window: the third call in a minute is an overload naming the
	// seconds until the window turns, and nothing is forwarded
	for i := 0; i < 2; i++ {
		if _, _, body := f.call(t, http.MethodPost, sid, toolCall(i, "screen.lookup", `{}`, ""), nil); body["result"].(map[string]any)["isError"] != nil {
			t.Fatalf("call %d: %v", i, body)
		}
	}
	before := len(f.service.sessions)
	_, _, body := f.call(t, http.MethodPost, sid, toolCall(2, "screen.lookup", `{}`, ""), nil)
	result := body["result"].(map[string]any)
	structured := result["structuredContent"].(map[string]any)
	if result["isError"] != true || structured["outcome"] != "overload" || structured["retryAfterSeconds"] == nil {
		t.Fatalf("the third call: %v", result)
	}
	if len(f.service.sessions) != before {
		t.Fatal("an overloaded call reached the signer")
	}
	// a refused call spent its quota too: still refused after the window
	// turns only when the window turns
	f.server.now = func() time.Time { return time.Now().Add(61 * time.Second) }
	if _, _, body := f.call(t, http.MethodPost, sid, toolCall(3, "screen.lookup", `{}`, ""), nil); body["result"].(map[string]any)["isError"] != nil {
		t.Fatalf("after the window turned: %v", body)
	}
	f.server.now = time.Now

	// the forward slots and the queue: with one slot and a stalled
	// source, a second call waits and a third is refused at once
	f.server.cfg.mcp.callsPerMinute = 100
	f.server.forwards = make(chan struct{}, 1)
	f.server.queue = make(chan struct{}, 1)
	release := filepath.Join(t.TempDir(), "release")
	t.Setenv(envSourceWait, release)
	results := make(chan map[string]any, 3)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, body := f.call(t, http.MethodPost, sid, toolCall(20+i, "screen.lookup", `{}`, ""), nil)
			results <- body["result"].(map[string]any)
		}(i)
		time.Sleep(150 * time.Millisecond)
	}
	// one is forwarded and stalled, one waits in the queue: a third finds
	// the queue full
	_, _, body = f.call(t, http.MethodPost, sid, toolCall(22, "screen.lookup", `{}`, ""), nil)
	third := body["result"].(map[string]any)
	if third["isError"] != true || !strings.Contains(third["structuredContent"].(map[string]any)["error"].(string), "full") {
		t.Fatalf("the third call with a full queue: %v", third)
	}
	os.WriteFile(release, []byte("go"), 0o600)
	wg.Wait()
	close(results)
	for r := range results {
		if r["isError"] != nil {
			t.Fatalf("a queued call failed: %v", r)
		}
	}
	// two receipts in the transport session's receipt session: indices 0 and 1
	t.Setenv(envSourceWait, "")
}

func TestMCPOverStdio(t *testing.T) {
	f := newMCPFixture(t, true)
	in := &bytes.Buffer{}
	lines := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		toolCall(2, "screen.lookup", `{"q":"x"}`, ""),
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"engine.seal","arguments":{"session":"SESSION"}}}`,
	}
	// the seal names the session the first answer reports: two passes
	out := &bytes.Buffer{}
	if err := f.server.serveStdio(context.Background(), strings.NewReader(lines[0]+"\n"+lines[1]+"\n"+lines[2]+"\n"), out, f.token); err != nil {
		t.Fatal(err)
	}
	answers := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(answers) != 2 {
		t.Fatalf("stdio answered %d lines: %s", len(answers), out.String())
	}
	var call map[string]any
	json.Unmarshal([]byte(answers[1]), &call)
	structured := call["result"].(map[string]any)["structuredContent"].(map[string]any)
	session := structured["session"].(string)
	if !strings.HasPrefix(session, "mcp-") || structured["receipt"] == nil {
		t.Fatalf("the stdio call: %v", call)
	}
	out.Reset()
	in.WriteString(strings.Replace(lines[3], "SESSION", session, 1) + "\n")
	if err := f.server.serveStdio(context.Background(), in, out, f.token); err != nil {
		t.Fatal(err)
	}
	var sealed map[string]any
	json.Unmarshal(out.Bytes(), &sealed)
	if sealed["result"].(map[string]any)["structuredContent"].(map[string]any)["finalCount"] != float64(1) {
		t.Fatalf("the stdio seal: %s", out.String())
	}
	// no token, with an identity: refused at start, nothing served
	if err := f.server.serveStdio(context.Background(), strings.NewReader(lines[0]+"\n"), out, ""); err == nil || !strings.Contains(err.Error(), mcpTokenEnv) {
		t.Fatalf("stdio without a token started: %v", err)
	}
	// the signer refusing the token over stdio is an error result
	other := identityFor(t, newIssuer(t))
	f.service.identity = &other
	out.Reset()
	f.server.serveStdio(context.Background(), strings.NewReader(toolCall(4, "screen.lookup", `{}`, "")+"\n"), out, f.token)
	var refused map[string]any
	json.Unmarshal(out.Bytes(), &refused)
	if r := refused["result"].(map[string]any); r["isError"] != true || r["structuredContent"].(map[string]any)["status"] != float64(401) {
		t.Fatalf("the signer's refusal over stdio: %s", out.String())
	}
	// a line over the bound ends the transport with an error
	out.Reset()
	if err := f.server.serveStdio(context.Background(), strings.NewReader(strings.Repeat("x", mcpMaxMessageBytes+2)+"\n"), out, f.token); err == nil || !strings.Contains(out.String(), "exceeds the bound") {
		t.Fatalf("a line over the bound: %v %s", err, out.String())
	}
}

func TestMCPReachCheck(t *testing.T) {
	cfg := engineConfig{seed: "/s/seed", store: "/s/store", platforms: []platformConfig{{name: "p", credentials: map[string]string{"live": "/c/live", "history": "/c/history"}}}}
	denied := func(string) error { return fs.ErrPermission }
	good := mcpReachHost{euid: 65533, gid: 65533, groups: func() ([]int, error) { return []int{65533}, nil }, caps: func() (bool, string) { return true, "" }, open: denied}
	if err := mcpReachCheck(cfg, good); err != nil {
		t.Fatalf("a deployment in place is refused: %v", err)
	}
	for _, c := range []struct {
		name string
		host func(h mcpReachHost) mcpReachHost
		want string
	}{
		{"root", func(h mcpReachHost) mcpReachHost { h.euid = 0; return h }, "runs as root"},
		{"a capability", func(h mcpReachHost) mcpReachHost {
			h.caps = func() (bool, string) { return false, "effective 0x20" }
			return h
		}, "holds a capability"},
		{"a supplementary group", func(h mcpReachHost) mcpReachHost {
			h.groups = func() ([]int, error) { return []int{65533, 65532}, nil }
			return h
		}, "supplementary group 65532"},
		{"a readable seed", func(h mcpReachHost) mcpReachHost {
			h.open = func(p string) error {
				if p == "/s/seed" {
					return nil
				}
				return fs.ErrPermission
			}
			return h
		}, "can open the seed"},
		{"a readable credentials file", func(h mcpReachHost) mcpReachHost {
			h.open = func(p string) error {
				if p == "/c/history" {
					return nil
				}
				return fs.ErrPermission
			}
			return h
		}, "can open platform p's history credentials"},
		{"a readable store", func(h mcpReachHost) mcpReachHost {
			h.open = func(p string) error {
				if p == "/s/store" {
					return nil
				}
				return fs.ErrPermission
			}
			return h
		}, "can open the store"},
		{"a missing seed", func(h mcpReachHost) mcpReachHost {
			h.open = func(p string) error {
				if p == "/s/seed" {
					return fs.ErrNotExist
				}
				return fs.ErrPermission
			}
			return h
		}, "not a denial"},
	} {
		if err := mcpReachCheck(cfg, c.host(good)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want %q, got %v", c.name, c.want, err)
		}
	}
	// against the real filesystem: a file this user cannot read is denied,
	// a readable one is refused, a missing one is refused
	if os.Geteuid() == 0 {
		t.Skip("root can open anything; the filesystem case needs an unprivileged user")
	}
	dir := t.TempDir()
	seed := filepath.Join(dir, "seed")
	store := filepath.Join(dir, "store")
	os.WriteFile(seed, []byte("x"), 0o000)
	os.Mkdir(store, 0o000)
	host := osMCPReachHost()
	host.caps = func() (bool, string) { return true, "" }
	host.groups = func() ([]int, error) { return nil, nil }
	real := engineConfig{seed: seed, store: store}
	if err := mcpReachCheck(real, host); err != nil {
		t.Fatalf("denied files refused: %v", err)
	}
	os.Chmod(seed, 0o600)
	if err := mcpReachCheck(real, host); err == nil || !strings.Contains(err.Error(), "can open the seed") {
		t.Fatalf("a readable seed: %v", err)
	}
	real.seed = filepath.Join(dir, "absent")
	if err := mcpReachCheck(real, host); err == nil || !strings.Contains(err.Error(), "not a denial") {
		t.Fatalf("a missing seed: %v", err)
	}
	_ = errors.New
}

func TestMCPCommandRefusals(t *testing.T) {
	catalog := t.TempDir()
	write := func(text string) string {
		path := filepath.Join(t.TempDir(), "engine.json")
		os.WriteFile(path, []byte(text), 0o600)
		return path
	}
	v2 := func(mcp, extra string) string {
		text := engineJSON(t, catalog, `,"mcp":`+mcp+extra, ``)
		return strings.Replace(text, `"engineVersion":"1"`, `"engineVersion":"2"`, 1)
	}
	for _, c := range []struct {
		name string
		args []string
		want int
	}{
		{"no arguments", nil, 2},
		{"no transport", []string{"--config", write(v2(`{"listen":"127.0.0.1:8788"}`, ``))}, 2},
		{"two transports", []string{"--config", write(v2(`{"listen":"127.0.0.1:8788"}`, ``)), "--http", "--stdio"}, 2},
		{"an unknown flag", []string{"--config", "x", "--tcp"}, 2},
		{"a configuration that does not load", []string{"--config", filepath.Join(t.TempDir(), "none.json"), "--stdio"}, 1},
		{"no mcp member", []string{"--config", write(engineJSON(t, catalog, ``, ``)), "--stdio"}, 1},
		{"http without a resource", []string{"--config", write(v2(`{"listen":"127.0.0.1:8788"}`, ``)), "--http"}, 1},
		{"http without an identity", []string{"--config", write(v2(`{"listen":"127.0.0.1:8788","resource":"https://e/mcp"}`, ``)), "--http"}, 1},
		{"http with an issuer that is no identifier", []string{"--config", write(v2(`{"listen":"127.0.0.1:8788","resource":"https://e/mcp"}`, `,"identity":{"issuer":"login.example","audience":"gateway:acme","keys":"`+filepath.ToSlash(filepath.Join(t.TempDir(), "keys.json"))+`"}`)), "--http"}, 1},
	} {
		if got := cmdMCP(c.args); got != c.want {
			t.Errorf("%s: exit %d, want %d", c.name, got, c.want)
		}
	}
}

func TestAcceptsJSON(t *testing.T) {
	for accept, want := range map[string]bool{
		"":                                    true,
		"application/json":                    true,
		"application/json, text/event-stream": true,
		"text/event-stream, application/json": true,
		"*/*":                                 true,
		"application/*":                       true,
		"text/event-stream":                   false,
		"application/json;q=0, text/event-stream": false,
		"*/*;q=0": false,
		"application/*;q=0.5, application/json;q=0": false,
		"text/*, */*;q=0.1":                         true,
		"APPLICATION/JSON":                          true,
	} {
		if got := acceptsJSON(accept); got != want {
			t.Errorf("Accept %q: %v, want %v", accept, got, want)
		}
	}
}

func TestMetadataPathAndDuplicates(t *testing.T) {
	for resource, path := range map[string]string{
		"https://engine.example/mcp":     "/.well-known/oauth-protected-resource/mcp",
		"https://engine.example":         "/.well-known/oauth-protected-resource",
		"https://engine.example/":        "/.well-known/oauth-protected-resource",
		"https://engine.example/a/b/mcp": "/.well-known/oauth-protected-resource/a/b/mcp",
	} {
		if got := metadataPath(resource); got != path {
			t.Errorf("%s: %s, want %s", resource, got, path)
		}
	}
	if metadataURL("https://engine.example:8443/mcp") != "https://engine.example:8443/.well-known/oauth-protected-resource/mcp" {
		t.Error(metadataURL("https://engine.example:8443/mcp"))
	}
	for text, ok := range map[string]bool{
		`{"a":1,"b":{"c":2,"d":[{"e":1},{"e":2}]}}`: true,
		`{"a":1,"a":2}`:             false,
		`{"a":{"b":1,"b":2}}`:       false,
		`{"a":[{"b":1,"b":2}]}`:     false,
		`{"a":"x","a":"y"}`:         false,
		`[{"a":1},{"a":1}]`:         true,
		`{"a":{"b":1},"c":{"b":1}}`: true,
	} {
		if err := noDuplicateMembers([]byte(text)); (err == nil) != ok {
			t.Errorf("%s: %v", text, err)
		}
	}
	_ = fmt.Sprint
}
