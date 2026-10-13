package main

import (
	"fmt"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The endpoint form a remote MCP server is named by, in a receipt and in a
// binding: the same cases adapters/mcphttp holds its own rule to, which
// the adapter's endpoint never leaves.
func TestRemoteEndpointForm(t *testing.T) {
	for _, ok := range []string{
		"https://mcp.example/mcp", "https://mcp.example:8443/api/2.0/mcp/functions/a/b", "https://127.0.0.1:9/mcp", "https://MCP.example/x",
		"http://127.0.0.1/mcp", "http://127.0.0.1:8080/mcp", "http://127.255.0.9:1", "http://[::1]:65535/x", "http://[::1]/", "https://h",
	} {
		if !isRemoteEndpoint(ok) {
			t.Errorf("%s refused", ok)
		}
	}
	for _, bad := range []string{
		"", "mcp.example/mcp", "HTTPS://mcp.example/mcp", "wss://mcp.example/mcp", "https://", "https:///mcp",
		"http://mcp.example/mcp", "http://localhost:8080/mcp", "http://128.0.0.1/mcp", "http://127.0.0.01/mcp", "http://127.0.0/mcp",
		"http://127.0.0.1:0/mcp", "http://127.0.0.1:080/mcp", "http://127.0.0.1:65536/mcp", "http://127.0.0.1:/mcp", "http://[::2]/mcp",
		"http://[0:0:0:0:0:0:0:1]/mcp", "http://[::1]x/mcp", "http://[::1]:/mcp",
		"https://user@mcp.example/mcp", "https://user:pw@mcp.example/mcp", "https://mcp.example/mcp?key=x", "https://mcp.example/mcp?",
		"https://mcp.example/mcp#x", "https://mcp.example/a b", "https://mcp.example/é", "https://mcp.example/" + strings.Repeat("a", 2048),
	} {
		if isRemoteEndpoint(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

// remoteEnvelope is an envelope as adapter-mcp writes it for a remote
// server: the eight members, transport and server, the URL as the endpoint
// and the TLS identity the answer came under.
func remoteEnvelope() (map[string]any, map[string]any) {
	acquisition := map[string]any{
		"adapter":       map[string]any{"name": "adapter-mcp", "version": "0", "digest": envelopeDigest("adapter-mcp")},
		"endpoint":      "https://mcp.example/api/mcp",
		"statement":     `{"arguments":{"id":7},"tool":"lookup"}`,
		"snapshot":      nil,
		"peerIdentity":  "tls:" + envelopeDigest("peer"),
		"schema":        nil,
		"upstreamToken": nil,
		"observedAt":    "2026-10-13T10:00:00Z",
		"transport":     "http",
		"server":        map[string]any{"name": "remote", "version": "1.4"},
	}
	return map[string]any{"acquisition": acquisition, "result": map[string]any{"content": []any{}}}, acquisition
}

// A remote acquisition is recorded as reported, transport and server with
// the rest, and the store verifies; an envelope whose remote members are
// out of their form, or reported by another shape than mcp, is refused as
// not an envelope, with nothing minted.
func TestRemoteMembersAreRecordedAndHeldToTheirForm(t *testing.T) {
	service, server := shapedService(t, "mcp")
	env, reported := remoteEnvelope()
	t.Setenv(envSourceEnvelope, envelopeText(t, env))
	code, first := post(t, server, "/acquire", `{"session":"remote-1","source":"history","arguments":{}}`)
	if code != http.StatusOK {
		t.Fatalf("acquire failed: %d %v", code, first)
	}
	acquisition := first["receipt"].(map[string]any)["acquisition"].(map[string]any)
	for _, name := range []string{"adapter", "endpoint", "peerIdentity", "transport", "server", "observedAt"} {
		if !reflect.DeepEqual(acquisition[name], reported[name]) {
			t.Fatalf("%s recorded as %v, reported %v", name, acquisition[name], reported[name])
		}
	}
	if len(acquisition) != 11 || acquisition["shape"] != "mcp" {
		t.Fatalf("the nine members of an acquisition and the two a remote server adds: %v", acquisition)
	}
	// Over plaintext loopback no identity is established.
	env, reported = remoteEnvelope()
	reported["endpoint"], reported["peerIdentity"] = "http://127.0.0.1:8080/mcp", nil
	t.Setenv(envSourceEnvelope, envelopeText(t, env))
	if code, body := post(t, server, "/acquire", `{"session":"remote-1","source":"history","arguments":{}}`); code != http.StatusOK {
		t.Fatalf("a loopback acquisition: %d %v", code, body)
	}
	for _, tc := range []struct {
		name   string
		mutate func(acq map[string]any)
	}{
		{"transport without server", func(acq map[string]any) { delete(acq, "server") }},
		{"server without transport", func(acq map[string]any) { delete(acq, "transport") }},
		{"a transport outside its enumeration", func(acq map[string]any) { acq["transport"] = "sse" }},
		{"a transport that is not a string", func(acq map[string]any) { acq["transport"] = true }},
		{"a server that is not an object", func(acq map[string]any) { acq["server"] = "remote 1.4" }},
		{"a server without a version", func(acq map[string]any) { delete(acq["server"].(map[string]any), "version") }},
		{"a server whose name is a number", func(acq map[string]any) { acq["server"].(map[string]any)["name"] = 7 }},
		{"a server with a member the signer did not ask for", func(acq map[string]any) { acq["server"].(map[string]any)["vendor"] = "x" }},
		{"an endpoint off its form", func(acq map[string]any) { acq["endpoint"] = "warehouse.internal:5432" }},
		{"an http endpoint off loopback", func(acq map[string]any) { acq["endpoint"] = "http://mcp.example/mcp"; acq["peerIdentity"] = nil }},
		{"an endpoint with a user", func(acq map[string]any) { acq["endpoint"] = "https://user@mcp.example/mcp" }},
		{"a null endpoint", func(acq map[string]any) { acq["endpoint"] = nil }},
		{"no identity over TLS", func(acq map[string]any) { acq["peerIdentity"] = nil }},
		{"an identity in upper case", func(acq map[string]any) { acq["peerIdentity"] = strings.ToUpper(acq["peerIdentity"].(string)) }},
		{"an identity of another kind", func(acq map[string]any) { acq["peerIdentity"] = "spiffe://example/mcp" }},
		{"an identity in the clear", func(acq map[string]any) { acq["endpoint"] = "http://127.0.0.1:8080/mcp" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, acq := remoteEnvelope()
			tc.mutate(acq)
			t.Setenv(envSourceEnvelope, envelopeText(t, env))
			code, body := post(t, server, "/acquire", `{"session":"remote-2","source":"history","arguments":{}}`)
			if code == http.StatusOK || !strings.Contains(fmt.Sprint(body["error"]), "not an envelope") {
				t.Fatalf("must be refused as not an envelope: %d %v", code, body)
			}
		})
	}
	if code, body := post(t, server, "/seal", `{"session":"remote-1"}`); code != http.StatusOK {
		t.Fatalf("seal failed: %d %v", code, body)
	}
	report, err := verifyWithRegistry(service.storeRoot, service.regPath, "gateway:test", service.publicKey)
	if err != nil || !report.OK {
		t.Fatalf("a store of remote acquisitions verifies, and no refusal minted: %v %+v", err, report)
	}
	// Another shape reports no remote server: an http adapter's envelope
	// carrying the two is refused.
	_, httpServer := shapedService(t, "http")
	env, _ = remoteEnvelope()
	t.Setenv(envSourceEnvelope, envelopeText(t, env))
	if code, body := post(t, httpServer, "/acquire", `{"session":"remote-3","source":"history","arguments":{}}`); code == http.StatusOK ||
		!strings.Contains(fmt.Sprint(body["error"]), "members of shape mcp alone") {
		t.Fatalf("an http-shaped source reporting a remote MCP server: %d %v", code, body)
	}
}

// A binding's mcp operation names a remote server by its URL, the member
// of the operation's credentials file sent as the bearer, and optionally
// fixed headers; the engine derives adapter-mcp's remote form for it, and
// the write's endpoint is the URL.
const remoteBinding = `{
  "bindingVersion": "1",
  "platform": "remote",
  "operations": {
    "live": {"shape": "mcp", "server": {"url": "https://mcp.example/api/mcp", "bearer": "TOKEN", "headers": ["X-MCP-Readonly=true"]}, "tools": ["lookup"], "probe": {"tool": "lookup"}, "licence": "MIT"},
    "write": {"shape": "mcp", "server": {"url": "https://mcp.example/api/mcp", "bearer": "WRITE_TOKEN"}, "tools": ["update"], "licence": "MIT"}
  }
}`

func TestEngineDerivesARemoteServer(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"remote": remoteBinding})
	bin := abs(t, t.TempDir(), "bin")
	text := engineJSON(t, catalog, `,"adapters":"`+bin+`","runtime":"podman"`,
		platformJSONFor(t, "remote", "remote@"+digestOf(remoteBinding), "engine-desk", `,"endpoint":"desk.internal","write":true`, "live", "write"))
	cfg, sources, err := load(t, text)
	if err != nil {
		t.Fatal(err)
	}
	creds := cfg.platforms[0].credentials
	adapter := filepath.Join(cfg.adapters, "adapter-mcp")
	live, write := sources["remote/live"], sources["remote/write"]
	if want := []string{adapter, "--url=https://mcp.example/api/mcp", "--credentials=" + creds["live"], "--bearer=TOKEN", "--header=X-MCP-Readonly=true", "--tools=lookup"}; !reflect.DeepEqual(live.argv, want) ||
		!reflect.DeepEqual(live.check, []string{"--probe=lookup"}) || live.shape != "mcp" {
		t.Fatalf("live:\n got %q %q\nwant %q", live.argv, live.check, want)
	}
	if want := []string{adapter, "--url=https://mcp.example/api/mcp", "--credentials=" + creds["write"], "--bearer=WRITE_TOKEN", "--tools=update", "--error-results"}; !reflect.DeepEqual(write.argv, want) {
		t.Fatalf("write:\n got %q\nwant %q", write.argv, want)
	}
	if write.endpoint != "https://mcp.example/api/mcp" {
		t.Fatalf("the write's endpoint is the URL it went to, not the platform's: %q", write.endpoint)
	}
}

func TestRemoteBindingRefusals(t *testing.T) {
	op := func(server string) string {
		return `{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"mcp","server":` + server + `,"tools":["q"],"licence":"MIT"}}}`
	}
	for server, want := range map[string]string{
		`{"url":"https://mcp.example/mcp","bearer":"T","image":"x@` + testImageDigest + `"}`:  `unknown member "image"`,
		`{"url":"https://mcp.example/mcp","bearer":"T","args":["--x"]}`:                       `unknown member "args"`,
		`{"url":"https://mcp.example/mcp"}`:                                                   `missing member "bearer"`,
		`{"url":"https://mcp.example/mcp","bearer":""}`:                                       "server.bearer names the credentials member",
		`{"url":"http://mcp.example/mcp","bearer":"T"}`:                                       "server.url must be https",
		`{"url":"https://user@mcp.example/mcp","bearer":"T"}`:                                 "server.url must be https",
		`{"url":"https://mcp.example/mcp?key=k","bearer":"T"}`:                                "server.url must be https",
		`{"url":"https://mcp.example/%zz","bearer":"T"}`:                                      "is not an absolute URL",
		`{"url":7,"bearer":"T"}`:                                                              "server.url must be https",
		`{"url":"https://mcp.example/mcp","bearer":"T","headers":[]}`:                         "server.headers, when present, is a non-empty array",
		`{"url":"https://mcp.example/mcp","bearer":"T","headers":["X-Read-Only"]}`:            "server.headers must be NAME=VALUE",
		`{"url":"https://mcp.example/mcp","bearer":"T","headers":["Authorization=Bearer x"]}`: "server.headers names Authorization",
		`{"url":"https://mcp.example/mcp","bearer":"T","headers":["mcp-session-id=s"]}`:       "server.headers names mcp-session-id",
	} {
		if _, err := parseBinding([]byte(op(server))); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want %q, got %v", server, want, err)
		}
	}
}
