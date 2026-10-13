package mcphttp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStreamableLifecycleAndAllowedTools(t *testing.T) {
	var calls []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("missing authorization")
		}
		var request struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		json.NewDecoder(r.Body).Decode(&request)
		if r.Method == "DELETE" {
			w.WriteHeader(204)
			return
		}
		calls = append(calls, request.Method)
		if request.Method == "initialize" {
			w.Header().Set("Mcp-Session-Id", "fixture-session")
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{"protocolVersion":"2025-11-25"}}`, request.ID)
			return
		}
		if r.Header.Get("Mcp-Session-Id") != "fixture-session" || r.Header.Get("Mcp-Protocol-Version") != "2025-11-25" {
			t.Error("session/version lost")
		}
		if request.ID == 0 {
			w.WriteHeader(202)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"hello\"}]}}\n\n", request.ID)
	}))
	defer server.Close()
	c, err := New(server.URL, "fixture-token", []string{"read"}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = c.CallTool(context.Background(), "write", map[string]any{}); !errors.Is(err, ErrTool) {
		t.Fatal("write allowed")
	}
	result, err := c.CallTool(context.Background(), "read", map[string]any{})
	if err != nil || !strings.Contains(string(result), "hello") {
		t.Fatalf("read: %s %v", result, err)
	}
	c.Close(context.Background())
	if len(calls) != 3 {
		t.Fatalf("unexpected calls: %v", calls)
	}
}
func TestHostileResponses(t *testing.T) {
	for _, tt := range []struct {
		name, body, media string
		status            int
		want              error
	}{
		{"wrong id", `{"jsonrpc":"2.0","id":7,"result":{}}`, "application/json", 200, ErrProtocol},
		{"duplicate", `{"jsonrpc":"2.0","id":1,"result":{},"result":{}}`, "application/json", 200, ErrProtocol},
		{"both", `{"jsonrpc":"2.0","id":1,"result":{},"error":null}`, "application/json", 200, ErrProtocol},
		{"token echo", `{"jsonrpc":"2.0","id":1,"result":{"value":"private-fixture"}}`, "application/json", 200, ErrProtocol},
		{"escaped token echo", `{"jsonrpc":"2.0","id":1,"result":{"value":"\u0070rivate-fixture"}}`, "application/json", 200, ErrProtocol},
		{"auth", "secret server failure", "application/json", 401, ErrUnauthorized},
		{"html", "<html>private</html>", "text/html", 200, ErrProtocol},
		{"truncated SSE", "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n", "text/event-stream", 200, ErrProtocol},
		{"notifications flood", strings.Repeat("data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n", 65), "text/event-stream", 200, ErrLimit},
		{"oversize", strings.Repeat(" ", MaxResponse+1), "application/json", 200, ErrLimit},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tt.media)
				w.WriteHeader(tt.status)
				io.WriteString(w, tt.body)
			}))
			defer s.Close()
			c, _ := New(s.URL, "private-fixture", nil, s.Client())
			_, err := c.call(context.Background(), "initialize", map[string]any{})
			if !errors.Is(err, tt.want) {
				t.Fatalf("%v, want %v", err, tt.want)
			}
		})
	}
}
func TestRedirectDoesNotForwardCredential(t *testing.T) {
	called := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer target.Close()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer s.Close()
	c, _ := New(s.URL, "fixture-token", nil, s.Client())
	if err := c.Initialize(context.Background()); err == nil || called {
		t.Fatal("followed redirect")
	}
}

// The endpoint a client is opened on: https, or http at a loopback address
// written as one; no user, query or fragment; printable ASCII.
func TestEndpointProblem(t *testing.T) {
	for _, ok := range []string{
		"https://mcp.example/mcp", "https://mcp.example:8443/api/2.0/mcp/functions/a/b", "https://127.0.0.1:9/mcp",
		"http://127.0.0.1/mcp", "http://127.0.0.1:8080/mcp", "http://127.255.0.9:1", "http://[::1]:65535/x", "http://[::1]/",
	} {
		if err := EndpointProblem(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
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
		if err := EndpointProblem(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// A client opened for the remote form sends fixed headers before its own,
// a bearer only when it has one -- and holds an answer to repeating the
// credential only then -- reads each answer to its own bound, records the
// TLS identity a result came under, and names a status it refuses.
func TestOpenedClient(t *testing.T) {
	var headers []http.Header
	result := `{"content":[{"type":"text","text":"x"}]}`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers = append(headers, r.Header.Clone())
		var request struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
		}
		json.NewDecoder(r.Body).Decode(&request)
		if r.Method == "DELETE" || request.ID == 0 {
			w.WriteHeader(202)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if request.Method == "initialize" {
			w.Header().Set("Mcp-Session-Id", "s-1")
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{"protocolVersion":"2025-06-18"}}`, request.ID)
			return
		}
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":%s}`, request.ID, result)
	}))
	defer server.Close()
	fixed := http.Header{}
	fixed.Set("X-MCP-Readonly", "true")
	c, err := Open(server.URL+"/mcp", Options{Headers: fixed, MaxResponse: 256}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := c.Request(ctx, "tools/list", map[string]any{}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("a request before initialize: %v", err)
	}
	if _, err := c.Request(ctx, "initialize", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CallTool(ctx, "any", map[string]any{}); !errors.Is(err, ErrTool) {
		t.Fatalf("a call before the session is negotiated: %v", err)
	}
	if err := c.Negotiated(ctx, "2025-06-18"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Request(ctx, "initialize", map[string]any{}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("a second initialize: %v", err)
	}
	if _, err := c.Request(ctx, "tools/call", map[string]any{"name": "any"}); !errors.Is(err, ErrTool) {
		t.Fatalf("a tool call is CallTool's: %v", err)
	}
	// No tool list: the caller holds the allowlist, and any tool is named.
	got, err := c.CallTool(ctx, "any", map[string]any{})
	if err != nil || string(got) != result {
		t.Fatalf("a call: %s %v", got, err)
	}
	sum := sha256.Sum256(server.Certificate().Raw)
	if c.PeerIdentity() != "tls:sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("the identity the result came under: %q", c.PeerIdentity())
	}
	for i, h := range headers {
		if h.Get("X-MCP-Readonly") != "true" || h.Get("Authorization") != "" || h.Get("Accept") != "application/json, text/event-stream" {
			t.Fatalf("request %d: fixed headers sent, no credential: %v", i, h)
		}
	}
	// An answer at the bound is read; one byte past it is refused.
	at := 256 - len(`{"jsonrpc":"2.0","id":5,"result":}`)
	result = `{"content":[{"type":"text","text":"` + strings.Repeat("x", at-len(`{"content":[{"type":"text","text":""}]}`)) + `"}]}`
	if _, err := c.CallTool(ctx, "any", map[string]any{}); err != nil {
		t.Fatalf("an answer at the bound: %v", err)
	}
	result = strings.Replace(result, `"x`, `"xx`, 1)
	if _, err := c.CallTool(ctx, "any", map[string]any{}); !errors.Is(err, ErrLimit) || !strings.Contains(err.Error(), "exceeds the bound of 256 bytes") {
		t.Fatalf("an answer one byte past the bound: %v", err)
	}
	// A client given a tool list holds a call to it.
	c, _ = Open(server.URL, Options{Token: "t", Tools: []string{"read"}}, server.Client())
	c.Request(ctx, "initialize", map[string]any{})
	c.Negotiated(ctx, "2025-06-18")
	if _, err := c.CallTool(ctx, "write", map[string]any{}); !errors.Is(err, ErrTool) {
		t.Fatalf("a tool outside the list: %v", err)
	}
	if _, err := Open("http://example.com/mcp", Options{}, nil); !errors.Is(err, ErrProtocol) {
		t.Fatalf("http off loopback: %v", err)
	}
}

// A status is named, the kind kept for errors.Is: a redirect by its status
// alone, never its location.
func TestStatusesAreNamed(t *testing.T) {
	for _, tt := range []struct {
		status int
		want   error
		text   string
	}{
		{307, ErrUnavailable, "the server answered 307 Temporary Redirect, a redirect, which is not followed"},
		{308, ErrUnavailable, "the server answered 308 Permanent Redirect, a redirect, which is not followed"},
		{401, ErrUnauthorized, "the server answered 401 Unauthorized"},
		{503, ErrUnavailable, "the server answered 503 Service Unavailable"},
	} {
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "https://elsewhere.example/secret-place")
			w.WriteHeader(tt.status)
		}))
		c, _ := Open(s.URL, Options{Token: "private-fixture"}, s.Client())
		_, err := c.Request(context.Background(), "initialize", map[string]any{})
		s.Close()
		if !errors.Is(err, tt.want) || err.Error() != tt.text {
			t.Fatalf("%d: %v, want %v %q", tt.status, err, tt.want, tt.text)
		}
	}
}

// A message the server writes at exactly its limit is read; one byte more is
// refused before any of it is parsed -- the client's screen, handed each
// message it goes on to read, is not handed it -- and the refusal names the
// limit of that kind of answer: initialize's, a tool list page's, a tool
// call's, as JSON and as an event stream.
func TestAnswerLimitsAreHeldBeforeParsing(t *testing.T) {
	const initialize, list, call = 300, 400, 500
	var size int
	var garbage bool // the last byte is no JSON
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
		}
		json.NewDecoder(r.Body).Decode(&request)
		if r.Method == "DELETE" || request.ID == 0 {
			w.WriteHeader(202)
			return
		}
		result := map[string]string{"initialize": `{"protocolVersion":"2025-06-18"}`, "tools/list": `{"tools":[]}`, "tools/call": `{"content":[]}`}[request.Method]
		message := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":%s}`, request.ID, result)
		var out string
		if r.Header.Get("X-Events") != "" {
			// "data: " and the blank line after are part of the stream.
			out = "data: " + message + strings.Repeat(" ", size-len(message)-len("data: ")-2)
			if garbage {
				out = out[:len(out)-1] + "x"
			}
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, out+"\n\n")
			return
		}
		out = message + strings.Repeat(" ", size-len(message))
		if garbage {
			out = out[:len(out)-1] + "x"
		}
		w.Header().Set("Content-Type", "application/json")
		// Flushed in two, so the body is chunked and carries no length the
		// client could refuse it by before reading.
		io.WriteString(w, out[:1])
		w.(http.Flusher).Flush()
		io.WriteString(w, out[1:])
	}))
	defer server.Close()
	for _, events := range []bool{false, true} {
		screened := 0
		headers := http.Header{}
		if events {
			headers.Set("X-Events", "1")
		}
		c, err := Open(server.URL, Options{Headers: headers, MaxResponse: 100000, InitializeLimit: initialize, ListLimit: list, CallLimit: call,
			Screen: func([]byte, string) bool { screened++; return false }}, server.Client())
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		step := func(name string, limit int, run func() error) {
			t.Helper()
			size, garbage = limit, false
			before := screened
			if err := run(); err != nil {
				t.Fatalf("%s at its limit (events %v): %v", name, events, err)
			}
			if screened != before+1 {
				t.Fatalf("%s at its limit is read once: %d", name, screened-before)
			}
			// Past the limit the body is still valid JSON, so only the order of
			// the checks -- the screen is handed a message after it is parsed --
			// shows whether it was read.
			size, garbage = limit+1, false
			before = screened
			err := run()
			if !errors.Is(err, ErrLimit) || !strings.Contains(err.Error(), fmt.Sprintf("exceeds the bound of %d bytes", limit)) {
				t.Fatalf("%s one byte past its limit (events %v): %v", name, events, err)
			}
			if screened != before {
				t.Fatalf("%s past its limit was read", name)
			}
		}
		// initialize may be repeated until negotiated; the session id is not
		// recorded by this server, so a second one is a fresh request.
		step("initialize", initialize, func() error { _, err := c.Request(ctx, "initialize", map[string]any{}); return err })
		size, garbage = initialize, false
		if err := c.Negotiated(ctx, "2025-06-18"); err != nil {
			t.Fatal(err)
		}
		step("tools/list", list, func() error { _, err := c.Request(ctx, "tools/list", map[string]any{}); return err })
		step("tools/call", call, func() error { _, err := c.CallTool(ctx, "any", map[string]any{}); return err })
	}
}
