package mcphttp

import (
	"context"
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
