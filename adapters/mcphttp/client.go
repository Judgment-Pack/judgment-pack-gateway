// Package mcphttp implements bounded Streamable HTTP for gateway companions.
// It serves no sampling, roots, elicitation, or other server-initiated requests.
// The caller supplies a reviewed endpoint and an explicit tool allowlist.
package mcphttp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"adapters/internal/canon"
)

const MaxResponse = 8 << 20

var ErrProtocol = errors.New("invalid-mcp-response")
var ErrUnavailable = errors.New("provider-unavailable")
var ErrUnauthorized = errors.New("reconnect-required")
var ErrLimit = errors.New("provider-response-too-large")
var ErrTool = errors.New("tool-not-allowed")

// Client is used serially within one operation. Credentials never occur in errors.
type Client struct {
	endpoint, token, session, version string
	allowed                           map[string]bool
	http                              *http.Client
	next                              int
}

func HTTPClient() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	t.MaxResponseHeaderBytes = 64 << 10
	t.ResponseHeaderTimeout = 15 * time.Second
	t.TLSHandshakeTimeout = 10 * time.Second
	t.DialContext = (&net.Dialer{Timeout: 10 * time.Second}).DialContext
	return &http.Client{Transport: t, Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func New(endpoint, token string, allowed []string, transport *http.Client) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(token) == 0 || len(token) > 8192 || strings.ContainsAny(token, "\r\n\x00") {
		return nil, ErrProtocol
	}
	if transport == nil {
		transport = HTTPClient()
	}
	// A caller's client may supply a fixture transport, but cannot enable redirects.
	h := *transport
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	h.Timeout = 45 * time.Second
	c := &Client{endpoint: endpoint, token: token, allowed: map[string]bool{}, http: &h}
	for _, name := range allowed {
		if name == "" || len(name) > 128 {
			return nil, ErrTool
		}
		c.allowed[name] = true
	}
	return c, nil
}
func (c *Client) Initialize(ctx context.Context) error {
	raw, err := c.call(ctx, "initialize", map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "judgment-pack-gateway", "version": "1"}})
	if err != nil {
		return err
	}
	var v struct {
		Protocol string `json:"protocolVersion"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return ErrProtocol
	}
	switch v.Protocol {
	case "2025-11-25", "2025-06-18", "2025-03-26":
		c.version = v.Protocol
	default:
		return ErrProtocol
	}
	_, err = c.post(ctx, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}, 0)
	return err
}
func (c *Client) CallTool(ctx context.Context, name string, args any) (json.RawMessage, error) {
	if c.version == "" || !c.allowed[name] {
		return nil, ErrTool
	}
	return c.call(ctx, "tools/call", map[string]any{"name": name, "arguments": args})
}

// Tools lists only explicitly allowed tools. Tool annotations never grant permission.
func (c *Client) Tools(ctx context.Context) (map[string]json.RawMessage, error) {
	if c.version == "" {
		return nil, ErrProtocol
	}
	out := map[string]json.RawMessage{}
	cursor := ""
	seen := map[string]bool{}
	budget := MaxResponse
	for page := 0; page < 16; page++ {
		params := map[string]string{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		raw, err := c.call(ctx, "tools/list", params)
		if err != nil {
			return nil, err
		}
		budget -= len(raw)
		if budget < 0 {
			return nil, ErrLimit
		}
		var r struct {
			Tools []struct {
				Name   string          `json:"name"`
				Schema json.RawMessage `json:"inputSchema"`
			} `json:"tools"`
			Next string `json:"nextCursor"`
		}
		if json.Unmarshal(raw, &r) != nil || len(r.Tools) > 1024 {
			return nil, ErrProtocol
		}
		for _, t := range r.Tools {
			if c.allowed[t.Name] {
				if _, exists := out[t.Name]; exists {
					return nil, ErrProtocol
				}
				out[t.Name] = t.Schema
			}
		}
		if r.Next == "" {
			return out, nil
		}
		if len(r.Next) > 4096 || seen[r.Next] {
			return nil, ErrProtocol
		}
		seen[r.Next] = true
		cursor = r.Next
	}
	return nil, ErrLimit
}
func (c *Client) Close(ctx context.Context) {
	if c.session == "" {
		return
	}
	req, err := http.NewRequestWithContext(ctx, "DELETE", c.endpoint, nil)
	if err != nil {
		return
	}
	c.headers(req)
	resp, err := c.http.Do(req)
	if err == nil {
		resp.Body.Close()
	}
	c.session = ""
}
func (c *Client) headers(r *http.Request) {
	r.Header.Set("Authorization", "Bearer "+c.token)
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("Content-Type", "application/json")
	if c.session != "" {
		r.Header.Set("Mcp-Session-Id", c.session)
	}
	if c.version != "" {
		r.Header.Set("Mcp-Protocol-Version", c.version)
	}
}
func (c *Client) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	c.next++
	return c.post(ctx, map[string]any{"jsonrpc": "2.0", "id": c.next, "method": method, "params": params}, c.next)
}
func (c *Client) post(ctx context.Context, message any, id int) (json.RawMessage, error) {
	raw, err := json.Marshal(message)
	if err != nil || len(raw) > 64<<10 {
		return nil, ErrLimit
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, ErrProtocol
	}
	c.headers(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		return nil, ErrUnauthorized
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, ErrUnavailable
	}
	if id == 0 {
		if resp.StatusCode != 202 {
			return nil, ErrProtocol
		}
		return nil, nil
	}
	if resp.ContentLength > MaxResponse {
		return nil, ErrLimit
	}
	if c.version == "" {
		session := resp.Header.Get("Mcp-Session-Id")
		if len(session) > 1024 {
			return nil, ErrProtocol
		}
		for _, r := range session {
			if r < 0x21 || r > 0x7e {
				return nil, ErrProtocol
			}
		}
		c.session = session
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, ErrProtocol
	}
	if media == "application/json" {
		body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse+1))
		if err != nil {
			return nil, ErrUnavailable
		}
		if len(body) > MaxResponse {
			return nil, ErrLimit
		}
		result, done, err := c.message(ctx, body, id)
		if !done && err == nil {
			return nil, ErrProtocol
		}
		return result, err
	}
	if media != "text/event-stream" {
		return nil, ErrProtocol
	}
	// Bound the entire stream, including comments/notifications, not just its result.
	limited := &io.LimitedReader{R: resp.Body, N: MaxResponse + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), MaxResponse)
	var event bytes.Buffer
	events := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		if limited.N <= 0 {
			return nil, ErrLimit
		}
		if len(line) == 0 {
			if event.Len() == 0 {
				continue
			}
			events++
			if events > 64 {
				return nil, ErrLimit
			}
			result, done, err := c.message(ctx, bytes.TrimSuffix(event.Bytes(), []byte{'\n'}), id)
			event.Reset()
			if err != nil || done {
				return result, err
			}
			continue
		}
		if bytes.HasPrefix(line, []byte("data:")) {
			value := bytes.TrimPrefix(line, []byte("data:"))
			value = bytes.TrimPrefix(value, []byte(" "))
			if event.Len()+len(value)+1 > MaxResponse {
				return nil, ErrLimit
			}
			event.Write(value)
			event.WriteByte('\n')
		}
	}
	if limited.N <= 0 {
		return nil, ErrLimit
	}
	return nil, ErrProtocol // Incomplete events and disconnected streams are not success.
}
func (c *Client) message(ctx context.Context, body []byte, id int) (json.RawMessage, bool, error) {
	if bytes.Contains(body, []byte(c.token)) {
		return nil, false, ErrProtocol
	}
	normalized, err := canon.Canonicalize(body, canon.CarryNumbersAsText)
	if err != nil || bytes.Contains(normalized, []byte(c.token)) {
		return nil, false, ErrProtocol
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil || string(m["jsonrpc"]) != `"2.0"` {
		return nil, false, ErrProtocol
	}
	if method, ok := m["method"]; ok {
		var name string
		if json.Unmarshal(method, &name) != nil || name == "" {
			return nil, false, ErrProtocol
		}
		if _, ok := m["result"]; ok {
			return nil, false, ErrProtocol
		}
		if _, ok := m["error"]; ok {
			return nil, false, ErrProtocol
		}
		if requestID, ok := m["id"]; ok {
			var response any = map[string]any{"code": -32601, "message": "This client serves no requests"}
			key := "error"
			if name == "ping" {
				key = "result"
				response = map[string]any{}
			}
			_, err := c.post(ctx, map[string]any{"jsonrpc": "2.0", "id": requestID, key: response}, 0)
			if err != nil {
				return nil, false, err
			}
		}
		return nil, false, nil
	}
	if string(m["id"]) != strconv.Itoa(id) {
		return nil, false, ErrProtocol
	}
	result, ok := m["result"]
	_, fault := m["error"]
	if ok == fault {
		return nil, false, ErrProtocol
	}
	if fault {
		return nil, false, ErrUnavailable
	}
	return result, true, nil
}
