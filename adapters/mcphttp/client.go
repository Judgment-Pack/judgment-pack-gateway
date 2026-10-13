// Package mcphttp implements bounded Streamable HTTP for gateway companions.
// It serves no sampling, roots, elicitation, or other server-initiated requests.
// The caller supplies a reviewed endpoint and an explicit tool allowlist:
// New for a connection's own client, Open for adapter-mcp's remote form.
package mcphttp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

// Error is one of the errors above with what happened in words: the status
// a server answered, the error it answered with, the reason an answer was
// not read. It is what errors.Is matches as its kind, so a caller that maps
// the kinds reads it as before. Its text never carries the credential, nor a
// redirect's location: an answer that repeats the credential is refused
// before anything of it is read into an error.
type Error struct {
	Kind   error
	Detail string
}

func (e *Error) Error() string { return e.Detail }
func (e *Error) Unwrap() error { return e.Kind }

func fault(kind error, format string, args ...any) error {
	return &Error{Kind: kind, Detail: fmt.Sprintf(format, args...)}
}

// Client is used serially within one operation. Credentials never occur in errors.
type Client struct {
	endpoint, token, session, version string
	allowed                           map[string]bool
	http                              *http.Client
	next                              int
	// anyTool is a client opened without a tool list (Open): its caller
	// holds the allowlist, and the client lets a call name any tool.
	anyTool bool
	// headers are sent on every request before the client's own, which a
	// fixed header cannot replace.
	headers http.Header
	// limit bounds each answer; MaxResponse for New.
	limit int64
	// initializeLimit, listLimit and callLimit bound the answers to
	// initialize, to tools/list and to tools/call, each the whole body of
	// the answer (or the whole event stream): limit where Options gave none.
	initializeLimit, listLimit, callLimit int64
	// kinded is a client opened with a limit of a kind: its refusals name
	// the kind of answer. refuseEncoding is Options.RefuseEncoding.
	kinded, refuseEncoding bool
	// requestLimit bounds each request this client sends: 64 KiB for New,
	// and for Open what a request on adapter-mcp's stdin may hold, 1 MiB,
	// with room for the message around it.
	requestLimit int
	// refuseSession is a client opened by Open: an answer that repeats the
	// session id is refused, since its caller records what it reads.
	refuseSession bool
	// peer is the TLS identity the last answer to a request came under,
	// "tls:sha256:" and the digest of the leaf certificate; "" over
	// plaintext.
	peer string
	// screen is the caller's Options.Screen, or nil.
	screen func(message []byte, session string) bool
}

// Options is how Open configures a client for adapter-mcp's remote form.
type Options struct {
	// Token, when given, is sent as "Authorization: Bearer"; a server that
	// takes no credential is given none.
	Token string
	// Headers are sent on every request as given. The caller holds them to
	// their names: a credential's header, and the headers this client
	// writes itself, are not among them.
	Headers http.Header
	// MaxResponse bounds each answer; zero is MaxResponse.
	MaxResponse int64
	// InitializeLimit, ListLimit and CallLimit bound the whole answer -- a
	// JSON body, or an event stream with every comment and notification in
	// it -- to initialize, to one page of tools/list and to tools/call; an
	// answer one byte past its limit is refused, and the refusal names the
	// kind of answer. A JSON body is read whole, to the limit and one byte
	// more, before any of it is parsed. An event stream is held to the limit
	// as a whole -- every byte read, comments and notifications included --
	// and to it for each event, but its events are parsed as they arrive,
	// and the response to the request ends the reading: what follows it is
	// not read. Zero is MaxResponse's value for that kind of answer.
	InitializeLimit, ListLimit, CallLimit int64
	// RefuseEncoding refuses an answer that names a Content-Encoding other
	// than identity, before any of it is read. A caller that sets it also
	// turns the transport's automatic decompression off, which would
	// otherwise decode the body before the limits above see it.
	RefuseEncoding bool
	// Tools are the only tools a call may name; nil lets a call name any
	// tool, the caller holding its own allowlist.
	Tools []string
	// Screen, when given, is handed each complete message the server
	// answers with -- a JSON body, or one event of a stream -- and the
	// session id the server issued ("" before it issues one), after the
	// client's own checks and before any member of it is read or acted on;
	// a message it reports true for is refused, and nothing of it is read.
	// A caller that holds credentials this client does not know -- other
	// connections', a client secret -- screens for them here.
	Screen func(message []byte, session string) bool
}

// EndpointProblem is why endpoint is not one a client is opened on, or nil:
// https, or http at a loopback address written as one -- an IPv4 address
// of 127.0.0.0/8 in dotted decimal, or [::1] -- since a credential sent in
// the clear is a credential given away; no user, no query, no fragment; at
// most 2048 bytes of printable ASCII. The endpoint is used as written.
func EndpointProblem(endpoint string) error {
	if endpoint == "" || len(endpoint) > 2048 {
		return errors.New("the url is empty or longer than 2048 bytes")
	}
	for i := 0; i < len(endpoint); i++ {
		if endpoint[i] < 0x21 || endpoint[i] > 0x7e {
			return errors.New("the url carries a byte outside printable ASCII")
		}
	}
	rest, plain := "", false
	switch {
	case strings.HasPrefix(endpoint, "https://"):
		rest = endpoint[len("https://"):]
	case strings.HasPrefix(endpoint, "http://"):
		rest, plain = endpoint[len("http://"):], true
	default:
		return errors.New("the url must begin https:// (or http:// at a loopback address), in lower case")
	}
	if strings.ContainsAny(endpoint, "?#") {
		return errors.New("the url carries a query or a fragment; it is used as written, and a credential's place is the credentials file")
	}
	authority, _, _ := strings.Cut(rest, "/")
	if authority == "" {
		return errors.New("the url names no host")
	}
	if strings.Contains(authority, "@") {
		return errors.New("the url carries a user: a credential's place is the credentials file")
	}
	if plain && !LoopbackAuthority(authority) {
		return errors.New("the url must be https; http is accepted at a loopback address written as one (127.0.0.0/8 in dotted decimal, or [::1]) only, since a credential sent in the clear is a credential given away")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return errors.New("the url is not an absolute URL of a host")
	}
	return nil
}

// LoopbackAuthority reports whether authority -- a URL's host, with its
// port when it has one -- is a loopback address written as one: an IPv4
// address of 127.0.0.0/8 in dotted decimal, each part 0 to 255 with no
// leading zero, or [::1]; a port, when given, in decimal from 1 to 65535
// with no leading zero. A name is not one, localhost included: what a name
// resolves to is not in the text.
func LoopbackAuthority(authority string) bool {
	host, port := authority, ""
	if strings.HasPrefix(authority, "[::1]") {
		host, port = "[::1]", strings.TrimPrefix(authority, "[::1]")
		if port != "" && !strings.HasPrefix(port, ":") {
			return false
		}
		port = strings.TrimPrefix(port, ":")
		if strings.HasSuffix(authority, ":") {
			return false
		}
	} else if h, p, found := strings.Cut(authority, ":"); found {
		if p == "" {
			return false
		}
		host, port = h, p
	}
	if port != "" && !decimalIn(port, 1, 65535) {
		return false
	}
	if host == "[::1]" {
		return true
	}
	parts := strings.Split(host, ".")
	if len(parts) != 4 || parts[0] != "127" {
		return false
	}
	for _, part := range parts {
		if !decimalIn(part, 0, 255) {
			return false
		}
	}
	return true
}

// decimalIn: digits only, no leading zero, within [low, high].
func decimalIn(s string, low, high int) bool {
	if s == "" || len(s) > 5 || (len(s) > 1 && s[0] == '0') {
		return false
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
		n = n*10 + int(r-'0')
	}
	return n >= low && n <= high
}

// Open is a client for adapter-mcp's remote form: the endpoint as
// EndpointProblem holds it, a bearer token only when one is given, fixed
// headers, a bound on each answer, and redirects never followed whatever
// the transport says.
func Open(endpoint string, opts Options, transport *http.Client) (*Client, error) {
	if err := EndpointProblem(endpoint); err != nil {
		return nil, &Error{Kind: ErrProtocol, Detail: err.Error()}
	}
	if len(opts.Token) > 8192 || strings.ContainsAny(opts.Token, "\r\n\x00") {
		return nil, fault(ErrProtocol, "the credential is not one a header can carry")
	}
	if transport == nil {
		transport = HTTPClient()
	}
	h := *transport
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	limit := opts.MaxResponse
	if limit <= 0 {
		limit = MaxResponse
	}
	own := func(n int64) int64 {
		if n <= 0 {
			return limit
		}
		return n
	}
	c := &Client{endpoint: endpoint, token: opts.Token, allowed: map[string]bool{}, http: &h, headers: opts.Headers.Clone(), limit: limit,
		initializeLimit: own(opts.InitializeLimit), listLimit: own(opts.ListLimit), callLimit: own(opts.CallLimit),
		kinded: opts.InitializeLimit > 0 || opts.ListLimit > 0 || opts.CallLimit > 0, refuseEncoding: opts.RefuseEncoding, requestLimit: 2 << 20, anyTool: opts.Tools == nil, refuseSession: true, screen: opts.Screen}
	for _, name := range opts.Tools {
		if name == "" {
			return nil, ErrTool
		}
		c.allowed[name] = true
	}
	return c, nil
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
	c := &Client{endpoint: endpoint, token: token, allowed: map[string]bool{}, http: &h, limit: MaxResponse, initializeLimit: MaxResponse, listLimit: MaxResponse, callLimit: MaxResponse, requestLimit: 64 << 10}
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
	_, err = c.post(ctx, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}, 0, 0, "")
	return err
}
func (c *Client) CallTool(ctx context.Context, name string, args any) (json.RawMessage, error) {
	if c.version == "" || !(c.allowed[name] || c.anyTool && name != "") {
		return nil, ErrTool
	}
	return c.call(ctx, "tools/call", map[string]any{"name": name, "arguments": args})
}

// Request sends one request other than a tool call and returns its result
// as the server wrote it: initialize first, which is answered with the
// session the server issues, then, once Negotiated, anything the caller
// reads for itself -- tools/list a page at a time. A tool call goes through
// CallTool, which holds the allowlist.
func (c *Client) Request(ctx context.Context, method string, params any) (json.RawMessage, error) {
	if method == "tools/call" {
		return nil, ErrTool
	}
	if (method == "initialize") != (c.version == "") {
		return nil, fault(ErrProtocol, "%s is not a request for this point of the session", method)
	}
	return c.call(ctx, method, params)
}

// Negotiated records the protocol version the caller accepted from the
// server's answer to initialize, which every later request names, and then
// tells the server the client is initialized.
func (c *Client) Negotiated(ctx context.Context, version string) error {
	if c.version != "" || version == "" {
		return fault(ErrProtocol, "the session was negotiated already")
	}
	c.version = version
	_, err := c.post(ctx, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}, 0, 0, "")
	return err
}

// SessionID is the session id the server issued, "" before initialize or
// when it issued none: for a caller's redaction set, never for a record.
func (c *Client) SessionID() string { return c.session }

// PeerIdentity is the TLS identity the last answer to a request came
// under -- "tls:sha256:" and the SHA-256 of the leaf certificate the server
// presented -- or "" when it came over plaintext.
func (c *Client) PeerIdentity() string { return c.peer }

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
	c.setHeaders(req)
	resp, err := c.http.Do(req)
	if err == nil {
		resp.Body.Close()
	}
	c.session = ""
}
func (c *Client) setHeaders(r *http.Request) {
	for name, values := range c.headers {
		r.Header[name] = append([]string(nil), values...)
	}
	if c.token != "" {
		r.Header.Set("Authorization", "Bearer "+c.token)
	}
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
	limit := c.limit
	switch method {
	case "initialize":
		limit = c.initializeLimit
	case "tools/list":
		limit = c.listLimit
	case "tools/call":
		limit = c.callLimit
	}
	return c.post(ctx, map[string]any{"jsonrpc": "2.0", "id": c.next, "method": method, "params": params}, c.next, limit, method)
}

// exceeded is the refusal of an answer past its limit: the number, and for a
// client with limits of its kinds the method the answer was to -- a fixed
// label, never any of the body.
func (c *Client) exceeded(method string, limit int64) error {
	if c.kinded && method != "" {
		return fault(ErrLimit, "the server's answer to %s exceeds the bound of %d bytes", method, limit)
	}
	return fault(ErrLimit, "the server's answer exceeds the bound of %d bytes", limit)
}

// post sends one message and reads its answer, no further than limit bytes:
// past it the answer is refused before any of it is parsed.
func (c *Client) post(ctx context.Context, message any, id int, limit int64, method string) (json.RawMessage, error) {
	raw, err := json.Marshal(message)
	if err != nil || len(raw) > c.requestLimit {
		return nil, fault(ErrLimit, "the request exceeds %d bytes", c.requestLimit)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, ErrProtocol
	}
	c.setHeaders(req)
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fault(ErrUnavailable, "the server did not answer in time: %v", ctx.Err())
		}
		// The transport's reason, without the URL it wraps it in: the URL
		// is the operator's, and the reason is what says why.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return nil, fault(ErrUnavailable, "the server could not be reached: %v", err)
	}
	defer resp.Body.Close()
	status := fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	if resp.StatusCode == 401 {
		return nil, fault(ErrUnauthorized, "the server answered %s", status)
	}
	// A redirect is an answer from another resource than the one the
	// operator fixed, and following one would carry the credential there.
	// It is named by its status alone: the location is the server's.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, fault(ErrUnavailable, "the server answered %s, a redirect, which is not followed", status)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fault(ErrUnavailable, "the server answered %s", status)
	}
	if id == 0 {
		if resp.StatusCode != 202 {
			return nil, fault(ErrProtocol, "the server answered a notification with %s, not 202 Accepted", status)
		}
		return nil, nil
	}
	// The identity this answer came under: the one a result is read from
	// is the one a caller records.
	c.peer = ""
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		sum := sha256.Sum256(resp.TLS.PeerCertificates[0].Raw)
		c.peer = "tls:sha256:" + hex.EncodeToString(sum[:])
	}
	if c.refuseEncoding {
		if resp.Uncompressed {
			return nil, fault(ErrProtocol, "the server's answer was encoded, which this client does not accept")
		}
		for _, value := range resp.Header.Values("Content-Encoding") {
			if value != "" && !strings.EqualFold(strings.TrimSpace(value), "identity") {
				return nil, fault(ErrProtocol, "the server's answer is encoded, which this client does not accept")
			}
		}
	}
	if resp.ContentLength > limit {
		return nil, c.exceeded(method, limit)
	}
	if c.version == "" {
		session := resp.Header.Get("Mcp-Session-Id")
		if len(session) > 1024 {
			return nil, fault(ErrProtocol, "the server issued a session id longer than 1024 bytes")
		}
		for _, r := range session {
			if r < 0x21 || r > 0x7e {
				return nil, fault(ErrProtocol, "the server issued a session id outside visible ASCII")
			}
		}
		c.session = session
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, fault(ErrProtocol, "the server's answer names no content type a client reads")
	}
	if media == "application/json" {
		body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err != nil {
			return nil, fault(ErrUnavailable, "the server's answer could not be read whole")
		}
		if int64(len(body)) > limit {
			return nil, c.exceeded(method, limit)
		}
		result, done, err := c.message(ctx, body, id)
		if !done && err == nil {
			return nil, fault(ErrProtocol, "the server's answer is not the response to the request")
		}
		return result, err
	}
	if media != "text/event-stream" {
		// The type is the server's text, and is not repeated.
		return nil, fault(ErrProtocol, "the server's answer is of a content type that is neither application/json nor text/event-stream")
	}
	// Bound the entire stream, including comments/notifications, not just its result.
	limited := &io.LimitedReader{R: resp.Body, N: limit + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), int(min(limit, 1<<30)))
	var event bytes.Buffer
	events := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		if limited.N <= 0 {
			return nil, c.exceeded(method, limit)
		}
		if len(line) == 0 {
			if event.Len() == 0 {
				continue
			}
			events++
			if events > 64 {
				return nil, fault(ErrLimit, "the server's answer carries more than 64 events")
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
			if int64(event.Len()+len(value)+1) > limit {
				return nil, c.exceeded(method, limit)
			}
			event.Write(value)
			event.WriteByte('\n')
		}
	}
	// A line longer than the limit stops the scanner before the sentinel
	// byte is read: that is the bound too.
	if errors.Is(scanner.Err(), bufio.ErrTooLong) || limited.N <= 0 {
		return nil, c.exceeded(method, limit)
	}
	// Incomplete events and disconnected streams are not success.
	return nil, fault(ErrProtocol, "the server's event stream ended before the response")
}
func (c *Client) message(ctx context.Context, body []byte, id int) (json.RawMessage, bool, error) {
	// An answer that repeats the credential is refused before anything of
	// it is read: a token is never carried into a result or an error.
	if c.token != "" && bytes.Contains(body, []byte(c.token)) {
		return nil, false, fault(ErrProtocol, "the server's answer repeats the credential")
	}
	normalized, err := canon.Canonicalize(body, canon.CarryNumbersAsText)
	if err != nil {
		return nil, false, fault(ErrProtocol, "the server's answer is not a JSON message in the canonical domain")
	}
	if c.token != "" && bytes.Contains(normalized, []byte(c.token)) {
		return nil, false, fault(ErrProtocol, "the server's answer repeats the credential")
	}
	// Nor is the session id the server issued -- the initialize answer's
	// own body included, its header read first -- carried into a result or
	// an error: a client opened for a caller that records what it reads
	// refuses an answer that repeats it, as written or as decoded. A
	// connection's own client (New) keeps its answers as they were.
	if c.refuseSession && c.session != "" && (bytes.Contains(body, []byte(c.session)) || bytes.Contains(normalized, []byte(c.session))) {
		return nil, false, fault(ErrProtocol, "the server's answer repeats its session id")
	}
	// Nor anything the caller's screen finds in the whole message, before
	// any member of it is read.
	if c.screen != nil && c.screen(body, c.session) {
		return nil, false, fault(ErrProtocol, "the server's answer repeats the credential or its session id, and is not kept")
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil || string(m["jsonrpc"]) != `"2.0"` {
		return nil, false, fault(ErrProtocol, "the server's answer is not a JSON-RPC 2.0 message")
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
			_, err := c.post(ctx, map[string]any{"jsonrpc": "2.0", "id": requestID, key: response}, 0, 0, "")
			if err != nil {
				return nil, false, err
			}
		}
		return nil, false, nil
	}
	if string(m["id"]) != strconv.Itoa(id) {
		return nil, false, fault(ErrProtocol, "the server answered another request than the one sent")
	}
	result, ok := m["result"]
	rpcError, failed := m["error"]
	if ok == failed {
		return nil, false, fault(ErrProtocol, "the server's response carries both a result and an error, or neither")
	}
	if failed {
		// The server's refusal in its own words, as the stdio form reports
		// one: its message and its code.
		var e struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		json.Unmarshal(rpcError, &e)
		return nil, false, fault(ErrUnavailable, "the server answered with an error: %s (code %d)", e.Message, e.Code)
	}
	return result, true, nil
}
