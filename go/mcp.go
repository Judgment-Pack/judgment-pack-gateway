package main

// The engine as an MCP server (docs/design/mcp-server.md): a fifth process
// that is a client of the signer's HTTP surface and nothing more. It holds no
// key, no credential and no store; it reads the configuration as metadata,
// verifies the caller's token as the signer does, and turns a tool call into
// a POST /acquire under that token. What comes back is the signer's answer,
// carried whole; what is refused is refused with the signer's reason; what
// is not known is said to be unknown.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	mcpProtocolVersion = "2025-06-18"
	// mcpSessionMeta is the metadata member by which a call names the
	// receipt session it chains into; without it the transport session's
	// generated one is used.
	mcpSessionMeta = "io.judgment-pack/session"
	// mcpSealTool is the one tool that is the engine's own.
	mcpSealTool = "engine.seal"
	// mcpForwardTimeout bounds one forward: the signer's thirty-second
	// source deadline, its five-second wait for the source's pipes, and a
	// margin.
	mcpForwardTimeout = 45 * time.Second
	// mcpQueueWait is how long a call waits for a forward slot.
	mcpQueueWait = 10 * time.Second
	// mcpMaxAnswerBytes bounds what the signer's answer may be.
	mcpMaxAnswerBytes = 8 << 20
	// mcpMaxMessageBytes bounds one JSON-RPC message.
	mcpMaxMessageBytes = 1 << 20
)

// mcpTool is one entry of the tool table: a platform's live tool, or the
// seal tool.
type mcpTool struct {
	name     string
	platform string
	tool     string
	binding  string
	seal     bool
}

// mcpSession is one transport session: over HTTP one per Mcp-Session-Id,
// over stdio one per process. It carries the receipt session generated for
// it and its rate window.
type mcpSession struct {
	id             string
	receiptSession string
	lastUsed       time.Time
	windowStart    time.Time
	windowCount    int
	initialized    bool
}

// mcpServer is the server's state: the table, the identity, the signer's
// address, the bounds, and the transport sessions.
type mcpServer struct {
	cfg      engineConfig
	tools    map[string]mcpTool
	order    []string
	identity *identityConfig
	signer   string // http://listen
	client   *http.Client
	now      func() time.Time
	newID    func() string
	forwards chan struct{} // one token per forward in flight
	queue    chan struct{} // one token per call waiting
	// forwardTimeout bounds one forward; mcpForwardTimeout unless a test
	// shortens it
	forwardTimeout time.Duration
	mu             sync.Mutex
	sessions       map[string]*mcpSession
}

// newMCPServer builds the server from a resolved configuration and its
// bindings: the tool table from every platform's live tools, the seal tool
// beside them, a collision a refusal.
func newMCPServer(cfg engineConfig, bindings map[string]binding, identity *identityConfig) (*mcpServer, error) {
	if cfg.mcp == nil {
		return nil, errors.New("the configuration has no mcp member; the MCP server needs one")
	}
	s := &mcpServer{
		cfg:      cfg,
		tools:    map[string]mcpTool{},
		identity: identity,
		signer:   "http://" + cfg.listen,
		client:   &http.Client{},
		now:      time.Now,
		newID:    randomSessionName,
		forwards: make(chan struct{}, cfg.mcp.concurrency),
		queue:    make(chan struct{}, cfg.mcp.concurrency),
		sessions: map[string]*mcpSession{},

		forwardTimeout: mcpForwardTimeout,
	}
	add := func(t mcpTool) error {
		if other, taken := s.tools[t.name]; taken {
			return fmt.Errorf("tool name %q would name both %s and %s; rename a platform", t.name, describeTool(other), describeTool(t))
		}
		s.tools[t.name] = t
		s.order = append(s.order, t.name)
		return nil
	}
	if err := add(mcpTool{name: mcpSealTool, seal: true}); err != nil {
		return nil, err
	}
	for _, p := range cfg.platforms { // in name order
		b, ok := bindings[p.name]
		if !ok || b.live == nil {
			continue
		}
		for _, tool := range b.live.tools {
			if err := add(mcpTool{name: p.name + "." + tool, platform: p.name, tool: tool, binding: p.binding}); err != nil {
				return nil, err
			}
		}
	}
	sort.Strings(s.order)
	return s, nil
}

func describeTool(t mcpTool) string {
	if t.seal {
		return "the engine's seal tool"
	}
	return fmt.Sprintf("tool %s of platform %s", t.tool, t.platform)
}

// randomSessionName is a receipt session name the server generates: mcp-
// and 128 bits of the system's randomness in lowercase hex, which §3a
// admits and which two processes repeat with negligible probability.
func randomSessionName() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("no randomness for a session name: " + err.Error())
	}
	return "mcp-" + hex.EncodeToString(b[:])
}

// newSession opens a transport session, with a receipt session of its own.
func (s *mcpServer) newSession() *mcpSession {
	return &mcpSession{id: s.newID(), receiptSession: s.newID(), lastUsed: s.now()}
}

// --- JSON-RPC ---------------------------------------------------------------

// jsonrpcError is a JSON-RPC error answer.
type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const (
	rpcParse          = -32700
	rpcInvalidRequest = -32600
	rpcMethodNotFound = -32601
	rpcInvalidParams  = -32602
)

// mcpRequest is one JSON-RPC message as the transport hands it over: the
// raw id (a request has one; a notification has none), the method, the
// params as bytes.
type mcpRequest struct {
	id     json.RawMessage
	method string
	params json.RawMessage
	// isResponse says the message answers something -- a client's response
	// to a server request, which this server never sends -- and is
	// acknowledged and ignored.
	isResponse bool
}

// parseMCPMessage reads one JSON-RPC message: an object with jsonrpc
// "2.0"; an array (a batch) is refused, as the pinned protocol does not
// carry them.
func parseMCPMessage(data []byte) (mcpRequest, *jsonrpcError) {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) == 0 {
		return mcpRequest{}, &jsonrpcError{rpcParse, "empty message"}
	}
	if trimmed[0] == '[' {
		return mcpRequest{}, &jsonrpcError{rpcInvalidRequest, "a batch is not accepted under protocol " + mcpProtocolVersion}
	}
	// The message is read by exact member names with no duplicate, as the
	// signer reads what it signs; but the canon domain's number rule is
	// the signer's to apply to the arguments it is handed, not this
	// server's to apply to every protocol member, so the walk here judges
	// structure alone.
	if !json.Valid(data) {
		return mcpRequest{}, &jsonrpcError{rpcParse, "the message is not JSON"}
	}
	if err := noDuplicateMembers(data); err != nil {
		return mcpRequest{}, &jsonrpcError{rpcInvalidRequest, err.Error()}
	}
	var m struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return mcpRequest{}, &jsonrpcError{rpcParse, "the message is not JSON-RPC"}
	}
	if m.JSONRPC != "2.0" {
		return mcpRequest{}, &jsonrpcError{rpcInvalidRequest, `jsonrpc must be "2.0"`}
	}
	if m.Method == "" {
		if len(m.Result) > 0 || len(m.Error) > 0 {
			return mcpRequest{isResponse: true, id: m.ID}, nil
		}
		return mcpRequest{}, &jsonrpcError{rpcInvalidRequest, "a message without a method"}
	}
	id := m.ID
	if string(id) == "null" {
		id = nil
	}
	return mcpRequest{id: id, method: m.Method, params: m.Params}, nil
}

// noDuplicateMembers walks a JSON text and refuses an object naming a
// member twice, at any depth, so no member can mean one thing to one
// reader and another to the next.
func noDuplicateMembers(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	type frame struct {
		object bool
		seen   map[string]bool
		key    bool // an object frame expecting a key next
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return errors.New("the message is not JSON")
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{':
				if top != nil && top.object {
					top.key = true
				}
				stack = append(stack, &frame{object: true, seen: map[string]bool{}, key: true})
			case '[':
				if top != nil && top.object {
					top.key = true
				}
				stack = append(stack, &frame{})
			case '}', ']':
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].object {
					stack[len(stack)-1].key = true
				}
			}
		case string:
			if top != nil && top.object && top.key {
				if top.seen[v] {
					return fmt.Errorf("member %q appears twice", v)
				}
				top.seen[v] = true
				top.key = false
				continue
			}
			if top != nil && top.object {
				top.key = true
			}
		default:
			if top != nil && top.object {
				top.key = true
			}
		}
	}
}

// mcpOutcome is what handling one message yields: a response to write (nil
// for a notification or a client's response), or a transport-level refusal
// the HTTP transport turns into its own status.
type mcpOutcome struct {
	response  []byte
	transport *mcpTransportRefusal
}

// mcpTransportRefusal is a refusal the HTTP transport answers with a
// status of its own rather than a JSON-RPC message: the signer's 401.
type mcpTransportRefusal struct {
	status int
	reason string
}

func rpcResult(id json.RawMessage, result any) []byte {
	out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	return out
}

func rpcFailure(id json.RawMessage, e jsonrpcError) []byte {
	if id == nil {
		id = json.RawMessage("null")
	}
	out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "error": e})
	return out
}

// handle answers one message for a transport session under the caller's
// bearer (empty when the engine has no identity). Over stdio the token is
// the one given at start; over HTTP it is the request's.
func (s *mcpServer) handle(ctx context.Context, sess *mcpSession, token string, data []byte) mcpOutcome {
	req, perr := parseMCPMessage(data)
	if perr != nil {
		return mcpOutcome{response: rpcFailure(nil, *perr)}
	}
	if req.isResponse {
		return mcpOutcome{}
	}
	if req.id == nil {
		// a notification: acknowledged without a response, whatever it says
		if req.method == "notifications/initialized" {
			sess.initialized = true
		}
		return mcpOutcome{}
	}
	switch req.method {
	case "initialize":
		info := "devel"
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
			info = bi.Main.Version
		}
		return mcpOutcome{response: rpcResult(req.id, map[string]any{
			"protocolVersion": mcpProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": s.cfg.authority, "version": info},
			"instructions":    "Every tool is a platform's live tool acquired by the engine under its key; the answer carries {session, result, receipt, salts}. A cancelled call is not cancelled at the engine and may still mint a receipt; a retry mints another. Seal a session with " + mcpSealTool + " before verifying it.",
		})}
	case "ping":
		return mcpOutcome{response: rpcResult(req.id, map[string]any{})}
	case "tools/list":
		return mcpOutcome{response: rpcResult(req.id, map[string]any{"tools": s.toolList()})}
	case "tools/call":
		return s.callTool(ctx, sess, token, req)
	default:
		return mcpOutcome{response: rpcFailure(req.id, jsonrpcError{rpcMethodNotFound, "method not supported: " + req.method})}
	}
}

// toolList is what tools/list answers: one page, no cursor.
func (s *mcpServer) toolList() []map[string]any {
	list := make([]map[string]any, 0, len(s.order))
	for _, name := range s.order {
		t := s.tools[name]
		if t.seal {
			list = append(list, map[string]any{
				"name":        t.name,
				"description": "Seal a receipt session at its final count, so it can be verified. Takes the session name; answers the seal record. A session with an acquisition still in flight is refused by the engine.",
				"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"session": map[string]any{"type": "string"}}, "required": []string{"session"}, "additionalProperties": false},
			})
			continue
		}
		list = append(list, map[string]any{
			"name":        t.name,
			"description": fmt.Sprintf("Tool %s of platform %s (binding %s), called by the engine's own adapter under the engine's key. Its arguments are what the platform's server defines; the engine does not read that server's schema. The answer carries {session, result, receipt, salts}.", t.tool, t.platform, t.binding),
			"inputSchema": map[string]any{"type": "object"},
		})
	}
	return list
}

// callTool turns tools/call into the signer's request.
func (s *mcpServer) callTool(ctx context.Context, sess *mcpSession, token string, req mcpRequest) mcpOutcome {
	var params struct {
		Name      string                     `json:"name"`
		Arguments json.RawMessage            `json:"arguments"`
		Meta      map[string]json.RawMessage `json:"_meta"`
	}
	if len(req.params) == 0 || json.Unmarshal(req.params, &params) != nil || params.Name == "" {
		return mcpOutcome{response: rpcFailure(req.id, jsonrpcError{rpcInvalidParams, "tools/call takes {name, arguments}"})}
	}
	tool, ok := s.tools[params.Name]
	if !ok {
		return mcpOutcome{response: rpcFailure(req.id, jsonrpcError{rpcInvalidParams, "unknown tool: " + params.Name})}
	}
	// the receipt session: the one the call names, else the transport
	// session's own
	session := sess.receiptSession
	if raw, named := params.Meta[mcpSessionMeta]; named {
		var named string
		if json.Unmarshal(raw, &named) != nil || named == "" {
			return mcpOutcome{response: rpcFailure(req.id, jsonrpcError{rpcInvalidParams, "_meta." + mcpSessionMeta + " must be a session name"})}
		}
		session = named
	}
	if tool.seal {
		var args map[string]json.RawMessage
		if len(params.Arguments) == 0 || json.Unmarshal(params.Arguments, &args) != nil {
			return mcpOutcome{response: rpcFailure(req.id, jsonrpcError{rpcInvalidParams, mcpSealTool + " takes {session}"})}
		}
		var named string
		if raw, ok := args["session"]; !ok || json.Unmarshal(raw, &named) != nil || named == "" {
			return mcpOutcome{response: rpcFailure(req.id, jsonrpcError{rpcInvalidParams, mcpSealTool + " takes {session}, a session name"})}
		}
		for k := range args {
			if k != "session" {
				return mcpOutcome{response: rpcFailure(req.id, jsonrpcError{rpcInvalidParams, mcpSealTool + " takes {session} and no other member"})}
			}
		}
		session = named
	}
	// the window: a call counts at arrival, whatever becomes of it
	if refusal := s.countCall(sess); refusal != nil {
		return mcpOutcome{response: rpcResult(req.id, toolError(refusal))}
	}
	// the queue and the forward slot
	select {
	case s.queue <- struct{}{}:
	default:
		return mcpOutcome{response: rpcResult(req.id, toolError(map[string]any{"session": session, "outcome": "overload", "error": "the engine's front is full; nothing was forwarded"}))}
	}
	waited := time.NewTimer(mcpQueueWait)
	select {
	case s.forwards <- struct{}{}:
		waited.Stop()
		<-s.queue
	case <-waited.C:
		<-s.queue
		return mcpOutcome{response: rpcResult(req.id, toolError(map[string]any{"session": session, "outcome": "overload", "error": "no forward slot within " + mcpQueueWait.String() + "; nothing was forwarded"}))}
	case <-ctx.Done():
		waited.Stop()
		<-s.queue
		return mcpOutcome{response: rpcResult(req.id, toolError(map[string]any{"session": session, "outcome": "overload", "error": "the call ended before a forward slot was free; nothing was forwarded"}))}
	}
	defer func() { <-s.forwards }()

	var path string
	var body []byte
	if tool.seal {
		path = "/seal"
		body, _ = json.Marshal(map[string]string{"session": session})
	} else {
		path = "/acquire"
		arguments := params.Arguments
		if len(bytes.TrimSpace(arguments)) == 0 {
			arguments = json.RawMessage("{}")
		}
		// the arguments are the client's bytes, inside the wrapper, never
		// decoded and re-encoded on the way: the signer's parser judges them
		sessionJSON, _ := json.Marshal(session)
		sourceJSON, _ := json.Marshal(tool.platform + "/live")
		toolJSON, _ := json.Marshal(tool.tool)
		body = []byte(`{"session":` + string(sessionJSON) + `,"source":` + string(sourceJSON) + `,"arguments":{"tool":` + string(toolJSON) + `,"arguments":` + string(arguments) + `}}`)
	}
	status, answer, err := s.forward(ctx, path, token, body)
	if err != nil {
		return mcpOutcome{response: rpcResult(req.id, toolError(map[string]any{"session": session, "outcome": "unknown", "error": "the engine's answer did not arrive: " + err.Error() + "; the call may have run and minted a receipt"}))}
	}
	if status == http.StatusUnauthorized {
		reason := signerReason(answer)
		return mcpOutcome{
			response:  rpcResult(req.id, toolError(map[string]any{"session": session, "status": status, "error": reason})),
			transport: &mcpTransportRefusal{status: status, reason: reason},
		}
	}
	if status < 200 || status >= 300 {
		return mcpOutcome{response: rpcResult(req.id, toolError(map[string]any{"session": session, "status": status, "error": signerReason(answer)}))}
	}
	if tool.seal {
		var record map[string]json.RawMessage
		if json.Unmarshal(answer, &record) != nil || record == nil {
			return mcpOutcome{response: rpcResult(req.id, toolError(map[string]any{"session": session, "outcome": "unknown", "error": "the engine's seal answer was not an object; the seal may have been written"}))}
		}
		return mcpOutcome{response: rpcResult(req.id, toolSuccess(record))}
	}
	var acquired struct {
		Result  json.RawMessage `json:"result"`
		Receipt json.RawMessage `json:"receipt"`
		Salts   json.RawMessage `json:"salts"`
	}
	if json.Unmarshal(answer, &acquired) != nil || len(acquired.Receipt) == 0 {
		return mcpOutcome{response: rpcResult(req.id, toolError(map[string]any{"session": session, "outcome": "unknown", "error": "the engine's answer was not an acquisition; a receipt may have been minted"}))}
	}
	return mcpOutcome{response: rpcResult(req.id, toolSuccess(map[string]any{"session": session, "result": acquired.Result, "receipt": acquired.Receipt, "salts": acquired.Salts}))}
}

// toolSuccess is a tool result carrying the object as one text block and as
// structuredContent.
func toolSuccess(structured any) map[string]any {
	text, _ := json.Marshal(structured)
	return map[string]any{"content": []map[string]any{{"type": "text", "text": string(text)}}, "structuredContent": structured}
}

// toolError is an error result carrying the object the same two ways and
// the protocol's own flag.
func toolError(structured any) map[string]any {
	r := toolSuccess(structured)
	r["isError"] = true
	return r
}

// countCall counts one call against the transport session's window and
// refuses past the bound, naming the seconds until the window turns.
func (s *mcpServer) countCall(sess *mcpSession) map[string]any {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.windowStart.IsZero() || now.Sub(sess.windowStart) >= time.Minute {
		sess.windowStart, sess.windowCount = now, 0
	}
	sess.windowCount++
	if sess.windowCount > s.cfg.mcp.callsPerMinute {
		wait := time.Minute - now.Sub(sess.windowStart)
		return map[string]any{"session": sess.receiptSession, "outcome": "overload", "error": fmt.Sprintf("%d calls in this window already; nothing was forwarded", s.cfg.mcp.callsPerMinute), "retryAfterSeconds": int(wait.Seconds()) + 1}
	}
	return nil
}

// forward sends one request to the signer under the caller's token and
// returns the status and the answer's bytes, bounded.
func (s *mcpServer) forward(ctx context.Context, path, token string, body []byte) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, s.forwardTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.signer+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := s.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(res.Body, mcpMaxAnswerBytes+1))
	if err != nil {
		return 0, nil, err
	}
	if len(answer) > mcpMaxAnswerBytes {
		return 0, nil, errors.New("the answer exceeds the bound")
	}
	return res.StatusCode, answer, nil
}

// signerReason is the reason a signer's refusal carries.
func signerReason(answer []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(answer, &e) == nil && e.Error != "" {
		return e.Error
	}
	text := strings.TrimSpace(string(answer))
	if len(text) > 512 {
		text = text[:512]
	}
	return text
}

// --- identity ---------------------------------------------------------------

// metadataPath is where RFC 9728 derives the protected-resource metadata
// document from the resource's URL: the well-known prefix, then the
// resource's path.
func metadataPath(resource string) string {
	u, err := url.Parse(resource)
	if err != nil {
		return "/.well-known/oauth-protected-resource"
	}
	p := strings.TrimSuffix(u.Path, "/")
	return "/.well-known/oauth-protected-resource" + p
}

// metadataURL is that document's URL, for the challenge.
func metadataURL(resource string) string {
	u, err := url.Parse(resource)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host + metadataPath(resource)
}

// metadataDocument is the document itself.
func (s *mcpServer) metadataDocument() map[string]any {
	doc := map[string]any{"resource": s.cfg.mcp.resource, "bearer_methods_supported": []string{"header"}}
	if s.cfg.identity != nil {
		doc["authorization_servers"] = []string{s.cfg.identity.issuer}
	}
	return doc
}

// verifyBearer holds a token to the identity, as the signer does; "" with
// no identity configured is admitted with no caller.
func (s *mcpServer) verifyBearer(token string) error {
	if s.identity == nil {
		return nil
	}
	if token == "" {
		return errors.New("a bearer token from the configured issuer is required")
	}
	_, err := verifyToken(token, *s.identity, s.now())
	return err
}
