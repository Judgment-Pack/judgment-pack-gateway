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
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
	// mcpResponseMargin is what an answer may take beyond the queue's wait
	// and the forward's deadline before the transport gives up on writing
	// it.
	mcpResponseMargin = 15 * time.Second
	// mcpMaxAnswerBytes bounds what the signer's answer may be: the
	// signer's own output bound is one mebibyte by default, and an answer
	// carries the result with its receipt and salts.
	mcpMaxAnswerBytes = 8 << 20
	// mcpMaxMessageBytes bounds one JSON-RPC message.
	mcpMaxMessageBytes = 1 << 20
	// mcpMaxIDBytes bounds a JSON-RPC id's spelling, and mcpMaxIDExponent
	// a numeric id's exponent: an identifier, not a number to compute
	// with.
	mcpMaxIDBytes    = 64
	mcpMaxIDExponent = 999
	// mcpReadTimeout bounds the reading of one request, headers and body:
	// a message is at most a mebibyte, and a client that takes longer than
	// this to say it is not speaking.
	mcpReadTimeout = 30 * time.Second
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
// it, its rate window, and whether it has been initialized.
type mcpSession struct {
	id             string
	receiptSession string
	lastUsed       time.Time
	windowStart    time.Time
	windowCount    int
	initialized    bool
}

// mcpServer is the server's state: the table, the identity, the signer's
// address, the bounds, the admission gate and the transport sessions.
type mcpServer struct {
	cfg      engineConfig
	tools    map[string]mcpTool
	order    []string
	identity *identityConfig
	signer   string // http://listen
	client   *http.Client
	now      func() time.Time
	newID    func() string
	log      io.Writer     // diagnostics: categories, never a token, never an address
	forwards chan struct{} // one token per forward in flight
	queue    chan struct{} // one token per call waiting
	// forwardTimeout bounds one forward, queueWait one wait for a slot,
	// readTimeout the reading of one request, responseMargin what an
	// answer may take past the two; the constants above unless a test
	// shortens them
	forwardTimeout time.Duration
	queueWait      time.Duration
	readTimeout    time.Duration
	responseMargin time.Duration
	// stdioBacklog bounds the messages admitted and unanswered over stdio;
	// mcpStdioBacklog unless a test lowers it
	stdioBacklog int
	mu           sync.Mutex
	sessions     map[string]*mcpSession
	// admission is open unless the operator closed it for maintenance:
	// closed, a new transport session is refused, a new acquisition is an
	// overload, a queued one is woken and refused, and sealing goes on.
	// Every closure is a generation: a call admitted under one generation
	// and given a slot under another was queued through a closure, and is
	// refused as the note says.
	closed     bool
	generation uint64
	reopened   chan struct{} // closed on every close of admission, replaced on reopen
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
		// the one destination is the configured signer: a redirect is not
		// followed, and is answered as the status it is
		client:   &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		now:      time.Now,
		newID:    randomSessionName,
		log:      os.Stderr,
		forwards: make(chan struct{}, cfg.mcp.concurrency),
		queue:    make(chan struct{}, cfg.mcp.concurrency),
		sessions: map[string]*mcpSession{},
		reopened: make(chan struct{}),

		forwardTimeout: mcpForwardTimeout,
		queueWait:      mcpQueueWait,
		readTimeout:    mcpReadTimeout,
		responseMargin: mcpResponseMargin,
		stdioBacklog:   mcpStdioBacklog,
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

// responseBudget is what an answer may take once the request is read: the
// queue's wait, the forward's deadline and the margin.
func (s *mcpServer) responseBudget() time.Duration {
	return s.queueWait + s.forwardTimeout + s.responseMargin
}

// --- admission ------------------------------------------------------------

// closeAdmission closes the gate for maintenance (the rotation contract of
// the note): what waits is woken and refused, what arrives is refused, and
// sealing goes on.
func (s *mcpServer) closeAdmission() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.generation++
	close(s.reopened)
	fmt.Fprintln(s.log, "mcp: admission closed")
}

// openAdmission reopens the gate.
func (s *mcpServer) openAdmission() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		return
	}
	s.closed = false
	s.reopened = make(chan struct{})
	fmt.Fprintln(s.log, "mcp: admission open")
}

// admission reports the gate, the channel that closes with it, and the
// generation: the count of closures so far.
func (s *mcpServer) admission() (closed bool, wake <-chan struct{}, generation uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed, s.reopened, s.generation
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

// members reads an object by its members' exact names: encoding/json's
// struct decoding folds case, and a member that means one thing to one
// reader and another to the next is what this server does not carry. With
// a set of allowed names, any other is refused; with none, any name is
// read.
func members(raw json.RawMessage, what string, allowed map[string]bool) (map[string]json.RawMessage, *jsonrpcError) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, &jsonrpcError{rpcInvalidRequest, what + " is not an object"}
	}
	if allowed != nil {
		for name := range m {
			if _, ok := allowed[name]; !ok {
				return nil, &jsonrpcError{rpcInvalidRequest, what + " carries a member this server does not read: " + name}
			}
		}
	}
	return m, nil
}

// isString says whether a raw value is a JSON string -- null decodes into
// a Go string without complaint, and is not one.
func isString(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 0 && t[0] == '"' && json.Valid(t)
}

// isObject says whether a raw value is a JSON object.
func isObject(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 0 && t[0] == '{' && json.Valid(t)
}

// validID says whether a JSON-RPC id is one the pinned protocol admits: a
// string, or an integer -- a number with no fractional part, in whatever
// spelling, within a spelling bound and an exponent bound, since an id is
// compared and echoed, never computed with -- never null, a boolean or a
// structure.
func validID(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || len(t) > mcpMaxIDBytes {
		return false
	}
	if t[0] == '"' {
		var s string
		return json.Unmarshal(t, &s) == nil
	}
	var n json.Number
	dec := json.NewDecoder(bytes.NewReader(t))
	dec.UseNumber()
	if dec.Decode(&n) != nil {
		return false
	}
	if _, exponent, found := strings.Cut(strings.ToLower(string(n)), "e"); found {
		e, err := strconv.Atoi(strings.TrimPrefix(exponent, "+"))
		if err != nil || e > mcpMaxIDExponent || e < -mcpMaxIDExponent {
			return false
		}
	}
	r, ok := new(big.Rat).SetString(string(n))
	return ok && r.IsInt()
}

// parseMCPMessage reads one JSON-RPC message: syntax first, then an object
// with jsonrpc "2.0" and the members the protocol names, read exactly. An
// array (a batch) is refused, as the pinned protocol does not carry them.
func parseMCPMessage(data []byte) (mcpRequest, *jsonrpcError) {
	if !json.Valid(data) {
		return mcpRequest{}, &jsonrpcError{rpcParse, "the message is not JSON"}
	}
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] == '[' {
		return mcpRequest{}, &jsonrpcError{rpcInvalidRequest, "a batch is not accepted under protocol " + mcpProtocolVersion}
	}
	// The message is read by exact member names with no duplicate, as the
	// signer reads what it signs; but what a call carries as its tool's
	// arguments is the signer's to judge -- its duplicates, its numbers --
	// so the walk skips that one value. (The seal tool's arguments are this
	// server's, and are walked where they are read.)
	if err := noDuplicateMembers(data, [][]string{{"params", "arguments"}}); err != nil {
		return mcpRequest{}, &jsonrpcError{rpcInvalidRequest, err.Error()}
	}
	m, perr := members(data, "the message", map[string]bool{"jsonrpc": true, "id": true, "method": true, "params": true, "result": true, "error": true})
	if perr != nil {
		return mcpRequest{}, perr
	}
	var version string
	if json.Unmarshal(m["jsonrpc"], &version) != nil || version != "2.0" {
		return mcpRequest{}, &jsonrpcError{rpcInvalidRequest, `jsonrpc must be "2.0"`}
	}
	id, hasID := m["id"]
	method, hasMethod := m["method"]
	result, hasResult := m["result"]
	errValue, hasError := m["error"]
	if !hasMethod {
		// a response: an id and exactly one of result -- an object -- and
		// error -- an object of an integer code and a string message
		if hasResult == hasError || !hasID || !validID(id) {
			return mcpRequest{}, &jsonrpcError{rpcInvalidRequest, "a message without a method is a response, with an id and exactly one of result and error"}
		}
		if hasResult && !isObject(result) {
			return mcpRequest{}, &jsonrpcError{rpcInvalidRequest, "a response's result is an object"}
		}
		if hasError {
			e, perr := members(errValue, "a response's error", map[string]bool{"code": true, "message": true, "data": true})
			if perr != nil || !validID(e["code"]) || isString(e["code"]) || !isString(e["message"]) {
				return mcpRequest{}, &jsonrpcError{rpcInvalidRequest, "a response's error is an object of an integer code and a string message"}
			}
		}
		return mcpRequest{isResponse: true, id: id}, nil
	}
	if hasResult || hasError {
		return mcpRequest{}, &jsonrpcError{rpcInvalidRequest, "a request carries no result or error"}
	}
	var name string
	if json.Unmarshal(method, &name) != nil || name == "" {
		return mcpRequest{}, &jsonrpcError{rpcInvalidRequest, "method must be a non-empty string"}
	}
	if params, ok := m["params"]; ok && !isObject(params) {
		// JSON-RPC admits an array; the pinned protocol's messages carry
		// objects
		return mcpRequest{}, &jsonrpcError{rpcInvalidRequest, "params must be an object"}
	}
	if !hasID {
		return mcpRequest{method: name, params: m["params"]}, nil
	}
	if !validID(id) {
		return mcpRequest{}, &jsonrpcError{rpcInvalidRequest, "id must be a string or an integer"}
	}
	return mcpRequest{id: id, method: name, params: m["params"]}, nil
}

// noDuplicateMembers walks a JSON text and refuses an object naming a
// member twice, at any depth, so no member can mean one thing to one
// reader and another to the next -- except under the paths given, whose
// values are another reader's to judge and are stepped over whole.
func noDuplicateMembers(data []byte, skip [][]string) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	type frame struct {
		object bool
		seen   map[string]bool
		key    bool   // an object frame expecting a key next
		last   string // the key whose value comes next
	}
	var stack []*frame
	path := func() []string {
		var p []string
		for _, f := range stack {
			if f.object {
				p = append(p, f.last)
			} else {
				p = append(p, "[]")
			}
		}
		return p
	}
	skipping := func() bool {
		p := path()
		for _, s := range skip {
			if len(p) == len(s) {
				same := true
				for i := range s {
					if p[i] != s[i] {
						same = false
						break
					}
				}
				if same {
					return true
				}
			}
		}
		return false
	}
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
		// a key just read, and the value under it is another reader's:
		// step over the value whole
		if top != nil && top.object && !top.key && skipping() {
			if d, ok := tok.(json.Delim); ok && (d == '{' || d == '[') {
				depth := 1
				for depth > 0 {
					t, err := dec.Token()
					if err != nil {
						return errors.New("the message is not JSON")
					}
					if d, ok := t.(json.Delim); ok {
						if d == '{' || d == '[' {
							depth++
						} else {
							depth--
						}
					}
				}
			}
			top.key = true
			continue
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{':
				stack = append(stack, &frame{object: true, seen: map[string]bool{}, key: true})
			case '[':
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
				top.last = v
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

// mcpOutcome is what admitting one message yields: a response to write (nil
// for a notification or a client's response), a transport-level refusal
// the HTTP transport turns into its own status, whether the message was an
// initialize that succeeded, and -- for a call admitted and not yet made
// -- the work that makes it, which a transport runs where it likes.
type mcpOutcome struct {
	response    []byte
	transport   *mcpTransportRefusal
	initialized bool
	run         func(ctx context.Context) mcpOutcome
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

// handle admits and answers one message: admit, then the work, inline.
func (s *mcpServer) handle(ctx context.Context, sess *mcpSession, token string, arrived time.Time, data []byte) mcpOutcome {
	outcome := s.admit(sess, token, arrived, data)
	if outcome.run != nil {
		return outcome.run(ctx)
	}
	return outcome
}

// admit reads one message that arrived at the given time, for a transport
// session, under the caller's bearer (empty when the engine has no
// identity), and does everything that is done in arrival order: the
// lifecycle, the session's resolution, the window, the gate. A call that
// passes comes back as work to run.
func (s *mcpServer) admit(sess *mcpSession, token string, arrived time.Time, data []byte) mcpOutcome {
	req, perr := parseMCPMessage(data)
	if perr != nil {
		return mcpOutcome{response: rpcFailure(nil, *perr)}
	}
	if req.isResponse {
		return mcpOutcome{}
	}
	if req.id == nil {
		// a notification: acknowledged without a response, whatever it says
		return mcpOutcome{}
	}
	switch req.method {
	case "initialize":
		return s.initialize(sess, req)
	case "ping":
		return mcpOutcome{response: rpcResult(req.id, map[string]any{})}
	}
	s.mu.Lock()
	initialized := sess.initialized
	s.mu.Unlock()
	if !initialized {
		return mcpOutcome{response: rpcFailure(req.id, jsonrpcError{rpcInvalidRequest, "initialize first"})}
	}
	switch req.method {
	case "tools/list":
		return mcpOutcome{response: rpcResult(req.id, map[string]any{"tools": s.toolList()})}
	case "tools/call":
		return s.admitCall(sess, token, arrived, req)
	default:
		return mcpOutcome{response: rpcFailure(req.id, jsonrpcError{rpcMethodNotFound, "method not supported: " + req.method})}
	}
}

// initialize holds the client's initialize to the lifecycle's shape and
// answers the one version this server speaks, whatever was proposed. The
// transition is one: a session initializes once, and two initializes that
// race find one of them second.
func (s *mcpServer) initialize(sess *mcpSession, req mcpRequest) mcpOutcome {
	params, perr := members(req.params, "initialize params", map[string]bool{"protocolVersion": true, "capabilities": true, "clientInfo": true, "_meta": true})
	if perr != nil {
		return mcpOutcome{response: rpcFailure(req.id, jsonrpcError{rpcInvalidParams, perr.Message})}
	}
	var proposed string
	if raw, ok := params["protocolVersion"]; !ok || !isString(raw) || json.Unmarshal(raw, &proposed) != nil || proposed == "" {
		return mcpOutcome{response: rpcFailure(req.id, jsonrpcError{rpcInvalidParams, "initialize names a protocolVersion"})}
	}
	if raw, ok := params["capabilities"]; !ok || !isObject(raw) {
		return mcpOutcome{response: rpcFailure(req.id, jsonrpcError{rpcInvalidParams, "initialize carries capabilities, an object"})}
	}
	clientInfo, perr := members(params["clientInfo"], "clientInfo", map[string]bool{"name": true, "version": true, "title": true, "websiteUrl": true})
	if perr != nil {
		return mcpOutcome{response: rpcFailure(req.id, jsonrpcError{rpcInvalidParams, "initialize carries clientInfo, an object of name and version"})}
	}
	if !isString(clientInfo["name"]) || !isString(clientInfo["version"]) {
		return mcpOutcome{response: rpcFailure(req.id, jsonrpcError{rpcInvalidParams, "clientInfo names name and version, strings"})}
	}
	s.mu.Lock()
	already := sess.initialized
	sess.initialized = true
	s.mu.Unlock()
	if already {
		return mcpOutcome{response: rpcFailure(req.id, jsonrpcError{rpcInvalidRequest, "the session is initialized already"})}
	}
	return mcpOutcome{initialized: true, response: rpcResult(req.id, map[string]any{
		"protocolVersion": mcpProtocolVersion,
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      map[string]any{"name": s.cfg.authority, "version": buildVersion()},
		"instructions":    "Every tool is a platform's live tool acquired by the engine under its key; the answer carries {session, result, receipt, salts}. A cancelled call is not cancelled at the engine and may still mint a receipt; a retry mints another. Seal a session with " + mcpSealTool + " before verifying it.",
	})}
}

// buildVersion is the version of this executable as its build recorded
// it: a module version for a released build, and the words "unversioned
// build" where the build recorded none, which is what a build from a
// checkout says of itself.
func buildVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "unversioned build"
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

// overload is an overload result naming the session.
func overload(session, reason string) map[string]any {
	return toolError(map[string]any{"session": session, "outcome": "overload", "error": reason})
}

// admitCall does the arrival-order part of tools/call: the session it
// resolves to, first, so that every refusal names it; the window, counted
// whatever becomes of the call; the shape; the gate. What passes is
// returned as work.
func (s *mcpServer) admitCall(sess *mcpSession, token string, arrived time.Time, req mcpRequest) mcpOutcome {
	session := sess.receiptSession
	var name string
	var arguments json.RawMessage
	var invalid *jsonrpcError
	params, perr := members(req.params, "tools/call params", map[string]bool{"name": true, "arguments": true, "_meta": true})
	if perr != nil {
		invalid = &jsonrpcError{rpcInvalidParams, perr.Message}
	} else {
		// the metadata's session first, whatever the name says
		if raw, ok := params["_meta"]; ok {
			meta, perr := members(raw, "_meta", nil)
			if perr != nil {
				invalid = &jsonrpcError{rpcInvalidParams, "_meta must be an object"}
			} else if named, ok := meta[mcpSessionMeta]; ok {
				if !isString(named) {
					invalid = &jsonrpcError{rpcInvalidParams, "_meta." + mcpSessionMeta + " must be a session name"}
				} else {
					json.Unmarshal(named, &session)
				}
			}
		}
		if invalid == nil && (!isString(params["name"]) || json.Unmarshal(params["name"], &name) != nil || name == "") {
			invalid = &jsonrpcError{rpcInvalidParams, "tools/call names a tool"}
		}
		arguments = params["arguments"]
	}
	tool, known := s.tools[name]
	if invalid == nil && !known {
		invalid = &jsonrpcError{rpcInvalidParams, "unknown tool: " + name}
	}
	if invalid == nil && tool.seal {
		// the seal tool's arguments are this server's own: read exactly,
		// no duplicate, a string
		if err := noDuplicateMembers(arguments, nil); err != nil {
			invalid = &jsonrpcError{rpcInvalidParams, mcpSealTool + " arguments: " + err.Error()}
		} else if args, perr := members(arguments, mcpSealTool+" arguments", map[string]bool{"session": true}); perr != nil {
			invalid = &jsonrpcError{rpcInvalidParams, mcpSealTool + " takes {session} and no other member"}
		} else if !isString(args["session"]) {
			invalid = &jsonrpcError{rpcInvalidParams, mcpSealTool + " takes {session}, a session name"}
		} else {
			json.Unmarshal(args["session"], &session)
		}
	}
	if invalid == nil && !tool.seal && len(bytes.TrimSpace(arguments)) > 0 && !isObject(arguments) {
		invalid = &jsonrpcError{rpcInvalidParams, "arguments must be an object"}
	}
	// the window: counted at arrival, whatever becomes of the call
	if refusal := s.countCall(sess, arrived, session); refusal != nil {
		return mcpOutcome{response: rpcResult(req.id, refusal)}
	}
	if invalid != nil {
		return mcpOutcome{response: rpcFailure(req.id, *invalid)}
	}
	// the gate: closed for maintenance, an acquisition is refused and a
	// seal goes on; the generation is remembered for the slot below
	closed, _, generation := s.admission()
	if closed && !tool.seal {
		return mcpOutcome{response: rpcResult(req.id, overload(session, "admission is closed for maintenance; nothing was forwarded"))}
	}
	return mcpOutcome{run: func(ctx context.Context) mcpOutcome {
		return s.runCall(ctx, token, req.id, tool, session, arguments, generation)
	}}
}

// runCall takes a queue token and a forward slot and makes the call. A
// queued acquisition is woken and refused when admission closes, and one
// that gets its slot after a closure -- the two ready at once, or the gate
// closed and reopened while it waited -- is refused too and gives the slot
// back; a queued seal is woken by nothing (a nil channel never fires).
func (s *mcpServer) runCall(ctx context.Context, token string, id json.RawMessage, tool mcpTool, session string, arguments json.RawMessage, generation uint64) mcpOutcome {
	select {
	case s.queue <- struct{}{}:
	default:
		return mcpOutcome{response: rpcResult(id, overload(session, "the engine's front is full; nothing was forwarded"))}
	}
	var wake <-chan struct{}
	if !tool.seal {
		_, wake, _ = s.admission()
	}
	waited := time.NewTimer(s.queueWait)
	select {
	case s.forwards <- struct{}{}:
		waited.Stop()
		<-s.queue
		if !tool.seal {
			if closed, _, now := s.admission(); closed || now != generation {
				<-s.forwards
				return mcpOutcome{response: rpcResult(id, overload(session, "admission closed for maintenance while the call waited; nothing was forwarded"))}
			}
		}
	case <-waited.C:
		<-s.queue
		return mcpOutcome{response: rpcResult(id, overload(session, "no forward slot within "+s.queueWait.String()+"; nothing was forwarded"))}
	case <-wake:
		waited.Stop()
		<-s.queue
		return mcpOutcome{response: rpcResult(id, overload(session, "admission closed for maintenance while the call waited; nothing was forwarded"))}
	case <-ctx.Done():
		waited.Stop()
		<-s.queue
		return mcpOutcome{response: rpcResult(id, overload(session, "the call ended before a forward slot was free; nothing was forwarded"))}
	}
	defer func() { <-s.forwards }()

	var path string
	var body []byte
	if tool.seal {
		path = "/seal"
		body, _ = json.Marshal(map[string]string{"session": session})
	} else {
		path = "/acquire"
		if len(bytes.TrimSpace(arguments)) == 0 {
			arguments = json.RawMessage("{}")
		}
		// the arguments are the client's bytes, inside the wrapper, never
		// decoded and re-encoded on the way: the signer's parser judges them
		sessionJSON, _ := json.Marshal(session)
		sourceJSON, _ := json.Marshal(tool.platform + "/live")
		toolJSON, _ := json.Marshal(tool.tool)
		body = []byte(`{"session":` + string(sessionJSON) + `,"source":` + string(sourceJSON) + `,"arguments":{"tool":` + string(toolJSON) + `,"arguments":` + string(bytes.TrimSpace(arguments)) + `}}`)
	}
	status, answer, err := s.forward(ctx, path, token, body)
	if err != nil {
		// the category stays here, token-free and address-free; the
		// client learns only that the answer did not arrive
		fmt.Fprintf(s.log, "mcp: forward to %s did not answer: %s\n", path, transportErrorCategory(err))
		return mcpOutcome{response: rpcResult(id, toolError(map[string]any{"session": session, "outcome": "unknown", "error": "the engine's answer did not arrive; the call may have run and minted a receipt"}))}
	}
	if status == http.StatusUnauthorized {
		reason := signerReason(answer)
		return mcpOutcome{
			response:  rpcResult(id, toolError(map[string]any{"session": session, "status": status, "error": reason})),
			transport: &mcpTransportRefusal{status: status, reason: reason},
		}
	}
	if status < 200 || status >= 300 {
		return mcpOutcome{response: rpcResult(id, toolError(map[string]any{"session": session, "status": status, "error": signerReason(answer)}))}
	}
	if tool.seal {
		var record map[string]json.RawMessage
		if json.Unmarshal(answer, &record) != nil || record == nil {
			return mcpOutcome{response: rpcResult(id, toolError(map[string]any{"session": session, "outcome": "unknown", "error": "the engine's seal answer was not an object; the seal may have been written"}))}
		}
		return mcpOutcome{response: rpcResult(id, toolSuccess(record))}
	}
	var acquired struct {
		Result  json.RawMessage `json:"result"`
		Receipt json.RawMessage `json:"receipt"`
		Salts   json.RawMessage `json:"salts"`
	}
	if json.Unmarshal(answer, &acquired) != nil || len(acquired.Receipt) == 0 {
		return mcpOutcome{response: rpcResult(id, toolError(map[string]any{"session": session, "outcome": "unknown", "error": "the engine's answer was not an acquisition; a receipt may have been minted"}))}
	}
	return mcpOutcome{response: rpcResult(id, toolSuccess(map[string]any{"session": session, "result": acquired.Result, "receipt": acquired.Receipt, "salts": acquired.Salts}))}
}

// transportErrorCategory names what went wrong with a forward, or a
// listener, in a word that carries no address, no name and no token: what
// a diagnostics stream may say, since a host may forward it anywhere.
func transportErrorCategory(err error) string {
	switch {
	case err == nil:
		return "nothing"
	case errors.Is(err, errAnswerTooLarge):
		return "the answer exceeded the bound"
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded):
		return "timed out"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.EADDRINUSE):
		return "address in use"
	case errors.Is(err, syscall.EACCES) || errors.Is(err, os.ErrPermission):
		return "permission denied"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timed out"
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return "connection failed"
	}
	return "transport error"
}

// errAnswerTooLarge is a forward whose answer crossed the bound.
var errAnswerTooLarge = errors.New("the answer exceeds the bound")

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

// countCall counts one call, at its arrival, against the transport
// session's window and refuses past the bound, naming the session the call
// resolved to and the seconds until the window turns.
func (s *mcpServer) countCall(sess *mcpSession, arrived time.Time, session string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.windowStart.IsZero() || arrived.Sub(sess.windowStart) >= time.Minute {
		sess.windowStart, sess.windowCount = arrived, 0
	}
	sess.windowCount++
	if sess.windowCount > s.cfg.mcp.callsPerMinute {
		wait := time.Minute - arrived.Sub(sess.windowStart)
		return toolError(map[string]any{"session": session, "outcome": "overload", "error": fmt.Sprintf("%d calls in this window already; nothing was forwarded", s.cfg.mcp.callsPerMinute), "retryAfterSeconds": int(math.Ceil(wait.Seconds()))})
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
		return 0, nil, errAnswerTooLarge
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
	if text == "" {
		return "no reason given"
	}
	if len(text) > 512 {
		text = text[:512]
	}
	return text
}

// --- identity ---------------------------------------------------------------

// metadataPath is where RFC 9728 derives the protected-resource metadata
// document from the resource's URL: the well-known prefix, then the
// resource's path as it was spelled.
func metadataPath(resource string) string {
	u, err := url.Parse(resource)
	if err != nil {
		return "/.well-known/oauth-protected-resource"
	}
	p := strings.TrimSuffix(u.EscapedPath(), "/")
	return "/.well-known/oauth-protected-resource" + p
}

// metadataURL is that document's URL, for the challenge: the resource's
// scheme and host, the derived path, and the resource's query, kept.
func metadataURL(resource string) string {
	u, err := url.Parse(resource)
	if err != nil {
		return ""
	}
	out := u.Scheme + "://" + u.Host + metadataPath(resource)
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
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
