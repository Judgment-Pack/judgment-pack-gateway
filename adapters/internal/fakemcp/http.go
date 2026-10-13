package fakemcp

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
)

// HTTPServer stands in for a remote MCP server reached over Streamable
// HTTP, in the test's own process: it answers initialize, tools/list and
// tools/call as Script says, issues a session id on initialize and holds
// every later request to it, and records every request it was sent, so a
// test can count them and read their headers.
type HTTPServer struct {
	// URL is the endpoint a client is given: the server's root and /mcp.
	URL string

	server *httptest.Server
	mu     sync.Mutex
	script Script
	seen   []Recorded
}

// Script is how the server answers. Its zero value answers as a server
// with one read tool and a result of one row.
type Script struct {
	// Session is the session id issued on initialize; "" issues none and
	// holds no request to one.
	Session string
	// Protocol is the version initialize answers; 2025-06-18 when empty.
	Protocol string
	// ServerInfo is initialize's serverInfo as written; the default names
	// fake-remote-mcp 2.0.
	ServerInfo string
	// Tools is the tools/list "tools" array as written.
	Tools string
	// Result is the tools/call result as written, carried into the
	// response byte for byte.
	Result string
	// Refuse answers tools/call with this JSON-RPC error object as written.
	Refuse string
	// Events answers every request as an event stream rather than JSON.
	Events bool
	// Answer, when set, answers a request before anything above: it is
	// handed the JSON-RPC method ("" for none) and the request id as
	// written, and reports whether it answered.
	Answer func(w http.ResponseWriter, method string, id json.RawMessage) bool
}

// Recorded is one request the server was sent.
type Recorded struct {
	// Verb is the HTTP method, Path the request's path and query as sent.
	Verb, Path string
	// Method is the JSON-RPC method of a POST, "" for none.
	Method string
	Header http.Header
	Body   []byte
}

// DefaultTools is the one tool the server offers unless told otherwise.
const DefaultTools = `[{"name":"query","description":"Run a read-only query","inputSchema":{"type":"object","properties":{"sql":{"type":"string"}},"required":["sql"]},"outputSchema":{"type":"object","properties":{"rows":{"type":"array"}}}}]`

// DefaultResult is the tools/call result unless told otherwise.
const DefaultResult = `{"content":[{"type":"text","text":"1 row"}],"structuredContent":{"rows":[{"id":101,"amount":12.5}]}}`

// NewHTTP starts the server: over TLS with a certificate of its own, or in
// the clear on loopback.
func NewHTTP(tls bool, script Script) *HTTPServer {
	s := &HTTPServer{script: script}
	handler := http.HandlerFunc(s.serve)
	if tls {
		s.server = httptest.NewTLSServer(handler)
	} else {
		s.server = httptest.NewServer(handler)
	}
	s.URL = s.server.URL + "/mcp"
	return s
}

// Close stops the server.
func (s *HTTPServer) Close() { s.server.Close() }

// Set changes how the server answers from the next request on.
func (s *HTTPServer) Set(change func(*Script)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	change(&s.script)
}

// Requests are the requests the server was sent, in order.
func (s *HTTPServer) Requests() []Recorded {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Recorded(nil), s.seen...)
}

// Methods are the JSON-RPC methods of the requests, a DELETE as "DELETE".
func (s *HTTPServer) Methods() []string {
	var out []string
	for _, r := range s.Requests() {
		if r.Verb == http.MethodDelete {
			out = append(out, "DELETE")
		} else {
			out = append(out, r.Method)
		}
	}
	return out
}

// Leaf is the DER of the certificate a TLS server presents.
func (s *HTTPServer) Leaf() []byte { return s.server.Certificate().Raw }

// WriteCA writes the TLS server's certificate as a PEM file, for a client's
// --ca-file.
func (s *HTTPServer) WriteCA(path string) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Leaf()}), 0o600)
}

func (s *HTTPServer) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	var m struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	if r.Method == http.MethodPost {
		json.Unmarshal(body, &m)
	}
	s.mu.Lock()
	s.seen = append(s.seen, Recorded{Verb: r.Method, Path: r.URL.RequestURI(), Method: m.Method, Header: r.Header.Clone(), Body: body})
	script := s.script
	s.mu.Unlock()
	if script.Answer != nil && script.Answer(w, m.Method, m.ID) {
		return
	}
	// Every request after initialize carries the session the server
	// issued: one without it is refused, one with another is unknown.
	if script.Session != "" && m.Method != "initialize" {
		switch got := r.Header.Get("Mcp-Session-Id"); {
		case got == "":
			http.Error(w, "missing session", http.StatusBadRequest)
			return
		case got != script.Session:
			http.Error(w, "unknown session", http.StatusNotFound)
			return
		}
	}
	if r.Method == http.MethodDelete {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if len(m.ID) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	var result string
	switch m.Method {
	case "initialize":
		protocol := script.Protocol
		if protocol == "" {
			protocol = "2025-06-18"
		}
		info := script.ServerInfo
		if info == "" {
			info = `{"name":"fake-remote-mcp","version":"2.0"}`
		}
		result = fmt.Sprintf(`{"protocolVersion":%q,"capabilities":{"tools":{}},"serverInfo":%s}`, protocol, info)
		if script.Session != "" {
			w.Header().Set("Mcp-Session-Id", script.Session)
		}
	case "tools/list":
		tools := script.Tools
		if tools == "" {
			tools = DefaultTools
		}
		result = `{"tools":` + tools + `}`
	case "tools/call":
		if script.Refuse != "" {
			s.write(w, script.Events, `{"jsonrpc":"2.0","id":`+string(m.ID)+`,"error":`+script.Refuse+`}`)
			return
		}
		result = script.Result
		if result == "" {
			result = DefaultResult
		}
	default:
		s.write(w, script.Events, `{"jsonrpc":"2.0","id":`+string(m.ID)+`,"error":{"code":-32601,"message":"method not found"}}`)
		return
	}
	s.write(w, script.Events, `{"jsonrpc":"2.0","id":`+string(m.ID)+`,"result":`+result+`}`)
}

// write answers with one message: as JSON, or as one event of a stream.
func (s *HTTPServer) write(w http.ResponseWriter, events bool, message string) {
	if events {
		w.Header().Set("Content-Type", "text/event-stream")
		var b bytes.Buffer
		for _, line := range strings.Split(message, "\n") {
			b.WriteString("data: " + line + "\n")
		}
		b.WriteString("\n")
		w.Write(b.Bytes())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, message)
}
