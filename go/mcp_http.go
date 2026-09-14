package main

// The streamable HTTP transport of the MCP server (docs/design/mcp-server.md,
// "Transport profile"): one endpoint, JSON responses only, the checks in the
// stated order, each before the next; and the protected-resource metadata
// document where RFC 9728 derives it, readable without a bearer.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const mcpEndpoint = "/mcp"

// mcpWriteJSON writes one JSON body with a status.
func mcpWriteJSON(w http.ResponseWriter, status int, body any) {
	out, _ := json.Marshal(body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(out)
}

// httpHandler is the transport.
func (s *mcpServer) httpHandler() http.Handler {
	mux := http.NewServeMux()
	if s.cfg.mcp.resource != "" {
		mux.HandleFunc(metadataPath(s.cfg.mcp.resource), func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", "GET")
				mcpWriteJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
				return
			}
			mcpWriteJSON(w, http.StatusOK, s.metadataDocument())
		})
	}
	mux.HandleFunc(mcpEndpoint, s.serveMCP)
	return mux
}

// challenge is the frontend's own: the bearer scheme and where the
// metadata document is, so a conforming client discovers where to get a
// token.
func (s *mcpServer) challenge(w http.ResponseWriter) {
	if s.cfg.mcp.resource != "" {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+metadataURL(s.cfg.mcp.resource)+`"`)
	} else {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
}

// serveMCP answers one request under the ordered checks.
func (s *mcpServer) serveMCP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("MCP-Protocol-Version", mcpProtocolVersion)
	// 1. Origin: present and not admitted, 403 before the body is read
	if origin := r.Header.Get("Origin"); origin != "" && !s.originAllowed(origin) {
		mcpWriteJSON(w, http.StatusForbidden, map[string]any{"error": "origin not admitted"})
		return
	}
	// 2. Authorization: refused at the transport, with the challenge
	token := bearerToken(r.Header.Get("Authorization"))
	if err := s.verifyBearer(token); err != nil {
		s.challenge(w)
		mcpWriteJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
		return
	}
	// 3. the protocol version, when named
	if v := r.Header.Get("MCP-Protocol-Version"); v != "" && v != mcpProtocolVersion {
		mcpWriteJSON(w, http.StatusBadRequest, map[string]any{"error": "protocol version not supported: " + v + "; this server speaks " + mcpProtocolVersion})
		return
	}
	// 4. the body bound
	if r.ContentLength > mcpMaxMessageBytes {
		mcpWriteJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "the message exceeds the bound"})
		return
	}
	var body []byte
	if r.Method == http.MethodPost {
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, mcpMaxMessageBytes+1))
		if err != nil {
			mcpWriteJSON(w, http.StatusBadRequest, map[string]any{"error": "the body could not be read"})
			return
		}
		if len(body) > mcpMaxMessageBytes {
			mcpWriteJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "the message exceeds the bound"})
			return
		}
	}
	initializing := false
	if r.Method == http.MethodPost {
		if req, perr := parseMCPMessage(body); perr == nil && req.method == "initialize" && req.id != nil {
			initializing = true
		}
	}
	// 5 and 6. the transport session: absent on anything but a POST of
	// initialize, 400; unknown, expired or ended, 404
	sid := r.Header.Get("Mcp-Session-Id")
	var sess *mcpSession
	if initializing {
		if sid != "" {
			mcpWriteJSON(w, http.StatusBadRequest, map[string]any{"error": "initialize opens a session; it carries no Mcp-Session-Id"})
			return
		}
	} else {
		if sid == "" {
			mcpWriteJSON(w, http.StatusBadRequest, map[string]any{"error": "Mcp-Session-Id is required"})
			return
		}
		sess = s.lookupSession(sid)
		if sess == nil {
			mcpWriteJSON(w, http.StatusNotFound, map[string]any{"error": "no such session"})
			return
		}
	}
	switch r.Method {
	case http.MethodGet:
		// 7. no stream is offered
		w.Header().Set("Allow", "POST, DELETE")
		mcpWriteJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "this server answers POST with JSON and offers no stream"})
		return
	case http.MethodDelete:
		// 8. the transport session ends; no receipt session is sealed by it
		s.endSession(sid)
		mcpWriteJSON(w, http.StatusOK, map[string]any{"ended": sid})
		return
	case http.MethodPost:
	default:
		w.Header().Set("Allow", "POST, DELETE")
		mcpWriteJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	// 9. JSON must be acceptable
	if !acceptsJSON(r.Header.Get("Accept")) {
		mcpWriteJSON(w, http.StatusNotAcceptable, map[string]any{"error": "this server answers application/json"})
		return
	}
	// 10. initialize opens a session, unless the sessions are all open
	if initializing {
		sess = s.openSession()
		if sess == nil {
			mcpWriteJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "every transport session is open; try again later"})
			return
		}
		w.Header().Set("Mcp-Session-Id", sess.id)
	}
	outcome := s.handle(r.Context(), sess, token, body)
	if outcome.transport != nil {
		// the signer's refusal of the token is the transport's refusal,
		// with this server's challenge
		s.challenge(w)
		mcpWriteJSON(w, outcome.transport.status, map[string]any{"error": outcome.transport.reason})
		return
	}
	if outcome.response == nil {
		// 12. a notification or a client's response: accepted, no body
		w.WriteHeader(http.StatusAccepted)
		return
	}
	// 11. a request
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(outcome.response)
}

// originAllowed admits an origin the configuration names exactly, or,
// when it names none, any loopback origin.
func (s *mcpServer) originAllowed(origin string) bool {
	if len(s.cfg.mcp.origins) > 0 {
		for _, o := range s.cfg.mcp.origins {
			if o == origin {
				return true
			}
		}
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Path != "" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// acceptsJSON says whether application/json is acceptable under an Accept
// header by RFC 9110's rules: the most specific matching range decides,
// wildcards match, and a quality of zero excludes. No header accepts all.
func acceptsJSON(accept string) bool {
	if strings.TrimSpace(accept) == "" {
		return true
	}
	best, bestSpecificity := -1.0, -1
	for _, part := range strings.Split(accept, ",") {
		fields := strings.Split(strings.TrimSpace(part), ";")
		mediaRange := strings.ToLower(strings.TrimSpace(fields[0]))
		q := 1.0
		for _, p := range fields[1:] {
			p = strings.TrimSpace(p)
			if strings.HasPrefix(strings.ToLower(p), "q=") {
				if v, err := strconv.ParseFloat(p[2:], 64); err == nil {
					q = v
				}
			}
		}
		specificity := -1
		switch mediaRange {
		case "application/json":
			specificity = 2
		case "application/*":
			specificity = 1
		case "*/*":
			specificity = 0
		}
		if specificity > bestSpecificity {
			bestSpecificity, best = specificity, q
		}
	}
	return bestSpecificity >= 0 && best > 0
}

// --- transport sessions --------------------------------------------------

func (s *mcpServer) idle() time.Duration { return time.Duration(s.cfg.mcp.idleSeconds) * time.Second }

// openSession opens one, after dropping the expired, unless the bound is
// reached.
func (s *mcpServer) openSession() *mcpSession {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if now.Sub(sess.lastUsed) > s.idle() {
			delete(s.sessions, id)
		}
	}
	if len(s.sessions) >= s.cfg.mcp.sessions {
		return nil
	}
	sess := s.newSession()
	s.sessions[sess.id] = sess
	return sess
}

// lookupSession finds a live session and marks it used; an expired one is
// dropped and not found.
func (s *mcpServer) lookupSession(id string) *mcpSession {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil
	}
	if now.Sub(sess.lastUsed) > s.idle() {
		delete(s.sessions, id)
		return nil
	}
	sess.lastUsed = now
	return sess
}

func (s *mcpServer) endSession(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// listenHTTP serves the transport on the configured address until the
// context ends.
func (s *mcpServer) listenHTTP(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.cfg.mcp.listen)
	if err != nil {
		return err
	}
	server := &http.Server{Handler: s.httpHandler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
