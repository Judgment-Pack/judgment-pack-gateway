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
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
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

// refuseUnread answers a request refused before its body is read, and
// closes the connection after it: the body is not waited for, and a body
// never read cannot be mistaken for the next request.
func refuseUnread(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Connection", "close")
	mcpWriteJSON(w, status, body)
}

// serveMCP answers one request under the ordered checks.
func (s *mcpServer) serveMCP(w http.ResponseWriter, r *http.Request) {
	arrived := s.now()
	w.Header().Set("MCP-Protocol-Version", mcpProtocolVersion)
	// 1. Origin: present and not admitted, 403 before the body is read;
	// present twice, or present and empty, is not an origin this server
	// admits either -- only the header's absence says "no browser"
	if origins := r.Header.Values("Origin"); len(origins) > 0 && (len(origins) != 1 || !s.originAllowed(origins[0])) {
		refuseUnread(w, http.StatusForbidden, map[string]any{"error": "origin not admitted"})
		return
	}
	// 2. Authorization: refused at the transport, with the challenge
	token := bearerToken(r.Header.Get("Authorization"))
	if err := s.verifyBearer(token); err != nil {
		s.challenge(w)
		refuseUnread(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
		return
	}
	// 3. the protocol version, when named
	if v := r.Header.Get("MCP-Protocol-Version"); v != "" && v != mcpProtocolVersion {
		refuseUnread(w, http.StatusBadRequest, map[string]any{"error": "protocol version not supported: " + v + "; this server speaks " + mcpProtocolVersion})
		return
	}
	// 4. the body bound, on every method: what is over it is refused
	// whether or not the method reads it
	if r.ContentLength > mcpMaxMessageBytes {
		refuseUnread(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "the message exceeds the bound"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, mcpMaxMessageBytes+1))
	if err != nil {
		mcpWriteJSON(w, http.StatusBadRequest, map[string]any{"error": "the body could not be read"})
		return
	}
	if len(body) > mcpMaxMessageBytes {
		mcpWriteJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "the message exceeds the bound"})
		return
	}
	// the request is read: from here the answer has the queue's wait, the
	// forward's deadline and the margin, whatever the body took
	_ = http.NewResponseController(w).SetWriteDeadline(s.now().Add(s.responseBudget()))
	// 5 and 6. the transport session: absent on anything but a POST of
	// initialize, 400; unknown, expired or ended, 404, on any method. An
	// initialize that names a live session is a request on that session,
	// which answers that it is initialized already.
	sid := r.Header.Get("Mcp-Session-Id")
	initializing := false
	if sid == "" && r.Method == http.MethodPost {
		if req, perr := parseMCPMessage(body); perr == nil && req.method == "initialize" && req.id != nil {
			initializing = true
		}
	}
	var sess *mcpSession
	if sid == "" && !initializing {
		mcpWriteJSON(w, http.StatusBadRequest, map[string]any{"error": "Mcp-Session-Id is required"})
		return
	}
	if sid != "" {
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
	if !acceptsJSON(r.Header.Values("Accept")) {
		mcpWriteJSON(w, http.StatusNotAcceptable, map[string]any{"error": "this server answers application/json"})
		return
	}
	// 10. initialize opens a session, unless the sessions are all open or
	// admission is closed; the session is published only when the
	// initialize succeeds, and dropped when it does not
	if initializing {
		sess = s.openSession()
		if sess == nil {
			mcpWriteJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "every transport session is open, or admission is closed; try again later"})
			return
		}
	}
	outcome := s.handle(r.Context(), sess, token, arrived, body)
	if initializing {
		if outcome.initialized {
			w.Header().Set("Mcp-Session-Id", sess.id)
		} else {
			s.endSession(sess.id)
		}
	}
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
// when the configuration names none at all, any loopback origin; an
// origin that is not spelled as one is admitted by neither.
func (s *mcpServer) originAllowed(origin string) bool {
	if validOrigin(origin) != nil {
		return false
	}
	if s.cfg.mcp.originsGiven {
		for _, o := range s.cfg.mcp.origins {
			if o == origin {
				return true
			}
		}
		return false
	}
	u, _ := url.Parse(origin)
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// qvalue is RFC 9110 §12.4.2's grammar for a weight: 0 with up to three
// decimals, or 1 with up to three zeros.
var qvalue = regexp.MustCompile(`^(0(\.[0-9]{0,3})?|1(\.0{0,3})?)$`)

// acceptsJSON says whether application/json is acceptable under the
// Accept header's values by RFC 9110 §12.5.1: every field value is read,
// a range's parameters other than q make it apply only to a response
// with those parameters -- which this server's answer never has -- the
// most specific applicable range decides, a quality of zero excludes, and
// a weight outside the grammar makes the header one this server cannot
// read. No header accepts all.
func acceptsJSON(values []string) bool {
	joined := strings.TrimSpace(strings.Join(values, ","))
	if joined == "" {
		return true
	}
	best, bestSpecificity := -1.0, -1
	for _, item := range splitQuoted(joined, ',') {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		fields := splitQuoted(item, ';')
		mediaRange := strings.ToLower(strings.TrimSpace(fields[0]))
		q := 1.0
		parameterized := false
		for _, p := range fields[1:] {
			p = strings.TrimSpace(p)
			name, value, _ := strings.Cut(p, "=")
			if strings.EqualFold(strings.TrimSpace(name), "q") {
				spelled := strings.TrimSpace(value)
				if !qvalue.MatchString(spelled) {
					return false
				}
				q = 0
				if spelled[0] == '1' {
					q = 1
				} else if len(spelled) > 2 {
					for i, digit := range spelled[2:] {
						q += float64(digit-'0') / math.Pow(10, float64(i+1))
					}
				}
				continue
			}
			// a media-type parameter: the range is for a response that
			// carries it, and none of this server's does
			parameterized = true
		}
		if parameterized {
			continue
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

// splitQuoted splits on a separator outside quoted strings.
func splitQuoted(s string, sep byte) []string {
	var parts []string
	var b strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && inQuote && i+1 < len(s):
			b.WriteByte(c)
			i++
			b.WriteByte(s[i])
		case c == '"':
			inQuote = !inQuote
			b.WriteByte(c)
		case c == sep && !inQuote:
			parts = append(parts, b.String())
			b.Reset()
		default:
			b.WriteByte(c)
		}
	}
	parts = append(parts, b.String())
	return parts
}

// --- transport sessions --------------------------------------------------

func (s *mcpServer) idle() time.Duration { return time.Duration(s.cfg.mcp.idleSeconds) * time.Second }

// openSession opens one, after dropping the expired, unless the bound is
// reached or admission is closed.
func (s *mcpServer) openSession() *mcpSession {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
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

// httpServer is the transport's server with its own deadlines, which bound
// a connection past the four configured bounds: a request's headers and
// body may take no longer than the read timeout; an answer may not be
// held open past the queue's wait, the forward's deadline and a margin
// from the moment the body is read (the handler sets that deadline
// itself, since the server's own write timeout starts at the headers and
// would count the body against the answer) with the server's ceiling the
// sum of the two; an idle connection is closed after a minute; and the
// headers are bounded.
func (s *mcpServer) httpServer() *http.Server {
	return &http.Server{
		Handler:           s.httpHandler(),
		ReadHeaderTimeout: s.readTimeout / 3,
		ReadTimeout:       s.readTimeout,
		WriteTimeout:      s.readTimeout + s.responseBudget(),
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
}

// listenHTTP serves the transport on the configured address until the
// context ends.
func (s *mcpServer) listenHTTP(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.cfg.mcp.listen)
	if err != nil {
		return err
	}
	server := s.httpServer()
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
