package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"adapters/internal/canon"
)

// client is one side of a JSON-RPC 2.0 conversation over newline-delimited
// messages: the MCP stdio transport. It sends requests with rising ids and
// reads until the matching response, answering a request the server makes
// of it with "method not found" -- this client serves nothing -- and
// passing over notifications and responses to other ids.
type client struct {
	in   io.Writer
	out  *bufio.Scanner
	next int64
}

func newClient(in io.Writer, out io.Reader) *client {
	scanner := bufio.NewScanner(out)
	scanner.Buffer(make([]byte, 1<<20), 64<<20)
	return &client{in: in, out: scanner}
}

type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// rpcMessage is a message the server wrote, read by its members' exact
// names with a duplicate refused: Go's struct decoding would let "RESULT"
// stand in for result, and a second member overwrite the first, on a line
// that decides what the server answered.
type rpcMessage struct {
	members map[string]json.RawMessage
}

// malformedMessage is a line that is JSON but not a message this client
// reads: a duplicate member, an invalid string.
type malformedMessage struct{ reason error }

func (m *malformedMessage) Error() string { return m.reason.Error() }

func decodeMessage(line []byte) (rpcMessage, error) {
	members, err := exactMembers(line)
	if err != nil {
		return rpcMessage{}, err
	}
	if _, err := canon.Canonicalize(line, canon.CarryNumbersAsText); err != nil {
		return rpcMessage{}, &malformedMessage{reason: err}
	}
	var version string
	if json.Unmarshal(members["jsonrpc"], &version) != nil || version != "2.0" {
		return rpcMessage{}, errors.New("not JSON-RPC 2.0")
	}
	return rpcMessage{members: members}, nil
}

func (m rpcMessage) has(name string) bool { _, ok := m.members[name]; return ok }

// str is the member's string value, or "" when absent or not a string.
func (m rpcMessage) str(name string) string {
	var s string
	json.Unmarshal(m.members[name], &s)
	return s
}

func (m rpcMessage) id() json.RawMessage { return m.members["id"] }

// isRequest: a method with an id that is not null.
func (m rpcMessage) isRequest() bool {
	id := m.id()
	return m.str("method") != "" && len(id) > 0 && string(id) != "null"
}

func (c *client) send(v any) error {
	line, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := c.in.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("the server's input closed: %w", err)
	}
	return nil
}

// notify sends a notification: a request without an id, which has no
// response.
func (c *client) notify(method string, params any) error {
	return c.send(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
}

// call sends a request and reads until its response. A line that is not a
// JSON-RPC message is a protocol violation and ends the call: the MCP
// stdio transport reserves the server's stdout for messages.
func (c *client) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	c.next++
	id := c.next
	if err := c.send(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
		return nil, err
	}
	for c.out.Scan() {
		m, err := decodeMessage(c.out.Bytes())
		if err != nil {
			var malformed *malformedMessage
			if errors.As(err, &malformed) {
				return nil, fmt.Errorf("the server wrote a JSON-RPC message that is malformed: %v", malformed.reason)
			}
			return nil, errors.New("the server wrote a line on stdout that is not a JSON-RPC message")
		}
		switch {
		case m.isRequest() && m.str("method") == "ping":
			// A liveness check must be answered with an empty result, or
			// a server that pings ends the conversation.
			if err := c.send(map[string]any{"jsonrpc": "2.0", "id": m.id(), "result": map[string]any{}}); err != nil {
				return nil, err
			}
		case m.isRequest():
			// A server may ask its client for roots or sampling; this
			// client serves nothing, and says so rather than hang the
			// server waiting.
			if err := c.send(map[string]any{"jsonrpc": "2.0", "id": m.id(), "error": rpcError{Code: -32601, Message: "this client serves no requests"}}); err != nil {
				return nil, err
			}
		case m.str("method") != "":
			// A notification: nothing to answer.
		case len(m.id()) > 0:
			var got int64
			if json.Unmarshal(m.id(), &got) != nil || got != id {
				continue // a response to another request, which this client never made
			}
			// A response carries exactly one of result and error, by
			// presence: an error member that is null is still present.
			hasResult, hasError := m.has("result"), m.has("error")
			if hasResult && hasError {
				return nil, fmt.Errorf("%s: the server answered with both a result and an error", method)
			}
			if hasError {
				fault, err := exactMembers(m.members["error"])
				if err != nil {
					return nil, fmt.Errorf("%s: the server answered with an error that is not an object", method)
				}
				var code int
				var message string
				json.Unmarshal(fault["code"], &code)
				json.Unmarshal(fault["message"], &message)
				return nil, fmt.Errorf("%s: %s (code %d)", method, message, code)
			}
			if !hasResult {
				return nil, fmt.Errorf("%s: the server answered with neither a result nor an error", method)
			}
			return m.members["result"], nil
		default:
			return nil, errors.New("the server wrote a JSON-RPC message that is neither a request, a notification nor a response")
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err := c.out.Err(); err != nil {
		return nil, fmt.Errorf("reading the server's output: %w", err)
	}
	return nil, fmt.Errorf("the server ended before answering %s", method)
}
