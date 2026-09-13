package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
}

type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
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
		var m rpcMessage
		if err := json.Unmarshal(c.out.Bytes(), &m); err != nil || m.JSONRPC != "2.0" {
			return nil, errors.New("the server wrote a line on stdout that is not a JSON-RPC message")
		}
		isRequest := m.Method != "" && len(m.ID) > 0 && string(m.ID) != "null"
		switch {
		case isRequest:
			// A server may ask its client for roots or sampling; this
			// client serves nothing, and says so rather than hang the
			// server waiting.
			if err := c.send(map[string]any{"jsonrpc": "2.0", "id": m.ID, "error": rpcError{Code: -32601, Message: "this client serves no requests"}}); err != nil {
				return nil, err
			}
		case m.Method != "":
			// A notification: nothing to answer.
		case len(m.ID) > 0:
			var got int64
			if json.Unmarshal(m.ID, &got) != nil || got != id {
				continue // a response to another request, which this client never made
			}
			if m.Error != nil {
				return nil, fmt.Errorf("%s: %s (code %d)", method, m.Error.Message, m.Error.Code)
			}
			return m.Result, nil
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
