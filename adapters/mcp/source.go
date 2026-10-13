package mcp

import (
	"context"
	"encoding/json"
	"errors"

	"adapters/mcphttp"
)

// A connection in adapters/connections that reaches a provider's own MCP
// server over Streamable HTTP reads it as this adapter's remote form reads
// a source: the tool's descriptor from tools/list, its declared output
// schema, and its result, each held to the same rules.

// ToolError is a tool result that reports an error (isError true), read as
// a source reads one: a read that did not happen. Text is the text of its
// content items, joined, as the server wrote it.
type ToolError struct{ Text string }

func (e *ToolError) Error() string { return "the tool reported an error: " + e.Text }

// ErrNotOffered is a tool the server's tools/list does not name.
var ErrNotOffered = errors.New("the server does not offer the tool")

// ToolResult holds a tools/call result to what a CallToolResult is, as the
// remote form holds a source's, and returns its canonical form; one that
// reports an error is refused as a *ToolError.
func ToolResult(raw json.RawMessage) ([]byte, error) { return parseToolResult(raw, false) }

// OutputSchema is a tool descriptor's declared output schema in canonical
// form, or nil where it declares none, as the remote form records it.
func OutputSchema(descriptor json.RawMessage) ([]byte, error) { return outputSchemaOf(descriptor) }

// OfferedTool pages the server's tools/list through client, once the
// session is initialized, until the tool named is found, and returns its
// descriptor as the server wrote it; a tool the server does not offer is
// ErrNotOffered.
func OfferedTool(ctx context.Context, client *mcphttp.Client, name string) (json.RawMessage, error) {
	descriptor, names, err := findTool(ctx, remoteConversation{client}, name)
	if err != nil && names != nil {
		return nil, ErrNotOffered
	}
	return descriptor, err
}

// OfferedTools is every tool name the server offers, through client once
// the session is initialized, in the order its pages list them.
func OfferedTools(ctx context.Context, client *mcphttp.Client) ([]string, error) {
	return listTools(ctx, remoteConversation{client}, false, nil)
}
