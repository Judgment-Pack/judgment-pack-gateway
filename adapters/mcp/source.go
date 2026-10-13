package mcp

import "encoding/json"

// A connection in adapters/connections that reaches a provider's own MCP
// server over Streamable HTTP reads a tool's declared output schema and its
// result as this adapter's remote form reads a source's, each held to the
// same rules.

// ToolError is a tool result that reports an error (isError true), read as
// a source reads one: a read that did not happen. Text is the text of its
// content items, joined, as the server wrote it.
type ToolError struct{ Text string }

func (e *ToolError) Error() string { return "the tool reported an error: " + e.Text }

// ToolResult holds a tools/call result to what a CallToolResult is, as the
// remote form holds a source's, and returns its canonical form; one that
// reports an error is refused as a *ToolError.
func ToolResult(raw json.RawMessage) ([]byte, error) { return parseToolResult(raw, false) }

// OutputSchema is a tool descriptor's declared output schema in canonical
// form, or nil where it declares none, as the remote form records it.
func OutputSchema(descriptor json.RawMessage) ([]byte, error) { return outputSchemaOf(descriptor) }
