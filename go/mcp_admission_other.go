//go:build !unix

package main

import "context"

// installOperatorControls: the admission signals are Unix signals, and the
// engine's processes run in its Linux image; elsewhere the gates stay
// open.
func installOperatorControls(context.Context, operatorGate) {}

// operatorControls installs the MCP server's.
func (s *mcpServer) operatorControls(ctx context.Context) { installOperatorControls(ctx, s) }
