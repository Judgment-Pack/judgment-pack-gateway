//go:build !unix

package main

import "context"

// operatorControls: the admission signals are Unix signals, and the
// process runs in the engine's Linux image; elsewhere admission stays
// open.
func (s *mcpServer) operatorControls(context.Context) {}
