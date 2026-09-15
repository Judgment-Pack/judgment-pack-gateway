//go:build unix

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// installOperatorControls closes a process's admission gate on SIGUSR1 and
// reopens it on SIGUSR2 (docs/design/mcp-server.md, "Rotation"), until the
// context ends. A second SIGUSR1 while closed reports where the closure
// stands.
func installOperatorControls(ctx context.Context, gate operatorGate) {
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		defer signal.Stop(signals)
		for {
			select {
			case <-ctx.Done():
				return
			case sig := <-signals:
				if sig == syscall.SIGUSR1 {
					gate.closeAdmission()
				} else {
					gate.openAdmission()
				}
			}
		}
	}()
}

// operatorControls installs the MCP server's.
func (s *mcpServer) operatorControls(ctx context.Context) { installOperatorControls(ctx, s) }
