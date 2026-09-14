//go:build unix

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// operatorControls closes admission on SIGUSR1 and reopens it on SIGUSR2
// (docs/design/mcp-server.md, "Rotation"), until the context ends.
func (s *mcpServer) operatorControls(ctx context.Context) {
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
					s.closeAdmission()
				} else {
					s.openAdmission()
				}
			}
		}
	}()
}
