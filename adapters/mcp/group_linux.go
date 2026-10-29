//go:build linux

package mcp

import (
	"adapters/internal/descendants"
	"time"
)

func adoptOrphans() error    { return descendants.Adopt() }
func killDescendants() error { return descendants.Kill() }
func stopDescendants(scan func() ([]int, int, error), kill func(int), within time.Duration) error {
	return descendants.Stop(scan, kill, within)
}
