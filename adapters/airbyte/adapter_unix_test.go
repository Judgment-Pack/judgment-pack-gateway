//go:build unix

package airbyte

import (
	"syscall"
	"testing"
)

// The mount's modes are what the connector needs whatever umask the
// adapter was launched under: the mounted directory and its files readable
// by any user, the parent private to the adapter's.
func TestMountModesSurviveARestrictiveUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })
	cfg := fake(t, discoverFixture, readFixture)
	acquire(t, cfg, Request{Stream: "decisions", Limit: 3})
	for _, inv := range invocations(t) {
		if inv.Modes["parent"] != "0700" || inv.Modes["dir"] != "0755" || inv.Modes["config.json"] != "0644" {
			t.Fatalf("modes under umask 077: %v", inv.Modes)
		}
	}
}
