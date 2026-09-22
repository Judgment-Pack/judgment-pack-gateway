//go:build linux || darwin

package connections

import (
	"context"
	"testing"
)

func TestDisconnectDoesNotInventRemoteRevocation(t *testing.T) {
	for _, connected := range []bool{false, true} {
		b, _, _ := testBroker(t)
		if connected {
			r := finish(t, b, start(t, b, "connect"), nil)
			if r.State != "complete" {
				t.Fatal(r)
			}
		}
		b.provider.revoke = ""
		result, err := b.Handle(context.Background(), "disconnect", nil)
		if err != nil || result.(map[string]bool)["revoked"] || !result.(map[string]bool)["disconnected"] {
			t.Fatal(result, err)
		}
		status, err := b.Handle(context.Background(), "status", nil)
		if err != nil || status.(Status).State == "connected" {
			t.Fatal("local access survived", status, err)
		}
	}
}
