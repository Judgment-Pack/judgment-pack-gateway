//go:build unix

package main

// `gateway serve` from the command line, run in this process (#387): what
// it writes on stderr when it starts on a loopback address is the readiness
// line alone, naming the address it bound, with --listen or without.

import (
	"crypto/ed25519"
	"testing"
)

func TestServeStartsWithTheReadinessLineAloneOnLoopback(t *testing.T) {
	key := keyIDFor(ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey))
	for _, tc := range []struct {
		name, network, host, origin string
		listen                      []string
	}{
		{"no --listen", "tcp4", "127.0.0.1", "http://127.0.0.1:", nil},
		{"--listen ::1", "tcp6", "::1", "http://[::1]:", []string{"--listen", "::1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args, _ := servedFiles(t)
			// servedFiles ends in --port and a port free on 127.0.0.1; this
			// one is free where the gateway is to listen
			port := boundOn(t, tc.network, tc.host)
			args = append(args[:len(args)-1], port)
			g := serveInProcess(t, append(args, tc.listen...))
			if g.exited {
				t.Fatalf("exited %d: %s", g.code, g.stderr())
			}
			want := "gateway on " + tc.origin + port + " (authority gateway:test, key " + key + ")\n"
			if got := g.stderr(); got != want {
				t.Fatalf("stderr\n%q, want\n%q", got, want)
			}
			if code := g.stop(); code != 0 {
				t.Fatalf("stopped with %d: %s", code, g.stderr())
			}
		})
	}
}
