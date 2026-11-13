//go:build unix

package main

// measureSandboxAtStart at serve --config's start, run in this process:
// on, the start says what it measured before it serves; off, it says
// nothing of it. A refusal of a source needs a source, and a source needs
// a user this process can switch to, so that path is run in the engine
// image instead (scripts/checks/image-sandbox-start.sh); the refusal
// itself is held in sandbox_at_start_test.go.

import (
	"os"
	"strings"
	"testing"
)

func TestServeConfigSaysWhatItMeasuredAtStart(t *testing.T) {
	for _, tc := range []struct {
		name, member string
		said         bool
	}{
		{"on", `,"measureSandboxAtStart":true`, true},
		{"off", `,"measureSandboxAtStart":false`, false},
		{"absent", ``, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := probeReturning(t, map[string]probeAnswer{})
			args, _ := engineFiles(t)
			config := readFile(t, args[1])
			raised := strings.Replace(strings.Replace(config, `"engineVersion":"6"`, `"engineVersion":"23"`, 1), `"platforms":{}}`, `"platforms":{}`+tc.member+`}`, 1)
			if !strings.Contains(raised, `"engineVersion":"23"`) {
				t.Fatalf("the configuration was not raised: %s", config)
			}
			if err := os.WriteFile(args[1], []byte(raised), 0o600); err != nil {
				t.Fatal(err)
			}
			g := serveInProcess(t, args)
			if g.exited {
				t.Fatalf("the gateway did not start: exit %d: %s", g.code, g.stderr())
			}
			g.stop()
			said := strings.Contains(g.stderr(), "start: measureSandboxAtStart: the configuration has no source to measure\n")
			if said != tc.said || len(calls) != 0 {
				t.Fatalf("said %v, probes %v: %s", said, calls, g.stderr())
			}
		})
	}
}
