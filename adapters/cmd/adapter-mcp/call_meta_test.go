package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"adapters/internal/fakemcp"
	"adapters/mcp"
)

// The transport (ADR-0060): adapter-mcp is handed the reference in its
// environment and takes it out before it starts the server, which learns it
// only from the tools/call request's _meta. Without it the request has no
// _meta.
func TestTheServerLearnsTheCallReferenceFromMetaAlone(t *testing.T) {
	ref := strings.Repeat("0123456789abcdef", 4)
	for _, on := range []bool{true, false} {
		dir := t.TempDir()
		trace := filepath.Join(dir, "trace.jsonl")
		t.Setenv(fakemcp.EnvActivate, "1")
		t.Setenv(fakemcp.EnvTrace, trace)
		t.Setenv(fakemcp.EnvEnvKeys, mcp.CallRefVariable+","+mcp.SessionIDVariable)
		t.Setenv(mcp.CallRefVariable, ref)
		t.Setenv(mcp.SessionIDVariable, "s-1")
		if !on {
			os.Unsetenv(mcp.CallRefVariable)
			os.Unsetenv(mcp.SessionIDVariable)
		}
		credentials := filepath.Join(dir, "credentials.json")
		if err := os.WriteFile(credentials, []byte(`{"TOKEN":"t"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		args := []string{"--credentials", credentials, "--endpoint", "api.example", "--tools", "query", "--", os.Args[0]}
		var stdout, stderr bytes.Buffer
		if code := run(args, strings.NewReader(`{"tool":"query","arguments":{"sql":"select 1"}}`), &stdout, &stderr); code != 0 {
			t.Fatalf("on %v: exit %d: %s", on, code, stderr.String())
		}
		if _, present := os.LookupEnv(mcp.CallRefVariable); present {
			t.Fatal("the adapter kept the reference in its environment")
		}
		tr, _ := os.ReadFile(trace)
		if !strings.Contains(string(tr), `"env":{"ADAPTER_MCP_CALL_REF":"","ADAPTER_MCP_SESSION_ID":""}`) {
			t.Fatalf("on %v: the server's environment: %s", on, tr)
		}
		var call string
		for _, line := range strings.Split(string(tr), "\n") {
			if strings.Contains(line, `"method":"tools/call"`) {
				call = line
			}
		}
		meta := `"_meta":{"judgment-pack/callRef":"` + ref + `","judgment-pack/sessionId":"s-1"}`
		if on && !strings.Contains(call, meta) || !on && strings.Contains(call, "_meta") || call == "" {
			t.Fatalf("on %v: tools/call: %s", on, call)
		}
	}
}
