package mcp

import (
	"encoding/json"
	"errors"
	"testing"
)

// Off (ADR-0060): without a reference the tools/call params are the bytes
// the adapter sent before, compared with the literal it built then. On:
// _meta carries exactly the reference and the session identifier.
func TestToolsCallParamsChangeOnlyForACallHandedAReference(t *testing.T) {
	args := json.RawMessage(`{"id":"T-1"}`)
	before, _ := json.Marshal(map[string]any{"name": "read", "arguments": args})
	off, _ := json.Marshal(toolsCallParams("read", args, nil))
	if string(off) != string(before) {
		t.Fatalf("off: %s, before %s", off, before)
	}
	ref := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	on, _ := json.Marshal(toolsCallParams("read", args, &CallMeta{CallRef: ref, SessionID: "s-1"}))
	if want := `{"_meta":{"judgment-pack/callRef":"` + ref + `","judgment-pack/sessionId":"s-1"},"arguments":{"id":"T-1"},"name":"read"}`; string(on) != want {
		t.Fatalf("on: %s", on)
	}
}

// The reference is read from the environment and taken out of it; one half
// without the other, or a reference out of its form, is refused.
func TestTakeCallMetaReadsBothOrNeither(t *testing.T) {
	ref := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	run := func(env map[string]string) (*CallMeta, error, map[string]string) {
		unset := func(k string) error { delete(env, k); return nil }
		lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
		m, err := TakeCallMeta(lookup, unset)
		return m, err, env
	}
	if m, err, env := run(map[string]string{CallRefVariable: ref, SessionIDVariable: "s-1", "OTHER": "x"}); err != nil || m == nil || m.CallRef != ref || m.SessionID != "s-1" || len(env) != 1 {
		t.Fatalf("both: %v %v %v", m, err, env)
	}
	if m, err, _ := run(map[string]string{}); m != nil || err != nil {
		t.Fatalf("neither: %v %v", m, err)
	}
	for _, env := range []map[string]string{{CallRefVariable: ref}, {SessionIDVariable: "s-1"}, {CallRefVariable: ref[:63], SessionIDVariable: "s"}, {CallRefVariable: "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef", SessionIDVariable: "s"}} {
		if m, err, _ := run(env); m != nil || err == nil {
			t.Fatalf("%v: %v %v", env, m, err)
		}
	}
	if _, err := TakeCallMeta(func(string) (string, bool) { return "", false }, func(string) error { return errors.New("x") }); err == nil {
		t.Fatal("a failed unset passes")
	}
}
