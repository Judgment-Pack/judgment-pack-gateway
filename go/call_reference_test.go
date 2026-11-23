package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The gate (ADR-0060, Tests): callReference is refused by name below its
// engine version, and is a boolean from it.
func TestCallReferenceIsAMemberOfItsEngineVersionAlone(t *testing.T) {
	if _, err := parsePlatformCallReference(vBool(true), "tickets", admissionReadV2Version); err == nil || !strings.Contains(err.Error(), "platform tickets: callReference is a version-"+callReferenceVersion+" member") {
		t.Fatalf("below the version: %v", err)
	}
	for _, want := range []bool{true, false} {
		if got, err := parsePlatformCallReference(vBool(want), "tickets", callReferenceVersion); err != nil || got != want {
			t.Fatalf("at the version, %v: %v %v", want, got, err)
		}
	}
	if _, err := parsePlatformCallReference(vString("yes"), "tickets", callReferenceVersion); err == nil || !strings.Contains(err.Error(), "callReference, when present, is a boolean") {
		t.Fatalf("not a boolean: %v", err)
	}
	if !engineVersions[callReferenceVersion] || engineVersion != callReferenceVersion {
		t.Fatalf("engine versions: %q %v", engineVersion, engineVersions[callReferenceVersion])
	}
}

// The gate's other half: an opt-in under version 2 receipts, or on a source
// that is not an MCP server, is refused at start naming the binding; the same
// at version 3 on an MCP server starts, and a source without it is not held.
func TestCallReferenceNeedsVersion3ReceiptsAndAnMCPServer(t *testing.T) {
	on := sourceSpec{shape: "mcp", binding: "tickets@sha256:" + strings.Repeat("a", 64), callReference: true}
	off := sourceSpec{shape: "http", binding: "other@sha256:" + strings.Repeat("b", 64)}
	if err := callReferenceRefusal(map[string]sourceSpec{"tickets/live": on, "other/live": off}, receiptVersion); err == nil || !strings.Contains(err.Error(), "tickets/live (binding "+on.binding+") sets callReference, which needs --receipt-version 3") {
		t.Fatalf("version 2: %v", err)
	}
	http := on
	http.shape = "http"
	if err := callReferenceRefusal(map[string]sourceSpec{"tickets/live": http}, receiptVersion3); err == nil || !strings.Contains(err.Error(), "is not an MCP server") {
		t.Fatalf("http: %v", err)
	}
	if err := callReferenceRefusal(map[string]sourceSpec{"tickets/live": on, "other/live": off}, receiptVersion3); err != nil {
		t.Fatal(err)
	}
	if err := callReferenceRefusal(map[string]sourceSpec{"other/live": off}, receiptVersion); err != nil {
		t.Fatal(err)
	}
}

const callRefEnvelope = `{"result":{"n":1},"acquisition":{"adapter":{"name":"fixture","version":"1","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"endpoint":null,"statement":null,"snapshot":null,"peerIdentity":null,"schema":null,"upstreamToken":null,"observedAt":"2026-10-29T00:00:00Z"}}`

// On, off and beside (ADR-0060, Tests): an opted-in source is handed a fresh
// reference and the receipt's session identifier, and its receipt signs the
// same reference; a second call gets another. A source without the opt-in in
// the same engine is handed nothing: its stdin is the canonical arguments, as
// before, its environment carries no reference, and its receipt no callRef.
func TestAnOptedInCallSendsTheReferenceItsReceiptSigns(t *testing.T) {
	service, server := testService(t)
	dir := t.TempDir()
	metaFile, stdinFile := filepath.Join(dir, "meta"), filepath.Join(dir, "stdin")
	t.Setenv(envSourceEnvelope, callRefEnvelope)
	t.Setenv(envSourceCallMetaFile, metaFile)
	t.Setenv(envSourceStdinFile, stdinFile)
	service.sources["tickets/live"] = sourceSpec{argv: []string{os.Args[0]}, env: helperEnv, shape: "mcp", endpoint: "https://mcp.example/", callReference: true}
	service.sources["other/live"] = sourceSpec{argv: []string{os.Args[0]}, env: helperEnv, shape: "mcp", endpoint: "https://mcp.example/"}

	call := func(source string) (map[string]any, string, string) {
		t.Helper()
		_ = os.Remove(metaFile)
		code, body := post(t, server, "/acquire", `{"session":"ref-1","source":"`+source+`","arguments":{"tool":"read","arguments":{"id":"T-1"}}}`)
		if code != 200 {
			t.Fatalf("%s: %d %v", source, code, body)
		}
		meta, _ := os.ReadFile(metaFile)
		stdin, _ := os.ReadFile(stdinFile)
		receipt, _ := body["receipt"].(map[string]any)
		return receipt, string(meta), string(stdin)
	}
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		receipt, meta, _ := call("tickets/live")
		ref, _ := receipt["callRef"].(string)
		session, _ := receipt["sessionId"].(string)
		if !isCallRef(ref) || session == "" || meta != "true "+ref+" true "+session {
			t.Fatalf("on: handed %q, receipt %q %q", meta, ref, session)
		}
		if seen[ref] {
			t.Fatalf("a reference handed twice: %s", ref)
		}
		seen[ref] = true
		// A verifier holds callRef to its form: the receipt as signed reads,
		// and with the reference in capitals it is malformed.
		raw, _ := json.Marshal(receipt)
		for _, tc := range []struct {
			text string
			ok   bool
		}{{string(raw), true}, {strings.Replace(string(raw), ref, strings.ToUpper(ref), 1), false}, {strings.Replace(string(raw), `"`+ref+`"`, `"`+ref[:63]+`"`, 1), false}} {
			v, err := parseJSON([]byte(tc.text))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := receiptFrom(v.(*vObject)); (err == nil) != tc.ok {
				t.Fatalf("verifier on %v: %v", tc.ok, err)
			}
		}
	}
	receipt, meta, stdin := call("other/live")
	if _, present := receipt["callRef"]; present || meta != "false  false " || stdin != `{"arguments":{"id":"T-1"},"tool":"read"}` {
		t.Fatalf("off: receipt %v, handed %q, stdin %q", receipt["callRef"], meta, stdin)
	}
}

// A failed draw refuses the call before the source starts.
func TestAFailedDrawRefusesTheCallBeforeTheSourceStarts(t *testing.T) {
	service, server := testService(t)
	stdinFile := filepath.Join(t.TempDir(), "stdin")
	t.Setenv(envSourceEnvelope, callRefEnvelope)
	t.Setenv(envSourceStdinFile, stdinFile)
	service.sources["tickets/live"] = sourceSpec{argv: []string{os.Args[0]}, env: helperEnv, shape: "mcp", endpoint: "https://mcp.example/", callReference: true}
	saved := callRefRandom
	callRefRandom = func([]byte) (int, error) { return 0, errors.New("no entropy") }
	t.Cleanup(func() { callRefRandom = saved })
	code, body := post(t, server, "/acquire", `{"session":"ref-2","source":"tickets/live","arguments":{"tool":"read","arguments":{}}}`)
	if code == 200 || !strings.Contains(strings.Join([]string{body["error"].(string)}, ""), "call reference could not be drawn") {
		t.Fatalf("%d %v", code, body)
	}
	if _, err := os.Stat(stdinFile); !os.IsNotExist(err) {
		t.Fatalf("the source started: %v", err)
	}
}
