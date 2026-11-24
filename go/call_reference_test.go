package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// The gate's other half: an opt-in on a source that is not an MCP server is
// refused at start naming the binding; the same on an MCP server starts, and
// a source without it is not held. An engine's receipts are always version 3,
// and the engine's own options say so.
func TestCallReferenceNeedsAnMCPServer(t *testing.T) {
	on := sourceSpec{shape: "mcp", binding: "tickets@sha256:" + strings.Repeat("a", 64), callReference: true}
	off := sourceSpec{shape: "http", binding: "other@sha256:" + strings.Repeat("b", 64)}
	if got := engineServeOptions(engineConfig{version: callReferenceVersion}, nil, nil).receiptVersion; got != receiptVersion3 {
		t.Fatalf("an engine's receipts: version %q", got)
	}
	http := on
	http.shape = "http"
	if err := callReferenceRefusal(map[string]sourceSpec{"tickets/live": http}); err == nil || !strings.Contains(err.Error(), "platform tickets: callReference on source tickets/live") || !strings.Contains(err.Error(), "is not an MCP server") {
		t.Fatalf("http: %v", err)
	}
	if err := callReferenceRefusal(map[string]sourceSpec{"tickets/live": on, "other/live": off}); err != nil {
		t.Fatal(err)
	}
	if err := callReferenceRefusal(map[string]sourceSpec{"other/live": off}); err != nil {
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

// receiptAt is the receipt of an answer's member, as JSON reads it: an
// uncertain action answers its action and the read-back made at once.
func receiptAt(t *testing.T, out map[string]any, member string) map[string]any {
	t.Helper()
	raw, err := json.Marshal(out[member])
	var m struct {
		Receipt map[string]any `json:"receipt"`
	}
	if err != nil || json.Unmarshal(raw, &m) != nil || m.Receipt == nil {
		t.Fatalf("the answer's %s receipt: %s", member, raw)
	}
	return m.Receipt
}

// handedLine is one run of the action target: its mode, and the reference
// and session it was handed, if any.
type handedLine struct {
	mode, ref, session string
	hasRef, hasSession bool
}

func handedLines(t *testing.T, path string) []handedLine {
	t.Helper()
	data, _ := os.ReadFile(path)
	var lines []handedLine
	for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		f := strings.Split(l, " ")
		if len(f) != 5 {
			t.Fatalf("a handed line: %q", l)
		}
		lines = append(lines, handedLine{mode: f[0], hasRef: f[1] == "true", ref: f[2], hasSession: f[3] == "true", session: f[4]})
	}
	return lines
}

// /act and its reconciled read-back (ADR-0060; on and off): the write an
// opted-in platform dispatches is handed a reference its receipt signs, its
// uncertain receipt included. Each read-back -- the one the uncertain action
// makes at once, in the action's session, and a reconciling request's after a
// restart, in that request's session -- draws its own under the session
// identifier its receipt names, and signs it into that receipt. Off, nothing is handed, neither receipt has
// callRef, and the write's stdin is byte for byte the opted-in one's.
func TestAnOptedInActionAndItsReadBackSignTheReferencesTheySent(t *testing.T) {
	if !actionJournalSupported {
		t.Skip("keyed dispatch fails closed on this host")
	}
	t.Setenv(envSourceHelper, "1")
	scenario := func(t *testing.T, on bool) (first, atOnce, readBack map[string]any, lines []handedLine, stdin []byte) {
		root := t.TempDir()
		actionKeysMode(t, root, "write", "drop")
		actionKeysMode(t, root, "live", "read")
		metaFile, stdinFile := filepath.Join(root, "call-meta"), filepath.Join(root, "stdin")
		sources := func() map[string]sourceSpec {
			s := actionKeysSources(t, root, os.Args[0], "ACTION_KEYS_CALL_META="+metaFile, "ACTION_KEYS_STDIN="+stdinFile)
			for _, name := range []string{"tickets/write", "tickets/live"} {
				spec := s[name]
				spec.callReference = on
				s[name] = spec
			}
			return s
		}
		g := actionKeysService(t, root, sources())
		c := actionKeysPrepare(t, g, root)
		key := strings.Repeat("c", 64)
		out, err := scopedAct(g, c, "first", key, actionKeysWho, true, false)
		if err != nil {
			t.Fatal(err)
		}
		first, atOnce = receiptAt(t, out, "action"), receiptAt(t, out, "reconciliation")
		stdin, _ = os.ReadFile(stdinFile + "-drop")
		actionKeysMode(t, root, "write", "respond")
		if out, err = scopedAct(actionKeysService(t, root, sources()), c, "takeover", key, actionKeysWho, true, true); err != nil {
			t.Fatal(err)
		}
		readBack = receiptAt(t, out, "reconciliation")
		return first, atOnce, readBack, handedLines(t, metaFile), stdin
	}
	first, atOnce, readBack, lines, onStdin := scenario(t, true)
	// The read-back made at once is in the action's session; a later one is
	// in the session the reconciling request names, and cites the action.
	cited, _ := readBack["acquisition"].(map[string]any)["reconciliation"].(map[string]any)["action"].(map[string]any)
	if first["sessionId"] != "first" || atOnce["sessionId"] != "first" || readBack["sessionId"] != "takeover" || cited["sessionId"] != "first" {
		t.Fatalf("sessions: %v %v %v, citing %v", first["sessionId"], atOnce["sessionId"], readBack["sessionId"], cited)
	}
	var write, read []handedLine
	for _, l := range lines {
		if !l.hasRef || !l.hasSession || !isCallRef(l.ref) {
			t.Fatalf("on: handed %+v", l)
		}
		if l.mode == "drop" {
			write = append(write, l)
		} else {
			read = append(read, l)
		}
	}
	if len(write) != 1 || len(read) != 2 || first["callRef"] != write[0].ref || atOnce["callRef"] != read[0].ref || readBack["callRef"] != read[1].ref ||
		write[0].ref == read[0].ref || read[0].ref == read[1].ref {
		t.Fatalf("on: write %+v read %+v; receipts %v %v %v", write, read, first["callRef"], atOnce["callRef"], readBack["callRef"])
	}
	// each was handed the session identifier its own receipt names
	if write[0].session != first["sessionId"] || read[0].session != atOnce["sessionId"] || read[1].session != readBack["sessionId"] {
		t.Fatalf("on: sessions handed %+v %+v", write, read)
	}
	first, atOnce, readBack, lines, offStdin := scenario(t, false)
	for _, r := range []map[string]any{first, atOnce, readBack} {
		if _, present := r["callRef"]; present {
			t.Fatalf("off: a receipt carries callRef: %v", r)
		}
	}
	for _, l := range lines {
		if l.hasRef || l.hasSession {
			t.Fatalf("off: handed %+v", l)
		}
	}
	if len(onStdin) == 0 || string(onStdin) != string(offStdin) {
		t.Fatalf("the write's stdin differs: %q / %q", onStdin, offStdin)
	}
}

// Two calls in flight at once (ADR-0060): each write waits until the other
// is in flight, and each is handed its own reference, signed into its own
// receipt.
func TestConcurrentCallsGetDistinctReferences(t *testing.T) {
	if !actionJournalSupported {
		t.Skip("keyed dispatch fails closed on this host")
	}
	t.Setenv(envSourceHelper, "1")
	root := t.TempDir()
	actionKeysMode(t, root, "write", "rendezvous")
	actionKeysMode(t, root, "live", "read")
	metaFile := filepath.Join(root, "call-meta")
	sources := actionKeysSources(t, root, os.Args[0], "ACTION_KEYS_CALL_META="+metaFile)
	spec := sources["tickets/write"]
	spec.callReference = true
	sources["tickets/write"] = spec
	g := actionKeysService(t, root, sources)
	c := actionKeysPrepare(t, g, root)
	refs := make([]string, 2)
	var wg sync.WaitGroup
	for i, key := range []string{strings.Repeat("a", 64), strings.Repeat("b", 64)} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := actionKeysAct(g, c, fmt.Sprintf("act-%d", i), key)
			if err != nil {
				t.Errorf("key %d: %v", i, err)
				return
			}
			receipt, _ := out["receipt"].(map[string]any)
			refs[i], _ = receipt["callRef"].(string)
		}()
	}
	wg.Wait()
	lines := handedLines(t, metaFile)
	if len(lines) != 2 || !isCallRef(refs[0]) || !isCallRef(refs[1]) || refs[0] == refs[1] {
		t.Fatalf("handed %+v, receipts %v", lines, refs)
	}
	for _, l := range lines {
		if want := refs[strings.TrimPrefix(l.session, "act-")[0]-'0']; l.ref != want {
			t.Fatalf("%s was handed %s, its receipt signs %s", l.session, l.ref, want)
		}
	}
}

// A reader that does not know callRef (ADR-0060, amendment): it holds the
// members it knows, and the signature is over every member, callRef among
// them, so the receipt verifies under the signer's key; the same core with
// callRef dropped does not.
func TestAReaderThatDoesNotKnowCallRefStillVerifiesTheSignature(t *testing.T) {
	service, server := testService(t)
	t.Setenv(envSourceEnvelope, callRefEnvelope)
	service.sources["tickets/live"] = sourceSpec{argv: []string{os.Args[0]}, env: helperEnv, shape: "mcp", endpoint: "https://mcp.example/", callReference: true}
	code, body := post(t, server, "/acquire", `{"session":"ref-3","source":"tickets/live","arguments":{"tool":"read","arguments":{}}}`)
	if code != 200 {
		t.Fatalf("%d %v", code, body)
	}
	raw, _ := json.Marshal(body["receipt"])
	v, err := parseJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	obj := v.(*vObject)
	core, withoutRef, known := newObject(), newObject(), newObject()
	for _, name := range obj.names {
		member, _ := obj.get(name)
		if name != "callRef" {
			known.set(name, member)
		}
		if name != "signature" {
			core.set(name, member)
			if name != "callRef" {
				withoutRef.set(name, member)
			}
		}
	}
	if _, present := core.get("callRef"); !present {
		t.Fatal("no callRef")
	}
	// the members such a reader knows hold, as it reads them
	if _, err := receiptFrom(known); err != nil {
		t.Fatalf("the members a reader knows: %v", err)
	}
	signatureHex, _ := memberString(obj, "signature")
	signature, _ := hex.DecodeString(signatureHex)
	public := ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)
	if !ed25519.Verify(public, append([]byte(receiptContext3), canon(core)...), signature) {
		t.Fatal("the signature does not verify over every member")
	}
	if ed25519.Verify(public, append([]byte(receiptContext3), canon(withoutRef)...), signature) {
		t.Fatal("callRef is not signed")
	}
}

// The sandbox posture probe a launch waits for is handed the source as it was
// configured: neither call-reference variable reaches it, whatever the call's
// environment holds, and the rest of that environment is kept in order.
func TestTheSandboxProbeIsNotHandedTheCallReference(t *testing.T) {
	saved := sandboxPostureProbe
	t.Cleanup(func() { sandboxPostureProbe = saved })
	var probed []string
	sandboxPostureProbe = func(_ context.Context, s sourceSpec) (sandboxProbeReport, error) {
		probed = append([]string(nil), s.env...)
		return sandboxProbeReport{}, errors.New("stop after the probe")
	}
	// an absolute path on every platform, naming nothing: the helper is
	// never run, and a path that is not absolute is refused before the probe
	helper := filepath.Join(t.TempDir(), "sandbox-helper-that-is-never-run")
	base := sourceSpec{shape: "mcp", callReference: true, env: []string{"KEEP=1"}, sandbox: &sourceSandbox{helper: helper}}
	run, ref, err := withCallReference(base, "s1")
	if err != nil || ref == "" {
		t.Fatal(ref, err)
	}
	if _, err := sandboxSourceCommand(context.Background(), run, filepath.Join(t.TempDir(), "adapter-that-is-never-run"), []string{"adapter"}); err == nil {
		t.Fatal("the stub probe's failure did not refuse the launch")
	}
	if len(probed) != 1 || probed[0] != "KEEP=1" {
		t.Fatalf("probe environment: %q", probed)
	}
	if off := withoutCallReference(sourceSpec{env: []string{callRefVariable + "=x"}}); len(off.env) != 1 {
		t.Fatalf("a source that did not opt in is returned as it is: %q", off.env)
	}
}
