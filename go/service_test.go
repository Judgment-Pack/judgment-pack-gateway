package main

// Service-level tests: the demonstration this repository exists to make, and the
// hardening around it. Ported from the Python reference when it was retired.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testSeed = []byte("judgment-pack-gateway-test-seed!") // exactly 32 bytes

const envSourceHelper = "GATEWAY_TEST_SOURCE_HELPER"

// Barrier channels for the admission tests. The helper announces that it has
// STARTED and then blocks until it is let go, so a test can hold a source
// mid-flight without asserting anything about timing.
const (
	envSourceReady = "GATEWAY_TEST_SOURCE_READY"
	envSourceWait  = "GATEWAY_TEST_SOURCE_WAIT"
	envSourceFail  = "GATEWAY_TEST_SOURCE_FAIL"
)

// A barrier named in the ARGUMENTS rather than the environment. Every helper
// this process starts inherits the same environment, so an environment-named
// barrier holds all of them at once and cannot express "hold session A while
// session B keeps working". Arguments differ per acquisition, so they can.
const barrierArgPrefix = "barrier:"

const (
	startedFile = "started"
	releaseFile = "release"
)

// barrierArg builds the arguments value that puts one acquisition's source
// behind the barrier in dir.
func barrierArg(dir string) value { return vString(barrierArgPrefix + dir) }

// barrierDir reports the barrier directory a canonical arguments value names,
// if it names one. An ordinary arguments value does not, and its source runs
// straight through.
func barrierDir(arguments []byte) (string, bool) {
	var s string
	if err := json.Unmarshal(arguments, &s); err != nil {
		return "", false
	}
	return strings.CutPrefix(s, barrierArgPrefix)
}

// awaitFile blocks until path exists. It runs inside the helper process, where
// there is no *testing.T to fail; a helper that is never released is killed by
// the gateway's own subprocess timeout.
func awaitFile(path string) {
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func TestMain(m *testing.M) {
	if os.Getenv(envSourceHelper) == "1" {
		arguments, _ := io.ReadAll(os.Stdin)
		if ready := os.Getenv(envSourceReady); ready != "" {
			_ = os.WriteFile(ready, []byte("started\n"), 0o600)
		}
		if dir, ok := barrierDir(arguments); ok {
			_ = os.WriteFile(filepath.Join(dir, startedFile), []byte("started\n"), 0o600)
			awaitFile(filepath.Join(dir, releaseFile))
		}
		if wait := os.Getenv(envSourceWait); wait != "" {
			awaitFile(wait)
		}
		if os.Getenv(envSourceFail) == "1" {
			fmt.Fprintln(os.Stderr, "source refused")
			os.Exit(1)
		}
		fmt.Print(`{"checkedSuccessfully":true,"status":"not_found"}`)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// waitForFile blocks until path exists. It fails the test rather than returning
// on a deadline, so a barrier that never opens is reported as the bug it is
// instead of silently becoming a race.
func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("barrier never opened: %s", path)
		}
		time.Sleep(time.Millisecond)
	}
}

func openBarrier(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("go\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func registryLines(t *testing.T, path string) int {
	t.Helper()
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return len(bytes.Split(bytes.TrimSpace(raw), []byte("\n"))) - boolToInt(len(bytes.TrimSpace(raw)) == 0)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func testStore(t *testing.T) (*store, *registryWriter, string, string) {
	t.Helper()
	root := t.TempDir()
	storeRoot := filepath.Join(root, "store")
	registryPath := filepath.Join(root, "registry.jsonl")
	st, err := newStore(storeRoot, testSeed, "gateway:test")
	if err != nil {
		t.Fatal(err)
	}
	reg, err := newRegistryWriter(registryPath, testSeed)
	if err != nil {
		t.Fatal(err)
	}
	return st, reg, storeRoot, registryPath
}

// stampSession attests `count` chained receipts, as the gateway would.
func stampSession(t *testing.T, st *store, sessionID string, count int64) {
	t.Helper()
	prev := ""
	for index := int64(0); index < count; index++ {
		payload := newObject()
		payload.set("session", vString(sessionID))
		payload.set("n", vInt(index))
		digest, err := st.retain(canon(payload))
		if err != nil {
			t.Fatal(err)
		}
		core := newObject()
		core.set("receiptVersion", vString(receiptVersion))
		core.set("sessionId", vString(sessionID))
		core.set("callIndex", vInt(index))
		if prev == "" {
			core.set("prevSignature", vNull{})
		} else {
			core.set("prevSignature", vString(prev))
		}
		core.set("source", vString("s"))
		core.set("argumentsDigest", vString("hmac-sha256:"+strings.Repeat("0", 64)))
		core.set("resultDigest", vString(digest))
		core.set("servedAt", vString("2026-07-31T00:00:00Z"))
		core.set("authority", vString("gateway:test"))
		_, signature, err := st.stamp(core)
		if err != nil {
			t.Fatal(err)
		}
		prev = signature
	}
}

func statuses(t *testing.T, storeRoot, registryPath string) (bool, map[string]int) {
	t.Helper()
	public := []byte(mustPublic(t))
	rep, err := verifyWithRegistry(storeRoot, registryPath, "gateway:test", public)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := rep.marshal()
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		OK       bool             `json:"ok"`
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, f := range decoded.Findings {
		if s, ok := f["status"].(string); ok {
			counts[s]++
		}
	}
	return decoded.OK, counts
}

func mustPublic(t *testing.T) string {
	t.Helper()
	st, err := newStore(t.TempDir(), testSeed, "x")
	if err != nil {
		t.Fatal(err)
	}
	return string(st.publicKey)
}

func TestSealedStoreVerifies(t *testing.T) {
	st, reg, storeRoot, registryPath := testStore(t)
	stampSession(t, st, "sess-a", 3)
	if _, err := reg.seal("sess-a", 3, "2026-07-31T00:00:01Z"); err != nil {
		t.Fatal(err)
	}
	ok, counts := statuses(t, storeRoot, registryPath)
	if !ok {
		t.Fatalf("a sealed, intact store did not verify: %v", counts)
	}
}

// The demonstration: per-receipt verification PASSES the same stores the
// registry-anchored verification rejects.
func TestPerReceiptVerificationMissesWhatTheRegistryCatches(t *testing.T) {
	st, reg, storeRoot, registryPath := testStore(t)
	stampSession(t, st, "sess-a", 3)
	if _, err := reg.seal("sess-a", 3, "2026-07-31T00:00:01Z"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(storeRoot, "receipts", "sess-a", "2.json")); err != nil {
		t.Fatal(err)
	}
	// Without the anchor: the truncated prefix is a valid chain.
	inline, err := verifyWithRegistry(storeRoot, os.DevNull, "gateway:test", []byte(mustPublic(t)))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := inline.marshal()
	if !bytes.Contains(raw, []byte("unregistered-session")) {
		t.Fatal("expected the anchor-less run to see only an unsealed session")
	}
	if bytes.Contains(raw, []byte("signature-mismatch")) || bytes.Contains(raw, []byte("chain-broken")) {
		t.Fatal("per-receipt verification should pass a truncated prefix")
	}
	// With the anchor: caught.
	ok, counts := statuses(t, storeRoot, registryPath)
	if ok || counts["tail-rollback"] != 1 {
		t.Fatalf("tail rollback not caught: ok=%v %v", ok, counts)
	}
}

func TestWholeSessionReplayIsUnregistered(t *testing.T) {
	st, _, storeRoot, registryPath := testStore(t)
	stampSession(t, st, "replayed", 2) // never sealed
	ok, counts := statuses(t, storeRoot, registryPath)
	if ok || counts["unregistered-session"] != 1 {
		t.Fatalf("replay not caught: ok=%v %v", ok, counts)
	}
}

func TestForgedSealIsDropped(t *testing.T) {
	st, _, storeRoot, registryPath := testStore(t)
	stampSession(t, st, "replayed", 2)
	forged := fmt.Sprintf(
		`{"finalCount":2,"keyId":"%s","sealedAt":"x","sessionId":"replayed","signature":"%s"}`,
		keyIDFor([]byte(mustPublic(t))), strings.Repeat("0", 128))
	if err := os.WriteFile(registryPath, []byte(forged+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ok, counts := statuses(t, storeRoot, registryPath)
	if ok || counts["unregistered-session"] != 1 {
		t.Fatalf("a seal nobody could sign was honoured: ok=%v %v", ok, counts)
	}
}

func TestWholeSessionDeletionIsCaught(t *testing.T) {
	st, reg, storeRoot, registryPath := testStore(t)
	stampSession(t, st, "sess-a", 2)
	stampSession(t, st, "sess-b", 2)
	for _, name := range []string{"sess-a", "sess-b"} {
		if _, err := reg.seal(name, 2, "t"); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.RemoveAll(filepath.Join(storeRoot, "receipts", "sess-b")); err != nil {
		t.Fatal(err)
	}
	ok, counts := statuses(t, storeRoot, registryPath)
	if ok || counts["sealed-session-missing"] != 1 {
		t.Fatalf("deleted session not caught: ok=%v %v", ok, counts)
	}
}

func TestResealIsRefused(t *testing.T) {
	_, reg, _, _ := testStore(t)
	if _, err := reg.seal("sess-a", 3, "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.seal("sess-a", 1, "t"); err == nil {
		t.Fatal("append-only violated: a seal was shrunk")
	}
}

// A session id names a directory under the store, and verification discovers
// sessions by ENUMERATING it. A value that escaped would produce genuinely
// signed receipts verification could never see.
func TestSessionIdIsNotAPath(t *testing.T) {
	st, reg, _, _ := testStore(t)
	core := func(sessionID string) *vObject {
		o := newObject()
		o.set("receiptVersion", vString(receiptVersion))
		o.set("sessionId", vString(sessionID))
		o.set("callIndex", vInt(0))
		o.set("prevSignature", vNull{})
		o.set("source", vString("s"))
		o.set("argumentsDigest", vString("x"))
		o.set("resultDigest", vString("y"))
		o.set("servedAt", vString("t"))
		o.set("authority", vString("gateway:test"))
		return o
	}
	for _, bad := range []string{
		filepath.Join(t.TempDir(), "ESCAPED"), "../../TRAVERSED", "a/b", ".", "..",
		"", strings.Repeat("x", 129), "sess id",
	} {
		if _, _, err := st.stamp(core(bad)); err == nil {
			t.Fatalf("session id %q was accepted", bad)
		}
	}
	for _, good := range []string{"s1", "sess-a", "run_2026.07.31", strings.Repeat("A", 128)} {
		if _, _, err := st.stamp(core(good)); err != nil {
			t.Fatalf("legitimate session id %q was refused: %v", good, err)
		}
	}
	if _, err := reg.seal("../../ESCAPED", 1, "t"); err == nil {
		t.Fatal("the registry sealed an escaping session id")
	}
}

// --- the HTTP surface ------------------------------------------------------

func testService(t *testing.T) (*gatewayService, *httptest.Server) {
	t.Helper()
	t.Setenv(envSourceHelper, "1")
	root := t.TempDir()
	service, err := newGatewayService(
		filepath.Join(root, "store"), testSeed, "gateway:test",
		filepath.Join(root, "registry.jsonl"),
		map[string][]string{"screening": {os.Args[0]}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(service.handler())
	t.Cleanup(server.Close)
	return service, server
}

func post(t *testing.T, server *httptest.Server, path, body string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(server.URL+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var decoded map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&decoded)
	return resp.StatusCode, decoded
}

func TestAcquireSealVerifyRoundTrip(t *testing.T) {
	service, server := testService(t)

	code, first := post(t, server, "/acquire",
		`{"session":"http-1","source":"screening","arguments":{"q":"acme"}}`)
	if code != http.StatusOK {
		t.Fatalf("acquire failed: %d %v", code, first)
	}
	result := first["result"].(map[string]any)
	if result["status"] != "not_found" {
		t.Fatalf("unexpected result: %v", result)
	}
	receipt := first["receipt"].(map[string]any)
	if receipt["keyId"] != service.keyID {
		t.Fatal("receipt does not name the gateway's key")
	}
	// The response receipt is the complete stored object: every member the
	// signature covers, keyId and signature beside them (SPEC.md §6).
	for _, member := range []string{
		"receiptVersion", "sessionId", "callIndex", "prevSignature", "source",
		"argumentsDigest", "resultDigest", "servedAt", "authority", "keyId", "signature",
	} {
		if _, present := receipt[member]; !present {
			t.Fatalf("the response receipt must carry %q; got %v", member, receipt)
		}
	}
	if len(receipt) != 11 {
		t.Fatalf("the response receipt carries the receipt's members and nothing else: %v", receipt)
	}
	if receipt["prevSignature"] != nil {
		t.Fatalf("the first receipt of a session chains from null: %v", receipt["prevSignature"])
	}
	// The caller supplied no receipt and cannot: nothing it sent appears as proof.
	encoded, _ := json.Marshal(receipt)
	if bytes.Contains(encoded, []byte("acme")) {
		t.Fatal("caller-supplied argument leaked into the receipt")
	}

	post(t, server, "/acquire", `{"session":"http-1","source":"screening","arguments":{"q":"beta"}}`)
	if code, body := post(t, server, "/seal", `{"session":"http-1"}`); code != http.StatusOK {
		t.Fatalf("seal failed: %d %v", code, body)
	}

	resp, err := http.Get(server.URL + "/verify")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var verdict map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&verdict)
	if verdict["ok"] != true {
		t.Fatalf("gateway does not verify its own store: %v", verdict)
	}
}

// A third party fetches the public key and checks everything with it -- holding
// no secret, and therefore unable to produce any receipt it just verified.
func TestThirdPartyVerifiesWithThePublicKeyAlone(t *testing.T) {
	service, server := testService(t)
	post(t, server, "/acquire", `{"session":"s1","source":"screening","arguments":{"q":"acme"}}`)
	post(t, server, "/seal", `{"session":"s1"}`)

	resp, err := http.Get(server.URL + "/publickey")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var document map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&document)
	if document["algorithm"] != "ed25519" {
		t.Fatalf("unexpected key document: %v", document)
	}
	public, err := hex.DecodeString(document["publicKey"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(public, testSeed) {
		t.Fatal("the published key is the secret")
	}
	report, err := verifyWithRegistry(service.storeRoot, service.regPath, "gateway:test", public)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := report.marshal()
	if !bytes.Contains(raw, []byte(`"ok":true`)) {
		t.Fatalf("third-party verification failed: %s", raw)
	}
}

func TestEscapingSessionIsRejectedOverHTTP(t *testing.T) {
	service, server := testService(t)
	for _, bad := range []string{"../../TRAVERSED", "a/b", "/tmp/ESCAPED"} {
		body := fmt.Sprintf(`{"session":%q,"source":"screening","arguments":{}}`, bad)
		if code, _ := post(t, server, "/acquire", body); code != http.StatusBadRequest {
			t.Fatalf("session %q was not refused: %d", bad, code)
		}
	}
	entries, err := os.ReadDir(filepath.Join(service.storeRoot, "receipts"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("a refused session still wrote receipts: %v", entries)
	}
}

func TestJSONBodiesRejectTrailingValuesAndAllowWhitespace(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		body        string
		setup       func(*testing.T, *gatewayService, *httptest.Server)
		wantCode    int
		wantMessage string
		checkState  func(*testing.T, *gatewayService)
	}{
		{
			name:        "acquire rejects a second object",
			path:        "/acquire",
			body:        `{"session":"trailing-acquire","source":"screening","arguments":{}} {"extra":true}`,
			wantCode:    http.StatusBadRequest,
			wantMessage: "exactly one JSON value",
			checkState: func(t *testing.T, service *gatewayService) {
				entries, err := os.ReadDir(filepath.Join(service.storeRoot, "receipts"))
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != 0 {
					t.Fatalf("rejected acquire wrote receipts: %v", entries)
				}
			},
		},
		{
			name: "seal rejects a second value",
			path: "/seal",
			body: `{"session":"trailing-seal"} null`,
			setup: func(t *testing.T, _ *gatewayService, server *httptest.Server) {
				if code, _ := post(t, server, "/acquire", `{"session":"trailing-seal","source":"screening","arguments":{}}`); code != http.StatusOK {
					t.Fatalf("setup acquire failed: %d", code)
				}
			},
			wantCode:    http.StatusBadRequest,
			wantMessage: "exactly one JSON value",
			checkState: func(t *testing.T, service *gatewayService) {
				data, err := os.ReadFile(service.regPath)
				if err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
				if len(bytes.TrimSpace(data)) != 0 {
					t.Fatalf("rejected seal changed the registry: %s", data)
				}
			},
		},
		{
			name:     "acquire allows trailing whitespace",
			path:     "/acquire",
			body:     "{\"session\":\"whitespace-acquire\",\"source\":\"screening\",\"arguments\":{}} \t\r\n",
			wantCode: http.StatusOK,
		},
		{
			name: "seal allows trailing whitespace",
			path: "/seal",
			body: "{\"session\":\"whitespace-seal\"}\n\t",
			setup: func(t *testing.T, _ *gatewayService, server *httptest.Server) {
				if code, _ := post(t, server, "/acquire", `{"session":"whitespace-seal","source":"screening","arguments":{}}`); code != http.StatusOK {
					t.Fatalf("setup acquire failed: %d", code)
				}
			},
			wantCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, server := testService(t)
			if tt.setup != nil {
				tt.setup(t, service, server)
			}
			code, response := post(t, server, tt.path, tt.body)
			if code != tt.wantCode {
				t.Fatalf("unexpected status: got %d, want %d (%v)", code, tt.wantCode, response)
			}
			if tt.wantMessage != "" && !strings.Contains(fmt.Sprint(response["error"]), tt.wantMessage) {
				t.Fatalf("unexpected error: %v", response)
			}
			if tt.checkState != nil {
				tt.checkState(t, service)
			}
		})
	}
}

// The acquire response is evidence on its own: the receipt it carries is the
// complete signed object, byte-equivalent under §1.1 to the one the store
// holds, so a caller can check the signature it was handed without reaching
// into the store — and a tampered member fails that check.
func TestAcquireResponseReceiptVerifiesAlone(t *testing.T) {
	service, server := testService(t)
	resp, err := http.Post(server.URL+"/acquire", "application/json",
		strings.NewReader(`{"session":"alone-1","source":"screening","arguments":{"q":"solo"}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("acquire failed: %d", resp.StatusCode)
	}
	// The receipt is captured as the raw bytes the wire carried, so §1.1's
	// rules are applied to what was actually received — a wire regression
	// emitting a float literal or a duplicate member is refused here rather
	// than silently normalized by a map decode.
	var envelope struct {
		Receipt json.RawMessage `json:"receipt"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	canonical, err := canonText(envelope.Receipt)
	if err != nil {
		t.Fatalf("the response receipt must canonicalize per §1.1: %v", err)
	}
	var receipt map[string]any
	if err := json.Unmarshal(canonical, &receipt); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(filepath.Join(service.store.root, "receipts", "alone-1", "0.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, bytes.TrimSuffix(stored, []byte("\n"))) {
		t.Fatalf("the response receipt and the stored receipt must be one object:\nresponse %s\nstored   %s", canonical, stored)
	}

	// The signature checks from the response alone, under §1.2's coverage rule:
	// canon of the receipt with signature removed and every other member kept.
	signature, _ := receipt["signature"].(string)
	sig, err := hex.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := map[string]any{}
	for member, value := range receipt {
		if member != "signature" {
			unsigned[member] = value
		}
	}
	unsignedText, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	unsignedCanon, err := canonText(unsignedText)
	if err != nil {
		t.Fatal(err)
	}
	public := ed25519.PublicKey(mustPublic(t))
	if !ed25519.Verify(public, append([]byte(receiptContext), unsignedCanon...), sig) {
		t.Fatal("the signature must verify over the response receipt's own members")
	}

	// One flipped member and the same check fails: the signature covers what
	// the caller was handed, not a shape of it.
	unsigned["source"] = "somewhere-else"
	tamperedText, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	tamperedCanon, err := canonText(tamperedText)
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(public, append([]byte(receiptContext), tamperedCanon...), sig) {
		t.Fatal("a tampered member must fail the check")
	}
}

// --- admission (issue #36) -------------------------------------------------
//
// Admission has to be linearized with sealing BEFORE a source runs. Sources are
// slow, cost money, and can have operator-visible side effects, so "this
// session is sealed" must be decided against the state as it is when the
// request arrives -- not as it will be when a subprocess finishes.

func TestAcquireAfterSealDoesNotStartTheSource(t *testing.T) {
	service, _ := testService(t)
	if _, err := service.acquire("race-sealed", "screening", vString("x")); err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if _, err := service.sealSession("race-sealed"); err != nil {
		t.Fatalf("seal: %v", err)
	}

	// From here the source must never run. It announces itself by creating this
	// file, so "was it started" is a side effect rather than an inference.
	started := filepath.Join(t.TempDir(), "source-started")
	t.Setenv(envSourceReady, started)

	if _, err := service.acquire("race-sealed", "screening", vString("x")); err == nil {
		t.Fatal("acquire on a sealed session must be refused")
	}
	if _, err := os.Stat(started); err == nil {
		t.Fatal("the source ran for an acquisition on a sealed session")
	}
}

func TestSealRefusesWhileAnAcquisitionIsInFlight(t *testing.T) {
	service, _ := testService(t)

	// One receipt first, so the session already EXISTS. Without this the test
	// passes against the unfixed gateway for the wrong reason: there, a session
	// is not created until its source completes, so the seal below fails with
	// "no such session" rather than because work is in flight. Found by
	// mutation-checking this test against the original code.
	if _, err := service.acquire("race-inflight", "screening", vString("x")); err != nil {
		t.Fatalf("seed acquire: %v", err)
	}

	dir := t.TempDir()
	started, release := filepath.Join(dir, "started"), filepath.Join(dir, "release")
	t.Setenv(envSourceReady, started)
	t.Setenv(envSourceWait, release)

	done := make(chan error, 1)
	go func() { _, err := service.acquire("race-inflight", "screening", vString("x")); done <- err }()
	waitForFile(t, started) // the source is now running and cannot finish

	before := registryLines(t, service.regPath)
	if _, err := service.sealSession("race-inflight"); err == nil {
		t.Fatal("seal must refuse while an admitted acquisition is in flight")
	}
	if after := registryLines(t, service.regPath); after != before {
		t.Fatalf("a refused seal wrote %d registry record(s)", after-before)
	}

	openBarrier(t, release)
	if err := <-done; err != nil {
		t.Fatalf("in-flight acquire: %v", err)
	}

	// Once the work it was waiting for has landed, the same seal succeeds and
	// counts that receipt -- the refusal is a retry, not a rejection.
	t.Setenv(envSourceWait, "")
	out, err := service.sealSession("race-inflight")
	if err != nil {
		t.Fatalf("seal after the acquisition finished: %v", err)
	}
	if count, ok := out["finalCount"].(float64); !ok || int(count) != 2 {
		t.Fatalf("finalCount = %v, want 2 (the seed receipt and the in-flight one)",
			out["finalCount"])
	}
}

// The hazard admitting early introduces: a session created for an acquisition
// whose source then FAILED would be left behind, and could be sealed as a real
// zero-receipt session that verifies.
//
// Recorded from a mutation check: this test also passes against the UNFIXED
// gateway, which never created the session in the first place. It does not
// demonstrate the fix -- it guards the new admission path against
// reintroducing the phantom, which is a regression this change could plausibly
// cause and nothing else would catch.
func TestFailedSourceLeavesNoSealablePhantomSession(t *testing.T) {
	service, _ := testService(t)
	t.Setenv(envSourceFail, "1")

	if _, err := service.acquire("race-phantom", "screening", vString("x")); err == nil {
		t.Fatal("a failing source must fail the acquisition")
	}
	if _, err := service.sealSession("race-phantom"); err == nil {
		t.Fatal("a session whose only acquisition failed must not be sealable")
	}
	service.mu.Lock()
	_, present := service.sessions["race-phantom"]
	service.mu.Unlock()
	if present {
		t.Fatal("the failed acquisition left a session behind")
	}
	if lines := registryLines(t, service.regPath); lines != 0 {
		t.Fatalf("registry has %d record(s) after a failed source", lines)
	}
}

// Independent sessions must not serialize, and concurrent successes on one
// session must still receive contiguous indices in completion order.
func TestConcurrentAcquisitionsKeepContiguousIndices(t *testing.T) {
	service, _ := testService(t)
	const n = 6
	done := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() { _, err := service.acquire("race-parallel", "screening", vString("x")); done <- err }()
	}
	for i := 0; i < n; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent acquire: %v", err)
		}
	}
	service.mu.Lock()
	state := service.sessions["race-parallel"]
	index, inFlight := state.index, state.inFlight
	service.mu.Unlock()
	if index != n {
		t.Fatalf("index = %d, want %d", index, n)
	}
	if inFlight != 0 {
		t.Fatalf("inFlight = %d after every acquisition finished, want 0", inFlight)
	}
	for i := 0; i < n; i++ {
		if _, err := os.Stat(filepath.Join(service.storeRoot, "receipts", "race-parallel",
			fmt.Sprintf("%d.json", i))); err != nil {
			t.Fatalf("receipt %d missing: %v", i, err)
		}
	}

	// Contiguous indices are necessary but not sufficient: the prevSignature
	// chain has to be sound too, and only verification checks that. Interleaved
	// stamping would produce n well-named files whose chain forks. The session
	// is deliberately left unsealed, so unregistered-session is expected here
	// and a broken chain or sequence is not.
	_, counts := statuses(t, service.storeRoot, service.regPath)
	if counts["chain-broken"] != 0 || counts["sequence-broken"] != 0 {
		t.Fatalf("chain-broken=%d sequence-broken=%d, want 0 and 0",
			counts["chain-broken"], counts["sequence-broken"])
	}
	if counts["ok"] != n {
		t.Fatalf("%d receipts verify, want %d", counts["ok"], n)
	}
}

// The converse of the in-flight seal refusal: holding one session must not hold
// the gateway. The mutex is taken to admit and released before the source runs,
// so an unrelated session can acquire AND seal while another's source is stuck.
//
// The barrier is named in session A's arguments, not in the environment, because
// every helper subprocess inherits the same environment -- an environment-named
// barrier would hold B's source alongside A's and the test could not tell a
// serialized gateway from a working one.
//
// Recorded from a mutation check: this test passes against the pre-#36 gateway
// too, which also released the mutex around the subprocess. It does not
// demonstrate that change; it pins the property the change had to preserve, and
// it fails if the critical section is ever widened to span a source.
func TestBlockedSourceDoesNotBlockAnIndependentSession(t *testing.T) {
	service, _ := testService(t)

	dir := t.TempDir()
	done := make(chan error, 1)
	go func() { _, err := service.acquire("race-indep-a", "screening", barrierArg(dir)); done <- err }()
	waitForFile(t, filepath.Join(dir, startedFile)) // A's source is running and cannot finish

	if _, err := service.acquire("race-indep-b", "screening", vString("x")); err != nil {
		t.Fatalf("session B could not acquire while session A's source was blocked: %v", err)
	}
	out, err := service.sealSession("race-indep-b")
	if err != nil {
		t.Fatalf("session B could not seal while session A's source was blocked: %v", err)
	}
	if count, ok := out["finalCount"].(float64); !ok || int(count) != 1 {
		t.Fatalf("session B finalCount = %v, want 1", out["finalCount"])
	}

	// A is untouched by B's traffic and still completes once released.
	openBarrier(t, filepath.Join(dir, releaseFile))
	if err := <-done; err != nil {
		t.Fatalf("session A acquire: %v", err)
	}
}

// --- request body bounds (issue #40) ---------------------------------------

// countingReader streams a VALID, enormous JSON object and reports how much of
// it the server consumed.
//
// Valid is load-bearing and was learned the hard way: an earlier version of
// this test streamed raw filler, which is not JSON at its first byte, so the
// decoder stopped immediately whether or not a limit existed. The test passed
// against the unbounded gateway — precisely the "rejects it, but only after
// reading all of it" trap this test exists to catch, reproduced inside the
// test itself. A body the decoder is willing to keep reading is the only kind
// that can distinguish the two.
type countingReader struct {
	prefix    []byte
	remaining int64
	suffix    []byte
	read      int64
}

func newCountingBody(total int64) *countingReader {
	prefix := []byte(`{"session":"`)
	suffix := []byte(`"}`)
	return &countingReader{
		prefix:    prefix,
		remaining: total - int64(len(prefix)) - int64(len(suffix)),
		suffix:    suffix,
	}
}

func (c *countingReader) Read(p []byte) (int, error) {
	take := func(src []byte) (int, []byte) {
		n := copy(p, src)
		c.read += int64(n)
		return n, src[n:]
	}
	if len(c.prefix) > 0 {
		n, rest := take(c.prefix)
		c.prefix = rest
		return n, nil
	}
	if c.remaining > 0 {
		n := int64(len(p))
		if n > c.remaining {
			n = c.remaining
		}
		for i := int64(0); i < n; i++ {
			p[i] = 'a'
		}
		c.remaining -= n
		c.read += n
		return int(n), nil
	}
	if len(c.suffix) > 0 {
		n, rest := take(c.suffix)
		c.suffix = rest
		return n, nil
	}
	return 0, io.EOF
}

func TestOversizedRequestBodyIsRefusedWithoutBufferingIt(t *testing.T) {
	service, _ := testService(t)
	handler := service.handler()

	for _, path := range []string{"/acquire", "/seal"} {
		t.Run(path, func(t *testing.T) {
			// Twenty times the limit, streamed rather than materialized, so the
			// test itself does not allocate what it is checking nobody reads.
			body := newCountingBody(20 * maxRequestBody)
			req := httptest.NewRequest(http.MethodPost, path, body)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
			// Some slack for buffering inside net/http and the JSON decoder;
			// the assertion that matters is that it is bounded, not that it is
			// exact.
			if limit := int64(maxRequestBody) + 64*1024; body.read > limit {
				t.Fatalf("server read %d bytes of a %d-byte body; the limit is %d, so "+
					"it buffered past the bound instead of refusing at it",
					body.read, 20*maxRequestBody, maxRequestBody)
			}
		})
	}
}

func TestBodyAtOrBelowTheLimitIsUnaffected(t *testing.T) {
	service, server := testService(t)
	_ = service

	// Padding the arguments object to just under the limit must still work, and
	// must still produce a receipt: the bound is a ceiling, not a new rejection
	// path for ordinary requests.
	pad := strings.Repeat("x", maxRequestBody-4096)
	payload := fmt.Sprintf(`{"session":"bounded","source":"screening","arguments":{"pad":%q}}`, pad)
	if len(payload) >= maxRequestBody {
		t.Fatalf("test payload %d bytes is not below the %d-byte limit", len(payload), maxRequestBody)
	}
	resp, err := http.Post(server.URL+"/acquire", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, raw)
	}

	// And trailing whitespace still parses, so #37's contract is untouched.
	resp2, err := http.Post(server.URL+"/seal", "application/json",
		strings.NewReader(`{"session":"bounded"}`+"\n\n  "))
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp2.Body)
		t.Fatalf("seal status = %d, want 200: %s", resp2.StatusCode, raw)
	}
}

func TestVerifyMissingReceiptsRoot(t *testing.T) {
	// the corpus materializer structurally creates the receipts and artifacts directories for every vector, so the frozen corpus cannot express a missing receipts root.

	t.Run("missing receipts root", func(t *testing.T) {
		st, reg, storeRoot, registryPath := testStore(t)
		stampSession(t, st, "sess-a", 2)
		if _, err := reg.seal("sess-a", 2, "t"); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(filepath.Join(storeRoot, "receipts")); err != nil {
			t.Fatal(err)
		}
		ok, counts := statuses(t, storeRoot, registryPath)
		if ok || counts["sealed-session-missing"] != 1 {
			t.Fatalf("deleted receipts root not caught: ok=%v %v", ok, counts)
		}
	})

	t.Run("non-existent store root", func(t *testing.T) {
		_, _, storeRoot, registryPath := testStore(t)
		missingRoot := filepath.Join(storeRoot, "does-not-exist")
		ok, findings := statuses(t, missingRoot, registryPath)
		if !ok {
			t.Errorf("expected ok=true, got ok=%v", ok)
		}
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %v", findings)
		}
	})

	t.Run("empty store", func(t *testing.T) {
		_, _, storeRoot, registryPath := testStore(t)
		ok, counts := statuses(t, storeRoot, registryPath)
		if !ok || len(counts) > 0 {
			t.Fatalf("empty store failed verification: ok=%v %v", ok, counts)
		}
	})
}

// --- /registry endpoint (issue #53) ----------------------------------------
func TestRegistryEndpointServesRawBytes(t *testing.T) {
	t.Run("empty before any seal", func(t *testing.T) {
		service, server := testService(t)

		resp, err := http.Get(server.URL + "/registry")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if len(body) != 0 {
			t.Fatalf("body = %d bytes, want 0 (empty body for absent registry)", len(body))
		}

		if _, err := os.Stat(service.regPath); err == nil {
			t.Fatal("registry file should not exist before any seal")
		}
	})

	t.Run("byte-identical to file after seals", func(t *testing.T) {
		service, server := testService(t)

		// accquire 2 sessions
		if code, _ := post(t, server, "/acquire",
			`{"session":"reg-a","source":"screening","arguments":{}}`); code != http.StatusOK {
			t.Fatalf("acquire reg-a: %d", code)
		}
		if code, _ := post(t, server, "/acquire",
			`{"session":"reg-b","source":"screening","arguments":{}}`); code != http.StatusOK {
			t.Fatalf("acquire reg-b: %d", code)
		}

		// Seal both sessions.
		if code, _ := post(t, server, "/seal", `{"session":"reg-a"}`); code != http.StatusOK {
			t.Fatalf("seal reg-a: %d", code)
		}
		if code, _ := post(t, server, "/seal", `{"session":"reg-b"}`); code != http.StatusOK {
			t.Fatalf("seal reg-b: %d", code)
		}

		// Fetch /registry and read the file directly.
		resp, err := http.Get(server.URL + "/registry")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		wire, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		disk, err := os.ReadFile(service.regPath)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(wire, disk) {
			t.Fatalf("/registry response is not byte-identical to the file on disk:\nwire: %s\ndisk: %s", wire, disk)
		}
	})

	t.Run("each line is canonical", func(t *testing.T) {
		service, server := testService(t)
		_ = service

		post(t, server, "/acquire", `{"session":"canon-a","source":"screening","arguments":{}}`)
		post(t, server, "/acquire", `{"session":"canon-b","source":"screening","arguments":{}}`)
		post(t, server, "/seal", `{"session":"canon-a"}`)
		post(t, server, "/seal", `{"session":"canon-b"}`)

		resp, err := http.Get(server.URL + "/registry")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		wire, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		lines := bytes.Split(bytes.TrimSpace(wire), []byte("\n"))
		if len(lines) != 2 {
			t.Fatalf("expected 2 seal lines, got %d", len(lines))
		}
		for i, line := range lines {
			// Must parse.
			if _, err := parseJSON(line); err != nil {
				t.Fatalf("line %d: parse failed: %v", i, err)
			}
			// Must equal its own canonical form.
			reCanon, err := canonText(line)
			if err != nil {
				t.Fatalf("line %d: canonicalize failed: %v", i, err)
			}
			if !bytes.Equal(line, reCanon) {
				t.Fatalf("line %d is not canonical:\ngot:  %s\nwant: %s", i, line, reCanon)
			}
		}
	})

	t.Run("loadSeals loads both sessions", func(t *testing.T) {
		service, server := testService(t)
		_ = service

		// Seal two sessions.
		post(t, server, "/acquire", `{"session":"load-a","source":"screening","arguments":{}}`)
		post(t, server, "/acquire", `{"session":"load-b","source":"screening","arguments":{}}`)
		post(t, server, "/seal", `{"session":"load-a"}`)
		post(t, server, "/seal", `{"session":"load-b"}`)

		resp, err := http.Get(server.URL + "/registry")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		wire, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		tmp := filepath.Join(t.TempDir(), "served-registry.jsonl")
		if err := os.WriteFile(tmp, wire, 0o600); err != nil {
			t.Fatal(err)
		}

		public := []byte(mustPublic(t))
		seals, _, err := loadSeals(tmp, public)
		if err != nil {
			t.Fatal(err)
		}

		// Both sessions must be present.
		if len(seals) != 2 {
			t.Fatalf("loadSeals loaded %d seal(s), want 2", len(seals))
		}
		for _, want := range []string{"load-a", "load-b"} {
			if _, ok := seals[want]; !ok {
				t.Fatalf("loadSeals missing session %q", want)
			}
		}
	})
}

func TestMethodContractForStateChangingRoutes(t *testing.T) {
	tests := []struct {
		method string
		route  string
		body   string
		name   string
	}{
		{http.MethodGet, "/acquire", "", "GET /acquire nil body"},
		{http.MethodPut, "/acquire", "", "PUT /acquire nil body"},
		{http.MethodDelete, "/acquire", "", "DELETE /acquire nil body"},
		{http.MethodGet, "/seal", "", "GET /seal nil body"},
		{http.MethodPut, "/seal", "", "PUT /seal nil body"},
		{http.MethodDelete, "/seal", "", "DELETE /seal nil body"},
		// The load-bearing rows that make the side-effect assertions active
		{http.MethodGet, "/acquire", `{"session":"test-session","source":"screening"}`, "GET /acquire valid body"},
		{http.MethodGet, "/seal", `{"session":"test-session"}`, "GET /seal valid body"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := testService(t)
			storeRoot := svc.storeRoot
			regPath := svc.regPath

			var reqBody io.Reader
			if tc.body != "" {
				reqBody = strings.NewReader(tc.body)
			}
			req := httptest.NewRequest(tc.method, tc.route, reqBody)
			rr := httptest.NewRecorder()

			svc.handler().ServeHTTP(rr, req)

			if rr.Code != http.StatusNotFound {
				t.Errorf("Code = %d, want %d", rr.Code, http.StatusNotFound)
			}

			body := strings.TrimSpace(rr.Body.String())
			if body != `{"error":"not found"}` {
				t.Errorf("Body = %q, want %q", body, `{"error":"not found"}`)
			}

			entries, err := os.ReadDir(filepath.Join(storeRoot, "receipts"))
			if err != nil {
				t.Errorf("ReadDir error = %v, want nil", err)
			}
			if len(entries) != 0 {
				t.Errorf("len(entries) = %d, want 0", len(entries))
			}

			_, err = os.Stat(regPath)
			if err == nil || !os.IsNotExist(err) {
				t.Errorf("Stat error = %v, want IsNotExist", err)
			}
		})
	}
}
