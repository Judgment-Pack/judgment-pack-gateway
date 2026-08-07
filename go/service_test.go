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
)

var testSeed = []byte("judgment-pack-gateway-test-seed!") // exactly 32 bytes

const envSourceHelper = "GATEWAY_TEST_SOURCE_HELPER"

func TestMain(m *testing.M) {
	if os.Getenv(envSourceHelper) == "1" {
		_, _ = io.Copy(io.Discard, os.Stdin)
		fmt.Print(`{"checkedSuccessfully":true,"status":"not_found"}`)
		os.Exit(0)
	}
	os.Exit(m.Run())
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
