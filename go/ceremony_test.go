package main

// SPEC.md §5a's consumer ceremony, executable: obtain the snapshot → verify
// under a pinned key → bind the receipt → re-digest → use. This file is the
// worked consumer the spec names. Each step is performed the way §5a requires
// — the key is a pinned literal rather than anything the gateway handed over,
// the verdict is read from the JSON, the artifact selector is bound to a
// receipt the consumer itself checked and located among the verifier's ok
// findings, and the bytes are re-digested before they count as attested — and
// each refusal leg fails the way §5a says a consumer must refuse.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// pinnedPublicKeyHex is the consumer's out-of-band pin: a literal, standing in
// for the value an operator copied from `gateway keygen`'s output when the
// identity was provisioned. It is deliberately NOT derived from the service's
// seed here — a pin that follows the signer is not a pin — so rotating the
// service identity makes this ceremony fail until the literal is deliberately
// updated, which is exactly what §5a.3 requires of a real deployment. (The
// value is testSeed's public key; TestThePinIsAPin holds the two in agreement
// so a drifted constant fails loudly rather than silently.)
const pinnedPublicKeyHex = "86775d72e6d4c3f9c04ff81b78b293561c580e3899ddb4ea30c92f08f3f043fa"

func pinnedKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pinned, err := hex.DecodeString(pinnedPublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.PublicKey(pinned)
}

// TestThePinIsAPin: the literal above must be the identity the test service
// actually signs under — and must not be obtained from the service at
// ceremony time.
func TestThePinIsAPin(t *testing.T) {
	if mustPublic(t) != string(pinnedKey(t)) {
		t.Fatal("the pinned literal no longer names the provisioned identity; update it deliberately")
	}
}

// ceremonyVerify is the consumer's own verifier run (§5a.3): over the store
// the consumer holds, with the registry from the key holder, under the pinned
// key — never `GET /verify`, which is the audited party grading itself.
func ceremonyVerify(t *testing.T, service *gatewayService, pinned ed25519.PublicKey) *report {
	t.Helper()
	verdict, err := verifyWithRegistry(service.storeRoot, service.regPath, "gateway:test", pinned)
	if err != nil {
		// §4.1: an error is "no verdict at all", which is not a failing
		// verdict; a consumer treats it as unusable and stops.
		t.Fatalf("no verdict could be reached: %v", err)
	}
	return verdict
}

// sessionScopedVerdict is §5a.1's deliberate mode, exactly as specified: the
// session's own findings all ok and at least one present, and no
// registration, seal, or chain finding naming it. Every finding this verifier
// emits carries sessionId and status (the invariant §5a.1 states), so the
// four bullets collapse to this one scan. It exists here so the spec's list
// is code somewhere a consumer can copy.
func sessionScopedVerdict(verdict *report, session string) bool {
	mine := 0
	for _, finding := range verdict.Findings {
		if finding["sessionId"] != session {
			continue
		}
		mine++
		if finding["status"] != "ok" {
			return false
		}
	}
	// A session with no findings holds no accepted receipt — absent, or
	// validly sealed at count zero — and there is nothing in it to act on.
	return mine > 0
}

// acceptedReceipt reports whether the verifier's findings include an ok for
// this (sessionId, callIndex): §5a.4's membership half, binding a checked
// receipt to the verified store rather than to a look-alike. The finding's
// callIndex is an int64 in-process and a JSON number over the wire, so the
// comparison goes through the marshaled form both take.
func acceptedReceipt(t *testing.T, verdict *report, session string, callIndex float64) bool {
	t.Helper()
	for _, finding := range verdict.Findings {
		if finding["sessionId"] != session || finding["status"] != "ok" {
			continue
		}
		found, err := json.Marshal(finding["callIndex"])
		if err != nil {
			t.Fatal(err)
		}
		wanted, err := json.Marshal(callIndex)
		if err != nil {
			t.Fatal(err)
		}
		if string(found) == string(wanted) {
			return true
		}
	}
	return false
}

var digestHexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestCeremonyFromAcquireToUsableBytes(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("needs /bin/sh")
	}
	service, server := testService(t)

	// Producer steps, done here because this test is also its own producer:
	// acquire, then seal. An offline consumer of an already-sealed snapshot
	// starts below, at the verify.
	resp, err := http.Post(server.URL+"/acquire", "application/json",
		strings.NewReader(`{"session":"consumer-1","source":"screening","arguments":{"q":"ceremony"}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("acquire failed: %d", resp.StatusCode)
	}
	var envelope struct {
		Receipt json.RawMessage `json:"receipt"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	if code, body := post(t, server, "/seal", `{"session":"consumer-1"}`); code != http.StatusOK {
		t.Fatalf("seal failed: %d %v", code, body)
	}

	// Verify under the pinned key (§5a.3): the consumer's own run, over the
	// store it holds, registry from the key holder, pin from provisioning.
	pinned := pinnedKey(t)
	verdict := ceremonyVerify(t, service, pinned)

	// The verdict is the JSON, never an exit code (§5a.2), and it is
	// store-wide and fail-closed (§5a.1).
	if !verdict.OK {
		t.Fatalf("the store must verify before any byte is believed: %v", verdict.Findings)
	}

	// Bind the receipt (§5a.4, first half). The acquire response carries the
	// complete receipt (§6); the consumer checks its signature under the
	// pinned key — never trusting it for having arrived — and then locates
	// exactly that (sessionId, callIndex) among the verifier's ok findings,
	// so the checked receipt is a member of the verified store.
	canonical, err := canonText(envelope.Receipt)
	if err != nil {
		t.Fatalf("the response receipt must canonicalize per §1.1: %v", err)
	}
	var receipt map[string]any
	if err := json.Unmarshal(canonical, &receipt); err != nil {
		t.Fatal(err)
	}
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
	if !ed25519.Verify(pinned, append([]byte(receiptContext), unsignedCanon...), sig) {
		t.Fatal("an unverifiable response receipt selects nothing")
	}
	session, _ := receipt["sessionId"].(string)
	callIndex, _ := receipt["callIndex"].(float64)
	if !acceptedReceipt(t, verdict, session, callIndex) {
		t.Fatal("a receipt the verifier did not accept selects nothing")
	}

	// Re-digest before use (§5a.4, second half): the digest's hex is
	// validated before it touches a path, and the bytes actually loaded are
	// checked against the receipt the consumer just bound.
	resultDigest, _ := receipt["resultDigest"].(string)
	digestHex := strings.TrimPrefix(resultDigest, "sha256:")
	if !digestHexPattern.MatchString(digestHex) {
		t.Fatalf("a selector that is not 64 lowercase hex characters is refused before any path use: %q", digestHex)
	}
	artifact, err := os.ReadFile(filepath.Join(service.storeRoot, "artifacts", digestHex))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(artifact)
	if hex.EncodeToString(sum[:]) != digestHex {
		t.Fatal("bytes nobody re-checked are bytes nobody attested")
	}

	// Only now are the bytes usable.
	var result map[string]any
	if err := json.Unmarshal(artifact, &result); err != nil {
		t.Fatal(err)
	}
	if result["status"] != "not_found" {
		t.Fatalf("the attested result is what the source returned: %v", result)
	}
}

// §5a.1's two readings, demonstrated on one store: a tampered receipt in one
// session flips the store-wide verdict for every session, and the deliberate
// session-scoped mode still admits the untouched session only because its own
// registration, seal, and chain findings all hold. The same store then
// exercises §5a.2 at the real consumer boundary: the CLI verifier exits 0
// while its JSON carries the failing verdict. A wrong pin refuses everything.
func TestStoreWideVerdictWithholdsACleanSession(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("needs /bin/sh")
	}
	service, server := testService(t)

	for _, session := range []string{"clean-1", "dirty-1"} {
		body := `{"session":"` + session + `","source":"screening","arguments":{}}`
		if code, response := post(t, server, "/acquire", body); code != http.StatusOK {
			t.Fatalf("acquire %s failed: %d %v", session, code, response)
		}
		if code, response := post(t, server, "/seal", `{"session":"`+session+`"}`); code != http.StatusOK {
			t.Fatalf("seal %s failed: %d %v", session, code, response)
		}
	}

	// Tamper one member of dirty-1's stored receipt: genuinely written, no
	// longer what was signed.
	receiptPath := filepath.Join(service.storeRoot, "receipts", "dirty-1", "0.json")
	stored, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte(strings.Replace(string(stored), `"source":"screening"`, `"source":"elsewhere"`, 1))
	if string(tampered) == string(stored) {
		t.Fatal("the tamper must change the receipt")
	}
	if err := os.WriteFile(receiptPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	verdict := ceremonyVerify(t, service, pinnedKey(t))

	// Store-wide (the default): clean-1 is withheld with everything else.
	if verdict.OK {
		t.Fatal("a store tampered anywhere must not verify")
	}

	// Session-scoped (the deliberate mode): clean-1 passes its own checks,
	// dirty-1 does not, and a session the store never held is absent rather
	// than clean.
	if !sessionScopedVerdict(verdict, "clean-1") {
		t.Fatalf("the untouched session's own findings hold: %v", verdict.Findings)
	}
	if sessionScopedVerdict(verdict, "dirty-1") {
		t.Fatal("the tampered session must fail its own scope")
	}
	if sessionScopedVerdict(verdict, "never-existed") {
		t.Fatal("a session with no findings holds nothing to act on")
	}

	// §5a.2 at the real boundary: the gateway binary's verify exits 0 for
	// this failing verdict — the verdict is the JSON it prints, never the
	// exit code a consumer might be tempted to gate on.
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("needs the go tool to run the CLI boundary leg")
	}
	command := exec.Command(goTool, "run", ".", "verify", service.storeRoot, service.regPath, "gateway:test")
	command.Stdin = strings.NewReader(pinnedPublicKeyHex)
	command.Env = append(os.Environ(), "GOFLAGS=-buildvcs=false")
	stdout, err := command.Output()
	if err != nil {
		t.Fatalf("a reached verdict exits 0, failing or not: %v", err)
	}
	var cli report
	if err := json.Unmarshal(stdout, &cli); err != nil {
		t.Fatalf("the verdict is the JSON on stdout: %v (%q)", err, stdout)
	}
	if cli.OK {
		t.Fatal("the CLI must report the same failing verdict")
	}

	// A wrong pin refuses everything, tampered or clean: the identity is the
	// pin's to assert, not the store's.
	wrong := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(wrong, pinnedKey(t))
	wrong[0] ^= 0xff
	misPinned := ceremonyVerify(t, service, wrong)
	if misPinned.OK || sessionScopedVerdict(misPinned, "clean-1") {
		t.Fatal("under a wrong pin no session verifies, clean or not")
	}
}
