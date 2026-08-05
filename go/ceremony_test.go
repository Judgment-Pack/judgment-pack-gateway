package main

// SPEC.md §5a's consumer ceremony, executable: acquire → seal → verify under a
// pinned key → re-digest → use. This file is the worked consumer the spec
// names. Each step is performed the way §5a requires — the key pinned out of
// band rather than fetched from the gateway under audit, the verdict read
// from the JSON rather than an exit code, the artifact re-digested before its
// bytes count as attested — and each refusal leg fails the way §5a says a
// consumer must refuse.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ceremonyVerify is the consumer's own verifier run (§5a.3): over the store
// the consumer holds, with the registry from the key holder, under the pinned
// key — never `GET /verify`, which is the audited party grading itself.
func ceremonyVerify(t *testing.T, service *gatewayService, pinned []byte) *report {
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
// registration, seal, or chain finding naming it. It exists here so the spec's
// list is code somewhere a consumer can copy.
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
	// A session with no findings is absent, not clean.
	return mine > 0
}

func TestCeremonyFromAcquireToUsableBytes(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("needs /bin/sh")
	}
	service, server := testService(t)

	// Acquire. The response receipt is the complete §1.2 object (§6); the
	// consumer keeps resultDigest for the re-digest step.
	code, first := post(t, server, "/acquire",
		`{"session":"consumer-1","source":"screening","arguments":{"q":"ceremony"}}`)
	if code != http.StatusOK {
		t.Fatalf("acquire failed: %d %v", code, first)
	}
	receipt := first["receipt"].(map[string]any)
	resultDigest, _ := receipt["resultDigest"].(string)
	if !strings.HasPrefix(resultDigest, "sha256:") {
		t.Fatalf("resultDigest = %q", resultDigest)
	}

	// Seal. An unsealed session is unregistered to the verifier (§4), so a
	// consumer that skips this step withholds its own work.
	if code, body := post(t, server, "/seal", `{"session":"consumer-1"}`); code != http.StatusOK {
		t.Fatalf("seal failed: %d %v", code, body)
	}

	// Verify under a pinned key. The pin arrives out of band — here it stands
	// in for the operator's keygen output — and never from /publickey (§5a.3).
	verdict := ceremonyVerify(t, service, []byte(mustPublic(t)))

	// The verdict is the JSON, never an exit code (§5a.2), and it is
	// store-wide and fail-closed (§5a.1).
	if !verdict.OK {
		t.Fatalf("the store must verify before any byte is believed: %v", verdict.Findings)
	}

	// Re-digest before use (§5a.4): the bytes the consumer actually loads are
	// checked against the receipt it verified, not trusted for their address.
	digestHex := strings.TrimPrefix(resultDigest, "sha256:")
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
// registration, seal, and chain findings all hold.
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

	verdict := ceremonyVerify(t, service, []byte(mustPublic(t)))

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
		t.Fatal("a session with no findings is absent, not clean")
	}
}
