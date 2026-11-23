package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recordMissing is whether the engine's own verdict (/verify) reports the
// session's action decision-record-mismatch: its record not found.
func (h *actScopeHarness) recordMissing(t *testing.T, session string) bool {
	t.Helper()
	rep, err := h.g.verifyReport()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Findings {
		if f["sessionId"] == session && f["status"] == "decision-record-mismatch" {
			return true
		}
	}
	return false
}

// /verify finds a scoped action's decision record in its scope's own
// directory (ADR-0054), and nowhere else: a record placed only in another
// scope's directory, or in the gateway's, is not found. An action of none
// finds its record in the gateway's directory throughout.
func TestActScopeVerifyFindsTheRecordInItsScopeAlone(t *testing.T) {
	h := actScopeSetup(t)
	if code, out := authed(t, h.server, "/act", h.body("act-b", "tickets-b", scopeB, strings.Repeat("a", 64), h.decisionB, h.cite("b-read", h.scopedSig)), h.tokenB); code != http.StatusOK {
		t.Fatalf("the scoped action: %d %v", code, out)
	}
	if code, out := authed(t, h.server, "/act", h.body("act-u", "tickets", "", strings.Repeat("b", 64), h.decisionU, h.cite("u-read", h.unscopedSig)), h.tokenA); code != http.StatusOK {
		t.Fatalf("the action of none: %d %v", code, out)
	}
	if h.recordMissing(t, "act-b") || h.recordMissing(t, "act-u") {
		t.Fatal("a record in its own directory is reported missing")
	}
	// scope B's record now lies only in scope A's directory and the gateway's
	ownDir, otherDir := filepath.Join(h.root, "decisions-b"), filepath.Join(h.root, "decisions-a")
	line, err := os.ReadFile(filepath.Join(ownDir, "decision.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(otherDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(otherDir, "decision.json"), filepath.Join(h.g.decisionRecords, "decision-b.json")} {
		if err := os.WriteFile(path, line, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(filepath.Join(ownDir, "decision.json")); err != nil {
		t.Fatal(err)
	}
	other := h.g.sources["tickets-b/write"]
	other.scope, other.decisionRecords = callerScopeA, otherDir
	h.g.sources["tickets-a/write"] = other
	if !h.recordMissing(t, "act-b") {
		t.Fatal("a scoped action's record found in another scope's directory, or the gateway's")
	}
	if h.recordMissing(t, "act-u") {
		t.Fatal("the action of none lost its record")
	}
}
