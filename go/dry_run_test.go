package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The dry-run family: verify-dry-run and the store verifier's reading of the
// same bytes agree with every vector (SPEC.md §1.2c).
func TestDryRunVectors(t *testing.T) {
	failures, count, err := runDryRunVectors(corpusPath())
	if err != nil || count != 10 || len(failures) != 0 {
		t.Fatalf("%d vectors, %v, %v", count, failures, err)
	}
}

// A dry-run receipt met as a receipt is malformed, and the reason says why.
func TestADryRunReceiptIsNotAReceiptOfASession(t *testing.T) {
	vector := readDryRunVector(t, "valid")
	v, err := parseJSON([]byte(vector.Receipt))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receiptFrom(v.(*vObject)); !errors.Is(err, errDryRunNotAReceipt) {
		t.Fatalf("receiptFrom: %v", err)
	}
}

func readDryRunVector(t *testing.T, name string) dryRunVector {
	t.Helper()
	var vector dryRunVector
	raw, err := os.ReadFile(corpusPath("dry-run", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func TestCmdVerifyDryRun(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "dry-run.json")
	if err := os.WriteFile(file, []byte(readDryRunVector(t, "valid").Receipt), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(corpusPath("TEST-PUBLIC-KEY"))
	if err != nil {
		t.Fatal(err)
	}
	edHex := strings.TrimSpace(string(key))
	var out, errOut bytes.Buffer
	if code := cmdVerifyDryRun([]string{"--public-key", edHex, file}, &out, &errOut); code != 0 || strings.TrimSpace(out.String()) != `{"ok":true,"findings":[],"dryRun":true}` {
		t.Fatalf("exit %d: %s %s", code, out.String(), errOut.String())
	}
	// under the P-256 pin the Ed25519 receipt names another key
	p256, err := os.ReadFile(corpusPath("TEST-P256-PUBLIC-KEY"))
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := cmdVerifyDryRun([]string{"--public-key", strings.TrimSpace(string(p256)), "--public-key-alg", "ES256", file}, &out, &errOut); code != 0 || !strings.Contains(out.String(), `"key-mismatch"`) || !strings.Contains(out.String(), `"dryRun":true`) {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	for _, args := range [][]string{
		{file},
		{"--public-key", edHex},
		{"--public-key", edHex, "--public-key-alg", "ES384", file},
		{"--public-key", strings.ToUpper(edHex), file},
		{"--public-key", edHex, file, file},
		{"--public-key", edHex, filepath.Join(dir, "absent.json")},
	} {
		if code := cmdVerifyDryRun(args, &out, &errOut); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

// approval-cited-again is on an action that cites a single record another
// action also cites, by id and digest; a standing record cited twice, or a
// single one under another digest, is not observed.
func TestApprovalCitedAgainOnlyForASingleRecord(t *testing.T) {
	d1, d2 := "sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64)
	act := func(index int64, approvals ...approvalCitation) *receipt {
		return &receipt{sessionID: "s1", callIndex: index, kind: "action", approvals: approvals}
	}
	got := approvalObservations([]*receipt{
		act(0, approvalCitation{approvalSingle, "a", d1}),
		act(1, approvalCitation{approvalStanding, "a", d1}),
		act(2, approvalCitation{approvalStanding, "b", d1}, approvalCitation{approvalStanding, "c", d2}),
		act(3, approvalCitation{approvalStanding, "b", d1}),
		act(4, approvalCitation{approvalSingle, "e", d1}),
		act(5, approvalCitation{approvalSingle, "e", d2}),
		act(6),
	})
	if len(got) != 1 || got[0]["callIndex"] != int64(0) || got[0]["observation"] != observationApprovalCitedAgain {
		t.Fatalf("%v", got)
	}
}
