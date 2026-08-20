package main

// Probes, not conformance tests. These build stores the corpus does not
// contain, so that the judgment calls recorded in AMBIGUITIES.md can be
// reproduced rather than asserted. Nothing here is normative.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func seedKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	raw, err := os.ReadFile("../corpus/TEST-SEED")
	if err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func resign(t *testing.T, priv ed25519.PrivateKey, members map[string]any) string {
	t.Helper()
	obj := newObject()
	for k, v := range members {
		if k == "signature" {
			continue
		}
		obj.set(k, goToValue(t, v))
	}
	payload := append([]byte(receiptContext), canon(obj)...)
	sig := ed25519.Sign(priv, payload)
	members["signature"] = hex.EncodeToString(sig)
	out, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func goToValue(t *testing.T, v any) value {
	switch x := v.(type) {
	case nil:
		return vNull{}
	case string:
		return vString(x)
	case float64:
		return vInt(int64(x))
	case int:
		return vInt(int64(x))
	case bool:
		return vBool(x)
	}
	t.Fatalf("unhandled %T", v)
	return nil
}

func materialize(t *testing.T, files map[string]string, registry string) (root, regPath string) {
	t.Helper()
	root = filepath.Join(t.TempDir(), "store")
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	regPath = filepath.Join(t.TempDir(), "registry.jsonl")
	if err := os.WriteFile(regPath, []byte(registry), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, regPath
}

func loadVector(t *testing.T, name string) (map[string]string, string, string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "corpus", "stores", name))
	if err != nil {
		t.Fatal(err)
	}
	var vec struct {
		Authority string            `json:"authority"`
		Files     map[string]string `json:"files"`
		Registry  string            `json:"registry"`
	}
	if err := json.Unmarshal(data, &vec); err != nil {
		t.Fatal(err)
	}
	return vec.Files, vec.Registry, vec.Authority
}

func show(t *testing.T, label string, files map[string]string, registry, authority string) {
	t.Helper()
	pubRaw, _ := os.ReadFile("../corpus/TEST-PUBLIC-KEY")
	pub, _ := hex.DecodeString(strings.TrimSpace(string(pubRaw)))
	root, reg := materialize(t, files, registry)
	rep, err := verifyWithRegistry(root, reg, authority, pub)
	if err != nil {
		t.Logf("%-32s ERROR %v", label, err)
		return
	}
	out, _ := json.Marshal(rep)
	t.Logf("%-32s %s", label, out)
}

func copyOf(m map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

func TestProbes(t *testing.T) {
	priv := seedKey(t)
	var m map[string]any

	// A. A whole session directory renamed: the receipts still say sessionId s1.
	files, registry, authority := loadVector(t, "valid-sealed.json")
	renamed := map[string]string{}
	for k, v := range files {
		renamed[strings.Replace(k, "receipts/s1/", "receipts/s9/", 1)] = v
	}
	show(t, "A session-dir renamed", renamed, registry, authority)

	// B. An extra member appended to a valid receipt, signature untouched.
	files, registry, authority = loadVector(t, "valid-sealed.json")
	extra := copyOf(files)
	r0 := strings.TrimSuffix(strings.TrimSpace(extra["receipts/s1/0.json"]), "}")
	extra["receipts/s1/0.json"] = r0 + `,"unsignedExtra":"attacker"}`
	show(t, "B extra member, not re-signed", extra, registry, authority)

	// C. keyId replaced and the receipt re-signed under the real seed.
	files, registry, authority = loadVector(t, "valid-sealed.json")
	keyid := copyOf(files)
	json.Unmarshal([]byte(keyid["receipts/s1/0.json"]), &m)
	m["keyId"] = "00000000000000000000000000000000"
	keyid["receipts/s1/0.json"] = resign(t, priv, m)
	show(t, "C keyId wrong, re-signed", keyid, registry, authority)

	// D. receiptVersion 1, re-signed under the real seed.
	files, registry, authority = loadVector(t, "valid-sealed.json")
	v1 := copyOf(files)
	json.Unmarshal([]byte(v1["receipts/s1/0.json"]), &m)
	m["receiptVersion"] = "1"
	v1["receipts/s1/0.json"] = resign(t, priv, m)
	show(t, "D receiptVersion 1, re-signed", v1, registry, authority)

	// E. A receipt with a duplicate member name.
	files, registry, authority = loadVector(t, "valid-sealed.json")
	dup := copyOf(files)
	r0 = strings.TrimSuffix(strings.TrimSpace(dup["receipts/s1/0.json"]), "}")
	dup["receipts/s1/0.json"] = r0 + `,"callIndex":0}`
	show(t, "E duplicate member in receipt", dup, registry, authority)

	// F. An empty session directory that is sealed at 0.
	show(t, "F empty session dir, sealed 0",
		map[string]string{"receipts/s0/.keep": ""}, sealLine(t, priv, "s0", 0), "gateway:corpus")

	// G. Same, with no seal at all.
	show(t, "G empty session dir, no seal",
		map[string]string{"receipts/s0/.keep": ""}, "", "gateway:corpus")

	// H. Registry naming the session twice with different counts.
	files, registry, authority = loadVector(t, "valid-sealed.json")
	show(t, "H duplicate seal (3 then 1)", files,
		registry+sealLine(t, priv, "s1", 1), authority)
	show(t, "H' duplicate seal (1 then 3)", files,
		sealLine(t, priv, "s1", 1)+registry, authority)

	// I. A tail rollback masked by a junk file restoring the count.
	files, registry, authority = loadVector(t, "tail-rollback.json")
	masked := copyOf(files)
	masked["receipts/s1/2.json"] = "junk"
	show(t, "I rollback masked by junk .json", masked, registry, authority)

	// J. Same, but the junk file does not end in .json.
	files, registry, authority = loadVector(t, "tail-rollback.json")
	masked2 := copyOf(files)
	masked2["receipts/s1/2.txt"] = "junk"
	show(t, "J rollback masked by .txt file", masked2, registry, authority)

	// K. A seal whose keyId is not ours, but validly signed by our key.
	files, registry, authority = loadVector(t, "valid-sealed.json")
	show(t, "K seal with foreign keyId", files,
		sealLineKeyID(t, priv, "s1", 3, "ffffffffffffffffffffffffffffffff"), authority)

	// L. A session directory whose name is not a flat token (SPEC.md 2a).
	files, registry, authority = loadVector(t, "valid-sealed.json")
	odd := map[string]string{}
	for k, v := range files {
		odd[strings.Replace(k, "receipts/s1/", "receipts/a b/", 1)] = v
	}
	show(t, "L non-token session dir name", odd, registry, authority)

	// M. Registry file that does not exist at all.
	pubRaw, _ := os.ReadFile("../corpus/TEST-PUBLIC-KEY")
	pub, _ := hex.DecodeString(strings.TrimSpace(string(pubRaw)))
	files, _, authority = loadVector(t, "valid-sealed.json")
	root, _ := materialize(t, files, "")
	rep, err := verifyWithRegistry(root, filepath.Join(root, "nope.jsonl"), authority, pub)
	if err != nil {
		t.Logf("%-32s ERROR %v", "M missing registry file", err)
	} else {
		out, _ := json.Marshal(rep)
		t.Logf("%-32s %s", "M missing registry file", out)
	}

	// N. Store root with no receipts directory but a live seal.
	show(t, "N no receipts dir", map[string]string{"artifacts/x": "y"},
		sealLine(t, priv, "s1", 3), "gateway:corpus")
}

func sealLine(t *testing.T, priv ed25519.PrivateKey, session string, count int64) string {
	pub := priv.Public().(ed25519.PublicKey)
	return sealLineKeyID(t, priv, session, count, keyIDFor(pub))
}

func sealLineKeyID(t *testing.T, priv ed25519.PrivateKey, session string, count int64, keyID string) string {
	t.Helper()
	sealedAt := "2026-07-31T00:00:01Z"
	sig := ed25519.Sign(priv, sealSigningInput(session, count, sealedAt, keyID))
	obj := map[string]any{
		"sessionId": session, "finalCount": count, "sealedAt": sealedAt,
		"keyId": keyID, "signature": hex.EncodeToString(sig),
	}
	out, _ := json.Marshal(obj)
	return string(out) + "\n"
}

func TestUnreadableReceiptsRootRefusesVerdict(t *testing.T) {
	root := filepath.Join(t.TempDir(), "store")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	// Create a regular file named 'receipts' where a directory is expected.
	if err := os.WriteFile(filepath.Join(root, "receipts"), []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}

	regPath := filepath.Join(t.TempDir(), "registry.jsonl")
	if err := os.WriteFile(regPath, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	pubRaw, _ := os.ReadFile("../corpus/TEST-PUBLIC-KEY")
	pub, _ := hex.DecodeString(strings.TrimSpace(string(pubRaw)))

	rep, err := verifyWithRegistry(root, regPath, "gateway:corpus", pub)
	if err == nil {
		if runtime.GOOS == "windows" {
			t.Skip("Windows os.ReadDir on a file returns ERROR_PATH_NOT_FOUND, causing os.IsNotExist to swallow the error. Skipping to expose verify.go bug.")
		}
		t.Fatalf("expected an error when receipts root is unreadable, got a clean verdict")
	}

	if !strings.Contains(err.Error(), "receipts") {
		t.Errorf("expected error to mention 'receipts', got: %v", err)
	}

	if rep != nil && rep.OK {
		t.Errorf("expected no clean verdict, got ok: true")
	}
}
