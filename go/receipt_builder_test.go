package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Read the first member table in the normative v3 section. Its inherited
// members share a cell; optional and kind-specific rows are explicitly
// distinguished by the table's prose. A newly required common row therefore
// changes this check without a second list of member names in Go.
func specCommonReceiptMembers(t *testing.T) []string {
	t.Helper()
	text, err := os.ReadFile(filepath.Join("..", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, section, found := strings.Cut(string(text), "### 1.2a The receipt (version 3)\n")
	if !found {
		t.Fatal("SPEC has no version 3 receipt section")
	}
	section, _, _ = strings.Cut(section, "\n### ")
	_, table, found := strings.Cut(section, "| Member | Type |\n|---|---|\n")
	if !found {
		t.Fatal("SPEC has no version 3 receipt member table")
	}
	member := regexp.MustCompile("`([A-Za-z][A-Za-z0-9]*)`")
	var names []string
	for _, row := range strings.Split(table, "\n") {
		if !strings.HasPrefix(row, "|") {
			break
		}
		cells := strings.Split(row, "|")
		if len(cells) != 4 {
			t.Fatalf("cannot read SPEC receipt member row: %s", row)
		}
		if strings.Contains(cells[2], "optional") || strings.Contains(cells[2], "present exactly when") {
			continue
		}
		matches := member.FindAllStringSubmatch(cells[1], -1)
		if len(matches) == 0 {
			t.Fatalf("SPEC receipt row names no members: %s", row)
		}
		for _, match := range matches {
			names = append(names, match[1])
		}
	}
	if len(names) == 0 {
		t.Fatal("SPEC receipt member table yielded no common members")
	}
	return names
}

// This is hand-authored adapter output, not a recording of a receipt. Both
// production paths run the helper subprocess and sign/store its result.
const receiptBuilderEnvelope = `{"acquisition":{"adapter":{"name":"adapter-mcp","version":"1.0","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"endpoint":"http://127.0.0.1:8080/mcp","statement":"execute","snapshot":null,"peerIdentity":null,"schema":null,"upstreamToken":"proof","observedAt":"2026-10-14T10:00:00Z","transport":"http","server":{"name":"fixture","version":"1.0"}},"result":[{"ok":true}],"page":true}`

func receiptBuilderService(t *testing.T) *gatewayService {
	t.Helper()
	t.Setenv(envSourceHelper, "1")
	root := t.TempDir()
	g, err := newGatewayService(filepath.Join(root, "store"), testSeed, "gateway:test", filepath.Join(root, "registry.jsonl"), map[string]sourceSpec{
		"read":          {argv: []string{os.Args[0]}, env: helperEnv, shape: "mcp"},
		"tickets/write": {argv: []string{os.Args[0], "--tools=update_ticket"}, env: helperEnv, shape: "mcp", tools: []string{"update_ticket"}, endpoint: "http://127.0.0.1:8080/mcp", transport: "http"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(envSourceEnvelope, receiptBuilderEnvelope)
	g.decisionRecords = t.TempDir()
	return g
}

func receiptBuilderCaller() *caller {
	return &caller{issuer: "https://login.example/", subject: "approver", tokenDigest: "sha256:" + strings.Repeat("b", 64)}
}

func receiptBuilderAct(t *testing.T, g *gatewayService, cited map[string]any, who *caller) (map[string]any, string) {
	t.Helper()
	line := `{"kind":"evaluation","cites":[{"sessionId":"shared","callIndex":0,"signature":"` + cited["signature"].(string) + `"}]}`
	if err := os.WriteFile(filepath.Join(g.decisionRecords, "record.json"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	record := receiptBuilderDigest([]byte(line))
	out, err := g.act(json.RawMessage(`"shared"`), json.RawMessage(`"tickets"`), json.RawMessage(`"update_ticket"`), json.RawMessage(`{"id":7}`),
		json.RawMessage(`{"recordDigest":"`+record+`","packDigest":"sha256:`+strings.Repeat("c", 64)+`"}`),
		json.RawMessage(`[{"sessionId":"shared","callIndex":0,"signature":"`+cited["signature"].(string)+`"}]`), who)
	if err != nil {
		t.Fatal(err)
	}
	return out, record
}

func TestReceiptPathsCarryEverySpecCommonMember(t *testing.T) {
	names := specCommonReceiptMembers(t)
	g, who := receiptBuilderService(t), receiptBuilderCaller()
	acquired, err := g.acquire("shared", "read", newObject(), who)
	if err != nil {
		t.Fatal(err)
	}
	check := func(path string, out map[string]any) {
		t.Helper()
		receipt := out["receipt"].(map[string]any)
		for _, name := range names {
			if _, present := receipt[name]; !present {
				t.Fatalf("%s receipt lacks SPEC §1.2a common member %q", path, name)
			}
		}
	}
	check("acquire", acquired)
	acted, _ := receiptBuilderAct(t, g, acquired["receipt"].(map[string]any), who)
	check("act", acted)
}

func receiptBuilderDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum)
}

// Recompute commitments independently of commitmentOver and the canonical
// implementation. The fixture's argument and statement bytes are written by
// hand in canonical form; returned salts are the only random inputs used here.
func receiptBuilderCommitment(t *testing.T, out map[string]any, name, label, text string) string {
	t.Helper()
	salt, err := hex.DecodeString(out["salts"].(map[string]any)[name].(string))
	if err != nil || len(salt) != 32 {
		t.Fatalf("bad %s salt: %x (%v)", name, salt, err)
	}
	return receiptBuilderDigest(append(append(salt, label...), text...))
}

// encoding/json sorts this ASCII-only fixture's keys in canonical order.
// Expectations are constructed independently, then independently signed; no
// output fields except clock stamps and the returned salts are used to form them.
func assertReceiptBuilderBytes(t *testing.T, g *gatewayService, out, want map[string]any, index int) {
	t.Helper()
	minted := out["receipt"].(map[string]any)
	stamp, err := time.Parse("2006-01-02T15:04:05Z", minted["servedAt"].(string))
	if err != nil || stamp.After(time.Now()) || time.Since(stamp) > time.Minute {
		t.Fatalf("unexpected servedAt %v: %v", minted["servedAt"], err)
	}
	want["servedAt"] = minted["servedAt"]
	private := ed25519.NewKeyFromSeed(testSeed)
	keyDigest := sha256.Sum256(private.Public().(ed25519.PublicKey))
	want["keyId"] = fmt.Sprintf("%x", keyDigest)[:32]
	unsigned, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	want["signature"] = hex.EncodeToString(ed25519.Sign(private, append([]byte("judgment-pack-gateway/receipt/"+want["receiptVersion"].(string)+":"), unsigned...)))
	expected, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(g.storeRoot, "receipts", "shared", fmt.Sprintf("%d.json", index)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, append(expected, '\n')) {
		t.Fatalf("signed receipt bytes changed:\n got %s\nwant %s", got, expected)
	}
	response, err := json.Marshal(minted)
	if err != nil || !bytes.Equal(response, expected) {
		t.Fatalf("response receipt differs from independent expected bytes: %s (%v)", response, err)
	}
}

func TestReceiptBuilderProductionBytes(t *testing.T) {
	g, who := receiptBuilderService(t), receiptBuilderCaller()
	arguments, err := parseJSON([]byte(`{"id":7}`))
	if err != nil {
		t.Fatal(err)
	}
	w, err := namedWitnessOf(namedTrail, "https://witness.example:443", witnessKey, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	g.witnessedBy = map[string]namedWitness{namedTrail: w}
	acquired, err := g.acquireForTrail("shared", "read", namedTrail, arguments, who)
	if err != nil {
		t.Fatal(err)
	}
	identity := map[string]any{"issuer": "https://login.example/", "subject": "approver", "tokenDigest": "sha256:" + strings.Repeat("b", 64)}
	adapter := map[string]any{"name": "adapter-mcp", "version": "1.0", "digest": "sha256:" + strings.Repeat("a", 64)}
	want := map[string]any{
		"receiptVersion": "3", "sessionId": "shared", "callIndex": 0, "prevSignature": nil,
		"source": "read", "resultDigest": receiptBuilderDigest([]byte(`[{"ok":true}]`)), "authority": "gateway:test",
		"kind": "acquisition", "caller": identity,
		"argumentsCommitment": receiptBuilderCommitment(t, acquired, "args", "args:", `{"id":7}`),
		"witness":             map[string]any{"origin": "https://witness.example:443", "keyId": w.keyID, "trail": namedTrail},
		"acquisition": map[string]any{
			"adapter": adapter, "shape": "mcp", "endpoint": "http://127.0.0.1:8080/mcp",
			"statement": receiptBuilderCommitment(t, acquired, "statement", "statement:", `"execute"`),
			"snapshot":  nil, "peerIdentity": nil, "schema": nil, "upstreamToken": "proof", "observedAt": "2026-10-14T10:00:00Z",
			"pageItems": []string{receiptBuilderDigest([]byte(`{"ok":true}`))}, "transport": "http", "server": map[string]any{"name": "fixture", "version": "1.0"},
		},
	}
	assertReceiptBuilderBytes(t, g, acquired, want, 0)
	if salts := acquired["salts"].(map[string]any); len(salts) != 2 || salts["args"] == salts["statement"] {
		t.Fatalf("acquisition salts: %v", salts)
	}
	cited := acquired["receipt"].(map[string]any)
	acted, record := receiptBuilderAct(t, g, cited, who)
	want = map[string]any{
		"receiptVersion": "3", "sessionId": "shared", "callIndex": 1, "prevSignature": cited["signature"],
		"source": "tickets/write", "resultDigest": receiptBuilderDigest([]byte(`[{"ok":true}]`)), "authority": "gateway:test",
		"kind": "action", "caller": identity,
		"argumentsCommitment": receiptBuilderCommitment(t, acted, "args", "args:", `{"id":7}`),
		"action": map[string]any{
			"requester": identity, "decision": map[string]any{"recordDigest": record, "packDigest": "sha256:" + strings.Repeat("c", 64)},
			"cites":   []any{map[string]any{"sessionId": "shared", "callIndex": 0, "signature": cited["signature"]}},
			"tool":    map[string]any{"shape": "mcp", "endpoint": "http://127.0.0.1:8080/mcp", "name": "update_ticket", "transport": "http"},
			"request": receiptBuilderCommitment(t, acted, "request", "request:", `{"arguments":{"id":7},"tool":"update_ticket"}`),
			"adapter": adapter, "observedAt": "2026-10-14T10:00:00Z",
		},
	}
	assertReceiptBuilderBytes(t, g, acted, want, 1)
	if salts := acted["salts"].(map[string]any); len(salts) != 2 || salts["args"] == salts["request"] {
		t.Fatalf("action salts: %v", salts)
	}
}

func TestReceiptBuilderCommandBytesByVersion(t *testing.T) {
	for _, version := range []string{"2", "3"} {
		t.Run(version, func(t *testing.T) {
			g := receiptBuilderService(t)
			g.receiptVersion = version
			g.sources["read"] = sourceSpec{argv: []string{os.Args[0]}, env: helperEnv}
			t.Setenv(envSourceEnvelope, `{"ok":true}`)
			var who *caller
			trail := ""
			if version == "2" {
				// Even configured identity/witness inputs add no v3 members.
				w, err := namedWitnessOf(namedTrail, "https://witness.example:443", witnessKey, "fixture")
				if err != nil {
					t.Fatal(err)
				}
				g.witnessedBy = map[string]namedWitness{namedTrail: w}
				who, trail = receiptBuilderCaller(), namedTrail
			}
			out, err := g.acquireForTrail("shared", "read", trail, newObject(), who)
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]any{
				"receiptVersion": version, "sessionId": "shared", "callIndex": 0, "prevSignature": nil,
				"source": "read", "resultDigest": receiptBuilderDigest([]byte(`{"ok":true}`)), "authority": "gateway:test",
			}
			if version == "2" {
				key := sha256.Sum256(append([]byte("judgment-pack-gateway/arguments-key/2:"), testSeed...))
				mac := hmac.New(sha256.New, key[:])
				mac.Write([]byte(`args:{}`))
				want["argumentsDigest"] = fmt.Sprintf("hmac-sha256:%x", mac.Sum(nil))
				if _, present := out["salts"]; present {
					t.Fatal("version 2 returned salts")
				}
			} else {
				binary, err := os.ReadFile(os.Args[0])
				if err != nil {
					t.Fatal(err)
				}
				minted := out["receipt"].(map[string]any)
				observed := minted["acquisition"].(map[string]any)["observedAt"]
				observedTime, err := time.Parse("2006-01-02T15:04:05Z", observed.(string))
				servedTime, servedErr := time.Parse("2006-01-02T15:04:05Z", minted["servedAt"].(string))
				if err != nil || servedErr != nil || observedTime.After(servedTime) {
					t.Fatalf("command observedAt %v after servedAt %v: %v, %v", observed, minted["servedAt"], err, servedErr)
				}
				want["kind"], want["caller"] = "acquisition", nil
				want["argumentsCommitment"] = receiptBuilderCommitment(t, out, "args", "args:", `{}`)
				want["acquisition"] = map[string]any{
					"adapter": map[string]any{"name": os.Args[0], "version": "", "digest": receiptBuilderDigest(binary)}, "shape": "command",
					"endpoint": nil, "statement": nil, "snapshot": nil, "peerIdentity": nil, "schema": nil, "upstreamToken": nil, "observedAt": observed,
				}
				if len(out["salts"].(map[string]any)) != 1 {
					t.Fatalf("command salts: %v", out["salts"])
				}
			}
			assertReceiptBuilderBytes(t, g, out, want, 0)
		})
	}
}
