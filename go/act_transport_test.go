package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// updateActionGolden rewrites testdata/action-golden from the code as it
// stands. It is for the commit that changes a stdio write's receipt on
// purpose, and none other: action.tool.transport (issue #268) was added for
// a remote write without one.
var updateActionGolden = flag.Bool("update-action-golden", false, "rewrite testdata/action-golden from the code as it stands")

// A write through a binding whose server the adapter runs over stdio mints
// the receipt it minted before action.tool.transport existed, byte for
// byte: no transport in action.tool, the platform's endpoint or null there,
// every member where it was. The write source is the engine's own
// derivation of an image binding, its executor the test's stand-in; what
// moves from run to run -- the stamp, the salted commitments, the
// signatures and the record's digest, which names a signature -- is put in
// place before the comparison and nowhere else, each found exactly once.
func TestTheStdioWritesReceiptIsByteForByteWhatItWas(t *testing.T) {
	for _, tc := range []struct{ name, endpoint string }{
		{"stdio-endpoint", `,"endpoint":"warehouse.internal:5432"`},
		{"stdio-endpoint-null", ``},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ref := "postgres@" + digestOf(postgresBinding)
			_, sources, err := load(t, engineJSON(t, catalogWith(t, map[string]string{"postgres": postgresBinding}), ``,
				platformJSONFor(t, "warehouse", ref, "engine-warehouse", tc.endpoint+`,"write":true`, "history", "live", "write")))
			if err != nil {
				t.Fatal(err)
			}
			spec := sources["warehouse/write"]
			if len(spec.argv) == 0 || spec.argv[0] != "adapter-mcp" || !contains(spec.argv, "--image=ghcr.io/example/mcp-postgres:2.1@"+testImageDigest) || remoteURL(spec.argv) != "" {
				t.Fatalf("the write source is adapter-mcp running an image: %q", spec.argv)
			}
			if spec.transport != "" {
				t.Fatalf("a server the adapter runs is reached over stdio, and its write names no transport: %q", spec.transport)
			}
			// The stand-in in the adapter's place: no installed program runs.
			spec.argv[0], spec.env, spec.user = os.Args[0], helperEnv, ""
			service, _ := testService(t)
			service.sources["warehouse/write"] = spec
			service.decisionRecords = t.TempDir()
			envelope := `{"acquisition":{"adapter":{"name":"ghcr.io/example/mcp-postgres","version":"2.1","digest":"` + testImageDigest + `"},` +
				`"endpoint":null,"statement":"execute","snapshot":null,"peerIdentity":null,"schema":null,"upstreamToken":null,"observedAt":"2026-10-14T10:00:00Z"},` +
				`"result":{"content":[{"type":"text","text":"executed"}]}}`
			t.Setenv(envSourceEnvelope, envelope)

			who := &caller{issuer: "https://login.example.com/", subject: "approver@example.com", tokenDigest: "sha256:" + strings.Repeat("8e", 32)}
			read, err := service.acquire("golden-read", "screening", newObject(), who)
			if err != nil {
				t.Fatal(err)
			}
			cited := read["receipt"].(map[string]any)["signature"].(string)
			line := `{"kind":"evaluation","cites":[{"sessionId":"golden-read","callIndex":0,"signature":"` + cited + `"}]}`
			if err := os.WriteFile(filepath.Join(service.decisionRecords, "evaluations.jsonl"), []byte(line+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			record := "sha256:" + hexOf([]byte(line))
			arguments := `{"statement":"update t set x = 1"}`
			acted, err := service.act(json.RawMessage(`"golden-write"`), json.RawMessage(`"warehouse"`), json.RawMessage(`"execute"`), json.RawMessage(arguments),
				json.RawMessage(`{"recordDigest":"`+record+`","packDigest":"sha256:`+strings.Repeat("b", 64)+`"}`),
				json.RawMessage(`[{"sessionId":"golden-read","callIndex":0,"signature":"`+cited+`"}]`), who)
			if err != nil {
				t.Fatal(err)
			}
			minted := acted["receipt"].(map[string]any)
			if _, carried := minted["action"].(map[string]any)["tool"].(map[string]any)["transport"]; carried {
				t.Fatalf("a stdio write's tool names a transport: %v", minted["action"])
			}
			// The commitments are the salts' over what was sent, before they
			// are put in place.
			salts := acted["salts"].(map[string]any)
			commitment := func(name, label, text string) string {
				salt, err := hex.DecodeString(salts[name].(string))
				if err != nil {
					t.Fatal(err)
				}
				v, err := parseJSON([]byte(text))
				if err != nil {
					t.Fatal(err)
				}
				return commitmentOver(salt, label, canon(v))
			}
			args := commitment("args", "args:", arguments)
			request := commitment("request", "request:", `{"tool":"execute","arguments":`+arguments+`}`)
			if minted["argumentsCommitment"] != args || minted["action"].(map[string]any)["request"] != request {
				t.Fatalf("the commitments are not over what was sent: %v", minted)
			}
			written, err := os.ReadFile(filepath.Join(service.storeRoot, "receipts", "golden-write", "0.json"))
			if err != nil {
				t.Fatal(err)
			}
			got := string(written)
			for _, moved := range []struct{ name, value, placeholder string }{
				{"servedAt", `"servedAt":"` + minted["servedAt"].(string) + `"`, `"servedAt":"SERVED"`},
				{"argumentsCommitment", `"argumentsCommitment":"` + args + `"`, `"argumentsCommitment":"ARGUMENTS"`},
				{"action.request", `"request":"` + request + `"`, `"request":"REQUEST"`},
				{"action.decision.recordDigest", `"recordDigest":"` + record + `"`, `"recordDigest":"RECORD"`},
				{"action.cites[0].signature", `"signature":"` + cited + `"`, `"signature":"CITED"`},
				{"signature", `"signature":"` + minted["signature"].(string) + `"`, `"signature":"SIGNATURE"`},
			} {
				if n := strings.Count(got, moved.value); n != 1 {
					t.Fatalf("%s: found %d times in %s", moved.name, n, got)
				}
				got = strings.Replace(got, moved.value, moved.placeholder, 1)
			}
			path := filepath.Join("testdata", "action-golden", tc.name+".json")
			if *updateActionGolden {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Fatalf("a stdio write's receipt moved:\n got %s\nwant %s", got, want)
			}
		})
	}
}
