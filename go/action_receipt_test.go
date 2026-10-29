package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestActionReceiptSharedMutations(t *testing.T) {
	raw, err := os.ReadFile("../testdata/action-reconciliation/mutations.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Kind, Member  string
		Value         json.RawMessage
		Remove, Valid bool
	}
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		t.Run(row.Kind+"/"+row.Member, func(t *testing.T) {
			text := `{"key":"` + strings.Repeat("a", 64) + `","contract":"sha256:` + strings.Repeat("b", 64) + `","outcome":"uncertain"}`
			if row.Kind != "delivery" {
				text = `{"key":"` + strings.Repeat("a", 64) + `","contract":"sha256:` + strings.Repeat("b", 64) + `","outcome":"committed","action":{"sessionId":"act","callIndex":0,"signature":"` + testSig3 + `"}}`
			}
			v, _ := parseJSON([]byte(text))
			o := v.(*vObject)
			target := o
			if row.Kind == "citation" {
				v, _ := o.get("action")
				target = v.(*vObject)
			}
			if row.Remove {
				replacement := newObject()
				for _, name := range target.names {
					if name != row.Member {
						v, _ := target.get(name)
						replacement.set(name, v)
					}
				}
				if row.Kind == "citation" {
					o.set("action", replacement)
				} else {
					o = replacement
				}
			} else {
				v, err := parseJSON(row.Value)
				if err != nil {
					t.Fatal(err)
				}
				target.set(row.Member, v)
			}
			kind := "action"
			if row.Kind != "delivery" {
				kind = "acquisition"
			}
			obj, r := receipt3(kind, func(receipt *vObject) {
				detail, _ := receipt.get(kind)
				name := "delivery"
				if kind == "acquisition" {
					name = "reconciliation"
				}
				detail.(*vObject).set(name, o)
			})
			err := validateVersion3(obj, r)
			if (err == nil) != row.Valid {
				t.Fatalf("valid=%v: %v", row.Valid, err)
			}
		})
	}
}

// #351 M3 and L3: what the store establishes of an uncertain action is
// reported beside ok, and a read-back must be the write's platform's live MCP
// operation. The rows are shared with verify-ts; the stores are made by hand.
func TestActionDeliveryObservationsSharedRows(t *testing.T) {
	raw, err := os.ReadFile("../testdata/action-reconciliation/delivery-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Name         string
		Delivery     string
		ActionSource *string
		Reads        []struct{ Outcome, Key, Contract, Source, Shape string }
		Observation  *string
		Unresolved   []int
	}
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		t.Run(row.Name, func(t *testing.T) {
			at := t.TempDir()
			s, err := newStore(filepath.Join(at, "store"), testSeed, "gateway:test")
			if err != nil {
				t.Fatal(err)
			}
			result, err := s.retain([]byte(`{"n":0}`))
			if err != nil {
				t.Fatal(err)
			}
			decisions := filepath.Join(at, "decisions")
			if err = os.MkdirAll(decisions, 0700); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(decisions, "decision.json"), []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
			digest := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
			put := func(receipt map[string]any) string {
				t.Helper()
				text, _ := json.Marshal(receipt)
				v, err := parseJSON(text)
				if err != nil {
					t.Fatal(err)
				}
				sig := ed25519.Sign(s.private, append([]byte(receiptContext3), canon(v)...))
				v.(*vObject).set("signature", vString(hex.EncodeToString(sig)))
				dir := filepath.Join(s.root, "receipts", receipt["sessionId"].(string))
				if err = os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, fmt.Sprint(receipt["callIndex"])+".json"), canon(v), 0644); err != nil {
					t.Fatal(err)
				}
				return hex.EncodeToString(sig)
			}
			base := func(session string, index int, prev any, source, kind string) map[string]any {
				return map[string]any{"receiptVersion": "3", "sessionId": session, "callIndex": index, "prevSignature": prev, "source": source, "resultDigest": result, "servedAt": "2026-09-15T00:00:00Z", "authority": "gateway:test", "keyId": s.keyID, "kind": kind, "argumentsCommitment": digest("0"), "caller": nil}
			}
			acquisition := func(shape string) map[string]any {
				return map[string]any{"adapter": map[string]any{"name": "adapter-mcp", "version": "1", "digest": digest("1")}, "shape": shape, "endpoint": nil, "statement": nil, "snapshot": nil, "peerIdentity": nil, "schema": nil, "upstreamToken": nil, "observedAt": "2026-09-15T00:00:00Z"}
			}
			read := base("s1", 0, nil, "src", "acquisition")
			read["acquisition"] = acquisition("mcp")
			readSignature := put(read)
			requester := map[string]any{"issuer": "https://issuer.test", "subject": "person", "tokenDigest": digest("2")}
			action := base("act", 0, nil, "tickets/write", "action")
			if row.ActionSource != nil {
				action["source"] = *row.ActionSource
			}
			action["action"] = map[string]any{
				"requester":  requester,
				"decision":   map[string]any{"recordDigest": digestOf("{}"), "packDigest": digest("3")},
				"cites":      []any{map[string]any{"sessionId": "s1", "callIndex": 0, "signature": readSignature}},
				"tool":       map[string]any{"shape": "mcp", "endpoint": nil, "name": "tickets.close"},
				"request":    digest("4"),
				"adapter":    map[string]any{"name": "adapter-mcp", "version": "1", "digest": digest("1")},
				"observedAt": "2026-09-15T00:00:01Z",
				"delivery":   map[string]any{"key": strings.Repeat("a", 64), "contract": digest("b"), "outcome": row.Delivery},
			}
			actionSignature := put(action)
			var prev any
			for i, r := range row.Reads {
				source, shape, key, contract := "tickets/live", "mcp", strings.Repeat("a", 64), digest("b")
				if r.Source != "" {
					source = r.Source
				}
				if r.Shape != "" {
					shape = r.Shape
				}
				if r.Key != "" {
					key = r.Key
				}
				if r.Contract != "" {
					contract = r.Contract
				}
				recon := base("recon", i, prev, source, "acquisition")
				recon["caller"] = map[string]any{"issuer": "https://issuer.test", "subject": "person", "tokenDigest": digest("f")}
				a := acquisition(shape)
				a["reconciliation"] = map[string]any{"key": key, "contract": contract, "outcome": r.Outcome, "action": map[string]any{"sessionId": "act", "callIndex": 0, "signature": actionSignature}}
				recon["acquisition"] = a
				prev = put(recon)
			}
			lines := []string{sealLine(t, s.private, "s1", 1), sealLine(t, s.private, "act", 1)}
			if len(row.Reads) > 0 {
				lines = append(lines, sealLine(t, s.private, "recon", int64(len(row.Reads))))
			}
			registry := filepath.Join(at, "registry.jsonl")
			if err = os.WriteFile(registry, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
				t.Fatal(err)
			}
			report, err := verifyWithRegistryAndRecords(s.root, registry, "gateway:test", decisions, s.publicKey)
			if err != nil {
				t.Fatal(err)
			}
			var observed []string
			for _, o := range report.Observations {
				if text := fmt.Sprint(o["observation"]); strings.HasPrefix(text, "action-") {
					observed = append(observed, fmt.Sprintf("%v/%v/%s", o["sessionId"], o["callIndex"], text))
				}
			}
			var want []string
			if row.Observation != nil {
				want = []string{"act/0/" + *row.Observation}
			}
			if fmt.Sprint(observed) != fmt.Sprint(want) {
				t.Fatalf("observations %v, want %v", observed, want)
			}
			var unresolved, others []string
			for _, f := range report.Findings {
				switch f["status"] {
				case "ok":
				case "action-reconciliation-unresolved":
					unresolved = append(unresolved, fmt.Sprintf("%v/%v", f["sessionId"], f["callIndex"]))
				default:
					others = append(others, fmt.Sprint(f))
				}
			}
			var wantUnresolved []string
			for _, i := range row.Unresolved {
				wantUnresolved = append(wantUnresolved, fmt.Sprintf("recon/%d", i))
			}
			if fmt.Sprint(unresolved) != fmt.Sprint(wantUnresolved) || len(others) > 0 {
				t.Fatalf("unresolved %v (want %v), other findings %v", unresolved, wantUnresolved, others)
			}
		})
	}
}
