package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// memberRows are the shared rows of testdata/delegation/receipt-members.json.
type memberRows struct {
	Bases map[string]json.RawMessage `json:"bases"`
	Rows  []struct {
		Base   string          `json:"base"`
		Path   []string        `json:"path"`
		Value  json.RawMessage `json:"value"`
		Remove bool            `json:"remove"`
		Valid  bool            `json:"valid"`
	} `json:"rows"`
}

// The forms of the delegation and reconciler members, and the comparisons
// within one receipt (SPEC.md §11.7): the rows the TypeScript reader reads
// too.
func TestDelegationReceiptMemberRows(t *testing.T) {
	raw, err := os.ReadFile("../testdata/delegation/receipt-members.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc memberRows
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Rows) < 50 {
		t.Fatalf("%d rows", len(doc.Rows))
	}
	for i, row := range doc.Rows {
		t.Run(fmt.Sprintf("%d-%s", i, strings.Join(row.Path, ".")), func(t *testing.T) {
			v, err := parseJSON(doc.Bases[row.Base])
			if err != nil {
				t.Fatal(err)
			}
			obj := v.(*vObject)
			target := obj
			for _, name := range row.Path[:len(row.Path)-1] {
				next, _ := target.get(name)
				target = next.(*vObject)
			}
			last := row.Path[len(row.Path)-1]
			if row.Remove {
				replacement := newObject()
				for _, name := range target.names {
					if name != last {
						v, _ := target.get(name)
						replacement.set(name, v)
					}
				}
				*target = *replacement
			} else {
				value, err := parseJSON(row.Value)
				if err != nil {
					t.Fatal(err)
				}
				target.set(last, value)
			}
			_, err = receiptFrom(obj)
			if (err == nil) != row.Valid {
				t.Fatalf("valid=%v: %v", row.Valid, err)
			}
		})
	}
}

// A receipt made under no delegation is byte for byte the receipt it was
// before the members existed (SPEC.md §11.7): every version 3 receipt the
// corpus holds is rebuilt by the builder with no delegation and no
// reconciler, signed by the corpus key, and compared with its file.
func TestUndelegatedReceiptsAreByteIdentical(t *testing.T) {
	seed := mustHex(t, strings.TrimSpace(readFile(t, corpusPath("TEST-SEED"))))
	key := ed25519.NewKeyFromSeed(seed)
	vectors, _ := filepath.Glob(corpusPath("v3", "stores", "*.json"))
	rebuilt := 0
	for _, path := range vectors {
		var vector struct {
			Files map[string]string `json:"files"`
		}
		readJSON(t, path, &vector)
		for name, text := range vector.Files {
			if !strings.HasPrefix(name, "receipts/") {
				continue
			}
			v, err := parseJSON([]byte(strings.TrimSuffix(text, "\n")))
			if err != nil {
				continue
			}
			obj, ok := v.(*vObject)
			if !ok {
				continue
			}
			version, _ := memberString(obj, "receiptVersion")
			kind, _ := memberString(obj, "kind")
			if version != "3" || (kind != "acquisition" && kind != "action") {
				continue
			}
			if _, delegated := obj.get("delegation"); delegated {
				continue
			}
			if _, reconciled := obj.get("reconciler"); reconciled {
				continue
			}
			// Only a receipt the corpus key signed as it stands is a receipt
			// this builder could have minted.
			r, err := receiptFrom(obj)
			if err != nil || !ed25519.Verify(key.Public().(ed25519.PublicKey), r.signingInput(), mustHex(t, r.signature)) {
				continue
			}
			if len(obj.byName) != expectedTopLevel(obj) {
				continue // a vector that appends a member the builder never writes
			}
			in := receiptInput{version: "3", kind: kind}
			in.sessionID, _ = memberString(obj, "sessionId")
			index, _ := obj.get("callIndex")
			in.callIndex = int64(index.(vInt))
			in.prevSignature, _ = memberString(obj, "prevSignature")
			in.source, _ = memberString(obj, "source")
			in.resultDigest, _ = memberString(obj, "resultDigest")
			in.servedAt, _ = memberString(obj, "servedAt")
			in.authority, _ = memberString(obj, "authority")
			if c, _ := obj.get("caller"); c != nil {
				if co, isObject := c.(*vObject); isObject {
					in.who = &caller{}
					in.who.issuer, _ = memberString(co, "issuer")
					in.who.subject, _ = memberString(co, "subject")
					in.who.tokenDigest, _ = memberString(co, "tokenDigest")
				}
			}
			if w, present := obj.get("witness"); present {
				in.witness = w.(*vObject)
			}
			detail, _ := obj.get(kind)
			in.detail = detail.(*vObject)
			core := buildReceipt(in)
			commitment, _ := obj.get("argumentsCommitment")
			core.set("argumentsCommitment", commitment) // the salt is not in the store
			keyID, _ := obj.get("keyId")
			core.set("keyId", keyID)
			covered := append([]byte(receiptContext3), canon(core)...)
			core.set("signature", vString(fmt.Sprintf("%x", ed25519.Sign(key, covered))))
			if string(canon(core))+"\n" != text {
				t.Fatalf("%s %s: rebuilt\n%s\nfile\n%s", filepath.Base(path), name, canon(core), text)
			}
			rebuilt++
		}
	}
	if rebuilt < 40 {
		t.Fatalf("only %d receipts rebuilt", rebuilt)
	}
}

// expectedTopLevel is how many top-level members the builder writes for a
// receipt like obj.
func expectedTopLevel(obj *vObject) int {
	n := 14 // the common members, argumentsCommitment, kind, caller, the detail, keyId and signature
	if _, present := obj.get("witness"); present {
		n++
	}
	return n
}
