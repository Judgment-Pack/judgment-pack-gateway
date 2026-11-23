package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// es256StatementsSHA256 is the SHA-256 of testdata/delegation/es256-statements.json,
// as the spec repository's conformance/delegation/README.md records it for
// its conformance/delegation/es256-statements.json, of which this file is a
// byte-for-byte copy: the statement cases of spec RFC 0030's amendment of
// 2026-11-22, tables 1 and 2, made once by a signer independent of this
// repository and frozen, since ES256 signatures are not reproducible.
const es256StatementsSHA256 = "5a687a254c35989951345cea7b7f7b5cdf3a2edc2cc1f02918ed2e3f7d900f8b"

const es256StatementsPath = "../testdata/delegation/es256-statements.json"

type es256Case struct {
	Name      string                       `json:"name"`
	Table     int                          `json:"table"`
	Kind      string                       `json:"kind"`
	Expect    string                       `json:"expect"`
	Link      *int                         `json:"link"`
	Keys      map[string][]json.RawMessage `json:"keys"`
	Pin       json.RawMessage              `json:"pin"`
	PinExpect string                       `json:"pinExpect"`
	Chain     json.RawMessage              `json:"chain"`
}

type es256Cases struct {
	Keys  map[string][]json.RawMessage `json:"keys"`
	Cases []es256Case                  `json:"cases"`
}

func readES256Cases(t *testing.T) es256Cases {
	t.Helper()
	raw, err := os.ReadFile(es256StatementsPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc es256Cases
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// pinDelegationKeys pins each host's keys as the configuration reads them,
// at the version that takes the P-256 form.
func pinDelegationKeys(t *testing.T, pins map[string][]json.RawMessage) delegationKeys {
	t.Helper()
	keys := delegationKeys{}
	for host, list := range pins {
		keys[host] = map[string]heldKey{}
		for i, raw := range list {
			v, err := parseJSONWithin(raw, maxArgumentValues)
			if err != nil {
				t.Fatal(err)
			}
			key, err := delegationHostKey(i, v, delegationP256Version)
			if err != nil {
				t.Fatalf("pin %s[%d]: %v", host, i, err)
			}
			keys[host][key.keyID()] = key
		}
	}
	return keys
}

// The copy is the frozen file, byte for byte.
func TestDelegationES256CasesAreTheFrozenBytes(t *testing.T) {
	raw, err := os.ReadFile(es256StatementsPath)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != es256StatementsSHA256 {
		t.Fatalf("%s is not the frozen file: sha256 %x", es256StatementsPath, sum)
	}
}

// Every case of tables 1 and 2 gets its recorded verdict: the first refusal
// of steps 1 to 7, at the link the case names, or ok; and a pin a case marks
// refused is refused at every version, the link under it key-mismatch.
func TestDelegationES256Cases(t *testing.T) {
	doc := readES256Cases(t)
	defaults := pinDelegationKeys(t, doc.Keys)
	if len(doc.Cases) != 55 {
		t.Fatalf("%d cases, want 55", len(doc.Cases))
	}
	tables := map[int]int{}
	for _, c := range doc.Cases {
		tables[c.Table]++
		t.Run(c.Name, func(t *testing.T) {
			keys := defaults
			if c.Keys != nil {
				keys = pinDelegationKeys(t, c.Keys)
			}
			if c.Pin != nil {
				if c.PinExpect != "refused" {
					t.Fatalf("pinExpect %q", c.PinExpect)
				}
				pin, err := parseJSONWithin(c.Pin, maxArgumentValues)
				if err != nil {
					t.Fatal(err)
				}
				for _, version := range []string{"15", p256SignerVersion, delegationP256Version} {
					if key, err := delegationHostKey(0, pin, version); err == nil {
						t.Fatalf("version %s pins %x", version, key.key)
					}
				}
			}
			got, at := "ok", ""
			value, err := parseJSONWithin(c.Chain, maxArgumentValues)
			if err != nil {
				got = refusalMalformed
			} else if _, refusal := verifyDelegationChain(value, keys); refusal != nil {
				got, at = refusal.name, refusal.reason
			}
			if got != c.Expect {
				t.Fatalf("got %s (%s), want %s", got, at, c.Expect)
			}
			if c.Link != nil && !strings.HasPrefix(at, fmt.Sprintf("link %d ", *c.Link)) {
				t.Fatalf("refused at %q, want link %d", at, *c.Link)
			}
		})
	}
	if tables[1] != 30 || tables[2] != 25 {
		t.Fatalf("tables %v", tables)
	}
}

// The gateway's 39 Ed25519 cases still pass under keys pinned by the
// configuration's reading, at the version that takes the P-256 form.
func TestDelegationEd25519CasesUnderTheP256Version(t *testing.T) {
	raw, err := os.ReadFile("../testdata/delegation/statements.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Keys map[string][]json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	keys := pinDelegationKeys(t, doc.Keys)
	vectors, _ := readStatementVectors(t)
	if len(vectors.Vectors) != 39 {
		t.Fatalf("%d Ed25519 cases, want 39", len(vectors.Vectors))
	}
	for _, v := range vectors.Vectors {
		got := "ok"
		value, err := parseJSONWithin(v.Chain, maxArgumentValues)
		if err != nil {
			got = refusalMalformed
		} else if _, refusal := verifyDelegationChain(value, keys); refusal != nil {
			got = refusal.name
		}
		if got != v.Expect {
			t.Fatalf("%s: got %s, want %s", v.Name, got, v.Expect)
		}
	}
}
