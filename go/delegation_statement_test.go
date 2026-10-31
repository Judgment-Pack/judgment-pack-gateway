package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// statementVectors are the hand-written chains of testdata/delegation, signed
// by an independent signer, and the keys they are pinned under.
type statementVectors struct {
	Keys    map[string][]string `json:"keys"`
	Vectors []struct {
		Name   string          `json:"name"`
		Chain  json.RawMessage `json:"chain"`
		Expect string          `json:"expect"`
	} `json:"vectors"`
}

func readStatementVectors(t testing.TB) (statementVectors, delegationKeys) {
	t.Helper()
	raw, err := os.ReadFile("../testdata/delegation/statements.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc statementVectors
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	keys := delegationKeys{}
	for host, list := range doc.Keys {
		keys[host] = map[string]ed25519.PublicKey{}
		for _, k := range list {
			pub, err := hex.DecodeString(k)
			if err != nil {
				t.Fatal(err)
			}
			keys[host][keyIDFor(pub)] = ed25519.PublicKey(pub)
		}
	}
	return doc, keys
}

// Steps 1 to 7 and the narrowing check (SPEC.md §11.1): each vector gets its
// first refusal, or verifies.
func TestDelegationStatementVectors(t *testing.T) {
	doc, keys := readStatementVectors(t)
	if len(doc.Vectors) < 30 {
		t.Fatalf("only %d vectors", len(doc.Vectors))
	}
	for _, v := range doc.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			got := "ok"
			value, err := parseJSONWithin(v.Chain, maxArgumentValues)
			if err != nil {
				got = refusalMalformed
			} else if _, refusal := verifyDelegationChain(value, keys); refusal != nil {
				got = refusal.name
			}
			if got != v.Expect {
				t.Fatalf("got %s, want %s", got, v.Expect)
			}
		})
	}
}

// A chain whose bytes hold a duplicate member name, or a number outside the
// canon domain, is malformed at step 1: the parser refuses it.
func TestDelegationStepOneParser(t *testing.T) {
	for _, text := range []string{`[{"delegationVersion":"1","delegationVersion":"1"}]`, `[{"delegationVersion":"1","depth":1.0}]`, `[]`, `{}`, `["x"]`} {
		value, err := parseJSONWithin([]byte(text), maxArgumentValues)
		if err == nil {
			_, refusal := verifyDelegationChain(value, delegationKeys{})
			if refusal == nil || refusal.name != refusalMalformed {
				t.Fatalf("%s: %v", text, refusal)
			}
		}
	}
}

// Step 8 at the gateway's time: equal to expiresAt is expired, before
// issuedAt is not yet valid, with no skew allowance; not-yet-valid is
// reported before expired.
func TestDelegationTimeStep(t *testing.T) {
	doc, keys := readStatementVectors(t)
	value, _ := parseJSON(doc.Vectors[1].Chain)
	chain, refusal := verifyDelegationChain(value, keys)
	if refusal != nil {
		t.Fatal(refusal)
	}
	at := func(s string) time.Time { tm, _ := time.Parse(delegationTimeLayout, s); return tm }
	for _, c := range []struct {
		t    string
		want string
	}{
		{"2026-10-29T23:59:59.999Z", refusalNotYetValid},
		{"2026-10-30T00:00:00.000Z", ""},
		{"2026-10-30T01:59:59.999Z", ""},
		{"2026-10-30T02:00:00.000Z", refusalExpired}, // the grandchild's expiry
	} {
		r := chain.timeRefusal(at(c.t))
		got := ""
		if r != nil {
			got = r.name
		}
		if got != c.want {
			t.Fatalf("%s: got %q, want %q", c.t, got, c.want)
		}
	}
}

// Step 11's gateway part, its reasons in order within a link, and links
// root first.
func TestDelegationScopeReasons(t *testing.T) {
	doc, keys := readStatementVectors(t)
	value, _ := parseJSON(doc.Vectors[1].Chain)
	chain, _ := verifyDelegationChain(value, keys)
	for _, c := range []struct {
		audience, source, tool, effect string
		want                           string
	}{
		{"gateway:test", "tickets/live", "query", "read-external", ""},
		{"gateway:staging", "tickets/live", "query", "read-external", "source"},
		{"gateway:test", "tickets/write", "query", "act", "source"}, // the child drops the write
		{"gateway:test", "tickets/live", "sibling", "read-external", "tool"},
		{"gateway:test", "tickets/live", "", "read-external", "tool"},
		{"gateway:test", "tickets/live", "query", "read", "effect"}, // the root admits read, the child does not
		{"gateway:test", "tickets/live", "query", "", "effect"},
	} {
		r := chain.scopeRefusal(c.audience, c.source, c.tool, c.effect)
		got := ""
		if r != nil {
			got = r.scopeReason
		}
		if got != c.want {
			t.Fatalf("%+v: got %q, want %q", c, got, c.want)
		}
	}
	if chain.readOnly() != false {
		t.Fatal("the root admits act")
	}
}
