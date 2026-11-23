package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The refusal journal vectors of corpus/v3/stores (ADR-0059, build plan R3):
// each is v3-journal-holds with one refusal journal of the synthetic scope
// corpus-a beside its operator journal, signed by the corpus's TEST-SEED.
// Both verifiers run them by TestStoreVectors and verify-ts's corpus test;
// this test writes them again where GATEWAY_WRITE_REFUSAL_VECTORS is 1.
func TestRefusalJournalVectorsAreWritten(t *testing.T) {
	if os.Getenv("GATEWAY_WRITE_REFUSAL_VECTORS") != "1" {
		t.Skip("writes the corpus's refusal journal vectors where GATEWAY_WRITE_REFUSAL_VECTORS is 1")
	}
	dir := t.TempDir()
	g, err := newGatewayService(filepath.Join(dir, "store"), corpusSeed(t), "gateway:corpus", filepath.Join(dir, "registry.jsonl"), nil)
	if err != nil {
		t.Fatal(err)
	}
	key := g.store.signing.key()
	const scope, at = "corpus-a", "2026-09-12T00:00:02Z"
	name := refusalJournalName(scope)
	commitKey := sha256.Sum256([]byte("corpus refusal key"))
	token := sha256.Sum256([]byte("corpus token"))
	refusal := func(i int, scope string) *vObject {
		nonce := sha256.Sum256([]byte{'n', byte(i)})
		caller := newObject()
		caller.set("issuer", vString("https://issuer.test"))
		caller.set("subject", vString("caller-a"))
		caller.set("tokenDigest", vString("sha256:"+hex.EncodeToString(token[:])))
		b := newObject()
		b.set("kind", vString("refusal"))
		b.set("scope", vString(scope))
		b.set("route", vString("/acquire"))
		b.set("reason", vString("body"))
		b.set("status", vInt(400))
		b.set("answeredAt", vString("2026-09-12T00:00:02.000Z"))
		b.set("caller", caller)
		b.set("nonce", vString(hex.EncodeToString(nonce[:])))
		b.set("request", vString(refusalCommitment(refusalSalt(commitKey[:], nonce[:]), "/acquire", []byte(`{"session":"s9","bogus":true}`))))
		return b
	}
	tally := func(full bool) *vObject {
		b := newObject()
		b.set("kind", vString("tally"))
		b.set("scope", vString(scope))
		b.set("from", vString("2026-09-12T00:00:00Z"))
		b.set("to", vString("2026-09-12T00:01:00Z"))
		limit, dropped := newObject(), newObject()
		limit.set(limitScopeRate, vInt(2))
		dropped.set("queue-full", vInt(1))
		b.set("limit", limit)
		b.set("dropped", dropped)
		if full {
			b.set("full", vBool(true))
		}
		return b
	}
	operatorBody := newObject()
	operatorBody.set("kind", vString("remove-artifact"))
	operatorBody.set("by", vString("operator-1"))
	operatorBody.set("registryFrom", vInt(0))
	operatorBody.set("removalFrom", vInt(0))
	operatorBody.set("removalBytes", vInt(1))
	operatorBody.set("removalDigest", vString(hex.EncodeToString(token[:])))
	// chain signs bodies in order, each naming the line before it
	chain := func(bodies ...*vObject) [][]byte {
		var lines [][]byte
		previous := ""
		for i, b := range bodies {
			line, err := signedJournalEntry(key, name, int64(i), previous, at, b)
			if err != nil {
				t.Fatal(err)
			}
			lines = append(lines, line)
			previous = journalDigest(line[:len(line)-1])
		}
		return lines
	}
	file := func(lines ...[]byte) string { return string(bytes.Join(lines, nil)) }
	// resolved is a refusal made after the route resolved its tool (ADR-0059's
	// amendment): the tool, and its pinned descriptor digest where digest
	resolved := func(i int, tool, digest string) *vObject {
		b := refusal(i, scope)
		b.set("route", vString("/act"))
		b.set("reason", vString("decision"))
		b.set("tool", vString(tool))
		if digest != "" {
			b.set("descriptorDigest", vString(digest))
		}
		return b
	}
	descriptor := sha256.Sum256([]byte("corpus descriptor"))
	pinned := "sha256:" + hex.EncodeToString(descriptor[:])
	loose := refusal(1, scope)
	loose.set("descriptorDigest", vString(pinned))
	holds := chain(refusal(0, scope), refusal(1, scope), tally(false))
	forged := bytes.Clone(holds[1])
	forged[len(forged)-3] ^= 1
	mismatch := chain(refusal(0, scope), refusal(1, "corpus-b"))
	crossed := chain(refusal(0, scope), operatorBody)
	middle := func() [][]byte {
		first := chain(refusal(0, scope))[0]
		wrong, err := signedJournalEntry(key, name, 1, journalDigest([]byte("another line")), at, refusal(1, scope))
		if err != nil {
			t.Fatal(err)
		}
		third, err := signedJournalEntry(key, name, 2, journalDigest(wrong[:len(wrong)-1]), at, refusal(2, scope))
		if err != nil {
			t.Fatal(err)
		}
		return [][]byte{first, wrong, third}
	}()
	torn := `{"journal":"` + name
	finding := func(status string, ordinal int) map[string]any {
		return map[string]any{"journal": name, "ordinal": ordinal, "status": status}
	}
	from := func(n int) map[string]any {
		return map[string]any{"journal": name, "observation": "journal-from", "entries": n}
	}
	for _, v := range []struct {
		name, note, file string
		require          bool
		finding          map[string]any
		observations     []map[string]any
	}{
		{"v3-journal-refusal-holds", "A refusal journal of two refusals and a tally, each of its form and of its journal's scope, in one chain signed by the key in force (ADR-0059 §8): no finding, and journal-from, under --require-journal of its name.",
			file(holds...), true, nil, []map[string]any{from(3)}},
		{"v3-journal-refusal-tally-full", "A refusal journal closed by its tally with full: true (ADR-0059 §4, the cap): no finding, and journal-from.",
			file(chain(refusal(0, scope), tally(true))...), false, nil, []map[string]any{from(2)}},
		{"v3-journal-refusal-tool-holds", "A refusal journal whose first entry names the tool its route resolved and the tool's pinned descriptor digest, and whose second names the tool alone (ADR-0059's amendment): no finding, and journal-from.",
			file(chain(resolved(0, "create_ticket", pinned), resolved(1, "create_ticket", ""))...), false, nil, []map[string]any{from(2)}},
		{"v3-journal-refusal-digest-without-tool", "A refusal journal whose second entry, signed by the key in force, names a descriptor digest and no tool: journal-entry-forged at ordinal 1 (ADR-0059's amendment).",
			file(chain(refusal(0, scope), loose)...), false, finding("journal-entry-forged", 1), nil},
		{"v3-journal-refusal-forged", "A refusal journal whose second entry's signature does not hold: journal-entry-forged at ordinal 1 (ADR-0059 §8).",
			file(holds[0], forged, holds[2]), false, finding("journal-entry-forged", 1), nil},
		{"v3-journal-refusal-scope-mismatch", "A refusal journal whose second entry, signed by the key in force, names a scope whose journal is another: journal-entry-forged at ordinal 1 (ADR-0059 §8).",
			file(mismatch...), false, finding("journal-entry-forged", 1), nil},
		{"v3-journal-refusal-kind-crossed", "A refusal journal whose second entry, signed by the key in force, is an operator journal's body: journal-entry-forged at ordinal 1 (ADR-0059 §8).",
			file(crossed...), false, finding("journal-entry-forged", 1), nil},
		{"v3-journal-refusal-order-middle", "A refusal journal whose second entry names another line as its previous one: journal-order at ordinal 1 (ADR-0056 §6, ADR-0059 §8).",
			file(middle...), false, finding("journal-order", 1), nil},
		{"v3-journal-refusal-torn-tail", "A refusal journal of two entries and a torn last piece with no line end: no finding, journal-from and journal-torn-tail of the piece's bytes (ADR-0059 §8).",
			file(holds[0], holds[1]) + torn, false, nil, []map[string]any{from(2), {"journal": name, "observation": "journal-torn-tail", "bytes": len(torn)}}},
		{"v3-journal-refusal-missing", "No refusal journal of the name --require-journal gives: journal-missing (ADR-0059 §8).",
			"", true, map[string]any{"journal": name, "status": "journal-missing"}, nil},
	} {
		var vec map[string]any
		raw, err := os.ReadFile(corpusPath("v3", "stores", "v3-journal-holds.json"))
		if err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&vec); err != nil {
			t.Fatal(err)
		}
		vec["name"], vec["note"] = v.name, v.note
		if v.file != "" {
			vec["files"].(map[string]any)["journals/"+name+".jsonl"] = v.file
		}
		if v.require {
			vec["requireJournal"] = []any{"operator", name}
		}
		expected := vec["expected"].(map[string]any)
		if v.finding != nil {
			expected["findings"] = append(expected["findings"].([]any), v.finding)
			expected["ok"] = false
		}
		for _, o := range v.observations {
			expected["observations"] = append(expected["observations"].([]any), o)
		}
		var out bytes.Buffer
		encoder := json.NewEncoder(&out)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(vec); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(corpusPath("v3", "stores", v.name+".json"), out.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
