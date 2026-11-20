package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// askKeyHistory is GET /publickey/history of g, by its status and body.
func askKeyHistory(t *testing.T, g *gatewayService) (int, []byte) {
	t.Helper()
	rec := httptest.NewRecorder()
	g.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, keyHistoryRoute, nil))
	return rec.Code, rec.Body.Bytes()
}

// historyPinned is g's key history, which must answer 200 and hold from
// pinned.
func historyPinned(t *testing.T, g *gatewayService, pinned ed25519.PublicKey) ([]keyHistoryEntry, []byte) {
	t.Helper()
	code, body := askKeyHistory(t, g)
	if code != http.StatusOK {
		t.Fatalf("the key history answered %d: %s", code, body)
	}
	entries, err := checkKeyHistory(body, pinned)
	if err != nil {
		t.Fatalf("the key history does not hold from the key pinned: %v\n%s", err, body)
	}
	return entries, body
}

// wantKeys holds entries to keys, in order, each key's validTo the next
// one's validFrom, at[i] the rotation to keys[i+1].
func wantKeys(t *testing.T, entries []keyHistoryEntry, keys []ed25519.PublicKey, at []string) {
	t.Helper()
	if len(entries) != len(keys) {
		t.Fatalf("%d entries, want %d", len(entries), len(keys))
	}
	for i, e := range entries {
		if !bytes.Equal(e.key, keys[i]) || e.keyID != keyIDFor(keys[i]) {
			t.Fatalf("entry %d is key %s, want %s", i, e.keyID, keyIDFor(keys[i]))
		}
		wantTo := ""
		if i < len(at) {
			wantTo = at[i]
		}
		if e.validTo != wantTo || (i > 0 && e.validFrom != at[i-1]) || (i == 0 && e.validFrom != "") {
			t.Fatalf("entry %d: validFrom %q validTo %q, rotations at %v", i, e.validFrom, e.validTo, at)
		}
	}
}

func seedKeyOf(seed []byte) ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
}

func historySeed(word string) []byte {
	seed := sha256.Sum256([]byte("key-history-test/" + word))
	return seed[:]
}

// The key history follows each rotation while the gateway serves, from the
// seed's key to a key service's first key version and on to its second:
// each answer holds from the seed's key alone, the key in force last and
// without a validTo, each earlier key's validTo the rotation from it, and
// the key in force the one /publickey answers.
func TestTheKeyHistoryFollowsEachRotationWhileServing(t *testing.T) {
	standInKeyService(t)
	one, two := mustKeyServiceSigner(t, ksVersion1), mustKeyServiceSigner(t, ksVersion2)
	g, _, _ := ksService(t, nil)
	seedKey := seedKeyOf(testSeed)
	mustAcquire(t, g, "before")
	mustSeal(t, g, "before")
	entries, _ := historyPinned(t, g, seedKey)
	wantKeys(t, entries, []ed25519.PublicKey{seedKey}, nil)
	at := []string{"2026-11-19T00:00:00Z", "2026-11-19T00:00:01Z"}
	if _, err := g.registry.rotateTo(one, at[0]); err != nil {
		t.Fatal(err)
	}
	mustAcquire(t, g, "between")
	mustSeal(t, g, "between")
	entries, _ = historyPinned(t, g, seedKey)
	wantKeys(t, entries, []ed25519.PublicKey{seedKey, one.publicKey()}, at[:1])
	if _, err := g.registry.rotateTo(two, at[1]); err != nil {
		t.Fatal(err)
	}
	entries, body := historyPinned(t, g, seedKey)
	wantKeys(t, entries, []ed25519.PublicKey{seedKey, one.publicKey(), two.publicKey()}, at)
	if g.publicKeyDocument()["keyId"] != entries[2].keyID {
		t.Fatal("the key in force is not the key /publickey answers")
	}
	if _, err := checkKeyHistory(body, one.publicKey()); err == nil {
		t.Fatal("a history held from a key it does not begin at")
	}
}

// An entry the registry's chain does not prove is never served: a rotation
// the key in force did not sign stops the history, which is answered 500
// with a fixed sentence and none of the keys reached before it.
func TestTheKeyHistoryServesNoEntryTheChainDoesNotProve(t *testing.T) {
	g, _, registry := ksService(t, nil)
	mustAcquire(t, g, "a")
	mustSeal(t, g, "a")
	data, err := os.ReadFile(registry)
	if err != nil {
		t.Fatal(err)
	}
	forged := rotationRecord(data, 1, "2026-11-19T00:00:00Z", ed25519.NewKeyFromSeed(historySeed("other")), ed25519.NewKeyFromSeed(historySeed("next")))
	if err := os.WriteFile(registry, append(data, forged...), 0o600); err != nil {
		t.Fatal(err)
	}
	code, body := askKeyHistory(t, g)
	if code != http.StatusInternalServerError || string(body) != `{"error":"the key history could not be read; the gateway says why on its stderr"}` {
		t.Fatalf("a history past a forged rotation: %d %s", code, body)
	}
	// the gateway's own key-rotation with no key-continuation after it: a
	// walk that finds rotation-break, which ends at the gateway's key still
	record := rotationRecord(data, 1, "2026-11-19T00:00:00Z", ed25519.NewKeyFromSeed(testSeed), ed25519.NewKeyFromSeed(historySeed("next")))
	broken := append(bytes.Clone(data), bytes.SplitAfter(record, []byte("\n"))[0]...)
	if err := os.WriteFile(registry, broken, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, body := askKeyHistory(t, g); code != http.StatusInternalServerError {
		t.Fatalf("a history past a rotation without its continuation: %d %s", code, body)
	}
}

// The consumer's check refuses every entry the chain does not prove: the
// history of a seed's key rotated twice, altered one way at a time.
func TestTheKeyHistoryCheckRefusesWhatTheChainDoesNotProve(t *testing.T) {
	first, second, third := ed25519.NewKeyFromSeed(historySeed("1")), ed25519.NewKeyFromSeed(historySeed("2")), ed25519.NewKeyFromSeed(historySeed("3"))
	data := rotationRecord(nil, 1, "2026-11-19T00:00:00Z", first, second)
	data = append(data, rotationRecord(data, 2, "2026-11-19T00:00:01Z", second, third)...)
	entries, err := registryKeyHistory(data, third.Public().(ed25519.PublicKey), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	doc := keyHistoryDocument(entries)
	pinned := first.Public().(ed25519.PublicKey)
	if _, err := checkKeyHistory(doc, pinned); err != nil {
		t.Fatalf("the history itself: %v\n%s", err, doc)
	}
	var parsed map[string]any
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatal(err)
	}
	otherRotation := rotationRecord(nil, 1, "2026-11-19T00:00:00Z", ed25519.NewKeyFromSeed(historySeed("x")), second)
	altered := map[string]func(keys []any){
		"the last key given a validTo":   func(keys []any) { keys[2].(map[string]any)["validTo"] = "2026-11-19T00:00:02Z" },
		"the key in force dropped":       func(keys []any) { keys[2] = nil },
		"a validTo not the rotation's":   func(keys []any) { keys[0].(map[string]any)["validTo"] = "2026-11-18T00:00:00Z" },
		"a validFrom not the rotation's": func(keys []any) { keys[1].(map[string]any)["validFrom"] = "2026-11-18T00:00:00Z" },
		"a rotation whose signature does not verify": func(keys []any) {
			k := keys[1].(map[string]any)
			k["keyRotation"] = badSignature(k["keyRotation"].(string))
		},
		"a continuation whose signature does not verify": func(keys []any) {
			k := keys[2].(map[string]any)
			k["keyContinuation"] = badSignature(k["keyContinuation"].(string))
		},
		"a rotation another key signed": func(keys []any) {
			keys[1].(map[string]any)["keyRotation"] = strings.Split(string(otherRotation), "\n")[0]
		},
		"the statements of another rotation": func(keys []any) {
			k1, k2 := keys[1].(map[string]any), keys[2].(map[string]any)
			k1["keyRotation"], k1["keyContinuation"] = k2["keyRotation"], k2["keyContinuation"]
		},
		"a member the form does not have": func(keys []any) { keys[1].(map[string]any)["rotation"] = 1 },
		"a statement without its pair":    func(keys []any) { delete(keys[1].(map[string]any), "keyContinuation") },
		"the first key given a rotation":  func(keys []any) { keys[0].(map[string]any)["keyRotation"] = keys[1].(map[string]any)["keyRotation"] },
		"a key repeated":                  func(keys []any) { keys[2].(map[string]any)["publicKey"] = keys[0].(map[string]any)["publicKey"] },
	}
	for name, alter := range altered {
		var copied map[string]any
		_ = json.Unmarshal(doc, &copied)
		keys := copied["keys"].([]any)
		alter(keys)
		var kept []any
		for _, k := range keys {
			if k != nil {
				kept = append(kept, k)
			}
		}
		copied["keys"] = kept
		out, _ := json.Marshal(copied)
		if _, err := checkKeyHistory(out, pinned); err == nil {
			t.Errorf("%s: the check passed\n%s", name, out)
		}
	}
	if _, err := checkKeyHistory(doc, second.Public().(ed25519.PublicKey)); err == nil {
		t.Error("a history held from a key it does not begin at")
	}
}

// A store rotation carries the key history into the new store: the new
// store's gateway answers the old store's history, the key in force at the
// rotation its last entry; a rotation in the new store, whose ordinals start
// again at 1, ends that key; a second store rotation carries the whole
// history on. A history carried that does not hold is answered 500; one
// carried beside no store continuation too; and a continued store with
// none carried answers from the key in force at its continuation, which a
// consumer pinning the first key refuses.
func TestTheKeyHistoryIsCarriedAcrossStoreRotation(t *testing.T) {
	g, _, _ := ksService(t, nil)
	seed2, seed3 := historySeed("2"), historySeed("3")
	keys := []ed25519.PublicKey{seedKeyOf(testSeed), seedKeyOf(seed2), seedKeyOf(seed3)}
	at := []string{"2026-11-19T00:00:00Z", "2026-11-19T00:00:02Z"}
	mustAcquire(t, g, "a")
	mustSeal(t, g, "a")
	if _, err := g.registry.rotateTo(newSeedSigner(seed2), at[0]); err != nil {
		t.Fatal(err)
	}
	_, before := historyPinned(t, g, keys[0])
	dir := t.TempDir()
	newStore, newRegistry := filepath.Join(dir, "store"), filepath.Join(dir, "registry.jsonl")
	if code, stdout, stderr := rotateOn(t, g, writeSeedFile(t, t.TempDir(), seed2), newStore, newRegistry, "2026-11-19T00:00:01Z"); code != 0 {
		t.Fatalf("store rotate: %d %s %s", code, stdout, stderr)
	}
	if carried := readFile(t, keyHistoryBeside(newRegistry)); carried != string(before) {
		t.Fatalf("the history carried is not the old store's answer:\n%s\n%s", carried, before)
	}
	g2, err := newGatewayServiceSigned(newStore, seed2, nil, "gateway:test", newRegistry, ksSources())
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := historyPinned(t, g2, keys[0])
	wantKeys(t, entries, keys[:2], at[:1])
	mustAcquire(t, g2, "b")
	mustSeal(t, g2, "b")
	if _, err := g2.registry.rotateTo(newSeedSigner(seed3), at[1]); err != nil {
		t.Fatal(err)
	}
	entries, after := historyPinned(t, g2, keys[0])
	wantKeys(t, entries, keys, at)

	dir3 := t.TempDir()
	thirdStore, thirdRegistry := filepath.Join(dir3, "store"), filepath.Join(dir3, "registry.jsonl")
	if code, stdout, stderr := rotateOn(t, g2, writeSeedFile(t, t.TempDir(), seed3), thirdStore, thirdRegistry, "2026-11-19T00:00:03Z"); code != 0 {
		t.Fatalf("the second store rotate: %d %s %s", code, stdout, stderr)
	}
	g3, err := newGatewayServiceSigned(thirdStore, seed3, nil, "gateway:test", thirdRegistry, ksSources())
	if err != nil {
		t.Fatal(err)
	}
	if _, third := historyPinned(t, g3, keys[0]); !bytes.Equal(third, after) {
		t.Fatalf("the second store rotation did not carry the whole history:\n%s\n%s", third, after)
	}

	carried := keyHistoryBeside(thirdRegistry)
	altered := bytes.Replace(after, []byte(`"validTo":"`+at[0]), []byte(`"validTo":"2026-11-18T00:00:00Z`), 1)
	if err := os.WriteFile(carried, altered, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, body := askKeyHistory(t, g3); code != http.StatusInternalServerError {
		t.Fatalf("a carried history that does not hold: %d %s", code, body)
	}
	if err := os.Remove(carried); err != nil {
		t.Fatal(err)
	}
	code, body := askKeyHistory(t, g3)
	if code != http.StatusOK {
		t.Fatalf("a continued store with no history carried: %d %s", code, body)
	}
	if entries, err := checkKeyHistory(body, keys[2]); err != nil || len(entries) != 1 {
		t.Fatalf("a continued store with no history carried answers from the key in force at its continuation: %v %s", err, body)
	}
	if _, err := checkKeyHistory(body, keys[0]); err == nil {
		t.Fatal("a consumer pinning the first key took a history that does not begin at it")
	}
	if err := os.WriteFile(keyHistoryBeside(g.regPath), before, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, body := askKeyHistory(t, g); code != http.StatusInternalServerError {
		t.Fatalf("a history carried beside a registry that continues no store: %d %s", code, body)
	}
}

// A store rotation stopped after its new registry was made and before its
// mark is finished by a rerun, which carries the key history where none is
// beside the new registry -- the history a rotation made before histories
// were carried left out -- and the history it carries is the old store's.
func TestARerunOfAStoreRotationCarriesTheKeyHistory(t *testing.T) {
	g, _, _ := ksService(t, nil)
	seed2 := historySeed("2")
	if _, err := g.registry.rotateTo(newSeedSigner(seed2), "2026-11-19T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	_, before := historyPinned(t, g, seedKeyOf(testSeed))
	dir := t.TempDir()
	newStore, newRegistry := filepath.Join(dir, "store"), filepath.Join(dir, "registry.jsonl")
	seedPath := writeSeedFile(t, t.TempDir(), seed2)
	if code, stdout, stderr := rotateOn(t, g, seedPath, newStore, newRegistry, "2026-11-19T00:00:01Z"); code != 0 {
		t.Fatalf("store rotate: %d %s %s", code, stdout, stderr)
	}
	for _, path := range []string{rotatedMarkPath(g.regPath), keyHistoryBeside(newRegistry)} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if code, stdout, stderr := rotateOn(t, g, seedPath, newStore, newRegistry, "2026-11-19T00:00:02Z"); code != 0 {
		t.Fatalf("the rerun: %d %s %s", code, stdout, stderr)
	}
	if carried := readFile(t, keyHistoryBeside(newRegistry)); carried != string(before) {
		t.Fatalf("the rerun carried another history:\n%s\n%s", carried, before)
	}
}

// badSignature is a statement's line with its signature's first byte changed.
func badSignature(line string) string {
	at := strings.Index(line, `"signature":"`) + len(`"signature":"`)
	flipped := "00"
	if line[at:at+2] == "00" {
		flipped = "01"
	}
	return line[:at] + flipped + line[at+2:]
}
